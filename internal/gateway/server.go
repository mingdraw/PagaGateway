package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"sync"
	"time"
)

type agent struct {
	conn         net.Conn
	writer       controlWriter
	ctx          context.Context
	dialFeedback bool
	maxTunnels   int
	version      string
	// Lifecycle and counters are protected by Server.mu.
	online          bool
	pending         int
	active          int
	address         string
	connectedAt     time.Time
	lastHeartbeatAt time.Time
}

type work struct {
	conn  net.Conn
	error string
}
type pending struct {
	agent    *agent
	deadline time.Time
	ready    chan work
	closed   chan struct{}
}

type serverRoute struct {
	clientToken    [sha256.Size]byte
	accessToken    [sha256.Size]byte
	maxTunnels     int
	busyRejects    uint64 // protected by Server.mu
	lastOpenMicros int64
}

type Server struct {
	config  ServerConfig
	mu      sync.Mutex
	agents  map[string]*agent
	pending map[string]*pending
	routes  map[string]*serverRoute
	tunnels int // open requests including their reserved work connections
	active  int
}

func NewServer(c ServerConfig) (*Server, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	routes := make(map[string]*serverRoute, len(c.Routes))
	for _, route := range c.Routes {
		routes[route.ID] = &serverRoute{
			clientToken: sha256.Sum256([]byte(route.ClientToken)),
			accessToken: sha256.Sum256([]byte(route.AccessToken)),
			maxTunnels:  route.MaxTunnels,
		}
	}
	c.Routes = nil
	return &Server{config: c, agents: map[string]*agent{}, pending: map[string]*pending{}, routes: routes}, nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := s.Listen()
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Listen binds a TLS or plaintext TCP listener according to the configuration.
// The caller must pass the listener to Serve or close it.
func (s *Server) Listen() (net.Listener, error) {
	if s.config.CertFile == "" && s.config.KeyFile == "" {
		ln, err := net.Listen("tcp", s.config.Listen)
		if err == nil {
			log.Print(PlainTCPWarning)
		}
		return ln, err
	}
	cert, err := tls.LoadX509KeyPair(s.config.CertFile, s.config.KeyFile)
	if err != nil {
		return nil, errors.New("cannot load TLS certificate/key")
	}
	return tls.Listen("tcp", s.config.Listen, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
}

// Serve accepts a listener prepared by Listen; exposed for integration tests.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	connections := map[net.Conn]struct{}{}
	// A bounded intake pool can authenticate and reject new requests even when
	// the committed connection budget is full. It cannot add active tunnels.
	maxHandshakes := min(128, max(4, s.config.MaxConnections))
	handshakes := 0
	stopAccept := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer func() {
		stopAccept()
		_ = ln.Close()
		mu.Lock()
		remaining := make([]net.Conn, 0, len(connections))
		for c := range connections {
			remaining = append(remaining, c)
		}
		mu.Unlock()
		for _, c := range remaining {
			_ = c.Close()
		}
		wg.Wait()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		mu.Lock()
		if handshakes >= maxHandshakes || len(connections)-s.config.MaxConnections >= maxHandshakes || ctx.Err() != nil {
			mu.Unlock()
			_ = conn.Close()
			continue
		}
		connections[conn] = struct{}{}
		handshakes++
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			handshaking := true
			defer func() {
				_ = conn.Close()
				mu.Lock()
				if handshaking {
					handshakes--
				}
				delete(connections, conn)
				mu.Unlock()
			}()
			s.handle(conn, func() {
				mu.Lock()
				handshaking = false
				handshakes--
				mu.Unlock()
			})
		}()
	}
}

func reject(c net.Conn, code string) {
	_ = WriteMessage(c, Message{Kind: "error", Error: code})
}

func (s *Server) handle(c net.Conn, admitted func()) {
	deadline := time.Now().Add(handshakeTimeout)
	_ = c.SetDeadline(deadline)
	m, err := ReadMessage(c)
	if err != nil {
		return
	}
	rejectFrame := func(code string) {
		// A negotiated work stream only reads target data after its first
		// frame. Close rejected work streams without injecting a Page frame.
		if m.Kind != "work" || !m.DialFeedback {
			reject(c, code)
		}
	}
	route := s.routes[m.ClientID]
	if route == nil {
		rejectFrame("unauthorized")
		return
	}
	switch m.Kind {
	case "register":
		if !matchesToken(m.Token, route.clientToken) {
			reject(c, "unauthorized")
			return
		}
		s.register(c, m, deadline, admitted)
	case "open":
		if !matchesToken(m.Token, route.accessToken) {
			reject(c, "unauthorized")
			return
		}
		if m.Host == "" || len(m.Host) > 253 || m.Port == 0 {
			reject(c, "invalidTarget")
			return
		}
		s.open(c, m, deadline, admitted)
	case "work":
		if !matchesToken(m.Token, route.clientToken) {
			rejectFrame("unauthorized")
			return
		}
		s.mu.Lock()
		p := s.claimPendingLocked(m.ID, s.agents[m.ClientID])
		s.mu.Unlock()
		if p == nil {
			rejectFrame("unknownRequest")
			return
		}
		admitted()
		p.ready <- work{conn: c, error: m.Error}
		<-p.closed
	default:
		reject(c, "invalidKind")
	}
}

// Only the agent owning this live request can complete it, and only once.
func (s *Server) claimPendingLocked(id string, a *agent) *pending {
	p := s.pending[id]
	if p == nil || p.agent != a || a.ctx.Err() != nil || !time.Now().Before(p.deadline) {
		return nil
	}
	delete(s.pending, id)
	return p
}

func (s *Server) register(c net.Conn, m Message, deadline time.Time, admitted func()) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	id := m.ClientID
	limit := max(0, m.MaxTunnels)
	if configured := s.routes[id].maxTunnels; configured > 0 && (limit == 0 || configured < limit) {
		limit = configured
	}
	a := &agent{
		conn: c, writer: newControlWriter(c), ctx: ctx,
		address: c.RemoteAddr().String(), maxTunnels: limit, dialFeedback: m.DialFeedback,
		version: cleanClientVersion(m.ClientVersion),
	}
	if a.version == "" {
		a.version = LegacyClientVersion
	}
	s.mu.Lock()
	if s.agents[id] != nil {
		s.mu.Unlock()
		reject(c, "clientAlreadyOnline")
		return
	}
	if len(s.agents)+2*s.tunnels >= s.config.MaxConnections {
		s.routes[id].busyRejects++
		s.mu.Unlock()
		reject(c, "gatewayBusy")
		return
	}
	s.agents[id] = a
	s.mu.Unlock()
	admitted()
	defer func() {
		cancel()
		s.mu.Lock()
		delete(s.agents, id)
		s.mu.Unlock()
	}()
	if a.writer.send(Message{Kind: "registered", DialFeedback: a.dialFeedback}, deadline) != nil {
		return
	}
	s.mu.Lock()
	a.online = true
	a.connectedAt = time.Now().UTC()
	s.mu.Unlock()
	for {
		_ = c.SetReadDeadline(time.Now().Add(35 * time.Second))
		m, err := ReadMessage(c)
		if err != nil {
			return
		}
		switch {
		case m.Kind == "ping":
			s.mu.Lock()
			a.lastHeartbeatAt = time.Now().UTC()
			s.mu.Unlock()
			if a.writer.send(Message{Kind: "pong"}, time.Now().Add(handshakeTimeout)) != nil {
				return
			}
		case a.dialFeedback && m.Kind == "dialFailed":
			s.mu.Lock()
			p := s.claimPendingLocked(m.ID, a)
			s.mu.Unlock()
			if p != nil {
				p.ready <- work{error: dialFailureCode(m.Error)}
			}
		default:
			return
		}
	}
}

func (s *Server) open(c net.Conn, m Message, deadline time.Time, admitted func()) {
	started := time.Now()
	deadline = withTimeoutHint(deadline, m.TimeoutMS)
	_ = c.SetWriteDeadline(deadline)
	// Leave time to send the outcome before the caller's write budget expires.
	remaining := time.Until(deadline)
	if remaining < minDialBudget {
		reject(c, "targetTimeout")
		return
	}
	pairDeadline := deadline.Add(-min(100*time.Millisecond, remaining/10))
	route := s.routes[m.ClientID]
	s.mu.Lock()
	a := s.agents[m.ClientID]
	if a == nil || !a.online || a.ctx.Err() != nil {
		s.mu.Unlock()
		reject(c, "clientOffline")
		return
	}
	code := ""
	if a.maxTunnels > 0 && a.active+a.pending >= a.maxTunnels {
		code = "clientBusy"
	} else if s.tunnels >= (s.config.MaxConnections-len(s.agents))/2 {
		code = "gatewayBusy"
	}
	if code != "" {
		route.busyRejects++
		s.mu.Unlock()
		reject(c, code)
		return
	}
	id := randomID()
	p := &pending{agent: a, deadline: pairDeadline, ready: make(chan work, 1), closed: make(chan struct{})}
	a.pending++
	s.tunnels++
	s.pending[id] = p
	s.mu.Unlock()
	admitted()
	active := false
	defer func() {
		close(p.closed)
		s.mu.Lock()
		delete(s.pending, id)
		s.tunnels--
		if active {
			a.active--
			s.active--
		} else {
			a.pending--
		}
		s.mu.Unlock()
	}()
	request := Message{Kind: "dial", ID: id, Host: m.Host, Port: m.Port}
	if a.dialFeedback {
		request.TimeoutMS = max(1, time.Until(pairDeadline).Milliseconds())
	}
	if err := a.writer.send(request, pairDeadline); err != nil {
		if errors.Is(err, errControlWriteExpired) {
			reject(c, "targetTimeout")
			return
		}
		reject(c, "clientOffline")
		_ = a.conn.Close()
		return
	}
	timer := time.NewTimer(time.Until(pairDeadline))
	defer timer.Stop()
	select {
	case w := <-p.ready:
		if w.error != "" {
			code := dialFailureCode(w.error)
			if code == "clientBusy" {
				s.mu.Lock()
				route.busyRejects++
				s.mu.Unlock()
			}
			reject(c, code)
			return
		}
		if a.ctx.Err() != nil {
			reject(c, "clientOffline")
			return
		}
		if WriteMessage(c, Message{Kind: "ready"}) != nil {
			return
		}
		s.mu.Lock()
		active = true
		a.pending--
		a.active++
		s.active++
		route.lastOpenMicros = time.Since(started).Microseconds()
		s.mu.Unlock()
		_ = c.SetDeadline(time.Time{})
		_ = w.conn.SetDeadline(time.Time{})
		stop := context.AfterFunc(a.ctx, func() { _ = c.Close(); _ = w.conn.Close() })
		defer stop()
		relay(c, w.conn)
	case <-timer.C:
		reject(c, "targetTimeout")
	case <-a.ctx.Done():
		reject(c, "clientOffline")
	}
}
