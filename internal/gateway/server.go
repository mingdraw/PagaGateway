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

const defaultProbeTimeout = 2 * time.Second

type livenessProbe struct {
	id    string
	done  chan struct{}
	alive bool
}

type agent struct {
	conn         net.Conn
	writer       *controlWriter
	ctx          context.Context
	cancel       context.CancelFunc
	dialFeedback bool
	serverPing   bool
	maxTunnels   int
	version      string
	probeMu      sync.Mutex
	probe        *livenessProbe
	// Lifecycle and counters are protected by Server.mu.
	online          bool
	pending         int
	active          int
	address         string
	connectedAt     time.Time
	lastHeartbeatAt time.Time
}

func (a *agent) finishProbe(p *livenessProbe, alive bool) {
	a.probeMu.Lock()
	if a.probe == p {
		p.alive = alive
		a.probe = nil
		close(p.done)
	}
	a.probeMu.Unlock()
}

func (a *agent) completeProbe(id string) {
	a.probeMu.Lock()
	p := a.probe
	if p != nil && (id == "" || p.id == id) {
		p.alive = true
		a.probe = nil
		close(p.done)
	}
	a.probeMu.Unlock()
}

func (a *agent) failPendingProbe() {
	a.probeMu.Lock()
	p := a.probe
	if p != nil {
		p.alive = false
		a.probe = nil
		close(p.done)
	}
	a.probeMu.Unlock()
}

func (a *agent) probeAlive(deadline time.Time) bool {
	if !a.serverPing {
		return a.ctx.Err() == nil
	}
	if a.ctx.Err() != nil {
		return false
	}
	a.probeMu.Lock()
	p := a.probe
	leader := p == nil
	if leader {
		p = &livenessProbe{id: randomID(), done: make(chan struct{})}
		a.probe = p
	}
	a.probeMu.Unlock()
	if leader {
		go func() {
			if err := a.writer.sendPriority(Message{Kind: "ping", ID: p.id}, deadline); err != nil {
				a.finishProbe(p, false)
				return
			}
			remaining := time.Until(deadline)
			if remaining <= 0 {
				a.finishProbe(p, false)
				return
			}
			timer := time.NewTimer(remaining)
			defer timer.Stop()
			select {
			case <-p.done:
			case <-a.ctx.Done():
				a.finishProbe(p, false)
			case <-timer.C:
				a.finishProbe(p, false)
			}
		}()
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		select {
		case <-p.done:
			return p.alive
		default:
			return false
		}
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-p.done:
		return p.alive
	case <-a.ctx.Done():
		return false
	case <-timer.C:
		return false
	}
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
	config       ServerConfig
	probeTimeout time.Duration
	mu           sync.Mutex
	agents       map[string]*agent
	pending      map[string]*pending
	routes       map[string]*serverRoute
	tunnels      int // open requests including their reserved work connections
	active       int
}

func (s *Server) livenessProbeTimeout() time.Duration {
	if s.probeTimeout > 0 {
		return s.probeTimeout
	}
	return defaultProbeTimeout
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
	var acceptDelay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if !isTransientAcceptError(err) {
				return err
			}
			if acceptDelay == 0 {
				acceptDelay = 5 * time.Millisecond
			} else {
				acceptDelay = min(acceptDelay*2, time.Second)
			}
			timer := time.NewTimer(acceptDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
			continue
		}
		acceptDelay = 0
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

func isTransientAcceptError(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	var temp interface{ Temporary() bool }
	if errors.As(err, &temp) && temp.Temporary() {
		return true
	}
	return isTransientAcceptErrno(err)
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
	id := m.ClientID
	limit := max(0, m.MaxTunnels)
	if configured := s.routes[id].maxTunnels; configured > 0 && (limit == 0 || configured < limit) {
		limit = configured
	}
	a := &agent{
		conn: c, ctx: ctx, cancel: cancel,
		address: c.RemoteAddr().String(), maxTunnels: limit,
		dialFeedback: m.DialFeedback, serverPing: m.ServerPing,
		version: cleanClientVersion(m.ClientVersion),
	}
	if a.version == "" {
		a.version = LegacyClientVersion
	}
	var evicted *agent
	s.mu.Lock()
	existing := s.agents[id]
	if existing != nil {
		switch {
		case existing.ctx.Err() != nil:
			// Previous control session is already tearing down; reuse its agent slot.
			evicted = existing
			s.agents[id] = a
		case existing.online && existing.serverPing:
			s.mu.Unlock()
			probeDeadline := time.Now().Add(s.livenessProbeTimeout())
			if deadline.Before(probeDeadline) {
				probeDeadline = deadline
			}
			if existing.probeAlive(probeDeadline) {
				cancel()
				reject(c, "clientAlreadyOnline")
				return
			}
			s.mu.Lock()
			switch s.agents[id] {
			case existing:
				evicted = existing
				existing.cancel()
				s.agents[id] = a
			case nil:
				if len(s.agents)+2*s.tunnels >= s.config.MaxConnections {
					s.routes[id].busyRejects++
					s.mu.Unlock()
					cancel()
					reject(c, "gatewayBusy")
					return
				}
				s.agents[id] = a
			default:
				s.mu.Unlock()
				cancel()
				reject(c, "clientAlreadyOnline")
				return
			}
		default:
			// Legacy Clients do not understand Server-initiated ping frames.
			s.mu.Unlock()
			cancel()
			reject(c, "clientAlreadyOnline")
			return
		}
	} else {
		if len(s.agents)+2*s.tunnels >= s.config.MaxConnections {
			s.routes[id].busyRejects++
			s.mu.Unlock()
			cancel()
			reject(c, "gatewayBusy")
			return
		}
		s.agents[id] = a
	}
	s.mu.Unlock()
	if evicted != nil {
		evicted.cancel()
		_ = evicted.conn.Close()
	}
	a.writer = newControlWriter(ctx, c, func(error) {
		cancel()
		_ = c.Close()
	})
	admitted()
	defer func() {
		cancel()
		a.failPendingProbe()
		_ = c.Close()
		a.writer.wait()
		s.mu.Lock()
		if s.agents[id] == a {
			delete(s.agents, id)
		}
		s.mu.Unlock()
	}()
	if a.writer.send(Message{Kind: "registered", DialFeedback: a.dialFeedback, ServerPing: a.serverPing}, deadline) != nil {
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
			a.completeProbe("")
			if !a.writer.enqueuePriority(Message{Kind: "pong"}, time.Now().Add(handshakeTimeout)) {
				return
			}
		case a.serverPing && m.Kind == "pong":
			s.mu.Lock()
			a.lastHeartbeatAt = time.Now().UTC()
			s.mu.Unlock()
			a.completeProbe(m.ID)
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
		a.cancel()
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
