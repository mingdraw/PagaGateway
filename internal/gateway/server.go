package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"sync"
	"time"
)

type agent struct {
	conn net.Conn
	mu   sync.Mutex
	done chan struct{}
	// Connection metadata is protected by Server.mu.
	address         string
	connectedAt     time.Time
	lastHeartbeatAt time.Time
}

func (a *agent) send(m Message) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.conn.SetWriteDeadline(time.Now().Add(handshakeTimeout))
	return WriteMessage(a.conn, m)
}

type work struct {
	conn  net.Conn
	error string
	done  chan struct{}
}
type pending struct {
	agent  *agent
	ready  chan work
	closed chan struct{}
}

type Server struct {
	config  ServerConfig
	mu      sync.Mutex
	agents  map[string]*agent
	pending map[string]*pending
}

func NewServer(c ServerConfig) (*Server, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &Server{config: c, agents: map[string]*agent{}, pending: map[string]*pending{}}, nil
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
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer ln.Close()
	var wg sync.WaitGroup
	var mu sync.Mutex
	connections := map[net.Conn]bool{}
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
			mu.Lock()
			for c := range connections {
				_ = c.Close()
			}
			mu.Unlock()
		case <-stopped:
		}
	}()
	defer func() {
		cancel()
		mu.Lock()
		for c := range connections {
			_ = c.Close()
		}
		mu.Unlock()
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
		if len(connections) >= s.config.MaxConnections || ctx.Err() != nil {
			mu.Unlock()
			_ = conn.Close()
			continue
		}
		connections[conn] = true
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { _ = conn.Close(); mu.Lock(); delete(connections, conn); mu.Unlock() }()
			s.handle(conn)
		}()
	}
}

func reject(c net.Conn, code string) {
	_ = c.SetWriteDeadline(time.Now().Add(handshakeTimeout))
	_ = WriteMessage(c, Message{Kind: "error", Error: code})
}

func (s *Server) handle(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	m, err := ReadMessage(c)
	if err != nil {
		return
	}
	var route *Route
	for i := range s.config.Routes {
		if s.config.Routes[i].ID == m.ClientID {
			route = &s.config.Routes[i]
			break
		}
	}
	if route == nil {
		reject(c, "unauthorized")
		return
	}
	switch m.Kind {
	case "register":
		if !equalToken(m.Token, route.ClientToken) {
			reject(c, "unauthorized")
			return
		}
		s.register(c, m.ClientID)
	case "open":
		if !equalToken(m.Token, route.AccessToken) {
			reject(c, "unauthorized")
			return
		}
		if m.Host == "" || len(m.Host) > 253 || m.Port == 0 {
			reject(c, "invalidTarget")
			return
		}
		s.open(c, m)
	case "work":
		if !equalToken(m.Token, route.ClientToken) {
			reject(c, "unauthorized")
			return
		}
		s.mu.Lock()
		p := s.pending[m.ID]
		if p != nil && p.agent == s.agents[m.ClientID] {
			delete(s.pending, m.ID)
		} else {
			p = nil
		}
		s.mu.Unlock()
		if p == nil {
			reject(c, "unknownRequest")
			return
		}
		w := work{conn: c, error: m.Error, done: make(chan struct{})}
		select {
		case p.ready <- w:
			select {
			case <-w.done:
			case <-p.closed:
			}
		case <-p.closed:
		}
	default:
		reject(c, "invalidKind")
	}
}

func (s *Server) register(c net.Conn, id string) {
	a := &agent{conn: c, done: make(chan struct{}), address: c.RemoteAddr().String(), connectedAt: time.Now().UTC()}
	s.mu.Lock()
	if s.agents[id] != nil {
		s.mu.Unlock()
		reject(c, "clientAlreadyOnline")
		return
	}
	s.agents[id] = a
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.agents, id)
		close(a.done)
		s.mu.Unlock()
	}()
	if a.send(Message{Kind: "registered"}) != nil {
		return
	}
	for {
		_ = c.SetReadDeadline(time.Now().Add(35 * time.Second))
		m, err := ReadMessage(c)
		if err != nil || m.Kind != "ping" {
			return
		}
		s.mu.Lock()
		a.lastHeartbeatAt = time.Now().UTC()
		s.mu.Unlock()
		if a.send(Message{Kind: "pong"}) != nil {
			return
		}
	}
}

func (s *Server) open(c net.Conn, m Message) {
	s.mu.Lock()
	a := s.agents[m.ClientID]
	if a == nil {
		s.mu.Unlock()
		reject(c, "clientOffline")
		return
	}
	id := randomID()
	p := &pending{agent: a, ready: make(chan work), closed: make(chan struct{})}
	s.pending[id] = p
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.pending, id); s.mu.Unlock(); close(p.closed) }()
	if a.send(Message{Kind: "dial", ID: id, Host: m.Host, Port: m.Port}) != nil {
		_ = a.conn.Close()
		reject(c, "clientOffline")
		return
	}
	timer := time.NewTimer(handshakeTimeout)
	defer timer.Stop()
	select {
	case w := <-p.ready:
		defer close(w.done)
		if w.error != "" {
			code := "targetUnavailable"
			if w.error == "targetDenied" {
				code = "targetDenied"
			}
			reject(c, code)
			return
		}
		if WriteMessage(c, Message{Kind: "ready"}) != nil {
			return
		}
		_ = c.SetDeadline(time.Time{})
		_ = w.conn.SetDeadline(time.Time{})
		finished := make(chan struct{})
		defer close(finished)
		go func() {
			select {
			case <-a.done:
				_ = c.Close()
				_ = w.conn.Close()
			case <-finished:
			}
		}()
		relay(c, w.conn)
	case <-timer.C:
		reject(c, "targetTimeout")
	case <-a.done:
		reject(c, "clientOffline")
	}
}
