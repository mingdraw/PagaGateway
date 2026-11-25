package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const serverDNSTTL = 30 * time.Second

type Client struct {
	config     ClientConfig
	tls        *tls.Config
	acl        *targetACL
	serverIsIP bool

	dnsMu          sync.Mutex
	cachedServer   string
	cachedServerAt time.Time

	statusMu      sync.RWMutex
	status        ClientStatus
	lastTunnelLog time.Time
}

func NewClient(c ClientConfig) (*Client, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	acl, err := compileTargetACL(c.Allow)
	if err != nil {
		return nil, err
	}
	serverHost, _, err := net.SplitHostPort(c.Server)
	if err != nil {
		return nil, errors.New("server must be host:port")
	}
	serverIsIP := net.ParseIP(serverHost) != nil
	var t *tls.Config
	if strings.TrimSpace(c.Fingerprint) != "" {
		t, err = PinnedTLS(c.Fingerprint)
		if err != nil {
			return nil, err
		}
		if !serverIsIP && t.ServerName == "" {
			t.ServerName = serverHost
		}
	}
	return &Client{
		config: c, tls: t, acl: acl, serverIsIP: serverIsIP,
		status: ClientStatus{State: ClientConnecting, MaxTunnels: c.MaxTunnels},
	}, nil
}

func (c *Client) dialTCP(ctx context.Context) (net.Conn, error) {
	network := &net.Dialer{Timeout: handshakeTimeout, KeepAlive: 30 * time.Second}
	if c.serverIsIP {
		return network.DialContext(ctx, "tcp", c.config.Server)
	}
	var cached string
	c.dnsMu.Lock()
	if c.cachedServer != "" && time.Since(c.cachedServerAt) < serverDNSTTL {
		cached = c.cachedServer
	}
	c.dnsMu.Unlock()
	if cached != "" {
		conn, err := network.DialContext(ctx, "tcp", cached)
		if err == nil {
			return conn, nil
		}
		c.dnsMu.Lock()
		if c.cachedServer == cached {
			c.cachedServer = ""
		}
		c.dnsMu.Unlock()
		if ctx.Err() != nil {
			return nil, err
		}
	}
	conn, err := network.DialContext(ctx, "tcp", c.config.Server)
	if err != nil {
		return nil, err
	}
	if remote := conn.RemoteAddr(); remote != nil {
		c.dnsMu.Lock()
		c.cachedServer = remote.String()
		c.cachedServerAt = time.Now()
		c.dnsMu.Unlock()
	}
	return conn, nil
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	raw, err := c.dialTCP(ctx)
	if err != nil || c.tls == nil {
		return raw, err
	}
	tlsConn := tls.Client(raw, c.tls)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tlsConn, nil
}

// Run reconnects with bounded exponential backoff. Existing tunnels terminate
// with the control session; they are never silently reattached or replayed.
func (c *Client) Run(ctx context.Context) error {
	c.setStatus(ClientStatus{State: ClientConnecting})
	delay := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		err := c.runOnce(ctx)
		if ctx.Err() != nil {
			break
		}
		if time.Since(started) > time.Minute {
			delay = time.Second
		}
		wait := delay - time.Duration(rand.Int64N(int64(delay/4)+1))
		if err != nil {
			c.setStatus(ClientStatus{State: ClientReconnecting, LastError: err.Error(), LastErrorAt: time.Now().UTC()})
			log.Printf("Page client retrying in %s: %s", wait.Round(time.Millisecond), err)
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
		if delay < 30*time.Second {
			delay = min(delay*2, 30*time.Second)
		}
	}
	return nil
}

func (c *Client) runOnce(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	conn, err := c.dial(ctx)
	if err != nil {
		cancel()
		// tls.Dialer returns the TCP dial error unchanged if it never reached TLS.
		var opErr *net.OpError
		if c.tls != nil && !(errors.As(err, &opErr) && opErr.Op == "dial") {
			return clientConnectionError("TLS 握手失败", err)
		}
		return clientConnectionError("连接 Server 失败", err)
	}
	var workers sync.WaitGroup
	defer func() { cancel(); _ = conn.Close(); workers.Wait() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	registration := Message{
		Kind: "register", ClientID: c.config.ID, Token: c.config.Token,
		ClientVersion: cleanClientVersion(c.config.BuildVersion),
		MaxTunnels:    c.config.MaxTunnels, DialFeedback: true, ServerPing: true,
	}
	err = WriteMessage(conn, registration)
	if errors.Is(err, errInvalidFrame) && registration.ClientVersion != "" {
		// The version is optional; leave room for the original registration.
		registration.ClientVersion = ""
		err = WriteMessage(conn, registration)
	}
	if err != nil {
		return clientConnectionError("发送注册请求失败", err)
	}
	m, err := ReadMessage(conn)
	if err != nil {
		return clientConnectionError("读取注册响应失败", err)
	}
	if m.Kind == "error" {
		return clientRegistrationError(m.Error)
	}
	if m.Kind != "registered" {
		return errors.New("注册失败：Server 返回了意外的注册响应")
	}
	_ = conn.SetWriteDeadline(time.Time{})
	c.setStatus(ClientStatus{State: ClientConnected})
	log.Print("Page client registered")
	controlWriteErr := make(chan error, 1)
	recordWriteErr := func(failure string, err error) {
		select {
		case controlWriteErr <- clientConnectionError(failure, err):
		default:
		}
		cancel()
		_ = conn.Close()
	}
	writer := newControlWriter(ctx, conn, func(err error) {
		recordWriteErr("控制连接写入失败", err)
	})
	var heartbeatWG sync.WaitGroup
	defer func() {
		cancel()
		_ = conn.Close()
		heartbeatWG.Wait()
		writer.wait()
	}()
	var feedback func(id, code string)
	if m.DialFeedback {
		feedback = func(id, code string) {
			if !writer.enqueuePriority(Message{Kind: "dialFailed", ID: id, Error: code}, time.Now().Add(handshakeTimeout)) {
				if ctx.Err() == nil {
					recordWriteErr("报告工作连接失败时控制连接中断", errControlWriteExpired)
				}
			}
		}
	}
	heartbeatWG.Add(1)
	go func() {
		defer heartbeatWG.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				err := writer.sendPriority(Message{Kind: "ping"}, time.Now().Add(handshakeTimeout))
				if err != nil && !errors.Is(err, errControlWriteExpired) {
					recordWriteErr("发送心跳失败", err)
					return
				}
			}
		}
	}()
	slots := make(chan struct{}, c.config.MaxTunnels)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(35 * time.Second))
		m, err := ReadMessage(conn)
		if err != nil {
			select {
			case err := <-controlWriteErr:
				return err
			default:
				return clientConnectionError("控制连接中断", err)
			}
		}
		switch m.Kind {
		case "pong":
			continue
		case "ping":
			if !writer.enqueuePriority(Message{Kind: "pong", ID: m.ID}, time.Now().Add(handshakeTimeout)) {
				return errors.New("控制连接中断：响应探活失败")
			}
			continue
		case "dial":
			if len(m.ID) != 64 {
				return errors.New("控制连接中断：Server 返回了无效的控制消息")
			}
		default:
			return errors.New("控制连接中断：Server 返回了无效的控制消息")
		}
		select {
		case slots <- struct{}{}:
			workers.Add(1)
			go func() { defer workers.Done(); defer func() { <-slots }(); c.work(ctx, m, feedback) }()
		default:
			c.recordTunnelFailure("clientBusy", errors.New("Client 工作槽已满"))
			if feedback != nil {
				feedback(m.ID, "clientBusy")
			}
		}
	}
}

func (c *Client) allowed(host string, port uint16) bool {
	return c.acl.allowed(host, port)
}

func (c *Client) work(ctx context.Context, m Message, feedback func(string, string)) {
	deadline := withTimeoutHint(time.Now().Add(handshakeTimeout), m.TimeoutMS)
	setup, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	c.changeTunnelCounts(1, 0)
	active := false
	defer func() {
		if active {
			c.changeTunnelCounts(0, -1)
		} else {
			c.changeTunnelCounts(-1, 0)
		}
	}()
	fail := func(code string, reason error) {
		if ctx.Err() == nil {
			c.recordTunnelFailure(code, reason)
			if feedback != nil {
				feedback(m.ID, code)
			}
		}
	}

	// Check ACL and dial the target before opening a work socket. Slow targets
	// cannot hold unauthenticated connections in the Server's intake pool.
	reply := Message{Kind: "work", ClientID: c.config.ID, Token: c.config.Token, ID: m.ID, DialFeedback: feedback != nil}
	var target net.Conn
	if !c.allowed(m.Host, m.Port) {
		reply.Error = "targetDenied"
		fail(reply.Error, errors.New("Client 未允许此目标地址和端口"))
	} else {
		started := time.Now()
		dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		var err error
		target, err = dialer.DialContext(setup, "tcp", net.JoinHostPort(m.Host, strconv.Itoa(int(m.Port))))
		c.recordDialDuration(false, time.Since(started))
		if err != nil {
			reply.Error = "targetUnavailable"
			var netErr net.Error
			if errors.Is(setup.Err(), context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
				reply.Error = "targetTimeout"
			}
			fail(reply.Error, clientConnectionError("连接内网目标失败", err))
		} else {
			defer target.Close()
		}
	}
	if reply.Error != "" && feedback != nil {
		return
	}
	started := time.Now()
	conn, err := c.dial(setup)
	c.recordDialDuration(true, time.Since(started))
	if err != nil {
		fail("workUnavailable", clientConnectionError("工作连接回连 Server 失败", err))
		return
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
		if target != nil {
			_ = target.Close()
		}
	})
	defer stop()
	_ = conn.SetWriteDeadline(deadline)
	if err := WriteMessage(conn, reply); err != nil {
		fail("workUnavailable", clientConnectionError("发送工作连接请求失败", err))
		return
	}
	if reply.Error != "" {
		return
	}
	cancel()
	_ = conn.SetWriteDeadline(time.Time{})
	active = true
	c.changeTunnelCounts(-1, 1)
	// No response frame on work streams; the next byte belongs to the target.
	relay(conn, target)
}
