package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Client struct {
	config ClientConfig
	tls    *tls.Config
}

func NewClient(c ClientConfig) (*Client, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	var t *tls.Config
	if strings.TrimSpace(c.Fingerprint) != "" {
		var err error
		t, err = PinnedTLS(c.Fingerprint)
		if err != nil {
			return nil, err
		}
	}
	return &Client{config: c, tls: t}, nil
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	network := &net.Dialer{Timeout: handshakeTimeout, KeepAlive: 30 * time.Second}
	if c.tls == nil {
		return network.DialContext(ctx, "tcp", c.config.Server)
	}
	dialer := tls.Dialer{NetDialer: network, Config: c.tls}
	return dialer.DialContext(ctx, "tcp", c.config.Server)
}

// Run reconnects with bounded exponential backoff. Existing tunnels terminate
// with the control session; they are never silently reattached or replayed.
func (c *Client) Run(ctx context.Context) error {
	delay := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		err := c.runOnce(ctx)
		if ctx.Err() != nil {
			break
		}
		if err != nil {
			log.Print("Page client disconnected; retrying")
		}
		if time.Since(started) > time.Minute {
			delay = time.Second
		}
		timer := time.NewTimer(delay)
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
		return err
	}
	var workers sync.WaitGroup
	defer func() { cancel(); _ = conn.Close(); workers.Wait() }()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err = WriteMessage(conn, Message{Kind: "register", ClientID: c.config.ID, Token: c.config.Token}); err != nil {
		return err
	}
	m, err := ReadMessage(conn)
	if err != nil || m.Kind != "registered" {
		return errors.New("registration rejected")
	}
	_ = conn.SetWriteDeadline(time.Time{})
	log.Print("Page client registered")
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = conn.SetWriteDeadline(time.Now().Add(handshakeTimeout))
				if WriteMessage(conn, Message{Kind: "ping"}) != nil {
					_ = conn.Close()
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
			return err
		}
		if m.Kind == "pong" {
			continue
		}
		if m.Kind != "dial" || len(m.ID) != 64 {
			return errors.New("invalid control message")
		}
		select {
		case slots <- struct{}{}:
			workers.Add(1)
			go func() { defer workers.Done(); defer func() { <-slots }(); c.work(ctx, m) }()
		default:
			// Server times out requests beyond the bound; don't create more goroutines.
		}
	}
}

func (c *Client) allowed(host string, port uint16) bool {
	if port == 0 {
		return false
	}
	address := net.JoinHostPort(strings.ToLower(host), strconv.Itoa(int(port)))
	for _, allowed := range c.config.Allow {
		if allowed == "*" || address == strings.ToLower(allowed) {
			return true
		}
	}
	return false
}

func (c *Client) work(ctx context.Context, m Message) {
	conn, err := c.dial(ctx)
	if err != nil {
		return
	}
	defer conn.Close()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()
	reply := Message{Kind: "work", ClientID: c.config.ID, Token: c.config.Token, ID: m.ID}
	var target net.Conn
	if !c.allowed(m.Host, m.Port) {
		reply.Error = "targetDenied"
	} else {
		dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		target, err = dialer.DialContext(ctx, "tcp", net.JoinHostPort(m.Host, strconv.Itoa(int(m.Port))))
		if err != nil {
			reply.Error = "targetUnavailable"
		}
	}
	if target != nil {
		defer target.Close()
	}
	_ = conn.SetWriteDeadline(time.Now().Add(handshakeTimeout))
	if WriteMessage(conn, reply) != nil || reply.Error != "" {
		return
	}
	_ = conn.SetWriteDeadline(time.Time{})
	// No response frame on work streams; the next byte belongs to the target.
	go func() {
		select {
		case <-ctx.Done():
			_ = target.Close()
		case <-stop:
		}
	}()
	relay(conn, target)
}
