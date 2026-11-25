package gateway

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestAllowedTargetsMatching(t *testing.T) {
	for _, tc := range []struct {
		name  string
		allow []string
		host  string
		port  uint16
		want  bool
	}{
		{"wildcard IPv4", []string{"*"}, "10.0.0.20", 3389, true},
		{"wildcard IPv6", []string{"*"}, "2001:db8::1", 443, true},
		{"wildcard domain", []string{"*"}, "service.internal", 65535, true},
		{"wildcard zero port", []string{"*"}, "127.0.0.1", 0, false},
		{"exact case insensitive", []string{"Server.LAN:22"}, "server.lan", 22, true},
		{"exact wrong port", []string{"127.0.0.1:22"}, "127.0.0.1", 3389, false},
		{"exact wrong host", []string{"127.0.0.1:22"}, "127.0.0.2", 22, false},
		{"ipv4 cidr match", []string{"10.20.0.0/16:22"}, "10.20.5.9", 22, true},
		{"ipv4 cidr miss", []string{"10.20.0.0/16:22"}, "10.21.0.1", 22, false},
		{"ipv4 cidr does not match domain", []string{"10.20.0.0/16:22"}, "db.internal", 22, false},
		{"ipv6 cidr match", []string{"[2001:db8::/32]:443"}, "2001:db8:abcd::1", 443, true},
		{"ipv6 cidr miss", []string{"[2001:db8::/32]:443"}, "2001:db9::1", 443, false},
		{"wildcard port match", []string{"10.0.0.0/8:*"}, "10.1.2.3", 5432, true},
		{"wildcard port rejects zero", []string{"10.0.0.0/8:*"}, "10.1.2.3", 0, false},
		{"port range bounds", []string{"10.0.0.1:8000-8099"}, "10.0.0.1", 8000, true},
		{"port range upper", []string{"10.0.0.1:8000-8099"}, "10.0.0.1", 8099, true},
		{"port range below", []string{"10.0.0.1:8000-8099"}, "10.0.0.1", 7999, false},
		{"port range above", []string{"10.0.0.1:8000-8099"}, "10.0.0.1", 8100, false},
		{"domain wildcard subdomain", []string{"*.internal:5432"}, "db.internal", 5432, true},
		{"domain wildcard nested", []string{"*.internal:5432"}, "a.b.INTERNAL.", 5432, true},
		{"domain wildcard excludes apex", []string{"*.internal:5432"}, "internal", 5432, false},
		{"domain wildcard boundary", []string{"*.internal:5432"}, "evilinternal", 5432, false},
		{"any host specific port", []string{"*:443"}, "api.example.com", 443, true},
		{"any host wrong port", []string{"*:443"}, "api.example.com", 80, false},
		{"ipv6 zone rejected", []string{"*"}, "::1%lo0", 22, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewClient(ClientConfig{Server: "127.0.0.1:1", ID: "office", Token: "fixture-token", Allow: tc.allow})
			if err != nil {
				t.Fatal(err)
			}
			if got := client.allowed(tc.host, tc.port); got != tc.want {
				t.Fatalf("allowed = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClientReportsTLSAndRegistrationFailures(t *testing.T) {
	f := setup(t)
	f.startClient(t, []string{"*"})
	const wrongToken = "unrecognized-registration-token"
	for _, tc := range []struct {
		name, fingerprint, token string
		want                     string
	}{
		{"wrong pin", strings.Repeat("0", 64), testClientToken, "证书指纹不匹配"},
		{"unauthorized", f.fingerprint, wrongToken, "注册被拒绝（unauthorized）"},
		{"already online", f.fingerprint, testClientToken, "相同 Client ID 已在线"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewClient(ClientConfig{Server: f.address, Fingerprint: tc.fingerprint, ID: "office", Token: tc.token, Allow: []string{"*"}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err = c.runOnce(ctx)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("registration failure = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), wrongToken) {
				t.Fatal("registration failure exposed the token")
			}
		})
	}
}

func TestClientReportsOnlySafeRegistrationDetails(t *testing.T) {
	const token = "private-registration-token"
	for _, tc := range []struct {
		name string
		send func(net.Conn) error
		want string
	}{
		{"closed before response", func(net.Conn) error { return nil }, "读取注册响应失败：对端关闭了连接"},
		{"unrecognized error code", func(conn net.Conn) error {
			return WriteMessage(conn, Message{Kind: "error", Error: token + "\npeer-supplied diagnostic"})
		}, "Server 拒绝注册（未知错误码）"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err = ReadMessage(conn); err == nil {
					err = tc.send(conn)
				}
				done <- err
			}()
			c, err := NewClient(ClientConfig{Server: listener.Addr().String(), ID: "office", Token: token, Allow: []string{"*"}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err = c.runOnce(ctx)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("registration failure = %v, want %q", err, tc.want)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestClientServerDNSCacheAndFallback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	c, err := NewClient(ClientConfig{
		Server: "localhost:" + port,
		ID:     "office",
		Token:  "fixture-token",
		Allow:  []string{"*"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.serverIsIP {
		t.Fatal("localhost should use DNS cache path")
	}
	// Seed cache with a dead port; dial must invalidate it and fall back cleanly.
	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := deadLn.Addr().String()
	_ = deadLn.Close()
	c.dnsMu.Lock()
	c.cachedServer = deadAddr
	c.cachedServerAt = time.Now()
	c.dnsMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := c.dial(ctx)
	if err != nil {
		t.Fatalf("fallback dial failed: %v", err)
	}
	_ = conn.Close()

	c.dnsMu.Lock()
	gotCached := c.cachedServer
	c.dnsMu.Unlock()
	if gotCached == "" || gotCached == deadAddr {
		t.Fatalf("expected refreshed cached server address, got %q", gotCached)
	}
}
