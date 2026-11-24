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
