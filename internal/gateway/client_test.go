package gateway

import "testing"

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
			client := Client{config: ClientConfig{Allow: tc.allow}}
			if got := client.allowed(tc.host, tc.port); got != tc.want {
				t.Fatalf("allowed = %v, want %v", got, tc.want)
			}
		})
	}
}
