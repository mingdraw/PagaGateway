package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirectTokenConfiguration(t *testing.T) {
	for _, length := range []int{1, 257} {
		name := "short"
		if length > 256 {
			name = "long"
		}
		t.Run(name, func(t *testing.T) {
			clientToken := strings.Repeat("c", length)
			accessToken := strings.Repeat("a", length)
			load := func(name string, value any, destination any) {
				t.Helper()
				data, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), name+".json")
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				if err := LoadConfig(path, destination); err != nil {
					t.Fatal(err)
				}
			}
			var server ServerConfig
			load("server", map[string]any{
				"listen": "127.0.0.1:7443", "cert_file": "server.crt", "key_file": "server.key",
				"routes": []map[string]string{{"id": "office", "client_token": clientToken, "access_token": accessToken}},
			}, &server)
			if err := server.validate(); err != nil {
				t.Fatal(err)
			}
			if server.Routes[0].ClientToken != clientToken || server.Routes[0].AccessToken != accessToken {
				t.Fatal("server tokens must use their literal configuration values")
			}
			var client ClientConfig
			load("client", map[string]any{
				"server": "127.0.0.1:7443", "id": "office", "token": clientToken,
				"allowed_targets": []string{"127.0.0.1:22"},
			}, &client)
			if err := client.validate(); err != nil {
				t.Fatal(err)
			}
			if client.Token != clientToken {
				t.Fatal("client token must use its literal configuration value")
			}
		})
	}
}

func TestTokenConfigurationRequiresNonemptyDistinctValues(t *testing.T) {
	for _, tokens := range [][2]string{{"", "access"}, {"client", ""}, {"same", "same"}} {
		server := ServerConfig{Listen: "127.0.0.1:7443", CertFile: "server.crt", KeyFile: "server.key", Routes: []Route{{ID: "office", ClientToken: tokens[0], AccessToken: tokens[1]}}}
		if err := server.validate(); err == nil {
			t.Fatal("server accepted missing or identical tokens")
		}
	}
	client := ClientConfig{Server: "127.0.0.1:7443", ID: "office", Allow: []string{"127.0.0.1:22"}}
	if err := client.validate(); err == nil {
		t.Fatal("client accepted a missing token")
	}
}

func TestAllowedTargetsConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name  string
		allow []string
		valid bool
	}{
		{"wildcard", []string{"*"}, true},
		{"exact", []string{"127.0.0.1:22", "Server.LAN:3389", "[::1]:443"}, true},
		{"mixed", []string{"127.0.0.1:22", "*"}, true},
		{"empty", nil, false},
		{"invalid address with wildcard", []string{"*", "invalid"}, false},
		{"wildcard port", []string{"127.0.0.1:*"}, false},
		{"zero port", []string{"127.0.0.1:0"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := ClientConfig{Server: "127.0.0.1:7443", ID: "office", Token: "client", Allow: tc.allow}
			if err := client.validate(); (err == nil) != tc.valid {
				t.Fatalf("unexpected allowed_targets validation: %v", err)
			}
		})
	}
}

func TestOptionalTLSConfiguration(t *testing.T) {
	for _, test := range []struct {
		name, cert, key string
		valid           bool
	}{
		{"plaintext", "", "", true},
		{"tls", "server.crt", "server.key", true},
		{"missing key", "server.crt", "", false},
		{"missing certificate", "", "server.key", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := ServerConfig{Listen: "127.0.0.1:0", CertFile: test.cert, KeyFile: test.key, Routes: []Route{{ID: "office", ClientToken: "client", AccessToken: "access"}}}
			if _, err := NewServer(config); (err == nil) != test.valid {
				t.Fatalf("unexpected certificate configuration result: %v", err)
			}
		})
	}
	for _, fingerprint := range []string{"", " \t", strings.Repeat("ab", 32), "invalid", "SHA256:"} {
		client, err := NewClient(ClientConfig{Server: "127.0.0.1:7443", ID: "office", Token: "client", Allow: []string{"*"}, Fingerprint: fingerprint})
		plain := strings.TrimSpace(fingerprint) == ""
		valid := plain || fingerprint == strings.Repeat("ab", 32)
		if (err == nil) != valid {
			t.Fatalf("unexpected fingerprint validation for %q: %v", fingerprint, err)
		}
		if err == nil && (client.tls == nil) != plain {
			t.Fatal("fingerprint did not select the configured transport")
		}
	}
}
