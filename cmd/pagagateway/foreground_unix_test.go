//go:build linux || darwin

package main

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mingdraw/PagaGateway/internal/gateway"
)

func TestForegroundCommands(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "foreground deployment with spaces")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "pagagateway")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	certificate := exec.Command(binary, "certificate", "-host", "127.0.0.1")
	certificate.Dir = directory
	output, err := certificate.CombinedOutput()
	if err != nil {
		t.Fatalf("certificate: %v\n%s", err, output)
	}
	fingerprint := strings.TrimSpace(strings.TrimPrefix(string(output), "Server certificate "))
	writeConfig := func(name string, value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, mode := range []struct {
		name, action string
		plain        bool
	}{
		{"tls-run", "run", false}, {"tls-legacy", "", false},
		{"tcp-run", "run", true}, {"tcp-legacy", "", true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			reserve, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := reserve.Addr().String()
			reserve.Close()
			serverConfig := gateway.ServerConfig{Listen: address, CertFile: "server.crt", KeyFile: "server.key", Routes: []gateway.Route{{ID: "test", ClientToken: "foreground-client", AccessToken: "foreground-access"}}}
			clientConfig := gateway.ClientConfig{Server: address, Fingerprint: fingerprint, ID: "test", Token: "foreground-client", Allow: []string{"*"}}
			if mode.plain {
				serverConfig.CertFile, serverConfig.KeyFile = "", ""
				clientConfig.Fingerprint = ""
			}
			writeConfig("server.json", serverConfig)
			writeConfig("client.json", clientConfig)
			start := func(role, readyText string) func(os.Signal) {
				t.Helper()
				logPath := filepath.Join(directory, mode.name+"-"+role+"-captured.log")
				logFile, err := os.Create(logPath)
				if err != nil {
					t.Fatal(err)
				}
				args := []string{role}
				if mode.action != "" {
					args = append(args, mode.action)
				}
				args = append(args, "-config", role+".json")
				cmd := exec.Command(binary, args...)
				cmd.Dir, cmd.Stdout, cmd.Stderr = directory, logFile, logFile
				if err := cmd.Start(); err != nil {
					logFile.Close()
					t.Fatal(err)
				}
				done := make(chan struct{})
				var waitErr error
				go func() { waitErr = cmd.Wait(); close(done) }()
				t.Cleanup(func() {
					select {
					case <-done:
					default:
						_ = cmd.Process.Kill()
						<-done
					}
					logFile.Close()
				})
				deadline := time.Now().Add(5 * time.Second)
				for {
					select {
					case <-done:
						data, _ := os.ReadFile(logPath)
						t.Fatalf("%s exited instead of staying in foreground: %v\n%s", role, waitErr, data)
					default:
					}
					data, err := os.ReadFile(logPath)
					if err == nil && strings.Contains(string(data), readyText) {
						if strings.Contains(string(data), gateway.PlainTCPWarning) != (mode.plain && role == "server") {
							t.Fatalf("%s plaintext risk warning does not match role and transport mode", role)
						}
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("%s did not become ready\n%s", role, data)
					}
					time.Sleep(10 * time.Millisecond)
				}
				return func(signal os.Signal) {
					t.Helper()
					if err := cmd.Process.Signal(signal); err != nil {
						t.Fatal(err)
					}
					select {
					case <-done:
						if waitErr != nil {
							t.Fatalf("%s did not exit cleanly on %s: %v", role, signal, waitErr)
						}
					case <-time.After(5 * time.Second):
						t.Fatalf("%s ignored %s", role, signal)
					}
				}
			}
			stopServer := start("server", "Page server listening")
			stopClient := start("client", "Page client registered")
			for _, name := range []string{"server.json.pid", "client.json.pid", "server.log", "client.log"} {
				if _, err := os.Stat(filepath.Join(directory, name)); !os.IsNotExist(err) {
					t.Fatalf("foreground mode created background file %s: %v", name, err)
				}
			}
			signal := os.Signal(syscall.SIGTERM)
			if mode.action == "" {
				signal = os.Interrupt
			}
			stopServer(signal)
			// The Client must also stop cleanly while reconnecting after Server loss.
			stopClient(signal)
			listener, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatalf("foreground Server retained its listening port: %v", err)
			}
			listener.Close()
		})
	}
}
