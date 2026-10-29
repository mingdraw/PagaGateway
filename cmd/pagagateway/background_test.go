package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mingdraw/PagaGateway/internal/gateway"
)

func TestBackgroundCommands(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "deployment with spaces")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "pagagateway")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	commandIn := func(workingDirectory string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Dir = workingDirectory
		output, err := cmd.CombinedOutput()
		return string(output), err
	}
	command := func(args ...string) (string, error) {
		return commandIn(directory, args...)
	}
	mustRun := func(args ...string) string {
		t.Helper()
		output, err := command(args...)
		if err != nil {
			t.Fatalf("command %v: %v\n%s", args, err, output)
		}
		return output
	}
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
	// Help must succeed before any config exists and must not start a service or
	// generate certificates, including when requested through flag aliases.
	for _, test := range []struct {
		args []string
		want string
	}{
		{nil, "pagagateway server help"},
		{[]string{"help"}, "pagagateway client help"},
		{[]string{"-h"}, "certificate"},
		{[]string{"--help"}, "certificate"},
		{[]string{"server", "help"}, "pagagateway server clients"},
		{[]string{"client", "help"}, "pagagateway client restart"},
		{[]string{"help", "server"}, "server.log"},
		{[]string{"help", "client"}, "client.log"},
		{[]string{"server", "--help"}, "pagagateway server restart"},
		{[]string{"client", "-h"}, "pagagateway client restart"},
		{[]string{"server", "run", "-h"}, "server.log"},
		{[]string{"client", "start", "--help"}, "client.log"},
		{[]string{"certificate", "help"}, "-host"},
		{[]string{"certificate", "-host", "127.0.0.1", "-h"}, "-key"},
	} {
		output := mustRun(test.args...)
		if !strings.Contains(output, test.want) {
			t.Fatalf("help %v missing %q: %s", test.args, test.want, output)
		}
		if len(test.args) > 0 && test.args[0] == "client" && (strings.Contains(output, "clients") || strings.Contains(output, "-json")) {
			t.Fatalf("Client help contains Server-only commands: %s", output)
		}
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(binary) {
		t.Fatalf("help created files before startup: %v %v", entries, err)
	}
	certificateOutput := mustRun("certificate", "-host", "127.0.0.1")
	fingerprint := strings.TrimSpace(strings.TrimPrefix(certificateOutput, "Server certificate "))
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserve.Addr().String()
	reserve.Close()
	serverConfig := gateway.ServerConfig{Listen: address, CertFile: "server.crt", KeyFile: "server.key", Routes: []gateway.Route{
		{ID: "waiting", ClientToken: "waiting-client-token", AccessToken: "waiting-access-token"},
		{ID: "test", ClientToken: "test-client-token", AccessToken: "test-access-token"},
	}}
	writeConfig("running-server.json", serverConfig)
	writeConfig("client.json", gateway.ClientConfig{Server: address, Fingerprint: fingerprint, ID: "test", Token: "test-client-token", Allow: []string{"*"}})
	serverStatePath := filepath.Join(directory, "relay.pid")
	clientStatePath := filepath.Join(directory, "client.json.pid")
	serverArgs := []string{"-config", "running-server.json", "-pidfile", "relay.pid"}
	serverCommand := func(action string) []string {
		return append([]string{"server", action}, serverArgs...)
	}
	clientList := func() []gateway.ClientInfo {
		t.Helper()
		output := mustRun("server", "clients", "-json")
		for _, field := range []string{"\"secret\"", "\"instance\"", "\"pid\"", "client_token", "access_token"} {
			if strings.Contains(output, field) {
				t.Fatalf("client list exposed internal field %s", field)
			}
		}
		for _, secret := range []string{"test-client-token", "test-access-token", "waiting-client-token", "waiting-access-token"} {
			if strings.Contains(output, secret) {
				t.Fatal("client list leaked route credentials")
			}
		}
		var clients []gateway.ClientInfo
		if err := json.Unmarshal([]byte(output), &clients); err != nil {
			t.Fatalf("invalid client list JSON: %v\n%s", err, output)
		}
		if len(clients) != 2 || clients[0].ID != "test" || clients[1].ID != "waiting" || clients[1].Status != "offline" {
			t.Fatalf("incomplete or unsorted list: %+v", clients)
		}
		return clients
	}
	waitClientStatus := func(want string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			clients := clientList()
			if clients[0].Status == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("client status is %s, want %s", clients[0].Status, want)
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	if output, err := command("server", "clients"); err == nil || !strings.Contains(output, "服务未启动") {
		t.Fatalf("unstarted Server list: %v\n%s", err, output)
	}
	// Always stop any daemon owned by this fixture, including on test failure.
	t.Cleanup(func() {
		for _, item := range []struct{ role, config, state string }{
			{"client", "client.json", clientStatePath},
			{"server", "running-server.json", serverStatePath},
			{"server", "second-server.json", filepath.Join(directory, "second-server.json.pid")},
		} {
			config := filepath.Join(directory, item.config)
			if state, err := readBackgroundState(item.state, item.role, config); err == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
				_ = manageBackground(ctx, "stop", item.role, config, item.state)
				cancel()
				// Only kill a process that still proves ownership of this fixture.
				if contactBackground(context.Background(), state, false) == nil {
					if process, err := os.FindProcess(state.PID); err == nil {
						_ = process.Kill()
						_ = process.Release()
					}
				}
			}
		}
		if index, err := backgroundDirectory(binary); err == nil {
			_ = os.RemoveAll(index) // This fixture has a unique executable path.
		}
	})
	startArgs := append(serverCommand("start"), "-log", "relay.log")
	if output := mustRun(startArgs...); !strings.Contains(output, "started in background") {
		t.Fatal(output)
	}
	serverState, err := readBackgroundState(serverStatePath, "server", filepath.Join(directory, "running-server.json"))
	if err != nil {
		t.Fatal(err)
	}
	if serverState.Log != filepath.Join(directory, "relay.log") {
		t.Fatal("custom log path was not retained")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(serverStatePath)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("background state must be owner-only")
		}
	}
	if output := mustRun(serverCommand("status")...); !strings.Contains(output, "is running") {
		t.Fatal(output)
	}
	if clients := clientList(); clients[0].Status != "offline" || clients[0].ConnectedAt != nil || clients[0].LastHeartbeatAt != nil || clients[0].Address != "" {
		t.Fatalf("unconnected Client is not offline: %+v", clients[0])
	}
	if output := mustRun("server", "clients"); !strings.Contains(output, "0 online / 2 configured") || !strings.Contains(output, "CLIENT_ID") || !strings.Contains(output, "LAST_HEARTBEAT") {
		t.Fatal(output)
	}
	// Discovery must use the running instance, not assume a server.json path or
	// reload modified configuration. It must also work from another directory.
	writeConfig("server.json", map[string]string{"unexpected": "not-the-active-config"})
	writeConfig("running-server.json", map[string]string{"unexpected": "changed-after-start"})
	clientList()
	if output, err := commandIn(t.TempDir(), "server", "clients", "-json"); err != nil || !strings.Contains(output, "\"waiting\"") {
		t.Fatalf("query from another directory: %v\n%s", err, output)
	}
	writeConfig("running-server.json", serverConfig)
	// The old explicit selector remains valid; -pidfile also works by itself.
	mustRun(serverCommand("clients")...)
	mustRun("server", "clients", "-pidfile", serverStatePath, "-json")
	secondReserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	secondConfig := serverConfig
	secondConfig.Listen = secondReserve.Addr().String()
	secondReserve.Close()
	writeConfig("second-server.json", secondConfig)
	mustRun("server", "start", "-config", "second-server.json")
	if output, err := command("server", "clients"); err == nil || !strings.Contains(output, "多个后台 Server") || !strings.Contains(output, "-pidfile "+strconv.Quote(serverStatePath)) || !strings.Contains(output, "second-server.json.pid") {
		t.Fatalf("ambiguous Server query: %v\n%s", err, output)
	}
	mustRun("server", "clients", "-pidfile", serverStatePath)
	for _, action := range []string{"status", "stop", "restart"} {
		if output, err := command("server", action); err == nil || !strings.Contains(output, "多个后台 Server") || !strings.Contains(output, "-pidfile "+strconv.Quote(serverStatePath)) {
			t.Fatalf("ambiguous Server %s: %v\n%s", action, err, output)
		}
	}
	mustRun("server", "status", "-pidfile", serverStatePath)
	mustRun("server", "stop", "-config", "second-server.json")
	clientList()
	if _, err := command(startArgs...); err == nil {
		t.Fatal("duplicate background start succeeded")
	}
	wrongSecret := serverState
	wrongSecret.Secret = "wrong-secret"
	if contactBackground(context.Background(), wrongSecret, true) == nil {
		t.Fatal("unauthenticated stop succeeded")
	}
	if _, err := requestBackground(context.Background(), wrongSecret, http.MethodGet, "/clients"); err == nil {
		t.Fatal("unauthenticated client listing succeeded")
	}
	wrongInstance := serverState
	wrongInstance.Instance = "wrong-instance"
	if _, err := requestBackground(context.Background(), wrongInstance, http.MethodGet, "/clients"); err == nil {
		t.Fatal("client listing accepted a changed process identity")
	}
	if err := contactBackground(context.Background(), serverState, false); err != nil {
		t.Fatal("unauthenticated stop disrupted the server")
	}
	writeConfig("conflict.json", serverConfig)
	if _, err := command("server", "start", "-config", "conflict.json"); err == nil {
		t.Fatal("start succeeded before detecting a port conflict")
	}
	if _, err := os.Stat(filepath.Join(directory, "conflict.json.pid")); !os.IsNotExist(err) {
		t.Fatal("failed startup left a running state file")
	}
	writeConfig("invalid.json", map[string]string{"unexpected": "field"})
	if _, err := command("client", "start", "-config", "invalid.json"); err == nil {
		t.Fatal("start accepted an invalid configuration")
	}
	mustRun("client", "start", "-config", "client.json")
	mustRun("client", "status", "-config", "client.json")
	// The start commands above have exited. Their detached processes must still
	// relay real traffic, including when allowed_targets is ["*"].
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	pem, err := os.ReadFile(filepath.Join(directory, "server.crt"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("cannot trust fixture certificate")
	}
	var tunnel *tls.Conn
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		tunnel, err = tls.Dial("tcp", address, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots})
		if err != nil {
			t.Fatal(err)
		}
		_ = tunnel.SetDeadline(time.Now().Add(2 * time.Second))
		if err := gateway.WriteMessage(tunnel, gateway.Message{Kind: "open", ClientID: "test", Token: "test-access-token", Host: "127.0.0.1", Port: uint16(target.Addr().(*net.TCPAddr).Port)}); err != nil {
			t.Fatal(err)
		}
		reply, err := gateway.ReadMessage(tunnel)
		if err == nil && reply.Kind == "ready" {
			break
		}
		tunnel.Close()
		tunnel = nil
		time.Sleep(25 * time.Millisecond)
	}
	if tunnel == nil {
		t.Fatal("detached Server/Client did not become ready")
	}
	defer tunnel.Close()
	clients := clientList()
	if clients[0].Status != "online" || clients[0].ConnectedAt == nil {
		t.Fatalf("registered Client is not online: %+v", clients[0])
	}
	if host, port, err := net.SplitHostPort(clients[0].Address); err != nil || host != "127.0.0.1" || port == "" {
		t.Fatalf("client address is not the observed peer: %+v", clients[0])
	}
	if output := mustRun("server", "clients"); !strings.Contains(output, "1 online / 2 configured") || !strings.Contains(output, clients[0].Address) {
		t.Fatal(output)
	}
	payload := bytes.Repeat([]byte("background relay\x00\xff"), 1024)
	if _, err := tunnel.Write(payload); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(tunnel, received); err != nil || !bytes.Equal(payload, received) {
		t.Fatalf("detached relay changed data: %v", err)
	}
	mustRun("client", "stop", "-config", "client.json")
	_ = tunnel.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := tunnel.Read(make([]byte, 1)); err == nil {
		t.Fatal("stop did not close an active relay")
	}
	if _, err := command("client", "status", "-config", "client.json"); err == nil {
		t.Fatal("stopped client is still running")
	}
	waitClientStatus("offline")
	if clients := clientList(); clients[0].Status != "offline" || clients[0].ConnectedAt != nil || clients[0].LastHeartbeatAt != nil || clients[0].Address != "" {
		t.Fatalf("disconnected Client retained live metadata: %+v", clients[0])
	}
	mustRun("client", "start", "-config", "client.json")
	oldState, err := readBackgroundState(clientStatePath, "client", filepath.Join(directory, "client.json"))
	if err != nil {
		t.Fatal(err)
	}
	process, err := os.FindProcess(oldState.PID)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = process.Release()
	deadline = time.Now().Add(5 * time.Second)
	for {
		if lock, err := lockBackground(clientStatePath + ".lock"); err == nil {
			lock.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("killed process retained the instance lock")
		}
		time.Sleep(25 * time.Millisecond)
	}
	mustRun("client", "start", "-config", "client.json")
	current, err := readBackgroundState(clientStatePath, "client", filepath.Join(directory, "client.json"))
	if err != nil || current.Instance == oldState.Instance || current.Secret == oldState.Secret {
		t.Fatal("stale state was not replaced with a new instance")
	}
	if contactBackground(context.Background(), oldState, true) == nil {
		t.Fatal("stale control credentials stopped a new instance")
	}
	mustRun("client", "status", "-config", "client.json")
	mustRun("client", "stop", "-config", "client.json")
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := command("client", "start", "-config", "client.json")
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("concurrent starts created %d instances, want 1", success)
	}
	mustRun("client", "stop", "-config", "client.json")
	mustRun(serverCommand("stop")...)
	mustRun(serverCommand("stop")...)
	if _, err := command(serverCommand("status")...); err == nil {
		t.Fatal("stopped server is still running")
	}
	if output, err := command("server", "clients"); err == nil || !strings.Contains(output, "服务未启动") {
		t.Fatalf("stopped Server list: %v\n%s", err, output)
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal("stop did not release the Server port")
	}
	listener.Close()
	// Both daemon roles must also work without certificate files or a pin.
	serverConfig.CertFile, serverConfig.KeyFile = "", ""
	writeConfig("running-server.json", serverConfig)
	writeConfig("client.json", gateway.ClientConfig{Server: address, ID: "test", Token: "test-client-token", Allow: []string{"*"}})
	if output := mustRun(serverCommand("start")...); !strings.Contains(output, gateway.PlainTCPWarning) {
		t.Fatal("plaintext Server start did not show the risk warning")
	}
	if output := mustRun("client", "start", "-config", "client.json"); strings.Contains(output, gateway.PlainTCPWarning) {
		t.Fatal("plaintext Client start showed a Server-only risk warning")
	}
	waitClientStatus("online")
	for _, role := range []string{"server", "client"} {
		output := mustRun(role, "restart")
		if strings.Contains(output, gateway.PlainTCPWarning) != (role == "server") {
			t.Fatalf("%s restart risk warning does not match role", role)
		}
	}
	waitClientStatus("online")
	mustRun("client", "status", "-config", "client.json")
	mustRun(serverCommand("status")...)
	mustRun("client", "stop", "-config", "client.json")
	mustRun(serverCommand("stop")...)
	for _, name := range []string{"server.log", "client.log"} {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), gateway.PlainTCPWarning) != (name == "server.log") {
			t.Fatalf("%s risk warning does not match role", name)
		}
	}
	for _, name := range []string{"relay.log", "server.log", "client.log"} {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, token := range []string{"test-client-token", "test-access-token", serverState.Secret} {
			if strings.Contains(string(data), token) {
				t.Fatalf("%s leaked a token", name)
			}
		}
	}
}
