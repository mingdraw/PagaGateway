package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mingdraw/PagaGateway/internal/gateway"
)

func TestBackgroundManagementReusesStartConfiguration(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "deployment with spaces")
	for _, name := range []string{"configs", "states", "logs"} {
		if err := os.MkdirAll(filepath.Join(directory, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	queryDirectory := t.TempDir()
	binary := filepath.Join(directory, "pagagateway")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	commandIn := func(cwd string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Dir = cwd
		output, err := cmd.CombinedOutput()
		return string(output), err
	}
	mustRunIn := func(cwd string, args ...string) string {
		t.Helper()
		output, err := commandIn(cwd, args...)
		if err != nil {
			t.Fatalf("command %v: %v\n%s", args, err, output)
		}
		return output
	}
	mustRun := func(args ...string) string {
		t.Helper()
		return mustRunIn(queryDirectory, args...)
	}
	writeConfig := func(path string, config any) {
		t.Helper()
		data, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	type deployment struct{ role, config, state, log string }
	server := deployment{"server", filepath.Join(directory, "configs", "relay-settings.json"), filepath.Join(directory, "states", "relay.pid"), filepath.Join(directory, "logs", "relay.log")}
	client := deployment{"client", filepath.Join(directory, "configs", "jump-settings.json"), filepath.Join(directory, "states", "jump.pid"), filepath.Join(directory, "logs", "jump.log")}
	secondClient := deployment{"client", filepath.Join(directory, "configs", "second-jump.json"), filepath.Join(directory, "states", "second-jump.pid"), filepath.Join(directory, "logs", "second-jump.log")}
	readState := func(item deployment) backgroundState {
		t.Helper()
		state, err := readBackgroundState(item.state, item.role, item.config)
		if err != nil {
			t.Fatal(err)
		}
		if state.Log != item.log || state.WorkDir != directory {
			t.Fatalf("startup paths were not retained: %+v", state)
		}
		return state
	}
	t.Cleanup(func() {
		for _, item := range []deployment{secondClient, client, server} {
			if state, err := readBackgroundState(item.state, item.role, item.config); err == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
				_ = stopBackgroundInstance(ctx, backgroundInstance{state: state, path: item.state})
				cancel()
				if contactBackground(context.Background(), state, false) == nil {
					if process, err := os.FindProcess(state.PID); err == nil {
						_ = process.Kill()
						_ = process.Release()
					}
				}
			}
		}
		if index, err := backgroundDirectory(binary); err == nil {
			_ = os.RemoveAll(index) // Unique executable owned by this fixture.
		}
	})
	for _, role := range []string{"server", "client"} {
		for _, action := range []string{"status", "restart"} {
			if output, err := commandIn(queryDirectory, role, action); err == nil || !strings.Contains(output, "is not running") {
				t.Fatalf("unstarted %s %s: %v\n%s", role, action, err, output)
			}
		}
		mustRun(role, "stop")
	}
	certificateOutput := mustRunIn(directory, "certificate", "-host", "127.0.0.1")
	fingerprint := strings.TrimSpace(strings.TrimPrefix(certificateOutput, "Server certificate "))
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserve.Addr().String()
	reserve.Close()
	serverConfig := gateway.ServerConfig{Listen: address, CertFile: "server.crt", KeyFile: "server.key", Routes: []gateway.Route{{ID: "jump", ClientToken: "client-token", AccessToken: "access-token"}}}
	clientConfig := gateway.ClientConfig{Server: address, Fingerprint: fingerprint, ID: "jump", Token: "client-token", Allow: []string{"127.0.0.1:1"}}
	writeConfig(server.config, serverConfig)
	writeConfig(client.config, clientConfig)
	start := func(item deployment) {
		t.Helper()
		mustRunIn(directory, item.role, "start", "-config", item.config, "-pidfile", item.state, "-log", item.log)
	}
	start(server)
	start(client)
	oldServer, oldClient := readState(server), readState(client)
	for _, item := range []deployment{server, client} {
		output := mustRun(item.role, "status")
		if !strings.Contains(output, item.config) || !strings.Contains(output, item.log) {
			t.Fatalf("status lost original paths: %s", output)
		}
	}
	waitRegistered := func() {
		t.Helper()
		deadline := time.Now().Add(8 * time.Second)
		for {
			var clients []gateway.ClientInfo
			output := mustRun("server", "clients", "-json")
			if err := json.Unmarshal([]byte(output), &clients); err != nil {
				t.Fatal(err)
			}
			for _, item := range clients {
				if item.ID == "jump" && item.Status == "online" {
					return
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("Client did not reconnect: %s", output)
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
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
	checkTarget := func(want string) {
		t.Helper()
		waitRegistered()
		pin, err := gateway.PinnedTLS(fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", address, pin)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if err := gateway.WriteMessage(conn, gateway.Message{Kind: "open", ClientID: "jump", Token: "access-token", Host: "127.0.0.1", Port: uint16(target.Addr().(*net.TCPAddr).Port)}); err != nil {
			t.Fatal(err)
		}
		reply, err := gateway.ReadMessage(conn)
		if err != nil || (want == "ready" && reply.Kind != want) || (want != "ready" && reply.Error != want) {
			t.Fatalf("target result %+v, %v; want %s", reply, err, want)
		}
		if want == "ready" {
			const payload = "configuration reloaded"
			if _, err := io.WriteString(conn, payload); err != nil {
				t.Fatal(err)
			}
			received := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, received); err != nil || string(received) != payload {
				t.Fatalf("relay after restart: %q %v", received, err)
			}
		}
	}
	checkTarget("targetDenied")
	serverConfig.Routes = append(serverConfig.Routes, gateway.Route{ID: "new-route", ClientToken: "second-token", AccessToken: "second-access"})
	clientConfig.Allow = []string{"*"}
	writeConfig(server.config, serverConfig)
	writeConfig(client.config, clientConfig)
	for _, item := range []deployment{server, client} {
		if output := mustRun(item.role, "restart"); !strings.Contains(output, "restarted") {
			t.Fatal(output)
		}
		mustRun(item.role, "status")
	}
	newServer, newClient := readState(server), readState(client)
	for i, pair := range [][2]backgroundState{{oldServer, newServer}, {oldClient, newClient}} {
		if pair[0].Instance == pair[1].Instance || pair[0].Secret == pair[1].Secret {
			t.Fatal("restart reused the old process identity")
		}
		if contactBackground(context.Background(), pair[0], true) == nil {
			t.Fatalf("old instance %d could stop a replacement", i)
		}
	}
	if output := mustRun("server", "clients", "-json"); !strings.Contains(output, "new-route") {
		t.Fatalf("Server did not reload routes: %s", output)
	}
	checkTarget("ready")
	assertRestartRejected := func(item deployment, want string, expected backgroundState) {
		t.Helper()
		if output, err := commandIn(queryDirectory, item.role, "restart"); err == nil || !strings.Contains(output, want) {
			t.Fatalf("invalid %s restart: %v\n%s", item.role, err, output)
		}
		if state := readState(item); state.Instance != expected.Instance || contactBackground(context.Background(), state, false) != nil {
			t.Fatalf("invalid configuration stopped the existing %s", item.role)
		}
		mustRun(item.role, "status")
	}
	serverConfig.CertFile = "missing.crt"
	writeConfig(server.config, serverConfig)
	assertRestartRejected(server, "cannot load TLS certificate/key", newServer)
	serverConfig.CertFile = "server.crt"
	writeConfig(server.config, serverConfig)
	clientConfig.Fingerprint = "invalid-pin"
	writeConfig(client.config, clientConfig)
	assertRestartRejected(client, "server_fingerprint", newClient)
	clientConfig.Fingerprint = fingerprint
	writeConfig(client.config, clientConfig)
	secondConfig := clientConfig
	secondConfig.ID, secondConfig.Token = "new-route", "second-token"
	writeConfig(secondClient.config, secondConfig)
	start(secondClient)
	for _, action := range []string{"status", "stop", "restart"} {
		if output, err := commandIn(queryDirectory, "client", action); err == nil || !strings.Contains(output, "多个后台 Client") || !strings.Contains(output, "-pidfile "+strconv.Quote(secondClient.state)) {
			t.Fatalf("ambiguous Client %s: %v\n%s", action, err, output)
		}
	}
	mustRun("client", "status", "-pidfile", secondClient.state)
	mustRun("client", "restart", "-pidfile", secondClient.state)
	if readState(client).Instance != newClient.Instance {
		t.Fatal("selected restart changed another Client")
	}
	mustRun("client", "stop", "-pidfile", secondClient.state)
	// A valid configuration can still fail to bind after the old Server stops.
	conflict, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conflict.Close()
	serverConfig.Listen = conflict.Addr().String()
	writeConfig(server.config, serverConfig)
	if output, err := commandIn(queryDirectory, "server", "restart"); err == nil || !strings.Contains(output, "stopped but could not restart") || !strings.Contains(output, server.log) {
		t.Fatalf("restart port conflict: %v\n%s", err, output)
	}
	if _, err := os.Stat(server.state); !os.IsNotExist(err) {
		t.Fatal("failed restart retained a running state file")
	}
	if contactBackground(context.Background(), newServer, false) == nil {
		t.Fatal("failed restart did not stop the original Server")
	}
	if output, err := commandIn(queryDirectory, "server", "status"); err == nil || !strings.Contains(output, "is not running") {
		t.Fatalf("status after failed restart: %v\n%s", err, output)
	}
	serverConfig.Listen = address
	writeConfig(server.config, serverConfig)
	start(server)
	readState(server)
	// Status and stop must continue working even if the saved JSON is now invalid.
	for _, item := range []deployment{client, server} {
		writeConfig(item.config, map[string]string{"unexpected": "invalid-config"})
		expected := readState(item)
		assertRestartRejected(item, "invalid configuration JSON", expected)
		mustRun(item.role, "stop")
		if output, err := commandIn(queryDirectory, item.role, "status"); err == nil || !strings.Contains(output, "is not running") {
			t.Fatalf("stopped %s status: %v\n%s", item.role, err, output)
		}
		mustRun(item.role, "stop")
	}
}
