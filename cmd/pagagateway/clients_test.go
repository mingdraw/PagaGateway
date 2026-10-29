package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientListWithStaleState(t *testing.T) {
	directory := t.TempDir()
	config, statePath := filepath.Join(directory, "server.json"), filepath.Join(directory, "server.json.pid")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	state := backgroundState{PID: os.Getpid(), Role: "server", Config: config, Address: address, Instance: "stale-instance", Secret: "stale-secret"}
	if err := writeBackgroundState(statePath, state); err != nil {
		t.Fatal(err)
	}
	if err := listBackgroundClients(context.Background(), config, statePath, false); err == nil || !strings.Contains(err.Error(), "服务未启动") {
		t.Fatalf("stale instance did not report unavailability: %v", err)
	}
}

func TestClientListRequiresRunningVersionSupport(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	state := backgroundState{PID: os.Getpid(), Address: strings.TrimPrefix(server.URL, "http://"), Instance: "old-instance", Secret: "old-secret"}
	_, err := requestBackground(context.Background(), state, http.MethodGet, "/clients")
	if err == nil || !strings.Contains(err.Error(), "replace the executable and start it again") {
		t.Fatalf("old Server did not get an upgrade hint: %v", err)
	}
}
