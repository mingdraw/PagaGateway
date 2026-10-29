package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverBackgroundInstanceIgnoresStaleReferences(t *testing.T) {
	for _, role := range []string{"server", "client"} {
		t.Run(role, func(t *testing.T) { testDiscoverBackgroundInstance(t, role) })
	}
}

func testDiscoverBackgroundInstance(t *testing.T, role string) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	const instance, secret = "live-instance", "live-control-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(backgroundReply{PID: os.Getpid(), Instance: instance})
	}))
	defer server.Close()
	state := backgroundState{PID: os.Getpid(), Role: role, Config: filepath.Join(directory, "non-default.json"), Address: strings.TrimPrefix(server.URL, "http://"), Instance: instance, Secret: secret}
	statePath := filepath.Join(directory, "custom.pid")
	if err := writeBackgroundState(statePath, state); err != nil {
		t.Fatal(err)
	}
	writeReference := func(name, path, id string) {
		t.Helper()
		if err := writeBackgroundJSON(filepath.Join(directory, name+".json"), backgroundRegistration{StatePath: path, Instance: id}); err != nil {
			t.Fatal(err)
		}
	}
	writeReference("missing", filepath.Join(directory, "missing.pid"), "old-instance")
	writeReference("replaced", statePath, "old-instance")
	if _, err := discoverBackgroundInstance(context.Background(), directory, role); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale references should not select an instance: %v", err)
	}
	writeReference("current", statePath, instance)
	writeReference("duplicate", statePath, instance)
	current, err := discoverBackgroundInstance(context.Background(), directory, role)
	if err != nil || current.state.Instance != instance || current.state.Config != state.Config || current.path != statePath {
		t.Fatalf("did not select the authenticated live instance: %+v %v", current, err)
	}
	otherRole := "client"
	if role == "client" {
		otherRole = "server"
	}
	if _, err := discoverBackgroundInstance(context.Background(), directory, otherRole); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("discovery selected another role: %v", err)
	}
	state.Secret = "wrong-secret"
	if err := writeBackgroundState(statePath, state); err != nil {
		t.Fatal(err)
	}
	if _, err := discoverBackgroundInstance(context.Background(), directory, role); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("discovery accepted invalid control credentials: %v", err)
	}
	state.Secret, state.Instance = secret, "wrong-instance"
	if err := writeBackgroundState(statePath, state); err != nil {
		t.Fatal(err)
	}
	writeReference("wrong-instance", statePath, state.Instance)
	if _, err := discoverBackgroundInstance(context.Background(), directory, role); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("discovery accepted a changed response identity: %v", err)
	}
}

func TestBackgroundRegistrationCleanupPreservesReplacement(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := backgroundDirectory(executable)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(t.TempDir(), "server.pid")
	unregister, err := registerBackgroundInstance(statePath, "first-instance")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unregister(); _ = os.Remove(directory) })
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("registration not published: %v %v", entries, err)
	}
	unregisterReplacement, err := registerBackgroundInstance(statePath, "replacement-instance")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(unregisterReplacement)
	unregister()
	entries, err = os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("old cleanup removed the wrong registration: %v %v", entries, err)
	}
	current, err := readBackgroundRegistration(filepath.Join(directory, entries[0].Name()))
	replacement := backgroundRegistration{StatePath: statePath, Instance: "replacement-instance"}
	if err != nil || current != replacement {
		t.Fatalf("old instance removed a new registration: %+v %v", current, err)
	}
}
