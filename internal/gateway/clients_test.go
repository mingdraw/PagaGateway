package gateway

import (
	"testing"
	"time"
)

func TestClientListLifecycle(t *testing.T) {
	f := setup(t)
	assertOffline := func() {
		t.Helper()
		clients := f.s.Clients()
		if len(clients) != 1 || clients[0].ID != "office" || clients[0].Status != "offline" || clients[0].Address != "" || clients[0].ConnectedAt != nil || clients[0].LastHeartbeatAt != nil {
			t.Fatalf("unexpected offline snapshot: %+v", clients)
		}
		if clients[0].ClientVersion != "" {
			t.Fatalf("offline Client retained a version: %+v", clients[0])
		}
	}
	assertOffline()
	// Query while registration, heartbeats and disconnects modify the presence map.
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				_ = f.s.Clients()
			}
		}
	}()
	defer func() { close(stop); <-done }()
	before := time.Now()
	conn, reply := f.request(t, Message{Kind: "register", ClientID: "office", Token: testClientToken})
	if reply.Kind != "registered" {
		t.Fatal(reply)
	}
	f.waitOnline(t, true)
	client := f.s.Clients()[0]
	if client.Status != "online" || client.Address != conn.LocalAddr().String() || client.ConnectedAt == nil || client.ConnectedAt.Before(before) || client.ConnectedAt.After(time.Now()) || client.LastHeartbeatAt != nil {
		t.Fatalf("unexpected registered snapshot: %+v", client)
	}
	if client.ClientVersion != "0.1.0" {
		t.Fatalf("legacy Client version = %q, want 0.1.0", client.ClientVersion)
	}
	connectedAt := *client.ConnectedAt
	// Mutating a returned snapshot must not change runtime metadata.
	*client.ConnectedAt = time.Time{}
	if !f.s.Clients()[0].ConnectedAt.Equal(connectedAt) {
		t.Fatal("client snapshot aliases runtime state")
	}
	for i := 0; i < 3; i++ {
		before = time.Now()
		if err := WriteMessage(conn, Message{Kind: "ping"}); err != nil {
			t.Fatal(err)
		}
		if reply, err := ReadMessage(conn); err != nil || reply.Kind != "pong" {
			t.Fatalf("heartbeat: %+v %v", reply, err)
		}
		client = f.s.Clients()[0]
		if client.LastHeartbeatAt == nil || client.LastHeartbeatAt.Before(before) || client.LastHeartbeatAt.After(time.Now()) || !client.ConnectedAt.Equal(connectedAt) {
			t.Fatalf("heartbeat did not update its timestamp: %+v", client)
		}
	}
	_ = conn.Close()
	f.waitOnline(t, false)
	assertOffline()
	conn, reply = f.request(t, Message{Kind: "register", ClientID: "office", Token: testClientToken, ClientVersion: "v0.2.0-rc.1"})
	if reply.Kind != "registered" {
		t.Fatal(reply)
	}
	f.waitOnline(t, true)
	client = f.s.Clients()[0]
	if client.Status != "online" || client.Address != conn.LocalAddr().String() || !client.ConnectedAt.After(connectedAt) || client.LastHeartbeatAt != nil {
		t.Fatalf("reconnect retained old connection metadata: %+v", client)
	}
	if client.ClientVersion != "0.2.0-rc.1" {
		t.Fatalf("reconnected Client version = %q, want 0.2.0-rc.1", client.ClientVersion)
	}
}

func TestClientListIncludesConfiguredRoutesInIDOrder(t *testing.T) {
	s, err := NewServer(ServerConfig{Listen: "unused", CertFile: "unused", KeyFile: "unused", Routes: []Route{
		{ID: "z-office", ClientToken: "z-client", AccessToken: "z-access"},
		{ID: "a-office", ClientToken: "a-client", AccessToken: "a-access"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	clients := s.Clients()
	if len(clients) != 2 || clients[0].ID != "a-office" || clients[1].ID != "z-office" || clients[0].Status != "offline" || clients[1].Status != "offline" {
		t.Fatalf("configured clients were not sorted: %+v", clients)
	}
}
