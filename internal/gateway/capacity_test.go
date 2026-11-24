package gateway

import (
	"io"
	"net"
	"testing"
	"time"
)

func capacityFixture(t *testing.T, capacity, routeLimit int) *fixture {
	t.Helper()
	s, err := NewServer(ServerConfig{Listen: "127.0.0.1:0", MaxConnections: capacity, Routes: []Route{
		{ID: "office", ClientToken: testClientToken, AccessToken: testAccessToken, MaxTunnels: routeLimit},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	return serveFixture(t, &fixture{s: s, address: ln.Addr().String()}, ln)
}

func sendFixtureMessage(t *testing.T, address string, m Message) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := WriteMessage(conn, m); err != nil {
		t.Fatal(err)
	}
	return conn
}

func readFixtureMessage(t *testing.T, conn net.Conn, kind string) Message {
	t.Helper()
	m, err := ReadMessage(conn)
	if err != nil || m.Kind != kind {
		t.Fatalf("want %s, got %+v: %v", kind, m, err)
	}
	return m
}

func waitTunnelCounts(t *testing.T, s *Server, active, pending int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		status := s.Status()
		if status.ActiveTunnels == active && status.PendingTunnels == pending {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("want %d active and %d pending, got %+v", active, pending, status)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestLegacyClientKeepsReservedWorkSlot(t *testing.T) {
	f := capacityFixture(t, 3, 0)
	control, registered := f.request(t, Message{Kind: "register", ClientID: "office", Token: testClientToken})
	if registered.Kind != "registered" || registered.DialFeedback {
		t.Fatalf("unexpected legacy registration: %+v", registered)
	}
	f.waitOnline(t, true)
	request := openMessage("127.0.0.1:22")
	access := sendFixtureMessage(t, f.address, request)
	dial := readFixtureMessage(t, control, "dial")
	if dial.TimeoutMS != 0 || dial.DialFeedback {
		t.Fatalf("legacy Client received optional control fields: %+v", dial)
	}
	status := f.s.Status()
	if status.PendingTunnels != 1 || status.CommittedConnections != 3 {
		t.Fatalf("work connection was not reserved: %+v", status)
	}
	_, busy := f.request(t, request)
	if busy.Error != "gatewayBusy" {
		t.Fatalf("second access occupied the reserved work slot: %+v", busy)
	}
	work := sendFixtureMessage(t, f.address, Message{Kind: "work", ClientID: "office", Token: testClientToken, ID: dial.ID})
	if _, err := work.Write([]byte("early banner")); err != nil {
		t.Fatal(err)
	}
	readFixtureMessage(t, access, "ready")
	banner := make([]byte, len("early banner"))
	if _, err := io.ReadFull(access, banner); err != nil || string(banner) != "early banner" {
		t.Fatalf("banner was lost at handoff: %q, %v", banner, err)
	}
	waitTunnelCounts(t, f.s, 1, 0)
	if err := WriteMessage(control, Message{Kind: "ping"}); err != nil {
		t.Fatal(err)
	}
	readFixtureMessage(t, control, "pong")
	_ = access.Close()
	_ = work.Close()
	waitTunnelCounts(t, f.s, 0, 0)
	if f.s.Clients()[0].BusyRejects != 1 {
		t.Fatal("busy rejection was not recorded")
	}
}

func TestClientCapacityFastRejection(t *testing.T) {
	t.Run("server cannot fit a tunnel", func(t *testing.T) {
		f := capacityFixture(t, 2, 0)
		f.startClient(t, []string{"*"})
		_, reply := f.request(t, openMessage(target(t, false)))
		if reply.Error != "gatewayBusy" {
			t.Fatalf("wanted gatewayBusy before dispatch, got %+v", reply)
		}
	})
	t.Run("advertised client limit", func(t *testing.T) {
		f := capacityFixture(t, 32, 0)
		address := target(t, false)
		f.startClientWithLimit(t, []string{address}, 1)
		active, ready := f.request(t, openMessage(address))
		if ready.Kind != "ready" {
			t.Fatal(ready)
		}
		_, reply := f.request(t, openMessage(address))
		if reply.Error != "clientBusy" {
			t.Fatalf("wanted clientBusy before dispatch, got %+v", reply)
		}
		if _, err := active.Write([]byte("ok")); err != nil {
			t.Fatal(err)
		}
		var echo [2]byte
		if _, err := io.ReadFull(active, echo[:]); err != nil || string(echo[:]) != "ok" {
			t.Fatalf("busy rejection disturbed existing tunnel: %q, %v", echo, err)
		}
		info := f.s.Clients()[0]
		if info.MaxTunnels != 1 || info.ActiveTunnels != 1 || info.PendingTunnels != 0 || info.BusyRejects != 1 {
			t.Fatalf("wrong Client capacity snapshot: %+v", info)
		}
	})
}

func TestPairingBudgetAndNegotiatedFailure(t *testing.T) {
	f := capacityFixture(t, 3, 1)
	control, registered := f.request(t, Message{Kind: "register", ClientID: "office", Token: testClientToken, MaxTunnels: 5, DialFeedback: true})
	if registered.Kind != "registered" || !registered.DialFeedback {
		t.Fatalf("feedback not negotiated: %+v", registered)
	}
	f.waitOnline(t, true)
	if f.s.Clients()[0].MaxTunnels != 1 {
		t.Fatal("route limit did not constrain the advertised limit")
	}
	request := openMessage("127.0.0.1:22")
	request.TimeoutMS = 500
	access := sendFixtureMessage(t, f.address, request)
	dial := readFixtureMessage(t, control, "dial")
	if dial.TimeoutMS <= 0 || dial.TimeoutMS >= request.TimeoutMS {
		t.Fatalf("deadline was not passed to worker: %+v", dial)
	}
	if reply := readFixtureMessage(t, access, "error"); reply.Error != "targetTimeout" {
		t.Fatalf("unexpected budget expiry: %+v", reply)
	}
	waitTunnelCounts(t, f.s, 0, 0)
	// Late work must not consume a new request or inject control bytes into
	// a newer Client's target stream.
	late := sendFixtureMessage(t, f.address, Message{Kind: "work", ClientID: "office", Token: testClientToken, ID: dial.ID, DialFeedback: true})
	var byteRead [1]byte
	if _, err := late.Read(byteRead[:]); err != io.EOF {
		t.Fatalf("late work did not close without a response: %v", err)
	}
	request.TimeoutMS = 1500
	next := sendFixtureMessage(t, f.address, request)
	dial = readFixtureMessage(t, control, "dial")
	if err := WriteMessage(control, Message{Kind: "dialFailed", ID: dial.ID, Error: "workUnavailable"}); err != nil {
		t.Fatal(err)
	}
	if reply := readFixtureMessage(t, next, "error"); reply.Error != "workUnavailable" {
		t.Fatalf("negotiated failure lost: %+v", reply)
	}
	waitTunnelCounts(t, f.s, 0, 0)
	if err := WriteMessage(control, Message{Kind: "ping"}); err != nil {
		t.Fatal(err)
	}
	readFixtureMessage(t, control, "pong")
}
