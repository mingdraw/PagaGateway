package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixture struct {
	s                    *Server
	address, fingerprint string
	tls                  *tls.Config
	client               *Client
	stopClient           context.CancelFunc
}

const testClientToken = "client"
const testAccessToken = "access"

func setup(t *testing.T) *fixture {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(der)
	f := &fixture{address: ln.Addr().String(), fingerprint: hex.EncodeToString(digest[:])}
	f.tls, _ = PinnedTLS(f.fingerprint)
	f.s, err = NewServer(ServerConfig{Listen: "unused", CertFile: "unused", KeyFile: "unused", Routes: []Route{{ID: "office", ClientToken: testClientToken, AccessToken: testAccessToken}}})
	if err != nil {
		t.Fatal(err)
	}
	return serveFixture(t, f, ln)
}

func setupPlainTCP(t *testing.T) *fixture {
	t.Helper()
	s, err := NewServer(ServerConfig{Listen: "127.0.0.1:0", Routes: []Route{{ID: "office", ClientToken: testClientToken, AccessToken: testAccessToken}}})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	return serveFixture(t, &fixture{s: s, address: ln.Addr().String()}, ln)
}

func serveFixture(t *testing.T, f *fixture, ln net.Listener) *fixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.s.Serve(ctx, ln) }()
	t.Cleanup(func() {
		if f.stopClient != nil {
			f.stopClient()
		}
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("server shutdown leaked connections")
		}
	})
	return f
}

func (f *fixture) startClient(t *testing.T, allowed []string) {
	t.Helper()
	f.startClientWithLimit(t, allowed, 0)
}

func (f *fixture) startClientWithLimit(t *testing.T, allowed []string, limit int) {
	t.Helper()
	client, err := NewClient(ClientConfig{Server: f.address, Fingerprint: f.fingerprint, ID: "office", Token: testClientToken, Allow: allowed, MaxTunnels: limit})
	if err != nil {
		t.Fatal(err)
	}
	f.client = client
	ctx, cancel := context.WithCancel(context.Background())
	f.stopClient = cancel
	done := make(chan struct{})
	go func() { _ = client.Run(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("client shutdown leaked tunnels")
		}
	})
	f.waitOnline(t, true)
}

func (f *fixture) waitOnline(t *testing.T, want bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f.s.mu.Lock()
		a := f.s.agents["office"]
		online := a != nil && a.online
		f.s.mu.Unlock()
		if online == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("client presence did not update")
}

func (f *fixture) request(t *testing.T, m Message) (net.Conn, Message) {
	t.Helper()
	var conn net.Conn
	var err error
	if f.tls == nil {
		conn, err = net.Dial("tcp", f.address)
	} else {
		conn, err = tls.Dial("tcp", f.address, f.tls)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := WriteMessage(conn, m); err != nil {
		t.Fatal(err)
	}
	reply, err := ReadMessage(conn)
	if err != nil {
		t.Fatal(err)
	}
	return conn, reply
}

func target(t *testing.T, respondAfterEOF bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	connections := []net.Conn{}
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range connections {
			c.Close()
		}
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections = append(connections, conn)
			mu.Unlock()
			go func() {
				defer conn.Close()
				if respondAfterEOF {
					data, _ := io.ReadAll(conn)
					_, _ = conn.Write(data)
				} else {
					_, _ = io.Copy(conn, conn)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func openMessage(address string) Message {
	host, port, _ := net.SplitHostPort(address)
	n, _ := strconv.Atoi(port)
	return Message{Kind: "open", ClientID: "office", Token: testAccessToken, Host: host, Port: uint16(n)}
}

func TestRelayBinaryAndHalfClose(t *testing.T) {
	for name, start := range map[string]func(*testing.T) *fixture{"tls": setup, "plaintext": setupPlainTCP} {
		t.Run(name, func(t *testing.T) { testRelayBinaryAndHalfClose(t, start(t)) })
	}
}

func testRelayBinaryAndHalfClose(t *testing.T, f *fixture) {
	address := target(t, true)
	f.startClient(t, []string{address})
	conn, reply := f.request(t, openMessage(address))
	if reply.Kind != "ready" {
		t.Fatalf("open: %+v", reply)
	}
	payload := bytes.Repeat([]byte{0, 255, 1, 128, 13, 10}, 200000)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, payload) {
		t.Fatalf("binary stream changed: %d / %d bytes", len(actual), len(payload))
	}
}

func TestWildcardAllowsMultipleTargets(t *testing.T) {
	f := setup(t)
	addresses := []string{target(t, false), target(t, false)}
	f.startClient(t, []string{"*"})
	for _, address := range addresses {
		conn, reply := f.request(t, openMessage(address))
		if reply.Kind != "ready" {
			t.Fatalf("wildcard open: %+v", reply)
		}
		payload := []byte("wildcard tunnel " + address)
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		actual := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, actual); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(actual, payload) {
			t.Fatal("wildcard tunnel changed target data")
		}
		conn.Close()
	}
	m := openMessage(addresses[0])
	m.Token = testClientToken
	_, reply := f.request(t, m)
	if reply.Error != "unauthorized" {
		t.Fatal("wildcard allowed a tunnel without the access token")
	}
}

func TestAuthenticationACLAndOffline(t *testing.T) {
	for name, start := range map[string]func(*testing.T) *fixture{"tls": setup, "plaintext": setupPlainTCP} {
		t.Run(name, func(t *testing.T) { testAuthenticationACLAndOffline(t, start(t)) })
	}
}

func testAuthenticationACLAndOffline(t *testing.T, f *fixture) {
	m := openMessage("127.0.0.1:22")
	_, reply := f.request(t, m)
	if reply.Error != "clientOffline" {
		t.Fatal(reply)
	}
	m.Token = testClientToken
	_, reply = f.request(t, m)
	if reply.Error != "unauthorized" {
		t.Fatal("registration token authorized a user tunnel")
	}
	f.startClient(t, []string{"127.0.0.1:1"})
	_, reply = f.request(t, openMessage("127.0.0.1:22"))
	if reply.Error != "targetDenied" {
		t.Fatal(reply)
	}
	_, reply = f.request(t, openMessage("127.0.0.1:1"))
	if reply.Error != "targetUnavailable" {
		t.Fatal(reply)
	}
	_, reply = f.request(t, Message{Kind: "register", ClientID: "office", Token: testClientToken})
	if reply.Error != "clientAlreadyOnline" {
		t.Fatal(reply)
	}
	_, reply = f.request(t, Message{Kind: "work", ClientID: "office", Token: testClientToken, ID: strings.Repeat("0", 64)})
	if reply.Error != "unknownRequest" {
		t.Fatal(reply)
	}
	wrong, _ := PinnedTLS(strings.Repeat("0", 64))
	if conn, err := tls.Dial("tcp", f.address, wrong); err == nil {
		conn.Close()
		t.Fatal("wrong certificate pin was accepted")
	}
	f.stopClient()
	f.waitOnline(t, false)
}

func TestClientTLSNeverFallsBackToPlainTCP(t *testing.T) {
	f := setupPlainTCP(t)
	c, err := NewClient(ClientConfig{Server: f.address, Fingerprint: strings.Repeat("00", 32), ID: "office", Token: testClientToken, Allow: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.runOnce(ctx); err == nil {
		t.Fatal("TLS client fell back to plaintext registration")
	}
	if clients := f.s.Clients(); len(clients) != 1 || clients[0].Status != "offline" {
		t.Fatal("TLS client registered with a plaintext Server")
	}
}

func TestConcurrentTunnelsAndControlReconnect(t *testing.T) {
	f := setup(t)
	address := target(t, false)
	f.startClient(t, []string{address})
	var wg sync.WaitGroup
	errors := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := tls.Dial("tcp", f.address, f.tls)
			if err != nil {
				errors <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if err = WriteMessage(conn, openMessage(address)); err != nil {
				errors <- err
				return
			}
			r, err := ReadMessage(conn)
			if err != nil || r.Kind != "ready" {
				errors <- fmt.Errorf("open: %v %+v", err, r)
				return
			}
			payload := []byte(fmt.Sprintf("isolated tunnel %d", i))
			_, err = conn.Write(payload)
			if err != nil {
				errors <- err
				return
			}
			actual := make([]byte, len(payload))
			_, err = io.ReadFull(conn, actual)
			if err != nil || !bytes.Equal(payload, actual) {
				errors <- fmt.Errorf("stream crossed or failed: %v", err)
			}
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	conn, reply := f.request(t, openMessage(address))
	if reply.Kind != "ready" {
		t.Fatal(reply)
	}
	f.s.mu.Lock()
	_ = f.s.agents["office"].conn.Close()
	f.s.mu.Unlock()
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("old tunnel survived loss of control")
	}
	// The same Client.Run must register again after server-side control loss.
	time.Sleep(1200 * time.Millisecond)
	f.waitOnline(t, true)
	_, reply = f.request(t, openMessage(address))
	if reply.Kind != "ready" {
		t.Fatal(reply)
	}
}

func TestFrameLimitsAndExactReads(t *testing.T) {
	var b bytes.Buffer
	_ = WriteMessage(&b, Message{Kind: "ready"})
	b.Write([]byte("SSH-2.0-test\r\n"))
	if _, err := ReadMessage(&b); err != nil {
		t.Fatal(err)
	}
	if b.String() != "SSH-2.0-test\r\n" {
		t.Fatal("header consumed protocol bytes")
	}
	for _, size := range []uint32{0, MaxFrame + 1} {
		b.Reset()
		_ = binary.Write(&b, binary.BigEndian, size)
		if _, err := ReadMessage(&b); err == nil {
			t.Fatal("oversize/empty frame accepted")
		}
	}
}

type transientAcceptErr struct{}

func (transientAcceptErr) Error() string   { return "temporary accept error" }
func (transientAcceptErr) Timeout() bool   { return false }
func (transientAcceptErr) Temporary() bool { return true }

type flakyListener struct {
	net.Listener
	mu       sync.Mutex
	failures int
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.failures > 0 {
		l.failures--
		l.mu.Unlock()
		return nil, transientAcceptErr{}
	}
	l.mu.Unlock()
	return l.Listener.Accept()
}

func TestServerServeRetriesTransientAcceptErrors(t *testing.T) {
	s, err := NewServer(ServerConfig{Listen: "127.0.0.1:0", Routes: []Route{{ID: "office", ClientToken: testClientToken, AccessToken: testAccessToken}}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	ln := &flakyListener{Listener: raw, failures: 2}
	f := serveFixture(t, &fixture{s: s, address: raw.Addr().String()}, ln)
	address := target(t, false)
	f.startClient(t, []string{address})
	conn, reply := f.request(t, openMessage(address))
	if reply.Kind != "ready" {
		t.Fatalf("expected ready after transient accept errors, got %+v", reply)
	}
	if _, err := conn.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	var out [2]byte
	if _, err := io.ReadFull(conn, out[:]); err != nil || string(out[:]) != "ok" {
		t.Fatalf("unexpected echo: %q, %v", out, err)
	}
	if isTransientAcceptError(net.ErrClosed) {
		t.Fatal("net.ErrClosed must not be treated as transient")
	}
	if isTransientAcceptError(errors.New("fatal listener failure")) {
		t.Fatal("arbitrary fatal error must not be treated as transient")
	}
}

func TestReconnectProbesAndEvictsStaleClient(t *testing.T) {
	f := setupPlainTCP(t)
	f.s.probeTimeout = 150 * time.Millisecond
	address := target(t, false)

	// Simulate a new Client (server_ping: true) whose control socket silently hangs
	// (e.g., NAT drop) without sending FIN/RST.
	ghost, registered := f.request(t, Message{
		Kind: "register", ClientID: "office", Token: testClientToken,
		DialFeedback: true, ServerPing: true,
	})
	if registered.Kind != "registered" || !registered.ServerPing {
		t.Fatalf("expected server_ping negotiation, got %+v", registered)
	}
	f.waitOnline(t, true)

	// Open a tunnel on the ghost so we also verify eviction tears down old tunnels.
	oldAccess := sendFixtureMessage(t, f.address, openMessage(address))
	dial := readFixtureMessage(t, ghost, "dial")
	oldWork := sendFixtureMessage(t, f.address, Message{
		Kind: "work", ClientID: "office", Token: testClientToken, ID: dial.ID, DialFeedback: true,
	})
	readFixtureMessage(t, oldAccess, "ready")
	waitTunnelCounts(t, f.s, 1, 0)

	// Freeze ghost: stop reading/replying to pings, then reconnect a healthy Client.
	started := time.Now()
	f.startClient(t, []string{address})
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("stale client eviction took too long: %s", elapsed)
	}

	// Evicted ghost tunnel must be closed promptly.
	_ = oldAccess.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := oldAccess.Read(b[:]); err == nil {
		t.Fatal("evicted ghost tunnel stayed open")
	}
	_ = oldWork.Close()
	_ = ghost.Close()

	// Fresh Client must relay traffic immediately.
	conn, reply := f.request(t, openMessage(address))
	if reply.Kind != "ready" {
		t.Fatalf("new client failed after evicting stale ghost: %+v", reply)
	}
	if _, err := conn.Write([]byte("fresh")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "fresh" {
		t.Fatalf("unexpected relay reply: %q, %v", buf, err)
	}
}

func TestReconnectRejectsLiveClientAfterProbe(t *testing.T) {
	f := setupPlainTCP(t)
	f.s.probeTimeout = 500 * time.Millisecond
	address := target(t, false)
	f.startClient(t, []string{address})

	active, ready := f.request(t, openMessage(address))
	if ready.Kind != "ready" {
		t.Fatal(ready)
	}

	// Duplicate registration against a live Client must fail with clientAlreadyOnline
	// after the Server probes the existing Client.
	_, reply := f.request(t, Message{
		Kind: "register", ClientID: "office", Token: testClientToken, ServerPing: true,
	})
	if reply.Error != "clientAlreadyOnline" {
		t.Fatalf("expected clientAlreadyOnline for live client, got %+v", reply)
	}

	// Existing tunnel must remain completely undisturbed.
	if _, err := active.Write([]byte("still-alive")); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len("still-alive"))
	if _, err := io.ReadFull(active, out); err != nil || string(out) != "still-alive" {
		t.Fatalf("active tunnel disturbed by probe: %q, %v", out, err)
	}
}

func TestLegacyClientNeverReceivesServerPing(t *testing.T) {
	f := setupPlainTCP(t)
	f.s.probeTimeout = 150 * time.Millisecond

	// Register a legacy Client that omits dial_feedback and server_ping.
	legacy, registered := f.request(t, Message{
		Kind: "register", ClientID: "office", Token: testClientToken,
	})
	if registered.Kind != "registered" || registered.ServerPing || registered.DialFeedback {
		t.Fatalf("unexpected legacy registration response: %+v", registered)
	}
	f.waitOnline(t, true)

	// Duplicate registration must be rejected WITHOUT sending any ping to the legacy Client.
	_, duplicate := f.request(t, Message{
		Kind: "register", ClientID: "office", Token: testClientToken, ServerPing: true,
	})
	if duplicate.Error != "clientAlreadyOnline" {
		t.Fatalf("expected clientAlreadyOnline, got %+v", duplicate)
	}

	// Legacy Client must still receive normal dial messages (not unexpected ping).
	address := target(t, false)
	access := sendFixtureMessage(t, f.address, openMessage(address))
	dial := readFixtureMessage(t, legacy, "dial")
	work := sendFixtureMessage(t, f.address, Message{
		Kind: "work", ClientID: "office", Token: testClientToken, ID: dial.ID,
	})
	readFixtureMessage(t, access, "ready")
	if _, err := work.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	var out [2]byte
	if _, err := io.ReadFull(access, out[:]); err != nil || string(out[:]) != "ok" {
		t.Fatalf("legacy relay failed: %q, %v", out, err)
	}
}

func TestNewClientWorksWithLegacyServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	address := target(t, false)
	host, portStr, _ := net.SplitHostPort(address)
	portNum, _ := strconv.Atoi(portStr)

	serverDone := make(chan error, 1)
	go func() {
		ctrl, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer ctrl.Close()
		_ = ctrl.SetDeadline(time.Now().Add(5 * time.Second))
		reg, err := ReadMessage(ctrl)
		if err != nil || reg.Kind != "register" {
			serverDone <- fmt.Errorf("unexpected register: %+v, %v", reg, err)
			return
		}
		// Legacy server omits dial_feedback and server_ping in registered reply.
		if err := WriteMessage(ctrl, Message{Kind: "registered"}); err != nil {
			serverDone <- err
			return
		}
		dialID := randomID()
		if err := WriteMessage(ctrl, Message{Kind: "dial", ID: dialID, Host: host, Port: uint16(portNum)}); err != nil {
			serverDone <- err
			return
		}
		workConn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer workConn.Close()
		_ = workConn.SetDeadline(time.Now().Add(5 * time.Second))
		workMsg, err := ReadMessage(workConn)
		if err != nil || workMsg.Kind != "work" || workMsg.ID != dialID || workMsg.Error != "" {
			serverDone <- fmt.Errorf("unexpected work: %+v, %v", workMsg, err)
			return
		}
		if _, err := workConn.Write([]byte("legacy-server")); err != nil {
			serverDone <- err
			return
		}
		echoed := make([]byte, len("legacy-server"))
		if _, err := io.ReadFull(workConn, echoed); err != nil || string(echoed) != "legacy-server" {
			serverDone <- fmt.Errorf("unexpected echo: %q, %v", echoed, err)
			return
		}
		serverDone <- nil
	}()

	client, err := NewClient(ClientConfig{
		Server: ln.Addr().String(), ID: "office", Token: testClientToken, Allow: []string{address},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	clientDone := make(chan struct{})
	go func() { _ = client.Run(ctx); close(clientDone) }()
	defer func() { cancel(); <-clientDone }()

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("legacy server test timed out")
	}
}

func TestControlWriterPriorityAndExpiry(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := newControlWriter(ctx, a, nil)
	defer func() { cancel(); _ = a.Close(); w.wait() }()

	// Block the first write on net.Pipe so subsequent enqueued frames sit in the queues.
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- w.send(Message{Kind: "dial", ID: "first"}, time.Now().Add(3*time.Second))
	}()
	time.Sleep(20 * time.Millisecond)

	// Enqueue an already-short normal dial and a priority pong.
	expiredErr := w.send(Message{Kind: "dial", ID: "expired"}, time.Now().Add(5*time.Millisecond))
	if !errors.Is(expiredErr, errControlWriteExpired) {
		t.Fatalf("expected errControlWriteExpired, got %v", expiredErr)
	}
	normalDone := make(chan error, 1)
	go func() {
		normalDone <- w.send(Message{Kind: "dial", ID: "normal"}, time.Now().Add(3*time.Second))
	}()
	time.Sleep(20 * time.Millisecond)
	if !w.enqueuePriority(Message{Kind: "pong", ID: "prio"}, time.Now().Add(3*time.Second)) {
		t.Fatal("failed to enqueue priority pong")
	}

	// Reading from b must yield first, then priority pong BEFORE normal dial.
	m1, err := ReadMessage(b)
	if err != nil || m1.ID != "first" {
		t.Fatalf("expected first, got %+v, %v", m1, err)
	}
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	m2, err := ReadMessage(b)
	if err != nil || m2.Kind != "pong" || m2.ID != "prio" {
		t.Fatalf("expected priority pong ahead of normal dial, got %+v, %v", m2, err)
	}
	m3, err := ReadMessage(b)
	if err != nil || m3.Kind != "dial" || m3.ID != "normal" {
		t.Fatalf("expected normal dial, got %+v, %v", m3, err)
	}
	if err := <-normalDone; err != nil {
		t.Fatal(err)
	}
}

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c2 := <-accepted
	if c2 == nil {
		_ = c1.Close()
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })
	return c1, c2
}

func TestRelayHalfCloseIdleTimeoutAndActiveDrain(t *testing.T) {
	t.Run("stalled half-close terminates after idle timeout", func(t *testing.T) {
		clientEnd, relayA := tcpPair(t)
		relayB, stalledPeer := tcpPair(t)
		done := make(chan struct{})
		go func() {
			relayWithHalfCloseTimeout(relayA, relayB, 120*time.Millisecond)
			close(done)
		}()
		// Client finishes sending and half-closes; stalledPeer reads EOF but never closes back.
		_, _ = clientEnd.Write([]byte("req"))
		_ = clientEnd.(interface{ CloseWrite() error }).CloseWrite()
		got, _ := io.ReadAll(stalledPeer)
		if string(got) != "req" {
			t.Fatalf("stalledPeer got %q", got)
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("relay leaked on stalled half-close")
		}
	})

	t.Run("active draining extends half-close idle deadline", func(t *testing.T) {
		clientEnd, relayA := tcpPair(t)
		relayB, slowPeer := tcpPair(t)
		done := make(chan struct{})
		go func() {
			relayWithHalfCloseTimeout(relayA, relayB, 160*time.Millisecond)
			close(done)
		}()
		_, _ = clientEnd.Write([]byte("req"))
		_ = clientEnd.(interface{ CloseWrite() error }).CloseWrite()
		gotReq, _ := io.ReadAll(slowPeer)
		if string(gotReq) != "req" {
			t.Fatalf("slowPeer got %q", gotReq)
		}
		// Trickle 6 chunks spaced 60ms apart (total 360ms > 160ms idle timeout).
		var want bytes.Buffer
		for i := 0; i < 6; i++ {
			time.Sleep(60 * time.Millisecond)
			chunk := fmt.Sprintf("chunk-%d|", i)
			want.WriteString(chunk)
			if _, err := slowPeer.Write([]byte(chunk)); err != nil {
				t.Fatalf("slowPeer write %d failed: %v", i, err)
			}
		}
		_ = slowPeer.(interface{ CloseWrite() error }).CloseWrite()
		gotResp, err := io.ReadAll(clientEnd)
		if err != nil {
			t.Fatal(err)
		}
		if string(gotResp) != want.String() {
			t.Fatalf("got %q, want %q", gotResp, want.String())
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("relay did not finish after drain")
		}
	})
}
