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
	client, err := NewClient(ClientConfig{Server: f.address, Fingerprint: f.fingerprint, ID: "office", Token: testClientToken, Allow: allowed})
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
		online := f.s.agents["office"] != nil
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
