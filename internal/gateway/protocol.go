// Package gateway implements the Page v1 reverse TCP relay used by PagaShell.
package gateway

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"
)

const MaxFrame = 8192
const handshakeTimeout = 15 * time.Second

var (
	errInvalidFrameSize = errors.New("invalid frame size")
	errInvalidPageFrame = errors.New("invalid Page v1 frame")
	errInvalidFrame     = errors.New("invalid frame")
)

// Message is length-prefixed JSON. After ready, the connection carries raw TCP.
type Message struct {
	Version       int    `json:"version"`
	Kind          string `json:"kind"`
	ClientID      string `json:"client_id,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
	Token         string `json:"token,omitempty"`
	ID            string `json:"id,omitempty"`
	Host          string `json:"host,omitempty"`
	Port          uint16 `json:"port,omitempty"`
	Error         string `json:"error,omitempty"`
	MaxTunnels    int    `json:"max_tunnels,omitempty"`
	DialFeedback  bool   `json:"dial_feedback,omitempty"`
	TimeoutMS     int64  `json:"timeout_ms,omitempty"`
}

func ReadMessage(r io.Reader) (Message, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Message{}, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxFrame {
		return Message{}, errInvalidFrameSize
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return Message{}, err
	}
	var m Message
	if err := json.Unmarshal(data, &m); err != nil || m.Version != 1 {
		return Message{}, errInvalidPageFrame
	}
	return m, nil
}

func WriteMessage(w io.Writer, m Message) error {
	m.Version = 1
	data, err := json.Marshal(m)
	if err != nil || len(data) > MaxFrame {
		return errInvalidFrame
	}
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame, uint32(len(data)))
	copy(frame[4:], data)
	n, err := w.Write(frame)
	if err == nil && n != len(frame) {
		return io.ErrShortWrite
	}
	return err
}

func randomID() string {
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		panic("operating system random source unavailable")
	}
	return hex.EncodeToString(data[:])
}

func equalToken(a, b string) bool {
	return matchesToken(a, sha256.Sum256([]byte(b)))
}

func matchesToken(token string, digest [sha256.Size]byte) bool {
	hash := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(hash[:], digest[:]) == 1
}

// Older Page v1 peers omit the hint. A peer cannot extend our own deadline.
func withTimeoutHint(deadline time.Time, millis int64) time.Time {
	if millis > 0 && millis < handshakeTimeout.Milliseconds() {
		if hint := time.Now().Add(time.Duration(millis) * time.Millisecond); hint.Before(deadline) {
			return hint
		}
	}
	return deadline
}

func dialFailureCode(code string) string {
	switch code {
	case "clientBusy", "workUnavailable", "targetDenied", "targetTimeout":
		return code
	default:
		return "targetUnavailable"
	}
}

// Preserve TCP half-close so request/EOF/response protocols can drain replies.
// TLS CloseWrite sends close_notify without closing the read direction.
func relay(a, b net.Conn) {
	done := make(chan struct{})
	copyOne := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if err != nil {
			_ = a.Close()
			_ = b.Close()
		} else if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go func() {
		copyOne(a, b)
		close(done)
	}()
	copyOne(b, a)
	<-done
}
