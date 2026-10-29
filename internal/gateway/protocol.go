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
	"strings"
	"time"
)

const MaxFrame = 8192
const handshakeTimeout = 15 * time.Second

// Message is length-prefixed JSON. After ready, the connection carries raw TCP.
type Message struct {
	Version  int    `json:"version"`
	Kind     string `json:"kind"`
	ClientID string `json:"client_id,omitempty"`
	Token    string `json:"token,omitempty"`
	ID       string `json:"id,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     uint16 `json:"port,omitempty"`
	Error    string `json:"error,omitempty"`
}

func ReadMessage(r io.Reader) (Message, error) {
	var size uint32
	if err := binary.Read(r, binary.BigEndian, &size); err != nil {
		return Message{}, err
	}
	if size == 0 || size > MaxFrame {
		return Message{}, errors.New("invalid frame size")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return Message{}, err
	}
	var m Message
	if err := json.Unmarshal(data, &m); err != nil || m.Version != 1 {
		return Message{}, errors.New("invalid Page v1 frame")
	}
	return m, nil
}

func WriteMessage(w io.Writer, m Message) error {
	m.Version = 1
	data, err := json.Marshal(m)
	if err != nil || len(data) > MaxFrame {
		return errors.New("invalid frame")
	}
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame, uint32(len(data)))
	copy(frame[4:], data)
	_, err = io.Copy(w, strings.NewReader(string(frame)))
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
	x, y := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(x[:], y[:]) == 1
}

// Preserve TCP half-close so request/EOF/response protocols can drain replies.
// TLS CloseWrite sends close_notify without closing the read direction.
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
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
		done <- struct{}{}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	<-done
	<-done
}
