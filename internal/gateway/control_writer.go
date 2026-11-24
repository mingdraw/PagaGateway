package gateway

import (
	"errors"
	"net"
	"time"
)

var errControlWriteExpired = errors.New("control write budget exhausted before sending")

const minDialBudget = 25 * time.Millisecond

// Serialize control frames and their deadlines. A request that expires while
// waiting for the writer has not touched the stream and must not close it.
type controlWriter struct {
	conn net.Conn
	slot chan struct{}
}

func newControlWriter(conn net.Conn) controlWriter {
	return controlWriter{conn: conn, slot: make(chan struct{}, 1)}
}

func (w *controlWriter) send(m Message, deadline time.Time) error {
	select {
	case w.slot <- struct{}{}:
	default:
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		select {
		case w.slot <- struct{}{}:
		case <-timer.C:
			return errControlWriteExpired
		}
	}
	defer func() { <-w.slot }()
	remaining := time.Until(deadline)
	if remaining <= 0 || (m.Kind == "dial" && remaining < minDialBudget) {
		return errControlWriteExpired
	}
	if m.Kind == "dial" && m.TimeoutMS > 0 {
		m.TimeoutMS = max(1, remaining.Milliseconds())
	}
	if err := w.conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	return WriteMessage(w.conn, m)
}
