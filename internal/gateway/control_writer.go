package gateway

import (
	"context"
	"errors"
	"net"
	"time"
)

var errControlWriteExpired = errors.New("control write budget exhausted before sending")

const (
	minDialBudget        = 25 * time.Millisecond
	controlPriorityQueue = 64
	controlNormalQueue   = 128
)

type controlRequest struct {
	msg      Message
	deadline time.Time
	done     chan error
}

// controlWriter decouples control-plane reads from writes with a single writer
// goroutine and a priority lane for heartbeats, liveness probes, and dial
// failures. A request that expires before touching the wire returns
// errControlWriteExpired without closing the stream.
type controlWriter struct {
	conn     net.Conn
	priority chan controlRequest
	normal   chan controlRequest
	done     chan struct{}
	onError  func(error)
}

func newControlWriter(ctx context.Context, conn net.Conn, onError func(error)) *controlWriter {
	w := &controlWriter{
		conn:     conn,
		priority: make(chan controlRequest, controlPriorityQueue),
		normal:   make(chan controlRequest, controlNormalQueue),
		done:     make(chan struct{}),
		onError:  onError,
	}
	go w.loop(ctx)
	return w
}

func (w *controlWriter) loop(ctx context.Context) {
	defer close(w.done)
	for {
		var req controlRequest
		// Drain priority frames before normal dial requests.
		select {
		case <-ctx.Done():
			return
		case req = <-w.priority:
		default:
			select {
			case <-ctx.Done():
				return
			case req = <-w.priority:
			case req = <-w.normal:
			}
		}
		err := w.writeOne(req)
		if req.done != nil {
			req.done <- err
		}
		if err != nil && !errors.Is(err, errControlWriteExpired) {
			if w.onError != nil {
				w.onError(err)
			}
			return
		}
	}
}

func (w *controlWriter) writeOne(req controlRequest) error {
	remaining := time.Until(req.deadline)
	if remaining <= 0 || (req.msg.Kind == "dial" && remaining < minDialBudget) {
		return errControlWriteExpired
	}
	m := req.msg
	if m.Kind == "dial" && m.TimeoutMS > 0 {
		m.TimeoutMS = max(1, remaining.Milliseconds())
	}
	if err := w.conn.SetWriteDeadline(req.deadline); err != nil {
		return err
	}
	return WriteMessage(w.conn, m)
}

func (w *controlWriter) send(m Message, deadline time.Time) error {
	return w.sendTo(w.normal, m, deadline)
}

func (w *controlWriter) sendPriority(m Message, deadline time.Time) error {
	return w.sendTo(w.priority, m, deadline)
}

func (w *controlWriter) sendTo(ch chan controlRequest, m Message, deadline time.Time) error {
	if remaining := time.Until(deadline); remaining <= 0 || (m.Kind == "dial" && remaining < minDialBudget) {
		return errControlWriteExpired
	}
	req := controlRequest{msg: m, deadline: deadline, done: make(chan error, 1)}
	select {
	case <-w.done:
		return net.ErrClosed
	default:
	}
	select {
	case ch <- req:
	case <-w.done:
		return net.ErrClosed
	default:
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		select {
		case ch <- req:
		case <-w.done:
			return net.ErrClosed
		case <-timer.C:
			return errControlWriteExpired
		}
	}
	select {
	case err := <-req.done:
		return err
	case <-w.done:
		return net.ErrClosed
	}
}

// enqueuePriority posts a control response without blocking the reader loop.
// Returns false if the writer has stopped or the priority queue is saturated.
func (w *controlWriter) enqueuePriority(m Message, deadline time.Time) bool {
	select {
	case <-w.done:
		return false
	default:
	}
	select {
	case w.priority <- controlRequest{msg: m, deadline: deadline}:
		return true
	case <-w.done:
		return false
	default:
		return false
	}
}

func (w *controlWriter) wait() {
	<-w.done
}
