package gateway

import (
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"syscall"
	"time"
)

const (
	ClientConnecting   = "connecting"
	ClientConnected    = "connected"
	ClientReconnecting = "reconnecting"
)

// ClientStatus describes the local Client's registration with its Server.
type ClientStatus struct {
	State                string    `json:"state"`
	LastError            string    `json:"last_error,omitempty"`
	LastErrorAt          time.Time `json:"last_error_at,omitzero"`
	MaxTunnels           int       `json:"max_tunnels"`
	PendingTunnels       int       `json:"pending_tunnels"`
	ActiveTunnels        int       `json:"active_tunnels"`
	BusyRejects          uint64    `json:"busy_rejects"`
	LastTunnelError      string    `json:"last_tunnel_error,omitempty"`
	LastTunnelErrorAt    time.Time `json:"last_tunnel_error_at,omitzero"`
	LastTargetDialMicros int64     `json:"last_target_dial_us,omitempty"`
	LastWorkDialMicros   int64     `json:"last_work_dial_us,omitempty"`
}

func (c *Client) Status() ClientStatus {
	c.statusMu.RLock()
	defer c.statusMu.RUnlock()
	return c.status
}

func (c *Client) setStatus(status ClientStatus) {
	c.statusMu.Lock()
	c.status.State = status.State
	c.status.LastError = status.LastError
	c.status.LastErrorAt = status.LastErrorAt
	c.statusMu.Unlock()
}

func (c *Client) changeTunnelCounts(pending, active int) {
	c.statusMu.Lock()
	c.status.PendingTunnels += pending
	c.status.ActiveTunnels += active
	c.statusMu.Unlock()
}

func (c *Client) recordDialDuration(work bool, elapsed time.Duration) {
	c.statusMu.Lock()
	if work {
		c.status.LastWorkDialMicros = elapsed.Microseconds()
	} else {
		c.status.LastTargetDialMicros = elapsed.Microseconds()
	}
	c.statusMu.Unlock()
}

func (c *Client) recordTunnelFailure(code string, reason error) {
	now := time.Now()
	c.statusMu.Lock()
	if code == "clientBusy" {
		c.status.BusyRejects++
	}
	c.status.LastTunnelError = reason.Error()
	c.status.LastTunnelErrorAt = now.UTC()
	shouldLog := now.Sub(c.lastTunnelLog) >= time.Second
	if shouldLog {
		c.lastTunnelLog = now
	}
	c.statusMu.Unlock()
	if shouldLog {
		log.Printf("Page tunnel failed (%s): %s", code, reason)
	}
}

// Use known protocol and network errors for diagnostics shared by logs and status.
// Do not include raw endpoint addresses, frames, or peer-supplied error text.
func clientConnectionError(stage string, err error) error {
	var dnsErr *net.DNSError
	var addrErr *net.AddrError
	var recordErr tls.RecordHeaderError
	var netErr net.Error
	var errno syscall.Errno
	var detail string
	switch {
	case errors.Is(err, errRelayFingerprintMismatch):
		detail = "证书指纹不匹配，请核对 server_fingerprint"
	case errors.Is(err, errRelayCertificateMissing):
		detail = "Server 未提供证书"
	case errors.As(err, &recordErr):
		detail = "Server 未返回有效的 TLS 数据，请检查端口和 TLS 配置"
	case errors.As(err, &dnsErr):
		switch {
		case dnsErr.IsNotFound:
			detail = "找不到域名（DNS）"
		case dnsErr.Timeout():
			detail = "DNS 解析超时"
		default:
			detail = "DNS 解析失败"
		}
	case errors.As(err, &addrErr):
		detail = "地址无效"
	case errors.As(err, &netErr) && netErr.Timeout():
		detail = "等待超时"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		detail = "对端关闭了连接"
	case errors.Is(err, net.ErrClosed):
		detail = "连接已关闭"
	case errors.Is(err, errInvalidFrameSize), errors.Is(err, errInvalidPageFrame):
		detail = "Server 返回的消息不符合 Page v1 协议"
	case errors.Is(err, errInvalidFrame):
		detail = "请求超出 Page v1 消息大小限制"
	case errors.As(err, &errno):
		detail = errno.Error()
	default:
		return errors.New(stage)
	}
	return errors.New(stage + "：" + detail)
}

func clientRegistrationError(code string) error {
	switch code {
	case "unauthorized":
		return errors.New("注册被拒绝（unauthorized）：请核对 Client ID 和注册令牌")
	case "clientAlreadyOnline":
		return errors.New("注册被拒绝（clientAlreadyOnline）：相同 Client ID 已在线")
	case "gatewayBusy":
		return errors.New("注册被拒绝（gatewayBusy）：Page Server 连接额度已满")
	case "invalidKind":
		return errors.New("注册被拒绝（invalidKind）：Server 不支持注册请求")
	default:
		return errors.New("Server 拒绝注册（未知错误码）")
	}
}
