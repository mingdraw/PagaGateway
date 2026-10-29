package gateway

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

const PlainTCPWarning = "WARNING: TLS is disabled. Traffic and tokens are sent in plaintext, and the server identity is not verified. Use only on trusted networks."

type Route struct {
	ID          string `json:"id"`
	ClientToken string `json:"client_token"`
	AccessToken string `json:"access_token"`
}

type ServerConfig struct {
	Listen         string  `json:"listen"`
	CertFile       string  `json:"cert_file,omitempty"`
	KeyFile        string  `json:"key_file,omitempty"`
	MaxConnections int     `json:"max_connections"`
	Routes         []Route `json:"routes"`
}

type ClientConfig struct {
	Server      string   `json:"server"`
	Fingerprint string   `json:"server_fingerprint,omitempty"`
	ID          string   `json:"id"`
	Token       string   `json:"token"`
	Allow       []string `json:"allowed_targets"`
	MaxTunnels  int      `json:"max_tunnels"`
}

func LoadConfig(path string, value any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return errors.New("invalid configuration JSON")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("configuration must contain one JSON object")
	}
	return nil
}

func (c *ServerConfig) validate() error {
	if c.Listen == "" || len(c.Routes) == 0 {
		return errors.New("listen and routes are required")
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return errors.New("cert_file and key_file must both be set for TLS, or both omitted for plaintext TCP")
	}
	if c.MaxConnections == 0 {
		c.MaxConnections = 1024
	}
	if c.MaxConnections < 2 {
		return errors.New("max_connections must be at least 2")
	}
	seen := map[string]bool{}
	for i := range c.Routes {
		r := &c.Routes[i]
		if !validID(r.ID) || seen[r.ID] {
			return errors.New("route IDs must be unique and use 1-64 letters, digits, hyphens or underscores")
		}
		seen[r.ID] = true
		if r.ClientToken == "" || r.AccessToken == "" {
			return errors.New("client_token and access_token are required")
		}
		if equalToken(r.ClientToken, r.AccessToken) {
			return errors.New("client and access tokens must be different")
		}
	}
	return nil
}

func validID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, ch := range id {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}

func (c *ClientConfig) validate() error {
	if _, _, err := net.SplitHostPort(c.Server); err != nil {
		return errors.New("server must be host:port")
	}
	if !validID(c.ID) || len(c.Allow) == 0 {
		return errors.New("valid id and non-empty allowed_targets are required")
	}
	for _, address := range c.Allow {
		if address == "*" {
			continue
		}
		host, port, err := net.SplitHostPort(address)
		number, portErr := strconv.ParseUint(port, 10, 16)
		if err != nil || host == "" || portErr != nil || number == 0 || strconv.FormatUint(number, 10) != port {
			return errors.New(`allowed_targets must contain "*" or exact host:port addresses`)
		}
	}
	if c.MaxTunnels == 0 {
		c.MaxTunnels = 128
	}
	if c.MaxTunnels < 1 {
		return errors.New("max_tunnels must be positive")
	}
	if c.Token == "" {
		return errors.New("token is required")
	}
	return nil
}

// Pinning is the trust model: a certificate hash must be distributed out of band.
// The TLS implementation still verifies possession of the certificate's key.
func PinnedTLS(fingerprint string) (*tls.Config, error) {
	fingerprint = strings.TrimPrefix(strings.TrimSpace(fingerprint), "SHA256:")
	fingerprint = strings.ReplaceAll(fingerprint, ":", "")
	pin, err := hex.DecodeString(fingerprint)
	if err != nil || len(pin) != sha256.Size {
		return nil, errors.New("server_fingerprint must be a SHA-256 certificate hex digest")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		// PKI name/CA/expiry validation is replaced by exact certificate pinning.
		InsecureSkipVerify: true, //nolint:gosec // mandatory VerifyConnection below
		VerifyConnection: func(s tls.ConnectionState) error {
			if len(s.PeerCertificates) == 0 {
				return errors.New("missing relay certificate")
			}
			digest := sha256.Sum256(s.PeerCertificates[0].Raw)
			if !equalToken(hex.EncodeToString(digest[:]), hex.EncodeToString(pin)) {
				return errors.New("relay certificate fingerprint mismatch")
			}
			return nil
		},
	}, nil
}
