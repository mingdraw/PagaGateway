package gateway

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type targetHostKind uint8

const (
	targetHostAny targetHostKind = iota
	targetHostExactIP
	targetHostCIDR
	targetHostExactDomain
	targetHostWildcardDomain
)

type targetRule struct {
	allowAll  bool
	hostKind  targetHostKind
	addr      netip.Addr
	prefix    netip.Prefix
	host      string
	portStart uint16
	portEnd   uint16
}

func (r targetRule) matchesPort(port uint16) bool {
	return port >= r.portStart && port <= r.portEnd
}

type exactTargetKey struct {
	host string
	port uint16
}

type targetACL struct {
	allowAll    bool
	exactDomain map[exactTargetKey]struct{}
	rules       []targetRule
}

func compileTargetACL(entries []string) (*targetACL, error) {
	if len(entries) == 0 {
		return nil, errors.New("valid id and non-empty allowed_targets are required")
	}
	acl := &targetACL{
		exactDomain: make(map[exactTargetKey]struct{}),
	}
	for _, entry := range entries {
		rule, err := parseTargetRule(entry)
		if err != nil {
			return nil, err
		}
		if rule.allowAll {
			acl.allowAll = true
			continue
		}
		if rule.hostKind == targetHostExactDomain && rule.portStart == rule.portEnd {
			acl.exactDomain[exactTargetKey{host: rule.host, port: rule.portStart}] = struct{}{}
			continue
		}
		acl.rules = append(acl.rules, rule)
	}
	return acl, nil
}

func (a *targetACL) allowed(host string, port uint16) bool {
	if port == 0 || host == "" || strings.ContainsAny(host, " \t\r\n%") {
		return false
	}
	if a.allowAll {
		return true
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return false
		}
		for _, rule := range a.rules {
			if !rule.matchesPort(port) {
				continue
			}
			switch rule.hostKind {
			case targetHostAny:
				return true
			case targetHostExactIP:
				if rule.addr == addr {
					return true
				}
			case targetHostCIDR:
				if rule.prefix.Contains(addr) {
					return true
				}
			}
		}
		return false
	}
	norm := strings.TrimSuffix(strings.ToLower(host), ".")
	if norm == "" {
		return false
	}
	if _, ok := a.exactDomain[exactTargetKey{host: norm, port: port}]; ok {
		return true
	}
	for _, rule := range a.rules {
		if !rule.matchesPort(port) {
			continue
		}
		switch rule.hostKind {
		case targetHostAny:
			return true
		case targetHostExactDomain:
			if rule.host == norm {
				return true
			}
		case targetHostWildcardDomain:
			if strings.HasSuffix(norm, "."+rule.host) {
				return true
			}
		}
	}
	return false
}

const errInvalidAllowedTarget = `allowed_targets must contain "*" or valid host/CIDR/wildcard:port rules`

func parseTargetRule(raw string) (targetRule, error) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return targetRule{}, errors.New(errInvalidAllowedTarget)
	}
	if raw == "*" {
		return targetRule{allowAll: true}, nil
	}
	host, portText, err := net.SplitHostPort(raw)
	if err != nil || host == "" || portText == "" {
		return targetRule{}, errors.New(errInvalidAllowedTarget)
	}
	if strings.ContainsAny(host, " \t\r\n%") {
		return targetRule{}, errors.New(errInvalidAllowedTarget)
	}
	portStart, portEnd, err := parsePortSpec(portText)
	if err != nil {
		return targetRule{}, errors.New(errInvalidAllowedTarget)
	}
	rule := targetRule{portStart: portStart, portEnd: portEnd}
	switch {
	case host == "*":
		rule.hostKind = targetHostAny
		return rule, nil
	case strings.Contains(host, "/"):
		prefix, err := netip.ParsePrefix(host)
		if err != nil || prefix.Addr().Zone() != "" {
			return targetRule{}, errors.New(errInvalidAllowedTarget)
		}
		rule.hostKind = targetHostCIDR
		rule.prefix = prefix.Masked()
		return rule, nil
	case strings.HasPrefix(host, "*."):
		suffix := strings.TrimSuffix(strings.ToLower(host[2:]), ".")
		if !isValidDomainSuffix(suffix) {
			return targetRule{}, errors.New(errInvalidAllowedTarget)
		}
		rule.hostKind = targetHostWildcardDomain
		rule.host = suffix
		return rule, nil
	case strings.Contains(host, "*"):
		return targetRule{}, errors.New(errInvalidAllowedTarget)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return targetRule{}, errors.New(errInvalidAllowedTarget)
		}
		rule.hostKind = targetHostExactIP
		rule.addr = addr
		return rule, nil
	}
	norm := strings.TrimSuffix(strings.ToLower(host), ".")
	if !isValidDomainSuffix(norm) {
		return targetRule{}, errors.New(errInvalidAllowedTarget)
	}
	rule.hostKind = targetHostExactDomain
	rule.host = norm
	return rule, nil
}

func parsePortSpec(text string) (uint16, uint16, error) {
	if text == "*" {
		return 1, 65535, nil
	}
	if startText, endText, ok := strings.Cut(text, "-"); ok {
		start, err1 := parseCanonicalPort(startText)
		end, err2 := parseCanonicalPort(endText)
		if err1 != nil || err2 != nil || start > end {
			return 0, 0, errors.New("invalid port range")
		}
		return start, end, nil
	}
	port, err := parseCanonicalPort(text)
	if err != nil {
		return 0, 0, err
	}
	return port, port, nil
}

func parseCanonicalPort(text string) (uint16, error) {
	n, err := strconv.ParseUint(text, 10, 16)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != text {
		return 0, errors.New("invalid port")
	}
	return uint16(n), nil
}

func isValidDomainSuffix(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			return false
		}
		for i := 0; i < len(label); i++ {
			b := label[i]
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_') {
				return false
			}
		}
	}
	return true
}
