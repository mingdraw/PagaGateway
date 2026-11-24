package gateway

import (
	"sort"
	"time"
)

// ClientInfo describes a configured Client's current control connection.
// It contains no route credentials. Times are nil while offline; the heartbeat
// time is also nil until the first ping has arrived on this connection.
type ClientInfo struct {
	ID              string     `json:"id"`
	Status          string     `json:"status"`
	Address         string     `json:"address"`
	ConnectedAt     *time.Time `json:"connected_at"`
	LastHeartbeatAt *time.Time `json:"last_heartbeat_at"`
	ActiveTunnels   int        `json:"active_tunnels"`
	PendingTunnels  int        `json:"pending_tunnels"`
	MaxTunnels      int        `json:"max_tunnels,omitempty"`
	BusyRejects     uint64     `json:"busy_rejects"`
	LastOpenMicros  int64      `json:"last_open_us,omitempty"`
}

type ServerStatus struct {
	MaxConnections       int `json:"max_connections"`
	CommittedConnections int `json:"committed_connections"`
	ActiveTunnels        int `json:"active_tunnels"`
	PendingTunnels       int `json:"pending_tunnels"`
}

func (s *Server) Status() ServerStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ServerStatus{
		MaxConnections: s.config.MaxConnections, CommittedConnections: len(s.agents) + 2*s.tunnels,
		ActiveTunnels: s.active, PendingTunnels: s.tunnels - s.active,
	}
}

// Clients returns a detached snapshot sorted by Client ID. Address is the peer
// address observed by this Server, including the source TCP port.
func (s *Server) Clients() []ClientInfo {
	s.mu.Lock()
	clients := make([]ClientInfo, 0, len(s.routes))
	for id, route := range s.routes {
		info := ClientInfo{
			ID: id, Status: "offline", MaxTunnels: route.maxTunnels,
			BusyRejects: route.busyRejects, LastOpenMicros: route.lastOpenMicros,
		}
		if a := s.agents[id]; a != nil && a.online {
			connectedAt := a.connectedAt
			info.Status, info.Address, info.ConnectedAt = "online", a.address, &connectedAt
			info.ActiveTunnels, info.PendingTunnels, info.MaxTunnels = a.active, a.pending, a.maxTunnels
			if !a.lastHeartbeatAt.IsZero() {
				lastHeartbeatAt := a.lastHeartbeatAt
				info.LastHeartbeatAt = &lastHeartbeatAt
			}
		}
		clients = append(clients, info)
	}
	s.mu.Unlock()
	sort.Slice(clients, func(i, j int) bool { return clients[i].ID < clients[j].ID })
	return clients
}
