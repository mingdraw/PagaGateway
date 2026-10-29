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
}

// Clients returns a detached snapshot sorted by Client ID. Address is the peer
// address observed by this Server, including the source TCP port.
func (s *Server) Clients() []ClientInfo {
	s.mu.Lock()
	clients := make([]ClientInfo, 0, len(s.config.Routes))
	for _, route := range s.config.Routes {
		info := ClientInfo{ID: route.ID, Status: "offline"}
		if a := s.agents[route.ID]; a != nil {
			connectedAt := a.connectedAt
			info.Status, info.Address, info.ConnectedAt = "online", a.address, &connectedAt
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
