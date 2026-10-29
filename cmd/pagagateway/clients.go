package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/mingdraw/PagaGateway/internal/gateway"
)

func listBackgroundClients(ctx context.Context, config, statePath string, asJSON bool) error {
	state, err := clientListServer(ctx, config, statePath)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("Page Server 服务未启动")
	}
	if err != nil {
		return err
	}
	reply, err := requestBackground(ctx, state, http.MethodGet, "/clients")
	if errors.Is(err, errBackgroundNotResponding) {
		return errors.New("Page Server 服务未启动或无法响应")
	}
	if err != nil {
		return err
	}
	if reply.Clients == nil {
		return errors.New("invalid client list response")
	}
	return writeClientList(os.Stdout, reply.Clients, asJSON)
}

func clientListServer(ctx context.Context, config, statePath string) (backgroundState, error) {
	instance, err := resolveBackgroundInstance(ctx, "server", config, statePath)
	return instance.state, err
}

func writeClientList(output io.Writer, clients []gateway.ClientInfo, asJSON bool) error {
	if asJSON {
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		return encoder.Encode(clients)
	}
	online := 0
	for _, client := range clients {
		if client.Status == "online" {
			online++
		}
	}
	if _, err := fmt.Fprintf(output, "Clients: %d online / %d configured\n", online, len(clients)); err != nil {
		return err
	}
	table := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "CLIENT_ID\tSTATUS\tADDRESS\tCONNECTED_AT\tLAST_HEARTBEAT"); err != nil {
		return err
	}
	for _, client := range clients {
		address := client.Address
		if address == "" {
			address = "-"
		}
		if _, err := fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\n", client.ID, client.Status, address, clientTime(client.ConnectedAt), clientTime(client.LastHeartbeatAt)); err != nil {
			return err
		}
	}
	return table.Flush()
}

func clientTime(value *time.Time) string {
	if value == nil {
		return "-"
	}
	return value.Local().Format(time.RFC3339)
}
