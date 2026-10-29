package main

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCommandArguments(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"client", "clients", "-config", "client.json"}, "only supported by server"},
		{[]string{"server", "clients", "unexpected"}, "unexpected positional arguments"},
		{[]string{"server", "start"}, "-config is required"},
		{[]string{"server", "run"}, "-config is required"},
		{[]string{"client", "run", "-config", "client.json", "-log", "client.log"}, "require a background command"},
		{[]string{"server", "run", "-config", "server.json", "-pidfile", "server.pid"}, "require a background command"},
		{[]string{"server", "status", "-config", "server.json", "-json"}, "-json requires server clients"},
		{[]string{"server", "clients", "-config", "server.json", "-log", "server.log"}, "-log requires start"},
		{[]string{"server", "restart", "-log", "server.log"}, "-log requires start"},
		{[]string{"client", "restart", "-json"}, "-json requires server clients"},
		{[]string{"help", "unknown"}, "unknown help topic"},
		{[]string{"server", "help", "unexpected"}, "unexpected positional arguments"},
		{[]string{"client", "help", "unexpected"}, "unexpected positional arguments"},
	} {
		if err := run(test.args); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("%v: %v, want %q", test.args, err, test.want)
		}
	}
}

func TestCertificateCreatesUsablePairAndRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	args := []string{"-host", "127.0.0.1", "-cert", cert, "-key", key}
	if err := certificate(args); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := certificate(args); err == nil {
		t.Fatal("existing deployment key was overwritten")
	}
	current, _ := os.ReadFile(key)
	if string(original) != string(current) {
		t.Fatal("existing key changed")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(key)
		if info.Mode().Perm() != 0600 {
			t.Fatal("private key is not owner-only")
		}
	}
}
