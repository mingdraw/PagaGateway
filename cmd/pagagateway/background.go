package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mingdraw/PagaGateway/internal/gateway"
)

const backgroundTimeout = 10 * time.Second

var errBackgroundNotResponding = errors.New("background process is not responding")

type backgroundState struct {
	PID      int    `json:"pid"`
	Role     string `json:"role"`
	Config   string `json:"config"`
	Log      string `json:"log"`
	Address  string `json:"address"`
	Instance string `json:"instance"`
	Secret   string `json:"secret"`
	PlainTCP bool   `json:"plain_tcp,omitempty"`
	WorkDir  string `json:"work_dir,omitempty"`
}

type backgroundReply struct {
	PID      int                  `json:"pid"`
	Instance string               `json:"instance"`
	Clients  []gateway.ClientInfo `json:"clients,omitempty"`
}

func randomID() (string, error) {
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(data[:]), nil
}

func readBackgroundState(path, role, config string) (backgroundState, error) {
	var state backgroundState
	f, err := os.Open(path)
	if err != nil {
		return state, err
	}
	defer f.Close()
	if err := json.NewDecoder(io.LimitReader(f, 64<<10)).Decode(&state); err != nil {
		return state, errors.New("invalid background state file")
	}
	host, _, err := net.SplitHostPort(state.Address)
	if err != nil || host != "127.0.0.1" || state.PID <= 0 || state.Secret == "" || state.Instance == "" || state.Role != role || !filepath.IsAbs(state.Config) || (config != "" && state.Config != config) || (state.WorkDir != "" && !filepath.IsAbs(state.WorkDir)) {
		return state, errors.New("background state does not match this configuration")
	}
	return state, nil
}

func writeBackgroundState(path string, state backgroundState) error {
	return writeBackgroundJSON(path, state)
}

func writeBackgroundJSON(path string, value any) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".pagagateway-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := json.NewEncoder(f).Encode(value); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// Management commands address the instance through an authenticated loopback endpoint.
// A PID read from a stale file is never used to signal an unrelated process.
func contactBackground(ctx context.Context, state backgroundState, stop bool) error {
	method, path := http.MethodGet, "/status"
	if stop {
		method, path = http.MethodPost, "/stop"
	}
	_, err := requestBackground(ctx, state, method, path)
	return err
}

func requestBackground(ctx context.Context, state backgroundState, method, path string) (backgroundReply, error) {
	var reply backgroundReply
	req, err := http.NewRequestWithContext(ctx, method, "http://"+state.Address+path, nil)
	if err != nil {
		return reply, err
	}
	req.Header.Set("Authorization", "Bearer "+state.Secret)
	client := &http.Client{
		Timeout:   time.Second,
		Transport: &http.Transport{DisableKeepAlives: true}, // no environment proxy
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(req)
	if err != nil {
		return reply, errBackgroundNotResponding
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusNotFound && path == "/clients" {
			return reply, errors.New("running Server does not support client listing; stop it, replace the executable and start it again")
		}
		return reply, errors.New("background control request was rejected")
	}
	// The configured route list can be much larger than a status response.
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(&reply); err != nil {
		return reply, errors.New("invalid background control response")
	}
	if reply.PID != state.PID || reply.Instance != state.Instance {
		return reply, errors.New("background process identity changed")
	}
	return reply, nil
}

func startBackground(ctx context.Context, role, config, statePath, logPath, workDir string) error {
	if workDir == "" {
		var err error
		workDir, err = os.Getwd()
		if err != nil {
			return err
		}
	}
	if state, err := readBackgroundState(statePath, role, config); err == nil {
		if contactBackground(ctx, state, false) == nil {
			return fmt.Errorf("Page %s is already running (PID %d)", role, state.PID)
		}
	}
	instance, err := randomID()
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	logFile, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	cmd := exec.Command(executable, "_background", role, config, statePath, logPath, instance)
	cmd.Dir = workDir
	cmd.Stdout, cmd.Stderr = logFile, logFile
	detachBackground(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.NewTimer(backgroundTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		state, err := readBackgroundState(statePath, role, config)
		if err == nil && state.Instance == instance && contactBackground(ctx, state, false) == nil {
			if role == "server" && state.PlainTCP {
				fmt.Fprintln(os.Stderr, gateway.PlainTCPWarning)
			}
			fmt.Printf("Page %s started in background (PID %d)\nLog: %s\n", role, state.PID, logPath)
			return nil
		}
		select {
		case <-done:
			return fmt.Errorf("Page %s could not start; see %s", role, logPath)
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			return ctx.Err()
		case <-deadline.C:
			_ = cmd.Process.Kill()
			return fmt.Errorf("Page %s startup timed out; see %s", role, logPath)
		case <-ticker.C:
		}
	}
}

func manageBackground(ctx context.Context, action, role, config, statePath string) error {
	if action != "status" && action != "stop" && action != "restart" {
		return errors.New("expected status, stop or restart")
	}
	instance, err := resolveBackgroundInstance(ctx, role, config, statePath)
	if errors.Is(err, os.ErrNotExist) {
		if action == "stop" {
			fmt.Printf("Page %s is not running\n", role)
			return nil
		}
		return fmt.Errorf("Page %s is not running", role)
	}
	if err != nil {
		return err
	}
	state := instance.state
	if action == "status" {
		if err := contactBackground(ctx, state, false); err != nil {
			return fmt.Errorf("Page %s is not responding; start can recover a stale state file", role)
		}
		fmt.Printf("Page %s is running (PID %d)\nConfig: %s\nLog: %s\n", role, state.PID, state.Config, state.Log)
		return nil
	}
	if action == "restart" {
		if err := validateRestartConfiguration(state, instance.path); err != nil {
			return fmt.Errorf("cannot restart Page %s: %w", role, err)
		}
	}
	if err := stopBackgroundInstance(ctx, instance); err != nil {
		return err
	}
	if action == "restart" {
		if err := startBackground(ctx, role, state.Config, instance.path, state.Log, state.WorkDir); err != nil {
			return fmt.Errorf("Page %s stopped but could not restart: %w", role, err)
		}
		fmt.Printf("Page %s restarted\n", role)
		return nil
	}
	fmt.Printf("Page %s stopped\n", role)
	return nil
}

func validateRestartConfiguration(state backgroundState, statePath string) error {
	if state.WorkDir == "" {
		return errors.New("startup directory is missing; use stop, then start once with the updated executable")
	}
	if !filepath.IsAbs(state.Log) || state.Log == state.Config || state.Log == statePath || state.Log == statePath+".lock" {
		return errors.New("invalid saved background log path")
	}
	if info, err := os.Stat(state.WorkDir); err != nil || !info.IsDir() {
		return errors.New("the original startup directory is unavailable")
	}
	if state.Role == "client" {
		var config gateway.ClientConfig
		if err := gateway.LoadConfig(state.Config, &config); err != nil {
			return err
		}
		_, err := gateway.NewClient(config)
		return err
	}
	var config gateway.ServerConfig
	if err := gateway.LoadConfig(state.Config, &config); err != nil {
		return err
	}
	if _, err := gateway.NewServer(config); err != nil {
		return err
	}
	if config.CertFile != "" {
		resolve := func(path string) string {
			if filepath.IsAbs(path) {
				return path
			}
			return filepath.Join(state.WorkDir, path)
		}
		if _, err := tls.LoadX509KeyPair(resolve(config.CertFile), resolve(config.KeyFile)); err != nil {
			return errors.New("cannot load TLS certificate/key")
		}
	}
	return nil
}

func stopBackgroundInstance(ctx context.Context, instance backgroundInstance) error {
	state, statePath := instance.state, instance.path
	if err := contactBackground(ctx, state, true); err != nil {
		return fmt.Errorf("Page %s is not responding; start can recover a stale state file", state.Role)
	}
	deadline := time.NewTimer(backgroundTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		current, err := readBackgroundState(statePath, state.Role, state.Config)
		stopped := err == nil && current.Instance != state.Instance
		if errors.Is(err, os.ErrNotExist) {
			if lock, lockErr := lockBackground(statePath + ".lock"); lockErr == nil {
				lock.Close()
				stopped = true
			}
		}
		if stopped {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("Page %s has not finished stopping; check status and log", state.Role)
		case <-ticker.C:
		}
	}
}

func runBackground(role, config, statePath, logPath, instance string) error {
	workDir, err := os.Getwd()
	if err != nil {
		return err
	}
	lock, err := lockBackground(statePath + ".lock")
	if err != nil {
		return fmt.Errorf("cannot acquire background instance lock: %w", err)
	}
	defer lock.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	secret, err := randomID()
	if err != nil {
		return err
	}
	state := backgroundState{PID: os.Getpid(), Role: role, Config: config, Log: logPath, Address: listener.Addr().String(), Instance: instance, Secret: secret, WorkDir: workDir}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var runningServer atomic.Pointer[gateway.Server]
	server := &http.Server{
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       2 * time.Second,
		WriteTimeout:      2 * time.Second,
		IdleTimeout:       2 * time.Second,
		MaxHeaderBytes:    4096,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+secret)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if role == "server" && r.Method == http.MethodGet && r.URL.Path == "/clients" {
				s := runningServer.Load()
				if s == nil {
					http.Error(w, "server is starting", http.StatusServiceUnavailable)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(backgroundReply{PID: state.PID, Instance: state.Instance, Clients: s.Clients()})
				return
			}
			stop := r.Method == http.MethodPost && r.URL.Path == "/stop"
			if !stop && !(r.Method == http.MethodGet && r.URL.Path == "/status") {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(backgroundReply{PID: state.PID, Instance: state.Instance})
			if stop {
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				cancel()
			}
		}),
	}
	controlDone := make(chan struct{})
	go func() {
		defer close(controlDone)
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			cancel()
		}
	}()
	defer func() { _ = server.Close(); <-controlDone }()
	defer func() {
		if current, err := readBackgroundState(statePath, role, config); err == nil && current.Instance == instance {
			_ = os.Remove(statePath)
		}
	}()
	var unregister func()
	defer func() {
		if unregister != nil {
			unregister()
		}
	}()
	return runGateway(ctx, role, config, func(s *gateway.Server, plainTCP bool) error {
		runningServer.Store(s)
		state.PlainTCP = plainTCP
		var err error
		unregister, err = registerBackgroundInstance(statePath, instance)
		if err != nil {
			return err
		}
		return writeBackgroundState(statePath, state)
	})
}
