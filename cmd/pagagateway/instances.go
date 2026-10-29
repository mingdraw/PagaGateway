package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// The private per-user, per-executable runtime index locates background roles started
// with arbitrary config/state paths. It stores references, never credentials.
type backgroundRegistration struct {
	StatePath string `json:"state_path"`
	Instance  string `json:"instance"`
}

type backgroundInstance struct {
	state backgroundState
	path  string
}

func backgroundDirectory(executable string) (string, error) {
	account, err := user.Current()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(account.Uid + "\x00" + filepath.Clean(executable)))
	return filepath.Join(os.TempDir(), "pagagateway-"+hex.EncodeToString(digest[:16])), nil
}

func checkBackgroundDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return errors.New("background instance index must be a private directory")
	}
	return checkBackgroundDirectoryOwner(info)
}

func readBackgroundRegistration(path string) (backgroundRegistration, error) {
	var registration backgroundRegistration
	f, err := os.Open(path)
	if err != nil {
		return registration, err
	}
	defer f.Close()
	if err := json.NewDecoder(io.LimitReader(f, 64<<10)).Decode(&registration); err != nil {
		return registration, err
	}
	if !filepath.IsAbs(registration.StatePath) || registration.Instance == "" {
		return registration, errors.New("invalid background instance registration")
	}
	return registration, nil
}

func registerBackgroundInstance(statePath, instance string) (func(), error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	directory, err := backgroundDirectory(executable)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	if err := checkBackgroundDirectory(directory); err != nil {
		return nil, err
	}
	// Each instance owns a distinct filename, so old cleanup cannot unlink a
	// later instance's registration even when it uses the same state path.
	digest := sha256.Sum256([]byte(statePath + "\x00" + instance))
	path := filepath.Join(directory, hex.EncodeToString(digest[:])+".json")
	registration := backgroundRegistration{StatePath: statePath, Instance: instance}
	if err := writeBackgroundJSON(path, registration); err != nil {
		return nil, err
	}
	return func() {
		_ = os.Remove(path)
	}, nil
}

func resolveBackgroundInstance(ctx context.Context, role, config, statePath string) (backgroundInstance, error) {
	var err error
	if config != "" {
		config, err = filepath.Abs(config)
		if err != nil {
			return backgroundInstance{}, err
		}
		if statePath == "" {
			statePath = config + ".pid"
		}
	}
	if statePath != "" {
		statePath, err = filepath.Abs(statePath)
		if err != nil {
			return backgroundInstance{}, err
		}
		state, err := readBackgroundState(statePath, role, config)
		return backgroundInstance{state: state, path: statePath}, err
	}
	executable, err := os.Executable()
	if err != nil {
		return backgroundInstance{}, err
	}
	directory, err := backgroundDirectory(executable)
	if err != nil {
		return backgroundInstance{}, err
	}
	return discoverBackgroundInstance(ctx, directory, role)
}

func discoverBackgroundInstance(ctx context.Context, directory, role string) (backgroundInstance, error) {
	if err := checkBackgroundDirectory(directory); err != nil {
		return backgroundInstance{}, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return backgroundInstance{}, err
	}
	var instances []backgroundInstance
	seen := make(map[string]bool)
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		registration, err := readBackgroundRegistration(filepath.Join(directory, entry.Name()))
		if err != nil || seen[registration.StatePath] {
			continue
		}
		state, err := readBackgroundState(registration.StatePath, role, "")
		if err != nil || state.Instance != registration.Instance {
			continue
		}
		if err := contactBackground(ctx, state, false); err != nil {
			if ctx.Err() != nil {
				return backgroundInstance{}, ctx.Err()
			}
			continue
		}
		seen[registration.StatePath] = true
		instances = append(instances, backgroundInstance{state: state, path: registration.StatePath})
	}
	if len(instances) == 0 {
		return backgroundInstance{}, os.ErrNotExist
	}
	if len(instances) > 1 {
		var message strings.Builder
		label := "Server"
		if role == "client" {
			label = "Client"
		}
		fmt.Fprintf(&message, "检测到多个后台 %s，请使用 -pidfile 选择实例：", label)
		for _, instance := range instances {
			fmt.Fprintf(&message, "\nPID %d  Config: %s  -pidfile %q", instance.state.PID, instance.state.Config, instance.path)
		}
		return backgroundInstance{}, errors.New(message.String())
	}
	return instances[0], nil
}
