//go:build linux || darwin

package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func checkBackgroundDirectoryOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("background instance index must belong to the current user")
	}
	return nil
}

func detachBackground(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

func lockBackground(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, err
	}
	// Keep the lock file: unlinking it would allow two processes to lock
	// different inodes at the same pathname during concurrent starts.
	return f, nil
}
