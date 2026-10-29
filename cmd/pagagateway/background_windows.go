package main

import (
	"os"
	"os/exec"
	"syscall"
)

func checkBackgroundDirectoryOwner(_ os.FileInfo) error {
	// The user's temporary directory supplies the inherited Windows ACL.
	// Index records contain only references, not control credentials.
	return nil
}

func detachBackground(cmd *exec.Cmd) {
	const detachedProcess = 0x00000008
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: detachedProcess | syscall.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
}

func lockBackground(path string) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// A non-inheritable handle with no sharing provides an OS-released lock.
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}
