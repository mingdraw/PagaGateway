//go:build windows

package gateway

import (
	"errors"
	"syscall"
)

const (
	wsaEintr      = syscall.Errno(10004)
	wsaEmfile     = syscall.Errno(10024)
	wsaEconnabort = syscall.Errno(10053)
	wsaEconnreset = syscall.Errno(10054)
	wsaEnobufs    = syscall.Errno(10055)
)

func isTransientAcceptErrno(err error) bool {
	return errors.Is(err, wsaEintr) ||
		errors.Is(err, wsaEmfile) ||
		errors.Is(err, wsaEconnabort) ||
		errors.Is(err, wsaEconnreset) ||
		errors.Is(err, wsaEnobufs)
}
