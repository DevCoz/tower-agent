//go:build linux

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

func rootLinux() bool { return os.Geteuid() == 0 }
func lockAgent(path string, nonblocking bool) (func(), error) {
	if err := safePath(path); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("cannot open Agent lock")
	}
	flags := syscall.LOCK_EX
	if nonblocking {
		flags |= syscall.LOCK_NB
	}
	if syscall.Flock(fd, flags) != nil {
		syscall.Close(fd)
		return nil, errors.New("another Agent or installer is running")
	}
	return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = syscall.Close(fd) }, nil
}
func readToken(ctx context.Context) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("an interactive terminal is required for the Agent token")
	}
	defer tty.Close()
	var old syscall.Termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, tty.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&old))); errno != 0 {
		return "", errors.New("cannot read terminal settings")
	}
	hidden := old
	hidden.Lflag &^= syscall.ECHO
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, tty.Fd(), syscall.TCSETS, uintptr(unsafe.Pointer(&hidden))); errno != 0 {
		return "", errors.New("cannot hide terminal input")
	}
	defer func() {
		_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, tty.Fd(), syscall.TCSETS, uintptr(unsafe.Pointer(&old)))
		fmt.Fprintln(tty)
	}()
	fmt.Fprint(tty, "Agent token: ")
	type input struct {
		value string
		err   error
	}
	ready := make(chan input, 1)
	go func() {
		value, err := bufio.NewReader(io.LimitReader(tty, 256)).ReadString('\n')
		ready <- input{value, err}
	}()
	select {
	case <-ctx.Done():
		return "", errors.New("installation interrupted")
	case value := <-ready:
		if value.err != nil {
			return "", errors.New("cannot read Agent token")
		}
		return strings.TrimSpace(value.value), nil
	}
}
