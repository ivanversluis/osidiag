//go:build linux

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Linux raw keyboard input is used exclusively for the optional terminal UI.
// ISIG remains enabled so Ctrl+C still cancels the session.
func rawKeyboard() (func(), error) {
	fd := uintptr(os.Stdin.Fd())
	before := new(syscall.Termios)
	// #nosec G103 -- TCGETS requires an owned pointer to the Linux termios structure.
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(before)))
	if errno != 0 {
		return nil, fmt.Errorf("read terminal settings: %w", errno)
	}
	after := *before
	after.Lflag &^= syscall.ICANON | syscall.ECHO
	after.Iflag &^= syscall.ICRNL | syscall.IXON
	after.Cc[syscall.VMIN] = 1
	after.Cc[syscall.VTIME] = 0
	// #nosec G103 -- TCSETS accepts the address of the local termios structure.
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&after)))
	if errno != 0 {
		return nil, fmt.Errorf("enable terminal keyboard: %w", errno)
	}
	return func() {
		// #nosec G103 -- restore original terminal attributes before returning.
		_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(before)))
	}, nil
}

func keyboardEvents() <-chan byte {
	input := make(chan byte, 16)
	go func() {
		defer close(input)
		var b [1]byte
		for {
			n, err := os.Stdin.Read(b[:])
			if err != nil || n == 0 {
				return
			}
			// Ignore escape sequences, except ESC (overview) itself.
			select {
			case input <- b[0]:
			default:
			}
		}
	}()
	return input
}
