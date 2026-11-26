//go:build windows

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	windowsInputLine       = 0x0002
	windowsInputEcho       = 0x0004
	windowsVTOutput        = 0x0004
	windowsProcessedOutput = 0x0001
)

var (
	windowsConsole = syscall.NewLazyDLL("kernel32.dll")
	consoleGetMode = windowsConsole.NewProc("GetConsoleMode")
	consoleSetMode = windowsConsole.NewProc("SetConsoleMode")
)

func windowsGetMode(handle uintptr) (uint32, error) {
	var mode uint32
	ok, _, e := consoleGetMode.Call(handle, uintptr(unsafe.Pointer(&mode)))
	if ok == 0 {
		return 0, fmt.Errorf("GetConsoleMode: %w", e)
	}
	return mode, nil
}
func windowsSetMode(handle uintptr, mode uint32) error {
	ok, _, e := consoleSetMode.Call(handle, uintptr(mode))
	if ok == 0 {
		return fmt.Errorf("SetConsoleMode: %w", e)
	}
	return nil
}

// rawKeyboard configures a real Windows console or Windows Terminal PTY.
// Keep ENABLE_PROCESSED_INPUT so Ctrl+C remains a terminal interrupt.
// Every state mutation is restored, including when enabling VT output fails.
func rawKeyboard() (func(), error) {
	in, out := uintptr(os.Stdin.Fd()), uintptr(os.Stdout.Fd())
	beforeIn, e := windowsGetMode(in)
	if e != nil {
		return nil, fmt.Errorf("interactive TUI requires a Windows console input: %w", e)
	}
	beforeOut, e := windowsGetMode(out)
	if e != nil {
		return nil, fmt.Errorf("interactive TUI requires a Windows console output: %w", e)
	}
	if e = windowsSetMode(in, beforeIn&^(windowsInputLine|windowsInputEcho)); e != nil {
		return nil, e
	}
	if e = windowsSetMode(out, beforeOut|windowsVTOutput|windowsProcessedOutput); e != nil {
		_ = windowsSetMode(in, beforeIn)
		return nil, e
	}
	return func() { _ = windowsSetMode(out, beforeOut); _ = windowsSetMode(in, beforeIn) }, nil
}

// Windows console reads emit characters immediately when ENABLE_LINE_INPUT
// is disabled. The event stream is deliberately byte-oriented like Linux.
func keyboardEvents() <-chan byte {
	events := make(chan byte, 16)
	go func() {
		defer close(events)
		var buf [1]byte
		for {
			n, err := os.Stdin.Read(buf[:])
			if err != nil || n == 0 {
				return
			}
			select {
			case events <- buf[0]:
			default:
			}
		}
	}()
	return events
}