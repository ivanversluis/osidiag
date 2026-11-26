//go:build !linux && !windows

package main

import "errors"

func rawKeyboard() (func(), error) {
	return nil, errors.New("interactive TUI requires Linux")
}

func keyboardEvents() <-chan byte {
	ch := make(chan byte)
	close(ch)
	return ch
}
