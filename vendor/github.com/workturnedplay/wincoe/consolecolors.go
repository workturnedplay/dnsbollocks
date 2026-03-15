//go:build windows

// Copyright 2026 workturnedplay
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wincoe

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
)

var (
	kernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	procSetConsoleTextAttribute = kernel32.NewProc("SetConsoleTextAttribute")
)

const (
	// to be used with windows.GetStdHandle(STD_OUTPUT_HANDLE) only!
	STD_OUTPUT_HANDLE = uint32(-11 & 0xFFFFFFFF) // cast to uint32
	// to be used with windows.GetStdHandle(STD_OUTPUT_HANDLE) only!
	STD_ERROR_HANDLE = uint32(-12 & 0xFFFFFFFF)

	FOREGROUND_RED       = 0x0004
	FOREGROUND_GREEN     = 0x0002
	FOREGROUND_BLUE      = 0x0001
	FOREGROUND_NORMAL    = 0x0007
	FOREGROUND_INTENSITY = 0x0008
	FOREGROUND_GRAY      = FOREGROUND_INTENSITY // dark gray / bright black

	// derived colors
	FOREGROUND_YELLOW        = FOREGROUND_RED | FOREGROUND_GREEN
	FOREGROUND_BRIGHT_YELLOW = FOREGROUND_YELLOW | FOREGROUND_INTENSITY

	FOREGROUND_MAGENTA        = FOREGROUND_RED | FOREGROUND_BLUE
	FOREGROUND_BRIGHT_MAGENTA = FOREGROUND_MAGENTA | FOREGROUND_INTENSITY

	FOREGROUND_CYAN        = FOREGROUND_GREEN | FOREGROUND_BLUE
	FOREGROUND_BRIGHT_CYAN = FOREGROUND_CYAN | FOREGROUND_INTENSITY

	FOREGROUND_WHITE        = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE
	FOREGROUND_BRIGHT_WHITE = FOREGROUND_WHITE | FOREGROUND_INTENSITY

	FOREGROUND_BRIGHT_RED = FOREGROUND_RED | FOREGROUND_INTENSITY

	FOREGROUND_BRIGHT_GREEN = FOREGROUND_GREEN | FOREGROUND_INTENSITY
)

// WithConsoleColor temporarily changes text attribute, runs fn, then restores original
func WithConsoleColor(outputHandle windows.Handle, color uint16, fn func()) error {
	//hStdout := windows.Handle(STD_OUTPUT_HANDLE)

	//var csbi windows.ConsoleScreenBufferInfo
	originalColor, err := GetConsoleScreenBufferAttributes(outputHandle)
	//if err := windows.GetConsoleScreenBufferInfo(outputHandle, &csbi);
	if err != nil {
		return fmt.Errorf("GetConsoleScreenBufferInfo failed: %w", err)
	}
	//original := csbi.Attributes
	defer func() {
		// Always restore (even on panic inside fn)
		_ = SetConsoleTextAttribute(outputHandle, originalColor) //nolint:errcheck // because nothing to do with the error.
	}()
	// Set new color
	if err := SetConsoleTextAttribute(outputHandle, color); err != nil {
		return fmt.Errorf("SetConsoleTextAttribute failed: %w", err)
	}

	fn()
	return nil
}

// GetConsoleScreenBufferAttributes returns the current console text attribute so we can restore it after colored output.
// This is the missing piece you mentioned.
// NOTE: outputHandle must be gotten via windows.GetStdHandle(STD_OUTPUT_HANDLE) or via windows.Stdout or windows.Stderr but NOT directly using STD_OUTPUT_HANDLE
func GetConsoleScreenBufferAttributes(outputHandle windows.Handle) (uint16, error) {
	//hStdout := windows.Handle(STD_OUTPUT_HANDLE) //windows.GetStdHandle(STD_OUTPUT_HANDLE)
	if outputHandle == windows.InvalidHandle {
		return 0, errors.New("invalid console handle")
	}

	var csbi windows.ConsoleScreenBufferInfo
	//XXX: don't use STD_OUTPUT_HANDLE to this call, it won't work!
	if err := windows.GetConsoleScreenBufferInfo(outputHandle, &csbi); err != nil {
		return 0, fmt.Errorf("GetConsoleScreenBufferInfo failed: %w", err)
	}
	return csbi.Attributes, nil
}

// // RestoreConsoleTextAttribute is just a thin wrapper around your existing Set function.
// // Call it after every colored line.
// func RestoreConsoleTextAttribute(h windows.Handle, orig uint16) error {
// 	return SetConsoleTextAttribute(h, orig)
// }

// // Quick one-liners for common cases (optional, but cleaner usage)
// func WithInfoColor(fn func()) error {
// 	return WithConsoleColor(FOREGROUND_WHITE, fn)
// }

// func WithWarnColor(fn func()) error {
// 	return WithConsoleColor(FOREGROUND_BRIGHT_MAGENTA, fn)
// }

// func WithErrorColor(fn func()) error {
// 	return WithConsoleColor(FOREGROUND_RED|FOREGROUND_INTENSITY, fn) // bright red
// }

// func WithDebugColor(fn func()) error {
// 	return WithConsoleColor(FOREGROUND_GRAY, fn) // dim gray
// }

// SetConsoleTextAttribute used to set the color for the text next printed on console
func SetConsoleTextAttribute(h windows.Handle, color uint16) error {
	// We use CheckBool because the docs say this returns a BOOL.
	// We pass nil for onFail because we just want to return the error to the caller.
	// Execute the syscall
	r1, r2, callErr := procSetConsoleTextAttribute.Call(uintptr(h), uintptr(color))

	// Wrap it up using our utility
	_, _, err := WinCall(CheckBool, nil, r1, r2, callErr)

	return err
}
