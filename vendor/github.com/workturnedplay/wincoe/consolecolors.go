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

import "golang.org/x/sys/windows"

var (
	kernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	procSetConsoleTextAttribute = kernel32.NewProc("SetConsoleTextAttribute")
)

const (
	STD_OUTPUT_HANDLE = uint32(-11 & 0xFFFFFFFF) // cast to uint32

	FOREGROUND_RED       = 0x0004
	FOREGROUND_GREEN     = 0x0002
	FOREGROUND_BLUE      = 0x0001
	FOREGROUND_INTENSITY = 0x0008

	// derived colors
	FOREGROUND_YELLOW        = FOREGROUND_RED | FOREGROUND_GREEN
	FOREGROUND_BRIGHT_YELLOW = FOREGROUND_YELLOW | FOREGROUND_INTENSITY

	FOREGROUND_MAGENTA        = FOREGROUND_RED | FOREGROUND_BLUE
	FOREGROUND_BRIGHT_MAGENTA = FOREGROUND_MAGENTA | FOREGROUND_INTENSITY
)

func SetConsoleTextAttribute(h windows.Handle, color uint16) error {
	// We use CheckBool because the docs say this returns a BOOL.
	// We pass nil for onFail because we just want to return the error to the caller.
	// _, _, err := WinCall(
	// 	CheckBool,
	// 	nil,
	// 	procSetConsoleTextAttribute.Call(uintptr(h), uintptr(color)),
	// )
	// Execute the syscall
	r1, r2, callErr := procSetConsoleTextAttribute.Call(uintptr(h), uintptr(color))

	// Wrap it up using our utility
	_, _, err := WinCall(CheckBool, nil, r1, r2, callErr)

	return err
}
