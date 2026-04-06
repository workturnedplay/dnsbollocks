//go:build windows
// +build windows

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

// This just runs golanci-lint.exe because it's already v2 but vscode-go doesn't detect it!
// You need to have this line in vscode's settings.json file:
// "go.lintTool": "golangci-lint-v2",
// which means it wants golangci-lint-v2.exe (which should be this code you're reading, as the wrapper to the real exe)
// run 'go build' and put the resulting golancgi-lint-v2.exe that it made from this into %GOPATH%\bin\
// where golanci-lint.exe should already be, if it isn't install it first via:
// go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
// OR if you want v2 explicitly:
// go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
// it's gonna be the same exe name: %GOPATH%\bin\golanci-lint.exe
/*
Ok it's a bit more nuanced where 'go install' puts the binary:
(I didn't have GOBIN set)

The exact placement rules (in order)
If GOBIN is set
Go installs the binary exactly there:
%GOBIN%\tool.exe

Else if GOPATH is set
Go installs to:
%GOPATH%\bin\tool.exe

Else (GOPATH unset)
Go silently falls back to:
%USERPROFILE%\go\bin\

On Windows, Go automatically appends .exe.
*/
package main

import (
	"bufio"
	//"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	self, err := os.Executable()
	if err != nil {
		log.Fatalf("cannot determine executable path: %v", err)
	}

	dir := filepath.Dir(self)
	realExe := filepath.Join(dir, "golangci-lint.exe")

	info, err := os.Stat(realExe)
	if err != nil {
		log.Fatalf("cannot stat %s: %v", realExe, err)
	}
	if info.IsDir() {
		log.Fatalf("%s is a directory, not an executable", realExe)
	}
	realExe, err = filepath.EvalSymlinks(realExe)
	if err != nil {
		log.Fatalf("cannot resolve %s: %v", realExe, err)
	}

	//nolint:gosec,G204 // intentional exec of trusted sibling binary
	cmd := exec.Command(realExe, os.Args[1:]...)
	cmd.Stdin = os.Stdin

	// 	cmd.Stdout = os.Stdout
	// 	cmd.Stderr = os.Stderr
	//
	// if err := cmd.Run(); err != nil {
	// 	var exitErr *exec.ExitError
	// 	if errors.As(err, &exitErr) {
	// 		os.Exit(exitErr.ExitCode())
	// 	}

	// 	// if exitErr, ok := err.(*exec.ExitError); ok {
	// 	// 	os.Exit(exitErr.ExitCode())
	// 	// }
	// 	log.Fatalf("failed to run %s: %v", realExe, err)
	// }
	// We need to capture Stdout and Stderr to modify the text
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		log.Fatalf("failed to start %s: %v", realExe, err)
	}

	// // Track if we found a shadow to decide the exit code
	// hasShadow := false

	// // // Process output in a goroutine
	// // go processOutput(stdout, os.Stdout)
	// // go processOutput(stderr, os.Stderr)

	// // if err := cmd.Wait(); err != nil {
	// // 	var exitErr *exec.ExitError
	// // 	if errors.As(err, &exitErr) {
	// // 		os.Exit(exitErr.ExitCode())
	// // 	}
	// // 	log.Fatalf("failed to run %s: %v", realExe, err)
	// // }
	// // We use a channel to wait for output processing to finish
	// done := make(chan bool)
	// go func() {
	// 	hasShadow = processAndFilter(stdout, os.Stdout)
	// 	done <- true
	// }()
	// go processAndFilter(stderr, os.Stderr)

	// cmd.Wait()
	// <-done

	// // THE TRICK: If a shadow was found, exit with 1 to force VS Code
	// // to treat the whole run as an [error] (Red Squiggle)
	// if hasShadow {
	// 	os.Exit(1)
	// }
	// os.Exit(0)

	// Channel to signal that we found a shadow and need to bail
	killSignal := make(chan bool)

	go monitor(stdout, os.Stdout, killSignal)
	go monitor(stderr, os.Stderr, killSignal)

	// Wait for either the command to finish normally OR a shadow to be found
	done := make(chan error)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-killSignal:
		// SHADOW DETECTED: Kill the linter immediately
		_ = cmd.Process.Kill()
		// Wait a tiny bit for the pipe to flush the error message
		os.Exit(1)
	case <-done:
		// Finished normally without finding a shadow
		os.Exit(0)
	}
}

func monitor(r io.Reader, w io.Writer, killSignal chan bool) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		// if strings.Contains(line, "shadow:") {
		// 	// 1. Format the line exactly like the 'typechecking error' that worked
		// 	fmt.Fprintf(os.Stderr, "level=error msg=\"[linters_context] typechecking error: %s\"\n", line)
		// 	// 2. Tell the main thread to kill the process and exit(1)
		// 	killSignal <- true
		// 	return
		// }

		// if strings.Contains(line, "shadow:") {
		// 	// 1. Format the line exactly like the 'typechecking error' that worked
		// 	fmt.Fprintf(os.Stderr, "level=error msg=\"[linters_context] shadow error: %s\"\n", line)
		// 	// 2. Tell the main thread to kill the process and exit(1)
		// 	killSignal <- true
		// 	return
		// }

		// if strings.Contains(line, "shadow:") {
		// 	// We need to mimic the exact escape sequence VS Code expects:
		// 	// 1. level=error msg="..."
		// 	// 2. The internal string needs the \n before the file path
		// 	// 3. The file path needs to be absolute or relative to the workspace

		// 	parts := strings.SplitN(line, ": ", 2)
		// 	if len(parts) == 2 {
		// 		// The format VS Code's regex is hunting for:
		// 		// level=error msg="[linters_context] typechecking error: \n.\path\to\file.go:line:col: message"
		// 		fmt.Fprintf(os.Stderr, "level=error msg=\"[linters_context] typechecking error: : # manual-trigger\n%s: %s\"\n", parts[0], parts[1])
		// 	} else {
		// 		// Fallback if split fails
		// 		fmt.Fprintf(os.Stderr, "level=error msg=\"[linters_context] typechecking error: \n%s\"\n", line)
		// 	}

		// 	killSignal <- true
		// 	return
		// }

		fmt.Fprintln(w, line)
	}
}

func processAndFilter(r io.Reader, w io.Writer) bool {
	found := false
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "shadow:") {
			found = true
			// Mimic the "typechecking error" format that VS Code respects as Red
			// Format: level=error msg="[linters_context] typechecking error: file:line:col: message"
			fmt.Fprintf(w, "level=error msg=\"[linters_context] typechecking error: %s\"\n", line)
			continue
		}
		fmt.Fprintln(w, line)
	}
	return found
}

// func processOutput(r io.Reader, w io.Writer) {
// 	scanner := bufio.NewScanner(r)
// 	for scanner.Scan() {
// 		line := scanner.Text()

// 		// // The "Magic Trick":
// 		// // If the line contains "shadow" and comes from govet,
// 		// // we inject "error: " right after the file/line info.
// 		// if strings.Contains(line, "shadow:") && strings.Contains(line, "(govet)") {
// 		// 	// Find the last colon of the file:line:col part
// 		// 	// Example line: d:\path\file.go:80:18: shadow: declaration...
// 		// 	parts := strings.SplitN(line, ": ", 2)
// 		// 	if len(parts) == 2 {
// 		// 		line = fmt.Sprintf("%s: Error %s", parts[0], parts[1])
// 		// 	}
// 		// }

// 		// // Mimic the format of a standard Go compiler error
// 		// // Instead of: file:line:col: message (govet)
// 		// // Try: file:line:col: shadow: declaration of...
// 		// if strings.Contains(line, "shadow:") {
// 		// 	// Remove the "(govet)" suffix which tells VS Code "this is just a linter"
// 		// 	line = strings.ReplaceAll(line, " (govet)", "")
// 		// 	// Prepend a fake "typechecking error" string that often triggers Red
// 		// 	line = fmt.Sprintf("%s: %s", parts[0], parts[1])
// 		// }

// 		// // Match lines that are definitely shadows from govet
// 		// if strings.Contains(line, "shadow:") { // && strings.Contains(line, "(govet)") {
// 		// 	// standard format:  d:\path\file.go:80:18: shadow: message (govet)
// 		// 	// We split at the first occurrence of ": " to separate the
// 		// 	// file:line:col from the message content.
// 		// 	parts := strings.SplitN(line, ": ", 2)

// 		// 	if len(parts) == 2 {
// 		// 		// We strip "(govet)" because the Go extension uses that
// 		// 		// suffix to identify "Linter" (Warning) status.
// 		// 		cleanMsg := strings.ReplaceAll(parts[1], " (govet)", "")

// 		// 		// Reconstruct the line so it looks like a compiler error:
// 		// 		// d:\path\file.go:80:18: error: shadow: message
// 		// 		line = fmt.Sprintf("%s: error: %s", parts[0], cleanMsg)
// 		// 	}
// 		// }

// 		n, err := fmt.Fprintln(w, line)
// 		if err != nil {
// 			log.Fatalf("failed to print line '%s', only printed %d bytes, err:%v", line, n, err)
// 		}
// 	}
// }
