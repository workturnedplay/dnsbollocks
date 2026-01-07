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
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
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
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}

		// if exitErr, ok := err.(*exec.ExitError); ok {
		// 	os.Exit(exitErr.ExitCode())
		// }
		log.Fatalf("failed to run %s: %v", realExe, err)
	}

	os.Exit(0)
}
