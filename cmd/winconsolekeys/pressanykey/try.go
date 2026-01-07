//go:build windows

package main

import (
	"dnsbollocks/internal/dnsbollocks"
	"fmt"
	"os"
	"time"

	"golang.org/x/term"
)

func main() {

	fmt.Println("Move mouse / press keys for 3 seconds…")
	time.Sleep(3 * time.Second)

	var hadKey bool
	dnsbollocks.WithConsoleEventRaw(func() {
		fmt.Println("foo1")
		hadKey = dnsbollocks.ClearStdin()
		fmt.Println("foo2")
	})

	if hadKey {
		fmt.Println("A key was pending and was cleared.")
	} else {
		fmt.Println("No key was pending.")
	}

	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		fmt.Print("couldn't make the terminal raw, bailing!")
		return // or log, or fail loudly — your call
	}
	defer term.Restore(fd, oldState)

	fmt.Print("Now press any key to exit.")
	dnsbollocks.ReadKeySequence()
	fmt.Println()
}
