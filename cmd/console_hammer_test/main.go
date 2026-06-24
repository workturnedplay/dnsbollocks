//go:build windows
// +build windows

// cmd/console_hammer_test/main.go
// Hammer test for coloredConsoleHandler concurrency safety.
// Run this directly from cmd.exe / PowerShell (not go test, not redirected).
package main

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/workturnedplay/dnsbollocks/internal/dnsbollocks"
	"golang.org/x/term"
)

func main() {
	fmt.Println("=== DNSbollocks Colored Console Hammer — UNIFIED STRESS TEST ===")

	// 1. Ensure we are in a real terminal
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Println("ERROR: Must run from a real console (cmd/powershell), not redirected.")
		os.Exit(1)
	}
	var mainLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug, //TODO: allow env. var. to dictate the level? but nothing right now uses this yet because initBootstrapLogging gets hit early!
	}))
	// 2. Initialize the official handler (this also enables ANSI via wincoe)
	handler := dnsbollocks.NewColoredConsoleHandler(slog.LevelDebug, mainLogger)
	logger := slog.New(handler)

	const goroutines = 50
	const iterations = 200

	fmt.Printf("Hammering with %d goroutines and %d iterations each...\n", goroutines, iterations)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	start := time.Now()

	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				// Mix of actions to test different color word-coloring
				action := "forwarded"
				if i%3 == 0 {
					action = "blocked"
				} else if i%3 == 1 {
					action = "cache_hit"
				}

				// The "Big Message" stress case from your old main3.go
				blockedMsg := ""
				if action == "blocked" {
					blockedMsg = ";; opcode: QUERY, status: NXDOMAIN\n;; QUESTION: google.com. A"
				}

				logger.Info("logged_query",
					"gid", gid,
					"iter", i,
					"domain", fmt.Sprintf("hammer-%d-%d.test", gid, i),
					"action", action,
					"proto", "UDP",
					"blocked_dnsMsg", blockedMsg, // Stress multi-line/long strings
					"err", "<nil>",
				)
			}
		}(g)
	}

	wg.Wait()
	fmt.Printf("\nFinished in %v. No crashes or garbled lines should have occurred.\n", time.Since(start))
}
