//go:build windows
// +build windows

// cmd/console_hammer_test/main.go
// Hammer test for coloredConsoleHandler concurrency safety.
// Run this directly from cmd.exe / PowerShell (not go test, not redirected).

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/term"

	"github.com/workturnedplay/dnsbollocks/internal/dnsbollocks"
	"github.com/workturnedplay/wincoe"
)

func main() {
	fmt.Println("=== DNSbollocks Colored Console Hammer Test ===")
	fmt.Println("This test must be run from a real console (cmd.exe or PowerShell).")

	// Check we have a real console
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Println("ERROR: stdout is not a real console (probably redirected).")
		fmt.Println("Run this binary directly, not with go test or > file.txt")
		os.Exit(1)
	}

	hStdout, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil || hStdout == windows.InvalidHandle {
		fmt.Println("ERROR: Failed to get console handle")
		os.Exit(1)
	}

	// Create the handler exactly as production does
	handler := &dnsbollocks.ColoredConsoleHandler{
		Inner:    slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		HStdout:  hStdout,
		OrigAttr: 7, // typical default text attribute
		UseColor: true,
		Mu:       sync.Mutex{},
	}

	// Make sure queryActionColors exist (adjust map name if yours differs)
	if len(dnsbollocks.QueryActionColors) == 0 {
		dnsbollocks.QueryActionColors = map[string]uint16{
			"blocked":   wincoe.FOREGROUND_BRIGHT_RED,
			"forwarded": wincoe.FOREGROUND_BRIGHT_GREEN,
			"cache_hit": wincoe.FOREGROUND_BRIGHT_CYAN,
		}
	}

	const goroutines = 32
	const iterations = 300 // high enough to hit the race window

	fmt.Printf("Starting hammer: %d goroutines × %d iterations on REAL console...\n", goroutines, iterations)
	fmt.Println("If the OLD handler is used, this will likely crash with exit code 2 / access violation.")
	fmt.Println("Press Ctrl+C to stop early.")

	var wg sync.WaitGroup
	wg.Add(goroutines)

	start := time.Now()

	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				rec := slog.NewRecord(time.Now(), slog.LevelInfo, "logged_query", 0)
				rec.Add("category", "query")
				var action string
				if i%3 == 0 {
					action = "blocked"
				} else if i%2 == 0 {
					action = "forwarded"
				} else {
					action = "cache_hit"
				}
				rec.Add("action", action)
				rec.Add("domain", fmt.Sprintf("hammer%d.example.com", gid))
				rec.Add("type", "AAAA")
				rec.Add("proto", "DoH")
				rec.Add("clientAddr", "127.0.0.1:54321")
				rec.Add("pid", 1164)
				rec.Add("exe", "svchost.exe")
				// Long blocked_dnsMsg - this stresses the output path
				rec.Add("blocked_dnsMsg", `;; opcode: QUERY, status: NXDOMAIN, id: 0
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 2
;; OPT PSEUDOSECTION:
; EDNS: version 0; flags: do; udp: 1232
; EDE: 15 (Blocked): (Blocked by "C:\z\dnsbollocks\bin\dnsbollocks.exe")
;; QUESTION SECTION:
;firefox.settings.services.mozilla.com.	IN	A
;; ADDITIONAL SECTION:`)

				if err := handler.Handle(context.Background(), rec); err != nil {
					fmt.Printf("goroutine %d iter %d error: %v\n", gid, i, err)
				}

				// Increase chance of interleaving
				if i%11 == 0 {
					time.Sleep(30 * time.Microsecond)
				}
			}
		}(g)
	}

	wg.Wait()
	elapsed := time.Since(start)

	fmt.Printf("\n=== TEST COMPLETED SUCCESSFULLY in %v ===\n", elapsed)
	fmt.Println("No crash occurred. The handler survived heavy concurrent console output.")
	fmt.Println("If you were using the OLD handler, this would very likely have crashed.")
}
