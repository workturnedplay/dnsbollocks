//go:build windows
// +build windows

// cmd/console_hammer_test/main.go
// Strong reproduction for the colored console race.
// Run directly from cmd.exe or PowerShell (real console).

package main

import (
"runtime"
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

// ================================================
// CONFIG — change this to switch between old and new
// ================================================
const useNewSafeHandler = false // set to true once you have the fixed handler

// ================================================

func main() {
	fmt.Println("=== DNSbollocks Colored Console Hammer — STRONG REPRODUCTION ===")
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Println("ERROR: Must run from real console (cmd.exe / PowerShell), not redirected.")
		os.Exit(1)
	}

	hStdout, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil || hStdout == windows.InvalidHandle {
		fmt.Println("ERROR: Failed to get console handle")
		os.Exit(1)
	}

	// Use the real handler type from your package
	handler := &dnsbollocks.ColoredConsoleHandler{ // adjust struct name if it's lowercase in your code
		Inner:    slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		HStdout:  hStdout,
		OrigAttr: 7,
		UseColor: true,
		Mu:       sync.Mutex{},
	}

	// Ensure colors are initialized
	if len(dnsbollocks.QueryActionColors) == 0 {
		dnsbollocks.QueryActionColors = map[string]uint16{
			"blocked":   wincoe.FOREGROUND_BRIGHT_RED,
			"forwarded": wincoe.FOREGROUND_BRIGHT_GREEN,
			"cache_hit": wincoe.FOREGROUND_BRIGHT_CYAN,
		}
	}

	const goroutines = 64
	const iterations = 600

	fmt.Printf("useNewSafeHandler = %v\n", useNewSafeHandler)
	fmt.Printf("Hammering %d goroutines × %d iterations with GC pressure...\n", goroutines, iterations)
	if !useNewSafeHandler {
		fmt.Println(">>> USING OLD RACy HANDLER — expect crash soon!")
	}

	var wg sync.WaitGroup
	wg.Add(goroutines)
	start := time.Now()

	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				// Real production-like record
				rec := slog.NewRecord(time.Now(), slog.LevelInfo, "logged_query", 0)
				rec.Add("category", "query")
				action := "blocked"
				if i%3 == 1 {
					action = "forwarded"
				} else if i%3 == 2 {
					action = "cache_hit"
				}
				rec.Add("action", action)
				rec.Add("domain", fmt.Sprintf("hammer%d.example.com", gid))
				rec.Add("type", "AAAA")
				rec.Add("proto", "DoH")
				rec.Add("clientAddr", "127.0.0.1:54321")
				rec.Add("pid", 1164)
				rec.Add("exe", "svchost.exe")
				rec.Add("blocked_dnsMsg", `;; opcode: QUERY, status: NXDOMAIN, id: 0
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 2
;; OPT PSEUDOSECTION:
; EDNS: version 0; flags: do; udp: 1232
; EDE: 15 (Blocked): (Blocked by "C:\z\dnsbollocks\bin\dnsbollocks.exe")
;; QUESTION SECTION:
;firefox.settings.services.mozilla.com.	IN	A
;; ADDITIONAL SECTION:`)

				_ = handler.Handle(context.Background(), rec)

				// Extra GC pressure + allocation to mimic production load
				if i%5 == 0 {
					_ = make([]byte, 8*1024) // 8KB garbage
					runtime.GC()             // force GC occasionally
				}

				if i%11 == 0 {
					time.Sleep(15 * time.Microsecond)
				}
			}
		}(g)
	}

	wg.Wait()
	fmt.Printf("\n=== COMPLETED in %v ===\n", time.Since(start))
	if useNewSafeHandler {
		fmt.Println("New safe handler survived.")
	} else {
		fmt.Println("Old handler survived this run. Try increasing numbers or run multiple times.")
	}
}