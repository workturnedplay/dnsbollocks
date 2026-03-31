//go:build windows
// +build windows

// cmd/console_hammer_test/main.go
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

	"github.com/workturnedplay/dnsbollocks/internal/dnsbollocks" // adjust import if needed
	"github.com/workturnedplay/wincoe"
)

// ================================================
// CONFIG: Change this to test old vs new handler
// ================================================
const useNewSafeHandler = false // ← set to true to use the safe version

// ================================================

type testHandler struct {
	inner    slog.Handler
	hStdout  windows.Handle
	origAttr uint16
	useColor bool
	mu       sync.Mutex
}

func (h *testHandler) Handle(ctx context.Context, r slog.Record) error {
	if !h.useColor {
		return h.inner.Handle(ctx, r)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Decide color (same as production)
	var color uint16
	var isQuery bool
	var action string
	r.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "category":
			if a.Value.String() == "query" {
				isQuery = true
			}
		case "action":
			action = a.Value.String()
		}
		return true
	})

	if isQuery && action != "" {
		if c, ok := dnsbollocks.QueryActionColors[action]; ok { // adjust map name if different
			color = c
		} else {
			color = dnsbollocks.LevelToAttr[r.Level] // adjust if your map is different
		}
	} else {
		color = dnsbollocks.LevelToAttr[r.Level]
	}
	if color == 0 {
		color = h.origAttr
	}

	if useNewSafeHandler {
		// ==================== NEW SAFE VERSION ====================
		// Unconditional restore + explicit error handling
		defer func() {
			if resetErr := wincoe.SetConsoleTextAttribute(h.hStdout, h.origAttr); resetErr != nil {
				slog.Error("SetConsoleTextAttribute restore failed",
					slog.Uint64("original_attr", uint64(h.origAttr)),
					slog.Any("err", resetErr))
			}
		}()

		if err := wincoe.SetConsoleTextAttribute(h.hStdout, color); err != nil {
			_ = wincoe.SetConsoleTextAttribute(h.hStdout, h.origAttr) // best-effort
			return fmt.Errorf("SetConsoleTextAttribute (set color %d): %w", color, err)
		}

		return h.inner.Handle(ctx, r)
	}

	// ==================== OLD VERSION (the racy one) ====================
	err := wincoe.SetConsoleTextAttribute(h.hStdout, color)
	if err == nil {
		defer func() {
			_ = wincoe.SetConsoleTextAttribute(h.hStdout, h.origAttr)
		}()
	} // else: ignore set error, no restore registered  ← this was the crash source

	return h.inner.Handle(ctx, r)
}

func main() {
	fmt.Println("=== DNSbollocks Colored Console Hammer Test ===")
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Println("ERROR: stdout is not a real console.")
		os.Exit(1)
	}

	hStdout, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil || hStdout == windows.InvalidHandle {
		fmt.Println("ERROR: Failed to get console handle")
		os.Exit(1)
	}

	handler := &testHandler{
		inner:    slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		hStdout:  hStdout,
		origAttr: 7,
		useColor: true,
	}

	// Ensure colors map exists
	if len(dnsbollocks.QueryActionColors) == 0 {
		dnsbollocks.QueryActionColors = map[string]uint16{
			"blocked":   wincoe.FOREGROUND_BRIGHT_RED,
			"forwarded": wincoe.FOREGROUND_BRIGHT_GREEN,
			"cache_hit": wincoe.FOREGROUND_BRIGHT_CYAN,
		}
	}

	const goroutines = 40
	const iterations = 400

	fmt.Printf("Hammering with useNewSafeHandler = %v\n", useNewSafeHandler)
	fmt.Printf("%d goroutines × %d iterations...\n", goroutines, iterations)
	if !useNewSafeHandler {
		fmt.Println("WARNING: Using OLD racy handler — expect crash!")
	}

	var wg sync.WaitGroup
	wg.Add(goroutines)
	start := time.Now()

	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
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
				rec.Add("blocked_dnsMsg", `;; long dns message that stresses output...`)

				_ = handler.Handle(context.Background(), rec)

				if i%13 == 0 {
					time.Sleep(20 * time.Microsecond)
				}
			}
		}(g)
	}

	wg.Wait()
	fmt.Printf("Completed in %v — no crash\n", time.Since(start))
	if !useNewSafeHandler {
		fmt.Println("Old handler survived this run. Increase goroutines/iterations if needed.")
	}
}