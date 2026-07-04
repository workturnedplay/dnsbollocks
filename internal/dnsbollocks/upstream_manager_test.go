//go:build windows
// +build windows

package dnsbollocks

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/url"
	//"os"

	//"strings"
	"sync/atomic"
	"testing"
)

// setupTestContext creates a fresh UpstreamManager with atomic pointers initialized.
func setupTestContext(cfg *Config) *UpstreamManager {
	var liveConfig atomic.Pointer[Config]
	liveConfig.Store(cfg)

	var liveLogger atomic.Pointer[slog.Logger]
	//logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	liveLogger.Store(logger)

	return NewUpstreamManager(context.Background(), &liveConfig, &liveLogger, nil)
}

func TestValidateUpstream(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		wantErr     bool
		errContains string
	}{
		{
			name: "Valid IPs and SNIs with default port",
			config: Config{
				UpstreamURLs:         []string{"https://1.1.1.1/dns-query", "https://9.9.9.9/dns-query"},
				UpstreamSNIHostnames: []string{"cloudflare-dns.com", "dns.quad9.net"},
			},
			wantErr: false,
		},
		{
			name: "Valid IPs with explicit ports",
			config: Config{
				UpstreamURLs:         []string{"https://1.1.1.1:443/dns-query"},
				UpstreamSNIHostnames: []string{"cloudflare-dns.com"},
			},
			wantErr: false,
		},
		{
			name: "Empty Upstream list",
			config: Config{
				UpstreamURLs: []string{},
			},
			wantErr:     true,
			errContains: "upstream_urls list is empty",
		},
		{
			name: "Invalid Scheme (HTTP instead of HTTPS)",
			config: Config{
				UpstreamURLs:         []string{"http://1.1.1.1/dns-query"},
				UpstreamSNIHostnames: []string{"cloudflare-dns.com"},
			},
			wantErr:     true,
			errContains: "invalid upstream URL (must be https)",
		},
		{
			name: "Hostname instead of IP Literal",
			config: Config{
				UpstreamURLs:         []string{"https://dns.google/dns-query"},
				UpstreamSNIHostnames: []string{"dns.google"},
			},
			wantErr:     true,
			errContains: "upstream host must be IP literal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			um := setupTestContext(&tt.config)
			err := um.updateInnerState()
			cfg := um.getConfig()

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errContains)
				} else if tt.errContains != "" && !containsErr(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				// Verify internal state mutations
				if len(cfg.UpstreamURLsParsed) != len(tt.config.UpstreamURLs) {
					t.Errorf("expected %d mapped URLs, got %d", len(tt.config.UpstreamURLs), len(cfg.UpstreamURLsParsed))
				}
				// Ensure port 443 was injected if missing
				for i, u := range cfg.UpstreamURLsParsed {
					ip := u.Hostname()
					if net.ParseIP(ip) == nil {
						t.Errorf("expected IP not hostname for parsed url %q, got %q", u, ip)
					}
					if u.Port() != "443" {
						t.Errorf("expected port to be strictly 443, got %q for URL %s", u.Port(), u.String())
					}
					rawURL := tt.config.UpstreamURLs[i]
					u2, err := url.Parse(rawURL)
					if err != nil {
						t.Errorf("failed to parse URL %q", rawURL)
					}
					ip2 := u2.Hostname()
					if net.ParseIP(ip2) == nil {
						t.Errorf("expected IP not hostname for parsed url %q raw: %q, got %q", u2, rawURL, ip2)
					}
					if ip != ip2 {
						t.Errorf("expected host(or IP) to be same, got %q != %q for URL %s", ip, ip2, rawURL)
					}
				}
			}
		})
	}
}

// Helper function to check substring in errors
func containsErr(full, sub string) bool {
	// Simple wrapper for strings.Contains (import "strings" if not present)
	fromStringsContains := func(s, substr string) bool {
		for i := 0; i < len(s)-len(substr)+1; i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	}
	return fromStringsContains(full, sub)
}

func TestLifecycleManagement(t *testing.T) {
	cfg := Config{
		UpstreamURLs:               []string{"https://1.1.1.1/dns-query"},
		UpstreamSNIHostnames:       []string{"cloudflare-dns.com"},
		UpstreamIdleConnTimeoutSec: 10,
	}
	um := setupTestContext(&cfg)

	// // Must validate first to populate internal IPs/URLs
	// if err := um.updateInnerState(); err != nil {
	// 	t.Fatalf("setup failed: %v", err)
	// }

	// 1. Test Initialization
	um.InitDoHClients()
	set1 := um.activeSet.Load()
	if set1 == nil {
		t.Fatal("expected activeSet to be initialized, got nil")
	}
	if len(set1.upstreams) != 1 {
		t.Fatalf("expected 1 upstream in the set, got %d", len(set1.upstreams))
	}
	set11 := um.GetOrBuildSet()
	if set11 != set1 {
		t.Fatalf("expected activeSet to be the same as before")
	}

	// 3. Test Rebuild (Ensuring old state doesn't persist)
	um.ReInitDoHClients()
	set2 := um.activeSet.Load()
	if set2 == nil {
		t.Fatal("expected activeSet to be rebuilt after calling InitDoHClients again")
	}
	// We want to ensure it generated an entirely new object in memory,
	// not just passing back the old activeSet pointer.
	if set1 == set2 {
		t.Fatal("expected a completely new pointer for activeSet after rebuild to prevent state leakage")
	}

	set21 := um.GetOrBuildSet()
	if set21 != set2 {
		t.Fatalf("expected activeSet to be the same as before")
	}

	um.activeSet.Store(nil)
	set3 := um.GetOrBuildSet()
	if set3 == nil {
		t.Fatalf("expected non-nil activeSet")
	}
	if set21 == set3 {
		t.Fatalf("expected activeSet to be different than before")
	}

}

// Test 1: Verify that a wired shutdown handler triggers successfully and halts control flow
func TestUpstreamManager_ValidationPanicOnEmptyURLs(t *testing.T) {
	// 1. Force a validation failure via empty UpstreamURLs
	cfg := Config{
		UpstreamURLs: []string{}, // Triggers "upstream_urls list is empty"
	}

	// setupTestContext sets the shutdown handler argument to nil
	um := setupTestContext(&cfg)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected InitDoHClients to panic on invalid config when handler is nil")
		} else {
			expectedPanic := "BUG: Shutdown requested, but no shutdown handler is wired (likely in a test environment)."
			if r != expectedPanic {
				t.Errorf("Expected panic message %q, got: %v", expectedPanic, r)
			}
		}
	}()

	// Triggers buildSet(false) -> updateInnerState() -> Validation Error -> Panic
	um.InitDoHClients()
}

func TestUpstreamManager_ValidationShutdownCallbackOnInvalidScheme(t *testing.T) {
	// 2. Force a validation failure via an invalid URL scheme (must be https)
	cfg := Config{
		UpstreamURLs: []string{"http://127.0.0.1:853"},
	}

	var liveConfig atomic.Pointer[Config]
	liveConfig.Store(&cfg)
	var liveLogger atomic.Pointer[slog.Logger]
	liveLogger.Store(slog.New(slog.NewTextHandler(io.Discard, nil)))
	//logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var capturedExitCode int
	callbackInvoked := false

	// Define a unique sentinel to identify our simulated exit
	const shutdownSentinel = "process-terminated-sentinel"

	shutdownHandler := func(exitCode int) {
		callbackInvoked = true
		capturedExitCode = exitCode
		// 🟢 Fix: Panic here so we never return normally, satisfying your production guardrail
		panic(shutdownSentinel)
	}

	// Manually wire the UpstreamManager with the shutdownHandler callback instead of nil
	um := NewUpstreamManager(context.Background(), &liveConfig, &liveLogger, shutdownHandler)

	// 🟢 Fix: Set up the defer block to catch the sentinel and safely evaluate assertions
	defer func() {
		if r := recover(); r != nil {
			if r != shutdownSentinel {
				// It was an accidental runtime panic from a different bug entirely!
				t.Fatalf("Caught an unexpected runtime crash instead of a clean shutdown signal: %v", r)
			}
		} else {
			t.Fatal("Expected buildSet to trigger a termination sequence via OnShutdown, but it returned normally.")
		}

		// Run your assertions here inside the safe defer window
		if !callbackInvoked {
			t.Errorf("Expected UpstreamManager to fire the OnShutdown callback on invalid URL scheme")
		}
		if capturedExitCode != 1 {
			t.Errorf("Expected exit code 1 to be fed into the shutdown callback, got %d", capturedExitCode)
		}
	}()

	// Should safely hit the callback and panic straight into the deferred recovery above
	um.InitDoHClients()
}

func TestUpstreamManager_BuildSet_ValidationFailureShutdown(t *testing.T) {
	const shutdownSentinel = "um-shutdown-sentinel"

	// Create a broken config that causes updateInnerState() to fail
	cfg := Config{
		UpstreamURLs: []string{"invalid-url-no-scheme"},
	}

	liveConfig := &atomic.Pointer[Config]{}
	liveConfig.Store(&cfg)
	liveLogger := &atomic.Pointer[slog.Logger]{}
	liveLogger.Store(slog.New(slog.NewTextHandler(
		//os.Stdout,
		io.Discard,
		nil)))

	// Wire up the panic sentinel directly into the manager
	um := NewUpstreamManager(context.Background(), liveConfig, liveLogger, func(exitCode int) {
		if exitCode != 1 {
			t.Errorf("expected exit code 1, got %d", exitCode)
		}
		panic(shutdownSentinel)
	})

	defer func() {
		if r := recover(); r != nil {
			if r != shutdownSentinel {
				t.Fatalf("Caught a chaotic downstream crash instead of a clean shutdown intercept: %v", r)
			}
			// Success: Code was stopped exactly at um.OnShutdown(1)
		} else {
			t.Fatal("Expected buildSet to trigger an application shutdown on validation failure, but it kept going.")
		}
	}()

	// This triggers updateInnerState(), fails, and hits the OnShutdown branch
	um.InitDoHClients()
}
