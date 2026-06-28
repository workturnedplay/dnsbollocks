package dnsbollocks

import (
	"context"
	"log/slog"
	//"net/url"
	"os"
	"sync/atomic"
	"testing"
)

// setupTestContext creates a fresh UpstreamManager with atomic pointers initialized.
func setupTestContext(cfg *Config) *UpstreamManager {
	var liveConfig atomic.Pointer[Config]
	liveConfig.Store(cfg)

	var liveLogger atomic.Pointer[slog.Logger]
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	liveLogger.Store(logger)

	return NewUpstreamManager(context.Background(), &liveConfig, &liveLogger)
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
				UpstreamURLs: []string{"https://1.1.1.1/dns-query", "https://9.9.9.9/dns-query"},
				SNIHostnames: []string{"cloudflare-dns.com", "dns.quad9.net"},
			},
			wantErr: false,
		},
		{
			name: "Valid IPs with explicit ports",
			config: Config{
				UpstreamURLs: []string{"https://1.1.1.1:443/dns-query"},
				SNIHostnames: []string{"cloudflare-dns.com"},
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
				UpstreamURLs: []string{"http://1.1.1.1/dns-query"},
				SNIHostnames: []string{"cloudflare-dns.com"},
			},
			wantErr:     true,
			errContains: "invalid upstream URL (must be https)",
		},
		{
			name: "Hostname instead of IP Literal",
			config: Config{
				UpstreamURLs: []string{"https://dns.google/dns-query"},
				SNIHostnames: []string{"dns.google"},
			},
			wantErr:     true,
			errContains: "upstream host must be IP literal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			um := setupTestContext(&tt.config)
			err := um.ValidateUpstream()

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
				if len(um.upstreamURLs) != len(tt.config.UpstreamURLs) {
					t.Errorf("expected %d mapped URLs, got %d", len(tt.config.UpstreamURLs), len(um.upstreamURLs))
				}
				// Ensure port 443 was injected if missing
				for _, u := range um.upstreamURLs {
					if u.Port() != "443" {
						t.Errorf("expected port to be strictly 443, got %q for URL %s", u.Port(), u.String())
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
		SNIHostnames:               []string{"cloudflare-dns.com"},
		UpstreamIdleConnTimeoutSec: 10,
	}
	um := setupTestContext(&cfg)

	// Must validate first to populate internal IPs/URLs
	if err := um.ValidateUpstream(); err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	// 1. Test Initialization
	um.InitDoHClients()
	set1 := um.activeSet.Load()
	if set1 == nil {
		t.Fatal("expected activeSet to be initialized, got nil")
	}
	if len(set1.upstreams) != 1 {
		t.Fatalf("expected 1 upstream in the set, got %d", len(set1.upstreams))
	}

	// 2. Test Reset (Simulation of a config reload trigger)
	um.ResetForReload()
	if um.activeSet.Load() != nil {
		t.Fatal("expected activeSet to be explicitly nil after ResetForReload")
	}

	// 3. Test Rebuild (Ensuring old state doesn't persist)
	um.InitDoHClients()
	set2 := um.activeSet.Load()
	if set2 == nil {
		t.Fatal("expected activeSet to be rebuilt after calling InitDoHClients again")
	}

	// We want to ensure it generated an entirely new object in memory,
	// not just passing back the old activeSet pointer.
	if set1 == set2 {
		t.Fatal("expected a completely new pointer for activeSet after rebuild to prevent state leakage")
	}
}
