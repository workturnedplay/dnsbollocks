//go:build windows
// +build windows

package dnsbollocks

import (
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSCache(t *testing.T) {
	// Discard logs to keep test output clean
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var liveLogger atomic.Pointer[slog.Logger]
	liveLogger.Store(logger)
	// Initialize cache with a fast janitor interval for testing if needed
	cache := newGoCacheStore(5*time.Minute, 100, &liveLogger)

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	entry := CacheEntry{
		Msg: msg,
		State: UpstreamState{
			Strategy:     "fastest",
			UpstreamUsed: "https://1.1.1.1/dns-query",
		},
	}

	key := "example.com.:A"

	// Test: Get on empty cache
	_, ok := cache.Get(key)
	if ok {
		t.Fatal("Expected cache miss on empty cache")
	}

	// Test: Set and Get
	cache.Set(key, entry, 1*time.Minute)

	cachedEntry, ok := cache.Get(key)
	if !ok {
		t.Fatal("Expected cache hit after Set")
	}
	if cachedEntry.State.Strategy != "fastest" {
		t.Errorf("Expected strategy 'fastest', got %q", cachedEntry.State.Strategy)
	}
	if cachedEntry.Msg.Question[0].Name != "example.com." {
		t.Errorf("Expected cached message question to match")
	}

	// Test: ItemCount
	if count := cache.ItemCount(); count != 1 {
		t.Errorf("Expected ItemCount to be 1, got %d", count)
	}

	// Test: Delete
	cache.Delete(key)
	_, ok = cache.Get(key)
	if ok {
		t.Fatal("Expected cache miss after Delete")
	}

	// Test: Flush
	cache.Set("another.com.:A", entry, 1*time.Minute)
	cache.Set("third.com.:AAAA", entry, 1*time.Minute)

	if cache.ItemCount() != 2 {
		t.Fatalf("Expected 2 items, got %d", cache.ItemCount())
	}

	cache.Flush()
	if cache.ItemCount() != 0 {
		t.Errorf("Expected cache to be empty after Flush, got %d items", cache.ItemCount())
	}
}
