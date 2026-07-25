package dnsbollocks

import (
	"github.com/miekg/dns"
	"testing"
	"time"
)

func TestCacheSetZeroTTL(t *testing.T) {
	// Create a fast-expiring background janitor for the test
	cacheStore := newGoCacheStore(1*time.Minute, 100, nil)

	// Attempt to cache an entry with TTL 0
	cacheStore.Set("test-zero:A", CacheEntry{}, 0)

	// Attempt to cache an entry with negative TTL
	cacheStore.Set("test-negative:A", CacheEntry{}, -1*time.Second)

	// Verify nothing was cached
	if _, found := cacheStore.Get("test-zero:A"); found {
		t.Errorf("Expected TTL=0 to silently bypass cache, but entry was found")
	}
	if _, found := cacheStore.Get("test-negative:A"); found {
		t.Errorf("Expected TTL < 0 to silently bypass cache, but entry was found")
	}

	// Verify normal caching still works
	cacheStore.Set("test-valid:A", CacheEntry{}, 1*time.Second)
	if _, found := cacheStore.Get("test-valid:A"); !found {
		t.Errorf("Expected valid TTL to be cached, but entry was not found")
	}
}

func TestComputeTTLForCaching_ZeroRespected(t *testing.T) {
	msg := new(dns.Msg)

	// Simulate an upstream response that explicitly demands NO caching (TTL: 0)
	rr := new(dns.A)
	rr.Hdr = dns.RR_Header{Name: "test.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}
	rr.A = []byte{1, 1, 1, 1}
	msg.Answer = append(msg.Answer, rr)

	ttl := computeTTLForCaching(msg)

	if ttl != 0 {
		t.Errorf("Expected computeTTLForCaching to respect 0 TTL, but got %v", ttl)
	}
}
