//go:build windows
// +build windows

package dnsbollocks

import (
	"net"
	"testing"
	"time"
)

// --- LoginTracker Tests ---

func TestLoginTracker(t *testing.T) {
	tracker := newLoginTracker()
	ip := "192.168.1.100"
	maxFailures := 3
	lockoutSec := 1 // Use 1 second so we can test expiration easily if needed

	// 1. Initial State
	allowed, rem, _ := tracker.IsAllowed(ip, maxFailures)
	if !allowed || rem != maxFailures {
		t.Errorf("Expected initial state allowed=true, rem=%d, got allowed=%v, rem=%d", maxFailures, allowed, rem)
	}

	// 2. Record Failures until Lockout
	lockedOut, _, total := tracker.RecordFailure(ip, maxFailures, lockoutSec)
	if lockedOut || total != 1 {
		t.Errorf("Expected lockedOut=false, total=1, got %v, %d", lockedOut, total)
	}

	tracker.RecordFailure(ip, maxFailures, lockoutSec)
	lockedOut, _, total = tracker.RecordFailure(ip, maxFailures, lockoutSec)
	if !lockedOut || total != maxFailures {
		t.Errorf("Expected lockout after %d failures, got lockedOut=%v, total=%d", maxFailures, lockedOut, total)
	}

	// 3. Verify Lockout State
	allowed, rem, _ = tracker.IsAllowed(ip, maxFailures)
	if allowed || rem != 0 {
		t.Errorf("Expected IsAllowed to reject during lockout, got allowed=%v, rem=%d", allowed, rem)
	}

	// 4. Record Success Clears Tracking
	tracker.RecordSuccess(ip)
	allowed, rem, _ = tracker.IsAllowed(ip, maxFailures)
	if !allowed || rem != maxFailures {
		t.Errorf("Expected RecordSuccess to completely clear tracking, got allowed=%v, rem=%d", allowed, rem)
	}
}

// --- BlacklistStore Tests ---

func TestBlacklistStore(t *testing.T) {
	store := newBlacklistStore()
	_, cidr1, _ := net.ParseCIDR("10.0.0.0/8")
	_, cidr2, _ := net.ParseCIDR("192.168.1.0/24")

	// 1. Test TryAdd
	if added := store.TryAdd(cidr1); !added || store.Len() != 1 {
		t.Errorf("Expected TryAdd to succeed and len=1, got added=%v, len=%d", added, store.Len())
	}

	// 2. Test Duplicate Add
	if added := store.TryAdd(cidr1); added || store.Len() != 1 {
		t.Errorf("Expected duplicate TryAdd to fail and len=1, got added=%v, len=%d", added, store.Len())
	}

	store.TryAdd(cidr2)

	// 3. Test Contains
	tests := []struct {
		ip       string
		expected bool
	}{
		{"10.5.5.5", true},      // Inside /8
		{"192.168.1.50", true},  // Inside /24
		{"192.168.2.50", false}, // Outside /24
		{"11.0.0.1", false},     // Outside /8
	}

	for _, tt := range tests {
		if store.Contains(net.ParseIP(tt.ip)) != tt.expected {
			t.Errorf("Contains(%q) expected %v", tt.ip, tt.expected)
		}
	}

	// 4. Test TryDelete
	if deleted := store.TryDelete("10.0.0.0/8"); !deleted || store.Len() != 1 {
		t.Errorf("Expected TryDelete to succeed, got deleted=%v, len=%d", deleted, store.Len())
	}
	if store.Contains(net.ParseIP("10.5.5.5")) {
		t.Errorf("Expected 10.5.5.5 to be allowed after CIDR deletion")
	}
}

// --- RecentBlocksTracker Tests ---

func TestRecentBlocksTracker(t *testing.T) {
	tracker := newRecentBlocksTracker()
	maxBlocks := 2

	// 1. Basic recording and LRU cap
	tracker.Record("example.com", "A", maxBlocks)
	tracker.Record("test.com", "AAAA", maxBlocks)
	tracker.Record("overflow.com", "A", maxBlocks) // This should evict example.com

	snap := tracker.Snapshot(func(_, _ string) bool { return false })

	if len(snap) != 2 {
		t.Fatalf("Expected snapshot length to cap at %d, got %d", maxBlocks, len(snap))
	}
	if snap[0].Domain != "overflow.com" || snap[1].Domain != "test.com" {
		t.Errorf("Expected [overflow.com, test.com] order, got [%s, %s]", snap[0].Domain, snap[1].Domain)
	}

	// 2. Move to front on duplicate
	// Sending test.com again should push it to the front of the list without changing length
	time.Sleep(1 * time.Millisecond) // Ensure time diff
	tracker.Record("test.com", "AAAA", maxBlocks)

	snap = tracker.Snapshot(func(_, _ string) bool { return false })
	if len(snap) != 2 || snap[0].Domain != "test.com" {
		t.Errorf("Expected test.com to move to the front, got %s at index 0", snap[0].Domain)
	}
}

// --- HostStore Tests ---

func TestHostStore(t *testing.T) {
	store := newHostStore()

	// 1. Test Add
	err := store.AddHost("router.local", []net.IP{net.ParseIP("192.168.1.1")})
	if err != nil {
		t.Fatalf("Failed to add host: %v", err)
	}

	// 2. Test Duplicate Error
	err = store.AddHost("router.local", []net.IP{net.ParseIP("10.0.0.1")})
	if err == nil {
		t.Errorf("Expected error when adding a duplicate host pattern")
	}

	// 3. Test Match (Uses wildcard matcher under the hood, but we test the store plumbing)
	ips, match := store.Match("router.local")
	if !match || len(ips) != 1 || ips[0].String() != "192.168.1.1" {
		t.Errorf("Match failed, got match=%v, ips=%v", match, ips)
	}

	// 4. Test Edit
	store.EditHost("router.local", "router.home", []net.IP{net.ParseIP("192.168.1.2")})
	_, match = store.Match("router.local")
	if match {
		t.Errorf("Expected old pattern 'router.local' to be deleted after edit")
	}
	ips, match = store.Match("router.home")
	if !match || ips[0].String() != "192.168.1.2" {
		t.Errorf("Expected new pattern 'router.home' to yield new IP")
	}

	// 5. Test Delete
	if deleted := store.DeleteHost("router.home"); !deleted || store.Len() != 0 {
		t.Errorf("Expected host to be deleted, got deleted=%v, len=%d", deleted, store.Len())
	}
}
