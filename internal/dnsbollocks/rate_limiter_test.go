package dnsbollocks

import (
	//"context"
	"fmt"
	"io"
	"log/slog"
	//"os"
	"testing"
)

func TestClientRateLimiter_Allow(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(
		//os.Stderr,
		io.Discard,
		nil))

	cfg := RateLimitConfig{
		GlobalQPS:   10,
		GlobalBurst: 10,
		ClientQPS:   2,
		ClientBurst: 2,
	}
	// ctx, cancel := context.WithCancel(context.Background())
	// defer cancel() // <--- This cleanly shuts down the janitor goroutine when the test ends
	// rl := newClientRateLimiter(ctx, cfg, logger)
	// Modern Go 1.24+ approach: No manual context creation or defer cancel() required!
	rl := newClientRateLimiter(t.Context(), cfg, logger)

	// Test 1: Client burst limit
	clientA := "192.168.1.10:53421"

	for i := 0; i < 2; i++ {
		allowed, reason := rl.Allow(clientA)
		if !allowed {
			t.Fatalf("Expected Client A to be allowed on request %d, got blocked: %s", i+1, reason)
		}
	}

	// 3rd request for Client A should be blocked (exceeds client burst of 2)
	allowed, reason := rl.Allow(clientA)
	if allowed {
		t.Fatal("Expected Client A to be blocked on 3rd request (client limit exceeded)")
	}
	if reason != clientRateLimitExceeded {
		t.Errorf("Expected reason %q, got %q", clientRateLimitExceeded, reason)
	}

	// Test 2: Different client should still be allowed
	clientB := "10.0.0.5:12345"
	allowed, _ = rl.Allow(clientB)
	if !allowed {
		t.Fatal("Expected Client B to be allowed, but it was blocked")
	}

	// Test 3: Global limit exhaustion
	// Drain the remaining global tokens dynamically
	var globalBlocked bool
	for i := 0; i < 20; i++ { // 20 is comfortably higher than the burst of 10
		// Use a unique IP every time so we don't trigger the client limit
		allowed, reason = rl.Allow(fmt.Sprintf("172.16.0.%d:1000", i))
		if !allowed {
			if reason == globalRateLimitExceeded {
				globalBlocked = true
				break
			} else {
				t.Fatalf("Unexpected block reason while draining global tokens: %s", reason)
			}
		}
	}

	if !globalBlocked {
		t.Fatal("Expected global rate limit to trigger, but it never did")
	}
}
