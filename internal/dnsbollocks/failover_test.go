package dnsbollocks

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// --- Mocking Utilities ---

// mockTransport allows us to intercept HTTP calls and return simulated DoH responses.
type mockTransport struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

// createMockUpstream creates an Upstream configured with a specific RoundTripper behavior.
func createMockUpstream(u string, handler func(*http.Request) (*http.Response, error)) Upstream {
	parsedURL, _ := url.Parse(u)
	return Upstream{
		URL: parsedURL,
		SNI: parsedURL.Hostname(),
		Client: &http.Client{
			Transport: &mockTransport{roundTripFunc: handler},
		},
		logger:        slog.Default(),
		Retries:       0,
		BackgroundCtx: context.Background(),
	}
}

// makeDoHResponse packs a dummy DNS message into an HTTP 200 response.
func makeDoHResponse() *http.Response {
	msg := new(dns.Msg)
	msg.Id = 1234
	msg.Rcode = dns.RcodeSuccess
	b, _ := msg.Pack()
	
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(b)),
	}
	resp.Header.Set("Content-Type", "application/dns-message")
	return resp
}

// --- Failover Selector Tests ---

func TestFailoverSelector_Exchange(t *testing.T) {
	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dummyReqBytes := []byte("dummy-dns-query")

	t.Run("Primary Success", func(t *testing.T) {
		fs := NewFailoverSelector(discardLogger)
		upstreams := []Upstream{
			createMockUpstream("https://primary.com", func(req *http.Request) (*http.Response, error) {
				return makeDoHResponse(), nil
			}),
			createMockUpstream("https://secondary.com", func(req *http.Request) (*http.Response, error) {
				t.Fatal("Secondary should not be called if primary succeeds immediately")
				return nil, errors.New("should not be reached")
			}),
		}

		_, usedURL, failedURLs, err := fs.Exchange(context.Background(), upstreams, dummyReqBytes)
		
		if err != nil {
			t.Fatalf("Expected success, got error: %v", err)
		}
		if usedURL != "https://primary.com" {
			t.Errorf("Expected primary.com to be used, got %s", usedURL)
		}
		if len(failedURLs) != 0 {
			t.Errorf("Expected 0 failures, got %d", len(failedURLs))
		}
		if fs.activeIndex != 0 {
			t.Errorf("Expected activeIndex 0, got %d", fs.activeIndex)
		}
	})

	t.Run("Primary Fails, Falls back to Secondary", func(t *testing.T) {
		fs := NewFailoverSelector(discardLogger)
		upstreams := []Upstream{
			createMockUpstream("https://primary.com", func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("simulated timeout/failure")
			}),
			createMockUpstream("https://secondary.com", func(req *http.Request) (*http.Response, error) {
				return makeDoHResponse(), nil
			}),
		}

		_, usedURL, failedURLs, err := fs.Exchange(context.Background(), upstreams, dummyReqBytes)

		if err != nil {
			t.Fatalf("Expected success via fallback, got error: %v", err)
		}
		if usedURL != "https://secondary.com" {
			t.Errorf("Expected secondary.com to be used, got %s", usedURL)
		}
		if len(failedURLs) != 1 || failedURLs[0] != "https://primary.com" {
			t.Errorf("Expected primary.com in failed list, got %v", failedURLs)
		}
		
		// The selector should have promoted the secondary to active
		fs.mu.RLock()
		idx := fs.activeIndex
		fs.mu.RUnlock()
		if idx != 1 {
			t.Errorf("Expected activeIndex to update to 1, got %d", idx)
		}
	})

	t.Run("Global Blackout", func(t *testing.T) {
		fs := NewFailoverSelector(discardLogger)
		upstreams := []Upstream{
			createMockUpstream("https://primary.com", func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("fail")
			}),
			createMockUpstream("https://secondary.com", func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("fail")
			}),
		}

		_, _, failedURLs, err := fs.Exchange(context.Background(), upstreams, dummyReqBytes)

		if err == nil {
			t.Fatal("Expected error due to global blackout, got nil")
		}
		if len(failedURLs) != 2 {
			t.Errorf("Expected 2 failed URLs, got %d", len(failedURLs))
		}

		fs.mu.RLock()
		allFailed := fs.allFailed
		fs.mu.RUnlock()
		if !allFailed {
			t.Error("Expected allFailed state to be true")
		}
	})

	t.Run("Healing Probe Restores Primary", func(t *testing.T) {
		fs := NewFailoverSelector(discardLogger)
		// Force state to simulate that secondary is currently active
		fs.activeIndex = 1 

		var primaryCalled atomic.Bool
		
		upstreams := []Upstream{
			createMockUpstream("https://primary.com", func(req *http.Request) (*http.Response, error) {
				primaryCalled.Store(true)
				return makeDoHResponse(), nil
			}),
			createMockUpstream("https://secondary.com", func(req *http.Request) (*http.Response, error) {
				// Add slight delay to ensure primary probe finishes first and proves the race condition works
				time.Sleep(10 * time.Millisecond)
				return makeDoHResponse(), nil
			}),
		}

		_, usedURL, _, err := fs.Exchange(context.Background(), upstreams, dummyReqBytes)

		if err != nil {
			t.Fatalf("Expected success, got error: %v", err)
		}
		if !primaryCalled.Load() {
			t.Error("Primary upstream should have been probed in parallel")
		}
		if usedURL != "https://primary.com" {
			t.Errorf("Expected primary.com to win the probe race, got %s", usedURL)
		}

		fs.mu.RLock()
		idx := fs.activeIndex
		fs.mu.RUnlock()
		if idx != 0 {
			t.Errorf("Expected activeIndex to heal back to 0, got %d", idx)
		}
	})
}