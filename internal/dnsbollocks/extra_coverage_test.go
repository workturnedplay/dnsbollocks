//go:build windows
// +build windows

package dnsbollocks

// This file adds test coverage for areas not yet exercised by the existing
// test suite: blockResponse (all BlockModes + EDE + EDNS0 clamping),
// BlacklistStore.TryEdit/CheckMatches, HostStore.ToRawMap,
// RecentBlocksTracker's IsUnblocked flag, LoginTracker lockout expiry and
// ClearAll, ClientRateLimiter.UpdateConfig, the RuleStore copy-returning
// helpers + ID generation, rotatingLogWriter rotation behavior, and the
// AdminUI security middlewares (CSRF, Origin validation, Host validation,
// Fetch-Metadata whitelist, security headers).
//
// Reuses discardLogger() (rulestore_test.go) and setupTestAdminUI()
// (admin_ui_test.go) from elsewhere in this package.

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ════════════════════════════════════════════════════════════════════════
// blockResponse
// ════════════════════════════════════════════════════════════════════════

func newBlockTestServer(cfg Config) *Server {
	s := &Server{}
	s.liveConfig.Store(&cfg)
	s.logMgr = NewLoggerManager(discardLogger())
	return s
}

func newBlockQuery(qtype uint16, name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	return m
}

func TestBlockResponse_NXDOMAIN(t *testing.T) {
	cfg := defaultConfig()
	cfg.BlockMode = "nxdomain"
	s := newBlockTestServer(cfg)

	resp := s.blockResponse(newBlockQuery(dns.TypeA, "blocked.example.com"))
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN, got %d", resp.Rcode)
	}
	if !resp.Authoritative || !resp.RecursionAvailable {
		t.Error("expected Authoritative and RecursionAvailable to be set")
	}
}

func TestBlockResponse_NXDOMAIN_AAAAEmptyNoError(t *testing.T) {
	cfg := defaultConfig()
	cfg.BlockMode = "nxdomain"
	cfg.BlockAAAAasEmptyNoError = true
	s := newBlockTestServer(cfg)

	resp := s.blockResponse(newBlockQuery(dns.TypeAAAA, "blocked.example.com"))
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("expected Success rcode for AAAA-as-empty-noerror, got %d", resp.Rcode)
	}
	if len(resp.Answer) != 0 || len(resp.Ns) != 0 || len(resp.Extra) != 0 {
		t.Errorf("expected all sections empty, got Answer=%d Ns=%d Extra=%d",
			len(resp.Answer), len(resp.Ns), len(resp.Extra))
	}
}

func TestBlockResponse_IPBlock(t *testing.T) {
	cfg := defaultConfig()
	cfg.BlockMode = "ip_block"
	cfg.BlockIPv4Parsed = net.ParseIP("0.0.0.0").To4()
	cfg.BlockIPv6Parsed = net.ParseIP("::").To16()
	s := newBlockTestServer(cfg)

	t.Run("A query returns block IPv4", func(t *testing.T) {
		resp := s.blockResponse(newBlockQuery(dns.TypeA, "blocked.example.com"))
		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("expected Success, got %d", resp.Rcode)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
		}
		a, ok := resp.Answer[0].(*dns.A)
		if !ok || !a.A.Equal(cfg.BlockIPv4Parsed) {
			t.Errorf("expected block IPv4 answer, got %v", resp.Answer[0])
		}
	})

	t.Run("AAAA query returns block IPv6", func(t *testing.T) {
		resp := s.blockResponse(newBlockQuery(dns.TypeAAAA, "blocked.example.com"))
		if len(resp.Answer) != 1 {
			t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
		}
		aaaa, ok := resp.Answer[0].(*dns.AAAA)
		if !ok || !aaaa.AAAA.Equal(cfg.BlockIPv6Parsed) {
			t.Errorf("expected block IPv6 answer, got %v", resp.Answer[0])
		}
	})

	t.Run("other query type returns empty success", func(t *testing.T) {
		resp := s.blockResponse(newBlockQuery(dns.TypeTXT, "blocked.example.com"))
		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("expected Success, got %d", resp.Rcode)
		}
		if len(resp.Answer) != 0 {
			t.Errorf("expected empty answer for non-A/AAAA type, got %d", len(resp.Answer))
		}
	})
}

func TestBlockResponse_Drop(t *testing.T) {
	cfg := defaultConfig()
	cfg.BlockMode = "drop"
	s := newBlockTestServer(cfg)

	resp := s.blockResponse(newBlockQuery(dns.TypeA, "blocked.example.com"))
	if resp != nil {
		t.Errorf("expected nil response for drop mode, got %v", resp)
	}
}

func TestBlockResponse_UnknownModePanics(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.BlockMode = "totally-not-a-real-mode"

	s := newBlockTestServer(cfg)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic")
		}

		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected panic(string), got %T (%v)", r, r)
		}

		const want = "BUG: validated BlockMode reached impossible value"
		if !strings.Contains(msg, want) {
			t.Fatalf("panic message %q does not contain %q", msg, want)
		}
	}()

	_ = s.blockResponse(newBlockQuery(dns.TypeA, "blocked.example.com"))
}

func TestBlockResponse_EDE(t *testing.T) {
	t.Run("EDE enabled adds EDNS0_EDE option and sets DO bit", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.BlockMode = "nxdomain"
		cfg.UseEDEInBlockedReply = true
		s := newBlockTestServer(cfg)

		resp := s.blockResponse(newBlockQuery(dns.TypeA, "blocked.example.com"))
		opt := resp.IsEdns0()
		if opt == nil {
			t.Fatal("expected an OPT record in Extra")
		}
		if !opt.Do() {
			t.Error("expected DO bit to be set when EDE is enabled")
		}
		if len(opt.Option) != 1 {
			t.Fatalf("expected exactly one EDNS0 option, got %d", len(opt.Option))
		}
		ede, ok := opt.Option[0].(*dns.EDNS0_EDE)
		if !ok {
			t.Fatalf("expected EDNS0_EDE option, got %T", opt.Option[0])
		}
		if ede.InfoCode != edeCode {
			t.Errorf("expected InfoCode %v, got %v", edeCode, ede.InfoCode)
		}
	})

	t.Run("EDE disabled omits EDNS0 option", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.BlockMode = "nxdomain"
		cfg.UseEDEInBlockedReply = false
		s := newBlockTestServer(cfg)

		resp := s.blockResponse(newBlockQuery(dns.TypeA, "blocked.example.com"))
		opt := resp.IsEdns0()
		if opt == nil {
			t.Fatal("expected an OPT record in Extra even without EDE")
		}
		if opt.Do() {
			t.Error("expected DO bit to be unset when EDE is disabled")
		}
		if len(opt.Option) != 0 {
			t.Errorf("expected no EDNS0 options when EDE is disabled, got %d", len(opt.Option))
		}
	})
}

func TestBlockResponse_ClampsUDPSizeToClientAdvertised(t *testing.T) {
	cfg := defaultConfig()
	cfg.BlockMode = "nxdomain"
	s := newBlockTestServer(cfg)

	q := newBlockQuery(dns.TypeA, "blocked.example.com")
	q.SetEdns0(500, false)

	resp := s.blockResponse(q)
	opt := resp.IsEdns0()
	if opt == nil {
		t.Fatal("expected OPT record in response")
	}
	if opt.UDPSize() != 500 {
		t.Errorf("expected UDP size clamped to client-advertised 500, got %d", opt.UDPSize())
	}
}

// ════════════════════════════════════════════════════════════════════════
// BlacklistStore: TryEdit / CheckMatches
// ════════════════════════════════════════════════════════════════════════

func TestBlacklistStore_TryEdit(t *testing.T) {
	store := newBlacklistStore()
	_, cidrA, _ := net.ParseCIDR("10.0.0.0/8")     //nolint:errcheck // IP is already valid
	_, cidrB, _ := net.ParseCIDR("192.168.0.0/16") //nolint:errcheck // IP is already valid
	store.TryAdd(cidrA)
	store.TryAdd(cidrB)

	_, newNet, _ := net.ParseCIDR("172.16.0.0/12") //nolint:errcheck // IP is already valid
	if err := store.TryEdit("10.0.0.0/8", newNet); err != nil {
		t.Fatalf("unexpected error editing entry: %v", err)
	}
	if store.Contains(net.ParseIP("10.5.5.5")) {
		t.Error("expected old CIDR to no longer match after edit")
	}
	if !store.Contains(net.ParseIP("172.20.1.1")) {
		t.Error("expected new CIDR to match after edit")
	}
	if store.Len() != 2 {
		t.Errorf("expected Len()=2 after edit, got %d", store.Len())
	}

	if err := store.TryEdit("does-not-exist", newNet); err == nil {
		t.Error("expected error editing nonexistent entry")
	}

	_, conflictNet, _ := net.ParseCIDR("192.168.0.0/16") //nolint:errcheck // IP is already valid
	if err := store.TryEdit("172.16.0.0/12", conflictNet); err == nil {
		t.Error("expected error editing to a CIDR that already exists elsewhere in the store")
	}
}

func TestBlacklistStore_CheckMatches(t *testing.T) {
	store := newBlacklistStore()
	_, cidrA, _ := net.ParseCIDR("10.0.0.0/8") //nolint:errcheck // IP is already valid
	store.TryAdd(cidrA)

	_, sub, _ := net.ParseCIDR("10.1.0.0/16") //nolint:errcheck // IP is already valid
	matches := store.CheckMatches(sub)
	if len(matches) != 1 || matches[0] != "10.0.0.0/8" {
		t.Errorf("expected match against 10.0.0.0/8, got %v", matches)
	}

	_, unrelated, _ := net.ParseCIDR("172.16.0.0/12") //nolint:errcheck // IP is already valid
	matches = store.CheckMatches(unrelated)
	if len(matches) != 0 {
		t.Errorf("expected no matches for unrelated CIDR, got %v", matches)
	}
}

// ════════════════════════════════════════════════════════════════════════
// HostStore.ToRawMap
// ════════════════════════════════════════════════════════════════════════

func TestHostStore_ToRawMap(t *testing.T) {
	store := newHostStore()
	if err := store.AddHost("router.local", []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2")}); err != nil {
		t.Fatalf("AddHost: %v", err)
	}
	if err := store.AddHost("nas.local", []net.IP{net.ParseIP("10.0.0.5")}); err != nil {
		t.Fatalf("AddHost: %v", err)
	}

	raw := store.ToRawMap()
	if len(raw) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(raw))
	}
	ips, ok := raw["router.local"]
	if !ok || len(ips) != 2 {
		t.Fatalf("expected 2 IPs for router.local, got %v", ips)
	}
	if ips[0] != "192.168.1.1" || ips[1] != "192.168.1.2" {
		t.Errorf("unexpected IP order/content: %v", ips)
	}
}

// ════════════════════════════════════════════════════════════════════════
// RecentBlocksTracker: IsUnblocked flag
// ════════════════════════════════════════════════════════════════════════

func TestRecentBlocksTracker_Snapshot_IsUnblockedFlag(t *testing.T) {
	tracker := newRecentBlocksTracker()
	tracker.Record("blocked.example.com", "A", 10)
	tracker.Record("unblocked.example.com", "A", 10)

	snap := tracker.Snapshot(func(domain, qtype string) bool {
		_ = qtype
		return domain == "unblocked.example.com"
	})

	if len(snap) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(snap))
	}
	for _, b := range snap {
		switch b.Domain {
		case "unblocked.example.com":
			if !b.IsUnblocked {
				t.Error("expected unblocked.example.com to have IsUnblocked=true")
			}
		case "blocked.example.com":
			if b.IsUnblocked {
				t.Error("expected blocked.example.com to have IsUnblocked=false")
			}
		}
	}
}

// ════════════════════════════════════════════════════════════════════════
// LoginTracker: ClearAll and lockout expiry
// ════════════════════════════════════════════════════════════════════════

func TestLoginTracker_ClearAll(t *testing.T) {
	lt := newLoginTracker()
	lt.RecordFailure("1.2.3.4", 3, 60)
	lt.RecordFailure("5.6.7.8", 3, 60)

	n := lt.ClearAll()
	if n != 2 {
		t.Errorf("expected ClearAll to report 2 cleared entries, got %d", n)
	}

	allowed, remaining, _ := lt.IsAllowed("1.2.3.4", 3)
	if !allowed || remaining != 3 {
		t.Errorf("expected fresh state after ClearAll, got allowed=%v remaining=%d", allowed, remaining)
	}
}

func TestLoginTracker_LockoutExpiry(t *testing.T) {
	lt := newLoginTracker()
	ip := "9.9.9.9"
	maxFailures := 2
	lockoutSec := 1

	lt.RecordFailure(ip, maxFailures, lockoutSec)
	lockedOut, _, _ := lt.RecordFailure(ip, maxFailures, lockoutSec)
	if !lockedOut {
		t.Fatal("expected lockout after reaching maxFailures")
	}

	allowed, _, _ := lt.IsAllowed(ip, maxFailures)
	if allowed {
		t.Fatal("expected IsAllowed to reject during active lockout")
	}

	time.Sleep(time.Duration(lockoutSec+1) * time.Second)

	allowed, remaining, _ := lt.IsAllowed(ip, maxFailures)
	if !allowed || remaining != maxFailures {
		t.Errorf("expected lockout to expire and reset, got allowed=%v remaining=%d", allowed, remaining)
	}
}

// ════════════════════════════════════════════════════════════════════════
// ClientRateLimiter.UpdateConfig
// ════════════════════════════════════════════════════════════════════════

func TestClientRateLimiter_UpdateConfig(t *testing.T) {
	logger := discardLogger()
	cfg := RateLimitConfig{GlobalQPS: 100, GlobalBurst: 100, ClientQPS: 1, ClientBurst: 1}
	rl := newClientRateLimiter(t.Context(), cfg, logger)

	client := "192.0.2.50:1234"
	allowed, _ := rl.Allow(client)
	if !allowed {
		t.Fatal("expected first request to be allowed")
	}
	allowed, reason := rl.Allow(client)
	if allowed {
		t.Fatal("expected second request to be blocked under restrictive client burst")
	}
	if reason != clientRateLimitExceeded {
		t.Errorf("expected reason %q, got %q", clientRateLimitExceeded, reason)
	}

	// Loosen the config; UpdateConfig must drop existing per-client state so
	// the new burst applies immediately rather than being capped by a
	// leftover limiter built from the old (stricter) config.
	rl.UpdateConfig(RateLimitConfig{GlobalQPS: 100, GlobalBurst: 100, ClientQPS: 50, ClientBurst: 50})

	allowed, reason = rl.Allow(client)
	if !allowed {
		t.Fatalf("expected client to be allowed again after UpdateConfig loosened limits, reason=%q", reason)
	}
}

// ════════════════════════════════════════════════════════════════════════
// RuleStore copy-returning helpers + ID generation
// ════════════════════════════════════════════════════════════════════════

func TestWithRulePrepended(t *testing.T) {
	log := discardLogger()

	var entries []RuleEntry
	entries = withRulePrepended(entries, RuleEntry{ID: "1", Pattern: "a.com"}, log)
	if len(entries) != 1 || entries[0].ID != "1" {
		t.Fatalf("unexpected state after first prepend: %+v", entries)
	}

	entries = withRulePrepended(entries, RuleEntry{ID: "2", Pattern: "b.com"}, log)
	if len(entries) != 2 || entries[0].ID != "2" || entries[1].ID != "1" {
		t.Fatalf("expected newest rule at front, got %+v", entries)
	}
}

func TestWithRuleRemovedAt(t *testing.T) {
	log := discardLogger()
	entries := []RuleEntry{{ID: "1"}, {ID: "2"}, {ID: "3"}}

	result := withRuleRemovedAt(entries, 1, log)
	if len(result) != 2 || result[0].ID != "1" || result[1].ID != "3" {
		t.Fatalf("unexpected result after removal: %+v", result)
	}

	// Out-of-range indices must be safe no-ops.
	same := withRuleRemovedAt(entries, -1, log)
	if len(same) != len(entries) {
		t.Error("expected no-op for negative index")
	}
	same = withRuleRemovedAt(entries, len(entries), log)
	if len(same) != len(entries) {
		t.Error("expected no-op for out-of-bounds index")
	}
}

func TestWithRuleUpdatedAtIndex(t *testing.T) {
	log := discardLogger()
	entries := []RuleEntry{{ID: "1", Pattern: "a.com"}, {ID: "2", Pattern: "b.com"}}

	updated := withRuleUpdatedAtIndex(entries, 0, RuleEntry{ID: "1", Pattern: "changed.com", Enabled: true}, log)
	if updated[0].Pattern != "changed.com" || !updated[0].Enabled {
		t.Errorf("expected index 0 to be updated, got %+v", updated[0])
	}
	if updated[1].Pattern != "b.com" {
		t.Errorf("expected index 1 to remain untouched, got %+v", updated[1])
	}
	// Ensure the original slice's contents weren't corrupted by aliasing.
	if entries[0].Pattern != "a.com" {
		t.Errorf("expected original entries to be unmodified, got %+v", entries[0])
	}
}

func TestGenerateUniqueRuleID2_AvoidsCollisions(t *testing.T) {
	log := discardLogger()

	existing := map[string][]RuleEntry{
		"A": {{ID: "fixed-id-1"}, {ID: "fixed-id-2"}},
	}

	seen := make(map[string]struct{})
	for range 20 {
		id := generateUniqueRuleID(existing, log)
		if id == "" {
			t.Fatal("expected non-empty generated ID")
		}
		if id == "fixed-id-1" || id == "fixed-id-2" {
			t.Fatalf("generated ID collided with pre-existing ID: %s", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("generated duplicate ID across calls: %s", id)
		}
		seen[id] = struct{}{}
	}
}

// ════════════════════════════════════════════════════════════════════════
// rotatingLogWriter
// ════════════════════════════════════════════════════════════════════════

func TestRotatingLogWriter_WriteAndRotate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	logger := discardLogger()

	w, err := newRotatingLogWriter(path, 100, logger) // 100MB; we override maxBytes below.
	if err != nil {
		t.Fatalf("newRotatingLogWriter failed: %v", err)
	}
	// Add this immediately after initialization to ensure cleanup
	defer func() {
		if w.file != nil {
			err2 := w.file.Close()
			if err2 != nil {
				t.Fatalf("file close failed, err:%v", err2)
			}
		}
	}()

	// Force a tiny threshold so we can trigger rotation without writing
	// megabytes of data.
	w.maxBytes = 10

	if _, err2 := w.Write([]byte("hello")); err2 != nil { // 5 bytes, size=5, no rotation yet
		t.Fatalf("first write failed: %v", err2)
	}
	if w.size != 5 {
		t.Fatalf("expected size=5 after first write, got %d", w.size)
	}

	if _, err3 := w.Write([]byte("world!")); err3 != nil { // 6 bytes; check happens BEFORE this write (size=5<10), so no rotation yet; size becomes 11 after
		t.Fatalf("second write failed: %v", err3)
	}
	if w.size != 11 {
		t.Fatalf("expected size=11 after second write, got %d", w.size)
	}

	// Third write: rotateIfNeeded runs first (size 11 >= maxBytes 10) → rotates,
	// then writes "x" into the fresh file.
	if _, err4 := w.Write([]byte("x")); err4 != nil {
		t.Fatalf("third write failed: %v", err4)
	}
	if w.size != 1 {
		t.Fatalf("expected size=1 after rotation+write, got %d", w.size)
	}

	backupPath := path + ".1"
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("expected backup file %q to exist: %v", backupPath, err)
	}
	if string(backupData) != "helloworld!" {
		t.Errorf("expected backup file to contain %q, got %q", "helloworld!", backupData)
	}

	currentData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected current log file to exist: %v", err)
	}
	if string(currentData) != "x" {
		t.Errorf("expected current log file to contain %q, got %q", "x", currentData)
	}
}

// ════════════════════════════════════════════════════════════════════════
// AdminUI security middlewares
// ════════════════════════════════════════════════════════════════════════

func TestAdminUI_CSRFMiddleware(t *testing.T) {
	t.Run("GET sets cookie and passes through", func(t *testing.T) {
		ui, rec := setupTestAdminUI(t)
		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; _ = w; _ = r })
		h := ui.csrfMiddleware(next)

		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		h.ServeHTTP(rec, req)

		if !called {
			t.Error("expected GET to reach the next handler")
		}
		found := false
		for _, c := range rec.Result().Cookies() {
			if c.Name == "csrf_token" {
				found = true
			}
		}
		if !found {
			t.Error("expected csrf_token cookie to be set")
		}
	})

	t.Run("POST without token is rejected", func(t *testing.T) {
		ui, rec := setupTestAdminUI(t)
		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; _ = w; _ = r })
		h := ui.csrfMiddleware(next)

		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.ServeHTTP(rec, req)

		if called {
			t.Error("expected next handler NOT to be called without a valid CSRF token")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("POST with matching cookie+form token passes", func(t *testing.T) {
		ui, rec := setupTestAdminUI(t)
		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; _ = w; _ = r })
		h := ui.csrfMiddleware(next)

		token := "test-token-value"
		formData := url.Values{}
		formData.Set("csrf_token", token)
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
		h.ServeHTTP(rec, req)

		if !called {
			t.Error("expected next handler to be called with a valid CSRF token")
		}
	})
}

func TestAdminUI_OriginValidationMiddleware(t *testing.T) {
	const host = "127.0.0.1:8080"

	newHandler := func(ui *AdminUI) (http.Handler, *bool) {
		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; _ = w; _ = r })
		return ui.originValidationMiddleware(host, true /* useTLS */, next), &called
	}

	t.Run("GET without Origin passes (safe method)", func(t *testing.T) {
		ui, rec := setupTestAdminUI(t)
		h, called := newHandler(ui)
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Host = host
		h.ServeHTTP(rec, req)
		if !*called {
			t.Error("expected GET without Origin to pass")
		}
	})

	t.Run("POST without Origin or Referer is blocked", func(t *testing.T) {
		ui, rec := setupTestAdminUI(t)
		h, called := newHandler(ui)
		req := httptest.NewRequest(http.MethodPost, "/", http.NoBody)
		req.Host = host
		h.ServeHTTP(rec, req)
		if *called {
			t.Error("expected POST without Origin/Referer to be blocked")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("POST with matching Origin passes", func(t *testing.T) {
		ui, rec := setupTestAdminUI(t)
		h, called := newHandler(ui)
		req := httptest.NewRequest(http.MethodPost, "/", http.NoBody)
		req.Host = host
		req.Header.Set("Origin", "https://"+host)
		h.ServeHTTP(rec, req)
		if !*called {
			t.Error("expected POST with matching Origin to pass")
		}
	})

	t.Run("POST with mismatched Origin is blocked", func(t *testing.T) {
		ui, rec := setupTestAdminUI(t)
		h, called := newHandler(ui)
		req := httptest.NewRequest(http.MethodPost, "/", http.NoBody)
		req.Host = host
		req.Header.Set("Origin", "https://evil.example.com")
		h.ServeHTTP(rec, req)
		if *called {
			t.Error("expected POST with mismatched Origin to be blocked")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("null Origin with matching Referer passes", func(t *testing.T) {
		ui, rec := setupTestAdminUI(t)
		h, called := newHandler(ui)
		req := httptest.NewRequest(http.MethodPost, "/", http.NoBody)
		req.Host = host
		req.Header.Set("Origin", "null")
		req.Header.Set("Referer", "https://"+host+"/rules")
		h.ServeHTTP(rec, req)
		if !*called {
			t.Error("expected null Origin with matching Referer to pass")
		}
	})

	t.Run("null Origin without Referer is blocked", func(t *testing.T) {
		ui, rec := setupTestAdminUI(t)
		h, called := newHandler(ui)
		req := httptest.NewRequest(http.MethodPost, "/", http.NoBody)
		req.Host = host
		req.Header.Set("Origin", "null")
		h.ServeHTTP(rec, req)
		if *called {
			t.Error("expected null Origin without Referer to be blocked")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("cross-site non-navigate request is blocked even with a valid Origin", func(t *testing.T) {
		ui, rec := setupTestAdminUI(t)
		h, called := newHandler(ui)
		req := httptest.NewRequest(http.MethodPost, "/", http.NoBody)
		req.Host = host
		req.Header.Set("Origin", "https://"+host)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		h.ServeHTTP(rec, req)
		if *called {
			t.Error("expected cross-site non-navigate request to be blocked")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rec.Code)
		}
	})
}

func TestAdminUI_HostValidationMiddleware(t *testing.T) {
	const expectedHost = "127.0.0.1:8080"

	t.Run("matching host passes", func(t *testing.T) {
		ui, rec := setupTestAdminUI(t)
		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; _ = w; _ = r })
		h := ui.hostValidationMiddleware(expectedHost, next)

		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Host = expectedHost
		h.ServeHTTP(rec, req)
		if !called {
			t.Error("expected matching host to pass")
		}
	})

	t.Run("mismatched host is blocked", func(t *testing.T) {
		ui, rec := setupTestAdminUI(t)
		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; _ = w; _ = r })
		h := ui.hostValidationMiddleware(expectedHost, next)

		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Host = "evil.example.com"
		h.ServeHTTP(rec, req)
		if called {
			t.Error("expected mismatched host to be blocked")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rec.Code)
		}
	})
}

func TestAdminUI_FetchMetadataWhitelistMiddleware(t *testing.T) {
	mkHandler := func(ui *AdminUI) (http.Handler, *bool) {
		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; _ = w; _ = r })
		return ui.fetchMetadataWhitelistMiddleware(next), &called
	}

	t.Run("no Sec-Fetch-Site header passes (older browsers)", func(t *testing.T) {
		ui, rec := setupTestAdminUI(t)
		h, called := mkHandler(ui)
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		h.ServeHTTP(rec, req)
		if !*called {
			t.Error("expected request without Sec-Fetch-Site to pass")
		}
	})

	t.Run("same-origin passes", func(t *testing.T) {
		ui, rec := setupTestAdminUI(t)
		h, called := mkHandler(ui)
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		h.ServeHTTP(rec, req)
		if !*called {
			t.Error("expected same-origin request to pass")
		}
	})

	t.Run("cross-site navigate GET passes", func(t *testing.T) {
		ui, rec := setupTestAdminUI(t)
		h, called := mkHandler(ui)
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		h.ServeHTTP(rec, req)
		if !*called {
			t.Error("expected cross-site navigate GET to pass")
		}
	})

	t.Run("cross-site cors mode is blocked", func(t *testing.T) {
		ui, rec := setupTestAdminUI(t)
		h, called := mkHandler(ui)
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		h.ServeHTTP(rec, req)
		if *called {
			t.Error("expected cross-site cors request to be blocked")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rec.Code)
		}
	})
}

func TestAdminUI_SecurityHeadersMiddleware(t *testing.T) {
	ui, rec := setupTestAdminUI(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK); _ = r })
	h := ui.securityHeadersMiddleware(next)

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	h.ServeHTTP(rec, req)

	headers := rec.Header()
	if headers.Get("X-Frame-Options") != "DENY" {
		t.Errorf("expected X-Frame-Options=DENY, got %q", headers.Get("X-Frame-Options"))
	}
	if headers.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("expected X-Content-Type-Options=nosniff, got %q", headers.Get("X-Content-Type-Options"))
	}
	if headers.Get("Referrer-Policy") != "same-origin" {
		t.Errorf("expected Referrer-Policy=same-origin, got %q", headers.Get("Referrer-Policy"))
	}
	if headers.Get("Content-Security-Policy") == "" {
		t.Error("expected Content-Security-Policy header to be set")
	}
}
