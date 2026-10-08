//go:build windows
// +build windows

package dnsbollocks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const (
	steamP2PWildcardPattern = "p2p-????.discovery.steamserver.net"
	steamP2PFRA1Domain      = "p2p-fra1.discovery.steamserver.net"
)

// Same layout formatModifiedAt produces for the /rules "Last Modified" column.
var blockTimeDisplayRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$`)

func TestMatchPattern_QuestionMarkWildcard_SteamP2PDiscovery(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{"fra1 (exactly 4 chars) matches", "p2p-fra1.discovery.steamserver.net", true},
		{"ams4 (exactly 4 chars) matches", "p2p-ams4.discovery.steamserver.net", true},
		{"3 chars does not match", "p2p-fra.discovery.steamserver.net", false},
		{"5 chars does not match", "p2p-fra12.discovery.steamserver.net", false},
		{"? never consumes a dot", "p2p-fr.1.discovery.steamserver.net", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchPattern(steamP2PWildcardPattern, tt.domain); got != tt.want {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", steamP2PWildcardPattern, tt.domain, got, tt.want)
			}
		})
	}
}

func TestRuleStore_SteamP2PWildcardRule_TypeScopedAndNotExact(t *testing.T) {
	rs := newRuleStore()
	mustAdd(t, rs, "A", steamP2PWildcardPattern, true)

	if _, ok := rs.MatchForType("A", steamP2PFRA1Domain); !ok {
		t.Error("expected the A wildcard rule to match p2p-fra1")
	}
	// A rule is per record type: an A rule must not allow AAAA queries.
	if _, ok := rs.MatchForType("AAAA", steamP2PFRA1Domain); ok {
		t.Error("an A rule must not match an AAAA query")
	}
	// Documents why /blocks shows an "Unblock" button even though a wildcard
	// rule already resolves the domain (see buildIsUnblockedPredicate).
	if rs.HasExactEnabledPattern("A", steamP2PFRA1Domain) {
		t.Error("a wildcard rule must not count as an exact-pattern rule for the specific domain")
	}
}

func TestHandleDNSQuery_SteamP2PWildcardRule_ForwardsAAndDoesNotRecordBlocks(t *testing.T) {
	q := aQuery(steamP2PFRA1Domain)
	fwd := fixedFwd(upstreamAResp(q, "8.8.8.8"), UpstreamState{Strategy: "fastest"})
	s := newQueryTestServer(t, defaultConfig(), fwd)
	addWhitelistRule(t, s, "A", steamP2PWildcardPattern)

	resp := s.handleDNSQuery(context.Background(), aQuery(steamP2PFRA1Domain), testClient)
	if resp == nil {
		t.Fatal("want non-nil response, got nil")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("A rcode: want Success, got %d", resp.Rcode)
	}
	if ips := extractIPs(resp); len(ips) != 1 || ips[0] != "8.8.8.8" {
		t.Errorf("A IPs: want [8.8.8.8], got %v", ips)
	}
	if fwd.CallCount() != 1 {
		t.Errorf("forwarder call count: want 1, got %d", fwd.CallCount())
	}

	// AAAA has no rule of its own, so it is blocked (counted in stats), but
	// since an A rule allows the domain the block is intentionally not
	// recorded in the recent-blocks list (see shouldSkipAAAARecentBlockEntry).
	respAAAA := s.handleDNSQuery(context.Background(), aaaaQuery(steamP2PFRA1Domain), testClient)
	if respAAAA == nil {
		t.Fatal("want non-nil AAAA response, got nil")
	}
	if respAAAA.Rcode != dns.RcodeSuccess || len(respAAAA.Answer) != 0 {
		t.Errorf("AAAA: want empty NOERROR, got rcode=%d answers=%d", respAAAA.Rcode, len(respAAAA.Answer))
	}
	if n := s.blockedQueries.Value(); n != 1 {
		t.Errorf("blockedQueries: want 1 (the AAAA), got %d", n)
	}
	if snap := s.recentBlocks.Snapshot(func(_, _ string) bool { return false }); len(snap) != 0 {
		t.Errorf("recentBlocks: want empty, got %d entries: %+v", len(snap), snap)
	}
}

// Establishes the timeline an operator needs when comparing /blocks against a
// rule's Last Modified: the recorded block time precedes the rule's timestamp,
// adding the rule (plus its cache invalidation) makes the same query resolve,
// and that resolution does NOT create a newer block entry.
func TestHandleDNSQuery_BlockThenAddWildcardRule_TimelineAndCacheInvalidation(t *testing.T) {
	q := aQuery(steamP2PFRA1Domain)
	fwd := fixedFwd(upstreamAResp(q, "8.8.8.8"), UpstreamState{Strategy: "fastest"})
	s := newQueryTestServer(t, defaultConfig(), fwd)

	resp := s.handleDNSQuery(context.Background(), aQuery(steamP2PFRA1Domain), testClient)
	if resp == nil || resp.Rcode != dns.RcodeNameError {
		t.Fatalf("first query: want NXDOMAIN, got %+v", resp)
	}
	snap := s.recentBlocks.Snapshot(func(_, _ string) bool { return false })
	if len(snap) != 1 {
		t.Fatalf("recentBlocks: want 1 entry, got %d", len(snap))
	}
	blockedAt := snap[0].Time

	time.Sleep(20 * time.Millisecond)
	addWhitelistRule(t, s, "A", steamP2PWildcardPattern)
	ruleModifiedAt := s.ruleStore.Snapshot()["A"][0].ModifiedAt
	if !ruleModifiedAt.After(blockedAt) {
		t.Fatalf("rule ModifiedAt (%v) should be after the recorded block time (%v)", ruleModifiedAt, blockedAt)
	}

	// Without invalidation the earlier block is still served from the DNS
	// cache (this is why every WebUI rule mutation invalidates by pattern).
	resp = s.handleDNSQuery(context.Background(), aQuery(steamP2PFRA1Domain), testClient)
	if resp == nil || resp.Rcode != dns.RcodeNameError {
		t.Fatalf("stale-cache query: want cached NXDOMAIN, got %+v", resp)
	}
	if fwd.CallCount() != 0 {
		t.Fatalf("forwarder must not be called while the block is cached, got %d calls", fwd.CallCount())
	}

	s.invalidateCacheForPattern(steamP2PWildcardPattern)

	resp = s.handleDNSQuery(context.Background(), aQuery(steamP2PFRA1Domain), testClient)
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("post-invalidation query: want Success, got %+v", resp)
	}
	if fwd.CallCount() != 1 {
		t.Errorf("forwarder call count: want 1, got %d", fwd.CallCount())
	}

	snap2 := s.recentBlocks.Snapshot(func(_, _ string) bool { return false })
	if len(snap2) != 1 {
		t.Fatalf("recentBlocks: want still 1 entry, got %d", len(snap2))
	}
	if !snap2[0].Time.Equal(blockedAt) {
		t.Errorf("block time must be unchanged by the later allowed query: was %v, now %v", blockedAt, snap2[0].Time)
	}
}

func TestGetRecentBlocksCopy_PopulatesTimeDisplayAndLowPriorityFlag(t *testing.T) {
	ui, _ := setupTestAdminUI(t)
	ui.recentBlocks.Record("plain.example.com", "A", 10)
	ui.recentBlocks.Record("v6.example.com", "AAAA", 10)
	ui.recentBlocks.Record("svcb.example.com", "HTTPS", 10)
	ui.recentBlocks.Record("mail.example.com", "MX", 10)

	wantLow := map[string]bool{"A": false, "AAAA": true, "HTTPS": true, "MX": false}

	blocks := ui.getRecentBlocksCopy()
	if len(blocks) != 4 {
		t.Fatalf("want 4 blocks, got %d", len(blocks))
	}
	for _, b := range blocks {
		if !blockTimeDisplayRE.MatchString(b.TimeDisplay) {
			t.Errorf("%s (%s): TimeDisplay %q does not match the /rules timestamp layout", b.Domain, b.Type, b.TimeDisplay)
		}
		if b.TimeDisplay != formatModifiedAt(b.Time) {
			t.Errorf("%s (%s): TimeDisplay %q != formatModifiedAt(Time) %q", b.Domain, b.Type, b.TimeDisplay, formatModifiedAt(b.Time))
		}
		if b.IsLowPriorityType != wantLow[b.Type] {
			t.Errorf("%s (%s): IsLowPriorityType = %v, want %v", b.Domain, b.Type, b.IsLowPriorityType, wantLow[b.Type])
		}
	}
}

func TestGetRecentAllowedCopy_PopulatesTimeDisplayAndLowPriorityFlag(t *testing.T) {
	ui, _ := setupTestAdminUI(t)
	ui.recentAllowed = newRecentBlocksTracker()
	ui.recentAllowed.Record("plain.example.com", "A", 10)
	ui.recentAllowed.Record("v6.example.com", "AAAA", 10)

	for _, a := range ui.getRecentAllowedCopy() {
		if !blockTimeDisplayRE.MatchString(a.TimeDisplay) {
			t.Errorf("%s (%s): TimeDisplay %q does not match the /rules timestamp layout", a.Domain, a.Type, a.TimeDisplay)
		}
		if want := a.Type == "AAAA"; a.IsLowPriorityType != want {
			t.Errorf("%s (%s): IsLowPriorityType = %v, want %v", a.Domain, a.Type, a.IsLowPriorityType, want)
		}
	}
}

// Renders the real ui.html "blocks" template end-to-end: the timestamp must
// be present for every entry and only the AAAA/HTTPS entries get the dim class.
func TestBlocksHandler_RendersTimestampAndDimClass(t *testing.T) {
	ui, rec := setupTestAdminUI(t)
	ui.uiTemplates = uiTemplates0
	ui.recentBlocks.Record("plain.example.com", "A", 10)
	ui.recentBlocks.Record("v6.example.com", "AAAA", 10)

	req := httptest.NewRequest(http.MethodGet, "/blocks", http.NoBody)
	ui.blocksHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	for _, b := range ui.getRecentBlocksCopy() {
		if !strings.Contains(body, b.TimeDisplay) {
			t.Errorf("rendered page is missing the timestamp %q for %s (%s)", b.TimeDisplay, b.Domain, b.Type)
		}
	}
	if n := strings.Count(body, "block-entry-dim"); n != 1 {
		t.Errorf("want exactly 1 dimmed entry (the AAAA one), got %d", n)
	}
}

// assertCopyButtonsRendered checks that exactly len(wantTexts) copy buttons
// were rendered and that each one carries its host in data-copy-text.
func assertCopyButtonsRendered(t *testing.T, body string, wantTexts ...string) {
	t.Helper()
	if n := strings.Count(body, `class="btn-copy js-copy-btn"`); n != len(wantTexts) {
		t.Errorf("want %d copy buttons, got %d", len(wantTexts), n)
	}
	for _, text := range wantTexts {
		if !strings.Contains(body, `data-copy-text="`+text+`"`) {
			t.Errorf("missing copy button carrying data-copy-text=%q", text)
		}
	}
}

func TestBlocksHandler_RendersCopyButtonPerEntry(t *testing.T) {
	ui, rec := setupTestAdminUI(t)
	ui.uiTemplates = uiTemplates0
	ui.recentBlocks.Record("plain.example.com", "A", 10)
	ui.recentBlocks.Record("xn--caf-dma.com", "A", 10) // IDN: the Unicode display form is what gets copied

	ui.blocksHandler(rec, httptest.NewRequest(http.MethodGet, "/blocks", http.NoBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	assertCopyButtonsRendered(t, rec.Body.String(), "plain.example.com", "café.com")
}

func TestAllowsHandler_RendersCopyButtonPerEntry(t *testing.T) {
	ui, rec := setupTestAdminUI(t)
	ui.uiTemplates = uiTemplates0
	ui.recentAllowed = newRecentBlocksTracker()
	ui.recentAllowed.Record("allowed.example.com", "A", 10)

	ui.allowsHandler(rec, httptest.NewRequest(http.MethodGet, "/allows", http.NoBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	assertCopyButtonsRendered(t, rec.Body.String(), "allowed.example.com")
}
