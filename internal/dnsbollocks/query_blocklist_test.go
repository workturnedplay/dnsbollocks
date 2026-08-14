//go:build windows
// +build windows

package dnsbollocks

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// ── checkQueryBlocklist ──────────────────────────────────────────────────────

func TestCheckQueryBlocklist_NilStoreAndNilExternal_NeverBlocks(t *testing.T) {
	s := &Server{}
	// queryBlocklistStore and externalBlocklist are both zero-value here.
	reason, matchedID, blocked := s.checkQueryBlocklist("example.com")
	if blocked {
		t.Errorf("expected not blocked with nil store/external, got blocked (reason=%q id=%q)", reason, matchedID)
	}
}

func TestCheckQueryBlocklist_LocalBlockAlwaysWins(t *testing.T) {
	s := &Server{queryBlocklistStore: newRuleStore()}
	log := discardLogger()

	id, err := s.queryBlocklistStore.AddRule(queryBlockCategoryBlock, "ads.example.com", true, log)
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	reason, matchedID, blocked := s.checkQueryBlocklist("ads.example.com")
	if !blocked {
		t.Fatal("expected local block match to block the query")
	}
	if reason != queryBlockedLocalSTR {
		t.Errorf("reason = %q, want %q", reason, queryBlockedLocalSTR)
	}
	if matchedID != id {
		t.Errorf("matchedID = %q, want %q", matchedID, id)
	}
}

func TestCheckQueryBlocklist_LocalBlockDisabled_DoesNotBlock(t *testing.T) {
	s := &Server{queryBlocklistStore: newRuleStore()}
	log := discardLogger()

	if _, err := s.queryBlocklistStore.AddRule(queryBlockCategoryBlock, "ads.example.com", false, log); err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	_, _, blocked := s.checkQueryBlocklist("ads.example.com")
	if blocked {
		t.Error("expected a disabled local block rule to NOT block")
	}
}

func TestCheckQueryBlocklist_ExternalListedWithoutExcept_Blocks(t *testing.T) {
	s := &Server{queryBlocklistStore: newRuleStore()}
	s.externalBlocklist.Store(&ExternalHostsBlocklistSource{
		hosts:     map[string]struct{}{"tracker.example.com": {}},
		HostCount: 1,
	})

	reason, matchedID, blocked := s.checkQueryBlocklist("tracker.example.com")
	if !blocked {
		t.Fatal("expected external-source listing to block")
	}
	if reason != queryBlockedExternalSTR {
		t.Errorf("reason = %q, want %q", reason, queryBlockedExternalSTR)
	}
	if matchedID != "" {
		t.Errorf("matchedID = %q, want empty for external-source block", matchedID)
	}
}

func TestCheckQueryBlocklist_ExceptCancelsExternalBlockOnly(t *testing.T) {
	s := &Server{queryBlocklistStore: newRuleStore()}
	log := discardLogger()
	s.externalBlocklist.Store(&ExternalHostsBlocklistSource{
		hosts:     map[string]struct{}{"tracker.example.com": {}},
		HostCount: 1,
	})

	if _, err := s.queryBlocklistStore.AddRule(queryBlockCategoryExcept, "tracker.example.com", true, log); err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	_, _, blocked := s.checkQueryBlocklist("tracker.example.com")
	if blocked {
		t.Error("expected except rule to cancel the external-source block")
	}
}

func TestCheckQueryBlocklist_ExceptDoesNotCancelLocalBlock(t *testing.T) {
	// An except pattern must never override a local "block" pattern — see
	// checkQueryBlocklist's doc comment. Both patterns target the same
	// domain here; local block must still win.
	s := &Server{queryBlocklistStore: newRuleStore()}
	log := discardLogger()

	if _, err := s.queryBlocklistStore.AddRule(queryBlockCategoryBlock, "example.com", true, log); err != nil {
		t.Fatalf("AddRule(block) failed: %v", err)
	}
	if _, err := s.queryBlocklistStore.AddRule(queryBlockCategoryExcept, "example.com", true, log); err != nil {
		t.Fatalf("AddRule(except) failed: %v", err)
	}

	reason, _, blocked := s.checkQueryBlocklist("example.com")
	if !blocked || reason != queryBlockedLocalSTR {
		t.Errorf("expected local block to still win despite an except rule for the same domain; got blocked=%v reason=%q", blocked, reason)
	}
}

func TestCheckQueryBlocklist_ExceptWithoutExternalListing_NeverBlocksButHasNoOtherEffect(t *testing.T) {
	// An except pattern that doesn't correspond to any external-source entry
	// (or local block) is simply inert — it must not itself cause a block,
	// and it must not accidentally "allow" anything either (that's the
	// ordinary whitelist/default-policy decision's job, made afterward).
	s := &Server{queryBlocklistStore: newRuleStore()}
	log := discardLogger()

	if _, err := s.queryBlocklistStore.AddRule(queryBlockCategoryExcept, "harmless.example.com", true, log); err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	_, _, blocked := s.checkQueryBlocklist("harmless.example.com")
	if blocked {
		t.Error("expected an except rule with no corresponding block to never itself block")
	}
}

func TestCheckQueryBlocklist_WildcardLocalBlockMatches(t *testing.T) {
	s := &Server{queryBlocklistStore: newRuleStore()}
	log := discardLogger()

	if _, err := s.queryBlocklistStore.AddRule(queryBlockCategoryBlock, "*.tracker.example", true, log); err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	_, _, blocked := s.checkQueryBlocklist("cdn.tracker.example")
	if !blocked {
		t.Error("expected wildcard local block pattern to match a subdomain")
	}
}

// ── RuleStore.SetEnabledByID / setEnabledWhere ───────────────────────────────

func TestRuleStore_SetEnabledByID_TogglesRegardlessOfPattern(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	id, err := rs.AddRule(queryBlockCategoryBlock, "*.ads.example.com", true, log)
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	pattern, found, changed := rs.SetEnabledByID(queryBlockCategoryBlock, id, false, log)
	if !found || !changed {
		t.Fatalf("expected found=true changed=true, got found=%v changed=%v", found, changed)
	}
	if pattern != "*.ads.example.com" {
		t.Errorf("pattern = %q, want %q", pattern, "*.ads.example.com")
	}

	snap := rs.Snapshot()
	if snap[queryBlockCategoryBlock][0].Enabled {
		t.Error("expected rule to be disabled after SetEnabledByID(false)")
	}
}

func TestRuleStore_SetEnabledByID_NoOpWhenAlreadySet(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	id, err := rs.AddRule(queryBlockCategoryBlock, "example.com", true, log)
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	_, found, changed := rs.SetEnabledByID(queryBlockCategoryBlock, id, true, log)
	if !found {
		t.Fatal("expected found=true")
	}
	if changed {
		t.Error("expected changed=false when already in the desired state")
	}
}

func TestRuleStore_SetEnabledByID_NotFound(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	_, found, changed := rs.SetEnabledByID(queryBlockCategoryBlock, "nonexistent-id", false, log)
	if found || changed {
		t.Errorf("expected found=false changed=false for missing id, got found=%v changed=%v", found, changed)
	}
}

func TestRuleStore_SetEnabledByID_WrongTypeMisses(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	id, err := rs.AddRule(queryBlockCategoryBlock, "example.com", true, log)
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	// Correct ID but looked up under the wrong category/type bucket.
	_, found, _ := rs.SetEnabledByID(queryBlockCategoryExcept, id, false, log)
	if found {
		t.Error("expected SetEnabledByID to miss when id exists under a different type/category")
	}
}

// TestRuleStore_SetEnabled_And_SetEnabledByID_Consistent verifies both
// entry points into the shared setEnabledWhere implementation agree when
// targeting the very same rule.
func TestRuleStore_SetEnabled_And_SetEnabledByID_Consistent(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	id, err := rs.AddRule("A", "example.com", true, log)
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	foundByPattern, changedByPattern := rs.SetEnabled("A", "example.com", false, log)
	if !foundByPattern || !changedByPattern {
		t.Fatalf("SetEnabled: found=%v changed=%v", foundByPattern, changedByPattern)
	}

	// Flip back on via ID this time; must observe the disabled state set above.
	pattern, foundByID, changedByID := rs.SetEnabledByID("A", id, true, log)
	if !foundByID || !changedByID {
		t.Fatalf("SetEnabledByID: found=%v changed=%v", foundByID, changedByID)
	}
	if pattern != "example.com" {
		t.Errorf("pattern = %q, want %q", pattern, "example.com")
	}
}

// ── quickToggleExactRule ─────────────────────────────────────────────────────

func TestQuickToggleExactRule_UnblockCreatesNewRuleWhenNoneExists(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	msg, err := quickToggleExactRule(rs, "A", "example.com", "example.com", true, log, "whitelist")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg == "" {
		t.Error("expected non-empty success message")
	}

	snap := rs.Snapshot()
	if len(snap["A"]) != 1 || !snap["A"][0].Enabled || snap["A"][0].Pattern != "example.com" {
		t.Errorf("expected one new enabled rule for example.com, got %+v", snap["A"])
	}
}

func TestQuickToggleExactRule_UnblockReactivatesExistingDisabledRule(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	if _, err := rs.AddRule("A", "example.com", false, log); err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	msg, err := quickToggleExactRule(rs, "A", "example.com", "example.com", true, log, "whitelist")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg == "" {
		t.Error("expected non-empty success message")
	}

	snap := rs.Snapshot()
	if len(snap["A"]) != 1 || !snap["A"][0].Enabled {
		t.Errorf("expected the existing rule to be reactivated, got %+v", snap["A"])
	}
}

func TestQuickToggleExactRule_UnblockAlreadyActiveIsNoOpMessage(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	if _, err := rs.AddRule("A", "example.com", true, log); err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	msg, err := quickToggleExactRule(rs, "A", "example.com", "example.com", true, log, "whitelist")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg == "" {
		t.Error("expected a non-empty already-active message")
	}
	if rs.CountAll() != 1 {
		t.Errorf("expected no duplicate rule created, got CountAll=%d", rs.CountAll())
	}
}

func TestQuickToggleExactRule_ReblockNeverCreates(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	_, err := quickToggleExactRule(rs, "A", "example.com", "example.com", false, log, "whitelist")
	if err == nil {
		t.Fatal("expected an error when reblocking a domain with no existing rule")
	}
	if rs.CountAll() != 0 {
		t.Errorf("expected reblock to never create a rule, got CountAll=%d", rs.CountAll())
	}
}

func TestQuickToggleExactRule_ReblockPausesExistingRule(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	if _, err := rs.AddRule("A", "example.com", true, log); err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	msg, err := quickToggleExactRule(rs, "A", "example.com", "example.com", false, log, "whitelist")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg == "" {
		t.Error("expected non-empty success message")
	}

	snap := rs.Snapshot()
	if snap["A"][0].Enabled {
		t.Error("expected rule to be paused after reblock")
	}
}

func TestQuickToggleExactRule_ReblockAlreadyPausedIsNoOpMessage(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	if _, err := rs.AddRule("A", "example.com", false, log); err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	msg, err := quickToggleExactRule(rs, "A", "example.com", "example.com", false, log, "whitelist")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg == "" {
		t.Error("expected a non-empty already-paused message")
	}
}

func TestQuickToggleExactRule_ExceptCategoryEndToEnd(t *testing.T) {
	// Exercises the exact code path the /blocks "unblock_qb"/"reblock_qb"
	// actions use: queryBlockCategoryExcept as the "type".
	rs := newRuleStore()
	log := discardLogger()

	msg, err := quickToggleExactRule(rs, queryBlockCategoryExcept, "tracker.example.com", "tracker.example.com", true, log, "query blocklist: external-source except")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg == "" {
		t.Error("expected non-empty message")
	}

	snap := rs.Snapshot()
	if len(snap[queryBlockCategoryExcept]) != 1 || !snap[queryBlockCategoryExcept][0].Enabled {
		t.Errorf("expected one enabled except rule, got %+v", snap[queryBlockCategoryExcept])
	}

	// Now reblock it (pause the except, so the external block resumes).
	msg2, err2 := quickToggleExactRule(rs, queryBlockCategoryExcept, "tracker.example.com", "tracker.example.com", false, log, "query blocklist: external-source except")
	if err2 != nil {
		t.Fatalf("unexpected error: %v", err2)
	}
	if msg2 == "" {
		t.Error("expected non-empty message")
	}
	snap2 := rs.Snapshot()
	if snap2[queryBlockCategoryExcept][0].Enabled {
		t.Error("expected except rule to be paused after reblock_qb equivalent")
	}
}

// ── AdminUI.populateQueryBlocklistRowState ───────────────────────────────────

func TestPopulateQueryBlocklistRowState_NilStoresLeavesZeroValue(t *testing.T) {
	ui := &AdminUI{} // queryBlocklistStore and externalBlocklist both nil
	bq := &BlockedQuery{Domain: "example.com", Type: "A"}
	ui.populateQueryBlocklistRowState(bq)

	if bq.QueryBlocklistLocalBlocked || bq.QueryBlocklistExternalListed || bq.QueryBlocklistExternalExcepted || bq.QueryBlocklistLocalRuleID != "" {
		t.Errorf("expected all query-blocklist fields to remain zero-value, got %+v", bq)
	}
}

func TestPopulateQueryBlocklistRowState_LocalBlockedSetsIDAndFlag(t *testing.T) {
	log := discardLogger()
	store := newRuleStore()
	id, err := store.AddRule(queryBlockCategoryBlock, "ads.example.com", true, log)
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	ui := &AdminUI{queryBlocklistStore: store}
	bq := &BlockedQuery{Domain: "ads.example.com", Type: "A"}
	ui.populateQueryBlocklistRowState(bq)

	if !bq.QueryBlocklistLocalBlocked {
		t.Error("expected QueryBlocklistLocalBlocked=true")
	}
	if bq.QueryBlocklistLocalRuleID != id {
		t.Errorf("QueryBlocklistLocalRuleID = %q, want %q", bq.QueryBlocklistLocalRuleID, id)
	}
	if bq.QueryBlocklistExternalListed {
		t.Error("expected QueryBlocklistExternalListed=false")
	}
}

func TestPopulateQueryBlocklistRowState_ExternalListedWithAndWithoutExcept(t *testing.T) {
	log := discardLogger()
	store := newRuleStore()

	var extPtr atomic.Pointer[ExternalHostsBlocklistSource]
	extPtr.Store(&ExternalHostsBlocklistSource{
		hosts:     map[string]struct{}{"tracker.example.com": {}},
		HostCount: 1,
	})

	ui := &AdminUI{queryBlocklistStore: store, externalBlocklist: &extPtr}

	t.Run("listed, not yet excepted", func(t *testing.T) {
		bq := &BlockedQuery{Domain: "tracker.example.com", Type: "A"}
		ui.populateQueryBlocklistRowState(bq)
		if !bq.QueryBlocklistExternalListed {
			t.Error("expected QueryBlocklistExternalListed=true")
		}
		if bq.QueryBlocklistExternalExcepted {
			t.Error("expected QueryBlocklistExternalExcepted=false before adding an except rule")
		}
	})

	if _, err := store.AddRule(queryBlockCategoryExcept, "tracker.example.com", true, log); err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	t.Run("listed and excepted", func(t *testing.T) {
		bq := &BlockedQuery{Domain: "tracker.example.com", Type: "A"}
		ui.populateQueryBlocklistRowState(bq)
		if !bq.QueryBlocklistExternalListed {
			t.Error("expected QueryBlocklistExternalListed=true")
		}
		if !bq.QueryBlocklistExternalExcepted {
			t.Error("expected QueryBlocklistExternalExcepted=true after adding an except rule")
		}
	})
}

func TestPopulateQueryBlocklistRowState_NotListedAtAll(t *testing.T) {
	var extPtr atomic.Pointer[ExternalHostsBlocklistSource]
	extPtr.Store(&ExternalHostsBlocklistSource{hosts: map[string]struct{}{"other.example.com": {}}, HostCount: 1})

	ui := &AdminUI{queryBlocklistStore: newRuleStore(), externalBlocklist: &extPtr}
	bq := &BlockedQuery{Domain: "unrelated.example.com", Type: "A"}
	ui.populateQueryBlocklistRowState(bq)

	if bq.QueryBlocklistLocalBlocked || bq.QueryBlocklistExternalListed || bq.QueryBlocklistExternalExcepted {
		t.Errorf("expected no fields set for an unrelated domain, got %+v", bq)
	}
}

// ── ExternalHostsBlocklistSource.Contains ────────────────────────────────────

func TestExternalHostsBlocklistSource_Contains_NilSourceIsSafe(t *testing.T) {
	var src *ExternalHostsBlocklistSource
	if src.Contains("example.com") {
		t.Error("expected nil *ExternalHostsBlocklistSource.Contains to return false")
	}
}

func TestExternalHostsBlocklistSource_Contains_EmptyHostsIsSafe(t *testing.T) {
	src := &ExternalHostsBlocklistSource{}
	if src.Contains("example.com") {
		t.Error("expected empty hosts map to never match")
	}
}

// ── loadExternalQueryBlocklist ───────────────────────────────────────────────

// newExternalBlocklistTestServer builds a minimal *Server sufficient for
// loadExternalQueryBlocklist, which needs getConfig/getLogger/flushDNSCache
// (via s.rt and s.liveDNSCache) but nothing else.
func newExternalBlocklistTestServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	log := discardLogger()
	s := &Server{}
	s.liveConfigs.Store(&LiveConfigs{Resolved: &cfg, Raw: &cfg})
	s.rt = newTestRuntime(log)
	s.swapDNSCache(5, 100)
	return s
}

func TestLoadExternalQueryBlocklist_EmptyPathDisablesLayer(t *testing.T) {
	cfg := defaultConfig()
	cfg.QueryBlocklistExternalHostsFile = ""
	s := newExternalBlocklistTestServer(t, cfg)

	s.loadExternalQueryBlocklist()

	src := s.externalBlocklist.Load()
	if src == nil {
		t.Fatal("expected a non-nil (empty) source to be stored")
	}
	if src.Path != "" || src.HostCount != 0 {
		t.Errorf("expected empty/disabled source, got %+v", src)
	}
	if src.Contains("example.com") {
		t.Error("expected disabled layer to never match")
	}
}

func TestLoadExternalQueryBlocklist_MissingFileSetsLoadError(t *testing.T) {
	cfg := defaultConfig()
	cfg.QueryBlocklistExternalHostsFile = filepath.Join(t.TempDir(), "does-not-exist.txt")
	s := newExternalBlocklistTestServer(t, cfg)

	s.loadExternalQueryBlocklist()

	src := s.externalBlocklist.Load()
	if src == nil {
		t.Fatal("expected a non-nil source to be stored even on failure")
	}
	if src.LoadError == "" {
		t.Error("expected LoadError to be set for a missing file")
	}
	if src.HostCount != 0 {
		t.Errorf("expected HostCount=0 on load failure, got %d", src.HostCount)
	}
}

func TestLoadExternalQueryBlocklist_ParsesValidEntriesAndSkipsMalformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")
	// Mirrors the conventional StevenBlack / system hosts preamble that
	// operators previously had to comment out by hand: only 0.0.0.0/::
	// lines must become blocks; loopback/broadcast mappings must not.
	content := "" +
		"# comment line\n" +
		"0.0.0.0 ads.example.com\n" +
		"0.0.0.0 tracker.example.com alias.example.com # trailing comment\n" +
		":: blocked-v6.example.com\n" +
		"\n" +
		"not-an-ip a-malformed-line.example.com\n" +
		"justonefield\n" +
		"192.168.1.1 nonstandard-ip.example.com\n" +
		"127.0.0.1 localhost\n" +
		"127.0.0.1 localhost.localdomain\n" +
		"127.0.0.1 local\n" +
		"255.255.255.255 broadcasthost\n" +
		"::1 localhost\n" +
		"::1 ip6-localhost\n" +
		"::1 ip6-loopback\n" +
		"fe80::1%lo0 localhost\n" + // invalid IP token (zone id) → malformed
		"ff00::0 ip6-localnet\n" +
		"ff02::1 ip6-allnodes\n" +
		"0.0.0.0 0.0.0.0\n" // unspecified IP + hostname "0.0.0.0" — still a valid block entry
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test hosts file: %v", err)
	}

	cfg := defaultConfig()
	cfg.QueryBlocklistExternalHostsFile = path
	s := newExternalBlocklistTestServer(t, cfg)

	s.loadExternalQueryBlocklist()

	src := s.externalBlocklist.Load()
	if src == nil {
		t.Fatal("expected non-nil source")
	}
	if src.LoadError != "" {
		t.Errorf("expected no load error, got %q", src.LoadError)
	}

	// Only unspecified-IP lines (0.0.0.0 / ::) contribute to the block set.
	for _, host := range []string{"ads.example.com", "tracker.example.com", "alias.example.com", "blocked-v6.example.com", "0.0.0.0"} {
		if !src.Contains(host) {
			t.Errorf("expected %q to be present in external blocklist", host)
		}
	}
	// Non-unspecified mapping IPs are deliberately ignored for blocking so
	// ordinary hosts-file loopback/broadcast entries never false-positive.
	for _, host := range []string{
		"nonstandard-ip.example.com",
		"localhost",
		"localhost.localdomain",
		"local",
		"broadcasthost",
		"ip6-localhost",
		"ip6-loopback",
		"ip6-localnet",
		"ip6-allnodes",
		"a-malformed-line.example.com",
	} {
		if src.Contains(host) {
			t.Errorf("expected %q to be ignored for blocking (non-unspecified or malformed), not present", host)
		}
	}

	// "not-an-ip ...", "justonefield", and "fe80::1%lo0 ..." (zone id → ParseIP nil)
	if src.MalformedLines != 3 {
		t.Errorf("MalformedLines = %d, want 3", src.MalformedLines)
	}
	// 192.168.1.1, 127.0.0.1×3, 255.255.255.255, ::1×3, ff00::0, ff02::1
	if src.NonStandardIPWarnings != 10 {
		t.Errorf("NonStandardIPWarnings = %d, want 10", src.NonStandardIPWarnings)
	}
	if src.HostCount != 5 {
		t.Errorf("HostCount = %d, want 5 (only the unspecified-IP lines)", src.HostCount)
	}
	if src.HostCount != len(src.hosts) {
		t.Errorf("HostCount = %d, want len(hosts)=%d", src.HostCount, len(src.hosts))
	}
}

func TestLoadExternalQueryBlocklist_NormalizesAndPunycodeEncodesHostnames(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")
	// Uppercase + trailing dot to exercise NormalizeDomain, and an IDN label
	// to exercise punycodeEncodePattern.
	content := "0.0.0.0 Ads.Example.com.\n0.0.0.0 café.example.com\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test hosts file: %v", err)
	}

	cfg := defaultConfig()
	cfg.QueryBlocklistExternalHostsFile = path
	s := newExternalBlocklistTestServer(t, cfg)

	s.loadExternalQueryBlocklist()

	src := s.externalBlocklist.Load()
	if !src.Contains("ads.example.com") {
		t.Error("expected uppercase+trailing-dot hostname to be normalized to lowercase with no trailing dot")
	}
	encoded, _, err := punycodeEncodePattern("café.example.com")
	if err != nil {
		t.Fatalf("punycodeEncodePattern failed: %v", err)
	}
	if !src.Contains(encoded) {
		t.Errorf("expected IDN hostname to be stored as punycode %q", encoded)
	}
}

func TestLoadExternalQueryBlocklist_ReloadReplacesPreviousSnapshotWholesale(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")

	if err := os.WriteFile(path, []byte("0.0.0.0 first.example.com\n"), 0600); err != nil {
		t.Fatalf("failed to write test hosts file: %v", err)
	}
	cfg := defaultConfig()
	cfg.QueryBlocklistExternalHostsFile = path
	s := newExternalBlocklistTestServer(t, cfg)

	s.loadExternalQueryBlocklist()
	if !s.externalBlocklist.Load().Contains("first.example.com") {
		t.Fatal("expected first.example.com present after initial load")
	}

	// Simulate an upgraded/replaced blocklist file (e.g. a newer StevenBlack
	// Hosts release) — old entries must be gone entirely, not merged.
	if err := os.WriteFile(path, []byte("0.0.0.0 second.example.com\n"), 0600); err != nil {
		t.Fatalf("failed to rewrite test hosts file: %v", err)
	}
	s.loadExternalQueryBlocklist()

	src := s.externalBlocklist.Load()
	if src.Contains("first.example.com") {
		t.Error("expected the old snapshot's entries to be fully replaced, not merged")
	}
	if !src.Contains("second.example.com") {
		t.Error("expected the new snapshot's entries to be present")
	}
}

// ── loadQueryBlocklist / saveQueryBlocklist (file round-trip) ───────────────

func TestLoadSaveQueryBlocklist_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}
	defer func() {
		if err2 := os.Chdir(origWD); err2 != nil {
			t.Errorf("failed to restore working directory: %v", err2)
		}
	}()

	cfg := defaultConfig()
	cfg.QueryBlocklistFile = "query_blocklist_roundtrip_test.json"
	s := &Server{queryBlocklistStore: newRuleStore()}
	s.liveConfigs.Store(&LiveConfigs{Resolved: &cfg, Raw: &cfg})
	s.rt = newTestRuntime(discardLogger())
	s.swapDNSCache(5, 100)

	log := discardLogger()
	if _, err := s.queryBlocklistStore.AddRule(queryBlockCategoryBlock, "ads.example.com", true, log); err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}
	if _, err := s.queryBlocklistStore.AddRule(queryBlockCategoryExcept, "safe.ads.example.com", true, log); err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	if err := s.saveQueryBlocklist(); err != nil {
		t.Fatalf("saveQueryBlocklist failed: %v", err)
	}

	// Fresh store + reload from disk.
	s.queryBlocklistStore = newRuleStore()
	// tableMutationMu isn't held here deliberately: this test runs single-
	// threaded and loadQueryBlocklist's locking requirement exists only to
	// guard against concurrent Reload()/WebUI mutation, neither of which is
	// present in this test.
	if err := s.loadQueryBlocklist(); err != nil {
		t.Fatalf("loadQueryBlocklist failed: %v", err)
	}

	snap := s.queryBlocklistStore.Snapshot()
	if len(snap[queryBlockCategoryBlock]) != 1 || snap[queryBlockCategoryBlock][0].Pattern != "ads.example.com" {
		t.Errorf("block category after reload = %+v", snap[queryBlockCategoryBlock])
	}
	if len(snap[queryBlockCategoryExcept]) != 1 || snap[queryBlockCategoryExcept][0].Pattern != "safe.ads.example.com" {
		t.Errorf("except category after reload = %+v", snap[queryBlockCategoryExcept])
	}
}

// ── processQueryBlockChange: toggle via SetEnabledByID path ─────────────────

func TestProcessQueryBlockChange_ToggleDisablesByID(t *testing.T) {
	ui, _ := setupTestAdminUI(t)
	log := discardLogger()

	id, err := ui.queryBlocklistStore.AddRule(queryBlockCategoryBlock, "ads.example.com", true, log)
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	status, err2 := ui.processQueryBlockChange(map[string]string{
		"toggle":   "1",
		"id":       id,
		"category": queryBlockCategoryBlock,
	}, func(string) {})
	if err2 != nil {
		t.Fatalf("processQueryBlockChange failed: %v", err2)
	}
	if status != 200 {
		t.Errorf("status = %d, want 200", status)
	}

	snap := ui.queryBlocklistStore.Snapshot()
	if snap[queryBlockCategoryBlock][0].Enabled {
		t.Error("expected rule to be disabled after toggle")
	}
}

func TestProcessQueryBlockChange_ToggleNotFound(t *testing.T) {
	ui, _ := setupTestAdminUI(t)

	status, err := ui.processQueryBlockChange(map[string]string{
		"toggle":   "1",
		"id":       "nonexistent-id",
		"category": queryBlockCategoryBlock,
	}, func(string) {})
	if err == nil {
		t.Fatal("expected error for nonexistent id")
	}
	if status != 404 {
		t.Errorf("status = %d, want 404", status)
	}
}

func TestProcessQueryBlockChange_AddAndDelete(t *testing.T) {
	ui, _ := setupTestAdminUI(t)

	status, err := ui.processQueryBlockChange(map[string]string{
		"category": queryBlockCategoryBlock,
		"pattern":  "new-ads.example.com",
		"enabled":  "true",
	}, func(string) {})
	if err != nil {
		t.Fatalf("add failed: %v", err)
	}
	if status != 200 {
		t.Errorf("status = %d, want 200", status)
	}

	snap := ui.queryBlocklistStore.Snapshot()
	if len(snap[queryBlockCategoryBlock]) != 1 {
		t.Fatalf("expected 1 block rule, got %d", len(snap[queryBlockCategoryBlock]))
	}
	id := snap[queryBlockCategoryBlock][0].ID

	status2, err2 := ui.processQueryBlockChange(map[string]string{
		"delete":   "1",
		"id":       id,
		"category": queryBlockCategoryBlock,
	}, func(string) {})
	if err2 != nil {
		t.Fatalf("delete failed: %v", err2)
	}
	if status2 != 200 {
		t.Errorf("status = %d, want 200", status2)
	}
	if ui.queryBlocklistStore.CountAll() != 0 {
		t.Error("expected rule to be deleted")
	}
}

func TestProcessQueryBlockChange_InvalidCategoryRejected(t *testing.T) {
	ui, _ := setupTestAdminUI(t)

	_, err := ui.processQueryBlockChange(map[string]string{
		"category": "not-a-real-category",
		"pattern":  "example.com",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected error for invalid category")
	}
}

func TestQueryBlocklistVersionToken_NilStoreReturnsZero(t *testing.T) {
	ui := &AdminUI{}
	if got := ui.queryBlocklistVersionToken(); got != "0" {
		t.Errorf("expected \"0\" for nil queryBlocklistStore, got %q", got)
	}
}

func TestProcessQueryBlockChange_EditUpdatesPatternAndEnabled(t *testing.T) {
	ui, _ := setupTestAdminUI(t)
	log := discardLogger()

	id, err := ui.queryBlocklistStore.AddRule(queryBlockCategoryBlock, "old.example.com", true, log)
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	status, err2 := ui.processQueryBlockChange(map[string]string{
		"edit":     "1",
		"id":       id,
		"category": queryBlockCategoryBlock,
		"pattern":  "new.example.com",
		"enabled":  "false",
	}, func(string) {})
	if err2 != nil {
		t.Fatalf("edit failed: %v", err2)
	}
	if status != 200 {
		t.Errorf("status = %d, want 200", status)
	}

	snap := ui.queryBlocklistStore.Snapshot()
	if len(snap[queryBlockCategoryBlock]) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(snap[queryBlockCategoryBlock]))
	}
	rule := snap[queryBlockCategoryBlock][0]
	if rule.Pattern != "new.example.com" {
		t.Errorf("pattern = %q, want %q", rule.Pattern, "new.example.com")
	}
	if rule.Enabled {
		t.Error("expected rule to be disabled after edit")
	}
	if rule.ID != id {
		t.Errorf("expected ID to be preserved (%q), got %q", id, rule.ID)
	}
}

func TestProcessQueryBlockChange_EditMissingIDRejected(t *testing.T) {
	ui, _ := setupTestAdminUI(t)

	_, err := ui.processQueryBlockChange(map[string]string{
		"edit":     "1",
		"category": queryBlockCategoryBlock,
		"pattern":  "example.com",
		"enabled":  "true",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected error when editing without an id")
	}
}

func TestProcessQueryBlockChange_EditCrossCategoryMove(t *testing.T) {
	ui, _ := setupTestAdminUI(t)
	log := discardLogger()

	id, err := ui.queryBlocklistStore.AddRule(queryBlockCategoryBlock, "move-me.example.com", true, log)
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	status, err2 := ui.processQueryBlockChange(map[string]string{
		"edit":     "1",
		"id":       id,
		"category": queryBlockCategoryExcept,
		"pattern":  "move-me.example.com",
		"enabled":  "true",
	}, func(string) {})
	if err2 != nil {
		t.Fatalf("edit failed: %v", err2)
	}
	if status != 200 {
		t.Errorf("status = %d, want 200", status)
	}

	snap := ui.queryBlocklistStore.Snapshot()
	if len(snap[queryBlockCategoryBlock]) != 0 {
		t.Errorf("expected block category to be empty after move, got %d entries", len(snap[queryBlockCategoryBlock]))
	}
	if len(snap[queryBlockCategoryExcept]) != 1 || snap[queryBlockCategoryExcept][0].ID != id {
		t.Errorf("expected moved rule to be present in except category, got %+v", snap[queryBlockCategoryExcept])
	}
}

func TestApplyTablesHandler_QueryBlocklistBatchAppliesChangesAndVersion(t *testing.T) {
	ui, rec := setupTestAdminUI(t)

	type batchChange struct {
		URL      string            `json:"url"`
		Fields   map[string]string `json:"fields"`
		ClientID string            `json:"client_id"`
	}
	type batchVersions struct {
		QueryBlocklist string `json:"query_blocklist"`
	}
	type batchRequest struct {
		Versions batchVersions `json:"versions"`
		Changes  []batchChange `json:"changes"`
	}

	reqBody := batchRequest{
		Versions: batchVersions{QueryBlocklist: ui.queryBlocklistVersionToken()},
		Changes: []batchChange{
			{
				URL:      "/query-blocklist",
				ClientID: "c1",
				Fields: map[string]string{
					"category": queryBlockCategoryBlock,
					"pattern":  "batch-added.example.com",
					"enabled":  "true",
				},
			},
		},
	}
	payloadBytes, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("marshal payload failed: %v", err)
	}

	form := url.Values{}
	form.Set("payload", string(payloadBytes))

	httpReq := httptest.NewRequest(http.MethodPost, "/apply-tables", strings.NewReader(form.Encode()))
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ui.applyTablesHandler(rec, httpReq)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	snap := ui.queryBlocklistStore.Snapshot()
	found := false
	for _, r := range snap[queryBlockCategoryBlock] {
		if r.Pattern == "batch-added.example.com" {
			found = true
		}
	}
	if !found {
		t.Error("expected batch-added.example.com to be present in query blocklist after batch apply")
	}
}

func TestApplyTablesHandler_QueryBlocklistBatchStaleVersionRejected(t *testing.T) {
	ui, rec := setupTestAdminUI(t)

	type batchChange struct {
		URL      string            `json:"url"`
		Fields   map[string]string `json:"fields"`
		ClientID string            `json:"client_id"`
	}
	type batchVersions struct {
		QueryBlocklist string `json:"query_blocklist"`
	}
	type batchRequest struct {
		Versions batchVersions `json:"versions"`
		Changes  []batchChange `json:"changes"`
	}

	reqBody := batchRequest{
		Versions: batchVersions{QueryBlocklist: "stale-version-token"},
		Changes: []batchChange{
			{
				URL:      "/query-blocklist",
				ClientID: "c1",
				Fields: map[string]string{
					"category": queryBlockCategoryBlock,
					"pattern":  "should-not-apply.example.com",
					"enabled":  "true",
				},
			},
		},
	}
	payloadBytes, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("marshal payload failed: %v", err)
	}

	form := url.Values{}
	form.Set("payload", string(payloadBytes))

	httpReq := httptest.NewRequest(http.MethodPost, "/apply-tables", strings.NewReader(form.Encode()))
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ui.applyTablesHandler(rec, httpReq)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}

	snap := ui.queryBlocklistStore.Snapshot()
	for _, r := range snap[queryBlockCategoryBlock] {
		if r.Pattern == "should-not-apply.example.com" {
			t.Error("expected stale-version batch to be rejected, but change was applied")
		}
	}
}
