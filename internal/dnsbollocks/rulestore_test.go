//go:build windows
// +build windows

package dnsbollocks

import (
	"io"
	"log/slog"
	"strings"
	"testing"
)

// discardLogger returns a logger that throws everything away, keeping test
// output clean while still satisfying the *slog.Logger parameters that
// RuleStore methods require.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ── helpers ──────────────────────────────────────────────────────────────────

// mustAdd calls AddRule and fatals if it returns an error.
func mustAdd(t *testing.T, rs *RuleStore, typ, pattern string, enabled bool) string {
	t.Helper()
	id, err := rs.AddRule(typ, pattern, enabled, discardLogger())
	if err != nil {
		t.Fatalf("AddRule(%q, %q) unexpected error: %v", typ, pattern, err)
	}
	return id
}

// ── AddRule ──────────────────────────────────────────────────────────────────

func TestRuleStore_AddRule_Basic(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	id, err := rs.AddRule("A", "example.com", true, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id == "" {
		t.Fatal("expected non-empty id")
	}
	if rs.CountAll() != 1 {
		t.Errorf("expected CountAll=1, got %d", rs.CountAll())
	}
}

func TestRuleStore_AddRule_DuplicatePatternSameType(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	mustAdd(t, rs, "A", "example.com", true)

	_, err := rs.AddRule("A", "example.com", true, log)
	if err == nil {
		t.Fatal("expected error for duplicate pattern, got nil")
	}
	// Count must not have grown.
	if rs.CountAll() != 1 {
		t.Errorf("expected CountAll=1 after rejected add, got %d", rs.CountAll())
	}
}

func TestRuleStore_AddRule_SamePatternDifferentType_IsAllowed(t *testing.T) {
	rs := newRuleStore()

	mustAdd(t, rs, "A", "example.com", true)
	mustAdd(t, rs, "AAAA", "example.com", true) // same pattern, different type — OK

	if rs.CountAll() != 2 {
		t.Errorf("expected CountAll=2, got %d", rs.CountAll())
	}
}

func TestRuleStore_AddRule_IDsAreUnique(t *testing.T) {
	rs := newRuleStore()

	seen := make(map[string]struct{})
	for i := range 50 {
		pattern := strings.Repeat("a", i+1) + ".com"
		id := mustAdd(t, rs, "A", pattern, true)
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate ID generated: %q", id)
		}
		seen[id] = struct{}{}
	}
}

func TestRuleStore_AddRule_PrependOrder(t *testing.T) {
	// AddRule prepends, so the most recently added rule is at index 0.
	rs := newRuleStore()

	mustAdd(t, rs, "A", "first.com", true)
	mustAdd(t, rs, "A", "second.com", true)

	snap := rs.Snapshot()
	rules := snap["A"]
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].Pattern != "second.com" {
		t.Errorf("expected second.com at index 0 (prepend), got %q", rules[0].Pattern)
	}
	if rules[1].Pattern != "first.com" {
		t.Errorf("expected first.com at index 1, got %q", rules[1].Pattern)
	}
}

// ── DeleteRule ────────────────────────────────────────────────────────────────

func TestRuleStore_DeleteRule_Success(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	id := mustAdd(t, rs, "A", "delete-me.com", true)

	pattern, err := rs.DeleteRule("A", id, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pattern != "delete-me.com" {
		t.Errorf("expected returned pattern %q, got %q", "delete-me.com", pattern)
	}
	if rs.CountAll() != 0 {
		t.Errorf("expected CountAll=0 after delete, got %d", rs.CountAll())
	}
}

func TestRuleStore_DeleteRule_NotFound_BadID(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	mustAdd(t, rs, "A", "example.com", true)

	_, err := rs.DeleteRule("A", "nonexistent-id", log)
	if err == nil {
		t.Fatal("expected error for missing id, got nil")
	}
	if rs.CountAll() != 1 {
		t.Errorf("expected CountAll=1 (delete failed), got %d", rs.CountAll())
	}
}

func TestRuleStore_DeleteRule_NotFound_WrongType(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	id := mustAdd(t, rs, "A", "example.com", true)

	// Correct ID but wrong type bucket.
	_, err := rs.DeleteRule("AAAA", id, log)
	if err == nil {
		t.Fatal("expected error when type doesn't match, got nil")
	}
}

func TestRuleStore_DeleteRule_LeavesOtherRulesIntact(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	idA := mustAdd(t, rs, "A", "alpha.com", true)
	mustAdd(t, rs, "A", "beta.com", true)

	_, err := rs.DeleteRule("A", idA, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rs.CountAll() != 1 {
		t.Errorf("expected CountAll=1, got %d", rs.CountAll())
	}
	snap := rs.Snapshot()
	if snap["A"][0].Pattern != "beta.com" {
		t.Errorf("expected beta.com to remain, got %q", snap["A"][0].Pattern)
	}
}

// ── UpdateRule ────────────────────────────────────────────────────────────────

func TestRuleStore_UpdateRule_SameType(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	id := mustAdd(t, rs, "A", "old.com", true)

	oldType, oldPattern, err := rs.UpdateRule(id, "A", "new.com", false, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if oldType != "A" {
		t.Errorf("expected oldType=A, got %q", oldType)
	}
	if oldPattern != "old.com" {
		t.Errorf("expected oldPattern=old.com, got %q", oldPattern)
	}
	if rs.CountAll() != 1 {
		t.Errorf("expected CountAll=1 after in-place update, got %d", rs.CountAll())
	}

	snap := rs.Snapshot()
	rule := snap["A"][0]
	if rule.Pattern != "new.com" {
		t.Errorf("expected updated pattern new.com, got %q", rule.Pattern)
	}
	if rule.Enabled {
		t.Error("expected enabled=false after update")
	}
	if rule.ID != id {
		t.Errorf("expected ID to be preserved (%q), got %q", id, rule.ID)
	}
}

func TestRuleStore_UpdateRule_CrossType(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	id := mustAdd(t, rs, "A", "example.com", true)
	mustAdd(t, rs, "AAAA", "other.com", true) // pre-populate target bucket

	oldType, _, err := rs.UpdateRule(id, "AAAA", "example.com", true, log)
	if err != nil {
		t.Fatalf("unexpected error on cross-type move: %v", err)
	}
	if oldType != "A" {
		t.Errorf("expected oldType=A, got %q", oldType)
	}

	snap := rs.Snapshot()
	if len(snap["A"]) != 0 {
		t.Errorf("expected A bucket to be empty after cross-type move, got %d entries", len(snap["A"]))
	}
	if rs.CountAll() != 2 { // other.com + moved rule
		t.Errorf("expected CountAll=2, got %d", rs.CountAll())
	}
	// The moved rule must live in AAAA now.
	found := false
	for _, r := range snap["AAAA"] {
		if r.ID == id {
			found = true
			break
		}
	}
	if !found {
		t.Error("moved rule not found in AAAA bucket")
	}
}

func TestRuleStore_UpdateRule_NotFound(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	_, _, err := rs.UpdateRule("no-such-id", "A", "whatever.com", true, log)
	if err == nil {
		t.Fatal("expected error for missing id, got nil")
	}
}

func TestRuleStore_UpdateRule_PatternConflict(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	id := mustAdd(t, rs, "A", "alpha.com", true)
	mustAdd(t, rs, "A", "beta.com", true)

	// Try to rename alpha → beta (collision with existing entry in same bucket).
	_, _, err := rs.UpdateRule(id, "A", "beta.com", true, log)
	if err == nil {
		t.Fatal("expected conflict error, got nil")
	}
	if rs.CountAll() != 2 {
		t.Errorf("store must be unchanged after rejected update, got CountAll=%d", rs.CountAll())
	}
}

func TestRuleStore_UpdateRule_EmptyID_Panics(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for empty ID, got none")
		}
	}()
	//nolint:errcheck
	rs.UpdateRule("", "A", "example.com", true, log)
}

// ── SetEnabled ────────────────────────────────────────────────────────────────

func TestRuleStore_SetEnabled_ToggleOff(t *testing.T) {
	rs := newRuleStore()
	mustAdd(t, rs, "A", "example.com", true)

	found, changed := rs.SetEnabled("A", "example.com", false)
	if !found {
		t.Fatal("expected found=true")
	}
	if !changed {
		t.Fatal("expected changed=true")
	}

	snap := rs.Snapshot()
	if snap["A"][0].Enabled {
		t.Error("expected rule to be disabled after SetEnabled(false)")
	}
}

func TestRuleStore_SetEnabled_NoOpWhenAlreadySet(t *testing.T) {
	rs := newRuleStore()
	mustAdd(t, rs, "A", "example.com", true)

	found, changed := rs.SetEnabled("A", "example.com", true) // already true
	if !found {
		t.Fatal("expected found=true")
	}
	if changed {
		t.Error("expected changed=false when value is already set")
	}
}

func TestRuleStore_SetEnabled_NotFound(t *testing.T) {
	rs := newRuleStore()

	found, changed := rs.SetEnabled("A", "nonexistent.com", false)
	if found {
		t.Error("expected found=false for missing pattern")
	}
	if changed {
		t.Error("expected changed=false for missing pattern")
	}
}

// ── MatchForType ──────────────────────────────────────────────────────────────

func TestRuleStore_MatchForType_ExactMatch(t *testing.T) {
	rs := newRuleStore()
	id := mustAdd(t, rs, "A", "example.com", true)

	gotID, ok := rs.MatchForType("A", "example.com")
	if !ok {
		t.Fatal("expected match, got none")
	}
	if gotID != id {
		t.Errorf("expected matched ID %q, got %q", id, gotID)
	}
}

func TestRuleStore_MatchForType_WildcardMatch(t *testing.T) {
	rs := newRuleStore()
	mustAdd(t, rs, "A", "*.example.com", true)

	_, ok := rs.MatchForType("A", "sub.example.com")
	if !ok {
		t.Error("expected wildcard to match sub.example.com")
	}

	_, ok = rs.MatchForType("A", "example.com")
	if ok {
		t.Error("*.example.com must not match bare example.com")
	}
}

func TestRuleStore_MatchForType_DisabledRuleIsSkipped(t *testing.T) {
	rs := newRuleStore()
	mustAdd(t, rs, "A", "example.com", false) // disabled

	_, ok := rs.MatchForType("A", "example.com")
	if ok {
		t.Error("disabled rule must not produce a match")
	}
}

func TestRuleStore_MatchForType_WrongTypeMisses(t *testing.T) {
	rs := newRuleStore()
	mustAdd(t, rs, "A", "example.com", true)

	_, ok := rs.MatchForType("AAAA", "example.com")
	if ok {
		t.Error("rule stored under A must not match AAAA query")
	}
}

func TestRuleStore_MatchForType_EnabledWinsOverDisabled(t *testing.T) {
	// Two rules for the same pattern (different IDs — not possible via AddRule
	// due to duplicate-pattern guard, so we load via ReplaceAll to simulate
	// a pre-existing store with one disabled and one enabled rule).
	rs := newRuleStore()
	rs.ReplaceAll(map[string][]RuleEntry{
		"A": {
			{ID: "id-disabled", Pattern: "example.com", Enabled: false},
			{ID: "id-enabled", Pattern: "*.example.com", Enabled: true},
		},
	})

	_, ok := rs.MatchForType("A", "sub.example.com")
	if !ok {
		t.Error("enabled wildcard rule should match")
	}

	_, ok = rs.MatchForType("A", "example.com")
	if ok {
		t.Error("disabled exact rule must not match")
	}
}

// ── CountAll ─────────────────────────────────────────────────────────────────

func TestRuleStore_CountAll_AcrossTypes(t *testing.T) {
	rs := newRuleStore()
	mustAdd(t, rs, "A", "a.com", true)
	mustAdd(t, rs, "A", "b.com", true)
	mustAdd(t, rs, "AAAA", "c.com", true)

	if rs.CountAll() != 3 {
		t.Errorf("expected CountAll=3, got %d", rs.CountAll())
	}
}

// ── Snapshot ─────────────────────────────────────────────────────────────────

func TestRuleStore_Snapshot_IsDeepCopy(t *testing.T) {
	rs := newRuleStore()
	mustAdd(t, rs, "A", "example.com", true)

	snap := rs.Snapshot()

	// Mutate the snapshot slice — the store's internal slice must not change.
	snap["A"][0].Pattern = "mutated.com"
	snap["A"] = append(snap["A"], RuleEntry{ID: "extra", Pattern: "extra.com", Enabled: true})

	snap2 := rs.Snapshot()
	if len(snap2["A"]) != 1 {
		t.Errorf("store's internal slice was mutated by external append, expected 1 rule, got %d", len(snap2["A"]))
	}
	if snap2["A"][0].Pattern != "example.com" {
		t.Errorf("store's internal entry was mutated, expected example.com, got %q", snap2["A"][0].Pattern)
	}
}

// ── ReplaceAll ────────────────────────────────────────────────────────────────

func TestRuleStore_ReplaceAll_ClearsExistingData(t *testing.T) {
	rs := newRuleStore()
	mustAdd(t, rs, "A", "old.com", true)
	mustAdd(t, rs, "AAAA", "old6.com", true)

	rs.ReplaceAll(map[string][]RuleEntry{
		"TXT": {{ID: "new-id", Pattern: "new.com", Enabled: true}},
	})

	if rs.CountAll() != 1 {
		t.Errorf("expected CountAll=1 after ReplaceAll, got %d", rs.CountAll())
	}
	snap := rs.Snapshot()
	if _, hasA := snap["A"]; hasA {
		t.Error("A bucket should be gone after ReplaceAll")
	}
	if snap["TXT"][0].Pattern != "new.com" {
		t.Errorf("expected new.com in TXT bucket, got %q", snap["TXT"][0].Pattern)
	}
}

func TestRuleStore_ReplaceAll_WithEmpty(t *testing.T) {
	rs := newRuleStore()
	mustAdd(t, rs, "A", "example.com", true)

	rs.ReplaceAll(make(map[string][]RuleEntry))

	if rs.CountAll() != 0 {
		t.Errorf("expected CountAll=0 after ReplaceAll with empty map, got %d", rs.CountAll())
	}
}
