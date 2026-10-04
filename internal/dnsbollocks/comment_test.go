//go:build windows
// +build windows

package dnsbollocks

import (
	"net"
	"strings"
	"testing"
)

func TestNormalizeRuleComment(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"empty", "", "", false},
		{"trimmed", "  hello  ", "hello", false},
		{"max length ok", strings.Repeat("é", maxRuleCommentLength), strings.Repeat("é", maxRuleCommentLength), false},
		{"too long", strings.Repeat("é", maxRuleCommentLength+1), "", true},
		{"newline rejected", "a\nb", "", true},
		{"tab rejected", "a\tb", "", true},
		{"invalid utf8 rejected", "a\xffb", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeRuleComment(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("normalizeRuleComment(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("normalizeRuleComment(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRepairRuleCommentForLoad(t *testing.T) {
	if got := repairRuleCommentForLoad("ok"); got != "ok" {
		t.Errorf("clean comment changed: %q", got)
	}
	if got := repairRuleCommentForLoad("a\nb\tc"); got != "a b c" {
		t.Errorf("control chars not replaced: %q", got)
	}
	got := repairRuleCommentForLoad(strings.Repeat("x", maxRuleCommentLength+50))
	if len(got) != maxRuleCommentLength {
		t.Errorf("expected truncation to %d, got %d", maxRuleCommentLength, len(got))
	}
}

func TestRuleStore_Comment_AtomicAndPreserved(t *testing.T) {
	rs := newRuleStore()
	log := discardLogger()

	id, err := rs.AddRuleWithComment("A", "a.com", true, "hello", log)
	if err != nil {
		t.Fatalf("AddRuleWithComment: %v", err)
	}
	if got := rs.Snapshot()["A"][0].Comment; got != "hello" {
		t.Fatalf("comment after add = %q", got)
	}

	if _, _, err := rs.UpdateRule(id, "A", "b.com", true, log); err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}
	if got := rs.Snapshot()["A"][0].Comment; got != "hello" {
		t.Errorf("UpdateRule must preserve the comment, got %q", got)
	}

	if _, found, _ := rs.SetEnabledByID("A", id, false, log); !found {
		t.Fatal("SetEnabledByID: not found")
	}
	if got := rs.Snapshot()["A"][0].Comment; got != "hello" {
		t.Errorf("SetEnabledByID must preserve the comment, got %q", got)
	}

	if _, _, err := rs.UpdateRuleWithComment(id, "AAAA", "b.com", true, "moved", log); err != nil {
		t.Fatalf("UpdateRuleWithComment: %v", err)
	}
	if got := rs.Snapshot()["AAAA"][0].Comment; got != "moved" {
		t.Errorf("comment after cross-type edit = %q", got)
	}

	if _, _, err := rs.UpdateRuleWithComment(id, "AAAA", "b.com", true, "", log); err != nil {
		t.Fatalf("UpdateRuleWithComment(clear): %v", err)
	}
	if got := rs.Snapshot()["AAAA"][0].Comment; got != "" {
		t.Errorf("empty comment must clear it, got %q", got)
	}
}

func TestHostStore_Comment_AtomicAndPreserved(t *testing.T) {
	hs := newHostStore()
	ips := []net.IP{net.ParseIP("10.0.0.1")}

	if err := hs.AddHostWithComment("h.local", ips, true, "first"); err != nil {
		t.Fatalf("AddHostWithComment: %v", err)
	}
	if err := hs.EditHostWithEnabled("h.local", "h2.local", ips, true); err != nil {
		t.Fatalf("EditHostWithEnabled: %v", err)
	}
	if got := hs.ToRawMap()["h2.local"].Comment; got != "first" {
		t.Errorf("EditHostWithEnabled must preserve the comment, got %q", got)
	}
	if err := hs.EditHostWithComment("h2.local", "h2.local", ips, true, "second"); err != nil {
		t.Fatalf("EditHostWithComment: %v", err)
	}
	if got := hs.Snapshot()[0].Comment; got != "second" {
		t.Errorf("snapshot comment = %q", got)
	}
}

func TestBlacklistStore_Comment_AtomicAndPreserved(t *testing.T) {
	bs := newBlacklistStore()
	_, n1, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	_, n2, err := net.ParseCIDR("172.16.0.0/12")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}

	if !bs.TryAddWithComment(n1, true, "lan") {
		t.Fatal("TryAddWithComment failed")
	}
	if err := bs.TryEditWithEnabled("10.0.0.0/8", n2, true); err != nil {
		t.Fatalf("TryEditWithEnabled: %v", err)
	}
	if got := bs.Snapshot()[0].Comment; got != "lan" {
		t.Errorf("TryEditWithEnabled must preserve the comment, got %q", got)
	}
	if err := bs.TryEditWithComment("172.16.0.0/12", n2, true, "other"); err != nil {
		t.Fatalf("TryEditWithComment: %v", err)
	}
	if got := bs.Snapshot()[0].Comment; got != "other" {
		t.Errorf("comment after TryEditWithComment = %q", got)
	}
}

func TestQuickToggleExactRule_UnblockStampsAutoComment(t *testing.T) {
	rs := newRuleStore()
	if _, err := quickToggleExactRule(rs, "A", "example.com", "example.com", true, discardLogger(), "whitelist"); err != nil {
		t.Fatalf("quickToggleExactRule: %v", err)
	}
	got := rs.Snapshot()["A"][0].Comment
	if !strings.HasPrefix(got, "quick-unblocked via WebUI (whitelist) on ") {
		t.Errorf("unexpected auto comment %q", got)
	}
	if err := validateRuleComment(got); err != nil {
		t.Errorf("auto comment must itself be valid: %v", err)
	}
}