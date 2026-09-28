//go:build windows
// +build windows

package dnsbollocks

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestPatternSyntaxHelp_WellFormed(t *testing.T) {
	seen := make(map[string]struct{}, len(patternSyntaxHelp))
	for _, e := range patternSyntaxHelp {
		if e.Token == "" || e.Meaning == "" {
			t.Errorf("incomplete entry: %+v", e)
		}
		if strings.Contains(e.Meaning, `"`) {
			t.Errorf("Meaning of %q must not contain double quotes (it's embedded in an HTML title attribute): %q", e.Token, e.Meaning)
		}
		if _, dup := seen[e.Token]; dup {
			t.Errorf("duplicate token %q", e.Token)
		}
		seen[e.Token] = struct{}{}
	}
	if len(patternSyntaxNotes) == 0 {
		t.Error("expected at least one note")
	}
}

func TestPatternSyntaxTooltip_ContainsEveryTokenAndNote(t *testing.T) {
	for _, e := range patternSyntaxHelp {
		if !strings.Contains(patternSyntaxTooltip, e.Token) || !strings.Contains(patternSyntaxTooltip, e.Meaning) {
			t.Errorf("tooltip is missing %q / %q", e.Token, e.Meaning)
		}
	}
	for _, n := range patternSyntaxNotes {
		if !strings.Contains(patternSyntaxTooltip, n) {
			t.Errorf("tooltip is missing note %q", n)
		}
	}
}

// Ties the documentation to matchPattern's real behavior: every documented
// token must have a behavior case (and vice versa), each checked as "a<token>c".
func TestPatternSyntaxHelp_TokensBehaveAsDocumented(t *testing.T) {
	type nameCase struct {
		name string
		want bool
	}
	behavior := map[string][]nameCase{
		"*":    {{"ac", true}, {"abc", true}, {"a.c", false}},
		"{*}":  {{"ac", false}, {"abc", true}, {"a.c", false}},
		"**":   {{"ac", true}, {"abc", true}, {"a.b.c", true}},
		"{**}": {{"ac", false}, {"abc", true}, {"a.c", true}},
		"?":    {{"ac", false}, {"abc", true}, {"a.c", false}},
		"!":    {{"ac", false}, {"abc", true}, {"a.c", true}},
	}

	documented := make(map[string]struct{}, len(patternSyntaxHelp))
	for _, e := range patternSyntaxHelp {
		documented[e.Token] = struct{}{}
		cases, ok := behavior[e.Token]
		if !ok {
			t.Errorf("documented token %q has no behavior test case", e.Token)
			continue
		}
		pattern := "a" + e.Token + "c"
		for _, tc := range cases {
			if got := matchPattern(pattern, tc.name); got != tc.want {
				t.Errorf("matchPattern(%q, %q) = %v, want %v (token %q: %s)", pattern, tc.name, got, tc.want, e.Token, e.Meaning)
			}
		}
	}
	for token := range behavior {
		if _, ok := documented[token]; !ok {
			t.Errorf("behavior case for %q exists but the token is not documented in patternSyntaxHelp", token)
		}
	}
}

func TestRulesHandler_RendersPatternHintsAndTooltips(t *testing.T) {
	ui, rec := setupTestAdminUI(t)
	ui.uiTemplates = uiTemplates0

	req := httptest.NewRequest(http.MethodGet, "/rules", http.NoBody)
	ui.rulesHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	if !regexp.MustCompile(`<details id="patternHints"[^>]*\sopen`).MatchString(body) {
		t.Error("expected the pattern hints <details> to be rendered open by default")
	}
	if !strings.Contains(body, `data-remember-key="patternHints"`) {
		t.Error("expected data-remember-key so app.js can persist the open/closed state")
	}
	for _, e := range patternSyntaxHelp {
		if !strings.Contains(body, "<code>"+e.Token+"</code>") {
			t.Errorf("hints section is missing token %q", e.Token)
		}
	}
	if !regexp.MustCompile(`<input[^>]*id="addRulePattern"[^>]*title="[^"]+"`).MatchString(body) {
		t.Error("add-form pattern input has no tooltip")
	}
	if !regexp.MustCompile(`<input[^>]*edit-pattern[^>]*title="[^"]+"`).MatchString(body) {
		t.Error("edit-row pattern input has no tooltip")
	}
	if !strings.Contains(body, `class="grow-input"`) {
		t.Error("add-form pattern input should use the grow-input class")
	}
}