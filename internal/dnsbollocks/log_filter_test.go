//go:build windows
// +build windows

package dnsbollocks

import (
	"strings"
	"testing"
)

func TestLogFilterExpr_Matches(t *testing.T) {
	tests := []struct {
		name   string
		filter string
		text   string
		want   bool
	}{
		{"empty matches all", "", "anything", true},
		{"whitespace only matches all", "   ", "anything", true},
		{"plain substring", "foo", "a foo b", true},
		{"plain substring miss", "foo", "a bar b", false},
		{"case-insensitive filter", "ERROR", "an error happened", true},
		{"ordered words in order", "foo bar", "foo then bar", true},
		{"ordered words out of order", "foo bar", "bar then foo", false},
		{"ordered words cannot overlap", "aa aa", "aaa", false},
		{"AND any order", "foo & bar", "bar then foo", true},
		{"AND one missing", "foo & bar", "only foo", false},
		{"OR first", "foo | bar", "only foo", true},
		{"OR second", "foo | bar", "only bar", true},
		{"OR none", "foo | bar", "baz", false},
		{"NOT excludes", "error !timeout", "error timeout", false},
		{"NOT allows", "error !timeout", "error ok", true},
		{"only NOT matches others", "!timeout", "hello", true},
		{"only NOT excludes", "!timeout", "a timeout", false},
		{"OR plus global NOT excluded", "face | fbcdn !hugging", "fbcdn hugging", false},
		{"OR plus global NOT allowed", "face | fbcdn !hugging", "fbcdn x", true},
		{"lone pipe matches all", "|", "anything", true},
		{"lone ampersand matches all", "&", "anything", true},
		{"bang inside word is literal", "a!b", "xa!bx", true},
		{"bang inside word literal miss", "a!b", "xabx", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLogFilterExpression(tt.filter).matches(strings.ToLower(tt.text))
			if got != tt.want {
				t.Errorf("filter %q vs text %q = %v, want %v", tt.filter, tt.text, got, tt.want)
			}
		})
	}
}

func TestLogFilterExpr_IsEmpty(t *testing.T) {
	if !parseLogFilterExpression("").isEmpty() {
		t.Error("empty filter must be isEmpty")
	}
	if !parseLogFilterExpression(" | & ").isEmpty() {
		t.Error("operator-only filter has no terms and must be isEmpty")
	}
	if parseLogFilterExpression("foo").isEmpty() {
		t.Error("non-empty filter must not be isEmpty")
	}
	if parseLogFilterExpression("!foo").isEmpty() {
		t.Error("negative-only filter must not be isEmpty")
	}
}