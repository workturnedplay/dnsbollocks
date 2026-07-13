//go:build windows
// +build windows

package dnsbollocks

import (
	"strings"
	"testing"
)

func TestValidateRulePattern3(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantErr     bool
		errContains string
	}{
		{"empty", "", true, "empty"},
		{"valid simple", "example.com", false, ""},
		{"valid subdomain", "sub.domain.example.com", false, ""},
		{"valid wildcard", "*.example.com", false, ""},
		{"valid with underscore", "sub_domain.example.com", false, ""},
		{"valid special chars", "sub*?!_domain.example.com", false, ""},

		// Length
		{"max length ok", strings.Repeat("a", 512), false, ""},
		{"too long", strings.Repeat("a", 513), true, "maximum length"},

		// Case
		{"must be lowercase", "Example.COM", true, "lowercase"},

		// Illegal characters / structure
		{"invalid @", "user@example.com", true, "illegal characters"},
		{"invalid space", "exa mple.com", true, "illegal"},
		{"control char", "exa\x00mple.com", true, "illegal"},
		{"emoji", "😀.com", true, "illegal"},

		//{"leading dot", ".example.com", true, "illegal characters"}, //TODO?
		//{"trailing dot", "example.com.", true, "illegal characters"}, //TODO?
		//{"consecutive dots", "ex..ample.com", true, "illegal characters"}, //TODO?
		//{"only dots", "...", true, "illegal characters"}, //TODO?

		// IDN should fail at this stage
		{"IDN café", "café.com", true, "illegal characters"},
		{"Cyrillic", "пример.рф", true, "illegal characters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRulePattern(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRulePattern(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if tt.errContains != "" && err != nil && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("expected error to contain %q, got: %v", tt.errContains, err)
			}
		})
	}
}

func TestSanitizeDomainInput3(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		want     string
		modified bool
	}{
		{"already clean", "example.com", "example.com", false},
		{"uppercase kept (no lower)", "Example.COM", "Example.COM", false}, // important: does NOT lowercase
		{"IDN stripped", "Café.com", "Caf.com", true},
		{"special chars kept", "sub*?!_domain.example.com", "sub*?!_domain.example.com", false},
		{"invalid chars removed", "exa@m#ple!.com", "example!.com", true}, // @ and # removed
		{"template with colon", "{builtin:clientexe}.com", "{builtinclientexe}.com", true}, // : gets stripped
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, modified := sanitizeDomainInput(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeDomainInput(%q) = %q, want %q", tt.input, got, tt.want)
			}
			if modified != tt.modified {
				t.Errorf("modified flag = %v, want %v for input %q", modified, tt.modified, tt.input)
			}
		})
	}
}