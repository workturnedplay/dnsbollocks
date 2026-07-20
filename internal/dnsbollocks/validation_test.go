//go:build windows
// +build windows

package dnsbollocks

import (
	"net/url"
	"os"
	"path/filepath"
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
		{"invalid chars removed", "exa@m#ple!.com", "example!.com", true},                  // @ and # removed
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

// TestUpstreamURLWithBuiltinTemplate verifies that Go's url.Parse handles
// {builtin:clientexe} in various positions without returning syntax errors.
func TestUpstreamURLWithBuiltinTemplate(t *testing.T) {
	tests := []struct {
		name         string
		rawURL       string
		expectErr    bool
		errContains  string
		expectedHost string
		expectedPath string
	}{
		{
			name:         "builtin in path",
			rawURL:       "https://doh.example.com/dns-query/{builtin:clientexe}",
			expectErr:    false,
			expectedHost: "doh.example.com",
			expectedPath: "/dns-query/{builtin:clientexe}",
		},
		{
			name:         "builtin in query param",
			rawURL:       "https://doh.example.com/dns-query?client={builtin:clientexe}",
			expectErr:    false,
			expectedHost: "doh.example.com",
			expectedPath: "/dns-query",
		},
		{
			name:        "builtin as hostname (fails due to colon as port separator)",
			rawURL:      "https://{builtin:clientexe}/dns-query",
			expectErr:   true,
			errContains: "invalid port",
		},
		{
			name:        "builtin raw scheme-less (fails due to colon in 1st path segment)",
			rawURL:      "{builtin:clientexe}",
			expectErr:   true,
			errContains: "first path segment in URL cannot contain colon",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := url.Parse(tt.rawURL)

			// Verify error expectation
			if (err != nil) != tt.expectErr {
				t.Fatalf("url.Parse(%q) unexpected error status: got err=%v, wantErr=%v", tt.rawURL, err, tt.expectErr)
			}

			// Verify expected error message substring
			if tt.expectErr && tt.errContains != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error to contain %q, got: %v", tt.errContains, err)
				}
			}

			// Verify Host and Path if parsing was successful
			if !tt.expectErr {
				if parsed.Host != tt.expectedHost {
					t.Errorf("Host mismatch for %q: got %q, want %q", tt.rawURL, parsed.Host, tt.expectedHost)
				}
				if parsed.Path != tt.expectedPath {
					t.Errorf("Path mismatch for %q: got %q, want %q", tt.rawURL, parsed.Path, tt.expectedPath)
				}
			}
		})
	}
}

// TestExpandBuiltinTemplate verifies replacing {builtin:clientexe} with the executable name.
func TestExpandBuiltinTemplate(t *testing.T) {
	exePath, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to get executable path: %v", err)
	}
	execName := filepath.Base(exePath)

	inputURL := "https://doh.example.com/dns-query?app={builtin:clientexe}"
	expandedURL := strings.ReplaceAll(inputURL, "{builtin:clientexe}", execName)

	parsed, err := url.Parse(expandedURL)
	if err != nil {
		t.Fatalf("failed to parse expanded URL %q: %v", expandedURL, err)
	}

	if !strings.Contains(parsed.RawQuery, execName) {
		t.Errorf("expected expanded query to contain %q, got: %q", execName, parsed.RawQuery)
	}
}
