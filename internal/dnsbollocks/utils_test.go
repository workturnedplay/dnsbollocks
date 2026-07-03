//go:build windows
// +build windows

package dnsbollocks

import (
	"log/slog"
	"strings"
	"testing"
)

func TestIsValidDNSName(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		{"Valid simple", "example.com", true},
		{"Valid subdomains", "sub.example.co.uk", true},
		{"Valid single char", "a.com", true},
		{"Valid with numbers", "123.com", true},
		{"Valid with hyphens", "my-domain.com", true},
		{"Invalid empty", "", false},
		{"Invalid starts with hyphen", "-example.com", false},
		{"Invalid ends with hyphen", "example-.com", false},
		{"Invalid double dot", "example..com", false},
		{"Invalid characters", "example!.com", false},
		{"Invalid space", "ex ample.com", false},
		{"Invalid too long", strings.Repeat("a", 254) + ".com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidDNSName(tt.domain)
			if result != tt.expected {
				t.Errorf("isValidDNSName(%q) = %v, want %v", tt.domain, result, tt.expected)
			}
		})
	}
}

func TestSanitizeDomainInput(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		expectedSanitize string
		expectedModified bool
	}{
		{"Clean input", "example.com", "example.com", false},
		{"Wildcards and symbols", "*.example.com!?", "*.example.com!?", false},
		{"With spaces", "ex ample .com", "example.com", true},
		{"With illegal symbols", "example.com/path", "example.compath", true},
		{"With protocol", "https://example.com", "httpsexample.com", true},
		{"Empty string", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sanitized, modified := sanitizeDomainInput(tt.input)
			if sanitized != tt.expectedSanitize || modified != tt.expectedModified {
				t.Errorf("sanitizeDomainInput(%q) = (%q, %v), want (%q, %v)",
					tt.input, sanitized, modified, tt.expectedSanitize, tt.expectedModified)
			}
		})
	}
}

func TestSanitizeDomainInput2(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantSanitized string
		wantModified  bool
	}{
		{"Valid domain", "example.com", "example.com", false},
		{"Valid with wildcard", "*.example.com", "*.example.com", false},
		{"Contains invalid characters", "bad|domain$.com", "baddomain.com", true},
		{"Contains spaces", " my domain .com ", "mydomain.com", true},
		{"Already clean complex", "{**}.test-123.org", "{**}.test-123.org", false},
		{"Only bad chars", "@#%^&()", "", true},
		{"Empty string", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSanitized, gotModified := sanitizeDomainInput(tt.input)
			if gotSanitized != tt.wantSanitized {
				t.Errorf("sanitizeDomainInput() gotSanitized = %v, want %v", gotSanitized, tt.wantSanitized)
			}
			if gotModified != tt.wantModified {
				t.Errorf("sanitizeDomainInput() gotModified = %v, want %v", gotModified, tt.wantModified)
			}
		})
	}
}

func TestIsValidDNSName2(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"Standard domain", "google.com", true},
		{"Single label", "localhost", true},
		{"Max length label", "a12345678901234567890123456789012345678901234567890123456789012.com", true},
		{"Over max length label", "a123456789012345678901234567890123456789012345678901234567890123.com", false},
		{"Hyphen in middle", "my-test-domain.org", true},
		{"Hyphen at start", "-bad.com", false},
		{"Hyphen at end", "bad-.com", false},
		{"Invalid character", "bad$domain.com", false},
		{"Trailing underscore allowed per regex", "test._service", true},
		{"Underscore in middle", "bad_domain.com", false},
		{"Empty string", "", false},
		{"Starts with dot", ".bad.com", false},
		{"Consecutive dots", "bad..com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidDNSName(tt.input); got != tt.want {
				t.Errorf("isValidDNSName(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsLowerASCII(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"All lowercase", "example.com", true},
		{"With numbers", "example123.com", true},
		{"With hyphens", "ex-ample.com", true},
		{"Contains uppercase", "Example.com", false},
		{"All uppercase", "EXAMPLE.COM", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isLowerASCII(tt.input)
			if result != tt.expected {
				t.Errorf("isLowerASCII(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMatchPattern2(t *testing.T) {
	// Note: pattern and name must be lowercased before passing to matchPattern per the function's panic constraints.
	tests := []struct {
		name     string
		pattern  string
		domain   string
		expected bool
	}{
		{"Exact match", "example.com", "example.com", true},
		{"Exact mismatch", "example.com", "example.org", false},

		{"Single asterisk (*) matches one label", "*.example.com", "test.example.com", true},
		{"Single asterisk (*) does not match dot", "*.example.com", "a.b.example.com", false},
		{"Single asterisk (*) matches empty", "*.example.com", ".example.com", true},

		{"Double asterisk (**) matches multiple labels", "**.example.com", "a.b.example.com", true},
		{"Double asterisk (**) matches single label", "**.example.com", "test.example.com", true},

		{"Bracket asterisk ({*}) limits to one label", "{*}.example.com", "test.example.com", true},
		{"Bracket asterisk ({*}) fails on multi label", "{*}.example.com", "a.b.example.com", false},

		{"Bracket double asterisk ({**}) matches multi", "{**}.example.com", "a.b.example.com", true},

		{"Question mark (?) matches single non-dot char", "?xample.com", "example.com", true},
		{"Question mark (?) fails on dot", "?xample.com", ".xample.com", false},
		{"Question mark (?) fails on length mismatch", "?xample.com", "xample.com", false},

		{"Exclamation (!) matches any single char including dot", "!xample.com", "example.com", true},
		{"Exclamation (!) matches dot", "a!b.com", "a.b.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchPattern(tt.pattern, tt.domain)
			if result != tt.expected {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.domain, result, tt.expected)
			}
		})
	}
}

func TestHostFromURL(t *testing.T) {
	tests := []struct {
		name        string
		rawURL      string
		expected    string
		expectError bool
	}{
		{"Standard HTTPS", "https://9.9.9.9/dns-query", "9.9.9.9", false},
		{"With port", "https://1.1.1.1:8443/dns-query", "1.1.1.1", false},
		{"Hostname", "https://dns.google/dns-query", "dns.google", false},
		{"Empty hostname", "https:///dns-query", "", true},
		{"Invalid URL", "::not-a-url", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, err := hostFromURL(tt.rawURL)
			if (err != nil) != tt.expectError {
				t.Errorf("hostFromURL(%q) error = %v, expectError %v", tt.rawURL, err, tt.expectError)
				return
			}
			if host != tt.expected {
				t.Errorf("hostFromURL(%q) = %v, want %v", tt.rawURL, host, tt.expected)
			}
		})
	}
}

func TestParseConsoleLogLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"D", slog.LevelDebug},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"w", slog.LevelWarn},
		{"error", slog.LevelError},
		{"E", slog.LevelError},
		{"info", slog.LevelInfo},
		{"unknown", slog.LevelInfo}, // defaults to info
		{"", slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseConsoleLogLevel(tt.input)
			if result != tt.expected {
				t.Errorf("parseConsoleLogLevel(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}
