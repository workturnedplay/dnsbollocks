//go:build windows
// +build windows

package dnsbollocks

import (
	"reflect"
	"testing"
)

// --- Config Clone Tests ---

func TestConfigClone(t *testing.T) {
	original := defaultConfig()
	original.UpstreamURLs = []string{"https://1.1.1.1/dns-query"}
	original.UpstreamSNIHostnames = []string{"cloudflare-dns.com"}

	clone := original.Clone()

	// 1. Verify deep equality of the initial clone
	if !reflect.DeepEqual(original, clone) {
		t.Fatalf("Clone did not match original.\nOriginal: %+v\nClone: %+v", original, clone)
	}

	// 2. Modify the clone's slices to ensure they are decoupled from the original
	clone.UpstreamURLs[0] = "https://8.8.8.8/dns-query"
	clone.UpstreamSNIHostnames[0] = "dns.google"

	if original.UpstreamURLs[0] == clone.UpstreamURLs[0] {
		t.Errorf("Config.Clone() did not deep copy UpstreamURLs! Both share: %s", original.UpstreamURLs[0])
	}
	if original.UpstreamSNIHostnames[0] == clone.UpstreamSNIHostnames[0] {
		t.Errorf("Config.Clone() did not deep copy SNIHostnames! Both share: %s", original.UpstreamSNIHostnames[0])
	}
}

// --- Validation Functions ---

func TestValidateRulePattern(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		expectError bool
	}{
		{"Valid domain", "example.com", false},
		{"Valid wildcard", "*.example.com", false},
		{"Valid bracket wildcard", "{**}.example.com", false},
		{"Empty pattern", "", true},
		{"Illegal characters", "example.com/path", true},
		{"Spaces", "example .com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRulePattern(tt.pattern)
			if (err != nil) != tt.expectError {
				t.Errorf("validateRulePattern(%q) error = %v, expectError %v", tt.pattern, err, tt.expectError)
			}
		})
	}
}

func TestValidateDNSType(t *testing.T) {
	tests := []struct {
		typ         string
		expectError bool
	}{
		{"A", false},
		{"AAAA", false},
		{"TXT", false},
		{"HTTPS", false},
		{"MX", false},
		{"INVALID_TYPE", true},
		{"a", true}, // Assuming case-sensitive exact match required by dnsTypes map
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.typ, func(t *testing.T) {
			err := validateDNSType(tt.typ)
			if (err != nil) != tt.expectError {
				t.Errorf("validateDNSType(%q) error = %v, expectError %v", tt.typ, err, tt.expectError)
			}
		})
	}
}

// --- JSON Duplication Detection ---

func TestDetectDuplicateJSONObjectKeys(t *testing.T) {
	tests := []struct {
		name           string
		jsonStr        string
		expectDups     []string
		expectParseErr bool
	}{
		{
			name:       "No duplicates",
			jsonStr:    `{"a": 1, "b": 2, "c": {"nested_a": 1}}`,
			expectDups: nil,
		},
		{
			name:       "Single duplicate",
			jsonStr:    `{"a": 1, "b": 2, "a": 3}`,
			expectDups: []string{"a"},
		},
		{
			name:       "Multiple duplicates",
			jsonStr:    `{"host1": "1.1.1.1", "host2": "8.8.8.8", "host1": "1.0.0.1", "host2": "8.8.4.4"}`,
			expectDups: []string{"host1", "host2"},
		},
		{
			name:           "Invalid JSON array instead of object",
			jsonStr:        `["a", "b", "c"]`,
			expectParseErr: true,
		},
		{
			name:           "Malformed JSON",
			jsonStr:        `{"a": 1, "b": }`,
			expectParseErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dups, err := detectDuplicateJSONObjectKeysAtTopLevelOnly([]byte(tt.jsonStr))

			if (err != nil) != tt.expectParseErr {
				t.Fatalf("detectDuplicateJSONObjectKeys() error = %v, expectParseErr %v", err, tt.expectParseErr)
			}

			if err == nil {
				if len(dups) != len(tt.expectDups) {
					t.Errorf("Expected %d duplicates, got %d (%v)", len(tt.expectDups), len(dups), dups)
				} else {
					// Check if all expected dupes are present
					for i, expected := range tt.expectDups {
						if dups[i] != expected {
							t.Errorf("Expected duplicate key %q at index %d, got %q", expected, i, dups[i])
						}
					}
				}
			}
		})
	}
}
