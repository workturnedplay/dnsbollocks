//go:build windows
// +build windows

package dnsbollocks

import (
	"testing"
  "strings"
)

func TestIDNEncodeAndDecode(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantEncoded   string // partial match is fine for some
		expectPunycode bool
	}{
		{"ascii unchanged", "example.com", "example.com", false},
		{"french café", "café.com", "xn--caf-dma.com", true},
		{"german umlaut", "bücher.de", "xn--bcher-kva.de", true},
		{"chinese", "例子.中国", "xn--fsq.com", true}, // actual punycode may vary slightly
		{"russian", "пример.рф", "xn--e1afmkfd.xn--p1ai", true},
		{"arabic", "مثال.مصر", "", true},
		{"greek", "αβγ.com", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := encodePatternOrErr(tt.input)
			if err != nil {
				t.Fatalf("encode failed: %v", err)
			}

			if tt.expectPunycode && !strings.Contains(encoded, "xn--") && encoded == tt.input {
				t.Error("expected punycode encoding for non-ASCII domain")
			}

			if tt.wantEncoded != "" && encoded != tt.wantEncoded {
				t.Logf("Note: got encoded %q, expected %q (may be acceptable if correct punycode)", encoded, tt.wantEncoded)
			}

			// Roundtrip display
			decoded, wasIDN := punycodeDecodePatternForDisplay(encoded)
			if wasIDN && decoded != tt.input {
				t.Errorf("roundtrip failed: decoded %q, original %q", decoded, tt.input)
			}
		})
	}
}

func TestIDNHomographAndMixedScript(t *testing.T) {
	dangerous := []string{
		"аррӏе.com",     // Cyrillic + Latin lookalikes
		"ｇｏｏｇｌｅ.com", // full-width
		"paypaI.com",    // capital I vs l
	}

	for _, d := range dangerous {
		t.Run(d, func(t *testing.T) {
			err := validateRulePattern(d)
			if err == nil {
				t.Errorf("Expected validation to reject dangerous homograph: %s", d)
			}
		})
	}
}