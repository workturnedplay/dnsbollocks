package dnsbollocks

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestResolveTag(t *testing.T) {
	// Create a temporary file in the current directory to satisfy the strict path rules
	const testFileName1 = "test_secret_file_123.txt"
	configDir := filepath.Dir(configFileName)
	path := filepath.Join(configDir, testFileName1)
	err := os.WriteFile(path, []byte("secret_from_file\n"), 0600)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	defer os.Remove(path) //nolint:errcheck //don't case

	// Set up a mock environment variable
	t.Setenv("TEST_ENV_VAR", "secret_from_env")

	tests := []struct {
		name      string
		input     string
		wantVal   string
		wantIsTag bool
		wantErr   bool
	}{
		{"Literal string", "just_a_normal_string", "just_a_normal_string", false, false},
		{"Valid file tag", "{file:test_secret_file_123.txt}", "secret_from_file", true, false},
		{"Valid file tag with spaces", "  {file:test_secret_file_123.txt}  ", "secret_from_file", true, false},
		{"Invalid file tag (path traversal)", "{file:../secret.txt}", "", true, true},
		{"Invalid file tag (not found)", "{file:does_not_exist.txt}", "", true, true},
		{"Valid env tag", "{env:TEST_ENV_VAR}", "secret_from_env", true, false},
		{"Valid env tag with spaces", "  {env:TEST_ENV_VAR}  ", "secret_from_env", true, false},
		{"Invalid env tag (not set)", "{env:MISSING_ENV_VAR_123}", "", true, true},
		{
			name:      "Reserved filename CON",
			input:     "{file:CON}",
			wantIsTag: true,
			wantErr:   true,
		},
		{
			name:      "Reserved filename con (case-insensitive)",
			input:     "{file:con}",
			wantIsTag: true,
			wantErr:   true,
		},
		{
			name:      "Reserved filename COM1",
			input:     "{file:COM1}",
			wantIsTag: true,
			wantErr:   true,
		},
		{
			name:      "Reserved filename with trailing dot",
			input:     "{file:con.}",
			wantIsTag: true,
			wantErr:   true,
		},
		{
			name:      "Reserved filename with trailing spaces",
			input:     "{file:con   }",
			wantIsTag: true,
			wantErr:   true,
		},
		{
			name:      "Backslash path rejected",
			input:     `{file:foo\bar.txt}`,
			wantIsTag: true,
			wantErr:   true,
		},
		{
			name:      "Forward slash path rejected",
			input:     "{file:foo/bar.txt}",
			wantIsTag: true,
			wantErr:   true,
		},
		{
			name:      "Drive letter rejected",
			input:     "{file:C:test.txt}",
			wantIsTag: true,
			wantErr:   true,
		},
		{
			name:      "Empty filename",
			input:     "{file:}",
			wantIsTag: true,
			wantErr:   true,
		},
		{
			name:      "Whitespace filename",
			input:     "{file:     }",
			wantIsTag: true,
			wantErr:   true,
		},
		{
			name:      "Malformed tag is treated as literal",
			input:     "{file:test.txt",
			wantVal:   "{file:test.txt",
			wantIsTag: false,
			wantErr:   false,
		},
		{
			name:      "Unknown tag type is literal",
			input:     "{foobar:test.txt}",
			wantVal:   "{foobar:test.txt}",
			wantIsTag: false,
			wantErr:   false,
		},
		{
			name:      "Empty env name",
			input:     "{env:}",
			wantIsTag: true,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVal, gotIsTag, err := resolveTag(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveTag() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotIsTag != tt.wantIsTag {
				t.Errorf("resolveTag() gotIsTag = %v, want %v", gotIsTag, tt.wantIsTag)
			}
			if gotVal != tt.wantVal {
				t.Errorf("resolveTag() gotVal = %v, want %v", gotVal, tt.wantVal)
			}
		})
	}
}

func TestResolveAndRestoreConfigTags(t *testing.T) {
	// 1. Setup mock environment
	const testFileName2 = "test_upstream_123.txt"
	configDir := filepath.Dir(configFileName)
	path := filepath.Join(configDir, testFileName2)
	err := os.WriteFile(path, []byte("https://8.8.8.8/dns-query\n"), 0600)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	defer os.Remove(path) //nolint:errcheck //don't case

	t.Setenv("TEST_WEBUI_PWD", "hashed_pwd_xyz")

	// 2. Setup a dummy Config with a mix of literals and tags
	cfg := &Config{
		ListenDNS:         "127.0.0.1:53",         // Literal string
		WebUIPasswordHash: "{env:TEST_WEBUI_PWD}", // Env tag
		UpstreamURLs: []string{
			"https://9.9.9.9/dns-query",    // Literal slice item
			"{file:test_upstream_123.txt}", // File slice item
		},
	}

	// ==========================================
	// Phase 1: Test Resolution
	// ==========================================
	err = resolveConfigTags(cfg)
	if err != nil {
		t.Fatalf("resolveConfigTags failed unexpectedly: %v", err)
	}

	// Verify the values were swapped into memory correctly
	if cfg.WebUIPasswordHash != "hashed_pwd_xyz" {
		t.Errorf("expected WebUIPasswordHash to be resolved, got %q", cfg.WebUIPasswordHash)
	}
	if len(cfg.UpstreamURLs) != 2 || cfg.UpstreamURLs[1] != "https://8.8.8.8/dns-query" {
		t.Errorf("expected UpstreamURLs[1] to be resolved, got %q", cfg.UpstreamURLs[1])
	}
	if cfg.ListenDNS != "127.0.0.1:53" {
		t.Errorf("literal string was altered unexpectedly, got %q", cfg.ListenDNS)
	}

	// Verify the tracking maps captured the original tags
	if cfg.RawStrings["webui_password_hash"] != "{env:TEST_WEBUI_PWD}" {
		t.Errorf("missing/incorrect raw string tracking: %v", cfg.RawStrings)
	}
	expectedRawSlice := []string{"https://9.9.9.9/dns-query", "{file:test_upstream_123.txt}"}
	if !reflect.DeepEqual(cfg.RawStringSlices["upstream_urls"], expectedRawSlice) {
		t.Errorf("missing/incorrect raw string slice tracking: got %v, want %v", cfg.RawStringSlices["upstream_urls"], expectedRawSlice)
	}

	// ==========================================
	// Phase 2: Test Restoration (Serialization Prep)
	// ==========================================

	// Simulate an active application making an unrelated configuration change
	cfg.ListenDNS = "0.0.0.0:53"

	restoreRawValues(cfg)

	// Verify the tags were put back
	if cfg.WebUIPasswordHash != "{env:TEST_WEBUI_PWD}" {
		t.Errorf("expected WebUIPasswordHash to be restored to tag, got %q", cfg.WebUIPasswordHash)
	}
	if len(cfg.UpstreamURLs) != 2 || cfg.UpstreamURLs[1] != "{file:test_upstream_123.txt}" {
		t.Errorf("expected UpstreamURLs[1] to be restored to tag, got %q", cfg.UpstreamURLs[1])
	}

	// Verify unrelated modifications were preserved
	if cfg.ListenDNS != "0.0.0.0:53" {
		t.Errorf("expected unmodified fields to retain runtime changes, got %q", cfg.ListenDNS)
	}

	cfg2 := &Config{
		WebUIPasswordHash: "{env:DOES_NOT_EXIST_123456}",
		ListenDNS:         "127.0.0.1:53",
	}

	err2 := resolveConfigTags(cfg2)
	if err2 == nil {
		t.Fatal("expected error")
	}

	cfg3 := &Config{
		ListenDNS: "127.0.0.1:53",
	}

	if err3 := resolveConfigTags(cfg3); err3 != nil {
		t.Fatal(err3)
	}

	if len(cfg3.RawStrings) != 0 {
		t.Errorf("RawStrings should be empty")
	}
	if len(cfg3.RawStringSlices) != 0 {
		t.Errorf("RawStringSlices should be empty")
	}

	cfg4 := &Config{
		UpstreamURLs: []string{"runtime"},
		RawStringSlices: map[string][]string{
			"upstream_urls": {
				"{file:a.txt}",
				"{file:b.txt}",
			},
		},
	}

	restoreRawValues(cfg4)

	if len(cfg4.UpstreamURLs) != 1 || cfg4.UpstreamURLs[0] != "runtime" {
		t.Fatal("slice should not have been modified on length mismatch")
	}
}
