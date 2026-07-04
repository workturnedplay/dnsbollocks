package dnsbollocks

import (
	"os"
	"path/filepath"
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

func TestResolveConfigTags(t *testing.T) {
	const testFileName2 = "test_upstream_123.txt"
	configDir := filepath.Dir(configFileName)
	path := filepath.Join(configDir, testFileName2)
	if err := os.WriteFile(path, []byte("https://8.8.8.8/dns-query\n"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	defer os.Remove(path) //nolint:errcheck

	t.Setenv("TEST_WEBUI_PWD", "hashed_pwd_xyz")

	raw := &Config{
		ListenDNS:         "127.0.0.1:53",
		WebUIPasswordHash: "{env:TEST_WEBUI_PWD}",
		UpstreamURLs: []string{
			"https://9.9.9.9/dns-query",
			"{file:test_upstream_123.txt}",
		},
	}

	resolved, err := resolveConfigTags(raw)
	if err != nil {
		t.Fatalf("resolveConfigTags failed unexpectedly: %v", err)
	}

	// raw must be completely untouched.
	if raw.WebUIPasswordHash != "{env:TEST_WEBUI_PWD}" {
		t.Errorf("raw.WebUIPasswordHash was mutated: got %q", raw.WebUIPasswordHash)
	}
	if raw.UpstreamURLs[1] != "{file:test_upstream_123.txt}" {
		t.Errorf("raw.UpstreamURLs[1] was mutated: got %q", raw.UpstreamURLs[1])
	}
	if raw.ListenDNS != "127.0.0.1:53" {
		t.Errorf("raw.ListenDNS was mutated: got %q", raw.ListenDNS)
	}

	// resolved has real values.
	if resolved.WebUIPasswordHash != "hashed_pwd_xyz" {
		t.Errorf("resolved.WebUIPasswordHash = %q, want %q", resolved.WebUIPasswordHash, "hashed_pwd_xyz")
	}
	if resolved.UpstreamURLs[1] != "https://8.8.8.8/dns-query" {
		t.Errorf("resolved.UpstreamURLs[1] = %q, want %q", resolved.UpstreamURLs[1], "https://8.8.8.8/dns-query")
	}
	if resolved.ListenDNS != "127.0.0.1:53" {
		t.Errorf("resolved.ListenDNS = %q, want %q (literal should pass through)", resolved.ListenDNS, "127.0.0.1:53")
	}

	// resolved is a deep copy; mutating it must not affect raw.
	resolved.ListenDNS = "0.0.0.0:53"
	if raw.ListenDNS != "127.0.0.1:53" {
		t.Errorf("raw.ListenDNS changed after mutating resolved: got %q", raw.ListenDNS)
	}

	// Error case: unresolvable token.
	bad := &Config{WebUIPasswordHash: "{env:DOES_NOT_EXIST_123456}"}
	if _, err2 := resolveConfigTags(bad); err2 == nil {
		t.Error("expected error for missing env var, got nil")
	}
	// bad must still be unmodified after an error.
	if bad.WebUIPasswordHash != "{env:DOES_NOT_EXIST_123456}" {
		t.Errorf("bad.WebUIPasswordHash was mutated despite error: got %q", bad.WebUIPasswordHash)
	}

	// No tokens → resolved is a clean clone with no mutations.
	plain := &Config{ListenDNS: "127.0.0.1:53"}
	resolvedPlain, err3 := resolveConfigTags(plain)
	if err3 != nil {
		t.Fatalf("unexpected error for plain config: %v", err3)
	}
	if resolvedPlain.ListenDNS != plain.ListenDNS {
		t.Errorf("resolvedPlain.ListenDNS = %q, want %q", resolvedPlain.ListenDNS, plain.ListenDNS)
	}
}
