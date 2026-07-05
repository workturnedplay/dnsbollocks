//go:build windows
// +build windows

package dnsbollocks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveTag(t *testing.T) {
	// Create temporary files in the current directory to satisfy strict path rules
	const testFileName1 = "test_secret_file_123.txt"
	configDir := filepath.Dir(configFileName)
	path := filepath.Join(configDir, testFileName1)
	err := os.WriteFile(path, []byte("secret_from_file\n"), 0600)
	if err != nil {
		t.Fatalf("failed to create first test file: %v", err)
	}
	defer os.Remove(path) //nolint:errcheck //don't care
	const testFileName2 = "test_secret_file_456.txt"
	path2 := filepath.Join(configDir, testFileName2)
	err2 := os.WriteFile(path2, []byte("another_secret_content\n"), 0600)
	if err2 != nil {
		t.Fatalf("failed to create second test file: %v", err2)
	}
	defer os.Remove(path2) //nolint:errcheck //don't care

	const emptyFileName = "test_empty_file.txt"
	emptyPath := filepath.Join(configDir, emptyFileName)
	if err := os.WriteFile(emptyPath, nil, 0600); err != nil {
		t.Fatalf("failed to create empty test file: %v", err)
	}
	defer os.Remove(emptyPath) //nolint:errcheck //don't care

	const crlfFileName = "test_crlf_file.txt"
	crlfPath := filepath.Join(configDir, crlfFileName)
	if err := os.WriteFile(crlfPath, []byte("secret\r\n"), 0600); err != nil {
		t.Fatalf("failed to create CRLF test file: %v", err)
	}
	defer os.Remove(crlfPath) //nolint:errcheck //don't care

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
		{"Valid file tag with spaces", "  {file:test_secret_file_123.txt}  ", "  secret_from_file  ", true, false},
		{"Invalid file tag (path traversal)", "{file:../secret.txt}", "", true, true},
		{"Invalid file tag (not found)", "{file:does_not_exist.txt}", "", true, true},
		{"Valid env tag", "{env:TEST_ENV_VAR}", "secret_from_env", true, false},
		{"Valid env tag with spaces", "  {env:TEST_ENV_VAR}  ", "  secret_from_env  ", true, false},
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

		// --- Inline / Multiple Template Edge Cases ---
		{
			name:      "Multiple env tags",
			input:     "{env:TEST_ENV_VAR}/{env:TEST_ENV_VAR}",
			wantVal:   "secret_from_env/secret_from_env",
			wantIsTag: true,
			wantErr:   false,
		},
		{
			name:      "Multiple distinct file tags",
			input:     "https://{file:test_secret_file_123.txt}/{file:test_secret_file_456.txt}",
			wantVal:   "https://secret_from_file/another_secret_content",
			wantIsTag: true,
			wantErr:   false,
		},
		{
			name:      "Mixed file and env tags",
			input:     "http://{env:TEST_ENV_VAR}/{file:test_secret_file_123.txt}",
			wantVal:   "http://secret_from_env/secret_from_file",
			wantIsTag: true,
			wantErr:   false,
		},
		{
			name:      "Multiple tags surrounded by literal text",
			input:     "Prefix-{env:TEST_ENV_VAR}-Middle-{file:test_secret_file_123.txt}-Suffix",
			wantVal:   "Prefix-secret_from_env-Middle-secret_from_file-Suffix",
			wantIsTag: true,
			wantErr:   false,
		},
		{
			name:      "Multiple tags where one is an invalid env",
			input:     "{env:TEST_ENV_VAR}/{env:MISSING_ENV_VAR_123}",
			wantVal:   "",
			wantIsTag: true,
			wantErr:   true,
		},
		{
			name:      "Multiple tags where one is a missing file",
			input:     "{file:test_secret_file_123.txt}/{file:does_not_exist.txt}",
			wantVal:   "",
			wantIsTag: true,
			wantErr:   true,
		},
		{
			name:      "No tags but literal curly lookalikes",
			input:     "this {is not a valid:tag}",
			wantVal:   "this {is not a valid:tag}",
			wantIsTag: false,
			wantErr:   false,
		},
		{
			name:      "Invalid prefix spacing is rejected as literal",
			input:     "{file : test_secret_file_123.txt}",
			wantVal:   "{file : test_secret_file_123.txt}",
			wantIsTag: false,
			wantErr:   false,
		},
		{
			name:      "Adjacent tags",
			input:     "{env:TEST_ENV_VAR}{file:test_secret_file_123.txt}",
			wantVal:   "secret_from_envsecret_from_file",
			wantIsTag: true,
			wantErr:   false,
		},
		{
			name:      "Tag at beginning",
			input:     "{env:TEST_ENV_VAR}suffix",
			wantVal:   "secret_from_envsuffix",
			wantIsTag: true,
			wantErr:   false,
		},
		{
			name:      "Tag at end",
			input:     "prefix{env:TEST_ENV_VAR}",
			wantVal:   "prefixsecret_from_env",
			wantIsTag: true,
			wantErr:   false,
		},
		{
			name:      "Duplicate file tags",
			input:     "{file:test_secret_file_123.txt}{file:test_secret_file_123.txt}",
			wantVal:   "secret_from_filesecret_from_file",
			wantIsTag: true,
			wantErr:   false,
		},
		{
			name:      "Empty file",
			input:     "{file:test_empty_file.txt}",
			wantVal:   "",
			wantIsTag: true,
			wantErr:   false,
		},
		{
			name:      "CRLF file trimmed",
			input:     "{file:test_crlf_file.txt}",
			wantVal:   "secret",
			wantIsTag: true,
			wantErr:   false,
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
				t.Errorf("resolveTag() gotVal = %q, want %q", gotVal, tt.wantVal)
			}
		})
	}
}

func TestResolveConfigTags(t *testing.T) {
	const testFileName3 = "test_upstream_123.txt"
	configDir := filepath.Dir(configFileName)
	path := filepath.Join(configDir, testFileName3)
	if err := os.WriteFile(path, []byte("https://8.8.8.8/dns-query\n"), 0600); err != nil {
		t.Fatalf("failed to create upstream test file: %v", err)
	}
	defer os.Remove(path) //nolint:errcheck // don't care

	t.Setenv("TEST_WEBUI_PWD", "hashed_pwd_xyz")

	raw := &Config{
		ListenDNS:         "127.0.0.1:53",
		CacheMinTTL:       123,
		ExtraSafety:       false,
		WebUIPasswordHash: "{env:TEST_WEBUI_PWD}",
		UpstreamURLs: []string{
			"https://9.9.9.9/dns-query",
			"{file:test_upstream_123.txt}",
			"https://{env:TEST_WEBUI_PWD}.example.com/api?endpoint={file:test_upstream_123.txt}", // Multiple inline mix
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
	if raw.UpstreamURLs[2] != "https://{env:TEST_WEBUI_PWD}.example.com/api?endpoint={file:test_upstream_123.txt}" {
		t.Errorf("raw.UpstreamURLs[2] was mutated: got %q", raw.UpstreamURLs[2])
	}
	if raw.ListenDNS != "127.0.0.1:53" {
		t.Errorf("raw.ListenDNS was mutated: got %q", raw.ListenDNS)
	}

	// Result must not alias the original slices.
	resolved.UpstreamURLs[0] = "modified"

	if raw.UpstreamURLs[0] == "modified" {
		t.Fatal("resolved.UpstreamURLs aliases raw.UpstreamURLs")
	}

	if resolved.CacheMinTTL != 123 {
		t.Errorf("CacheMinTTL changed: got %d want %d", resolved.CacheMinTTL, 123)
	}

	if resolved.ExtraSafety != false {
		t.Errorf("ExtraSafety changed unexpectedly")
	}

	// resolved has real values.
	if resolved.WebUIPasswordHash != "hashed_pwd_xyz" {
		t.Errorf("resolved.WebUIPasswordHash = %q, want %q", resolved.WebUIPasswordHash, "hashed_pwd_xyz")
	}
	if resolved.UpstreamURLs[1] != "https://8.8.8.8/dns-query" {
		t.Errorf("resolved.UpstreamURLs[1] = %q, want %q", resolved.UpstreamURLs[1], "https://8.8.8.8/dns-query")
	}
	if resolved.UpstreamURLs[2] != "https://hashed_pwd_xyz.example.com/api?endpoint=https://8.8.8.8/dns-query" {
		t.Errorf("resolved.UpstreamURLs[2] = %q, want %q", resolved.UpstreamURLs[2], "https://hashed_pwd_xyz.example.com/api?endpoint=https://8.8.8.8/dns-query")
	}
	if resolved.ListenDNS != "127.0.0.1:53" {
		t.Errorf("resolved.ListenDNS = %q, want %q (literal should pass through)", resolved.ListenDNS, "127.0.0.1:53")
	}

	// resolved is a deep copy; mutating it must not affect raw.
	resolved.ListenDNS = "0.0.0.0:53"
	if raw.ListenDNS != "127.0.0.1:53" {
		t.Errorf("raw.ListenDNS changed after mutating resolved: got %q", raw.ListenDNS)
	}

	// Error case: single unresolvable token.
	bad := &Config{WebUIPasswordHash: "{env:DOES_NOT_EXIST_123456}"}
	if _, err2 := resolveConfigTags(bad); err2 == nil {
		t.Error("expected error for missing env var, got nil")
	}
	// bad must still be unmodified after an error.
	if bad.WebUIPasswordHash != "{env:DOES_NOT_EXIST_123456}" {
		t.Errorf("bad.WebUIPasswordHash was mutated despite error: got %q", bad.WebUIPasswordHash)
	}

	// Error case: multi-tag template with one unresolvable token.
	badMulti := &Config{
		UpstreamURLs: []string{"https://{env:TEST_WEBUI_PWD}.com/{env:DOES_NOT_EXIST_ABC_123}"},
	}
	if _, errMulti := resolveConfigTags(badMulti); errMulti == nil {
		t.Error("expected error for multi-tag slice string containing an unresolvable env token, got nil")
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

func TestResolveConfigTags_NilSlicesRemainNil(t *testing.T) {
	raw := &Config{}

	resolved, err := resolveConfigTags(raw)
	if err != nil {
		t.Fatalf("resolveConfigTags failed: %v", err)
	}

	if resolved.UpstreamURLs != nil {
		t.Fatal("UpstreamURLs should remain nil")
	}

	if resolved.UpstreamSNIHostnames != nil {
		t.Fatal("UpstreamSNIHostnames should remain nil")
	}
}
