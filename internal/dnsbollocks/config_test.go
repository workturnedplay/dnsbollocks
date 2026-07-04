//go:build windows
// +build windows

package dnsbollocks

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
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

func TestValidateRulePattern2(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		wantErr string
	}{
		{
			name:    "lowercase check happens before illegal character check",
			pattern: "Example/com",
			wantErr: "pattern must be lowercase",
		},
		{
			name:    "illegal character after lowercase passes",
			pattern: "example/com",
			wantErr: "pattern contains illegal characters",
		},
		{
			name:    "uppercase takes precedence over illegal characters",
			pattern: "Example/com",
			wantErr: "pattern must be lowercase",
		},
		{
			name:    "uppercase unicode takes precedence over illegal characters",
			pattern: "Éxample.com",
			wantErr: "pattern must be lowercase",
		},
		{
			name:    "only illegal characters when already lowercase",
			pattern: "example .com",
			wantErr: "pattern contains illegal characters",
		},
		{
			name:    "only illegal characters when already lowercase",
			pattern: "éxample.com",
			wantErr: "pattern contains illegal characters",
		},
		{
			name:    "valid hostname",
			pattern: "example.com",
		},
		{
			name:    "valid wildcard",
			pattern: "*.example.com",
		},
		{
			name:    "valid underscore",
			pattern: "_service._tcp.example.com",
		},
		{
			name:    "empty",
			pattern: "",
			wantErr: "pattern cannot be empty",
		},
		{
			name:    "uppercase",
			pattern: "Example.com",
			wantErr: "pattern must be lowercase",
		},
		{
			name:    "mixed case",
			pattern: "foo.Bar",
			wantErr: "pattern must be lowercase",
		},
		{
			name:    "space",
			pattern: "example .com",
			wantErr: "pattern contains illegal characters",
		},
		{
			name:    "slash",
			pattern: "example/com",
			wantErr: "pattern contains illegal characters",
		},
		{
			name:    "unicode",
			pattern: "éxample.com",
			wantErr: "pattern contains illegal characters",
		},
		{
			name:    "leading space",
			pattern: " example.com",
			wantErr: "pattern contains illegal characters",
		},
		{
			name:    "trailing space",
			pattern: "example.com ",
			wantErr: "pattern contains illegal characters",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateRulePattern(tc.pattern)

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateRulePattern(%q) returned unexpected error: %v", tc.pattern, err)
				}
				return
			}

			if err == nil {
				t.Fatalf("validateRulePattern(%q) returned nil, want %q", tc.pattern, tc.wantErr)
			}
			if err.Error() != tc.wantErr {
				t.Fatalf("validateRulePattern(%q) error = %q, want %q", tc.pattern, err.Error(), tc.wantErr)
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

func TestDefaultConfig_AllJSONFieldsHaveExplicitDefaults(t *testing.T) { //XXX: this test is obsoleted by the next one which is better as it doesn't need a whitelist!
	t.Parallel()

	/*
		The whitelist intentionalZeroDefaults is needed because the following are are see as value.IsZero()
		0
		false
		""
		nil
		time.Duration(0)
		[]string(nil)
		map[string]int(nil)
		struct{}{}
	*/
	intentionalZeroDefaults := map[string]struct{}{

		"AllowRunAsAdmin":   {},
		"WebUIPasswordHash": {},
	}

	cfg := defaultConfig()

	cfgValue := reflect.ValueOf(cfg)
	cfgType := cfgValue.Type()

	seenJSONTags := make(map[string]string, cfgType.NumField())

	for i := 0; i < cfgType.NumField(); i++ {
		field := cfgType.Field(i)

		jsonTag, _, _ := strings.Cut(field.Tag.Get("json"), ",") // handle things like `json:"listen_dns,omitempty"`
		//jsonTag := field.Tag.Get("json")
		if jsonTag == "" {
			t.Fatalf("Config.%s is missing a json tag", field.Name)
		}
		if jsonTag == "-" {
			continue
		}

		if previousField, exists := seenJSONTags[jsonTag]; exists {
			t.Fatalf(
				"duplicate json tag %q used by both Config.%s and Config.%s",
				jsonTag,
				previousField,
				field.Name,
			)
		}
		seenJSONTags[jsonTag] = field.Name

		value := cfgValue.Field(i)

		if value.IsZero() {
			if _, ok := intentionalZeroDefaults[field.Name]; !ok {
				t.Errorf(
					"defaultConfig() left Config.%s (%q) at its zero value (%#v); every persisted config field must have an explicit default",
					field.Name,
					jsonTag,
					value.Interface(),
				)
			}
		}
	}

	if t.Failed() {
		t.Fatal("defaultConfig() is missing one or more explicit defaults")
	}
}

func TestDefaultConfig_InitializesEveryConfigField(t *testing.T) {
	t.Parallel()
	/*
		// Reflection cannot distinguish an intentionally written zero value (false, "", 0)
		// from an omitted field.
		// That's why here we: Parse the AST instead, and verify that every persisted
		// Config field is explicitly present in the Config{...} literal returned by
		// defaultConfig().

					The nice properties are:

				AllowRunAsAdmin: false passes.
				WebUIPasswordHash: "" passes.
				Omitting either one fails.
				Adding a new Config field but forgetting to initialize it fails.
				Removing a Config field but leaving it in defaultConfig() also fails.
				Reordering fields doesn't matter.
				The actual values don't matter.
	*/
	var literalsFound int
	// var configVarName string

	fset := token.NewFileSet()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}

	pkg, err := parser.ParseDir(fset, filepath.Dir(thisFile), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Every exported Config field that should be initialized.
	expected := make(map[string]struct{})

	cfgType := reflect.TypeOf(Config{})
	for i := 0; i < cfgType.NumField(); i++ {
		f := cfgType.Field(i)

		tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if tag == "-" {
			continue
		}

		expected[f.Name] = struct{}{}
	}

	initialized := make(map[string]struct{})
	foundDefaultConfig := false
	for _, p := range pkg {
		for _, file := range p.Files {
			if foundDefaultConfig {
				break
			}
			ast.Inspect(file, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok || fn.Name.Name != "defaultConfig" {
					return true
				}
				foundDefaultConfig = true

				var configVarName string

				for _, stmt := range fn.Body.List {
					switch s := stmt.(type) {
					case *ast.AssignStmt:
						// cfg := Config{...}
						if len(s.Lhs) == 1 && len(s.Rhs) == 1 {
							lhs, lok := s.Lhs[0].(*ast.Ident)
							cl, rok := s.Rhs[0].(*ast.CompositeLit)

							if lok && rok {
								switch typ := cl.Type.(type) {
								case *ast.Ident:
									if typ.Name != "Config" {
										break
									}
								case *ast.SelectorExpr:
									if typ.Sel.Name != "Config" {
										break
									}
								default:
									break
								}

								literalsFound++
								configVarName = lhs.Name

								for _, elt := range cl.Elts {
									kv, ok := elt.(*ast.KeyValueExpr)
									if !ok {
										t.Fatalf("unexpected non-keyed element in Config literal")
									}

									key, ok := kv.Key.(*ast.Ident)
									if !ok {
										t.Fatalf("unexpected key type %T", kv.Key)
									}

									initialized[key.Name] = struct{}{}
								}

								continue
							}
						}

						// cfg.SomeField = ...
						if configVarName != "" {
							for _, lhs := range s.Lhs {
								sel, ok := lhs.(*ast.SelectorExpr)
								if !ok {
									continue
								}

								obj, ok := sel.X.(*ast.Ident)
								if !ok || obj.Name != configVarName {
									continue
								}

								initialized[sel.Sel.Name] = struct{}{}
							}
						}

					case *ast.DeclStmt:
						// var cfg = Config{...}
						gen, ok := s.Decl.(*ast.GenDecl)
						if !ok || gen.Tok != token.VAR {
							continue
						}

						for _, spec := range gen.Specs {
							vs, ok := spec.(*ast.ValueSpec)
							if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
								continue
							}

							cl, ok := vs.Values[0].(*ast.CompositeLit)
							if !ok {
								continue
							}

							switch typ := cl.Type.(type) {
							case *ast.Ident:
								if typ.Name != "Config" {
									continue
								}
							case *ast.SelectorExpr:
								if typ.Sel.Name != "Config" {
									continue
								}
							default:
								continue
							}

							literalsFound++
							configVarName = vs.Names[0].Name

							for _, elt := range cl.Elts {
								kv, ok := elt.(*ast.KeyValueExpr)
								if !ok {
									t.Fatalf("unexpected non-keyed element in Config literal")
								}

								key, ok := kv.Key.(*ast.Ident)
								if !ok {
									t.Fatalf("unexpected key type %T", kv.Key)
								}

								initialized[key.Name] = struct{}{}
							}
						}
					}
				}
				return false // no need to inspect any other functions
			})
		}
	}
	if literalsFound != 1 {
		t.Fatalf("expected exactly one Config composite literal in defaultConfig(), found %d", literalsFound)
	}
	for field := range expected {
		if _, ok := initialized[field]; !ok {
			t.Errorf("defaultConfig() does not explicitly initialize Config.%s", field)
		}
	}

	for field := range initialized {
		if _, ok := expected[field]; !ok {
			t.Errorf("defaultConfig() initializes unknown Config field %q", field)
		}
	}
}

var cloneReferenceFields = map[string]struct{}{
	"UpstreamURLs":         {},
	"UpstreamSNIHostnames": {},
	"BlockIPv4Parsed":      {},
	"BlockIPv6Parsed":      {},
	"UpstreamURLsParsed":   {},
	"UpstreamIPs":          {},
	"UpstreamSNIs":         {},
}

func TestConfigCloneReferenceFieldCoverage(t *testing.T) {
	typ := reflect.TypeFor[Config]()

	for i := range typ.NumField() {
		field := typ.Field(i)

		switch field.Type.Kind() {
		case reflect.Slice,
			reflect.Map,
			reflect.Pointer,
			reflect.Interface,
			reflect.Func,
			reflect.Chan,
			reflect.UnsafePointer:

			if _, ok := cloneReferenceFields[field.Name]; !ok {
				t.Fatalf(
					"Config field %q is a reference type (%v). "+
						"Update Config.Clone() and cloneReferenceFields.",
					field.Name,
					field.Type,
				)
			}
		}
	}
}

func TestConfigCloneReferenceFieldListHasNoStaleEntries(t *testing.T) {
	typ := reflect.TypeFor[Config]()

	fields := make(map[string]struct{})

	for i := range typ.NumField() {
		field := typ.Field(i)

		switch field.Type.Kind() {
		case reflect.Slice,
			reflect.Map,
			reflect.Pointer,
			reflect.Interface,
			reflect.Func,
			reflect.Chan,
			reflect.UnsafePointer:

			fields[field.Name] = struct{}{}
		}
	}

	for name := range cloneReferenceFields {
		if _, ok := fields[name]; !ok {
			t.Fatalf("%q is listed in cloneReferenceFields but is no longer a reference-type field", name)
		}
	}
}

func TestSanitizeAndValidateConfig_WebUITLSPromotion(t *testing.T) {
	t.Parallel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := defaultConfig()
	cfg.ListenUI = "0.0.0.0:5380"
	cfg.WebUIUseTLS = false
	cfg.WebUIForceTLSOnNonLocalhost = true

	resolved := cfg.Clone()
	raw := cfg.Clone()
	def := defaultConfig()

	modified, err := sanitizeAndValidateConfig(
		log,
		&resolved,
		&raw,
		&def,
		false,
	)
	if err != nil {
		t.Fatalf("sanitizeAndValidateConfig() returned error: %v", err)
	}

	if !modified {
		t.Fatal("expected modified=true")
	}

	if !resolved.WebUIUseTLS {
		t.Fatal("resolved config was not promoted to TLS")
	}

	if !raw.WebUIUseTLS {
		t.Fatal("raw config was not promoted to TLS")
	}
}

func TestSanitizeAndValidateConfig_WebUITLSNotPromotedOnLoopback(t *testing.T) {
	t.Parallel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := defaultConfig()
	cfg.ListenUI = "127.0.0.1:5380"
	cfg.WebUIUseTLS = false
	cfg.WebUIForceTLSOnNonLocalhost = true

	resolved := cfg.Clone()
	raw := cfg.Clone()
	def := defaultConfig()

	modified, err := sanitizeAndValidateConfig(
		log,
		&resolved,
		&raw,
		&def,
		false,
	)
	if err != nil {
		t.Fatalf("sanitizeAndValidateConfig() returned error: %v", err)
	}

	if modified {
		t.Fatal("expected modified=false")
	}

	if resolved.WebUIUseTLS {
		t.Fatal("resolved config unexpectedly enabled TLS")
	}

	if raw.WebUIUseTLS {
		t.Fatal("raw config unexpectedly enabled TLS")
	}
}

func TestSanitizeAndValidateConfig_WebUITLSNotPromotedOnIPv6Loopback(t *testing.T) {
	t.Parallel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := defaultConfig()
	cfg.ListenUI = "[::1]:5380"
	cfg.WebUIUseTLS = false
	cfg.WebUIForceTLSOnNonLocalhost = true

	resolved := cfg.Clone()
	raw := cfg.Clone()
	def := defaultConfig()

	modified, err := sanitizeAndValidateConfig(
		log,
		&resolved,
		&raw,
		&def,
		false,
	)
	if err != nil {
		t.Fatalf("sanitizeAndValidateConfig() returned error: %v", err)
	}

	if modified {
		t.Fatal("expected modified=false")
	}

	if resolved.WebUIUseTLS {
		t.Fatal("resolved config unexpectedly enabled TLS")
	}

	if raw.WebUIUseTLS {
		t.Fatal("raw config unexpectedly enabled TLS")
	}
}

func TestSanitizeAndValidateConfig_BlockModeLowercased(t *testing.T) {
	t.Parallel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := defaultConfig()
	cfg.BlockMode = "Ip_BlocK"

	resolved := cfg.Clone()
	raw := cfg.Clone()
	def := defaultConfig()

	modified, err := sanitizeAndValidateConfig(
		log,
		&resolved,
		&raw,
		&def,
		false,
	)
	if err != nil {
		t.Fatalf("sanitizeAndValidateConfig() returned error: %v", err)
	}

	const want = "ip_block"

	if resolved.BlockMode != want {
		t.Fatalf("resolved BlockMode = %q, want %q", resolved.BlockMode, want)
	}

	if raw.BlockMode != want {
		t.Fatalf("raw BlockMode = %q, want %q", raw.BlockMode, want)
	}

	// Today this normalization doesn't request a save.
	// If that ever changes intentionally, update this expectation.
	if modified {
		t.Fatal("expected modified=false")
	}
}

func TestSanitizeAndValidateConfig_BlockModeAlreadyLowercase(t *testing.T) {
	t.Parallel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := defaultConfig()
	cfg.BlockMode = blockModeIPBlock

	resolved := cfg.Clone()
	raw := cfg.Clone()
	def := defaultConfig()

	modified, err := sanitizeAndValidateConfig(
		log,
		&resolved,
		&raw,
		&def,
		false,
	)
	if err != nil {
		t.Fatalf("sanitizeAndValidateConfig() returned error: %v", err)
	}

	if resolved.BlockMode != blockModeIPBlock {
		t.Fatal("resolved BlockMode unexpectedly changed")
	}

	if raw.BlockMode != blockModeIPBlock {
		t.Fatal("raw BlockMode unexpectedly changed")
	}

	if modified {
		t.Fatal("expected modified=false")
	}
}

func TestSanitizeAndValidateConfig_BlockModeInvalid(t *testing.T) {
	t.Parallel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := defaultConfig()
	cfg.BlockMode = "lolnope"

	resolved := cfg.Clone()
	raw := cfg.Clone()
	def := defaultConfig()

	modified, err := sanitizeAndValidateConfig(
		log,
		&resolved,
		&raw,
		&def,
		false,
	)
	if err == nil {
		t.Fatal("expected error for invalid BlockMode")
	}

	if modified {
		t.Fatal("expected modified=false on validation failure")
	}

	if resolved.BlockMode != "lolnope" {
		t.Fatalf("resolved BlockMode changed unexpectedly: %q", resolved.BlockMode)
	}

	if raw.BlockMode != "lolnope" {
		t.Fatalf("raw BlockMode changed unexpectedly: %q", raw.BlockMode)
	}
}

func TestSanitizeAndValidateConfig_BlockModeAliasesCanonicalized(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{"block_ip", "block_ip"},
		{"ipblock", "ipblock"},
		{"blockip", "blockip"},
		{"uppercase", "IPBLOCK"},
		{"mixed", "BlOcK_iP"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := slog.New(slog.NewTextHandler(io.Discard, nil))

			cfg := defaultConfig()
			cfg.BlockMode = tt.input

			resolved := cfg.Clone()
			raw := cfg.Clone()
			def := defaultConfig()

			modified, err := sanitizeAndValidateConfig(
				log,
				&resolved,
				&raw,
				&def,
				false,
			)
			if err != nil {
				t.Fatalf("sanitizeAndValidateConfig() returned error: %v", err)
			}

			if !modified {
				t.Fatal("expected modified=true")
			}

			const want = blockModeIPBlock

			if resolved.BlockMode != want {
				t.Fatalf("resolved BlockMode = %q, want %q", resolved.BlockMode, want)
			}

			if raw.BlockMode != want {
				t.Fatalf("raw BlockMode = %q, want %q", raw.BlockMode, want)
			}
		})
	}
}

func TestSanitizeAndValidateConfig_BlockModeCanonical(t *testing.T) {
	t.Parallel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := defaultConfig()
	cfg.BlockMode = blockModeIPBlock

	resolved := cfg.Clone()
	raw := cfg.Clone()
	def := defaultConfig()

	modified, err := sanitizeAndValidateConfig(
		log,
		&resolved,
		&raw,
		&def,
		false,
	)
	if err != nil {
		t.Fatalf("sanitizeAndValidateConfig() returned error: %v", err)
	}

	if modified {
		t.Fatal("expected modified=false")
	}

	if resolved.BlockMode != blockModeIPBlock {
		t.Fatalf("resolved BlockMode = %q", resolved.BlockMode)
	}

	if raw.BlockMode != blockModeIPBlock {
		t.Fatalf("raw BlockMode = %q", raw.BlockMode)
	}
}
