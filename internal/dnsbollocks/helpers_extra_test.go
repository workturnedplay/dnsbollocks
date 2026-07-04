//go:build windows
// +build windows

package dnsbollocks

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"log/slog"
)

// ── isLoopbackBindHost ──────────────────────────────────────────────────────

func TestIsLoopbackBindHost(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected bool
	}{
		{"loopback with port", "127.0.0.1:53", true},
		{"loopback no port", "127.0.0.1", true},
		{"localhost lowercase", "localhost:8080", true},
		{"localhost uppercase", "LOCALHOST:8080", true},
		{"localhost mixed case", "LocalHost:8080", true},
		{"IPv6 loopback with port", "[::1]:8080", true},
		{"IPv6 loopback no port", "::1", true},
		{"any-interface IPv4", "0.0.0.0:53", false},
		{"any-interface IPv6", "[::]:53", false},
		{"LAN IP", "192.168.1.5:53", false},
		{"public IP", "8.8.8.8:443", false},
		{"bare hostname (not localhost)", "example.com:53", false},
		{"empty host with port", ":53", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLoopbackBindHost(tt.addr)
			if got != tt.expected {
				t.Errorf("isLoopbackBindHost(%q) = %v, want %v", tt.addr, got, tt.expected)
			}
		})
	}
}

// ── retryFileOp ──────────────────────────────────────────────────────────────

func TestRetryFileOp_SucceedsFirstTry(t *testing.T) {
	calls := 0
	err := retryFileOp(3, time.Millisecond, func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if calls != 1 {
		t.Errorf("expected exactly 1 call, got %d", calls)
	}
}

func TestRetryFileOp_SucceedsAfterRetries(t *testing.T) {
	calls := 0
	err := retryFileOp(5, time.Millisecond, func() error {
		calls++
		if calls < 3 {
			return errors.New("transient failure")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected eventual success, got %v", err)
	}
	if calls != 3 {
		t.Errorf("expected exactly 3 calls, got %d", calls)
	}
}

func TestRetryFileOp_ExhaustsAndReturnsLastError(t *testing.T) {
	calls := 0
	sentinel := errors.New("permanent failure")
	err := retryFileOp(4, time.Millisecond, func() error {
		calls++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error to propagate, got %v", err)
	}
	if calls != 4 {
		t.Errorf("expected exactly 4 calls (maxAttempts), got %d", calls)
	}
}

func TestRetryFileOp_PanicsOnInvalidMaxAttempts(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for maxAttempts < 1, got none")
		}
	}()
	_ = retryFileOp(0, time.Millisecond, func() error { return nil })
}

// ── truncateStagingFileToZero ────────────────────────────────────────────────

func TestTruncateStagingFileToZero_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "staging.tmp")
	if err := os.WriteFile(path, []byte("some leftover garbage data"), 0644); err != nil {
		t.Fatalf("setup write failed: %v", err)
	}

	if err := truncateStagingFileToZero(path, 0644); err != nil {
		t.Fatalf("truncateStagingFileToZero failed: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed after truncate: %v", err)
	}
	if fi.Size() != 0 {
		t.Errorf("expected file size 0 after truncate, got %d", fi.Size())
	}
}

func TestTruncateStagingFileToZero_NonexistentFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.tmp")

	err := truncateStagingFileToZero(path, 0644)
	if err == nil {
		t.Fatal("expected error for nonexistent staging file, got nil")
	}
	if !strings.Contains(err.Error(), "open for truncate failed") {
		t.Errorf("expected 'open for truncate failed' in error, got: %v", err)
	}
}

// ── writeSyncedFile ──────────────────────────────────────────────────────────

func TestWriteSyncedFile_CreatesAndWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	data := []byte("hello synced world")

	err := writeSyncedFile(path, data, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("writeSyncedFile failed: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read back written file: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("content mismatch: got %q, want %q", got, data)
	}
}

func TestWriteSyncedFile_TruncatesExistingContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")

	if err := writeSyncedFile(path, []byte("first longer payload here"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644); err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if err := writeSyncedFile(path, []byte("short"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644); err != nil {
		t.Fatalf("second write failed: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(got) != "short" {
		t.Errorf("expected truncated content %q, got %q", "short", got)
	}
}

func TestWriteSyncedFile_OpenFailure(t *testing.T) {
	dir := t.TempDir()
	// Parent directory component doesn't exist -> OpenFile must fail.
	path := filepath.Join(dir, "nonexistent-subdir", "out.txt")

	err := writeSyncedFile(path, []byte("data"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err == nil {
		t.Fatal("expected error for missing parent directory, got nil")
	}
	if !strings.Contains(err.Error(), "open failed") {
		t.Errorf("expected 'open failed' in error, got: %v", err)
	}
}

// ── getJSONTagByOffset ───────────────────────────────────────────────────────

func TestGetJSONTagByOffset_ValidField(t *testing.T) {
	tests := []struct {
		name     string
		offset   uintptr
		expected string
	}{
		{"ListenDNS", unsafe.Offsetof(Config{}.ListenDNS), "listen_dns"},
		{"ListenDoH", unsafe.Offsetof(Config{}.ListenDoH), "listen_doh"},
		{"WebUIPasswordHash", unsafe.Offsetof(Config{}.WebUIPasswordHash), "webui_password_hash"},
		{"ExtraSafety", unsafe.Offsetof(Config{}.ExtraSafety), "extra_safety"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getJSONTagByOffset(tt.offset)
			if got != tt.expected {
				t.Errorf("getJSONTagByOffset(%s offset) = %q, want %q", tt.name, got, tt.expected)
			}
		})
	}
}

func TestGetJSONTagByOffset_PanicsOnJSONDashField(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for a field tagged json:\"-\", got none")
		}
	}()
	// BlockIPv4Parsed is tagged `json:"-"`.
	_ = getJSONTagByOffset(unsafe.Offsetof(Config{}.BlockIPv4Parsed))
}

// ── formatColorTags ──────────────────────────────────────────────────────────

func TestFormatColorTags_NoTagsUnchanged(t *testing.T) {
	s := "plain message with no angle brackets"
	if got := formatColorTags(s, "BASE"); got != s {
		t.Errorf("expected unchanged string, got %q", got)
	}
}

func TestFormatColorTags_UnknownTagLeftLiteral(t *testing.T) {
	s := "plain <unknowntag> text"
	if got := formatColorTags(s, "BASE"); got != s {
		t.Errorf("expected unrecognized tag to remain literal, got %q", got)
	}
}

func TestFormatColorTags_KnownColors(t *testing.T) {
	tests := []struct {
		tag  string
		ansi string
	}{
		{"green", "\x1b[92m"},
		{"red", "\x1b[91m"},
		{"yellow", "\x1b[93m"},
		{"cyan", "\x1b[96m"},
		{"gray", "\x1b[90m"},
		{"white", "\x1b[97m"},
		{"magenta", "\x1b[95m"},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			in := "<" + tt.tag + ">hi</" + tt.tag + ">"
			want := tt.ansi + "hi" + "BASE"
			got := formatColorTags(in, "BASE")
			if got != want {
				t.Errorf("formatColorTags(%q) = %q, want %q", in, got, want)
			}
		})
	}
}

// ── stripColorTags ───────────────────────────────────────────────────────────

func TestStripColorTags_StringWithTags(t *testing.T) {
	in := slog.String("msg", "hello <green>world</green>")
	out := stripColorTags(nil, in)
	if out.Value.Kind() != slog.KindString {
		t.Fatalf("expected string kind, got %v", out.Value.Kind())
	}
	got := out.Value.String()
	if strings.Contains(got, "<") {
		t.Errorf("expected all tags stripped, got %q", got)
	}
	if got != "hello world" {
		t.Errorf("expected %q, got %q", "hello world", got)
	}
}

func TestStripColorTags_StringWithoutTagsUnchanged(t *testing.T) {
	in := slog.String("msg", "no tags here")
	out := stripColorTags(nil, in)
	if out.Value.String() != "no tags here" {
		t.Errorf("expected unchanged string, got %q", out.Value.String())
	}
}

func TestStripColorTags_AnyErrorWithTags(t *testing.T) {
	in := slog.Any("err", errors.New("boom <red>failure</red>"))
	out := stripColorTags(nil, in)
	if out.Value.Kind() != slog.KindString {
		t.Fatalf("expected error to be converted to string kind, got %v", out.Value.Kind())
	}
	if got := out.Value.String(); got != "boom failure" {
		t.Errorf("expected %q, got %q", "boom failure", got)
	}
}

func TestStripColorTags_AnyNonErrorUnaffected(t *testing.T) {
	// A struct type isn't one of slog.AnyValue's fast-pathed kinds (string,
	// int, bool, error, etc.), so it stays as KindAny — this is the actual
	// branch stripColorTags takes when a.Value.Kind() == slog.KindAny but
	// the type assertion to `error` fails.
	type customPayload struct {
		X int
	}
	original := customPayload{X: 42}
	in := slog.Any("data", original)

	if in.Value.Kind() != slog.KindAny {
		t.Fatalf("test setup invalid: slog.Any(customPayload) produced kind %v, want KindAny", in.Value.Kind())
	}

	out := stripColorTags(nil, in)
	if out.Value.Kind() != slog.KindAny {
		t.Errorf("expected non-error Any value to remain KindAny, got kind %v", out.Value.Kind())
	}
	got, ok := out.Value.Any().(customPayload)
	if !ok {
		t.Fatalf("expected underlying value to still be customPayload, got %T", out.Value.Any())
	}
	if got != original {
		t.Errorf("expected value unchanged, got %+v, want %+v", got, original)
	}
}

// ── SafeErr / SafeErr2 / SafeAddr ────────────────────────────────────────────

func TestSafeErr_Nil(t *testing.T) {
	a := SafeErr(nil)
	if a.Key != "err" {
		t.Errorf("expected key 'err', got %q", a.Key)
	}
	if a.Value.String() != "<nil>" {
		t.Errorf("expected \"<nil>\", got %q", a.Value.String())
	}
}

func TestSafeErr_NonNil(t *testing.T) {
	a := SafeErr(errors.New("boom"))
	if a.Value.String() != "boom" {
		t.Errorf("expected \"boom\", got %q", a.Value.String())
	}
}

func TestSafeErr2_CustomKey(t *testing.T) {
	a := SafeErr2("custom_key", errors.New("oops"))
	if a.Key != "custom_key" {
		t.Errorf("expected key 'custom_key', got %q", a.Key)
	}
	if a.Value.String() != "oops" {
		t.Errorf("expected \"oops\", got %q", a.Value.String())
	}
}

func TestSafeAddr_Nil(t *testing.T) {
	a := SafeAddr("clientAddr", nil)
	if a.Value.String() != "<nil>" {
		t.Errorf("expected \"<nil>\", got %q", a.Value.String())
	}
}

func TestSafeAddr_NonNil(t *testing.T) {
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:53")
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	a := SafeAddr("clientAddr", addr)
	if a.Value.String() != addr.String() {
		t.Errorf("expected %q, got %q", addr.String(), a.Value.String())
	}
}

// ── SafeStringSlice / SafeSlice ──────────────────────────────────────────────

func TestSafeStringSlice_Empty(t *testing.T) {
	a := SafeStringSlice("items", nil)
	if a.Value.Kind() != slog.KindGroup {
		t.Fatalf("expected group kind, got %v", a.Value.Kind())
	}
	if len(a.Value.Group()) != 0 {
		t.Errorf("expected empty group for nil slice, got %d attrs", len(a.Value.Group()))
	}
}

func TestSafeStringSlice_NonEmpty(t *testing.T) {
	items := []string{"alpha", "beta", "gamma"}
	a := SafeStringSlice("items", items)
	group := a.Value.Group()
	if len(group) != len(items) {
		t.Fatalf("expected %d attrs, got %d", len(items), len(group))
	}
	for i, want := range items {
		got := group[i].Value.String()
		if got != want {
			t.Errorf("group[%d] = %q, want %q", i, got, want)
		}
	}
}

func TestSafeSlice_CustomMapper(t *testing.T) {
	ips := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")}
	a := SafeSlice("ips", ips, net.IP.String)
	group := a.Value.Group()
	if len(group) != 2 {
		t.Fatalf("expected 2 attrs, got %d", len(group))
	}
	if group[0].Value.String() != "1.1.1.1" {
		t.Errorf("group[0] = %q, want %q", group[0].Value.String(), "1.1.1.1")
	}
	if group[1].Value.String() != "8.8.8.8" {
		t.Errorf("group[1] = %q, want %q", group[1].Value.String(), "8.8.8.8")
	}
}

// ── getNextLogBackupName ─────────────────────────────────────────────────────

func TestGetNextLogBackupName_Sequential(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "app.log")

	first := getNextLogBackupName(base)
	if first != base+".1" {
		t.Fatalf("expected %q, got %q", base+".1", first)
	}

	if err := os.WriteFile(first, []byte("x"), 0644); err != nil {
		t.Fatalf("setup write failed: %v", err)
	}

	second := getNextLogBackupName(base)
	if second != base+".2" {
		t.Fatalf("expected %q, got %q", base+".2", second)
	}

	if err := os.WriteFile(second, []byte("x"), 0644); err != nil {
		t.Fatalf("setup write failed: %v", err)
	}

	third := getNextLogBackupName(base)
	if third != base+".3" {
		t.Fatalf("expected %q, got %q", base+".3", third)
	}
}

func TestGetNextLogBackupName_NoExistingBackups(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "fresh.log")

	got := getNextLogBackupName(base)
	if got != base+".1" {
		t.Errorf("expected %q, got %q", base+".1", got)
	}
}

// ── getConfigFields ──────────────────────────────────────────────────────────

func TestGetConfigFields(t *testing.T) {
	cfg := Config{
		ListenDNS:                "127.0.0.1:53",
		GlobalRateQPS:            42,
		AllowRunAsAdmin:          true,
		UpstreamURLs:             []string{"https://1.1.1.1/dns-query", "https://9.9.9.9/dns-query"},
		LocalHostsOverrideTTLSec: 300,
		// UpstreamSNIHostnames deliberately left nil to exercise the empty-[]string case.
	}
	var liveConfig atomic.Pointer[Config]
	liveConfig.Store(&cfg)
	var liveLogger atomic.Pointer[slog.Logger]
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	liveLogger.Store(logger)
	ui := &AdminUI{liveConfig: &liveConfig, liveLogger: &liveLogger}

	fields := ui.getConfigFields()

	byKey := make(map[string]ConfigFieldView, len(fields))
	for _, f := range fields {
		if _, dup := byKey[f.Key]; dup {
			t.Fatalf("duplicate key %q in getConfigFields output", f.Key)
		}
		byKey[f.Key] = f
	}

	tests := []struct {
		key      string
		wantVal  string
		wantType string
	}{
		{"listen_dns", "127.0.0.1:53", "string"},
		{"qps_rate_globally", "42", "int"},
		{"allow_run_as_admin", "true", "bool"},
		{"upstream_urls", "https://1.1.1.1/dns-query, https://9.9.9.9/dns-query", "[]string"},
		// uint32 fields are labeled "int" by the current implementation — this
		// locks down that (slightly quirky) existing behavior explicitly.
		{"localhosts_override_ttl_sec", "300", "int"},
		// Nil []string must render as an empty string, not "<nil>" or panic.
		{"upstream_sni_hostnames", "", "[]string"},
	}
	for _, tt := range tests {
		f, ok := byKey[tt.key]
		if !ok {
			t.Errorf("expected key %q in output, missing", tt.key)
			continue
		}
		if f.Value != tt.wantVal {
			t.Errorf("key %q: value = %q, want %q", tt.key, f.Value, tt.wantVal)
		}
		if f.Type != tt.wantType {
			t.Errorf("key %q: type = %q, want %q", tt.key, f.Type, tt.wantType)
		}
	}

	// Fields tagged `json:"-"` (e.g. BlockIPv4Parsed, UpstreamURLsParsed) must
	// never leak into the WebUI-facing output.
	forbiddenKeys := []string{"BlockIPv4Parsed", "BlockIPv6Parsed", "UpstreamURLsParsed", "UpstreamIPs", "UpstreamSNIs"}
	for _, bad := range forbiddenKeys {
		if _, present := byKey[bad]; present {
			t.Errorf("field tagged json:\"-\" (%q) leaked into getConfigFields output", bad)
		}
	}

	// Output must be sorted ascending by Key (per the sort.Slice call in getConfigFields).
	for i := 1; i < len(fields); i++ {
		if fields[i-1].Key > fields[i].Key {
			t.Fatalf("fields not sorted: %q came before %q", fields[i-1].Key, fields[i].Key)
		}
	}
}

func TestGetConfigFields_NoDuplicateKeysAcrossFullDefaultConfig(t *testing.T) {
	// Run against a fully-populated defaultConfig() to catch any future field
	// additions that might collide on JSON tag or break the reflection walk.
	cfg := defaultConfig()
	var liveConfig atomic.Pointer[Config]
	liveConfig.Store(&cfg)
	var liveLogger atomic.Pointer[slog.Logger]
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	liveLogger.Store(logger)
	ui := &AdminUI{liveConfig: &liveConfig, liveLogger: &liveLogger}

	fields := ui.getConfigFields()
	if len(fields) == 0 {
		t.Fatal("expected non-empty field list from defaultConfig()")
	}

	seen := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		if _, dup := seen[f.Key]; dup {
			t.Fatalf("duplicate key %q found in full defaultConfig() field walk", f.Key)
		}
		seen[f.Key] = struct{}{}
		if f.Type == "" {
			t.Errorf("field %q has empty Type", f.Key)
		}
	}
}

func TestGetConfigFields_NoUnsupportedWarnings(t *testing.T) {
	// 1. Create a buffer to capture logs instead of discarding them
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// 2. Use your actual defaultConfig() to test your real codebase surface area
	cfg := defaultConfig()

	var liveConfig atomic.Pointer[Config]
	liveConfig.Store(&cfg)

	var liveLogger atomic.Pointer[slog.Logger]
	liveLogger.Store(logger)

	ui := &AdminUI{
		liveConfig: &liveConfig,
		liveLogger: &liveLogger,
	}

	// 3. Run the reflection loop
	fields := ui.getConfigFields()
	if len(fields) == 0 {
		t.Fatal("expected fields to be returned")
	}

	// 4. Assert that NO warnings were thrown.
	// If this buffer is not empty, it means a field was added to Config
	// that your switch statement doesn't explicitly know how to render yet.
	if logBuf.Len() > 0 {
		t.Errorf("Reflection loop hit an unhandled type or slice. Logs:\n%s", logBuf.String())
	}
}

// ── SafeRequestAttr ──────────────────────────────────────────────────────────

func TestSafeRequestAttr_Nil(t *testing.T) {
	a := SafeRequestAttr("query", nil)
	if a.Key != "query" {
		t.Errorf("expected key %q, got %q", "query", a.Key)
	}
	if a.Value.Kind() != slog.KindGroup {
		t.Fatalf("expected group kind, got %v", a.Value.Kind())
	}
	if len(a.Value.Group()) != 0 {
		t.Errorf("expected empty group for nil request, got %d attrs", len(a.Value.Group()))
	}
}

func TestSafeRequestAttr_NonNil(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://example.invalid/dns-query?x=1", http.NoBody)
	req.Host = "example.invalid"
	req.Header.Set("Content-Type", "application/dns-message")

	a := SafeRequestAttr("query", req)
	if a.Value.Kind() != slog.KindGroup {
		t.Fatalf("expected group kind, got %v", a.Value.Kind())
	}

	got := make(map[string]string)
	for _, attr := range a.Value.Group() {
		got[attr.Key] = attr.Value.String()
	}

	tests := map[string]string{
		"method":       http.MethodPost,
		"proto":        req.Proto,
		"host":         "example.invalid",
		"content_type": "application/dns-message",
	}
	for key, want := range tests {
		if got[key] != want {
			t.Errorf("attr %q = %q, want %q", key, got[key], want)
		}
	}
	if !strings.Contains(got["url"], "/dns-query") {
		t.Errorf("expected url attr to contain path, got %q", got["url"])
	}
}

func TestSafeRequestAttr_MissingContentTypeIsEmpty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.invalid/dns-query", http.NoBody)
	a := SafeRequestAttr("query", req)

	for _, attr := range a.Value.Group() {
		if attr.Key == "content_type" {
			if attr.Value.String() != "" {
				t.Errorf("expected empty content_type when header absent, got %q", attr.Value.String())
			}
			return
		}
	}
	t.Error("content_type attr not found in group")
}

// ── SafeRuleAttr ─────────────────────────────────────────────────────────────

func TestSafeRuleAttr(t *testing.T) {
	rule := RuleEntry{ID: "abc123", Pattern: "*.example.com", Enabled: true}
	a := SafeRuleAttr("rule", rule)

	if a.Key != "rule" {
		t.Errorf("expected key %q, got %q", "rule", a.Key)
	}
	if a.Value.Kind() != slog.KindGroup {
		t.Fatalf("expected group kind, got %v", a.Value.Kind())
	}

	got := make(map[string]string)
	for _, attr := range a.Value.Group() {
		got[attr.Key] = attr.Value.String()
	}

	if got["id"] != "abc123" {
		t.Errorf("id attr = %q, want %q", got["id"], "abc123")
	}
	if got["pattern"] != "*.example.com" {
		t.Errorf("pattern attr = %q, want %q", got["pattern"], "*.example.com")
	}
	if got["enabled"] != "true" {
		t.Errorf("enabled attr = %q, want %q", got["enabled"], "true")
	}
}

func TestSafeRuleAttr_DisabledFalseValueRendersCorrectly(t *testing.T) {
	rule := RuleEntry{ID: "id2", Pattern: "blocked.example.com", Enabled: false}
	a := SafeRuleAttr("rule", rule)

	for _, attr := range a.Value.Group() {
		if attr.Key == "enabled" {
			if attr.Value.String() != "false" {
				t.Errorf("enabled attr = %q, want %q", attr.Value.String(), "false")
			}
			return
		}
	}
	t.Error("enabled attr not found in group")
}

// RuleEntry.LogValue() is functionally identical to SafeRuleAttr but reached
// via slog's automatic LogValuer interface instead of a direct helper call —
// worth covering separately since a future refactor could let the two drift.
func TestRuleEntry_LogValue(t *testing.T) {
	rule := RuleEntry{ID: "xyz", Pattern: "foo.com", Enabled: true}
	v := rule.LogValue()
	if v.Kind() != slog.KindGroup {
		t.Fatalf("expected group kind, got %v", v.Kind())
	}

	got := make(map[string]string)
	for _, attr := range v.Group() {
		got[attr.Key] = attr.Value.String()
	}
	if got["id"] != "xyz" || got["pattern"] != "foo.com" || got["enabled"] != "true" {
		t.Errorf("unexpected LogValue group contents: %+v", got)
	}
}
