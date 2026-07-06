//go:build windows
// +build windows

package dnsbollocks

import (
	"fmt"
	"io"
	"log/slog"
	"testing"
)

// sanitizeHelper is a test-only convenience wrapper around
// sanitizeAndValidateConfig.  It clones cfg into independent resolved and raw
// copies, runs the function against a fresh defaultConfig(), and returns all
// four values so callers can assert whatever they need without repeating the
// boilerplate.  Each call is fully independent: no shared mutable state.
func sanitizeHelper(t *testing.T, cfg Config, isWebUI bool) (resolved, raw Config, modified bool, err error) {
	t.Helper()
	resolved = cfg.Clone()
	raw = cfg.Clone()
	def := defaultConfig()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	modified, err = sanitizeAndValidateConfig(log, &resolved, &raw, &def, isWebUI)
	return
}

// ─── zero / negative → clamped to default ────────────────────────────────────

// TestSanitizeAndValidateConfig_ZeroLimitsClamped verifies that every
// strictly-positive integer field is corrected to its default value when set
// to zero, and that the correction is applied symmetrically to both resolved
// and raw so it will be persisted to disk on the next save.
//
// Idle-timeout fields are excluded here because their clamp target is
// "2 × the corresponding read timeout", not the field's own default —
// see TestSanitizeAndValidateConfig_IdleTimeoutsClampedToDoubleRead.
func TestSanitizeAndValidateConfig_ZeroLimitsClamped(t *testing.T) {
	t.Parallel()

	def := defaultConfig()

	type clampCase struct {
		field   string
		mutate  func(*Config)
		getRes  func(*Config) int
		getRaw  func(*Config) int
		wantVal int
	}

	cases := []clampCase{
		// WebUI timeouts
		{"WebUIReadHeaderTimeoutSec",
			func(c *Config) { c.WebUIReadHeaderTimeoutSec = 0 },
			func(c *Config) int { return c.WebUIReadHeaderTimeoutSec },
			func(c *Config) int { return c.WebUIReadHeaderTimeoutSec },
			def.WebUIReadHeaderTimeoutSec},
		{"WebUIReadTimeoutSec",
			func(c *Config) { c.WebUIReadTimeoutSec = 0 },
			func(c *Config) int { return c.WebUIReadTimeoutSec },
			func(c *Config) int { return c.WebUIReadTimeoutSec },
			def.WebUIReadTimeoutSec},
		{"WebUIWriteTimeoutSec",
			func(c *Config) { c.WebUIWriteTimeoutSec = 0 },
			func(c *Config) int { return c.WebUIWriteTimeoutSec },
			func(c *Config) int { return c.WebUIWriteTimeoutSec },
			def.WebUIWriteTimeoutSec},
		{"WebUIMaxLoginFailures",
			func(c *Config) { c.WebUIMaxLoginFailures = 0 },
			func(c *Config) int { return c.WebUIMaxLoginFailures },
			func(c *Config) int { return c.WebUIMaxLoginFailures },
			def.WebUIMaxLoginFailures},
		{"WebUILoginLockoutSec",
			func(c *Config) { c.WebUILoginLockoutSec = 0 },
			func(c *Config) int { return c.WebUILoginLockoutSec },
			func(c *Config) int { return c.WebUILoginLockoutSec },
			def.WebUILoginLockoutSec},
		// local DoH timeouts
		{"LocalDoHReadHeaderTimeoutSec",
			func(c *Config) { c.LocalDoHReadHeaderTimeoutSec = 0 },
			func(c *Config) int { return c.LocalDoHReadHeaderTimeoutSec },
			func(c *Config) int { return c.LocalDoHReadHeaderTimeoutSec },
			def.LocalDoHReadHeaderTimeoutSec},
		{"LocalDoHReadTimeoutSec",
			func(c *Config) { c.LocalDoHReadTimeoutSec = 0 },
			func(c *Config) int { return c.LocalDoHReadTimeoutSec },
			func(c *Config) int { return c.LocalDoHReadTimeoutSec },
			def.LocalDoHReadTimeoutSec},
		{"LocalDoHWriteTimeoutSec",
			func(c *Config) { c.LocalDoHWriteTimeoutSec = 0 },
			func(c *Config) int { return c.LocalDoHWriteTimeoutSec },
			func(c *Config) int { return c.LocalDoHWriteTimeoutSec },
			def.LocalDoHWriteTimeoutSec},
		// upstream timeouts
		{"UpstreamDialTimeoutSec",
			func(c *Config) { c.UpstreamDialTimeoutSec = 0 },
			func(c *Config) int { return c.UpstreamDialTimeoutSec },
			func(c *Config) int { return c.UpstreamDialTimeoutSec },
			def.UpstreamDialTimeoutSec},
		// UpstreamClientTimeoutSec: after the zero-clamp (→ 5) the
		// cross-field guard (5 < 3?) does not fire, so we still get the
		// plain default.
		{"UpstreamClientTimeoutSec",
			func(c *Config) { c.UpstreamClientTimeoutSec = 0 },
			func(c *Config) int { return c.UpstreamClientTimeoutSec },
			func(c *Config) int { return c.UpstreamClientTimeoutSec },
			def.UpstreamClientTimeoutSec},
		{"CertLogTimeoutSec",
			func(c *Config) { c.CertLogTimeoutSec = 0 },
			func(c *Config) int { return c.CertLogTimeoutSec },
			func(c *Config) int { return c.CertLogTimeoutSec },
			def.CertLogTimeoutSec},
		{"UpstreamRetryBackoffMs",
			func(c *Config) { c.UpstreamRetryBackoffMs = 0 },
			func(c *Config) int { return c.UpstreamRetryBackoffMs },
			func(c *Config) int { return c.UpstreamRetryBackoffMs },
			def.UpstreamRetryBackoffMs},
		{"UpstreamIdleConnTimeoutSec",
			func(c *Config) { c.UpstreamIdleConnTimeoutSec = 0 },
			func(c *Config) int { return c.UpstreamIdleConnTimeoutSec },
			func(c *Config) int { return c.UpstreamIdleConnTimeoutSec },
			def.UpstreamIdleConnTimeoutSec},
		{"UpstreamMaxIdleConns",
			func(c *Config) { c.UpstreamMaxIdleConns = 0 },
			func(c *Config) int { return c.UpstreamMaxIdleConns },
			func(c *Config) int { return c.UpstreamMaxIdleConns },
			def.UpstreamMaxIdleConns},
		// UpstreamMaxIdleConnsPerHost: after zero-clamp (→ 10) the
		// cross-field guard (10 > 100?) does not fire.
		{"UpstreamMaxIdleConnsPerHost",
			func(c *Config) { c.UpstreamMaxIdleConnsPerHost = 0 },
			func(c *Config) int { return c.UpstreamMaxIdleConnsPerHost },
			func(c *Config) int { return c.UpstreamMaxIdleConnsPerHost },
			def.UpstreamMaxIdleConnsPerHost},
		// concurrency limits
		{"MaxConcurrentDNSTCPConns",
			func(c *Config) { c.MaxConcurrentDNSTCPConns = 0 },
			func(c *Config) int { return c.MaxConcurrentDNSTCPConns },
			func(c *Config) int { return c.MaxConcurrentDNSTCPConns },
			def.MaxConcurrentDNSTCPConns},
		{"MaxConcurrentDNSUDPQueries",
			func(c *Config) { c.MaxConcurrentDNSUDPQueries = 0 },
			func(c *Config) int { return c.MaxConcurrentDNSUDPQueries },
			func(c *Config) int { return c.MaxConcurrentDNSUDPQueries },
			def.MaxConcurrentDNSUDPQueries},
		{"ClientTCPTimeoutSec",
			func(c *Config) { c.ClientTCPTimeoutSec = 0 },
			func(c *Config) int { return c.ClientTCPTimeoutSec },
			func(c *Config) int { return c.ClientTCPTimeoutSec },
			def.ClientTCPTimeoutSec},
		// rate limits
		{"GlobalRateQPS",
			func(c *Config) { c.GlobalRateQPS = 0 },
			func(c *Config) int { return c.GlobalRateQPS },
			func(c *Config) int { return c.GlobalRateQPS },
			def.GlobalRateQPS},
		// GlobalBurstQPS: after zero-clamp (→ 200) the cross-field guard
		// (200 < GlobalRateQPS=100?) does not fire.
		{"GlobalBurstQPS",
			func(c *Config) { c.GlobalBurstQPS = 0 },
			func(c *Config) int { return c.GlobalBurstQPS },
			func(c *Config) int { return c.GlobalBurstQPS },
			def.GlobalBurstQPS},
		{"ClientRateQPS",
			func(c *Config) { c.ClientRateQPS = 0 },
			func(c *Config) int { return c.ClientRateQPS },
			func(c *Config) int { return c.ClientRateQPS },
			def.ClientRateQPS},
		// ClientBurstQPS: after zero-clamp (→ 50) the cross-field guard
		// (50 < ClientRateQPS=20?) does not fire.
		{"ClientBurstQPS",
			func(c *Config) { c.ClientBurstQPS = 0 },
			func(c *Config) int { return c.ClientBurstQPS },
			func(c *Config) int { return c.ClientBurstQPS },
			def.ClientBurstQPS},
		// payload / buffer
		{"DoHMaxRequestBodyBytes",
			func(c *Config) { c.DoHMaxRequestBodyBytes = 0 },
			func(c *Config) int { return c.DoHMaxRequestBodyBytes },
			func(c *Config) int { return c.DoHMaxRequestBodyBytes },
			def.DoHMaxRequestBodyBytes},
		// cache
		{"CacheMaxEntries",
			func(c *Config) { c.CacheMaxEntries = 0 },
			func(c *Config) int { return c.CacheMaxEntries },
			func(c *Config) int { return c.CacheMaxEntries },
			def.CacheMaxEntries},
		{"CacheJanitorIntervalMinutes",
			func(c *Config) { c.CacheJanitorIntervalMinutes = 0 },
			func(c *Config) int { return c.CacheJanitorIntervalMinutes },
			func(c *Config) int { return c.CacheJanitorIntervalMinutes },
			def.CacheJanitorIntervalMinutes},
		// misc
		{"MaxRecentBlocks",
			func(c *Config) { c.MaxRecentBlocks = 0 },
			func(c *Config) int { return c.MaxRecentBlocks },
			func(c *Config) int { return c.MaxRecentBlocks },
			def.MaxRecentBlocks},
		{"UILogMaxLines",
			func(c *Config) { c.UILogMaxLines = 0 },
			func(c *Config) int { return c.UILogMaxLines },
			func(c *Config) int { return c.UILogMaxLines },
			def.UILogMaxLines},
		{"LogMaxSizeMB",
			func(c *Config) { c.LogMaxSizeMB = 0 },
			func(c *Config) int { return c.LogMaxSizeMB },
			func(c *Config) int { return c.LogMaxSizeMB },
			def.LogMaxSizeMB},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.field, func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			tc.mutate(&cfg)
			resolved, raw, _, err := sanitizeHelper(t, cfg, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := tc.getRes(&resolved); got != tc.wantVal {
				t.Errorf("resolved.%s: got %d, want %d (default)", tc.field, got, tc.wantVal)
			}
			if got := tc.getRaw(&raw); got != tc.wantVal {
				t.Errorf("raw.%s: got %d, want %d (default)", tc.field, got, tc.wantVal)
			}
		})
	}
}

// TestSanitizeAndValidateConfig_SubZeroFieldsClamped covers fields whose
// clamp condition is strictly "< 0" rather than "<= 0", meaning zero is a
// legitimate value and must not be touched.
func TestSanitizeAndValidateConfig_SubZeroFieldsClamped(t *testing.T) {
	t.Parallel()
	def := defaultConfig()

	t.Run("UpstreamRetriesPerQuery=-1 clamped to default", func(t *testing.T) {
		t.Parallel()
		cfg := defaultConfig()
		cfg.UpstreamRetriesPerQuery = -1
		resolved, raw, _, err := sanitizeHelper(t, cfg, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resolved.UpstreamRetriesPerQuery != def.UpstreamRetriesPerQuery {
			t.Errorf("resolved: got %d, want %d", resolved.UpstreamRetriesPerQuery, def.UpstreamRetriesPerQuery)
		}
		if raw.UpstreamRetriesPerQuery != def.UpstreamRetriesPerQuery {
			t.Errorf("raw: got %d, want %d", raw.UpstreamRetriesPerQuery, def.UpstreamRetriesPerQuery)
		}
	})

	t.Run("UpstreamRetriesPerQuery=0 is valid (not clamped)", func(t *testing.T) {
		t.Parallel()
		cfg := defaultConfig()
		cfg.UpstreamRetriesPerQuery = 0
		resolved, _, _, err := sanitizeHelper(t, cfg, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resolved.UpstreamRetriesPerQuery != 0 {
			t.Errorf("resolved: zero should be valid, got %d", resolved.UpstreamRetriesPerQuery)
		}
	})

	t.Run("CacheNegativeTTLSec=-5 clamped to default", func(t *testing.T) {
		t.Parallel()
		cfg := defaultConfig()
		cfg.CacheNegativeTTLSec = -5
		resolved, raw, _, err := sanitizeHelper(t, cfg, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resolved.CacheNegativeTTLSec != def.CacheNegativeTTLSec {
			t.Errorf("resolved: got %d, want %d", resolved.CacheNegativeTTLSec, def.CacheNegativeTTLSec)
		}
		if raw.CacheNegativeTTLSec != def.CacheNegativeTTLSec {
			t.Errorf("raw: got %d, want %d", raw.CacheNegativeTTLSec, def.CacheNegativeTTLSec)
		}
	})

	t.Run("CacheNegativeTTLSec=0 is valid (not clamped)", func(t *testing.T) {
		t.Parallel()
		cfg := defaultConfig()
		cfg.CacheNegativeTTLSec = 0
		resolved, _, _, err := sanitizeHelper(t, cfg, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resolved.CacheNegativeTTLSec != 0 {
			t.Errorf("resolved: zero should be valid, got %d", resolved.CacheNegativeTTLSec)
		}
	})
}

// TestSanitizeAndValidateConfig_Uint32ZeroClamped covers the two uint32 TTL
// fields that cannot go negative but must not be zero either.
func TestSanitizeAndValidateConfig_Uint32ZeroClamped(t *testing.T) {
	t.Parallel()
	def := defaultConfig()

	t.Run("BlockedResponseTTLSec=0 clamped to default", func(t *testing.T) {
		t.Parallel()
		cfg := defaultConfig()
		cfg.BlockedResponseTTLSec = 0
		resolved, raw, _, err := sanitizeHelper(t, cfg, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resolved.BlockedResponseTTLSec != def.BlockedResponseTTLSec {
			t.Errorf("resolved: got %d, want %d", resolved.BlockedResponseTTLSec, def.BlockedResponseTTLSec)
		}
		if raw.BlockedResponseTTLSec != def.BlockedResponseTTLSec {
			t.Errorf("raw: got %d, want %d", raw.BlockedResponseTTLSec, def.BlockedResponseTTLSec)
		}
	})

	t.Run("LocalHostsOverrideTTLSec=0 clamped to default", func(t *testing.T) {
		t.Parallel()
		cfg := defaultConfig()
		cfg.LocalHostsOverrideTTLSec = 0
		resolved, raw, _, err := sanitizeHelper(t, cfg, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resolved.LocalHostsOverrideTTLSec != def.LocalHostsOverrideTTLSec {
			t.Errorf("resolved: got %d, want %d", resolved.LocalHostsOverrideTTLSec, def.LocalHostsOverrideTTLSec)
		}
		if raw.LocalHostsOverrideTTLSec != def.LocalHostsOverrideTTLSec {
			t.Errorf("raw: got %d, want %d", raw.LocalHostsOverrideTTLSec, def.LocalHostsOverrideTTLSec)
		}
	})
}

// ─── CacheMinTTL floor ────────────────────────────────────────────────────────

func TestSanitizeAndValidateConfig_CacheMinTTLFloor(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input int
		want  int
	}{
		{0, cacheMinTTLClamp},
		{1, cacheMinTTLClamp},
		{9, cacheMinTTLClamp},
		{cacheMinTTLClamp, cacheMinTTLClamp}, // exactly at floor → unchanged
		{cacheMinTTLClamp + 1, cacheMinTTLClamp + 1},
		{300, 300}, // well above floor → unchanged
	}

	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("input=%d_want=%d", tc.input, tc.want), func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			cfg.CacheMinTTL = tc.input
			resolved, raw, _, err := sanitizeHelper(t, cfg, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resolved.CacheMinTTL != tc.want {
				t.Errorf("resolved.CacheMinTTL: got %d, want %d", resolved.CacheMinTTL, tc.want)
			}
			if raw.CacheMinTTL != tc.want {
				t.Errorf("raw.CacheMinTTL: got %d, want %d", raw.CacheMinTTL, tc.want)
			}
		})
	}
}

// ─── WebUI bcrypt cost minimum ────────────────────────────────────────────────

func TestSanitizeAndValidateConfig_WebUIBcryptCostClampedToMinimum(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input int
		want  int
	}{
		{0, 12},
		{1, 12},
		{11, 12},
		{12, 12}, // exactly at minimum → unchanged
		{14, 14}, // above minimum → unchanged
		{31, 31},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("cost=%d", tc.input), func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			cfg.WebUIPasswordBcryptCost = tc.input
			resolved, raw, _, err := sanitizeHelper(t, cfg, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resolved.WebUIPasswordBcryptCost != tc.want {
				t.Errorf("resolved: got %d, want %d", resolved.WebUIPasswordBcryptCost, tc.want)
			}
			if raw.WebUIPasswordBcryptCost != tc.want {
				t.Errorf("raw: got %d, want %d", raw.WebUIPasswordBcryptCost, tc.want)
			}
		})
	}
}

// ─── idle timeout = 2× read timeout (cross-field constraint) ─────────────────

func TestSanitizeAndValidateConfig_WebUIIdleTimeoutClampedToDoubleRead(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		readTimeout int
		idleTimeout int
		wantIdle    int
	}{
		// idle strictly less than read → clamped to 2×read
		{"idle=0 clamped to 2×read=30", 15, 0, 30},
		{"idle=1 clamped (1 ≤ 15)", 15, 1, 30},
		{"idle=14 clamped (14 ≤ 15)", 15, 14, 30},
		// idle equal to read → also clamped (condition is ≤)
		{"idle=read clamped (15 ≤ 15)", 15, 15, 30},
		// idle strictly greater than read → unchanged
		{"idle=16 valid (16 > 15)", 15, 16, 16},
		{"idle=60 valid", 15, 60, 60},
		// different read timeout
		{"read=10 idle=5 clamped to 20", 10, 5, 20},
		{"read=10 idle=10 clamped to 20", 10, 10, 20},
		{"read=10 idle=11 valid", 10, 11, 11},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			cfg.WebUIReadTimeoutSec = tc.readTimeout
			cfg.WebUIIdleTimeoutSec = tc.idleTimeout
			resolved, raw, _, err := sanitizeHelper(t, cfg, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resolved.WebUIIdleTimeoutSec != tc.wantIdle {
				t.Errorf("resolved.WebUIIdleTimeoutSec: got %d, want %d", resolved.WebUIIdleTimeoutSec, tc.wantIdle)
			}
			if raw.WebUIIdleTimeoutSec != tc.wantIdle {
				t.Errorf("raw.WebUIIdleTimeoutSec: got %d, want %d", raw.WebUIIdleTimeoutSec, tc.wantIdle)
			}
		})
	}
}

func TestSanitizeAndValidateConfig_LocalDoHIdleTimeoutClampedToDoubleRead(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		readTimeout int
		idleTimeout int
		wantIdle    int
	}{
		{"idle=0 clamped to 2×read=60", 30, 0, 60},
		{"idle=29 clamped (29 ≤ 30)", 30, 29, 60},
		{"idle=30 clamped (30 ≤ 30)", 30, 30, 60},
		{"idle=31 valid (31 > 30)", 30, 31, 31},
		{"read=20 idle=10 clamped to 40", 20, 10, 40},
		{"read=20 idle=20 clamped to 40", 20, 20, 40},
		{"read=20 idle=21 valid", 20, 21, 21},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			cfg.LocalDoHReadTimeoutSec = tc.readTimeout
			cfg.LocalDoHIdleTimeoutSec = tc.idleTimeout
			resolved, raw, _, err := sanitizeHelper(t, cfg, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resolved.LocalDoHIdleTimeoutSec != tc.wantIdle {
				t.Errorf("resolved.LocalDoHIdleTimeoutSec: got %d, want %d", resolved.LocalDoHIdleTimeoutSec, tc.wantIdle)
			}
			if raw.LocalDoHIdleTimeoutSec != tc.wantIdle {
				t.Errorf("raw.LocalDoHIdleTimeoutSec: got %d, want %d", raw.LocalDoHIdleTimeoutSec, tc.wantIdle)
			}
		})
	}
}

// ─── burst < rate → clamped to rate (cross-field constraint) ─────────────────

func TestSanitizeAndValidateConfig_GlobalBurstQPS_ClampedToRateWhenBelow(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		rate      int
		burst     int
		wantBurst int
	}{
		// burst strictly less than rate → clamped to rate
		{"burst=1 rate=50 clamped", 50, 1, 50},
		{"burst=49 rate=50 clamped", 50, 49, 50},
		// burst equal to rate → condition is strictly <, so NOT clamped
		{"burst=rate=50 unchanged", 50, 50, 50},
		// burst above rate → unchanged
		{"burst=100 rate=50 unchanged", 50, 100, 100},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			cfg.GlobalRateQPS = tc.rate
			cfg.GlobalBurstQPS = tc.burst
			resolved, raw, _, err := sanitizeHelper(t, cfg, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resolved.GlobalBurstQPS != tc.wantBurst {
				t.Errorf("resolved.GlobalBurstQPS: got %d, want %d", resolved.GlobalBurstQPS, tc.wantBurst)
			}
			if raw.GlobalBurstQPS != tc.wantBurst {
				t.Errorf("raw.GlobalBurstQPS: got %d, want %d", raw.GlobalBurstQPS, tc.wantBurst)
			}
		})
	}
}

func TestSanitizeAndValidateConfig_ClientBurstQPS_ClampedToRateWhenBelow(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		rate      int
		burst     int
		wantBurst int
	}{
		{"burst=1 rate=20 clamped", 20, 1, 20},
		{"burst=19 rate=20 clamped", 20, 19, 20},
		{"burst=rate=20 unchanged", 20, 20, 20},
		{"burst=50 rate=20 unchanged", 20, 50, 50},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			cfg.ClientRateQPS = tc.rate
			cfg.ClientBurstQPS = tc.burst
			resolved, raw, _, err := sanitizeHelper(t, cfg, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resolved.ClientBurstQPS != tc.wantBurst {
				t.Errorf("resolved.ClientBurstQPS: got %d, want %d", resolved.ClientBurstQPS, tc.wantBurst)
			}
			if raw.ClientBurstQPS != tc.wantBurst {
				t.Errorf("raw.ClientBurstQPS: got %d, want %d", raw.ClientBurstQPS, tc.wantBurst)
			}
		})
	}
}

// ─── upstream client timeout < dial timeout → clamped to dial ────────────────

func TestSanitizeAndValidateConfig_UpstreamClientTimeoutBelowDial_ClampedToDial(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		dialSec    int
		clientSec  int
		wantClient int
	}{
		{"client=1 dial=5 clamped to 5", 5, 1, 5},
		{"client=4 dial=5 clamped to 5", 5, 4, 5},
		// equal → condition is strictly <, so NOT clamped
		{"client=dial=5 unchanged", 5, 5, 5},
		{"client=10 dial=5 unchanged", 5, 10, 10},
		{"large gap: client=1 dial=30 clamped to 30", 30, 1, 30},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			cfg.UpstreamDialTimeoutSec = tc.dialSec
			cfg.UpstreamClientTimeoutSec = tc.clientSec
			resolved, raw, _, err := sanitizeHelper(t, cfg, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resolved.UpstreamClientTimeoutSec != tc.wantClient {
				t.Errorf("resolved.UpstreamClientTimeoutSec: got %d, want %d",
					resolved.UpstreamClientTimeoutSec, tc.wantClient)
			}
			if raw.UpstreamClientTimeoutSec != tc.wantClient {
				t.Errorf("raw.UpstreamClientTimeoutSec: got %d, want %d",
					raw.UpstreamClientTimeoutSec, tc.wantClient)
			}
		})
	}
}

// ─── MaxIdleConnsPerHost > MaxIdleConns → clamped to MaxIdleConns ─────────────

func TestSanitizeAndValidateConfig_MaxIdleConnsPerHostAboveTotal_ClampedToTotal(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		totalConns  int
		perHost     int
		wantPerHost int
	}{
		{"perHost=80 total=50 clamped to 50", 50, 80, 50},
		{"perHost=51 total=50 clamped to 50", 50, 51, 50},
		// equal → condition is strictly >, so NOT clamped
		{"perHost=total=50 unchanged", 50, 50, 50},
		{"perHost=10 total=50 unchanged", 50, 10, 10},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			cfg.UpstreamMaxIdleConns = tc.totalConns
			cfg.UpstreamMaxIdleConnsPerHost = tc.perHost
			resolved, raw, _, err := sanitizeHelper(t, cfg, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resolved.UpstreamMaxIdleConnsPerHost != tc.wantPerHost {
				t.Errorf("resolved.UpstreamMaxIdleConnsPerHost: got %d, want %d",
					resolved.UpstreamMaxIdleConnsPerHost, tc.wantPerHost)
			}
			if raw.UpstreamMaxIdleConnsPerHost != tc.wantPerHost {
				t.Errorf("raw.UpstreamMaxIdleConnsPerHost: got %d, want %d",
					raw.UpstreamMaxIdleConnsPerHost, tc.wantPerHost)
			}
		})
	}
}

// ─── DNSUDPBufferSize range [512, 65535] ──────────────────────────────────────

func TestSanitizeAndValidateConfig_DNSUDPBufferSizeOutOfRange_ClampedToDefault(t *testing.T) {
	t.Parallel()
	def := defaultConfig()

	outOfRange := []struct {
		name  string
		input int
	}{
		{"zero", 0},
		{"one", 1},
		{"below minimum (511)", 511},
		{"above maximum (65536)", 65536},
		{"well above maximum (100000)", 100000},
	}

	for _, tc := range outOfRange {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			cfg.DNSUDPBufferSize = tc.input
			resolved, raw, _, err := sanitizeHelper(t, cfg, false)
			if err != nil {
				t.Fatalf("unexpected error for DNSUDPBufferSize=%d: %v", tc.input, err)
			}
			if resolved.DNSUDPBufferSize != def.DNSUDPBufferSize {
				t.Errorf("resolved.DNSUDPBufferSize: got %d, want default %d",
					resolved.DNSUDPBufferSize, def.DNSUDPBufferSize)
			}
			if raw.DNSUDPBufferSize != def.DNSUDPBufferSize {
				t.Errorf("raw.DNSUDPBufferSize: got %d, want default %d",
					raw.DNSUDPBufferSize, def.DNSUDPBufferSize)
			}
		})
	}
}

func TestSanitizeAndValidateConfig_DNSUDPBufferSizeValidBoundaries_Unchanged(t *testing.T) {
	t.Parallel()

	valid := []int{512, 513, 1500, 4096, 65534, 65535}

	for _, size := range valid {
		size := size
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			cfg.DNSUDPBufferSize = size
			resolved, _, _, err := sanitizeHelper(t, cfg, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resolved.DNSUDPBufferSize != size {
				t.Errorf("valid DNSUDPBufferSize=%d was changed to %d", size, resolved.DNSUDPBufferSize)
			}
		})
	}
}

// ─── BlockIP / BlockIPv6 parsing ──────────────────────────────────────────────

func TestSanitizeAndValidateConfig_BlockIPInvalid_ReturnsError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		blockIP string
	}{
		{"empty string", ""},
		{"not an IP", "not-an-ip"},
		{"IPv6 address (has no To4)", "::1"},
		{"IPv6 unspecified (has no To4)", "::"},
		{"malformed", "1.2.3.4.5"},
		{"hostname", "localhost"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			cfg.BlockIP = tc.blockIP
			_, _, _, err := sanitizeHelper(t, cfg, false)
			if err == nil {
				t.Errorf("expected error for BlockIP=%q, got nil", tc.blockIP)
			}
		})
	}
}

func TestSanitizeAndValidateConfig_BlockIPv6Invalid_ReturnsError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		blockIPv6 string
	}{
		{"empty string", ""},
		{"not an IP", "not-an-ip"},
		// An IPv4 address is rejected because To4() returns non-nil, making
		// isIPv6 = false.
		{"IPv4 as BlockIPv6", "0.0.0.0"},
		{"IPv4 as BlockIPv6 (non-zero)", "1.2.3.4"},
		{"malformed hex", "gggg::1"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			cfg.BlockIPv6 = tc.blockIPv6
			_, _, _, err := sanitizeHelper(t, cfg, false)
			if err == nil {
				t.Errorf("expected error for BlockIPv6=%q, got nil", tc.blockIPv6)
			}
		})
	}
}

func TestSanitizeAndValidateConfig_BlockIPandIPv6_ValidValues_ParsedIntoFields(t *testing.T) {
	t.Parallel()

	cases := []struct {
		blockIP   string
		blockIPv6 string
	}{
		{"0.0.0.0", "::"},
		{"127.0.0.1", "::1"},
		{"10.0.0.1", "2001:db8::1"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.blockIP+"/"+tc.blockIPv6, func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			cfg.BlockIP = tc.blockIP
			cfg.BlockIPv6 = tc.blockIPv6
			resolved, _, _, err := sanitizeHelper(t, cfg, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resolved.BlockIPv4Parsed == nil {
				t.Error("expected BlockIPv4Parsed to be populated, got nil")
			}
			if resolved.BlockIPv6Parsed == nil {
				t.Error("expected BlockIPv6Parsed to be populated, got nil")
			}
			if resolved.BlockIPv4Parsed.To4() == nil {
				t.Errorf("BlockIPv4Parsed %v is not a 4-byte IPv4", resolved.BlockIPv4Parsed)
			}
			if resolved.BlockIPv6Parsed.To4() != nil {
				t.Errorf("BlockIPv6Parsed %v unexpectedly has a To4 form", resolved.BlockIPv6Parsed)
			}
		})
	}
}

// ─── ListenDoH / ListenUI address validation ─────────────────────────────────

func TestSanitizeAndValidateConfig_ListenDoHInvalid_ReturnsError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		listenDoH string
	}{
		{"hostname instead of IP", "dns.example.com:443"},
		{"localhost hostname", "localhost:443"},
		{"no port", "127.0.0.1"},
		{"empty string", ""},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			cfg.ListenDoH = tc.listenDoH
			_, _, _, err := sanitizeHelper(t, cfg, false)
			if err == nil {
				t.Errorf("expected error for ListenDoH=%q, got nil", tc.listenDoH)
			}
		})
	}
}

func TestSanitizeAndValidateConfig_ListenUIInvalid_ReturnsError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		listenUI string
	}{
		{"hostname instead of IP", "admin.example.com:8080"},
		{"localhost hostname", "localhost:8080"},
		{"no port", "192.168.1.1"},
		{"empty string", ""},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			cfg.ListenUI = tc.listenUI
			_, _, _, err := sanitizeHelper(t, cfg, false)
			if err == nil {
				t.Errorf("expected error for ListenUI=%q, got nil", tc.listenUI)
			}
		})
	}
}

// ─── ConsoleLogLevel normalisation and validation ─────────────────────────────

func TestSanitizeAndValidateConfig_ConsoleLogLevelNormalized(t *testing.T) {
	t.Parallel()

	// sanitizeAndValidateConfig lowercases+trims ConsoleLogLevel and writes
	// the result back so the on-disk value is canonical.
	cases := []struct {
		input string
		want  string
	}{
		{"debug", "debug"},
		{"DEBUG", "debug"},
		{"  debug  ", "debug"},
		{"info", "info"},
		{"INFO", "info"},
		{"warn", "warn"},
		{"WARN", "warn"},
		{"WARNING", "warning"},
		{"warning", "warning"},
		{"error", "error"},
		{"ERROR", "error"},
		// single-letter aliases are preserved as-is after lower/trim
		{"d", "d"},
		{"D", "d"},
		{"i", "i"},
		{"w", "w"},
		{"e", "e"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("%q", tc.input), func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			cfg.ConsoleLogLevel = tc.input
			resolved, raw, _, err := sanitizeHelper(t, cfg, false)
			if err != nil {
				t.Fatalf("unexpected error for ConsoleLogLevel=%q: %v", tc.input, err)
			}
			if resolved.ConsoleLogLevel != tc.want {
				t.Errorf("resolved.ConsoleLogLevel: got %q, want %q", resolved.ConsoleLogLevel, tc.want)
			}
			if raw.ConsoleLogLevel != tc.want {
				t.Errorf("raw.ConsoleLogLevel: got %q, want %q", raw.ConsoleLogLevel, tc.want)
			}
		})
	}
}

func TestSanitizeAndValidateConfig_ConsoleLogLevelInvalid_ReturnsError(t *testing.T) {
	t.Parallel()

	invalid := []string{"verbose", "trace", "fatal", "off", "all", "none", "x", "z", "ii"}

	for _, level := range invalid {
		level := level
		t.Run(fmt.Sprintf("%q", level), func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			cfg.ConsoleLogLevel = level
			_, _, _, err := sanitizeHelper(t, cfg, false)
			if err == nil {
				t.Errorf("expected error for ConsoleLogLevel=%q, got nil", level)
			}
		})
	}
}

// ─── UpstreamSelectionMode normalisation and validation ───────────────────────

func TestSanitizeAndValidateConfig_UpstreamSelectionModeNormalized(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input string
		want  string
	}{
		{"failover", "failover"},
		{"FAILOVER", "failover"},
		{"Failover", "failover"},
		{"  failover  ", "failover"},
		{"fastest", "fastest"},
		{"FASTEST", "fastest"},
		{"strict", "strict"},
		{"STRICT", "strict"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("%q", tc.input), func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			cfg.UpstreamSelectionMode = tc.input
			resolved, raw, _, err := sanitizeHelper(t, cfg, false)
			if err != nil {
				t.Fatalf("unexpected error for UpstreamSelectionMode=%q: %v", tc.input, err)
			}
			if resolved.UpstreamSelectionMode != tc.want {
				t.Errorf("resolved.UpstreamSelectionMode: got %q, want %q", resolved.UpstreamSelectionMode, tc.want)
			}
			if raw.UpstreamSelectionMode != tc.want {
				t.Errorf("raw.UpstreamSelectionMode: got %q, want %q", raw.UpstreamSelectionMode, tc.want)
			}
		})
	}
}

func TestSanitizeAndValidateConfig_UpstreamSelectionModeInvalid_ReturnsError(t *testing.T) {
	t.Parallel()

	invalid := []string{"round_robin", "random", "sticky", "all", "", "fastest2"}

	for _, mode := range invalid {
		mode := mode
		t.Run(fmt.Sprintf("%q", mode), func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			cfg.UpstreamSelectionMode = mode
			_, _, _, err := sanitizeHelper(t, cfg, false)
			if err == nil {
				t.Errorf("expected error for UpstreamSelectionMode=%q, got nil", mode)
			}
		})
	}
}

// ─── Upstream SNI auto-fill ───────────────────────────────────────────────────

func TestSanitizeAndValidateConfig_UpstreamSNI_AutoFilledFromURL(t *testing.T) {
	t.Parallel()

	t.Run("all SNIs missing - filled from URL hosts", func(t *testing.T) {
		t.Parallel()
		cfg := defaultConfig()
		cfg.UpstreamURLs = []string{
			"https://9.9.9.9/dns-query",
			"https://1.1.1.1/dns-query",
		}
		cfg.UpstreamSNIHostnames = nil

		resolved, raw, modified, err := sanitizeHelper(t, cfg, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !modified {
			t.Error("expected modified=true when SNIs are auto-filled from URLs")
		}
		if len(resolved.UpstreamSNIHostnames) != 2 {
			t.Fatalf("resolved: expected 2 SNIs, got %d: %v", len(resolved.UpstreamSNIHostnames), resolved.UpstreamSNIHostnames)
		}
		if resolved.UpstreamSNIHostnames[0] != "9.9.9.9" {
			t.Errorf("resolved SNI[0]: got %q, want %q", resolved.UpstreamSNIHostnames[0], "9.9.9.9")
		}
		if resolved.UpstreamSNIHostnames[1] != "1.1.1.1" {
			t.Errorf("resolved SNI[1]: got %q, want %q", resolved.UpstreamSNIHostnames[1], "1.1.1.1")
		}
		// raw must also be updated so the fill is persisted to disk
		if len(raw.UpstreamSNIHostnames) != 2 {
			t.Fatalf("raw: expected 2 SNIs, got %d", len(raw.UpstreamSNIHostnames))
		}
		if raw.UpstreamSNIHostnames[0] != "9.9.9.9" {
			t.Errorf("raw SNI[0]: got %q, want %q", raw.UpstreamSNIHostnames[0], "9.9.9.9")
		}
	})

	t.Run("partial SNIs - trailing missing entries filled from URL", func(t *testing.T) {
		t.Parallel()
		cfg := defaultConfig()
		cfg.UpstreamURLs = []string{
			"https://9.9.9.9/dns-query",
			"https://1.1.1.1/dns-query",
			"https://8.8.8.8/dns-query",
		}
		cfg.UpstreamSNIHostnames = []string{"dns.quad9.net"} // only one provided

		resolved, raw, modified, err := sanitizeHelper(t, cfg, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !modified {
			t.Error("expected modified=true for partial SNI fill")
		}
		if len(resolved.UpstreamSNIHostnames) != 3 {
			t.Fatalf("resolved: expected 3 SNIs, got %d: %v", len(resolved.UpstreamSNIHostnames), resolved.UpstreamSNIHostnames)
		}
		// first entry was explicitly provided → preserved
		if resolved.UpstreamSNIHostnames[0] != "dns.quad9.net" {
			t.Errorf("resolved SNI[0]: got %q, want %q", resolved.UpstreamSNIHostnames[0], "dns.quad9.net")
		}
		// missing entries filled from URL host
		if resolved.UpstreamSNIHostnames[1] != "1.1.1.1" {
			t.Errorf("resolved SNI[1]: got %q, want %q", resolved.UpstreamSNIHostnames[1], "1.1.1.1")
		}
		if resolved.UpstreamSNIHostnames[2] != "8.8.8.8" {
			t.Errorf("resolved SNI[2]: got %q, want %q", resolved.UpstreamSNIHostnames[2], "8.8.8.8")
		}
		if len(raw.UpstreamSNIHostnames) != 3 {
			t.Fatalf("raw: expected 3 SNIs, got %d", len(raw.UpstreamSNIHostnames))
		}
	})

	t.Run("empty-string SNI entry filled from URL host", func(t *testing.T) {
		t.Parallel()
		cfg := defaultConfig()
		cfg.UpstreamURLs = []string{
			"https://9.9.9.9/dns-query",
			"https://1.1.1.1/dns-query",
		}
		// Count matches but second entry is an empty string
		cfg.UpstreamSNIHostnames = []string{"dns.quad9.net", ""}

		resolved, raw, modified, err := sanitizeHelper(t, cfg, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !modified {
			t.Error("expected modified=true when empty SNI string is filled")
		}
		if resolved.UpstreamSNIHostnames[0] != "dns.quad9.net" {
			t.Errorf("resolved SNI[0] should be unchanged, got %q", resolved.UpstreamSNIHostnames[0])
		}
		if resolved.UpstreamSNIHostnames[1] != "1.1.1.1" {
			t.Errorf("resolved SNI[1]: got %q, want %q", resolved.UpstreamSNIHostnames[1], "1.1.1.1")
		}
		if raw.UpstreamSNIHostnames[1] != "1.1.1.1" {
			t.Errorf("raw SNI[1]: got %q, want %q", raw.UpstreamSNIHostnames[1], "1.1.1.1")
		}
	})
}

func TestSanitizeAndValidateConfig_MoreSNIsThanURLs_ReturnsError(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	cfg.UpstreamURLs = []string{"https://9.9.9.9/dns-query"}
	cfg.UpstreamSNIHostnames = []string{"dns.quad9.net", "extra.example.com"} // 2 SNIs, 1 URL

	_, _, _, err := sanitizeHelper(t, cfg, false)
	if err == nil {
		t.Error("expected error when SNI count exceeds URL count, got nil")
	}
}

// ─── WebUI password check in isWebUI mode ─────────────────────────────────────

func TestSanitizeAndValidateConfig_EmptyPasswordInWebUIMode_ReturnsError(t *testing.T) {
	t.Parallel()
	// defaultConfig() ships with WebUIPasswordHash="" intentionally (it is
	// set interactively on first run).  When sanitizeAndValidateConfig is
	// called from the WebUI apply path (isWebUI=true) an empty hash must be
	// rejected because a password is required for the UI to be secure.
	_, _, _, err := sanitizeHelper(t, defaultConfig(), true)
	if err == nil {
		t.Error("expected error for empty WebUIPasswordHash in isWebUI=true mode, got nil")
	}
}

func TestSanitizeAndValidateConfig_EmptyPasswordInNonWebUIMode_NoError(t *testing.T) {
	t.Parallel()
	// In the normal startup path (isWebUI=false) an empty hash is acceptable
	// because loadMainConfig will prompt the user interactively.
	_, _, _, err := sanitizeHelper(t, defaultConfig(), false)
	if err != nil {
		t.Errorf("unexpected error for empty WebUIPasswordHash in isWebUI=false mode: %v", err)
	}
}

func TestSanitizeAndValidateConfig_NonEmptyPasswordInWebUIMode_NoError(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	// Any non-empty string is accepted; the actual bcrypt validity is not
	// re-checked here (it was validated when the hash was stored).
	cfg.WebUIPasswordHash = "$2a$12$placeholder_hash_for_testing_only_abc"
	_, _, _, err := sanitizeHelper(t, cfg, true)
	if err != nil {
		t.Errorf("unexpected error for non-empty WebUIPasswordHash in isWebUI=true mode: %v", err)
	}
}

// ─── sanity: valid defaultConfig produces no spurious save trigger ────────────

// TestSanitizeAndValidateConfig_ValidDefaultConfig_NotModified verifies that
// a fully-specified defaultConfig() passes validation without triggering a
// save (modified=false).  If this starts failing it means a new field was
// added whose default value accidentally triggers a clamping or auto-fill
// branch.
func TestSanitizeAndValidateConfig_ValidDefaultConfig_NotModified(t *testing.T) {
	t.Parallel()
	// defaultConfig() has empty WebUIPasswordHash; isWebUI=false so the
	// password check is skipped, and no other field should require correction.
	_, _, modified, err := sanitizeHelper(t, defaultConfig(), false)
	if err != nil {
		t.Fatalf("unexpected error for valid defaultConfig: %v", err)
	}
	if modified {
		t.Error("expected modified=false for an unmodified defaultConfig; " +
			"some field is being unnecessarily auto-corrected or auto-populated")
	}
}