//go:build windows
// +build windows

// Copyright 2026 workturnedplay
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package dnsbollocks see: https://github.com/workturnedplay/dnsbollocks
package dnsbollocks

import (
	"bufio"
	"bytes"
	"container/list"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"expvar"
	"reflect"
	"sort"
	"sync/atomic"

	"fmt"
	"html/template"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"

	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"github.com/workturnedplay/dnsbollocks/templates"
	"github.com/workturnedplay/wincoe"
	"golang.org/x/sys/windows"
	"golang.org/x/term"
	"golang.org/x/time/rate"

	"flag"
	"golang.org/x/crypto/bcrypt"

	"runtime/debug"
)

// Config holds the JSON configuration.
type Config struct {
	ListenDNS string `json:"listen_dns"` // e.g., "127.0.0.1:53"
	ListenDoH string `json:"listen_doh"` // e.g., "127.0.0.1:443"
	//UIPort                  int      `json:"ui_port"`                    // 8080
	ListenUI                string   `json:"listen_ui"`
	UpstreamURLs            []string `json:"upstream_urls"`              // ["https://9.9.9.9/dns-query", "https://1.1.1.1/dns-query"],
	UpstreamRetriesPerQuery int      `json:"upstream_retries_per_query"` // e.g., 1 retry (and 1 first try implied, thus 2 total tries!) ie. how many retries are attempted per DNS query to upstream DoH if it fails!
	SNIHostnames            []string `json:"sni_hostnames"`              // Optional: ["dns.quad9.net", "cloudflare-dns.com"]
	//"parallel" (or "all"): The old default behavior where everything is queried simultaneously.
	//"strict" (or "priority"): The existing strict rule matching behavior.
	//"failover": The new intelligent, stateful sticky failover behavior.
	UpstreamSelectionMode string `json:"upstream_selection_mode"` // "parallel", "strict", or "failover"
	BlockMode             string `json:"block_mode"`              // "nxdomain", "drop", "ip_block"
	BlockIP               string `json:"block_ip"`                // "0.0.0.0"
	GlobalRateQPS         int    `json:"qps_rate_globally"`       // 100
	GlobalBurstQPS        int    `json:"qps_burst_globally"`      // 100
	ClientRateQPS         int    `json:"qps_rate_per_client"`     // 20
	ClientBurstQPS        int    `json:"qps_burst_per_client"`    // 50
	CacheMinTTL           int    `json:"cache_min_ttl"`           // 300s
	CacheMaxEntries       int    `json:"cache_max_entries"`       // 10000
	// Whitelist         map[string][]Rule `json:"whitelist"`          // Per-type rules
	// ResponseBlacklist []string          `json:"response_blacklist"` // CIDR e.g., "127.0.0.1/8"
	WhitelistFile string `json:"whitelist_file"` // "query_whitelist.json"
	BlacklistFile string `json:"blacklist_file"` // "response_blacklist.json"
	HostsFile     string `json:"hosts_file"`     // "hosts2ip.json" XXX: a host has to match the whitelist first before being considered from here!
	// ConsoleLogLevel controls what appears on the terminal.
	// Valid values (case-insensitive): "debug", "info", "warn", "error".
	// Default: "info". Only >= this level is shown on console.
	// Full dnsbollocks.log always gets Debug+; queries.log always gets queries.
	LogQueriesFile  string `json:"log_queries"` // "queries.log"
	LogErrorsFile   string `json:"log_errors"`  // "errors.log" TODO: rename this key and the field because it's logging everything!
	ConsoleLogLevel string `json:"console_log_level"`
	LogMaxSizeMB    int    `json:"log_max_size_mb"`    // 1 for rotation
	AllowRunAsAdmin bool   `json:"allow_run_as_admin"` // if running the exe as Admin in windows is allowed or if false just exits.
	// Special-case: For AAAA queries, return NOERROR with an empty answer instead of NXDOMAIN.
	// Windows treats NXDOMAIN for AAAA as authoritative non-existence which prevents IPv4 fallback.
	BlockAAAAasEmptyNoError bool `json:"block_aaaa_as_empty_noerror"` // default true
	// NEW: If true, an 'HTTPS' query will be allowed if an 'A' rule matches the domain.
	AllowHTTPSIfAAllowed bool `json:"allow_https_if_a_allowed"`
	RemoveHTTPSIPv4Hints bool `json:"remove_https_ipv4_hints"`
	UseEDEInBlockedReply bool `json:"use_ede_in_blocked_reply"`

	WebUIPasswordHash string `json:"webui_password_hash"`
	WebUIUseTLS       bool   `json:"webui_use_tls"`

	// Network & Connection Limits
	ClientTCPTimeoutSec           int `json:"client_tcp_timeout_sec"`
	MaxRecentBlocks               int `json:"max_recent_blocks"`
	UpstreamServerReadTimeoutSec  int `json:"upstreamserver_read_timeout_sec"`
	UpstreamServerWriteTimeoutSec int `json:"upstreamserver_write_timeout_sec"`

	UpstreamDialTimeoutSec   int `json:"upstream_dial_timeout_sec"`
	UpstreamClientTimeoutSec int `json:"upstream_client_timeout_sec"`
	CertLogTimeoutSec        int `json:"cert_log_timeout_sec"`

	UpstreamIdleConnTimeoutSec  int `json:"upstream_idle_conn_timeout_sec"`
	UpstreamMaxIdleConns        int `json:"upstream_max_idle_conns"`
	UpstreamMaxIdleConnsPerHost int `json:"upstream_max_idle_conns_per_host"`
	UpstreamRetryBackoffMs      int `json:"upstream_retry_backoff_ms"`

	// Buffer & Sizing Limits
	DoHMaxRequestBodyBytes int `json:"doh_max_request_body_bytes"`
	DNSUDPBufferSize       int `json:"dns_udp_buffer_size"`

	CacheJanitorIntervalMinutes int `json:"cachejanitor_interval_minutes"`
	// Cache & Diagnostic Limits, affects our own caching of it only
	CacheNegativeTTLSec int `json:"cache_negative_ttl_sec"`

	//this is the TTL set in the DNS packet, so tells OS how long to cache this
	BlockedResponseTTLSec int `json:"blocked_response_ttl_sec"`

	LocalHostsOverrideTTLSec uint32 `json:"localhosts_override_ttl_sec"`

	UILogMaxLines int `json:"ui_log_max_lines"`

	ExtraSafety bool `json:"extra_safety"`
}

// Server encapsulates all the state required to run the DNSbollocks application.
type Server struct {
	config Config
	logger *slog.Logger

	// Upstream state
	upstreamIPs    []string
	upstreamURLs   []*url.URL
	upstreamSNIs   []string
	failoverSelect *FailoverSelector
	//upstreams      []Upstream // Combines clients, URLs, and SNIs safely

	// Caching & Rate limiting
	cacheStore     *cache.Cache
	globalLimiter  *rate.Limiter
	clientLimiters sync.Map // map[string]*rate.Limiter

	// Rules & Blocking
	whitelist           map[string][]RuleEntry // type -> rules
	ruleMutex           sync.RWMutex
	localHosts          []LocalHostRule
	localHostsMu        sync.RWMutex
	responseBlacklist   []*net.IPNet // parsed and ready-to-use form
	responseBlacklistMu sync.RWMutex
	fileWriteMu         sync.Mutex

	recentBlocksList *list.List
	recentBlocksMap  map[string]*list.Element
	blockMutex       sync.Mutex

	// HTTP/DoH state
	dohCert           tls.Certificate   // Loaded once for DoH listener
	dohTransportsPtrs []*http.Transport //protected by dohMu, used only to clean up during reinit via initDoHClient
	//dohClientsPtr     atomic.Pointer[[]*http.Client]
	upstreamsPtr atomic.Pointer[[]Upstream] // Combines clients, URLs, and SNIs safely
	dohMu        sync.Mutex                 // Only used for initialization/reloads

	// Lifecycle & Concurrency
	// Simple stats, FIXME.
	stats        *expvar.Int
	ctx          context.Context //the old backgroundCtx
	cancel       context.CancelFunc
	errChan      chan error
	shutdownWG   sync.WaitGroup
	shutdownOnce sync.Once
}

// NewServer initializes a new Server instance.
func NewServer(logger *slog.Logger) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		logger:           logger,
		failoverSelect:   NewFailoverSelector(logger),
		whitelist:        make(map[string][]RuleEntry),
		recentBlocksList: list.New(),
		recentBlocksMap:  make(map[string]*list.Element),
		errChan:          make(chan error, 10), // We use a buffer of (e.g.) 10 so multiple services failing at once won't block
		stats:            expvar.NewInt("blocks"),
		ctx:              ctx,
		cancel:           cancel,
	}
}

type FailoverSelector struct {
	logger         *slog.Logger // Passed during initialization
	mu             sync.RWMutex
	activeIndex    int
	inFlightProbes sync.Map
	allFailed      bool // Tracks if the system is coming out of a total blackout
}

// NewFailoverSelector initializes the tracker starting at the first upstream (index 0)
func NewFailoverSelector(logger *slog.Logger) *FailoverSelector {
	return &FailoverSelector{logger: logger, activeIndex: 0, allFailed: false}
}

// Upstream represents a single configured DoH target and handles its own network lifecycle.
type Upstream struct {
	// Client talks to the upstream
	Client            *http.Client
	URL               *url.URL
	SNI               string
	logger            *slog.Logger
	Retries           int //RetriesPerQuery
	RetryBackoff      time.Duration
	BackgroundCtx     context.Context
	CertLogTimeoutSec int
}

func (fs *FailoverSelector) Exchange(ctx context.Context, upstreams []Upstream, reqBytes []byte) (*dns.Msg, string, []string, error) {
	if len(upstreams) == 0 {
		return nil, "", nil, errors.New("no upstreams available")
	}

	fs.mu.RLock()
	currentIdx := fs.activeIndex
	fs.mu.RUnlock()

	// Safety check if upstream list dynamically changed or shrank
	// If the active index is impossible due to an upstream configuration shrink
	if currentIdx >= len(upstreams) {
		currentIdx = 0
		// Update the global state so it doesn't stay corrupted
		fs.mu.Lock()
		// Double-check under the write lock to safely update the global struct state
		if fs.activeIndex >= len(upstreams) {
			fs.activeIndex = 0
			//it means the underlying upstream layout has changed or shrunk out from under the selector. Any previous "global blackout" status (fs.allFailed = true) belonged to the old configuration of servers.
			//If you don't reset fs.allFailed = false when clamping an out-of-bounds index, the selector will carry over a pessimistic ghost blackout state onto the brand-new list of upstreams.
			fs.allFailed = false // 🟢 Give the new upstream slice a clean slate
		}
		fs.mu.Unlock()
	}

	type result struct {
		index int
		resp  *dns.Msg
		err   error
	}

	// 1. Try the current active working upstream AND all previous higher-priority
	// upstreams that failed before in parallel.
	numParallel := currentIdx + 1
	resChan := make(chan result, numParallel)
	var failedUpstreams []string

	//for i := 0; i < numParallel; i++ {
	for i := range numParallel {
		isProbe := i < currentIdx
		// If this is a probe to a previously failed upstream, check if we're already probing it.
		if isProbe {
			//LoadOrStore(i, true): This atomically checks if an operation is already in progress for that index. If loaded is true, we immediately push a dummy error to the channel and continue, bypassing doSingleDoHRequest. This kills the log spam.
			if _, loaded := fs.inFlightProbes.LoadOrStore(i, true); loaded {
				// Already probing this failed upstream. Skip to prevent network and log spam.
				resChan <- result{index: i, resp: nil, err: errors.New("skipped: probe already in flight")}
				continue
			}
		}
		go func(idx int, wasProbe bool) {
			// Clean up the probe lock when this request finishes
			if wasProbe {
				defer fs.inFlightProbes.Delete(idx)
			}
			// 1. Safe, single struct resolution instead of parallel slices
			target := upstreams[idx]
			resp, err := target.doSingleDoHRequest(ctx, reqBytes) //target.Client, target.URL, target.SNI, reqBytes)

			// 1. Do the promotion BEFORE sending to the channel
			// ASYNC HEALING: If a higher priority upstream unexpectedly succeeded
			// after we already returned the active response, update the active index.
			// If a probe succeeds, immediately promote it back to active status
			if err == nil {
				var healed bool = false
				var recoveredFromBlackout bool = false

				fs.mu.Lock()
				// CASE 1: The system was completely down, and ANY upstream just brought it back
				if fs.allFailed {
					fs.allFailed = false
					recoveredFromBlackout = true

					// If the primary recovered, make sure activeIndex points to it
					if idx < fs.activeIndex {
						fs.activeIndex = idx
					}
				} else if idx < currentIdx {
					// CASE 2: Normal operation, but a higher priority upstream probe succeeded
					if idx < fs.activeIndex {
						fs.activeIndex = idx
						healed = true
					}
				}
				fs.mu.Unlock()

				// Log safely outside of the lock
				if recoveredFromBlackout {
					fs.logger.Warn("💚 Global blackout resolved; upstreams are responding again",
						slog.String("url", target.URL.String()),
						slog.String("sni", target.SNI),
						slog.Int("index", idx),
					)
				} else if healed {
					fs.logger.Warn("⚙️ Primary upstream recovered; promoting back to active status",
						slog.String("url", target.URL.String()),
						slog.String("sni", target.SNI),
						slog.Int("index", idx),
					)
				}
			}
			// 2. Push to the channel last
			resChan <- result{index: idx, resp: resp, err: err}

		}(i, isProbe)
	}

	// Wait and evaluate results as they arrive
	receivedResults := 0
	for receivedResults < numParallel {
		res := <-resChan
		receivedResults++

		if res.err == nil {
			// fs.mu.Lock()
			// if res.index < fs.activeIndex {
			//     fs.activeIndex = res.index
			// }
			// fs.mu.Unlock()
			// No locks needed here anymore! The goroutine already handled it.
			return res.resp, upstreams[res.index].URL.String(), failedUpstreams, nil
		}
		// Track the failure
		failedUpstreams = append(failedUpstreams, upstreams[res.index].URL.String())
	}

	// 2. If ALL parallel attempts (0 through currentIdx) failed, only then do we
	// step down the list sequentially to find the next working backup.
	for i := currentIdx + 1; i < len(upstreams); i++ {
		target := upstreams[i]
		resp, err := target.doSingleDoHRequest(ctx, reqBytes) //doSingleDoHRequest(ctx, target.Client, target.URL, target.SNI, reqBytes)
		if err == nil {
			fs.mu.Lock()
			wasBlackout := fs.allFailed
			fs.allFailed = false // Connectivity restored by a fallback!
			fs.activeIndex = i
			fs.mu.Unlock()
			if wasBlackout { //TODO: DRY(see the above copy)
				fs.logger.Warn("💚 Global blackout resolved; fallback upstream responding",
					slog.String("url", target.URL.String()),
					slog.String("sni", target.SNI),
					slog.Int("index", i),
				)
			} else {
				oldTarget := upstreams[currentIdx]
				// ⚠️ New log line for the standard failover case
				fs.logger.Warn("⚠️ Upstream failover; switching to a different(next in list) upstream DoH server",
					slog.Int("old_index", currentIdx),
					slog.String("old_url", oldTarget.URL.String()),
					slog.String("old_sni", oldTarget.SNI),
					slog.Int("new_index", i),
					slog.String("new_url", target.URL.String()),
					slog.String("sni", target.SNI),
				)
			}
			return resp, target.URL.String(), failedUpstreams, nil
		}
		failedUpstreams = append(failedUpstreams, target.URL.String())
	}
	// If execution gets here, every single configured upstream failed
	fs.mu.Lock()
	fs.allFailed = true
	fs.mu.Unlock()
	return nil, "", failedUpstreams, errors.New("all upstreams failed to respond")
}

func (c Config) Clone() Config {
	// 1. Shallow copy all primitive fields and string headers at once
	dst := c

	// 2. Explicitly allocate and copy slices/maps
	if c.UpstreamURLs != nil {
		dst.UpstreamURLs = make([]string, len(c.UpstreamURLs))
		copy(dst.UpstreamURLs, c.UpstreamURLs)
	}

	if c.SNIHostnames != nil {
		dst.SNIHostnames = make([]string, len(c.SNIHostnames))
		copy(dst.SNIHostnames, c.SNIHostnames)
	}

	return dst
}

type LocalHostRule struct {
	Pattern string
	IPs     []net.IP
}

// RuleEntry represents a whitelist rule.
type RuleEntry struct {
	ID      string `json:"id"`
	Pattern string `json:"pattern"`
	Enabled bool   `json:"enabled"`
}

// LogValue makes RuleEntry 100% immune to dangerous reflection data races.
// When you pass RuleEntry to slog.Any, slog runs this function instead of reflecting.
// alternatively use SafeRuleAttr() helper
func (r RuleEntry) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", r.ID),
		slog.String("pattern", r.Pattern),
		slog.Bool("enabled", r.Enabled),
	)
}

// BlacklistFileFormat represents the strict on-disk structure of response_blacklist.json
type BlacklistFileFormat struct {
	ResponseBlacklist []string `json:"response_blacklist"`
}

// Call once during startup (inside loadConfig or after it)
func (s *Server) loadResponseBlacklist() error {
	blacklistFileName := s.config.BlacklistFile
	if blacklistFileName == "" {
		panic("dev. didn't set the default blacklist filename!")
	}
	blacklistFileName = filepath.Clean(blacklistFileName)
	s.checkPowerLossFile(blacklistFileName)
	var shouldSave bool = false
	var raw []string
	data, err := os.ReadFile(blacklistFileName)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("read blacklist %q: %w", blacklistFileName, err)
		} else {
			s.logger.Warn("Blacklist file not found → using built-in defaults", slog.String("file", blacklistFileName))
			raw = defaultResponseBlacklist() // see below
			shouldSave = true
		}
	} else {
		if dups, dupErr := detectDuplicateJSONObjectKeys(data); dupErr != nil {
			return fmt.Errorf("failed to scan blacklist file %q for duplicate keys: %w", blacklistFileName, dupErr)
		} else if len(dups) > 0 {
			for _, dup := range dups {
				s.logger.Error("Duplicate key found in blacklist file (JSON silently kept only the last value; fix the file manually)",
					slog.String("duplicate_key", dup),
					slog.String("file", blacklistFileName))
			}
			if s.config.ExtraSafety {
				s.logger.Error("ExtraSafety: refusing to continue with duplicate blacklist keys",
					slog.Int("duplicate_count", len(dups)))
				s.shutdown(5)
			}
			s.logger.Warn("Continuing despite duplicate blacklist keys — the JSON decoder kept an arbitrary value for each duplicate; consider fixing the file",
				slog.Int("duplicate_count", len(dups)))
		}

		// read the existing ones
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		var file BlacklistFileFormat
		if err = dec.Decode(&file); err != nil {
			return fmt.Errorf("failed to parse blacklist file '%q' (maybe it contains unsupported or typo-ed fields?), err: %w", blacklistFileName, err)
		}
		raw = file.ResponseBlacklist
	}

	parsed := make([]*net.IPNet, 0, len(raw))
	// fail-fast if the response blacklist has malformed CIDR addresses
	for _, cidr := range raw {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q in %q: %w", cidr, blacklistFileName, err)
		}
		parsed = append(parsed, n)
	}

	// Optional: after parsing, clean up duplicates (just in case)
	seen := make(map[string]struct{}, len(parsed))
	deduped := parsed[:0]
	for _, n := range parsed {
		str := n.String()
		if _, exists := seen[str]; !exists {
			seen[str] = struct{}{}
			deduped = append(deduped, n)
		} else {
			if s.config.ExtraSafety {
				s.logger.Error("Duplicate blacklist entry found", slog.String("entry", str))
			} else {
				s.logger.Warn("Duplicate blacklist entry found, removing it", slog.String("entry", str))
			}
			if !shouldSave {
				shouldSave = true
			}
		}
	}
	dups := len(parsed) - len(deduped)
	if dups > 0 {
		if s.config.ExtraSafety {
			s.logger.Error("ExtraSafety: Found duplicate CIDRs from blacklist file, it/they could be due to typos so silently removing it/them and overwriting the file might be a mistake!", slog.Int("found_count", len(parsed)-len(deduped)), slog.String("file", blacklistFileName))
			s.shutdown(5) //XXX: this will exit program here! //FIXME: find a better way to "quit" than exit program here
		} else {
			s.logger.Info("Removed duplicate CIDRs from blacklist file", slog.Int("removed_count", len(parsed)-len(deduped)), slog.String("file", blacklistFileName))
			parsed = deduped
		}
	}

	s.responseBlacklistMu.Lock()
	s.responseBlacklist = parsed
	s.responseBlacklistMu.Unlock()
	// ==========================================
	//   NEW: INJECT CACHE INVALIDATION HERE
	// ==========================================
	s.invalidateCacheForBlacklistedIPs()
	// ==========================================
	s.logger.Info("Loaded CIDR entries from blacklist file", slog.Int("count", len(s.responseBlacklist)), slog.Int("duplicates", dups), slog.String("file", blacklistFileName))
	if shouldSave {
		if err := s.saveResponseBlacklist(); err != nil {
			return fmt.Errorf("failed to save blacklist file %q, err: %w", blacklistFileName, err)
		} else {
			s.logger.Info("Saved blacklist file", slog.String("file", blacklistFileName))
		}
	}
	return nil
}

func (s *Server) saveResponseBlacklist() error {
	cidrs := s.getResponseBlacklist()
	jsonFileContents := BlacklistFileFormat{
		ResponseBlacklist: cidrs,
	}
	data, err := json.MarshalIndent(jsonFileContents, "", "  ")
	if err != nil {
		return fmt.Errorf("blacklist marshal failed: %w", err)
	}

	blacklistFileName := s.config.BlacklistFile
	if blacklistFileName == "" {
		panic("bad coding: dev. didn't set the default blacklist filename!")
	}
	s.fileWriteMu.Lock()
	defer s.fileWriteMu.Unlock()
	if err := s.safeWriteFile(blacklistFileName, data, 0600); err != nil {
		return fmt.Errorf("cannot save/write blacklist file %q: %w", blacklistFileName, err)
	} else {
		s.logger.Info("Saved blacklist file", slog.String("file", blacklistFileName))
	}
	return nil
}

// detectDuplicateJSONObjectKeys walks the top-level keys of a JSON object
// using the token API and returns any key that appears more than once.
//
// This is necessary because Go's json.Decoder silently overwrites duplicate
// keys when decoding into a map, so by the time our dedup logic runs the
// duplicate is already gone.  We therefore must inspect the raw bytes before
// decoding.
//
// Only the top-level object is inspected; nested objects are skipped as
// opaque blobs.  Returns an error only if the bytes are not a valid JSON
// object at all.
func detectDuplicateJSONObjectKeys(data []byte) (duplicates []string, err error) {
	dec := json.NewDecoder(bytes.NewReader(data))

	// Expect opening '{'.
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("JSON parse error: %w", err)
	}
	if tok != json.Delim('{') {
		return nil, fmt.Errorf("expected JSON object (got %T %v)", tok, tok)
	}

	seen := make(map[string]struct{})
	for dec.More() {
		// Read the key token.
		tok, err = dec.Token()
		if err != nil {
			return nil, fmt.Errorf("JSON key parse error: %w", err)
		}
		key, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("expected string key, got %T %v", tok, tok)
		}
		if _, alreadySeen := seen[key]; alreadySeen {
			duplicates = append(duplicates, key)
		}
		seen[key] = struct{}{}

		// Skip the value (may be any JSON type) so the decoder advances past it.
		var skip json.RawMessage
		if err = dec.Decode(&skip); err != nil {
			return nil, fmt.Errorf("JSON value parse error for key %q: %w", key, err)
		}
	}
	return duplicates, nil
}

func (s *Server) loadLocalHosts() error {
	hostsFileName := s.config.HostsFile
	if hostsFileName == "" {
		panic("dev: didn't set the default hosts filename!")
	}
	hostsFileName = filepath.Clean(hostsFileName)
	s.checkPowerLossFile(hostsFileName)
	data, err := os.ReadFile(hostsFileName)
	if os.IsNotExist(err) {
		s.logger.Warn("Hosts file not found, starting with empty local hosts", slog.String("path", hostsFileName))
		s.localHostsMu.Lock()
		s.localHosts = nil
		s.localHostsMu.Unlock()
		return s.saveLocalHosts() // creates empty default file
	}
	if err != nil {
		return fmt.Errorf("cannot read hosts file %q: %w", hostsFileName, err)
	}

	// Check for duplicate JSON keys BEFORE decoding into a map, because
	// Go's json.Decoder silently drops all but the last duplicate — our
	// post-decode seenPatterns check would never see them.
	if dups, dupErr := detectDuplicateJSONObjectKeys(data); dupErr != nil {
		return fmt.Errorf("failed to scan hosts file %q for duplicate keys: %w", hostsFileName, dupErr)
	} else if len(dups) > 0 {
		// A manually edited file with duplicate keys is almost certainly a
		// typo, so treat it the same way ExtraSafety treats other anomalies.
		for _, dup := range dups {
			s.logger.Error("Duplicate key found in hosts file (JSON silently kept only the last value; fix the file manually)",
				slog.String("duplicate_pattern", dup),
				slog.String("path", hostsFileName))
		}
		if s.config.ExtraSafety {
			s.logger.Error("ExtraSafety: refusing to continue with duplicate host keys",
				slog.Int("duplicate_count", len(dups)))
			s.shutdown(5)
		}
		// Non-ExtraSafety: warn loudly but continue; the map will have kept
		// whichever value the JSON decoder chose (last-write-wins).
		s.logger.Warn("Continuing despite duplicate host keys — the JSON decoder kept an arbitrary value for each duplicate key; consider fixing the file",
			slog.Int("duplicate_count", len(dups)))
	}

	var raw map[string][]string
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields() //XXX: DisallowUnknownFields only activates for struct targets. For a map[string][]string the decoder treats every key as a valid map entry regardless; kept nonetheless
	if err = dec.Decode(&raw); err != nil {
		return fmt.Errorf("failed to parse hosts file %q: %w", hostsFileName, err)
	}

	var parsed []LocalHostRule
	var changed uint64
	var removed uint64
	seenPatterns := make(map[string]struct{}, len(raw))

	for pat, ips := range raw {
		// pat = strings.ToLower(pat) // normalize for matchPattern
		// var netIPs []net.IP
		// for _, ipStr := range ips {
		// 	if ip := net.ParseIP(ipStr); ip != nil {
		// 		netIPs = append(netIPs, ip)
		// 	} else {
		// 		s.logger.Warn("Invalid IP in hosts file, skipping", slog.String("ip", ipStr), slog.String("pattern", pat))
		// 	}
		// }
		// //TODO: check for dup patterns or hostnames, wtw we're using here.
		// if len(netIPs) > 0 {
		// 	parsed = append(parsed, LocalHostRule{Pattern: pat, IPs: netIPs})
		// }

		// Normalize pattern the same way the WebUI does: trim whitespace, strip
		// trailing FQDN dot, lowercase.  Track whether anything actually changed
		// so we can rewrite the file if needed.
		normalizedPat := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(pat, ".")))
		if normalizedPat != pat {
			s.logger.Warn("Normalized host pattern",
				slog.String("before", pat),
				slog.String("after", normalizedPat))
			changed++
		}

		if normalizedPat == "" {
			s.logger.Warn("Purging host rule with empty pattern (after normalization)",
				slog.String("original_pattern", pat))
			removed++
			continue
		}

		if _, modified := sanitizeDomainInput(normalizedPat); modified {
			s.logger.Error("Purging invalid host pattern containing illegal characters",
				slog.String("invalid_pattern", normalizedPat))
			removed++
			continue

		}

		if _, dup := seenPatterns[normalizedPat]; dup {
			s.logger.Warn("Duplicate host pattern found, skipping/purging",
				slog.String("pattern", normalizedPat))
			removed++
			continue
		}
		seenPatterns[normalizedPat] = struct{}{}

		var netIPs []net.IP
		for _, ipStr := range ips {
			// Mirror the WebUI: trim whitespace around each IP before parsing.
			ipStr = strings.TrimSpace(ipStr)
			if ipStr == "" {
				continue
			}
			if ip := net.ParseIP(ipStr); ip != nil {
				netIPs = append(netIPs, ip)
			} else {
				s.logger.Warn("Invalid IP in hosts file, skipping",
					slog.String("ip", ipStr),
					slog.String("pattern", normalizedPat))
			}
		}

		if len(netIPs) == 0 {
			s.logger.Warn("Purging host rule with no valid IPs after filtering",
				slog.String("pattern", normalizedPat))
			removed++
			continue
		}

		parsed = append(parsed, LocalHostRule{Pattern: normalizedPat, IPs: netIPs})
	}

	if s.config.ExtraSafety && removed > 0 {
		s.logger.Error("ExtraSafety: refusing to remove host rules due to potential typos "+
			"(fix them manually or set extra_safety to false)",
			slog.Uint64("removed_count", removed))
		s.shutdown(5)
	}

	s.localHostsMu.Lock()
	s.localHosts = parsed
	s.localHostsMu.Unlock()

	// s.logger.Info("Loaded host rules", slog.Int("count", len(s.localHosts)), slog.String("path", path))
	s.logger.Info("Loaded host rules",
		slog.Int("count", len(s.localHosts)),
		slog.Uint64("changed_count", changed),
		slog.Uint64("removed_count", removed),
		slog.String("path", hostsFileName))

	if changed > 0 || removed > 0 {
		return s.saveLocalHosts()
	}

	return nil
}

func (s *Server) saveLocalHosts() error {
	var data []byte
	var err error

	// 1. Snapshot the data
	func() {
		s.localHostsMu.RLock()
		defer s.localHostsMu.RUnlock()
		raw := make(map[string][]string)
		for _, rule := range s.localHosts {
			var ips []string
			for _, ip := range rule.IPs {
				ips = append(ips, ip.String())
			}
			raw[rule.Pattern] = ips
		}
		data, err = json.MarshalIndent(raw, "", "  ")
	}()

	if err != nil {
		return fmt.Errorf("hosts file marshal failed: %w", err)
	}

	// 2. Serialize the disk write
	s.fileWriteMu.Lock()
	defer s.fileWriteMu.Unlock()

	if err := s.safeWriteFile(s.config.HostsFile, data, 0600); err != nil {
		return fmt.Errorf("cannot save/write hosts file %q: %w", s.config.HostsFile, err)
	}
	return nil
}

// getResponseBlacklist Helper – returns current list (snapshot copy)
func (s *Server) getResponseBlacklist() []string {
	s.responseBlacklistMu.RLock()
	defer s.responseBlacklistMu.RUnlock()

	out := make([]string, 0, len(s.responseBlacklist))
	for _, n := range s.responseBlacklist {
		out = append(out, n.String())
	}
	return out
}

// isBlacklistedIP Helper – used in filterResponse / processRR
func (s *Server) isBlacklistedIP(ip net.IP) bool {
	s.responseBlacklistMu.RLock()
	defer s.responseBlacklistMu.RUnlock()

	for _, n := range s.responseBlacklist {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func defaultResponseBlacklist() []string {
	return []string{
		// IPv4 loopback – never valid for public hosts
		"127.0.0.0/8",

		// RFC1918 private networks
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",

		// IPv4 link-local (APIPA)
		"169.254.0.0/16",

		// "This network" / unspecified addresses
		"0.0.0.0/8",

		// Carrier-grade NAT (CGNAT)
		"100.64.0.0/10",

		// Documentation / example ranges (RFC 5737)
		"192.0.2.0/24",
		"198.51.100.0/24",
		"203.0.113.0/24",

		// Benchmarking / performance testing
		"198.18.0.0/15",

		// IPv4 multicast
		"224.0.0.0/4",

		// IPv4 reserved / future use
		"240.0.0.0/4",

		// Limited broadcast
		"255.255.255.255/32",

		// IPv6 loopback
		"::1/128",

		// IPv6 unique local addresses (private)
		"fc00::/7",

		// IPv6 link-local
		"fe80::/10",

		// IPv6 documentation range
		"2001:db8::/32",

		// IPv6 multicast
		"ff00::/8",

		// IPv6 unspecified
		"::/128",
	}
}

func (s *Server) saveQueryWhitelist() error {
	var data []byte
	var err error

	// 1. Snapshot the data quickly under RLock to prevent blocking DNS queries during slow I/O
	func() {
		s.ruleMutex.RLock()
		defer s.ruleMutex.RUnlock()
		data, err = json.MarshalIndent(s.whitelist, "", "  ")
	}()

	if err != nil {
		return fmt.Errorf("whitelist marshal failed: %w", err)
	}

	// 2. Serialize the disk write so concurrent WebUI saves don't corrupt the file
	s.fileWriteMu.Lock()
	defer s.fileWriteMu.Unlock()

	whitelistFileName := s.config.WhitelistFile
	if whitelistFileName == "" {
		panic("bad coding: dev. didn't set the default whitelist filename!")
	}
	if err := s.safeWriteFile(whitelistFileName, data, 0600); err != nil {
		return fmt.Errorf("cannot save/write whitelist file %q: %w", whitelistFileName, err)
	}
	s.logger.Info("Saved whitelist file", slog.String("filename", whitelistFileName))
	return nil
}

func (s *Server) flushCache() {
	if s.cacheStore != nil {
		s.cacheStore.Flush()
		s.logger.Debug("Cache flushed/deleted.")
	} else {
		s.logger.Debug("Cache wasn't inited so can't be flushed here.")
	}
}

// Loads whitelist rules from dedicated file
func (s *Server) loadQueryWhitelist() error {
	whitelistFileName := s.config.WhitelistFile
	if whitelistFileName == "" {
		panic("dev. didn't set the default whitelist filename!")
	}
	whitelistFileName = filepath.Clean(s.config.WhitelistFile)
	s.checkPowerLossFile(whitelistFileName)
	data, err := os.ReadFile(whitelistFileName)
	if os.IsNotExist(err) {
		s.logger.Warn("Whitelist file not found, starting with empty whitelist", slog.String("path", whitelistFileName))
		func() {
			s.ruleMutex.Lock()
			defer s.ruleMutex.Unlock()
			s.whitelist = make(map[string][]RuleEntry)
		}() // lock released here
		s.flushCache()
		return s.saveQueryWhitelist() // create "empty" file; uses lock
	}
	if err != nil {
		return fmt.Errorf("cannot read whitelist file %q: %w", whitelistFileName, err)
	}
	if dups, dupErr := detectDuplicateJSONObjectKeys(data); dupErr != nil {
		return fmt.Errorf("failed to scan whitelist file %q for duplicate keys: %w", whitelistFileName, dupErr)
	} else if len(dups) > 0 {
		for _, dup := range dups {
			s.logger.Error("Duplicate key found in whitelist file (JSON silently kept only the last value; fix the file manually)",
				slog.String("duplicate_key", dup),
				slog.String("path", whitelistFileName))
		}
		if s.config.ExtraSafety {
			s.logger.Error("ExtraSafety: refusing to continue with duplicate whitelist keys",
				slog.Int("duplicate_count", len(dups)))
			s.shutdown(5)
		}
		s.logger.Warn("Continuing despite duplicate whitelist keys — the JSON decoder kept an arbitrary value for each duplicate; consider fixing the file",
			slog.Int("duplicate_count", len(dups)))
	}

	var rulesByType map[string][]RuleEntry
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&rulesByType); err != nil {
		return fmt.Errorf("failed to parse whitelist file '%q' (maybe it contains unsupported or typo-ed fields?), err: %w", whitelistFileName, err)
	}
	var changed uint64 = 0
	var removed uint64 = 0

	func() {
		s.ruleMutex.Lock()
		defer s.ruleMutex.Unlock()

		// Count total rules for initial map capacity
		totalRules := 0
		for _, rules := range rulesByType {
			totalRules += len(rules)
		}
		seenIDs := make(map[string]struct{}, totalRules) // global across all types

		s.whitelist = make(map[string][]RuleEntry, len(rulesByType))
		for typ, rules := range rulesByType {
			var cleaned []RuleEntry
			seenPatterns := make(map[string]struct{}, len(rules)) // only per DNS type ie. A, AAAA, HTTPS
			for i := range rules {
				r := &rules[i]
				// XXX: it may not have an ID set at this point
				if r.ID == "" {
					nid := s.newUniqueID(rulesByType) // still guards against rulesByType collisions
					// Also guard against IDs already assigned in this same load pass
					for _, alreadySeen := seenIDs[nid]; alreadySeen; _, alreadySeen = seenIDs[nid] {
						s.logger.Warn("Generated ID collided with already-seen ID in this load pass, regenerating", slog.String("id", nid))
						nid = s.newUniqueID(rulesByType)
					}
					s.logger.Warn("Making new not-already-existing ID for rule that had none", slog.String("id", nid))
					r.ID = nid
					changed++
				}
				//checks against all DNS types not just in 'typ'
				if _, duplicate := seenIDs[r.ID]; duplicate {
					s.logger.Warn("Duplicate rule ID found, skipping/purging it", slog.String("id", r.ID))
					removed++
					continue // Skip appending this rule
				}
				seenIDs[r.ID] = struct{}{}

				//lowercase it and strip the dot at the end:
				new2 := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(r.Pattern, ".")))
				if new2 != r.Pattern {
					s.logger.Warn("Changed rule pattern", slog.Any("new_pattern", new2), slog.String("old_pattern", r.Pattern), slog.Any("original_rule", r))
					r.Pattern = new2
					changed++
				}
				// Check for empty or entirely invalid structures
				if r.Pattern == "" {
					s.logger.Warn("Purging/deleting rule with empty pattern", slog.String("id", r.ID))
					removed++
					continue
				}

				// Validate using the allowed rule character set
				_, modified := sanitizeDomainInput(r.Pattern)
				if modified {
					s.logger.Error("Purging/deleting invalid whitelist rule pattern containing illegal characters",
						slog.String("id", r.ID),
						slog.String("invalid_pattern", r.Pattern),
					)
					removed++
					continue // Purges/omits it from being appended to cleaned slice
				}

				if _, dup := seenPatterns[r.Pattern]; dup {
					s.logger.Warn("Duplicate rule pattern found after normalization, skipping/purging it",
						slog.String("id", r.ID),
						slog.String("pattern", r.Pattern),
						slog.String("type", typ),
					)
					removed++
					continue
				}
				seenPatterns[r.Pattern] = struct{}{}

				cleaned = append(cleaned, *r)
			}

			s.whitelist[typ] = cleaned
		}

		if s.config.ExtraSafety {
			if removed > 0 {
				s.logger.Error("ExtraSafety: Refusing to remove rules due to potential typos(fix them manually or set extra_safety to false)", slog.Uint64("removed_count", removed))
				s.shutdown(5) //FIXME: find a better way to "quit" than exit program here
			}
		}

		s.logger.Info("Loaded whitelist and normalized(aka changed) or removed(if dup IDs) rules",
			slog.Int("types", len(s.whitelist)),
			slog.Uint64("rules", countRules(s.whitelist)),
			slog.Uint64("changed_count", changed),
			slog.Uint64("removed_count", removed),
			slog.String("path", whitelistFileName),
		)
		if countRules(rulesByType)-removed != countRules(s.whitelist) {
			panic("bad coding: lost some rules, shouldn't happen!")
		}
	}() // lock released here
	if changed > 0 || removed > 0 {
		s.flushCache()
		return s.saveQueryWhitelist() //uses lock!
	} else {
		return nil // no error
	}
}

// defaultConfig Every call produces a new map and slice backing array.
// must be func. or else(if configDefaults would be a 'var') the 'make' call/ref. will be shared and the []string{} too.
func defaultConfig() Config {
	return Config{
		ListenDNS: "127.0.0.1:53",
		ListenDoH: "127.0.0.1:443",
		//UIPort:                  8080,
		ListenUI:                "127.0.0.1:8080",
		UpstreamURLs:            []string{"https://9.9.9.9/dns-query", "https://1.1.1.1/dns-query"},
		SNIHostnames:            []string{"dns.quad9.net", "cloudflare-dns.com"}, // if empty it uses the IP or host from the url which also works!
		UpstreamSelectionMode:   "failover",
		UpstreamRetriesPerQuery: 1, // 1 initial try(not counted) + 1 retry(counted here)
		BlockMode:               "nxdomain",
		BlockIP:                 "0.0.0.0",
		GlobalRateQPS:           100,
		GlobalBurstQPS:          100,
		ClientRateQPS:           20,
		ClientBurstQPS:          50,
		CacheMinTTL:             300,
		CacheMaxEntries:         10000,

		WhitelistFile: "query_whitelist.json",
		BlacklistFile: "response_blacklist.json",
		HostsFile:     "hosts2ip.json",

		LogQueriesFile:          "queries.log",
		LogErrorsFile:           "dnsbollocks.log",
		ConsoleLogLevel:         "info",
		LogMaxSizeMB:            4095, // Rotation threshold
		AllowRunAsAdmin:         false,
		BlockAAAAasEmptyNoError: true,
		AllowHTTPSIfAAllowed:    true,
		RemoveHTTPSIPv4Hints:    true,
		WebUIUseTLS:             true,

		// Centralized Network Parameter Defaults

		//this is per operation: o1) read 2 bytes, o2) read the body, o3) write the response; so each 3 operations get this timeout!
		ClientTCPTimeoutSec: 5,

		MaxRecentBlocks:               100,
		UpstreamServerReadTimeoutSec:  30,
		UpstreamServerWriteTimeoutSec: 30,

		//High-latency satellite, VPN, or cellular links will drop upstream queries and trigger premature failovers under a strict 3 or 5-second limit. Conversely, high-availability setups might require an aggressive sub-second timeout to switch nodes rapidly.
		UpstreamDialTimeoutSec:   3,
		UpstreamClientTimeoutSec: 5, // overall per-request timeout
		//When inspecting upstream certificates for error diagnostics, a hardcoded 5-second timeout on firewalled or highly congested links can block or drag out startup sequences and system health loops unnecessarily.
		CertLogTimeoutSec: 5,

		//Resource allocations vary heavily between environments. A low-powered embedded home router running this binary shouldn't maintain 100 idle network connections. On the other hand, heavy enterprise or multi-user environments will exhaust MaxIdleConnsPerHost: 10 instantly, resulting in severe socket thrashing and latency spikes.
		UpstreamIdleConnTimeoutSec:  90,
		UpstreamMaxIdleConns:        100,
		UpstreamMaxIdleConnsPerHost: 10,
		//A 100ms backoff before retrying a transient network error is standard, but on highly congested networks, a longer backoff might be necessary to let the router breathe.
		UpstreamRetryBackoffMs: 100,

		//64KB is generally sufficient for regular DNS queries. However, non-standard corporate extensions or huge specialized EDNS0 queries with heavy DNSSEC attributes can breach this threshold. Additionally, server administrators may want to reduce this payload size even further to defend against memory-exhaustion denial-of-service (DoS) attempts on public interfaces.
		DoHMaxRequestBodyBytes: 65536, //maxDNSTCPPacketSize

		//Allocating a fixed 4096-byte array on every read loop iteration is optimized for EDNS0, but leaves administrators unable to restrict buffer memory consumption on thin-client devices (where standard 512-byte allocations are preferred) or expand it if dealing with custom local setups.
		DNSUDPBufferSize: 4096,

		//If an upstream server returns a temporary error state or a SERVFAIL status, caching it for an inflexible 2 seconds means local applications will repeatedly bombard the proxy and upstream endpoints during an outage. Allowing administrators to extend the negative cache TTL mitigates traffic stampedes during network service degradations.
		CacheNegativeTTLSec: 2,

		//When you return an ip_block or nxdomain response, telling the client's OS to cache that block for exactly 5 minutes (300 seconds) might be too aggressive or too lenient depending on how quickly users update their whitelist rules via the WebUI.
		BlockedResponseTTLSec: 300,

		//If an administrator updates hosts2ip.json, they currently have to wait up to 5 minutes for the cached overrides to expire.
		LocalHostsOverrideTTLSec: 300,

		//You are telling the underlying go-cache library to run its background cleanup sweep exactly every 60 minutes. If CacheMaxEntries is set very high, a 1-hour sweep might allow memory usage to balloon before it gets cleaned up.
		CacheJanitorIntervalMinutes: 60,

		//You added a smart truncation limit to prevent browser crashes when reading massive logs. However, some admins might have beefy machines and want to see 20,000 lines, while others might be running the UI on an old phone and need it capped at 1,000.
		UILogMaxLines: 5000,

		UseEDEInBlockedReply: true,

		ExtraSafety: true,
	}
}

// initBootstrapLogging sets up a colored console-only logger for the earliest messages.
// Called as the FIRST thing in OldMain, before anything else.
func initBootstrapLogging(logger *slog.Logger) *slog.Logger {
	// Use the exact same colored handler you already have (it gracefully falls back if no console)
	bootstrapLevel := slog.LevelDebug // hard-coded for bootstrap — only ~8 lines anyway
	logger = slog.New(NewColoredConsoleHandler(bootstrapLevel, logger))

	// This line is now the very first log in the entire program
	logger.Info("DNSbollocks starting... (bootstrap-logging inited)", slog.String("version", GetVersion()))
	return logger
}

// -----------------------------------------------------------------------------
// Colored console handler (Windows-only, uses your exact color request)
// -----------------------------------------------------------------------------

// XXX: bad Go v1.26.0 causes a crash(heisenbug), the cause is this https://github.com/golang/go/issues/77975#issuecomment-4021553575 and fix appears to be commit 6ab37c1ca59664375786fb2f3c122eb3db98e433 (addon) also seen in https://go-review.googlesource.com/c/go/+/753040 well the cause is this commit first: https://github.com/golang/go/commit/1a44be4cecdc742ac6cce9825f9ffc19857c99f3 )! See also: https://gist.github.com/bradfitz/46c4b69ee8d6db639f3f7bf52594675a

type ColoredConsoleHandler struct {
	Level   slog.Level
	Out     io.Writer
	Mu      *sync.Mutex
	Counter *uint64 // ADDED: Shared counter to track alternating rows
	Attrs   []slog.Attr
	Group   string
}

func NewColoredConsoleHandler(level slog.Level, logger *slog.Logger) slog.Handler {
	// Activate Windows VT Processing globally
	err := wincoe.EnableVirtualTerminalProcessing()
	if err != nil {
		logger.Warn("EnableVirtualTerminalProcessing failed", SafeErr(err)) //itwontFIXME: figure out if this would recuse infinitely
	}

	var c uint64 // Initialize the shared counter (escapes to heap, doh)
	return &ColoredConsoleHandler{
		Level:   level,
		Out:     os.Stdout,
		Mu:      &sync.Mutex{},
		Counter: &c, // Share pointer across clones
	}
}

func (h *ColoredConsoleHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= h.Level
}

func (h *ColoredConsoleHandler) Handle(ctx context.Context, r slog.Record) error {
	h.Mu.Lock()
	defer h.Mu.Unlock()

	// Increment line counter to determine zebra striping (even/odd)
	*h.Counter++
	isOdd := (*h.Counter % 2) != 0

	isDebug := false
	baseColor := "\x1b[37m" // Default to White
	var equalsColor string
	var bgColor string // Track the background color for the line

	if r.Level <= slog.LevelDebug {
		isDebug = true
		baseColor = "\x1b[90m"   // Gray
		equalsColor = "\x1b[37m" // White
		//bgColor = "\x1b[48;5;234m" // Very dark gray for Debug
		if isOdd {
			bgColor = "\x1b[48;5;234m" // Dark gray A
		} else {
			bgColor = "\x1b[48;5;235m" // Dark gray B
		}
	} else {
		equalsColor = "\x1b[95m" // Light Magenta / Purple
		//bgColor = "\x1b[48;5;235m" // Default dark gray fallback
		if isOdd {
			bgColor = "\x1b[48;5;235m"
		} else {
			bgColor = "\x1b[48;5;236m"
		}
	}

	levelColor := baseColor

	switch r.Level {
	case slog.LevelInfo:
		levelColor = "\x1b[93m" // Yellow, used for cache_hit tho
		//bgColor = "\x1b[48;5;236m" // Slightly lighter dark gray for Info
		if isOdd {
			bgColor = "\x1b[48;5;236m" // Lighter dark gray A
		} else {
			bgColor = "\x1b[48;5;237m" // Lighter dark gray B
		}
	case slog.LevelWarn:
		//levelColor = "\x1b[93m" // Yellow, used for cache_hit tho
		levelColor = "\x1b[95m" // Light Magenta / Purple
		//levelColor = "\x1b[38;5;208m" // Vibrant Orange
		//bgColor = "\x1b[48;5;53m" // Deep dark purple for Warn
		if isOdd {
			bgColor = "\x1b[48;5;53m" // Deep purple A
		} else {
			bgColor = "\x1b[48;5;54m" // Deep purple B (slightly lighter)
		}
	case slog.LevelError:
		levelColor = "\x1b[91m" // Red
		// bgColor = "\x1b[48;5;52m" // Deep dark red for Error
		if isOdd {
			bgColor = "\x1b[48;5;52m" // Deep red A
		} else {
			bgColor = "\x1b[48;5;88m" // Deep red B (slightly lighter)
		}
	}

	// --- NEW: Pre-scan for action color ---
	var statusColor string
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "action" {
			statusColor = QueryActionANSI[a.Value.String()]
			return false // Stop iterating
		}
		return true
	})
	// --------------------------------------

	timeStr := r.Time.Format(TimeStampsFormat) //"15:04:05.000")

	buf := bytes.NewBuffer(make([]byte, 0, 1024))

	// Apply the background color right at the start of the line
	buf.WriteString(bgColor)

	// Level string (colored)
	// Write the level text (also in the level color)
	buf.WriteString(levelColor)
	buf.WriteString(r.Level.String())

	// Reset back to the base color for the message text
	buf.WriteString(baseColor)
	buf.WriteString(" ")

	// Base color, time
	//buf.WriteString(baseColor)
	//// Write the timestamp using the level color (e.g., Yellow for WARN, Red for ERROR)
	//buf.WriteString(levelColor)
	buf.WriteString(timeStr)
	buf.WriteString(" ")

	// Process msg with potential <color> tags
	buf.WriteString(formatColorTags(r.Message, baseColor))

	var processAttr func(a slog.Attr, prefix string)
	processAttr = func(a slog.Attr, prefix string) {
		a.Value = a.Value.Resolve()
		if a.Equal(slog.Attr{}) {
			return
		}
		if a.Value.Kind() == slog.KindGroup {
			attrs := a.Value.Group()
			if len(attrs) == 0 {
				return
			}
			if a.Key != "" {
				prefix += a.Key + "."
			}
			for _, ga := range attrs {
				// Note: In a real group scenario, you might need to pass
				// statusColor recursively if domain/proto are inside groups.
				processAttr(ga, prefix)
			}
			return
		}

		key := prefix + a.Key
		valStr := a.Value.String()

		valColor := baseColor

		// Auto-color matching actions/errors

		// valColor logic using a tagged switch
		switch key {
		case "action", "domain", "type", "ips":
			if statusColor != "" {
				valColor = statusColor
			}
		case "exe", "services", "proto":
			if isDebug {
				valColor = "\x1b[34m" // (dark)blue
			} else {
				valColor = "\x1b[94m" // bright blue
			}
		case "err", "error":
			if valStr != "<nil>" {
				valColor = "\x1b[91m" // Red
			}
		}
		// ----------------------

		// Support explicit <color> overrides in value
		valStrFormatted := formatColorTags(valStr, valColor)

		// Uncomment the line below if you want to force everything onto one line
		valStrFormatted = strings.ReplaceAll(valStrFormatted, "\n", "\\n")

		buf.WriteString(" ")
		buf.WriteString(key)

		buf.WriteString(equalsColor)
		buf.WriteString("=")
		buf.WriteString(valColor)

		needsQuotes := strings.ContainsAny(valStrFormatted, " \t\n\r=") || len(valStrFormatted) == 0
		if needsQuotes {
			buf.WriteString(`"`)
			escaped := strings.ReplaceAll(valStrFormatted, `\`, `\\`)
			escaped = strings.ReplaceAll(escaped, `"`, `\"`)
			buf.WriteString(escaped)
			buf.WriteString(`"`)
		} else {
			buf.WriteString(valStrFormatted)
		}
		buf.WriteString(baseColor)
	}

	for _, a := range h.Attrs {
		processAttr(a, h.Group)
	}
	r.Attrs(func(a slog.Attr) bool {
		processAttr(a, h.Group)
		return true
	})

	// \x1b[K extends the background color to the right edge of the terminal.
	// \x1b[0m then clears all formatting(aka full reset) before dropping to the next line.
	buf.WriteString("\x1b[K\x1b[0m\n")
	//buf.WriteString("\x1b[0m\n") // Full reset at End Of Line

	_, err := h.Out.Write(buf.Bytes())
	return err
}

func (h *ColoredConsoleHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ColoredConsoleHandler{
		Level:   h.Level,
		Out:     h.Out,
		Mu:      h.Mu,
		Counter: h.Counter, // Carry over the counter pointer
		Attrs:   append(h.Attrs[:len(h.Attrs):len(h.Attrs)], attrs...),
		Group:   h.Group,
	}
}

func (h *ColoredConsoleHandler) WithGroup(name string) slog.Handler {
	prefix := h.Group
	if name != "" {
		prefix += name + "."
	}
	return &ColoredConsoleHandler{
		Level:   h.Level,
		Out:     h.Out,
		Mu:      h.Mu,
		Counter: h.Counter, // Carry over the counter pointer
		Attrs:   h.Attrs,
		Group:   prefix,
	}
}

// -----------------------------------------------------------------------------
// Query filter (only lets "query" category through to queries.log)
// -----------------------------------------------------------------------------

type queryFilterHandler struct {
	slog.Handler
}

func (h queryFilterHandler) Handle(ctx context.Context, r slog.Record) error {
	isQuery := false
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "category" && a.Value.String() == "query" {
			isQuery = true
			return false // stop early
		}
		return true
	})
	if !isQuery {
		return nil // silently dropped — this is the magic
	}
	return h.Handler.Handle(ctx, r)
}

// -----------------------------------------------------------------------------
// Multi-handler (the core of "one call logs everywhere")
// -----------------------------------------------------------------------------

type multiHandler struct {
	handlers []slog.Handler
}

func (m multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (m multiHandler) Handle(ctx context.Context, r slog.Record) error {
	var firstErr error
	for _, h := range m.handlers {
		if h.Enabled(ctx, r.Level) {
			if err := h.Handle(ctx, r.Clone()); err != nil && firstErr == nil {
				firstErr = err // continue anyway
			}
		}
	}
	return firstErr
}

func (m multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newH := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		newH[i] = h.WithAttrs(attrs)
	}
	return multiHandler{handlers: newH}
}

func (m multiHandler) WithGroup(name string) slog.Handler {
	newH := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		newH[i] = h.WithGroup(name)
	}
	return multiHandler{handlers: newH}
}

func parseConsoleLogLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug", "d":
		return slog.LevelDebug
	case "warn", "warning", "w":
		return slog.LevelWarn
	case "error", "e":
		return slog.LevelError
	default: // "info" or anything else
		return slog.LevelInfo
	}
}

// Globals.

// var (
// 	backgroundCtx, cancel = context.WithCancel(context.Background())
// )

var dnsTypes = []string{
	//most used first
	"A",
	"AAAA",  // dup on purpose
	"HTTPS", // dup on purpose
	"MX",    // dup on purpose
	"NS",    // dup on purpose
	"A6",
	"AAAA",
	"AFSDB",
	"AMTRELAY",
	"ANY",
	"APL",
	"AVC",
	"AXFR",
	"CAA",
	"CDNSKEY",
	"CDS",
	"CERT",
	"CNAME",
	"CSYNC",
	"DHCID",
	"DLV",
	"DNAME",
	"DNSKEY",
	"DOA",
	"DS",
	"EUI48",
	"EUI64",
	"GPOS",
	"HINFO",
	"HIP",
	"HTTPS",
	"IPSECKEY",
	"ISDN",
	"IXFR",
	"KEY",
	"KX",
	"L32",
	"L64",
	"LOC",
	"LP",
	"MAILA",
	"MAILB",
	"MB",
	"MD",
	"MF",
	"MG",
	"MINFO",
	"MR",
	"MX",
	"NAPTR",
	"NID",
	"NINFO",
	"NS",
	"NSAP",
	"NSAP-PTR",
	"NSEC",
	"NSEC3",
	"NSEC3PARAM",
	"NULL",
	"NXT",
	"OPENPGPKEY",
	"OPT",
	"PTR",
	"PX",
	"RKEY",
	"RP",
	"RRSIG",
	"RT",
	"SIG",
	"SOA",
	"SPF",
	"SRV",
	"SSHFP",
	"SVCB",
	"TA",
	"TALINK",
	"TKEY",
	"TLSA",
	"TSIG",
	"TXT",
	"URI",
	"WKS",
	"X25",
	"ZONEMD",
}

// dnsTypeSet is a deduplicated set built from dnsTypes for O(1) lookups.
// dnsTypes intentionally has duplicates for UI ordering; this set is for validation only.
var dnsTypeSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(dnsTypes))
	for _, t := range dnsTypes {
		m[t] = struct{}{}
	}
	return m
}()

type BlockedQuery struct {
	Domain      string    `json:"domain"`
	Type        string    `json:"type"`
	Time        time.Time `json:"time"`
	IsUnblocked bool      `json:"-"` // dynamically set for the UI
}

/*
NOTES:
DNS query uses only the ASCII form:

	letters a–z
	digits 0–9
	hyphen -
	dot .

What this enforces:

	Labels don’t start or end with -
	Labels ≤ 63 chars
	Total length ≤ 253 chars
	ASCII-only DNS reality
*/
var dnsNameRE = regexp.MustCompile(
	`^(?i)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`,
)

func isValidDNSName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	return dnsNameRE.MatchString(s)
}

// sanitizeDomainInput removes any characters not explicitly allowed.
// Safe for logs and DNS-related handling.
func sanitizeDomainInput(input string) (sanitized string, modified bool) {
	const allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-{}*!?_"

	var b strings.Builder
	b.Grow(len(input)) // safe over-allocation, but done only one allocation not more than once as it could happen without it.

	for _, r := range input {
		if strings.ContainsRune(allowed, r) {
			b.WriteRune(r)
		}
	}

	sanitized = b.String()
	modified = sanitized != input
	// Uses named returns — do not return explicit values. like: return "something", modified
	return
}

// validateRulePattern returns a non-nil error if the pattern contains characters
// outside the allowed set (as defined by sanitizeDomainInput).
// It does NOT enforce strict DNS name rules because patterns may contain
// wildcards: *, **, {*}, {**}, ?, !, and braces.
func validateRulePattern(pattern string) error {
	if pattern == "" {
		return errors.New("pattern cannot be empty")
	}
	if _, modified := sanitizeDomainInput(pattern); modified {
		return errors.New("pattern contains illegal characters")
	}
	return nil
}

// validateDNSType returns a non-nil error if typ is not a known DNS type.
func validateDNSType(typ string) error {
	if _, ok := dnsTypeSet[typ]; !ok {
		return fmt.Errorf("unknown DNS type %q", typ)
	}
	return nil
}

var uiTemplates = template.Must(template.ParseFS(templates.FS, "ui.html"))

//var uiTemplates = template.Must(template.New("").Parse(
//    `
//`))

const configFileName = "config.json"

// func logFatal(logger *slog.Logger, msg string, err error) {
// 	logger.Error(msg, SafeErr(err))
// 	shutdown(1) //os.Exit(1) // replaced log.Fatal
// }

// func logFatal2(logger *slog.Logger, msg string) {
// 	logger.Error(msg)
// 	shutdown(1) //os.Exit(1) // replaced log.Fatal
// }

func (s *Server) logFatal(msg string, err error) {
	s.logger.Error(msg, SafeErr(err))
	s.shutdown(1) //os.Exit(1) // replaced log.Fatal
}

func (s *Server) logFatal2(msg string) {
	s.logger.Error(msg)
	s.shutdown(1) //os.Exit(1) // replaced log.Fatal
}

func getWebUIPasswordHashJSONTag() string {
	var cfg Config
	t := reflect.TypeOf(cfg)
	if field, found := t.FieldByName("WebUIPasswordHash"); found {
		tag := field.Tag.Get("json")
		// Strip away options like ,omitempty if present
		if idx := strings.Index(tag, ","); idx != -1 {
			return tag[:idx]
		}
		return tag
	}
	return "webui_password_hash" // Fallback safety
}

func (s *Server) Run() error {
	// Signals setup FIRST: Catch interrupts from init onward
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)
	s.logger.Debug("Signal channel ready - Ctrl+C to shutdown gracefully")

	if err := s.loadConfig(); err != nil {
		s.logFatal("Config load failed:", err)
		// s.logger.Error("Config load failed", SafeErr(err))
		// os.Exit(1) // replaced log.Fatal
	}
	s.logger.Info("Config loaded", slog.String("file", configFileName))

	if !s.config.AllowRunAsAdmin && isAdmin {
		s.logFatal2("Exiting: Elevated privileges detected. Rerun without admin or change the config setting.")
		//os.Exit(1)
	}
	//s.logger.Debug("Non-elevated mode confirmed") // no good, as we can be admin here!

	// Now we have the real config → switch to full logging
	s.initFullLogging() // ← this replaces the logger with files + correct console level

	s.cacheStore = cache.New(time.Duration(s.config.CacheJanitorIntervalMinutes)*time.Minute, time.Duration(s.config.CacheJanitorIntervalMinutes)*time.Minute) // Janitor every hour
	s.logger.Debug("Cache initialized")

	s.globalLimiter = rate.NewLimiter(rate.Limit(s.config.GlobalRateQPS), s.config.GlobalBurstQPS)
	s.logger.Debug("Rate limiter initialized")

	if err := s.validateUpstream(); err != nil {
		s.logFatal("Upstream validation failed:", err)
	}
	s.logger.Debug("Upstreams validated",
		SafeStringSlice("upstreamURLs", s.config.UpstreamURLs),
		//slog.Any("upstreamURLs", config.UpstreamURLs),
		//slog.Any("upstreamIPs", upstreamIPs),
		SafeStringSlice("upstreamIPs", s.upstreamIPs),
	)

	s.generateCertIfNeeded() // For DoH and webUI!
	//s.logger.Debug("Cert checked/generated if needed")

	s.initDoHClients()
	// Sequential launches for ordered logging
	s.logger.Debug("Launching listeners sequentially...")
	s.startDNSListener(s.config.ListenDNS) // Blocks until complete/fail
	s.startDoHListener(s.config.ListenDoH) // Blocks until complete/fail
	go s.startWebUI(s.config.ListenUI)     // Concurrent server (blocks forever, but post-serial)

	go s.watchKeys(
		func() { // Ctrl+R aka reloadFn
			s.logger.Debug("Reload triggered...")
			s.flushCache()

			if err := s.loadQueryWhitelist(); err != nil {
				s.logFatal("Whitelist reload failed:", err)
			} else {
				s.logger.Debug("Whitelist reloaded")
			}
			if err := s.loadResponseBlacklist(); err != nil {
				s.logFatal("Blacklist reload failed:", err)
			} else {
				s.logger.Debug("Blacklist reloaded")
			}
			// Inside watchKeys, in the Ctrl+R lambda block:
			if err := s.loadLocalHosts(); err != nil {
				s.logFatal("Hosts reload failed:", err)
			} else {
				s.logger.Debug("Local hosts reloaded")
			}

			func() {
				s.dohMu.Lock()
				defer s.dohMu.Unlock()
				s.upstreamsPtr.Store(nil)
			}()
			_ = s.initDoHClients()
			// if upstreamsSlicePtr := s.upstreamsPtr.Load(); upstreamsSlicePtr != nil {
			// 	newLen := len(*upstreamsSlicePtr)
			// 	s.failoverSelect.mu.Lock()
			// 	if s.failoverSelect.activeIndex >= newLen {
			// 		s.failoverSelect.activeIndex = 0
			// 	}
			// 	s.failoverSelect.mu.Unlock()
			// }

			// 🟢 RESET THE SELECTOR STATE UNCONDITIONALLY HERE:
			s.failoverSelect.mu.Lock()
			s.failoverSelect.activeIndex = 0
			s.failoverSelect.allFailed = false
			s.failoverSelect.mu.Unlock()

			s.logger.Warn(
				"Reloading of configuration file wasn't done; restart required for changes. This reload only works for whitelist and blacklist changes.",
				slog.String("config_file", configFileName),
			)
		},
		func() { // alt+x Ctrl+X etc. aka cleanExitFn
			s.logger.Debug("Shutdown signal received, clean exit.")
			//doneFIXME: at least UDP DNS listener isn't shutdown while waiting for keypress to exit (after the shutdown(0) below) !!
			//cancel()    //doneFIXME: this triggers the below shutdown(4) !
			s.shutdown(0) // clean exit
		},
	)

	//<-sigChan // Wait here - UI goroutine handles serving
	// 4. The Seamless Wait
	select {
	case sig := <-sigChan:
		// Case A: User pressed Ctrl+C
		s.logger.Info("shutdown initiated by signal", slog.String("signal", sig.String()))
		// Proceed to graceful cleanup
		//cancel()      // Cancel context for graceful close
		s.shutdown(130) // Ctrl+C / SIGTERM → non-clean exit => exit code 130 (128+2 like in linux)

	case err := <-s.errChan:
		// Case B: A background goroutine (TCP/DoH) died
		s.logger.Error("CRITICAL: background service failure", SafeErr(err))
		// You can choose to exit(1) here because a vital organ failed
		//cancel()    // Cancel context for graceful close
		s.shutdown(3) // some error happened

	case <-s.ctx.Done():
		// Case C: Context was cancelled elsewhere
		s.logger.Info("context cancelled, shutting down")
		//cancel()    // Cancel context for graceful close, this was already done since we hit this.
		s.shutdown(4) // some error happened
	}

	return nil //unreachable tho
}

func OldMain() {

	// s.logger is the single source of truth. Every log event goes through ONE call here.
	// The multiHandler then fans it out to:
	//   - dnsbollocks.log (JSON, everything)
	//   - queries.log (JSON, only category=query)
	//   - console (colored text, >= ConsoleLogLevel)
	//
	// var s.logger *slog.Logger
	// s.logger starts as a bootstrap colored console logger (Info level).
	// It is replaced after loadConfig() with the full multi-handler (files + config level).
	// This guarantees the very first line of OldMain already uses s.logger.
	var mainLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug, //TODO: allow env. var. to dictate the level? but nothing right now uses this yet because initBootstrapLogging gets hit early!
	}))

	// wincoe.InstallCrashSink()
	// if true {
	//     panic("deliberate panic")
	// }
	// // TEMPORARY: race detector smoke test — remove before release
	//     var raceTest int
	//     done := make(chan struct{})
	//     go func() {
	//         raceTest = 1 // concurrent write
	//         close(done)
	//     }()
	//     raceTest = 2 // concurrent write
	//     <-done
	//     _ = raceTest
	// temporary placeholder — will be overwritten in initBootstrapLogging

	mainLogger = initBootstrapLogging(mainLogger) // ← FIRST LINE — colored console, s.logger now exists
	// go func() {
	//     ticker := time.NewTicker(5 * time.Second)
	//     defer ticker.Stop()
	//     for range ticker.C {
	//         s.logger.Debug("MARK")
	//     }
	// }()
	// go func() {
	//     for {
	//         wincoe.Churn2()
	//         // No sleep here, or a very small one
	//         time.Sleep(20 * time.Millisecond)
	//     }
	// }()

	//flag.Parse() // For future flags
	hashCmd := flag.Bool("hash-password", false, "Securely prompt for a password, output the bcrypt hash, and exit")
	flag.Parse()
	if *hashCmd {
		hash, err := promptAndHashPassword(mainLogger)
		if err != nil {
			mainLogger.Error("Failed to set password: ", SafeErr(err))
			finalShutdownSequence(mainLogger, 1)
		}
		//fmt.Printf("\nSuccess! Paste this exact string into your %s as the value for \"webui_password_hash\":\n%s\n", configFileName, hash)
		// Dynamic tag extraction
		var jsonTag string = getWebUIPasswordHashJSONTag()
		fmt.Printf("\nSuccess! Paste this exact string into your %s as the value for %q:\n%s\n", configFileName, jsonTag, hash)
		mainLogger.Debug("Generated new hash password(not logging it) via cmd line arg, not saved in config.", slog.String("config", configFileName))
		finalShutdownSequence(mainLogger, 0)
	}
	// if len(os.Args) > 1 {
	//     configPath = os.Args[1]
	// }

	srv := NewServer(mainLogger)

	if err := srv.Run(); err != nil {
		mainLogger.Error("Server exited with error", SafeErr(err))
		srv.shutdown(1)
	}

	mainLogger.Error("unreachable")
	//cancel()     // Cancel context for graceful close
	srv.shutdown(44) // impossible to reach this, unless code was added later and shutdown/exit was forgotten above.
}

func (s *Server) loadConfig() error {
	const cfgFname = configFileName
	s.logger.Info("Loading config file", slog.String("config_file", cfgFname))
	var shouldSaveConfig = false
	// ---> FIX: Pre-populate the global config with defaults BEFORE reading/decoding
	// this way missing keys from config.json file will be set to default value!
	// 1. ALWAYS start by filling the global config with defaults.
	// This is critical because Decode only overwrites what is in the file.
	defaultConfig := defaultConfig()
	//config = defaultConfig // deep copy, presumably!(it's shallow, but strings are immutable so it's acting like a deep-copy for them) doneFIXME?
	s.config = defaultConfig.Clone() // deep copy

	s.checkPowerLossFile(cfgFname)
	data, err := os.ReadFile(cfgFname)
	if err != nil {
		if isAdmin {
			return fmt.Errorf("config file %q not found; refusing to create a new config file with defaults due to running as Admin!"+
				" because you're likely just in the wrong dir like %%WINDIR%%\\System32\\", cfgFname)
		} else {
			// not admin, auto create config file with defaults
			//FIXME: make sure it's not found not just don't have read permission (but could have write!)
			s.logger.Warn("Config file not found or unreadable; using defaults and creating new file", slog.String("config_file", cfgFname))
		}
		// Defaults
		// REMOVED: config = DefaultConfig() because it is already set above
		//config = DefaultConfig()

		shouldSaveConfig = true
	} else {
		// Duplicate config keys (e.g. "extra_safety" appearing twice) are silently
		// last-write-wins in Go's json.Decoder.  Catch them before decoding.
		// s.config.ExtraSafety is not yet populated from the file at this point, so
		// we always treat duplicate config keys as a hard error regardless of that
		// setting — a config with duplicate keys is unambiguously a hand-edit mistake.
		if dups, dupErr := detectDuplicateJSONObjectKeys(data); dupErr != nil {
			return fmt.Errorf("failed to scan config file %q for duplicate keys: %w", cfgFname, dupErr)
		} else if len(dups) > 0 {
			for _, dup := range dups {
				s.logger.Error("Duplicate key found in config file (JSON silently kept only the last value; fix the file manually)",
					slog.String("duplicate_key", dup),
					slog.String("config_file", cfgFname))
			}
			return fmt.Errorf("config file %q contains %d duplicate key(s); fix the file and restart", cfgFname, len(dups))
		}

		// 2. First, check for unknown fields and decode into 'config'
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields() // This is why we use NewDecoder
		//var theReadConfig Config = DefaultConfig()

		//FIXME: any reload into existing config would race with other readers of config.* values, in theory, as this isn't mutex protected. But we don't reload config anyway, only the whitelist/blacklist which are mutexed.

		// dec.Decode will now overwrite ONLY the fields present in the JSON.
		// Missing fields will retain the values from DefaultConfig().
		if err = dec.Decode(&s.config); err != nil {
			//if err = dec.Decode(&theReadConfig); err != nil {
			s.logger.Error("Config file has typos or unknown fields", slog.String("file", cfgFname), SafeErr(err))
			return fmt.Errorf("Config has typos or unknown fields: %w", err)
		}
		// 3. Second, check for MISSING fields (No manual list!)
		// We decode into a map just to see which keys exist in the JSON.
		var presentKeys map[string]any
		if err2 := json.Unmarshal(data, &presentKeys); err2 != nil {
			panic(fmt.Errorf("shouldn't happen since decoding into Config worked! err:%w", err2))
			//return err
		}

		// 3. Check for MISSING fields
		// Use reflection to compare the struct's "json" tags against the map

		// missing := []string{}
		// t := reflect.TypeOf(config)
		// for i := 0; i < t.NumField(); i++ {
		//     tag := t.Field(i).Tag.Get("json")
		//     if tag == "" || tag == "-" {
		//         continue
		//     }

		//     if _, ok := presentKeys[tag]; !ok {
		//         missing = append(missing, tag)
		//     }
		// }

		// Use TypeFor[T] (Go 1.22+) and VisibleFields (Go 1.17+)
		missing := []string{}
		t := reflect.TypeFor[Config]()
		// reflect.Indirect safely handles both values and pointers (like *Config)
		v := reflect.Indirect(reflect.ValueOf(s.config))
		for _, field := range reflect.VisibleFields(t) {
			tag := field.Tag.Get("json")
			if tag == "" || tag == "-" {
				continue
			}

			if _, ok := presentKeys[tag]; !ok {
				val := v.FieldByIndex(field.Index).Interface()
				//missing = append(missing, tag)
				missing = append(missing, fmt.Sprintf("%s=%v", tag, val))
			}
		}

		if len(missing) > 0 {
			s.logger.Warn("Config file has missing keys - using default values for those keys", slog.String("config_file", cfgFname),
				SafeStringSlice("missing", missing),
			)
			shouldSaveConfig = true
		}
		// if theReadConfig != config {
		//     s.logger.Warn("Config file had 1 or more missing fields, using defaults for those and triggering a save next.", slog.String("file", cfgFname))
		//     config = theReadConfig
		//     shouldSaveConfig = true
		// }
	}

	if s.config.GlobalBurstQPS < s.config.GlobalRateQPS {
		s.logFatal2(fmt.Sprintf("global QPS burst(%d) must be >= than rate(%d) in %s", s.config.GlobalBurstQPS, s.config.GlobalRateQPS, configFileName))
	}

	if s.config.ClientBurstQPS < s.config.ClientRateQPS {
		s.logFatal2(fmt.Sprintf("client QPS burst(%d) must be >= than rate(%d) in %s", s.config.ClientBurstQPS, s.config.ClientRateQPS, configFileName))
	}

	s.config.BlockMode = strings.ToLower(s.config.BlockMode) //XXX: lowercasing this for future comparisons to be easier!
	//TODO: ensure only valid values are used here for config.BlockMode or warn/exit!

	const CacheMinTTLClamp = 60 // seconds
	// Validate loaded config
	if s.config.CacheMinTTL < CacheMinTTLClamp {
		s.config.CacheMinTTL = CacheMinTTLClamp // Min reasonable
		s.logger.Warn("cache_min_ttl clamped", slog.Int("to_seconds", CacheMinTTLClamp))
	}

	// Ensure SNIHostnames has the same length as UpstreamURLs, falling back to the URL's hostname
	for i := len(s.config.SNIHostnames); i < len(s.config.UpstreamURLs); i++ {
		host, err2 := hostFromURL(s.config.UpstreamURLs[i])
		if err2 != nil {
			return fmt.Errorf("invalid upstream URL at index %d: %w", i, err2)
		}
		s.config.SNIHostnames = append(s.config.SNIHostnames, host)
		shouldSaveConfig = true
	}
	for i := range s.config.UpstreamURLs {
		if s.config.SNIHostnames[i] == "" {
			host, err2 := hostFromURL(s.config.UpstreamURLs[i])
			if err2 != nil {
				return fmt.Errorf("invalid2 upstream URL at index %d: %w", i, err2)
			}
			s.config.SNIHostnames[i] = host
			shouldSaveConfig = true
		}
	}
	s.logger.Debug("Using upstream SNI hostnames:",
		//slog.Any("SNI_hostnames", config.SNIHostnames),
		SafeStringSlice("SNI_hostnames", s.config.SNIHostnames),
	)

	// Helper closure to apply the cleaning and track if a save is needed
	checkAndClean := func(target *string, desc, fallback string) {
		if cleaned, changed := s.cleanFileName(*target, desc, fallback); changed {
			*target = cleaned
			if !shouldSaveConfig {
				shouldSaveConfig = true
			}
		}
	}

	checkAndClean(&s.config.BlacklistFile, "blacklist_file", defaultConfig.BlacklistFile)
	checkAndClean(&s.config.WhitelistFile, "whitelist_file", defaultConfig.WhitelistFile)
	checkAndClean(&s.config.LogQueriesFile, "log_queries", defaultConfig.LogQueriesFile)
	checkAndClean(&s.config.LogErrorsFile, "log_errors", defaultConfig.LogErrorsFile)
	checkAndClean(&s.config.HostsFile, "hosts_file", defaultConfig.HostsFile)

	// After decoding config
	err = s.loadQueryWhitelist()
	if err != nil {
		return err
	}
	err = s.loadResponseBlacklist()
	if err != nil {
		return err
	}
	if err = s.loadLocalHosts(); err != nil {
		return err
	}

	// Add your new clear architectural description line here:
	switch s.config.UpstreamSelectionMode {
	case "strict":
		s.logger.Info("Upstream DNS strategy initialized: STRICT MATCH MODE (All upstreams queried; queries will be safely dropped if response IPs mismatch to protect against manipulation/spoofing; WARNING: Virtually unusable on standard networks due to false-positive drops caused by modern CDNs, Geo-DNS routing, and load balancers returning different IPs for identical queries.).")
	case "failover":
		s.logger.Info("Upstream DNS strategy initialized: FAILOVER MODE (Sticky sequence tracking; queries the current active upstream and all higher-priority(first in list are higher prio.) failed upstreams in parallel to eliminate timeout penalties while instantly healing and restoring primary upstreams the moment they recover.).")
	case "fastest":
		fallthrough
	default:
		s.logger.Info("Upstream DNS strategy initialized: FASTEST WINS MODE (Racing upstreams concurrently; the first successful response is accepted immediately to optimize for CDNs, Geo-DNS, and speed).")
	}

	// NEW: Enforce password setup if it's missing from the config
	if s.config.WebUIPasswordHash == "" {
		s.logger.Warn("No WebUI password configured. Securing WebUI now...")
		fmt.Println("\n========================================================")
		fmt.Println("   INITIAL SETUP: SECURING YOUR WEB CONTROL PANEL ")
		fmt.Println("========================================================")
		hash, err2 := promptAndHashPassword(s.logger)
		if err2 != nil {
			s.logFatal2("Failed to setup password (aborted): " + err2.Error())
		}

		// Update live config instance
		s.config.WebUIPasswordHash = hash

		s.logger.Info("WebUI password successfully set.")
		if !shouldSaveConfig {
			shouldSaveConfig = true
		}
	}

	if shouldSaveConfig {
		if err = s.saveConfig(); err != nil {
			return fmt.Errorf("config save failed: %w", err)
		}
	}
	return nil
}

// powerlossFileExtension any saved file with this extension means power-loss (or panic in code?) occurred in a very tiny window and thus this is your potentially safe config and should be manually investigated for restoration purposes esp. if the main file is 0 bytes.
const powerlossFileExtension string = ".powergotlost"

// safeWriteFile attempts a crash-safe file update without using os.Rename,
// preserving Windows ACLs and falling back gracefully if directory permissions
// block the creation of temporary files.
//
// By writing the complete payload to [filename].powergotlost first, flushing it to hardware, and only then truncating the target file, you create a cryptographic-like commit phase.
func (s *Server) safeWriteFile(filename string, data []byte, perm os.FileMode) error {
	if s.config.ExtraSafety {
		tmpName := filename + powerlossFileExtension

		// 1. Try to write to a temp file first to ensure disk space and data integrity.
		tmpFile, err := os.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
		if err == nil {
			_, writeErr := tmpFile.Write(data)
			syncErr := tmpFile.Sync()
			tmpFile.Close()

			if writeErr == nil && syncErr == nil {
				// Temp file is safely on disk. Overwrite the target file directly
				// so we don't alter its existing Windows permissions/ACLs.
				//XXX: which means we fallthru here

				// targetFile, targetErr := os.OpenFile(filename, os.O_WRONLY|os.O_TRUNC, perm)
				// if targetErr == nil {
				// 	_, _ = targetFile.Write(data)
				// 	_ = targetFile.Sync()
				// 	targetFile.Close()
				// }
				s.logger.Debug("ExtraSafety: Staged recovery file on disk", slog.String("tempfilename", tmpName))
				// and after the below fallthru (from step 2) then Clean up the temp file

				// Queue cleanup. If we crash/lose power after this point,
				// this defer never runs, leaving the safe copy intact.
				defer func() {
					ondeleteErr := os.Remove(tmpName)
					if ondeleteErr == nil {
						s.logger.Debug("ExtraSafety: unStaged recovery file from disk", slog.String("tempfilename", tmpName))
						// Successful deletion, nothing more to do
						return
					}
					//aside: Trying to rename the file as an intermediary step (e.g., trying to rename file.json.powergotlost to file.json.trash) usually fails under the exact same security context as a deletion. In almost all operating systems and file systems (including Windows NTFS), a Rename operation requires delete/modify privileges on the source file to un-link it from its original name. Wiping it to 0 bytes bypasses the directory management layer entirely and works purely on file-level write access, making it the most robust fallback option available.
					s.logger.Warn("ExtraSafety: failed to delete staging file(possibly due to directory permissions?), attempting truncation fallback", SafeErr(ondeleteErr))
					// Fallback: If we can't delete it, truncate it to 0 bytes.
					// Since we already have write handle permissions to this file, this is highly likely to succeed.
					truncFile, truncErr := os.OpenFile(tmpName, os.O_WRONLY|os.O_TRUNC, 0)
					if truncErr == nil {
						syncErr2 := truncFile.Sync() // Ensure the 0-byte state hits disk //FIXME: should we handle sync err same as truncErr?
						truncFile.Close()
						s.logger.Warn("ExtraSafety: successfully truncated staging file to 0 bytes as a fallback preservation step",
							slog.String("tempfilename", tmpName), SafeErr2("syncErr", syncErr2))
					} else {
						// Absolute worst case scenario: Can't delete AND can't write/truncate an open file.
						// s.logger.Error("ExtraSafety: CRITICAL - Unable to clean up or truncate staging file. Next application boot WILL panic!",
						// 	slog.String("tempfilename", tmpName), SafeErr(truncErr))

						// CRITICAL ESCALATION: We can't delete it AND we can't truncate it.
						// The file is stuck on disk with data, making a future boot panic inevitable.
						// Crash immediately while the administrator is interacting with the system.
						logmsg := fmt.Sprintf(
							"\n========================================================================\n"+
								"CRITICAL SAFETY PANIC: Staging file cleanup failed completely!\n"+
								"The temporary staging file %q cannot be deleted or truncated.\n\n"+
								"Delete error: %v\n"+
								"Truncation error: %v\n\n"+
								"Because the file contains non-zero bytes, the next server boot will panic.\n"+
								"Halting execution immediately to prevent corrupted filesystem operation.\n"+
								"========================================================================\n",
							tmpName, ondeleteErr, truncErr,
						)
						s.logger.Error(logmsg)
						panic(logmsg)
					}
				}()
				//return targetErr
			} else {
				// FIX FOR THE ELSE BRANCH: The staging write itself failed or was cut short.
				// Attempt deletion. If deletion fails, force a truncation down to 0 bytes
				// to neutralize any partial garbage data that would trip up the next boot.
				ondeleteErr := os.Remove(tmpName)
				s.logger.Warn("ExtraSafety: Failed to fully write or/and sync staging file", slog.String("tempfilename", tmpName), SafeErr2("writeErr", writeErr), SafeErr2("syncErr", syncErr), SafeErr2("ondelete_err", ondeleteErr))
				if ondeleteErr != nil {
					truncFile, truncErr := os.OpenFile(tmpName, os.O_WRONLY|os.O_TRUNC, 0)
					if truncErr == nil {
						syncErr3 := truncFile.Sync() //FIXME: should we handle sync err same as truncErr?
						truncFile.Close()
						s.logger.Warn("ExtraSafety: successfully neutralized staging file to 0 bytes to prevent false-positive reboot panics",
							slog.String("tempfilename", tmpName), SafeErr2("ondeleteErr", ondeleteErr), SafeErr2("syncErr", syncErr3))
					} else {
						// Worse-case scenario: Write failed, cannot delete, and cannot truncate.
						// Non-zero junk data is permanently locked on disk. Panic immediately.
						logmsg := fmt.Sprintf(
							"\n========================================================================\n"+
								"CRITICAL SAFETY PANIC: Failed staging write left un-neutralized garbage bytes!\n"+
								"The temporary staging file %q failed to write, and both deletion and\n"+
								"truncation attempts failed.\n\n"+
								"Delete error: %v\n"+
								"Truncation error: %v\n\n"+
								"To prevent a false-positive crash recovery panic on the next system boot,\n"+
								"execution is halted immediately.\n"+
								"========================================================================\n",
							tmpName, ondeleteErr, truncErr,
						)
						s.logger.Error(logmsg)
						panic(logmsg)
					}
				} else {
					s.logger.Debug("ExtraSafety: unStaged recovery file from disk", slog.String("tempfilename", tmpName))
				}
			}
		} else {
			s.logger.Warn("ExtraSafety: Can't create temp staging file before writing the actual file(lacking directory write permissions?), using fallback which means if power-loss occurs in a very tiny window here then the file is lost", slog.String("filename", filename), slog.String("wanted_tempfilename", tmpName))
		}
	} //end 'if' extraSafety

	// 2. Fallback: If we couldn't create the .tmp file (likely folder permissions),
	// do a direct write but enforce a hardware sync to minimize the corruption window.
	// 2. Overwrite the target file directly (Retains Windows ACLs)
	targetFile, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}

	_, writeErr := targetFile.Write(data)
	if writeErr != nil {
		targetFile.Close()
		return writeErr
	}

	syncErr := targetFile.Sync()
	closeErr := targetFile.Close()

	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

// checkPowerLossFile inspects the file system for a lingering commit file.
// If found, it halts execution to prevent the application from overwriting
// or loading potentially corrupted state.
func (s *Server) checkPowerLossFile(filename string) {
	if filename == "" {
		return
	}
	tmpName := filename + powerlossFileExtension
	fi, err := os.Stat(tmpName)
	if err != nil {
		// File doesn't exist (or is completely inaccessible), safe to proceed
		return
	}

	// -> THE FIX: If the file is 0 bytes, cleanup failed on a previous successful run.
	if fi.Size() == 0 {
		s.logger.Warn("ExtraSafety: Found an empty power-loss staging file. Previous write succeeded, "+
			"but the temporary file could not be deleted (likely due to directory permissions).",
			slog.String("tempfilename", tmpName))
		return
	}

	logmsg := fmt.Sprintf(
		"\n========================================================================\n"+
			"CRITICAL SAFETY PANIC: Power loss or crash detected!\n"+
			"The safety file %q exists and contains uncommitted data (%d bytes).\n\n"+
			"This indicates the server aborted mid-write while updating %q.\n"+
			"The main file may be corrupted, truncated, or empty (0 bytes).\n\n"+
			"ACTION REQUIRED:\n"+
			"1. Manually inspect both files.\n"+
			"2. The .powergotlost file contains your last valid saved data.\n"+
			"3. Restore the data to the main file, then DELETE the .powergotlost file.\n"+
			"========================================================================\n",
		tmpName, fi.Size(), filename,
	)
	s.logger.Error(logmsg)
	panic(logmsg)
}

// // don't pass empty or it will panic
// func cleanFileName(what *string, description string, fallback string) (didClean bool) {
//     if what == nil {
//         panic("dev fail: nil config filename passed to cleanFileName")
//     }

//     didClean = false
//     if *what == "" {
//         //woulda been cleaned into "." aka a dot!
//         //panic("dev fail: passed empty filename to clean for " + description)
//         if fallback == "" {
//             panic("dev fail: passed empty filename to clean for '" + description + "' and the passed(to func cleanFileName()) fallback '" + fallback + "' was empty!")
//         }
//         s.logger.Warn("Bad filename in config, used fallback", slog.String("bad_filename", *what), slog.String("fallback_filename", fallback), slog.String("for_config_key", description))
//         *what = fallback
//         didClean = true //FIXME: acts like a write the change to config, but we should really do all this outside of this function! some DRY attempt while half-asleep this was!
//     }

//     var cleanedFile string = filepath.Clean(*what)
//     //from doc: If the result of this process is an empty string, Clean returns the string ".".

//     if cleanedFile != *what {
//         s.logger.Debug("Cleaned filename from config file, before vs after: %q vs %q\n", slog.String("filename_description", description), slog.String("filename_before", *what), slog.String("filename_after", cleanedFile))
//         didClean = true
//         *what = cleanedFile
//     }
//     return
// }

// cleanFileName returns the cleaned filename and a boolean indicating if the original was modified.
func (s *Server) cleanFileName(original, description, fallback string) (string, bool) {
	if original == "" {
		if fallback == "" {
			panic(fmt.Sprintf("dev fail: passed empty filename to clean for %q and the fallback was also empty!", description))
		}
		s.logger.Warn("Bad filename in config, used fallback",
			slog.String("for_config_key", description),
			slog.String("bad_filename", original),
			slog.String("fallback_filename", fallback))

		// Ensure the fallback itself is clean before returning
		cleaned := filepath.Clean(fallback) //FIXME: not a fan of having to call Clean twice, for DRY purposes.
		if cleaned != fallback {
			panic(fmt.Sprintf("dev fail: fallback(%q) for config key %q had to be cleaned into %q", fallback, description, cleaned))
		}
		return cleaned, true
	}

	cleaned := filepath.Clean(original)
	if cleaned != original {
		s.logger.Debug("Cleaned filename from config file",
			slog.String("filename_description", description),
			slog.String("filename_before", original),
			slog.String("filename_after", cleaned))
		return cleaned, true
	}

	return original, false
}

// helper to return host (IP or hostname) from an URL
func hostFromURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	host := u.Hostname() // Built-in method strips the port safely
	// host := u.Host
	// // Strip any port if present (e.g. "example.com:443" -> "example.com")
	// if h, _, err := net.SplitHostPort(host); err == nil {
	//     host = h
	// }
	if strings.TrimSpace(host) == "" {
		return "", fmt.Errorf("hostname/IP is empty for %q", raw)
	}
	return host, nil
}

func (s *Server) saveConfig() error {
	data, err := json.MarshalIndent(s.config, "", "  ")
	if err != nil {
		return fmt.Errorf("config marshal failed: %w", err)
	}
	if err := s.safeWriteFile(configFileName, data, 0600); err != nil {
		return fmt.Errorf("config write failed: %w", err)
	}
	s.logger.Info("Saved config file", slog.String("config_file", configFileName))
	return nil
}

var isAdmin bool // Package level
func init() {
	// This runs automatically before main()
	// token := windows.GetCurrentProcessToken()
	// isAdmin = token.IsElevated()
	isAdmin = isAdminNow()
}

func isAdminNow() bool {
	// Windows: Use latest x/sys API for elevation check.
	token := windows.GetCurrentProcessToken()
	elevated := token.IsElevated() // Single bool return
	return elevated
}

// initLogging creates the single s.logger with three destinations.
// Called once after config is loaded (files and console level are known).
func (s *Server) initFullLogging() { //qpath, epath string) {
	consoleLevel := parseConsoleLogLevel(s.config.ConsoleLogLevel)
	// Simple rotation on open (respects your LogMaxSizeMB)
	openLog := func(path string) io.Writer {
		if path == "" {
			panic("empty logging filename: '" + path + "'")
		}
		path = filepath.Clean(path)
		s.rotateIfNeeded(path, s.config.LogMaxSizeMB)
		// if fi, err := os.Stat(path); err == nil && fi.Size() > int64(config.LogMaxSizeMB)*1024*1024 {
		//     os.Rename(path, path+".1") // one backup is enough for now
		// }
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			// We are still in bootstrap phase → use the bootstrap logger so the error is colored
			s.logger.Error("cannot open log file", slog.String("file", path), SafeErr(err))
			s.shutdown(1) //os.Exit(1)
			//panic(fmt.Errorf("cannot open log %q: %w", path, err))
		}
		return f
	}
	// if qpath == "" || epath == "" {
	//     panic("one of these is empty: '" + qpath + "','" + epath + "'")
	// }
	// qpath = filepath.Clean(qpath)
	// epath = filepath.Clean(epath)
	// Rotation stub: Rename if > max size
	// rotateIfNeeded(qpath, config.LogMaxSizeMB)
	// rotateIfNeeded(epath, config.LogMaxSizeMB)

	// qfile, err := os.OpenFile(qpath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	// if err != nil {
	//     logFatal("Query log open failed:", err)
	// }
	// opts := &slog.HandlerOptions{AddSource: false}
	// qh := slog.NewJSONHandler(qfile, opts)
	// queryLogger = slog.New(qh)

	// efile, err := os.OpenFile(epath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	// if err != nil {
	//     logFatal("Error log open failed:", err)
	// }
	// eh := slog.NewJSONHandler(efile, opts)
	// errorLogger = slog.New(eh)

	fullHandler := slog.NewJSONHandler(openLog(s.config.LogErrorsFile), &slog.HandlerOptions{
		Level:       slog.LevelDebug, // full log gets EVERYTHING
		ReplaceAttr: stripColorTags,  // Strips tags safely for files
	})

	consoleH := NewColoredConsoleHandler(consoleLevel, s.logger) // now uses the real config level

	queryH := queryFilterHandler{
		Handler: slog.NewJSONHandler(openLog(s.config.LogQueriesFile), &slog.HandlerOptions{
			ReplaceAttr: stripColorTags, // Strips tags safely for files
		}),
	}

	// root := multiHandler{
	//     handlers: []slog.Handler{fullHandler, consoleH, queryH},
	// }

	// s.logger = slog.New(root)
	// s.logger.Info("Logging fully initialized")
	s.logger = slog.New(multiHandler{ // <-- this REPLACES the global
		handlers: []slog.Handler{fullHandler, consoleH, queryH},
	})

	//Give the failover selector the new, fully-powered logger
	s.failoverSelect.logger = s.logger

	s.logger.Info("Logging initialized",
		slog.String("full_log", s.config.LogErrorsFile),
		slog.String("queries_log", s.config.LogQueriesFile),
		slog.String("console_level", s.config.ConsoleLogLevel),
	)
}

func (s *Server) rotateIfNeeded(path string, maxMB int) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > int64(maxMB*1024*1024) {
		old := path + ".old"
		if err := os.Rename(path, old); err != nil {
			s.logger.Error("Log rotation failed", slog.String("path", path), SafeErr(err))
		} else {
			s.logger.Info("Rotated log file", slog.String("path", path), slog.String("old_path", old), slog.Int("max_size_mb", maxMB))
		}
	}
}

func (s *Server) validateUpstream() error {
	s.upstreamURLs = nil
	s.upstreamIPs = nil
	s.upstreamSNIs = nil

	if len(s.config.UpstreamURLs) == 0 {
		return errors.New("upstream_urls list is empty")
	}

	for i, rawURL := range s.config.UpstreamURLs {
		u, err := url.Parse(rawURL)
		if err != nil || u.Scheme != "https" {
			return fmt.Errorf("invalid upstream URL (must be https): %s", rawURL)
		}
		port := u.Port()
		if port == "" {
			port = "443" // since we're allowing only https scheme, this should always be 443
			// s.logger.Warn("Using implied port for DoH upstream due to unspecified port and scheme",
			//     slog.String("implied_port", ImpliedPort),
			//     slog.Any("upstreamURL", u))
			// This is how you add the port back into the URL object
			u.Host = net.JoinHostPort(u.Hostname(), port)
		}
		if u.Port() == "" {
			panic("dev fail: port is empty")
		}
		s.upstreamURLs = append(s.upstreamURLs, u)

		ip := u.Hostname()
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("upstream host must be IP literal (no resolution): %s", ip)
		}
		s.upstreamIPs = append(s.upstreamIPs, ip)
		s.upstreamSNIs = append(s.upstreamSNIs, s.config.SNIHostnames[i])
	}

	return nil
	// var err error
	// upstreamURL, err = url.Parse(config.UpstreamURL)
	// if err != nil || upstreamURL.Scheme != "https" {
	//     return errors.New("invalid upstream URL, must be similar to this: https://IP/dns-query However, while /dns-query is the \"well-known\" default DoH Path (or Template) used by many providers (like Google and Cloudflare), the RFC 8484 standard allows server operators to configure any path they choose to handle incoming DNS queries.")
	// }
	// upstreamIP = upstreamURL.Hostname() // Host for IP
	// if ip := net.ParseIP(upstreamIP); ip == nil {
	//     return errors.New("upstream host must be IP literal (no resolution)")
	// }
	// return nil
}

func countRules(wl map[string][]RuleEntry) uint64 {
	var total uint64 = 0
	for _, rs := range wl {
		total += uint64(len(rs))
	}
	return total
}

func (s *Server) newUniqueID(alreadyHave map[string][]RuleEntry) string {
	existing := make(map[string]struct{})
	for _, rs := range alreadyHave {
		for _, r := range rs {
			existing[r.ID] = struct{}{}
		}
	}

	for try := 1; try <= 10; try++ {
		id := uuid.New().String()
		if _, ok := existing[id]; !ok {
			return id
		} else {
			s.logger.Warn("attempted to make newUniqueID() which existed", slog.String("id", id), slog.Int("try", try))
		}
	}
	panic("UUID collision limit reached—check RNG or storage")
}

func isLowerASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			return false
		}
	}
	return true
}

// it's assumed that pattern and name are already lowercase(d) or uppercase(d), if not they won't match due to char case difference.
func matchPattern(pattern, name string) bool {
	if !isLowerASCII(pattern) {
		panic("pattern was " + pattern + " which isn't lowercased, so bad coding somewhere!")
	}
	if !isLowerASCII(name) {
		panic("name was " + name + " which isn't lowercased, so bad coding somewhere!")
	}

	//pattern = strings.ToLower(pattern)//XXX: must be already lowercase
	//name = strings.ToLower(name)//XXX: must be already lowercase

	// idx := strings.Index(pattern, "**")
	// if idx != -1 {
	//     if idx > 0 && idx+2 < len(pattern) &&
	//         pattern[idx-1] == '{' && pattern[idx+2] == '}' {
	//         // {**}
	//         // Handle {**} wildcard (cross-label, requiring at least one label when used with dot)
	//         //The no allocs variant:
	//         prefix := pattern[:idx-1]
	//         suffix := pattern[idx+3:]

	//         if prefix != "" && !strings.HasPrefix(name, prefix) {
	//             return false
	//         }
	//         if suffix != "" && !strings.HasSuffix(name, suffix) {
	//             return false
	//         }

	//         if prefix == "" && strings.HasPrefix(suffix, ".") {
	//             return len(name) > len(suffix)
	//         }
	//         if suffix == "" && strings.HasSuffix(prefix, ".") {
	//             return len(name) > len(prefix)
	//         }

	//         return true
	//     } else {
	//         // **
	//         // Handle plain ** wildcard (cross-label, may match zero chars). This mirrors legacy behavior.
	//         //The no allocs variant:
	//         prefix := pattern[:idx]
	//         suffix := pattern[idx+2:]

	//         if prefix != "" && !strings.HasPrefix(name, prefix) {
	//             return false
	//         }
	//         if suffix != "" && !strings.HasSuffix(name, suffix) {
	//             return false
	//         }
	//         return true
	//     }
	// }

	// Fallback to recursive matching for other tokens ({*}, *, ?, !, literal text)
	return recursiveMatch(pattern, name)
}

// recursiveMatch handles all tokens recursively.
func recursiveMatch(pattern, name string) bool {
	for len(pattern) > 0 {
		switch {
		case strings.HasPrefix(pattern, "{**}"):
			// consume 1+ chars including dots
			pattern = pattern[4:]
			if len(name) < 1 {
				return false
			}
			for i := 1; i <= len(name); i++ {
				if recursiveMatch(pattern, name[i:]) {
					return true
				}
			}
			return false

		case strings.HasPrefix(pattern, "**"):
			// consume 0+ chars including dots
			pattern = pattern[2:]
			if len(name) == 0 {
				return recursiveMatch(pattern, "")
			}
			for i := 0; i <= len(name); i++ {
				if recursiveMatch(pattern, name[i:]) {
					return true
				}
			}
			return false

		case strings.HasPrefix(pattern, "{*}"):
			// consume 1+ chars, stop at dot
			pattern = pattern[3:]
			max3 := 0
			for j := 0; j < len(name) && name[j] != '.'; j++ {
				max3 = j + 1
			}
			if max3 < 1 {
				return false
			}
			for i := 1; i <= max3; i++ {
				if recursiveMatch(pattern, name[i:]) {
					return true
				}
			}
			return false

		case strings.HasPrefix(pattern, "*"):
			// consume 0+ chars, stop at dot
			pattern = pattern[1:]
			if len(name) == 0 {
				return recursiveMatch(pattern, "")
			}
			for i := 0; i <= len(name); i++ {
				if i < len(name) && name[i] == '.' {
					if recursiveMatch(pattern, name[i:]) {
						return true
					}
					break
				}
				if recursiveMatch(pattern, name[i:]) {
					return true
				}
			}
			return false

		case strings.HasPrefix(pattern, "?"):
			// consume exactly 1 char, not dot
			if len(name) == 0 || name[0] == '.' {
				return false
			}
			pattern = pattern[1:]
			name = name[1:]

		case strings.HasPrefix(pattern, "!"):
			// consume exactly 1 char, any
			if len(name) == 0 {
				return false
			}
			pattern = pattern[1:]
			name = name[1:]

		default:
			// literal char match
			if len(name) == 0 || pattern[0] != name[0] {
				return false
			}
			pattern = pattern[1:]
			name = name[1:]
		}
	}

	return len(name) == 0
}

func (s *Server) generateCertIfNeeded() {
	s.logger.Debug("check if cert is valid or needs regen")
	certFile := "cert.pem"
	keyFile := "key.pem"
	needsRegen := false

	var err error
	// Extract the host/IP from the config to put it in the cert
	host, _, err := net.SplitHostPort(s.config.ListenDoH)
	if err != nil {
		host = s.config.ListenDoH // Fallback if no port present
	}
	//In Go, net.ParseIP is a strict parser. It does not perform DNS lookups; it only checks if the string is a valid IPv4 or IPv6 literal. If you pass it "localhost", it returns nil.
	currentIP := net.ParseIP(host)
	if nil == currentIP {
		panic("coding error, IP isn't valid in config.ListenDoH") //FIXME: check this at config.json load time! or split the IP and port into two config options!
	}
	// 2. Check if cert exists and is still valid for this IP
	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		// File missing or unreadable
		s.logger.Warn("Cert file doesn't exist", slog.String("file", certFile), SafeErr(err)) // no \n
		needsRegen = true
	} else {
		// Parse the PEM
		block, _ := pem.Decode(certBytes)
		if block == nil {
			s.logger.Warn("Cert file had empty decoded block.", slog.String("file", certFile)) // no \n
			needsRegen = true
		} else {
			cert, err2 := x509.ParseCertificate(block.Bytes)
			if err2 != nil {
				s.logger.Warn("Cert file failed parsing", slog.String("file", certFile), SafeErr(err2)) // no \n
				needsRegen = true
			} else {
				// Check if the current IP is in the cert's SAN list

				found := false
				parsedIP := net.ParseIP(host)

				if parsedIP != nil {
					// Check IP list
					for _, ip := range cert.IPAddresses {
						if ip.Equal(parsedIP) {
							found = true
							break
						}
					}
				} else {
					// Check DNS list
					for _, name := range cert.DNSNames {
						if name == host {
							found = true
							break
						}
					}
				}

				if !found {
					s.logger.Warn("Cert identity mismatch", slog.String("want", host)) // no \n
					needsRegen = true
				}
			}
		}
	}

	// 3. Regen if necessary
	if needsRegen {
		s.logger.Warn("Due to above, regenerating self-signed cert(files: %s and %s) for DoH at %s...", slog.String("public_key_aka_cert_file", certFile), slog.String("private_key_file", keyFile),
			slog.String("sni_hostname", host))
		if err = generateCert(certFile, keyFile, host); err != nil {
			//done: need to unify logging errors in log and on console somehow, this printf and errorLogger thing is a mess.
			s.logFatal("cert generation failed", err) //SafeErr(err))
			//os.Exit(1)
		}
		s.logger.Warn("Cert generated: make sure you trust it in clients eg. in Firefox load the IP as url and add a cert exception, "+
			"or about:preferences#privacy scroll to Security click Manage Certificates and in Certificate Manager window select Servers click [Add Exception...] "+
			"button and use this IP with that https:// scheme or use full listen_address", slog.String("IP", currentIP.String() /*non nil here*/), slog.String("listen_address", s.config.ListenDoH))
	} else {
		s.logger.Debug("Existing cert is valid for host. Skipping generation.", slog.String("sni_hostname", host))
	}

	// Load cert/key into global for reuse
	s.logger.Info("Loading cert/key for DoH...")

	s.dohCert, err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		// errorLogger.Error("cert_load_failed", SafeErr(err))
		// os.Exit(1)
		s.logFatal("cert_load_failed", err)
	}
	s.logger.Info("Success - loaded into tls.Certificate")
}

// 'host' can be localhost or 127.0.0.1 for example, but it won't be looked up!
func generateCert(certFileNameNoPath, keyFileNameNoPath, host string) error {
	if certFileNameNoPath == "" || keyFileNameNoPath == "" {
		panic("unexpected empty filename(s) for cert,key: '" + certFileNameNoPath + "','" + keyFileNameNoPath + "'")
	}
	certFileNameNoPath = filepath.Clean(certFileNameNoPath)
	keyFileNameNoPath = filepath.Clean(keyFileNameNoPath)
	// From crypto/tls/generate_cert.go; edge: Ensure unique serial, valid for 10y
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("key gen failed: %w", err)
	}
	serial := big.NewInt(0)
	serial.SetString(uuid.New().String(), 16) // Unique serial
	certTemplate := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"DNSbollocks ie. Local DNS Proxy"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour * 10),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		//IPAddresses: []net.IP{net.ParseIP(host)},
	}

	// Try parsing as IP first (no network lookup)
	if ip := net.ParseIP(host); ip != nil {
		certTemplate.IPAddresses = append(certTemplate.IPAddresses, ip)
	} else {
		// If not an IP, treat it as a DNS hostname (e.g., "localhost")
		certTemplate.DNSNames = append(certTemplate.DNSNames, host)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("cert create failed: %w", err)
	}

	// not this way: #nosec G304
	certOut, err := os.Create(certFileNameNoPath)
	if err != nil {
		return fmt.Errorf("cert write failed: %w", err)
	}
	defer certOut.Close()
	if err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("pem encode cert failed: %w", err)
	}

	//keyOut, err := os.Create(keyFile)
	// 2. Fix the Key Permissions: Replace os.Create(keyFile) with this:
	// not this way: #nosec G304  but this way filepath.Clean(
	keyOut, err := os.OpenFile(keyFileNameNoPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("key write failed: %w", err)
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return fmt.Errorf("pem encode key failed: %w", err)
	}
	return nil
}

type contextKey string

const clientInfoKey contextKey = "clientInfo"

type clientMetadata struct {
	protocol   string
	pid        uint32
	exe        string
	services   []string
	err        error
	clientAddr net.Addr
	startTime  time.Time
}

// Listeners...

// non-blocking! listens on both UDP and TCP ports 53
func (s *Server) startDNSListener(addr string) {
	//    listenerErrs.Add(1)
	//    defer listenerErrs.Done()
	s.logger.Debug("Starting DNS listener", slog.String("addr", addr))

	// UDP
	s.logger.Debug("Attempting UDP bind for DNS listener...")

	// Assuming addr is a string like "127.0.0.1:53"
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		s.logger.Error("invalid UDP address", slog.String("addr", addr), SafeErr(err))
		s.shutdown(1) //os.Exit(1) //FIXME: see the below comment
	}
	udpLn, err := net.ListenUDP("udp", udpAddr)

	if err != nil {
		s.logger.Error("UDP bind/listen failed", slog.String("addr", addr), SafeErr(err))
		s.shutdown(1)
		//os.Exit(1) //FIXME: need to use winbollocks' dual deferrers as the traps for clean exit and thus have only 1-2 os.Exit in whole program!
	} else {
		s.shutdownWG.Add(1) // +1 for the Main UDP Loop

		go func() { //we won't be blocking here.
			defer s.shutdownWG.Done()
			//defer udpLn.Close()
			// 1. DEFENSIVE DEFER: This ensures the port is freed even if the
			// function panics or returns unexpectedly before the goroutine starts.
			closer := func() {
				// Use a local error variable here
				if closeErr := udpLn.Close(); closeErr != nil {
					_ = closeErr
				}
			} // will be called twice usually, because of the below goroutine
			defer closer()
			// 2. SHUTDOWN WATCHER: This handles the "Press any key" / context cancel
			s.shutdownWG.Add(1) // +1 for the UDP Shutdown Watcher
			go func() {
				defer s.shutdownWG.Done()
				<-s.ctx.Done()
				// We call Close here to unblock the Read/Accept loop immediately.
				// If this runs, the 'defer' above will just return an error later.
				closer()
			}()
			s.logger.Info("UDP DNS listening success", slog.String("addr", addr))

			// 1. Initialize the pool outside the loop
			udpPool := sync.Pool{
				//Zero-Allocation Happy Path: Reading an incoming packet, processing it, and handling it in a goroutine now requires zero new heap allocations for the packet data.
				//Thread Safety: Because each goroutine gets its own buffer straight from the pool, there are no race conditions with the ReadFromUDP loop overwriting data while the goroutine parses it.
				//Memory Bound: Under high bursts, the pool will scale up automatically to handle concurrent connections, but once traffic settles, the Go runtime will garbage collect the unused buffered slices in the pool automatically.
				New: func() any {
					//buf := make([]byte, 512+512)
					// Use a 4096-byte buffer to safely accommodate modern EDNS0 UDP packets
					b := make([]byte, s.config.DNSUDPBufferSize)
					return &b // Return a pointer to avoid interface conversion allocation
				},
			}

			//TheFor:
			for {
				// 2. Grab a buffer pointer from the pool
				bufPtr := udpPool.Get().(*[]byte)
				buf := *bufPtr

				n, clientAddr, err2 := udpLn.ReadFromUDP(buf)
				if err2 != nil {
					udpPool.Put(bufPtr) // Return buffer on error
					select {
					case <-s.ctx.Done():
						// to see this you've to wait like 1 sec in shutdown() or that "press a key" msg does it.
						s.logger.Debug("UDP DNS listener is quitting due to shutdown...")

						return // Quit on shutdown
					default:
						//runtime.Gosched()  // Yield to scheduler on error (deep yield, 0% CPU during)
						s.logger.Warn("UDP DNS listener udp_read_error", SafeErr(err2))
						//time.Sleep(100 * time.Millisecond)
						//break TheFor
						continue // Real network error, keep trying
					} //select
				} //if err2

				s.logger.Debug("client connected(early logging)",
					slog.String("proto", "UDP"),
					//slog.String("clientAddr", clientAddr.String()),
					SafeAddr("clientAddr", clientAddr),
					//slog.Any("pid", pid),
					//slog.String("exe", exe),
					//slog.String("service", serviceInfo),
					//SafeErr(err),
				)

				if n > len(buf) {
					udpPool.Put(bufPtr) // Clean up before panicking
					panic(fmt.Sprintf("n>len(buf) aka %d>%d", n, len(buf)))
				}

				//FIXME: this below(until the goroutine) slows down things here before going to the next ReadFromUDP aka client (above) again! could move these into the below goroutine but then XXX: it's gonna be too late to get the pid of the exe that just did this connection because it's gone from the list of UDP conns!

				// // Create a distinct copy for the background worker
				// wireCopy := make([]byte, n)
				// copy(wireCopy, buf[:n])

				pid, exe, err2 := wincoe.PidAndExeForUDP(clientAddr)
				// wincoe.Smashy()
				// pid := uint32(1)
				// exe := "foo"
				// err = nil

				udpPacketCtx := s.makeClientInfoContext(s.ctx /* this is your global shutdown ctx*/, "UDP", clientAddr, pid, exe, err2)
				//go handleUDP(udpPacketCtx, wireCopy, clientAddr, udpLn)
				// TRACK INDIVIDUAL REQUESTS:
				s.shutdownWG.Add(1)
				go func(pCtx context.Context, data []byte, bufferPtr *[]byte, addr *net.UDPAddr, ln *net.UDPConn) {
					defer s.shutdownWG.Done()
					defer udpPool.Put(bufferPtr) // 4. Recycle buffer when the handler finishes
					s.handleUDP(pCtx, data, addr, ln)
				}(udpPacketCtx, buf[:n], bufPtr, clientAddr, udpLn)
			} //infinite 'for'
		}()
	} // else

	// TCP
	s.logger.Debug("Attempting TCP bind for DNS listener...")

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr) // parses, no DNS for literal IPs, FIXME: this shouldn't attempt to DNS resolve the hostname!
	if err != nil {
		// errStr := fmt.Sprintf("TCP bind failed(the address should be an IP) on %q: %v", addr, err)
		//errorLogger.Error(errStr)
		s.logger.Error("invalid TCP address", slog.String("addr", addr), SafeErr(err))
		s.shutdown(1) //os.Exit(1)
	}
	tcpLn, err := net.ListenTCP("tcp", tcpAddr) // returns *net.TCPListener

	if err != nil {
		//errStr := fmt.Sprintf("TCP bind failed on %q: %v", addr, err)
		//errorLogger.Error(errStr)
		s.logger.Error("TCP bind/listen failed", slog.String("addr", addr), SafeErr(err))
		s.shutdown(1) //os.Exit(1)
	} else {
		// caller provides ctx context.Context and tcpLn *net.TCPListener
		s.shutdownWG.Add(1) // +1 for the Main TCP Loop
		go func() {
			defer s.shutdownWG.Done()

			closer := func() {
				err := tcpLn.Close()
				_ = err
			} // just in case we exit via non-shutdown(x)
			defer closer()
			// In a separate goroutine watch for shutdown and close the listener
			s.shutdownWG.Add(1) // +1 for the TCP Shutdown Watcher
			go func() {
				defer s.shutdownWG.Done()
				<-s.ctx.Done()
				closer() // This wakes up Accept() with an error safely
			}()
			s.logger.Info("TCP DNS listening", slog.String("address", addr))

			// // Then simplify your loop
			// for {
			//     conn, err := tcpLn.Accept()
			//     if err != nil {
			//         return // Exit on any error (like closed listener)
			//     }
			//     // ... handle connection
			// }

			// // small buffer for accept errors backoff
			// var backoff time.Duration

			for {
				// // allow Accept to be interruptible by context by using a deadline
				// err := tcpLn.SetDeadline(time.Now().Add(500 * time.Millisecond)) //doneFIXME: put 500ms back, or check the code above to not use deadline!
				// //err := tcpLn.SetDeadline(time.Now().Add(10 * time.Nanosecond))
				// if err != nil {
				//     s.logger.Warn("can't set TCP deadline", SafeErr(err))
				//     panic("wtw")
				// }

				conn, err := tcpLn.Accept()
				if err != nil {
					// if context canceled, exit cleanly
					select {
					case <-s.ctx.Done():
						s.logger.Debug("TCP DNS listener is quitting due to shutdown...")
						return
					default:
						// // handle timeout-like errors (due to SetDeadline)
						// // 1. Declare a variable for the interface you're looking for
						// var netErr net.Error
						// // 2. Use errors.As to check if 'err' (or anything it wraps) is a net.Error
						// if errors.As(err, &netErr) && netErr.Timeout() {
						//     // reset backoff and continue
						//     backoff = 0
						//     continue
						// }

						// non-temporary error: log, backoff a bit to avoid hot loop, continue
						s.logger.Warn("tcp_accept_error", SafeErr(err))

						// if backoff == 0 {
						//     backoff = 50 * time.Millisecond
						// } else if backoff < 1*time.Second {
						//     backoff *= 2
						// }
						// s.logger.Debug("DNS TCP accept sleeping", slog.Any("milliseconds", backoff))
						// time.Sleep(backoff)
						continue
					} // select
				} // if err

				tcpPacketCtx := s.ctx /* this is your global shutdown ctx*/
				// 1. Get the remote address as a *net.TCPAddr
				clientAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
				s.logger.Debug("client connected(early logging)",
					slog.String("proto", "TCP"),
					//slog.String("clientAddr", clientAddr.String()),
					SafeAddr("clientAddr", clientAddr),
				)
				if !ok {
					s.logger.Warn("could not cast remote addr to TCPAddr",
						//slog.String("addr", conn.RemoteAddr().String()),
						SafeAddr("addr", conn.RemoteAddr()),
					)
					//FIXME: when can this happen?!
				} else {
					//FIXME: this slows down things here until it's ready to tcpLn.Accept() (above) again!
					// 2. Call your new TCP PID/Exe helper
					pid, exe, err := wincoe.PidAndExeForTCP(clientAddr)
					// wincoe.Smashy()
					// pid := uint32(2)
					// exe := "foo2"
					// err = nil
					tcpPacketCtx = s.makeClientInfoContext(tcpPacketCtx, "TCP", clientAddr, pid, exe, err)
				}

				// accepted a connection; handle in new goroutine
				// go func(c net.Conn) {
				//     defer func() { _ = c.Close() }()
				//     handleTCP(tcpPacketCtx, c)
				// }(conn)

				//XXX: tcpPacketCtx is passed as arg(instead of as above commented out code) because: "Because that goroutine might not start instantly, the loop might move on to the next connection before the first goroutine actually reads the value of tcpPacketCtx." - Gemini 3 Thinking
				// TRACK INDIVIDUAL CONNECTIONS:
				s.shutdownWG.Add(1)
				go func(c net.Conn, pCtx context.Context) {
					defer s.shutdownWG.Done() // This fires when handleTCP returns
					defer c.Close()
					s.handleTCP(pCtx, c)
				}(conn, tcpPacketCtx)
			}
		}()

	}
	if udpLn == nil && tcpLn == nil { //XXX: this is deadcode because if ANY failed above shutdown/os.Exit is called
		s.logger.Warn("No DNS listeners(neither TCP nor UDP!")
	}
}

func (s *Server) makeClientInfoContext(ctx context.Context, protocol string, clientAddr net.Addr, pid uint32, exe string, err error) context.Context {
	var services []string
	var serviceInfo string
	if err != nil {
		s.logger.Warn("couldn't get pid and exe name",
			slog.String("proto", protocol),
			//slog.String("clientAddr", clientAddr.String()),
			SafeAddr("clientAddr", clientAddr),
			SafeErr(err))
		//services = []string{"<err:no_pid>"}
		//return ctx
		serviceInfo = "err:no_pid"
	} else {
		//fmt.Println("!before")
		//services, err := wincoe.GetServiceNamesFromPIDCached(pid) // this epic shadowing with no warnings! (golangci-lint v2 is broken when using v1.27 devel Go) and vscode didn't say anything on its own.
		services, err = wincoe.GetServiceNamesFromPIDCached(pid)
		//services = []string{"<service-lookup-disabled-for-debug>"}
		//fmt.Println("!after")
		if err != nil {
			serviceInfo = fmt.Sprintf("err=%v", err)
		} else {
			serviceInfo = fmt.Sprintf("%v", services)
			// if len(services) > 0 {
			//     serviceInfo = fmt.Sprintf("%d services: %v", len(services), services)
			// } else {
			//     serviceInfo = "no services"
			// }
		}
	}

	s.logger.Debug("client connected",
		slog.String("proto", protocol),
		//slog.String("clientAddr", clientAddr.String()),
		SafeAddr("clientAddr", clientAddr),
		slog.Int64("pid", int64(pid)),
		slog.String("exe", exe),
		slog.String("services", serviceInfo),
		SafeErr(err),
	)

	// Create a specific context for THIS packet
	//packetCtx := ctx // this is your global shutdown ctx
	//if pErr == nil {
	//names, _ := wincoe.GetServiceNamesFromPID(pid)
	return context.WithValue(ctx, clientInfoKey, clientMetadata{
		protocol:   protocol,
		pid:        pid,
		exe:        exe,
		services:   services,
		err:        err,
		clientAddr: clientAddr,
		startTime:  time.Now(), // Capture start time
	})
	//}
}

// SafeErr converts an error to a primitive string attribute safely.
// If the error is nil, it gracefully logs it as "<nil>" without panicking.
func SafeErr(err error) slog.Attr {
	// if err == nil {
	//     return slog.String("err", "<nil>")
	// }
	// return SafeErr(err)
	return SafeErr2("err", err)
}

// SafeErr2 converts an error to a primitive string attribute safely.
// If the error is nil, it gracefully logs it as "<nil>" without panicking.
func SafeErr2(msg string, err error) slog.Attr {
	if err == nil {
		return slog.String(msg, "<nil>")
	}
	return slog.String(msg, err.Error())
}

// func SafeUDPAddr(msg string, addr *net.UDPAddr) slog.Attr {
//     if addr == nil {
//         return slog.String(msg, "<nil>")
//     }
//     return slog.String(msg, (*addr).String())
// }

// SafeAddr converts any net.Addr (UDP, TCP, IP, Unix, etc.) to a safe primitive string.
// It gracefully handles nil interface values and nil pointer implementations.
func SafeAddr(key string, addr net.Addr) slog.Attr {
	// 1. Check if the interface itself is nil
	// 2. Check if the underlying concrete pointer is nil using a type switch/assertion if needed,
	//    but a simple nil check against the interface covers standard uninitialized interface variables.
	if addr == nil {
		return slog.String(key, "<nil>")
	}

	// net.Addr natively exposes the String() method, which evaluates instantly
	return slog.String(key, addr.String())
}

func (s *Server) handleUDP(ctx context.Context, wire []byte, clientAddr *net.UDPAddr, ln *net.UDPConn) {
	if clientAddr == nil {
		panic("nil ClientAddr in handleUDP, not possible?!")
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		// Edge: Invalid packet (common in floods)
		s.logger.Warn("invalid DNS UDP packet (couldn't Unpack) thus dropped/ignored", SafeErr(err))
		return
	}
	resp := s.handleDNSQuery(ctx, msg, clientAddr.String())
	if resp == nil {
		return // Drop
	}
	pack, err := resp.Pack()
	if err != nil {
		s.logger.Warn("failed to pack DNS UDP packet response thus not sent", SafeErr(err))
		return
	}
	wroteN, err := ln.WriteToUDP(pack, clientAddr)
	if err != nil {
		s.logger.Warn("failed to write to UDP the DNS packet response", SafeErr(err), slog.Int("wrote_bytes", wroteN), slog.Int("shoulda_written", len(pack)))
		return
	}
}

func (s *Server) handleTCP(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	var timeoutDuration time.Duration = time.Duration(s.config.ClientTCPTimeoutSec) * time.Second
	const maxDNSTCPPacketSize = 65535 //TODO: make this configurable in config.json

	// --- 1. READ THE LENGTH HEADER ---
	// We give the client 5 seconds to send just these 2 bytes.
	_ = conn.SetReadDeadline(time.Now().Add(timeoutDuration))

	const TWO = 2
	buf := make([]byte, TWO)
	if n, err := io.ReadFull(conn, buf); err != nil {
		s.logger.Warn("couldn't read 2 bytes from TCP DNS connection, thus dropped/ignored", SafeErr(err), slog.Int("read_bytes", n),
			slog.Int("wanted_to_read_bytes", TWO), slog.String("timeout", timeoutDuration.String() /*not nil*/))
		return
	}
	length := int(binary.BigEndian.Uint16(buf))
	if length > s.config.DoHMaxRequestBodyBytes || length == 0 { // Edge: Oversize packet
		s.logger.Warn("invalid packet length in TCP DNS connection, thus dropped/ignored", slog.Int("actual_bytes", length), slog.Int("max", maxDNSTCPPacketSize),
			slog.Int("min", 1))
		return
	}

	// --- 2. READ THE BODY ---
	// We REFRESH the deadline. The client gets a fresh 5 seconds
	// to finish sending the actual DNS message.
	_ = conn.SetReadDeadline(time.Now().Add(timeoutDuration))
	wire := make([]byte, length)
	if n, err := io.ReadFull(conn, wire); err != nil {
		s.logger.Warn("couldn't read some bytes from TCP DNS connection, thus dropped/ignored", SafeErr(err), slog.Int("read_bytes", n), slog.Int("wanted_to_read_bytes", length),
			slog.String("timeout", timeoutDuration.String() /*not nil*/))
		return
	}

	// --- 3. PROCESS ---
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		s.logger.Warn("invalid DNS TCP packet (couldn't Unpack) thus dropped/ignored", SafeErr(err))
		return
	}

	resp := s.handleDNSQuery(ctx, msg, conn.RemoteAddr().String())
	// --- 4. WRITE THE RESPONSE ---
	if resp != nil {
		pack, err := resp.Pack() // Ignore err
		if err != nil {
			s.logger.Warn("failed to pack DNS TCP packet response thus not sent", SafeErr(err))
			return
		}
		// Prepare the output (length + payload)
		out := new(bytes.Buffer)
		err = binary.Write(out, binary.BigEndian, uint16(len(pack))) // Single err return
		if err != nil {
			s.logger.Warn("failed to write-to-the-buffer the pack len (2 bytes) of the TCP DNS packet response", SafeErr(err))
			return
		}
		out.Write(pack)
		// Set a WRITE deadline. This prevents a "slow receiver" from
		// hanging your goroutine forever while you try to push data.
		_ = conn.SetWriteDeadline(time.Now().Add(timeoutDuration))
		wroteN, err := conn.Write(out.Bytes())
		if err != nil {
			s.logger.Warn("failed to write to TCP the DNS packet response body", SafeErr(err), slog.Int("wrote_bytes", wroteN),
				slog.Int("shoulda_written", len(pack)), slog.String("timeout", timeoutDuration.String() /*not nil*/))
			return
		}
	}
	s.logger.Warn("No TCP DNS response to write, filtered out maybe? Shouldn't happen tho. FIXME")
}

// non-blocking!
func (s *Server) startDoHListener(addr string) {
	s.logger.Debug("Starting DoH listener", slog.String("address", addr))

	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", s.dohHandler)

	listener, err := tls.Listen("tcp", addr, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{s.dohCert}, // Use loaded cert
	})
	if err != nil {
		// errStr := fmt.Sprintf("DoH listener failed on %q: %v", addr, err)
		// errorLogger.Error(errStr)
		s.logger.Error("DoH listener failed to bind/listen", slog.String("addr", addr), SafeErr(err))
		s.shutdown(1) //os.Exit(1) // Fail-fast serial
	}
	s.logger.Info("DoH listening", slog.String("address", addr))

	dohSrv := &http.Server{Handler: mux,
		ReadTimeout:  time.Duration(s.config.UpstreamServerReadTimeoutSec) * time.Second,  // Workaround for CPU/timer bug
		WriteTimeout: time.Duration(s.config.UpstreamServerWriteTimeoutSec) * time.Second, // Optional, for responses
	}
	/*
	       When you call go func(), you aren't running the function immediately. You are telling the Go scheduler: "Hey, when you have a spare millisecond, please start this task."

	       If Add(1) is inside: There is a tiny window of time where the goroutine is "scheduled" but hasn't actually started running.
	       If your shutdown() function calls Wait() during that tiny window, the WaitGroup counter is still 0. The program thinks there is no work to wait for and exits immediately,
	       killing the goroutine before it even begins.

	       If Add(1) is outside: You increment the counter before the goroutine is even created. This ensures that Wait() will see a counter of at least 1,
	       effectively "blocking the exit" until that goroutine starts, runs, and eventually calls Done().

	   The Rule of Thumb: Always Add() in the "parent" goroutine and Done() in the "child" goroutine.
	*/
	s.shutdownWG.Add(1)
	// Listen for the global shutdown signal to gracefully close the DoH server
	go func() {
		defer s.shutdownWG.Done() // Signal this watcher is finished
		<-s.ctx.Done()
		s.logger.Debug("Shutting down DoH server...")
		// Give it a max of 3 seconds to finish existing requests before force closing
		shutdownCtx, cancelDown := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancelDown()
		_ = dohSrv.Shutdown(shutdownCtx)
	}()

	s.shutdownWG.Add(1)
	go func() {
		defer s.shutdownWG.Done() // Signal the server is officially stopped

		defer listener.Close() // Graceful close on shutdown
		//doneFIXME: how do we know if this failed to maybe restart it or exit the whole program or whatever!?
		if err := dohSrv.Serve(listener); err != nil && err != http.ErrServerClosed {
			s.logger.Error("doh_serve_failed", SafeErr(err))
			s.errChan <- fmt.Errorf("DoH server failed: %w", err)
		}
	}()
	s.logger.Debug("DoH server loop launched in goroutine")
}

func getSecureID() uint16 {
	b := make([]byte, 2)
	maxRetries := 3

	//for i := 0; i < maxRetries; i++ {
	for i := range maxRetries {
		//"Read is a helper function that calls Reader.Read using io.ReadFull. On return, n == len(b) if and only if err == nil." - Gemini 3 Thinking
		_, err := rand.Read(b)
		if err == nil {
			//If err == nil, it is guaranteed that n is exactly the size of your buffer (2 bytes).
			return binary.BigEndian.Uint16(b)
		}
		// Small sleep before retry to let system entropy recover
		// Don't sleep on the very last attempt
		if i < maxRetries-1 {
			time.Sleep(10 * time.Millisecond)
		}
	}

	// If we get here, the OS is fundamentally broken.
	// It's safer to crash than to serve insecure/predictable DNS.
	// If we reach this point, the system CSPRNG is failing.
	// Panic is the safest security choice for a DNS proxy.
	panic("critical system error: failed to generate secure random entropy")
}

type CacheEntry struct {
	Msg   *dns.Msg
	State UpstreamState
}

func (s *Server) dohHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context() // Get the request context

	var err error
	// 1. Identify the client immediately, before replying.
	//Since you are performing the PID lookup inside the handler (before sending the response), the TCP connection is guaranteed to be in the ESTABLISHED state.
	// Firefox is sitting there waiting for its DNS-over-HTTPS answer, so it's the perfect time to "catch" it in the Windows TCP table.
	remoteTCP, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err == nil {
		s.logger.Debug("client connected(early logging)",
			slog.String("proto", "DoH"),
			//slog.String("clientAddr", remoteTCP.String()),
			SafeAddr("clientAddr", remoteTCP),
		)
		// Use our TCP PID helper
		pid, exe, pErr := wincoe.PidAndExeForTCP(remoteTCP)
		// wincoe.Smashy()
		// pid := uint32(3)
		// exe := "foo3"
		// var pErr error = nil
		ctx = s.makeClientInfoContext(ctx, "DoH", remoteTCP, pid, exe, pErr)
	} else {
		s.logger.Warn("DoH: could not resolve remote addr", slog.String("addr", r.RemoteAddr))
		//FIXME: this is a bigger problem than a WARN, if it happens! but an ERROR here would make it mix with the red colored blocked requests, thus harder to be seen!
		//TODO: see if we can trigger this! and/or think of what happens if it happens!
	}

	if r.Method != "POST" && r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body []byte

	if r.Method == "POST" {
		// Limit incoming DoH payload to 64KB to prevent memory exhaustion attacks
		r.Body = http.MaxBytesReader(w, r.Body, int64(s.config.DoHMaxRequestBodyBytes))
		body, err = io.ReadAll(r.Body)
	} else {
		encoded := r.URL.Query().Get("dns")
		body, err = base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			http.Error(w, "Invalid GET param", http.StatusBadRequest)
			return
		}
	}
	if err != nil || len(body) == 0 {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	msg := new(dns.Msg)
	if err2 := msg.Unpack(body); err2 != nil {
		http.Error(w, fmt.Sprintf("Failed to unpack DNS query, err:%v", err2), http.StatusBadRequest)
		return
	}
	resp := s.handleDNSQuery(ctx, msg, r.RemoteAddr) // Field, not method
	if resp == nil {
		s.logger.Warn("empty DNS response, replying to client with service unavailable", slog.String("client", r.RemoteAddr))
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	pack, err := resp.Pack()
	if err != nil {
		s.logger.Warn("doh_pack_response_to_client_failed", SafeErr(err), slog.String("client", r.RemoteAddr))
		// Return a 500 error to the DoH client
		http.Error(w, "Failed to pack DNS response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Content-Length", fmt.Sprint(len(pack)))
	w.WriteHeader(http.StatusOK)
	wroteN, err := w.Write(pack)
	if err != nil {
		s.logger.Warn("failed to write the DoH reply to client (the DNS packet response body)", SafeErr(err), slog.Int("wrote_bytes", wroteN), slog.Int("shoulda_written", len(pack)))
		return
	}
}

func (s *Server) handleDNSQuery(ctx context.Context, msg *dns.Msg, clientAddr string) *dns.Msg {
	if len(msg.Question) != 1 {
		return formerrResponse(msg)
	}
	q := msg.Question[0]
	domain := strings.ToLower(strings.TrimSuffix(q.Name, ".")) //XXX: must lowercase it for matchPattern below! at least.
	if domain == "" || !isValidDNSName(domain) {               // Edge: Empty domain
		return formerrResponse(msg)
	}
	qtype := dns.TypeToString[q.Qtype] // Map lookup

	// Rate limit
	var rateLimited string
	gl := s.globalLimiter.Allow()
	if !gl {
		rateLimited = globalRateLimitExceeded
	} else {

		// 1. Extract only the IP address to strip away the ephemeral port
		clientIP, _, err := net.SplitHostPort(clientAddr)
		if err != nil {
			// Fallback safety: if string parsing fails, default back to the raw string
			s.logger.Warn("Unexpected couldn't split clientAddr into IP:port to use only the IP as key in the limiter, so using it as is", slog.String("clientAddr", clientAddr))
			clientIP = clientAddr
		}
		// 2. If it's any loopback address (127.x.x.x or ::1), collapse it to "localhost" to avoid one .exe which could be using many IPs in range of 127.0.0.0/8 as the request sender.
		if parsedIP := net.ParseIP(clientIP); parsedIP != nil && parsedIP.IsLoopback() {
			clientIP = "localhost"
		}
		// 3. Use the clean IP as the sync.Map key
		clIface, _ := s.clientLimiters.LoadOrStore(clientIP, rate.NewLimiter(rate.Limit(s.config.ClientRateQPS), s.config.ClientBurstQPS)) // Per-client qps/burst
		//TODO: add per exe limit, not just per IP limit; already have global limit though as 'rate_qps' in config.json
		cl := clIface.(*rate.Limiter)
		if !cl.Allow() {
			rateLimited = clientRateLimitExceeded
		}
	}
	if rateLimited != "" { //!gl || !cl.Allow() { //doneTODO: log if global or client limit was exceeded!
		s.logger.Warn(rateLimited, slog.String("client", clientAddr))
		sfr := servfailResponse(msg)
		s.logQuery(ctx, clientAddr, domain, qtype, rateLimited, "", nil, sfr, UpstreamState{Strategy: "rateLimited"})
		return sfr
	}

	// Whitelist
	matchedID := "" // must be empty, used in 2 logical places, one's here.
	matched := false
	func() { //for 'defer'
		s.ruleMutex.RLock()
		defer s.ruleMutex.RUnlock()

		rules := s.whitelist[qtype]
		for _, rule := range rules {
			if !rule.Enabled {
				continue
			}
			if matchPattern(rule.Pattern, domain) {
				matchedID = rule.ID
				matched = true
				break
			}
		}

		// --- START OF NEW CODE --- by gemini 3.1 pro (free tier)
		// Fallback: Auto-allow HTTPS if an 'A' record rule permits it, doneTODO: make it a bool config.json option
		if s.config.AllowHTTPSIfAAllowed && !matched && qtype == "HTTPS" {
			for _, rule := range s.whitelist["A"] {
				if !rule.Enabled {
					continue
				}
				if matchPattern(rule.Pattern, domain) {
					matchedID = rule.ID
					matched = true
					break
				}
			}
		}
		// --- END OF NEW CODE ---

		// ruleMutex.RUnlock()
	}()
	// if !matched {
	//     stats.Add(1)
	//     func() {
	//         blockMutex.Lock()
	//         defer blockMutex.Unlock() // Executes even if the code below panics
	//         recentBlocks = append(recentBlocks, BlockedQuery{Domain: domain, Type: qtype, Time: time.Now()})
	//         if len(recentBlocks) > 50 {
	//             recentBlocks = recentBlocks[1:]
	//         }
	//         //blockMutex.Unlock()
	//     }() // Notice the parens here to call it immediately
	//     blocked := blockResponse(msg)
	if !matched {
		s.stats.Add(1)
		func() {
			s.blockMutex.Lock()
			defer s.blockMutex.Unlock()

			// // 1. Remove duplicate if it already exists (same domain and type)
			// for i := 0; i < len(recentBlocks); i++ {
			// 	if recentBlocks[i].Domain == domain && recentBlocks[i].Type == qtype {
			// 		recentBlocks = append(recentBlocks[:i], recentBlocks[i+1:]...)
			// 		break
			// 	}
			// }

			// // 2. Prepend the new blocked query (so it appears at the top of the UI)
			// newBlock := BlockedQuery{Domain: domain, Type: qtype, Time: time.Now()}
			// recentBlocks = append([]BlockedQuery{newBlock}, recentBlocks...)

			// // 3. Keep the list size to a maximum of keepTrackOfThisManyRecentBlocks
			// if len(recentBlocks) > keepTrackOfThisManyRecentBlocks {
			// 	recentBlocks = recentBlocks[:keepTrackOfThisManyRecentBlocks]
			// }

			key := domain + ":" + qtype

			if elem, ok := s.recentBlocksMap[key]; ok {
				// We already have this block. Update the time and bump it to the front.
				// (Zero allocations!)
				bq := elem.Value.(*BlockedQuery)
				bq.Time = time.Now()
				s.recentBlocksList.MoveToFront(elem)
			} else {
				// Brand new block. Add to the front of our list and map.
				newBlock := &BlockedQuery{Domain: domain, Type: qtype, Time: time.Now()}
				elem := s.recentBlocksList.PushFront(newBlock)
				s.recentBlocksMap[key] = elem

				// Evict the oldest item if we exceed the tracked limit
				if s.recentBlocksList.Len() > s.config.MaxRecentBlocks {
					backElem := s.recentBlocksList.Back()
					if backElem != nil {
						backBQ := backElem.Value.(*BlockedQuery)
						backKey := backBQ.Domain + ":" + backBQ.Type
						delete(s.recentBlocksMap, backKey)
						s.recentBlocksList.Remove(backElem)
					}
				}
			}
		}() // Notice the parens here to call it immediately
		blocked := s.blockResponse(msg)
		s.logQuery(ctx, clientAddr, domain, qtype, blockedSTR, "", nil, blocked, UpstreamState{Strategy: "blockedByLackOfRuleAllowingIt"})
		return blocked
	}

	// Cache (edge: Negative responses cached short)
	key := domain + ":" + qtype

	//fmt.Printf("checking '%s' key in cache\n", key)
	if cachedIf, ok := s.cacheStore.Get(key); ok {
		entry := cachedIf.(CacheEntry)
		cached := entry.Msg

		// Return a copy of cached response with the current query ID to avoid
		// clients rejecting replies because of mismatched transaction IDs.
		resp := cached.Copy()
		resp.Id = msg.Id
		//fmt.Printf("found '%s' key in cache as: '%s' aka %+v aka %#v\n", key, resp.String(), resp, resp)
		ips := extractIPs(resp)

		// Use the stored upstreamState4, but update the strategy to indicate it was loaded from cache
		upstreamState4 := entry.State
		//state.Strategy = "cached (was: " + state.Strategy + ")"

		s.logQuery(ctx, clientAddr, domain, qtype, cacheHit, matchedID, ips, resp, upstreamState4)
		return resp
	}

	// --- START Local Hosts Override ---
	var hasLocalHost bool
	var matchedIPs []net.IP
	func() {
		s.localHostsMu.RLock()
		defer s.localHostsMu.RUnlock() // maybe it panics so unlock it even then!
		for _, rule := range s.localHosts {
			if matchPattern(rule.Pattern, domain) {
				matchedIPs = rule.IPs
				hasLocalHost = true
				break
			}
		}
	}() // for defer

	if hasLocalHost {
		resp := new(dns.Msg)
		resp.SetReply(msg)
		resp.Authoritative = true
		resp.RecursionAvailable = true

		for _, ip := range matchedIPs {
			isIPv4 := ip.To4() != nil

			if qtype == "A" && isIPv4 {
				rr := new(dns.A)
				rr.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: s.config.LocalHostsOverrideTTLSec}
				rr.A = ip
				resp.Answer = append(resp.Answer, rr)
			} else if qtype == "AAAA" && !isIPv4 {
				rr := new(dns.AAAA)
				rr.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: s.config.LocalHostsOverrideTTLSec}
				rr.AAAA = ip
				resp.Answer = append(resp.Answer, rr)
			}
		}

		// Cache this override so subsequent queries bypass the pattern loop
		//cacheStore.Set(key, resp.Copy(), timeUntilLocalHostsExpireInSeconds*time.Second)
		upstreamState5 := UpstreamState{Strategy: "etc_hosts"}
		s.cacheStore.Set(key, CacheEntry{
			Msg:   resp.Copy(),
			State: upstreamState5,
		}, time.Duration(s.config.LocalHostsOverrideTTLSec)*time.Second) //TODO: configurable cache time and dns record aka ttl time? (see above)

		s.logQuery(ctx, clientAddr, domain, qtype, localHostOverride, "", extractIPs(resp), resp, upstreamState5)
		return resp
	}
	// --- END Local Hosts Override ---

	// Forward to upstream DNS
	// 1. Save the original client ID
	oldID := msg.Id
	msg.Id = getSecureID() // 2. Generate a random ID for the upstream query (helps prevent cache poisoning)
	// 3. DO THE ACTUAL UPSTREAM QUERY
	resp, upstreamState3 := s.forwardToDoH(ctx, msg)
	// 4. Restore the original ID so the client's DNS resolver accepts the answer
	msg.Id = oldID // unconditionally restore so any msg-derived error response carries the right ID
	if resp != nil {
		resp.Id = oldID // Restores the ID for the upstream's response object
	}
	//Gemini 3 Thinking: "The ID Matching is a "defense in depth" move. By using a random ID for the journey to Quad9 and back, you decouple your internal network's IDs from the public internet,
	// making it much harder for someone to inject fake DNS responses into your proxy."
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		ips := []string{} //{"NXDOMAIN"}
		if resp != nil {
			ips = append(ips, fmt.Sprintf("dns.Rcode:%d", resp.Rcode))
		}
		negResp := servfailResponse(msg)
		s.logQuery(ctx, clientAddr, domain, qtype, forwardedButFailedSoSERVFAIL, matchedID, ips, negResp, upstreamState3)
		// Cache negatives short
		// Store a copy of the negative response as well
		//cacheStore.Set(key, negResp.Copy(), 2*time.Second)
		s.cacheStore.Set(key, CacheEntry{
			Msg:   negResp.Copy(),
			State: upstreamState3,
		}, time.Duration(s.config.CacheNegativeTTLSec)*time.Second) // time to cache negatives
		return negResp
	}

	//ips := extractIPs(resp) //before 'resp' gets mutated, and its IPs deleted.
	// Use a copy of the original upstream response so we can log exactly what they tried to send
	originalCopy := resp.Copy()
	originalIPs := extractIPs(originalCopy)
	// Filter
	filtered, filterReason := s.filterResponse(resp) // XXX: resp gets mutated here!
	if filtered == nil {
		// filterReason now holds exact info like "blockedByUpstream_ZeroIP" or "dns_rebinding_protection"

		s.logQuery(ctx, clientAddr, domain, qtype,
			filterReason+originalSTR, //blockedByUpstream_ORIGINAL //doneFIXME: this here is a guess because the upstream answer was filtered out likely due to having an IP like 0.0.0.0 returned, but could also be any of the blocked IPs specified in the config like 127.0.0.1/8 or 192.168.0.0/16 therefore this could mean the upstream tried to return a local or LAN IP but we stripped it out and we should notify accordingly! not just say that upstream blocked the hostname request which it only does if IP was 0.0.0.0 and nothing else.
			matchedID, originalIPs, originalCopy, upstreamState3)
		blocked := s.blockResponse(msg)
		blockedIPs := extractIPs(blocked)
		s.logQuery(ctx, clientAddr, domain, qtype,
			filterReason+returnedModifiedSTR, //doneFIXME: this here is a guess because the upstream answer was filtered out likely due to having an IP like 0.0.0.0 returned, but could also be any of the blocked IPs specified in the config like 127.0.0.1/8 or 192.168.0.0/16 therefore this could mean the upstream tried to return a local or LAN IP but we stripped it out and we should notify accordingly! not just say that upstream blocked the hostname request which it only does if IP was 0.0.0.0 and nothing else.
			matchedID, blockedIPs, blocked, upstreamState3)
		return blocked
	}

	// Cache with clamped TTL
	//ttl := computeTTL(filtered)
	//expiry := time.Duration(ttl) * time.Second
	expiry := max(computeTTL(filtered), time.Duration(s.config.CacheMinTTL)*time.Second)
	// if expiry < time.Duration(config.CacheMinTTL)*time.Second {
	//     expiry = time.Duration(config.CacheMinTTL) * time.Second
	// }

	// Store a copy in the cache, not the pointer you are about to return
	//cacheStore.Set(key, filtered.Copy(), expiry)
	s.cacheStore.Set(key, CacheEntry{
		Msg:   filtered.Copy(),
		State: upstreamState3,
	}, expiry)

	ips := extractIPs(filtered)
	s.logQuery(ctx, clientAddr, domain, qtype, forwardedSTR, matchedID, ips, filtered, upstreamState3)

	return filtered
}

func computeTTL(msg *dns.Msg) time.Duration {
	//To correctly handle upstream negative caching responses (like NXDOMAIN or NODATA), we need to check both the Answer section and the Ns (Authority) section. Additionally, if an SOA (Start of Authority) record is found in the Authority section, RFC 2308 mandates that the negative cache TTL should be capped by the SOA's Minttl value.
	var minTTL uint32 = 3600 // Default 1 hour,  not: //86400 // 24 hours
	// for _, rr := range msg.Answer {
	//     if int(rr.Header().Ttl) < minTTL {
	//         minTTL = int(rr.Header().Ttl)
	//     }
	// }
	// if minTTL == 0 { // Edge: Zero TTL
	//     minTTL = 60
	// }
	// return minTTL
	found := false

	// 1. Check the Answer section
	for _, rr := range msg.Answer {
		found = true
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}

	// 2. Check the Authority (Ns) section for negative responses (e.g., SOA)
	for _, rr := range msg.Ns {
		found = true
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
		// RFC 2308: For negative caching, use the minimum of the SOA TTL and its MinTTL field
		if soa, ok := rr.(*dns.SOA); ok {
			if soa.Minttl < minTTL {
				minTTL = soa.Minttl
			}
		}
	}

	if !found {
		minTTL = 300 // * time.Second
	}
	if minTTL < 10 { //XXX: hardcoded minimum 10 seconds TTL, FIXME: note about it in config.CacheMinTTL !
		minTTL = 10
	}
	return time.Duration(minTTL) * time.Second
}

//const ImpliedPort string = "443"

// call once at startup or when upstream config changes
func (s *Server) initDoHClients() []Upstream { //[]*http.Client { //upstreamIP, sni string) {
	//What this function does is purely preparatory. You are assembling a plan for future connections, not executing one.
	//Here’s why nothing goes on the network yet:
	//The http.Transport you create is just configuration.
	//DialContext is a callback, not an action. Go stores that function and promises to call it later only when a request actually needs a connection.
	//CloseIdleConnections() is the only thing here that might touch sockets — and even then, only previously established idle ones. If this is the first init, or if no DoH requests were ever made, there’s nothing to close and nothing goes out.
	//http.Client and http.Transport are blueprints, not engines.
	s.logger.Debug("starting initDoHClient()")
	// 3. LOCK (Slow path, ensures only one goroutine builds the client)
	s.dohMu.Lock()
	defer s.dohMu.Unlock()
	s.logger.Debug("past lock in initDoHClient()")
	// 4. DOUBLE CHECK
	// While we were waiting for the lock, someone else might
	// have finished the initialization. Check again.
	if current := s.upstreamsPtr.Load(); current != nil {
		return *current
	}
	// 5. DO THE ACTUAL WORK
	// Build your transport, tls config, etc.

	for _, dT := range s.dohTransportsPtrs {
		if dT != nil {
			var sn string
			if dT.TLSClientConfig != nil {
				sn = dT.TLSClientConfig.ServerName
			} else {
				sn = "<nil>"
			}
			s.logger.Debug("Closed DoH idle connection",
				//slog.Any("transport", dT), //this will race due to reflection and background goroutine(s) retrying connection(s)
				slog.String("transport_ptr", fmt.Sprintf("%p", dT)),
				slog.String("tls_servername", sn),
			)
			dT.CloseIdleConnections()
		}
	}
	s.dohTransportsPtrs = nil

	// --- PRE-COMPUTE DIAL ADDRESS ONCE ---
	//var newClients []*http.Client
	var newUpstreams []Upstream

	for i, u := range s.upstreamURLs {
		ip := s.upstreamIPs[i]
		port := u.Port()
		// if port == "" {
		//     //port = "443"
		//     // Log this only once when the client initializes, not on every connection!
		//     if strings.ToLower(u.Scheme) == "https" {
		//         //don't log in this case
		//         port = ImpliedPort
		//     } else if u.Scheme != "" {
		//         s.logger.Warn("Ignoring incompatible scheme(using https instead)", slog.String("implied_port", ImpliedPort),
		//             slog.Any("upstreamURL", u))
		//     } else {
		//         port = ImpliedPort
		//         s.logger.Warn("Using implied port for DoH upstream due to unspecified port and scheme",
		//             slog.String("implied_port", ImpliedPort),
		//             slog.Any("upstreamURL", u))
		//     }
		// }
		if port == "" {
			panic("dev fail: port is empty but shoulda been set in validateUpstream() to 443")
		}

		// Create the final "IP:Port" string once
		// Pre-joining prevents doing string manipulation inside the DialContext closure
		dialAddr := net.JoinHostPort(ip, port)
		sniHost := s.upstreamSNIs[i]
		if sniHost == "" {
			panic("dev fail: SNIHostname shouldn't be empty at this point, upstream host=" + dialAddr)
		}

		t := &http.Transport{
			// Dial raw TCP to the chosen IP so we don't perform DNS resolution here.
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := &net.Dialer{Timeout: time.Duration(s.config.UpstreamDialTimeoutSec) * time.Second}
				// Use the pre-computed dialAddr captured via closure!
				s.logger.Debug("(re)connected to upstream DoH", slog.String("dialAddr", dialAddr))
				return d.DialContext(ctx, network, dialAddr)
			},
			TLSClientConfig: &tls.Config{
				ServerName:         sniHost,
				InsecureSkipVerify: false,
			},
			Proxy:               nil,  // avoid proxy interference
			ForceAttemptHTTP2:   true, // allow http2 negotiation via ALPN (needed for 9.9.9.9 due to it saying this "This server implements RFC 8484 - DNS Queries over HTTP, and requires HTTP/2 in accordance with section 5.2 of the RFC."
			IdleConnTimeout:     time.Duration(s.config.UpstreamIdleConnTimeoutSec) * time.Second,
			MaxIdleConns:        s.config.UpstreamMaxIdleConns,
			MaxIdleConnsPerHost: s.config.UpstreamMaxIdleConnsPerHost,
		}
		s.dohTransportsPtrs = append(s.dohTransportsPtrs, t) //they're both pointers
		if s.dohTransportsPtrs[i] != t {
			panic("dev fail: dohTransportsPtrs[i] != t")
		}
		// newClients = append(newClients, &http.Client{
		// 	Timeout:   time.Duration(s.config.UpstreamClientTimeoutSec) * time.Second,
		// 	Transport: t,
		// })
		client := &http.Client{
			Timeout:   time.Duration(s.config.UpstreamClientTimeoutSec) * time.Second,
			Transport: t,
		}
		// Bundle everything this specific upstream needs to execute queries completely independently
		newUpstreams = append(newUpstreams, Upstream{
			Client:            client,
			URL:               u,
			SNI:               sniHost,
			logger:            s.logger,
			Retries:           s.config.UpstreamRetriesPerQuery,
			RetryBackoff:      time.Duration(s.config.UpstreamRetryBackoffMs) * time.Millisecond,
			BackgroundCtx:     s.ctx, // Pass the server-wide context to manage lifecycle quits
			CertLogTimeoutSec: s.config.CertLogTimeoutSec,
		})
	}
	// 6. ATOMIC STORE
	// s.dohClientsPtr.Store(&newClients)
	s.upstreamsPtr.Store(&newUpstreams)
	s.logger.Info("DoH clients initialized", slog.Int("count", len(newUpstreams)))
	s.logger.Debug("ending initDoHClients()")
	return newUpstreams
}

// Version is a global variable that can be overwritten at build time like this: go build -ldflags="-X 'dnsbollocks.Version=$(git describe --tags --always)'" -o dnsbollocks.exe
var Version = ""

// Compute the string exactly once at package startup
var memoizedVersion = func() string {
	var baseVersion string
	var vcsRevision string
	var vcsTime string  // the datetime of that commit(aka vcsRevision) not the build datetime!
	var isModified bool //ie. dirty

	// 1. Determine the base version (Release tag / module path)
	if Version != "" {
		baseVersion = Version
	} else if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			baseVersion = info.Main.Version
		}
	}

	// Default base if nothing is found yet
	if baseVersion == "" {
		baseVersion = "dev"
	}

	// 2. Extract the underlying VCS revision if embedded by the compiler
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				if setting.Value != "" {
					vcsRevision = setting.Value
					// Cap to roughly 16 characters for clean visibility
					if len(vcsRevision) > 16 {
						vcsRevision = vcsRevision[:16]
					}
				}
			case "vcs.time":
				if setting.Value != "" {
					// Parse standard RFC3339 layout: "2026-06-20T20:49:57Z"
					if t, err := time.Parse(time.RFC3339, setting.Value); err == nil {
						// // Formats to a compact, human-readable slug: "20260620.204957"
						// vcsTime = t.Format("20060102.150405")
						// Formats to exact pseudo-version layout: "20260620204957"
						vcsTime = t.Format("20060102150405")
					} else {
						// // Fallback if parsing fails for some unexpected compiler reason
						// vcsTime = strings.ReplaceAll(setting.Value, ":", "")
						// Clean fallback if parsing fails
						vcsTime = strings.NewReplacer("-", "", "T", "", ":", "", "Z", "").Replace(setting.Value)
					}
				}
			case "vcs.modified":
				if setting.Value == "true" {
					isModified = true
				}
			}
		}
	}

	// 3. Assemble the final version string idiomatically
	suffix := ""
	//like this/(via `go version -m dnsbollocks.exe`):         dep     github.com/miekg/dns    v1.1.73-0.20260402044838-d1539a788a12
	if vcsTime != "" {
		suffix += "-0." + vcsTime // FIXME: Hardcodes the '0' generation counter before the timestamp (can't read/get it apparently)
	}
	// Avoid duplicating the hash if the base version string already includes it
	if vcsRevision != "" && !strings.Contains(baseVersion, vcsRevision) {
		suffix += "-" + vcsRevision
	}
	// //datetime at the end
	// if vcsTime != "" {
	//     suffix += "-" + vcsTime
	// }
	if isModified {
		suffix += "+dirty"
	}

	return baseVersion + suffix
}() //it's a func call

// GetVersion returns the cached build info string directly
func GetVersion() string {
	return memoizedVersion
}

type UpstreamState struct { //doneTODO: rename Telemetry to something normal
	Strategy        string   `json:"strategy"`
	UpstreamUsed    string   `json:"upstream_used"`
	FailedUpstreams []string `json:"failed_upstreams"`
}

// forwardToDoH uses the preinitialized dohClient and supports one retry on transient network errors.
func (s *Server) forwardToDoH(ctx context.Context, req *dns.Msg) (*dns.Msg, UpstreamState) {
	var upstreamState1 UpstreamState
	upstreamState1.Strategy = s.config.UpstreamSelectionMode

	reqBytes, err := req.Pack()
	if err != nil {
		s.logger.Error("doh_prepost_pack_failed", SafeErr(err))
		return nil, upstreamState1
	}

	// clientsPtr := s.dohClientsPtr.Load()
	// if clientsPtr == nil {
	// 	c := s.initDoHClients()
	// 	clientsPtr = &c
	// }
	// clients := *clientsPtr
	// 1. Load the thread-safe slice of Upstream objects atomically
	upstreamsPtr := s.upstreamsPtr.Load()
	if upstreamsPtr == nil {
		u := s.initDoHClients()
		upstreamsPtr = &u
	}
	upstreams := *upstreamsPtr

	type result struct {
		msg *dns.Msg
		err error
		idx int // Useful for tracking which upstream won or failed
	}

	switch s.config.UpstreamSelectionMode {
	case "strict":
		// ==========================================
		// STRICT MODE: Wait for all & strict compare
		// ==========================================
		// ==========================================
		// OLD LOGIC: Wait for all & strict compare
		// ==========================================
		results := make([]result, len(upstreams))
		var wg sync.WaitGroup

		// Fire all queries concurrently
		for i, upstream := range upstreams {
			if upstream.Client == nil {
				panic(fmt.Sprintf("dev fail: dohClient %d is still nil after init! shouldn't happen! upstreamURL=%s SNI=%s", i, s.upstreamURLs[i], s.upstreamSNIs[i]))
			}
			wg.Add(1)
			go func(idx int, target Upstream) { // c *http.Client, targetURL *url.URL, targetSNI string) {
				defer wg.Done()
				//results[idx].msg, results[idx].err = doSingleDoHRequest(c, targetURL, targetSNI, reqBytes)
				msg, err := target.doSingleDoHRequest(ctx, reqBytes) //c, targetURL, targetSNI, reqBytes)
				results[idx] = result{msg: msg, err: err, idx: idx}
			}(i, upstream) //, s.upstreamURLs[i], s.upstreamSNIs[i])
		}

		wg.Wait()

		var reference *dns.Msg
		var refIdx int

		// Compare responses
		for i, res := range results {
			if res.err != nil || res.msg == nil {
				s.logger.Error("upstream failed or returned nil", slog.String("url", s.upstreamURLs[i].String()),
					//slog.String("err", res.err.Error()),
					SafeErr(res.err),
				)
				upstreamState1.FailedUpstreams = append(upstreamState1.FailedUpstreams, s.upstreamURLs[i].String())
				return nil, upstreamState1 // Refuse to resolve if any upstream completely fails
			}

			if reference == nil {
				reference = res.msg
				refIdx = i
				upstreamState1.UpstreamUsed = s.upstreamURLs[i].String()
			} else {
				if !compareDNSResponses(reference, res.msg) {
					// Mismatch means failure to agree
					upstreamState1.FailedUpstreams = append(upstreamState1.FailedUpstreams, s.upstreamURLs[i].String())

					// Extract IPs for the log message
					refIPs := extractIPs(reference)
					curIPs := extractIPs(res.msg)
					s.logger.Warn("upstream DNS response mismatch! dropping query to protect client",
						slog.String("query", req.Question[0].Name),
						slog.String("upstream_DoH_url1", s.upstreamURLs[refIdx].String()),
						//slog.Any("ips_returned1", refIPs),
						SafeStringSlice("ips_returned1", refIPs),
						slog.String("upstream_DoH_url2", s.upstreamURLs[i].String()),
						//slog.Any("ips_returned2", curIPs),
						SafeStringSlice("ips_returned2", curIPs),
						slog.String("reference", reference.String() /*non nil*/),
						slog.String("current", res.msg.String() /*non nil here*/),
					)
					return nil, upstreamState1 // Drop the query because of answer discrepancy
				}
			}
		}

		return reference, upstreamState1
	case "failover":
		// ==========================================
		// FAILOVER MODE: Priority-based with active healing
		// ==========================================
		resp, used, failed, err := s.failoverSelect.Exchange(ctx, upstreams, reqBytes)
		upstreamState1.UpstreamUsed = used
		upstreamState1.FailedUpstreams = failed
		if err != nil {
			s.logger.Error("failover selection failed", SafeErr(err))
			return nil, upstreamState1
		}
		return resp, upstreamState1

	case "fastest":
		fallthrough
	default:
		// ==========================================
		// FASTEST MODE: Fastest successful response wins
		// ==========================================
		// ==========================================
		// NEW LOGIC: Fastest successful response wins
		// ==========================================
		// Use a buffered channel equal to the number of clients so slower goroutines
		// don't block forever trying to write their results after the function returns.
		resChan := make(chan result, len(upstreams))

		for i, upstream := range upstreams {
			if upstream.Client == nil {
				panic(fmt.Sprintf("dev fail: dohClient %d is still nil after init! shouldn't happen! upstreamURL=%s SNI=%s", i, s.upstreamURLs[i], s.upstreamSNIs[i]))
			}
			go func(idx int, target Upstream) { //, c *http.Client, targetURL *url.URL, targetSNI string) {
				msg, err := target.doSingleDoHRequest(ctx, reqBytes) //c, targetURL, targetSNI, reqBytes)
				resChan <- result{msg: msg, err: err, idx: idx}
			}(i, upstream) //, s.upstreamURLs[i], s.upstreamSNIs[i])
		}

		var lastErr error
		//for i := 0; i < len(clients); i++ {
		for range len(upstreams) {
			res := <-resChan

			// If we got a valid DNS response (even an NXDOMAIN), return it immediately
			if res.err == nil && res.msg != nil {
				upstreamState1.UpstreamUsed = s.upstreamURLs[res.idx].String()
				return res.msg, upstreamState1
			}

			upstreamState1.FailedUpstreams = append(upstreamState1.FailedUpstreams, s.upstreamURLs[res.idx].String())
			// Keep track of the error in case they ALL fail
			if res.err != nil {
				lastErr = res.err
			}
		}

		// If we reach here, every single upstream request failed
		s.logger.Error("all upstreams failed to provide a valid response",
			//slog.String("last_err", lastErr.Error()),
			SafeErr2("last_err", lastErr),
		)
		return nil, upstreamState1
	}
}

// SafeRequestAttr extracts only the essential primitive data fields from an http.Request
// into a race-safe, highly readable slog.Attr group without using reflection(ie. slog.Any).
func SafeRequestAttr(key string, req *http.Request) slog.Attr {
	if req == nil {
		return slog.Group(key)
	}

	return slog.Group(key,
		slog.String("method", req.Method),
		slog.String("url", req.URL.String()),
		slog.String("proto", req.Proto),
		slog.String("host", req.Host),
		slog.String("content_type", req.Header.Get("Content-Type")),
	)
}

func (u *Upstream) doSingleDoHRequest(ctx context.Context,
	//client *http.Client, targetURL *url.URL, sni string,
	reqBytes []byte) (*dns.Msg, error) {

	if u.Client == nil {
		panic(fmt.Sprintf("dev fail: dohClient is still nil at calling doSingleDoHRequest! shouldn't happen! upstreamURL=%s SNI=%s", u.URL, u.SNI))
	}

	retries := u.Retries //s.config.UpstreamRetriesPerQuery
	if retries < 1 {
		retries = 0 // Sanity check: must attempt at least once(see the 'for' below)
	}
	maxTries := 1 + retries

	var resp *http.Response
	var err4ClientDo error
	var req *http.Request
	var cancelCurrentReq func() // Track the active context cancel function across scopes

	//for attempt := range maxTries { // starts from 0 !
	for attempt := 1; attempt <= maxTries; attempt++ {
		// Use an anonymous function wrapper so 'defer' operates on a per-iteration scope
		failedToCreateRequest, errReq := func() (bool, error) {
			// 1. Create a transient request context derived from the client's ctx
			reqCtx, cancelReq := context.WithCancel(ctx)
			// Use a flag to track if responsibility for calling cancelReq() has been handed off
			var handedOver bool
			defer func() {
				if !handedOver {
					cancelReq() // Clean up immediately on panic or retryable error
				}
			}()

			// 2. Spin up a quick monitor to cancel the request if the application shuts down
			go func() {
				select {
				case <-u.BackgroundCtx.Done(): //this must be Server.ctx or s.ctx former backgroundCtx
					cancelReq() // Aborts the HTTP request immediately on Ctrl+C
				case <-reqCtx.Done():
					// Normal exit when the request finishes or client disconnects
				}
			}()

			// 3. Pass the merged context to the HTTP request

			// create request with supplied context so caller controls deadline/cancel
			var e error
			req, e = http.NewRequestWithContext(reqCtx, "POST", u.URL.String(), bytes.NewReader(reqBytes))
			if e != nil {
				//s.logger.Error("doh_newrequest_failed", slog.Any("err", e)) // not here!
				return true, e
			}

			req.Header.Set("Content-Type", "application/dns-message")
			if u.SNI != "" {
				req.Host = u.SNI
			}

			// Capture the HTTP client execution
			resp, err4ClientDo = u.Client.Do(req) // this is concurrency safe
			if err4ClientDo == nil {
				//success
				cancelCurrentReq = cancelReq // Hand off the cancellation function to the outer scope
				handedOver = true            // Detach this iteration's deferred cleanup
			}
			return false, nil
		}()

		// If NewRequestWithContext failed, abort immediately just like the original logic
		if failedToCreateRequest {
			return nil, errReq
		}

		// If client.Do succeeded, we can stop retrying
		if err4ClientDo == nil {
			//success!
			break
		}

		// decide if error is transient/retryable
		// common retryable errors: temporary network errors, EOF, connection reset
		var netErr net.Error
		isRetryable := errors.Is(err4ClientDo, io.EOF) || errors.Is(err4ClientDo, io.ErrUnexpectedEOF) ||
			errors.Is(err4ClientDo, syscall.ECONNRESET) || // Since you are on Windows, syscall.ECONNRESET is actually mapped to the Windows-specific WSAECONNRESET code internally by the Go net package, so errors.Is will work correctly across platforms if you ever decide to compile this for Linux/macOS too.
			errors.Is(err4ClientDo, syscall.ECONNREFUSED) ||
			(errors.As(err4ClientDo, &netErr) && netErr.Timeout()) //netErr.Timeout(): This is the "official" way to check for timeouts now. It covers both the network dial timing out and your http.Client.Timeout.

		if isRetryable {
			u.logger.Error("doh_post_transient_error for this query", SafeErr(err4ClientDo),
				slog.Int("current_try", attempt), slog.Int("max_tries", maxTries),
				//slog.Any("query", req),
				SafeRequestAttr("query", req),
				slog.Bool("will_retry", attempt < maxTries))
			// small backoff: sleep a bit but respect context
			select {
			case <-time.After(time.Duration(u.RetryBackoff) * time.Millisecond):
			case <-ctx.Done():
				u.logger.Debug("doh sensed client quit during retry backoff...")
				return nil, ctx.Err()
			case <-u.BackgroundCtx.Done():
				u.logger.Debug("doh sensed quit during retry backoff...")
				return nil, u.BackgroundCtx.Err()
			}
			continue
		}
		// non-retryable error
		// --- NEW DIAGNOSTIC BLOCK ---
		if strings.Contains(err4ClientDo.Error(), "tls:") || strings.Contains(err4ClientDo.Error(), "x509:") {
			u.logger.Error("TLS verification failed when tried to query upstream DNS server",
				slog.String("url", u.URL.String()),
				slog.String("sni_used", u.SNI),
				SafeErr(err4ClientDo))

			// Run a manual probe to see what the server is actually sending
			u.logCertDetails() //targetURL.Hostname(), targetURL.Port(), sni)
		} else {
			u.logger.Error("Failed to query upstream DNS server", SafeErr(err4ClientDo))
		}
		// --- END DIAGNOSTIC BLOCK ---
		return nil, err4ClientDo
	} //for retries

	// ✅ Ensure the active context gets cancelled when the outer function returns
	if cancelCurrentReq != nil {
		defer cancelCurrentReq()
	}

	if resp == nil {
		// last attempt produced no response (shouldn't happen), treat as failure
		u.logger.Error("doh_no_response")
		return nil, errors.New("no response")
	}
	defer resp.Body.Close()

	// ✅ This will now execute perfectly! The context is guaranteed to stay alive here.
	body, err4ReadAll := io.ReadAll(resp.Body)
	if err4ReadAll != nil {
		u.logger.Error("doh_readbody_failed", SafeErr(err4ReadAll))
		return nil, err4ReadAll
	}

	// debug/log non-200 or unexpected content-type
	if resp.StatusCode != 200 {
		u.logger.Error("doh_upstream_status", slog.String("status", resp.Status))
		return nil, fmt.Errorf("upstream status %s", resp.Status)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "application/dns-message" {
		u.logger.Error("doh_upstream_content_type isn't the expected application/dns-message", slog.String("content_type", ct))
	}
	if len(body) < 12 {
		u.logger.Error("doh_upstream_body_too_short", slog.Int("len", len(body)))
	}

	upMsg := new(dns.Msg)
	if err4Unpack := upMsg.Unpack(body); err4Unpack != nil {
		n := len(body)
		u.logger.Error("doh_unpack_failed", SafeErr(err4Unpack),
			slog.String("body_hex", fmt.Sprintf("Upstream body (hex, first %d): %x", n, body[:n])),
			slog.String("body_text", fmt.Sprintf("Upstream body (text, first %d): %q", n, body[:n])),
		)
		return nil, err4Unpack
	}
	return upMsg, nil
}

func (u *Upstream) logCertDetails() { //(ip, port, sni string) {
	port := u.URL.Port()
	if port == "" {
		//port = "443"
		panic("dev fail: port is empty but shoulda been set in validateUpstream() to 443")
		// port = ImpliedPort
		// s.logger.Warn("dev fail, port shoulda been already set in initDoHClients! Using default tho.",
		//     slog.String("implied_port", ImpliedPort),
		//     slog.Any("sni", sni))
	}
	addr := net.JoinHostPort(u.URL.Hostname(), port)

	dialer := &net.Dialer{Timeout: time.Duration(u.CertLogTimeoutSec) * time.Second}
	// We use InsecureSkipVerify: true ONLY for this probe so we can read the cert
	// that was otherwise rejected.
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         u.SNI,
		InsecureSkipVerify: true,
	})

	if err != nil {
		u.logger.Error("Diagnostic probe failed", slog.String("addr", addr), SafeErr(err))
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()
	u.logger.Info("--- TLS Diagnostic Probe ---", slog.String("remote_addr", addr), slog.String("sni_sent", u.SNI))

	for i, cert := range state.PeerCertificates {
		u.logger.Info(fmt.Sprintf("Certificate [%d] in chain", i),
			slog.String("subject", cert.Subject.String()),
			slog.String("issuer", cert.Issuer.String()),
			//slog.Any("dns_names", cert.DNSNames), // This is the most important part
			SafeStringSlice("dns_names", cert.DNSNames),
			//slog.Any("ips", cert.IPAddresses),
			SafeSlice("ips", cert.IPAddresses, net.IP.String),
			slog.Time("expires", cert.NotAfter),
		)
	}
}

func compareDNSResponses(a, b *dns.Msg) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Rcode != b.Rcode {
		return false
	}
	if len(a.Answer) != len(b.Answer) {
		return false
	}

	// Normalize answers by stripping out TTLs (as different caches will return different TTLs)
	// and sorting them (as DNS Round Robin changes order).
	getNorms := func(msg *dns.Msg) []string {
		norms := make([]string, 0, len(msg.Answer))
		for _, rr := range msg.Answer {
			clone := dns.Copy(rr)
			clone.Header().Ttl = 0
			norms = append(norms, clone.String())
		}
		sort.Strings(norms)
		return norms
	}

	normsA := getNorms(a)
	normsB := getNorms(b)

	for i := range normsA {
		if normsA[i] != normsB[i] {
			return false
		}
	}
	return true
}

// Globals for static data
var (
	// This runs once at startup
	edeText = func() string {
		exePath, err := os.Executable()
		if err != nil {
			exePath = "DNSbollocks"
		}
		// Get startup time. "15:04:05" is the Go magic layout for HH:MM:SS
		// You can also use time.DateOnly (2006-01-02) if you prefer
		startTime := time.Now().Format("2006-01-02 15:04:05-0700") // don't need more precision here!
		version := GetVersion()

		return fmt.Sprintf("Blocked by %q %q [which was started on %q]", exePath, version, startTime)
	}() //it's a func call

	edeCode = dns.ExtendedErrorCodeBlocked
)

func (s *Server) blockResponse(msg *dns.Msg) *dns.Msg {
	// Special-case: For AAAA queries, return NOERROR with an empty answer instead of NXDOMAIN.
	// Windows treats NXDOMAIN for AAAA as authoritative non-existence which prevents IPv4 fallback.
	// if you don't do this then, when you run the following in git-bash (git for windows's bash terminal):
	// $ ssh -T git@github.com
	// ssh: Could not resolve hostname github.com: Name or service not known
	// because win11 service "DNS Client" aka "dnscache" does two AAAA queries to us which we reply with NXDOMAIN and it stops.
	// if we reply with NOERROR and empty like this here, then it will try a third query as A which succeeds (if it's in the whitelist)
	// IF A were whitelisted and thus we're reply with NOERROR here otherwise with NXDOMAIN then the problem is when a domain is initially blocked
	// and we whitelist it in A afterwards, then dnscache might've cached the NXDOMAIN from AAAA and treat it as such for X more seconds thus
	// it's best to always NODATA(aka NOERROR with 0 answers, as per Gemini) this here regardless of whether its A is or isn't allowed
	// to avoid this case where dnscache win11 service caches the NXDOMAIN!
	if s.config.BlockAAAAasEmptyNoError && len(msg.Question) > 0 && msg.Question[0].Qtype == dns.TypeAAAA && s.config.BlockMode == "nxdomain" {
		resp := new(dns.Msg)
		resp.SetReply(msg)
		resp.Rcode = dns.RcodeSuccess
		resp.Answer = []dns.RR{}
		resp.Ns = []dns.RR{}
		resp.Extra = []dns.RR{}
		resp.Authoritative = true
		resp.RecursionAvailable = true
		// short TTL negative AAAA response is effectively encoded by empty answer; caching handled by caller
		return resp
	}

	//in Go, implicit 'break' after each 'case'
	switch s.config.BlockMode { //XXX: it's already lowercased!
	case "nxdomain":
		msg.SetRcode(msg, dns.RcodeNameError)
	case "ip_block", "block_ip":
		ttl := uint32(s.config.BlockedResponseTTLSec)
		blockIP := net.ParseIP(s.config.BlockIP)
		if blockIP == nil {
			blockIP = net.IPv4(0, 0, 0, 0) // Default, TODO: const or global this! unless we need a fresh instance each time?
		}
		if blockIP.To4() != nil { // A record
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
			rr.A = blockIP
			msg.Answer = []dns.RR{rr}
		} else { // AAAA stub, FIXME: what we doing here?! also, no IP?
			rr := new(dns.AAAA)
			rr.Hdr = dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
			msg.Answer = []dns.RR{rr}
		}
		msg.SetRcode(msg, dns.RcodeSuccess)
	case "drop":
		return nil
	default:
		// fallback to nxdomain
		msg.SetRcode(msg, dns.RcodeNameError)
	}

	msg.Authoritative = true
	msg.RecursionAvailable = true

	// this EDE for firefox, not needed but should be easier for the user to see why DNS didn't work.
	// 1. Manually build the EDE struct using the global variables
	ede := &dns.EDNS0_EDE{
		InfoCode:  edeCode,
		ExtraText: edeText,
	}

	// Re-allocate the OPT "envelope" but use the static EDE logic
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT

	// Logic: If the client asked for something specific,
	// we use 1232 as a "ceiling" to stay safe.
	//In DNS, the UDPSize you set in the OPT header (opt.SetUDPSize(1232)) isn't the size of the current packet—it's an advertisement to the other side saying, "I am capable of receiving packets up to this size."
	// 1. Start with your "Ideal" safety limit (1232)
	ourMax := uint16(1232)

	// 2. Check if the client specifically asked for less
	if clientOpt := msg.IsEdns0(); clientOpt != nil {
		if clientOpt.UDPSize() < ourMax {
			ourMax = clientOpt.UDPSize() // Respect the client's smaller limit
		}
	}

	// 3. Set the advertised size
	opt.SetUDPSize(ourMax)
	// 1232 is the "EDNS0 Flag Day" recommended value
	// It prevents IP fragmentation on modern networks
	//opt.SetUDPSize(1232) // Safer modern size, affects only current response. "What it actually does: When a client sends a query, it often includes its own OPT record saying "I can accept up to X bytes." By responding with SetUDPSize(1232), you are saying "I am sending this reply, and I'm letting you know my maximum limit is 1232."", "Future Queries: It does not bind future queries to that size. Each request/response pair is independent."

	if s.config.UseEDEInBlockedReply {
		opt.SetDo() // Set the "DNSSEC OK" bit; some browsers require this to process OPT records
		// You can reuse a global EDE struct here IF it is never modified
		opt.Option = []dns.EDNS0{ede}
	}

	msg.Extra = append(msg.Extra, opt)

	return msg

}

const NODATA string = "upstream_nodata"
const BlockedZeroIP string = "blocked_ZeroIP"
const BlockedBlacklistedIP string = "blocked_blacklisted_ip"
const StrippedRRSIG string = "stripped_rrsig"

const BlockedByUpstream string = "blockedByUpstream_ZeroIP"

// mutates the passed arg
func (s *Server) filterResponse(msg *dns.Msg /*, blacklists []string)*/) (*dns.Msg, string) {
	if msg == nil {
		panic("msg was nil, unexpected bad programming/code ;p")
	}
	if len(msg.Question) == 0 {
		panic("no DNS question! unexpected bad programming/code ;p")
	}

	q := msg.Question[0]
	qtype := dns.TypeToString[q.Qtype] // Map lookup

	// nets := make([]*net.IPNet, 0, len(blacklists))
	// for _, cidr := range blacklists {
	//     _, ipnet, err := net.ParseCIDR(cidr)
	//     if err == nil {
	//         nets = append(nets, ipnet)
	//     } else {
	//         //hard fail here (it should've alredy failed at startup or at some other future stage when updating the reponse blacklist)
	//         errorLogger.Error("invalid_cidr", slog.String("cidr", cidr), "context", "in blacklist reponse") // 'go vet' caught it (indirectly via 'go test')
	//         panic("unreachable2, or the logger is broken")
	//     }
	// }

	// FIX: If upstream naturally returned NOERROR with 0 answers (NODATA), let it through!
	if len(msg.Answer) == 0 && len(msg.Ns) == 0 && len(msg.Extra) == 0 {
		return msg, NODATA
	}

	var dropReasons []string
	// var dropReasons string // Start as empty string ""

	// Define a local closure to process any arbitrary DNS section
	filterSection := func(records []dns.RR, sectionName string) []dns.RR {
		var good []dns.RR
		for _, rr := range records {
			if keep, modifiedRR, reason := s.processRR(rr); keep {
				good = append(good, modifiedRR)
			} else {
				// Captures and mutates 'dropReasons' from the outer scope automatically

				dropReasons = append(dropReasons, reason)

				// // Append with a separator if it's not the first reason
				// if dropReasons != "" {
				//     dropReasons += ", " + reason
				// } else {
				//     dropReasons = reason
				// }

				s.logger.Warn("Dropped "+sectionName+" from upstream",
					slog.String("reason", reason),
					slog.String("query_type", qtype),
					slog.String("rr", rr.String() /*non-nil if here due to 'for' was entered*/),
				)
			}
		}
		return good
	}

	// Re-assign the filtered slices directly back to the message
	msg.Answer = filterSection(msg.Answer, "inAnswer")
	msg.Extra = filterSection(msg.Extra, "inExtra")

	//if len(msg.Answer) == 0 { // this dropped HTTPS replies and they were thus not seen at all, so seen as blockedbyUpstream
	if len(msg.Answer) == 0 && len(msg.Ns) == 0 && len(msg.Extra) == 0 {
		s.logger.Warn("response_filtered_all", slog.String("query_type", qtype), slog.String("domain", q.Name),

			// slog.String("drop_reasons",
			//     //dropReasons
			//     strings.Join(dropReasons, ", "),
			// ),
			SafeStringSlice("drop_reasons", dropReasons),
		)

		hasZeroIP := false
		hasBlacklistedIP := false
		for _, r := range dropReasons {
			if r == BlockedZeroIP {
				hasZeroIP = true
			}
			if r == BlockedBlacklistedIP {
				hasBlacklistedIP = true
			}
		}

		// Tell handleDNSQuery EXACTLY why this was zeroed out
		if hasZeroIP {
			return nil, BlockedByUpstream
		}
		if hasBlacklistedIP {
			return nil, BlockedBlacklistedIP
		}
		return nil, "filtered_all_records"
		//return nil
	}
	return msg, ""
}

// filters out unwanteds like the IPs that are returned or ip hints in HTTPS dns types.
// mutates the passed arg!
func (s *Server) processRR(rr dns.RR /*, nets []*net.IPNet*/) (bool, dns.RR, string) {
	switch r := rr.(type) {
	case *dns.A:
		if r.A.IsUnspecified() { // Matches 0.0.0.0
			return false, nil, BlockedZeroIP
		}
		if s.isBlacklistedIP(r.A) {
			return false, nil, BlockedBlacklistedIP
		}
		return true, r, ""

	case *dns.AAAA:
		if r.AAAA.IsUnspecified() { // Matches ::
			return false, nil, BlockedZeroIP
		}
		if s.isBlacklistedIP(r.AAAA) {
			return false, nil, BlockedBlacklistedIP
		}
		return true, r, ""

	// Look for HTTPS records (Type 65)
	case *dns.HTTPS:
		//doneTODO: make this configurable in config.json so only if 'true' do this:
		if s.config.RemoveHTTPSIPv4Hints {
			// Strip ipv4hint (Key 4) and ipv6hint (Key 6)
			// This keeps ALPN (h3) and ECH (privacy) but forces IP lookup via A/AAAA
			// Filter the SVCB/HTTPS parameters
			newParams := []dns.SVCBKeyValue{}
			for _, param := range r.Value {
				k := param.Key()
				// Key 4 = ipv4hint, Key 6 = ipv6hint
				// We only keep keys that AREN'T hints
				if k != dns.SVCB_IPV4HINT && k != dns.SVCB_IPV6HINT {
					newParams = append(newParams, param)
				} else {
					s.logger.Warn("Dropping IP hint from the HTTPS reply", slog.String("param", param.String() /*non nil*/))
				}
			}
			r.Value = newParams
			//return true, r, "" //XXX: (already doing this below)
		} //else keep as is
		return true, r, ""

	case *dns.RRSIG:
		// Always drop signatures because we are modifying the RRsets they sign.
		// A missing signature is better than a broken one.
		return false, nil, StrippedRRSIG

	default:
		// Keep other types (MX, TXT, CNAME, etc.)
		return true, rr, ""
	}

	//nolint:unreachable  (can't get rid of warning, so i guess not keeping panic here)
	//panic("some unhandled case fell thru from switch/ifelse?")
}

// func ipInNets(ip net.IP, nets []*net.IPNet) bool {
//     for _, n := range nets {
//         if n.Contains(ip) {
//             return true
//         }
//     }
//     return false
// }

func extractIPs(msg *dns.Msg) []string {
	var ips []string
	for _, rr := range msg.Answer {
		switch r := rr.(type) {
		case *dns.A:
			ips = append(ips, r.A.String())
		case *dns.AAAA:
			ips = append(ips, r.AAAA.String())
		}
	}
	return ips
}

const originalSTR string = "_ORIGINAL"
const returnedModifiedSTR string = "_RETURNEDMODIFIED"
const forwardedButFailedSoSERVFAIL string = "forwarded_but_FAILED_so_SERVFAIL"
const forwardedSTR string = "forwarded"
const localHostOverride string = "local_host_override"
const cacheHit string = "cache_hit"
const blockedSTR string = "blocked"
const globalRateLimitExceeded string = "rate_limit_exceeded_globally"
const clientRateLimitExceeded string = "rate_limit_exceeded_for_client"

var QueryActionANSI = map[string]string{
	forwardedSTR:                       "\x1b[92m", // Bright Green
	cacheHit:                           "\x1b[93m", // Bright Yellow
	blockedSTR:                         "\x1b[91m", // Bright Red
	globalRateLimitExceeded:            "\x1b[31m", // Red
	clientRateLimitExceeded:            "\x1b[31m", // Red
	BlockedBlacklistedIP + originalSTR: "\x1b[91m",
	BlockedBlacklistedIP + returnedModifiedSTR: "\x1b[91m",
	BlockedByUpstream + originalSTR:            "\x1b[91m",
	BlockedByUpstream + returnedModifiedSTR:    "\x1b[91m",
	forwardedButFailedSoSERVFAIL:               "\x1b[91m",
	localHostOverride:                          "\x1b[96m", // Bright Cyan
}

var colorTagsRegex = regexp.MustCompile(`<(/?)(green|red|yellow|cyan|gray|white|magenta)>`)

// formatColorTags parses tags like <green>word</green> into ANSI codes
func formatColorTags(s string, baseColor string) string {
	if !strings.Contains(s, "<") {
		return s
	}
	return colorTagsRegex.ReplaceAllStringFunc(s, func(match string) string {
		if strings.HasPrefix(match, "</") {
			return baseColor
		}
		switch match {
		case "<green>":
			return "\x1b[92m"
		case "<red>":
			return "\x1b[91m"
		case "<yellow>":
			return "\x1b[93m"
		case "<cyan>":
			return "\x1b[96m"
		case "<gray>":
			return "\x1b[90m"
		case "<white>":
			return "\x1b[97m"
		case "<magenta>":
			return "\x1b[95m"
		}
		return match
	})
}

// stripColorTags will be used by the JSON (File) handlers to strip out <color> tags entirely
var stripColorTags = func(groups []string, a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindString {
		str := a.Value.String()
		if strings.Contains(str, "<") {
			str = colorTagsRegex.ReplaceAllString(str, "")
			a.Value = slog.StringValue(str)
		}
	} else if a.Value.Kind() == slog.KindAny {
		// We can still safe-read incoming errors using type assertion...
		if err, ok := a.Value.Any().(error); ok && err != nil {
			str := err.Error()
			if strings.Contains(str, "<") {
				str = colorTagsRegex.ReplaceAllString(str, "")
				//a.Value = slog.AnyValue(errors.New(str))

				// FIX: Convert the error into a pure, safe primitive string value.
				// This removes slog.AnyValue and prevents any downstream reflection.
				a.Value = slog.StringValue(str)
			}
		}
	}
	return a
}

// func logQuery(client, domain, typ, action, ruleID string, ips []string) {
//     attrs := []any{
//         slog.String("client", client),
//         slog.String("domain", domain),
//         slog.String("type", typ),
//         slog.String("action", action),
//         slog.String("ts", time.Now().Format(time.RFC3339)),
//     }
//     if ruleID != "" {
//         attrs = append(attrs, slog.String("rule_id", ruleID))
//     }
//     if len(ips) > 0 {
//         attrs = append(attrs, slog.String("ips", strings.Join(ips, ",")))
//     }
//     queryLogger.Log(ctx, slog.LevelInfo, "query", attrs...)
// }

// SafeStringSlice returns a race-safe, structured slog.Attr group.
// It explicitly handles string quoting for items with spaces without using reflection.
// All this is to avoid using slog.Any which can race when passed networking structs that are modified by other goroutines
func SafeStringSlice(key string, slice []string) slog.Attr {
	// if len(slice) == 0 {
	//     // Return an empty group under the specified key safely
	//     return slog.Group(key)
	// }

	// attrs := make([]slog.Attr, len(slice))
	// for i, val := range slice {
	//     // Explicitly map each item to an immutable slog.String attribute token.
	//     // The index is the key ("0", "1", etc.), ensuring no structural reflection.
	//     attrs[i] = slog.String(fmt.Sprintf("%d", i), val)
	// }

	// // slog.Group returns a single slog.Attr token containing the inner attributes
	// return slog.GroupAttrs(key, attrs...)
	return SafeSlice(key, slice, func(s string) string { return s })
}

// SafeSlice converts a slice of ANY type into a race-safe, structured slog.Attr group.
// It uses a mapper function to evaluate strings immediately, bypassing reflection.
// All this is to avoid using slog.Any which can race when passed networking structs that are modified by other goroutines
func SafeSlice[T any](key string, slice []T, mapper func(T) string) slog.Attr {
	if len(slice) == 0 {
		// Return an empty group under the specified key safely
		return slog.GroupAttrs(key)
	}

	attrs := make([]slog.Attr, len(slice))
	for i, item := range slice {
		// Evaluates the string instantly, ensuring zero thread-safety issues
		// Explicitly map each item to an immutable slog.String attribute token.
		// The index is the key ("0", "1", etc.), ensuring no structural reflection.
		attrs[i] = slog.String(fmt.Sprintf("%d", i), mapper(item))
	}
	// slog.Group returns a single slog.Attr token containing the inner attributes
	return slog.GroupAttrs(key, attrs...)
}

const TimeStampsFormat string = "2006-01-02 15:04:05.000000000-07:00 MST" // old: /*time.RFC3339*/

func (s *Server) logQuery(ctx context.Context, client, domain, typ, action, ruleID string, ips []string, blocked *dns.Msg, upstreamState2 UpstreamState) {
	if ctx == nil {
		s.logger.Error("bad coding: logQuery called with nil context", // should never happen
			slog.String("client", client),
			slog.String("domain", domain))
		return
	}

	var ts string = time.Now().Format(TimeStampsFormat)

	var attrs []any = []any{
		slog.String("domain", domain),
		slog.String("type", typ),
		slog.String("action", action),
	}

	//this is Grok 4.20 code which makes it always hit "coding_fail: logQuery called without metadata in context"
	// val := ctx.Value(clientInfoKey)
	// var info *clientMetadata
	// var ok bool
	// info, ok = val.(*clientMetadata) // ← this was the bug, shouldn't have been pointer(just as I thought was the problem, initially)
	// if !ok || info == nil {
	//     // Epic Coding Fail tracker - this should never happen in production
	//     // attrs = append(attrs, slog.String("metadata_error", "context_missing_client_info"))
	//     // This is the "Epic Coding Fail" tracker.
	//     // We add a field to the query log so you can find these easily.
	//     attrs = append(attrs, slog.String("metadata_error", "context_missing_client_info"))

	//     // Also, log a separate Error to your main system log/stderr
	//     // so you get alerted that a handler is broken.
	//     s.logger.Warn("coding_fail: logQuery called without metadata in context",
	//         slog.String("client", client),
	//         slog.String("domain", domain))
	// } else {
	// --- NEW: Pull the PID/Exe info from the context backpack ---
	if info, ok := ctx.Value(clientInfoKey).(clientMetadata); ok {
		elapsed := time.Since(info.startTime)
		attrs = append(attrs,
			slog.String("exe", info.exe))
		//To avoid cluttering the console, at least.
		numServices := len(info.services)
		if numServices != 0 {
			attrs = append(attrs,
				//slog.String("services", strings.Join(info.services, ", ")),
				SafeStringSlice("services", info.services),
				slog.Int("num_services", numServices),
			)
		}
		attrs = append(attrs,
			slog.String("proto", info.protocol),
			//slog.String("clientAddr", info.clientAddr.String()),
			SafeAddr("clientAddr", info.clientAddr),
			slog.Uint64("pid", uint64(info.pid)),
		)
		if info.err != nil {
			attrs = append(attrs,
				//slog.String("err", info.err.Error()),
				SafeErr(info.err),
			)
		}
		attrs = append(attrs,
			slog.String("elapsed", elapsed.String()),
			//slog.Int64("elapsed_ms", elapsed.Milliseconds()),
			slog.Int64("elapsed_ns", elapsed.Nanoseconds()),
			slog.String("client_connected_at_ts", info.startTime.Format(TimeStampsFormat)),
			slog.String("log_ts", ts),
		)
	} else {
		// This is the "Epic Coding Fail" tracker.
		// We add a field to the query log so you can find these easily.
		attrs = append(attrs, slog.String("metadata_error", "context_missing_client_info"))

		// Also, log a separate Error to your main system log/stderr
		// so you get alerted that a handler is broken.
		s.logger.Warn("coding_fail: logQuery called without metadata in context",
			slog.String("client", client),
			slog.String("domain", domain))
	}

	if ruleID != "" {
		attrs = append(attrs, slog.String("rule_id", ruleID))
	}
	if len(ips) > 0 {
		attrs = append(attrs, slog.String("ips", strings.Join(ips, ",")))
	}
	attrs = append(attrs,
		slog.String("client", client),

		slog.String("category", "query"), // <-- this routes it to "queries.log" only
	)
	if blocked != nil {
		attrs = append(attrs, slog.String("blocked_dnsMsg", blocked.String()))
	}
	// Inject the upstream-state payload
	if upstreamState2.Strategy != "" {
		attrs = append(attrs, slog.String("strategy", upstreamState2.Strategy))
	}
	if upstreamState2.UpstreamUsed != "" {
		attrs = append(attrs, slog.String("upstream_used", upstreamState2.UpstreamUsed))
	}
	if len(upstreamState2.FailedUpstreams) > 0 {
		attrs = append(attrs, slog.Any("failed_upstreams", upstreamState2.FailedUpstreams))
	}
	s.logger.Log(ctx, slog.LevelInfo, "logged_query", attrs...)
}

func servfailResponse(msg *dns.Msg) *dns.Msg {
	msg.SetRcode(msg, dns.RcodeServerFailure)
	msg.RecursionAvailable = true
	return msg
}

func formerrResponse(msg *dns.Msg) *dns.Msg {
	msg.SetRcode(msg, dns.RcodeFormatError)
	return msg
}

// Add this helper to Server
func (s *Server) tryAddBlacklistIP(n *net.IPNet) bool {
	s.responseBlacklistMu.Lock()
	defer s.responseBlacklistMu.Unlock()

	for _, existing := range s.responseBlacklist {
		if existing.String() == n.String() {
			return false // Already exists
		}
	}
	s.responseBlacklist = append(s.responseBlacklist, n)
	return true // Added successfully
}

func (s *Server) responseBlacklistHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		data := map[string]any{
			"Page":              "response-blacklist",
			"ResponseBlacklist": s.getResponseBlacklist(),
		}
		s.renderTemplate(w, r, "response-blacklist", data)
		return
	}

	if r.Method == "POST" {
		action := r.FormValue("action")

		if action == "add" {
			cidrStr := strings.TrimSpace(r.FormValue("cidr"))
			if cidrStr != "" {
				_, n, err := net.ParseCIDR(cidrStr)
				if err != nil {
					// Fallback: if they just enter an IP, auto-convert it to CIDR
					ip := net.ParseIP(cidrStr)
					if ip != nil {
						if ip.To4() != nil {
							_, n, _ = net.ParseCIDR(cidrStr + "/32")
						} else {
							_, n, _ = net.ParseCIDR(cidrStr + "/128")
						}
					}
				}

				if n != nil {
					// exists := false
					// func() {
					// 	s.responseBlacklistMu.Lock()
					// 	defer s.responseBlacklistMu.Unlock()
					// 	for _, existing := range s.responseBlacklist {
					// 		if existing.String() == n.String() {
					// 			exists = true
					// 			break
					// 		}
					// 	}
					// 	if !exists {
					// 		s.responseBlacklist = append(s.responseBlacklist, n)
					// 	}
					// }()

					// if !exists {
					// 	if err := s.saveResponseBlacklist(); err != nil {
					// 		s.logFatal("failed to save response blacklist after add from webUI", err)
					// 	}
					// 	// Instantly evict cached entries that contain the newly blacklisted IP
					// 	s.invalidateCacheForBlacklistedIPs()
					// }

					// Using the clean add helper method with natural defer unlock
					if s.tryAddBlacklistIP(n) { //added so it didn't exist
						if err := s.saveResponseBlacklist(); err != nil {
							s.logFatal("failed to save response blacklist after add from webUI", err)
						}
						// Instantly evict cached entries that contain the newly blacklisted IP
						s.invalidateCacheForBlacklistedIPs()
					}
				} else {
					http.Error(w, "Invalid IP or CIDR format", http.StatusBadRequest)
					return
				}
			}
		} else if action == "delete" {
			cidrStr := strings.TrimSpace(r.FormValue("cidr"))
			// Using the clean delete helper method with natural defer unlock
			if s.tryDeleteBlacklistIP(cidrStr) { //it got deleted
				if err := s.saveResponseBlacklist(); err != nil {
					s.logFatal("failed to save response blacklist after delete from webUI", err)
				}
			}

			// deleted := false
			// s.responseBlacklistMu.Lock()
			// for i, existing := range s.responseBlacklist {
			// 	if existing.String() == cidrStr {
			// 		s.responseBlacklist = append(s.responseBlacklist[:i], s.responseBlacklist[i+1:]...)
			// 		deleted = true
			// 		break
			// 	}
			// }
			// s.responseBlacklistMu.Unlock()
			// if deleted {
			// 	if err := s.saveResponseBlacklist(); err != nil {
			// 		s.logFatal("failed to save response blacklist after delete from webUI", err)
			// 	}
			// }
		}
		http.Redirect(w, r, "/response-blacklist", http.StatusSeeOther)
	}
}

// tryDeleteBlacklistIP removes a CIDR string match from the blacklist slice.
// Returns true if the target was found and deleted, false otherwise.
func (s *Server) tryDeleteBlacklistIP(cidrStr string) bool {
	s.responseBlacklistMu.Lock()
	defer s.responseBlacklistMu.Unlock()

	for i, existing := range s.responseBlacklist {
		if existing.String() == cidrStr {
			s.responseBlacklist = append(s.responseBlacklist[:i], s.responseBlacklist[i+1:]...)
			return true
		}
	}
	return false
}

// Add this helper to Server
func (s *Server) checkBlacklistMatches(n *net.IPNet) []string {
	s.responseBlacklistMu.RLock()
	defer s.responseBlacklistMu.RUnlock()

	var matches []string
	for _, existing := range s.responseBlacklist {
		// Check if they match exactly, OR if the existing network fully encompasses the new IP/subnet
		if existing.String() == n.String() || existing.Contains(n.IP) {
			matches = append(matches, existing.String())
		}
	}
	return matches
}

func (s *Server) responseBlacklistCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	cidrStr := strings.TrimSpace(r.URL.Query().Get("cidr"))
	if cidrStr == "" {
		w.Write([]byte(`{"matches":[]}`))
		return
	}

	// Parse incoming string to a network block
	_, n, err := net.ParseCIDR(cidrStr)
	if err != nil {
		ip := net.ParseIP(cidrStr)
		if ip != nil {
			if ip.To4() != nil {
				_, n, _ = net.ParseCIDR(cidrStr + "/32")
			} else {
				_, n, _ = net.ParseCIDR(cidrStr + "/128")
			}
		}
	}

	var matches []string
	if n != nil {
		// func() {
		// 	s.responseBlacklistMu.RLock()
		// 	defer s.responseBlacklistMu.RUnlock()
		// 	for _, existing := range s.responseBlacklist {
		// 		// Check if they match exactly, OR if the existing network fully encompasses the new IP/subnet
		// 		if existing.String() == n.String() || existing.Contains(n.IP) {
		// 			matches = append(matches, existing.String())
		// 		}
		// 	}
		// }()
		matches = s.checkBlacklistMatches(n)
	}

	// Return array of matching filters to frontend
	json.NewEncoder(w).Encode(map[string][]string{"matches": matches})
}

func (s *Server) startWebUI(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.statsHandler)
	mux.HandleFunc("/rules", s.rulesHandler)
	mux.HandleFunc("/hosts", s.hostsHandler)
	mux.HandleFunc("/blocks", s.blocksHandler) // XXX: changing this "/blocks" requires changing more occurrences in other places in the uiTemplates as well!
	mux.HandleFunc("/response-blacklist", s.responseBlacklistHandler)
	mux.HandleFunc("/response-blacklist/check", s.responseBlacklistCheckHandler)
	mux.HandleFunc("/logs", s.logsHandler)
	mux.HandleFunc("/logs_queries", s.logsQueriesHandler)
	mux.Handle("/debug/vars", expvar.Handler()) // Stats endpoint

	//FIXME: need the IP to be settable for UI as well, not just the port, else cannot run multiple UIs on diff. localhost IPs w/ same port.
	baseListener, err := net.Listen("tcp", addr) //fmt.Sprintf("%s:%d", hostOrIP, port))
	if err != nil {
		s.logger.Error("UI listener failed to bind/listen", slog.String("addr", addr),
			//slog.String("hostOrIp", hostOrIP), slog.Int("port", port),
			SafeErr(err))
		s.shutdown(1) //os.Exit(1) // Fail-fast serial
	}

	// 2. Adaptive Upgrading: Intercept listener if TLS is requested
	var finalListener net.Listener = baseListener
	// // Using a closure looks up finalListener at the moment the function returns
	// defer func() {
	//     if finalListener != nil {
	//         finalListener.Close()
	//     }
	// }()
	protocolScheme := "http"

	//s.logger.Info("Web UI listening", slog.String("host", hostOrIP), slog.Int("port", port)) //, slog.String("stats_path", "/debug/vars"))
	if s.config.WebUIUseTLS {
		// Leverage the global certificate loaded/generated during startup
		tlsConfig := &tls.Config{
			//In Go, a tls.Certificate struct is entirely read-only once it has been loaded into memory. When you pass it to tls.Config, the underlying crypto libraries only read its public certificate chains and private key blocks to perform cryptographic handshakes with incoming clients.
			Certificates: []tls.Certificate{s.dohCert}, // Reuse the global keypair directly!
			MinVersion:   tls.VersionTLS12,
		}

		// Wrap the basic TCP listener inside Go's built-in TLS protocol filter
		finalListener = tls.NewListener(baseListener, tlsConfig)
		protocolScheme = "https"
	}

	//uiSrv := &http.Server{Handler: mux}
	// CHANGED: Wrap the mux in our new authMiddleware
	//uiSrv := &http.Server{Handler: s.authMiddleware(mux)}
	uiSrv := &http.Server{Handler: s.authMiddleware(s.csrfMiddleware(mux))}
	// BETTER APPROACH: Query the active listener for its real bound address.
	// This is guaranteed to be split-safe, and correctly exposes the port
	// if the user passes ":0" for a dynamically allocated port.
	boundAddr := baseListener.Addr().String()
	host, portStr, err := net.SplitHostPort(boundAddr)
	//// Split the address for the logger to maintain your existing clean log output
	//host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		panic(fmt.Errorf("this wasn't supposed to fail, boundAddr=%s err:%w", boundAddr, err))
		//host = addr
		//portStr = "unknown"
	}
	s.logger.Info("Web UI listening",
		slog.String("scheme", protocolScheme),
		slog.String("host", host),
		slog.String("port", portStr),
		slog.String("url", fmt.Sprintf("%s://%s", protocolScheme, boundAddr)),
	)

	// Listen for the global shutdown signal to gracefully close the Web UI
	s.shutdownWG.Add(1)
	go func() {
		defer s.shutdownWG.Done()

		<-s.ctx.Done()
		s.logger.Debug("Shutting down Web UI server...")
		shutdownCtx, cancelDown := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancelDown()
		_ = uiSrv.Shutdown(shutdownCtx)
	}()
	s.shutdownWG.Add(1)
	go func() {
		defer s.shutdownWG.Done()

		defer finalListener.Close() // Graceful close
		if err := uiSrv.Serve(finalListener); err != nil && err != http.ErrServerClosed {
			s.logFatal("ui_serve_failed", err)
		}
	}()
	s.logger.Debug("UI server loop launched")
	s.logger.Info("Interactive controls available: Ctrl+X to clean exit, Ctrl+R to reload (partial)config, Ctrl+C to break gracefully")
}

const csrfTokenKey contextKey = "csrfToken"

func (s *Server) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Get or generate the CSRF cookie
		cookie, err := r.Cookie("csrf_token")
		var token string

		if err != nil || cookie.Value == "" {
			token = uuid.New().String()
			http.SetCookie(w, &http.Cookie{
				Name:     "csrf_token",
				Value:    token,
				Path:     "/",
				HttpOnly: true, // Prevent client-side JS from reading the cookie
				SameSite: http.SameSiteLaxMode,
			})
		} else {
			token = cookie.Value
		}

		// 2. Pass token down the context so the template renderer can grab it
		ctx := context.WithValue(r.Context(), csrfTokenKey, token)
		r = r.WithContext(ctx)

		// 3. Validate the token on all state-changing POST requests
		if r.Method == "POST" {
			formToken := r.FormValue("csrf_token")
			if formToken == "" || formToken != token {
				//s.logger.Warn("CSRF token validation failed; dropping request", slog.String("client", r.RemoteAddr))

				// Capture everything safely in local variables immediately (optional, but clean)
				//because the request is completely isolated to this single thread of execution at this moment, you can read any field or header from r with zero risk of a data race.
				clientIP := r.RemoteAddr
				targetPath := r.URL.Path
				targetHost := r.Host
				originHeader := r.Header.Get("Origin")
				refererHeader := r.Header.Get("Referer")
				userAgent := r.Header.Get("User-Agent")

				s.logger.Warn("CSRF token validation failed; dropping request",
					slog.String("client", clientIP),
					slog.String("method", r.Method),
					slog.String("path", targetPath),
					slog.String("host", targetHost),
					slog.String("origin", originHeader),   // The site initiating the request
					slog.String("referer", refererHeader), // The exact URL making the request
					slog.String("user_agent", userAgent),
				)
				http.Error(w, "403 Forbidden - CSRF Verification Failed", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) statsHandler(w http.ResponseWriter, r *http.Request) {
	//w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var body strings.Builder
	body.WriteString("<h2>Statistics</h2>")
	fmt.Fprintf(&body, "<p>Blocks: %q</p><p>Cache size: %d</p><p>Upstream IPs: %v</p>", s.stats.String(), s.cacheStore.ItemCount(), s.upstreamIPs)
	//uiTemplates.Execute(w, struct{ Body template.HTML }{Body: template.HTML(body)}) // Raw HTML, no escape
	data := map[string]any{
		"Page":    "stats",
		"RawBody": template.HTML(body.String()), // Tells template "I'm not ready to be a sub-template yet"
	}
	//uiTemplates.Execute(w, data)
	s.renderTemplate(w, r, "stats", data)
}

func (s *Server) snapshotWhitelist() map[string][]RuleEntry {
	s.ruleMutex.RLock()
	defer s.ruleMutex.RUnlock()

	copyMap := make(map[string][]RuleEntry)
	for key, entries := range s.whitelist {
		// Copy the slice to prevent modification of the underlying array
		newSlice := make([]RuleEntry, len(entries))
		copy(newSlice, entries)
		copyMap[key] = newSlice
	}
	return copyMap
}

type RuleView struct {
	Type    string
	ID      string
	Pattern string
	Enabled bool
}

func (s *Server) rulesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// data := map[string]any{
		//     "Page":     "rules",
		//     "DNSTypes": dnsTypes,
		//     "Rules":    snapshotWhitelist(), // Safe, independent copy
		// }

		// Flatten the map into a single slice for unified table rendering
		rulesSnapshot := s.snapshotWhitelist() // Safe, independent copy
		// var flatRules []RuleView
		// for typ, rules := range rulesSnapshot {
		//     for _, rule := range rules {
		// 1. Extract and sort the keys (DNS Types) to stop random UI shuffling
		var types []string
		for typ := range rulesSnapshot {
			types = append(types, typ)
		}
		sort.Strings(types) // "A" will now consistently appear before "HTTPS"

		// 2. Build the flat list using the sorted types
		var flatRules []RuleView
		for _, typ := range types {
			rules := rulesSnapshot[typ]
			for _, rule := range rules {
				flatRules = append(flatRules, RuleView{
					Type:    typ,
					ID:      rule.ID,
					Pattern: rule.Pattern,
					Enabled: rule.Enabled,
				})
			}
		}

		data := map[string]any{
			"Page":     "rules",
			"DNSTypes": dnsTypes,
			"Rules":    flatRules, // Passing the flattened slice now
		}

		s.renderTemplate(w, r, "rules", data)
		return
	}

	if r.Method == "POST" {
		// Handle delete requests
		if r.FormValue("delete") == "1" {
			id := r.FormValue("id")
			typ := r.FormValue("type")

			if id == "" || typ == "" {
				http.Error(w, "id and type required for delete", http.StatusBadRequest)
				return
			}
			if err := validateDNSType(typ); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// id is a UUID used only as a map key; sanitize it against injection just in case.
			if _, modified := sanitizeDomainInput(id); modified {
				http.Error(w, "id contains illegal characters", http.StatusBadRequest)
				return
			}

			var deleted bool = false

			//TODO: make proper delete rule function, heh.
			func() {
				s.ruleMutex.Lock()
				defer s.ruleMutex.Unlock()

				if rules, ok := s.whitelist[typ]; ok {
					for i, rule := range rules {
						if rule.ID == id {
							//     // Copy the tail over the deleted element
							//     copy(rules[i:], rules[i+1:])
							//     // Explicitly zero the last element to prevent string memory leaks
							//     rules[len(rules)-1] = RuleEntry{}
							//     // Shrink the slice (wouldn't have zeroed last without the above explicit!)
							//     whitelist[typ] = rules[:len(rules)-1]

							s.invalidateCacheForPattern(rule.Pattern)
							// Replaces the shifting copy hacks with an isolated fresh array allocation
							s.whitelist[typ] = s.withRuleRemovedAt(rules, i)
							deleted = true
							break
						}
					}
				}
			}() // lock released here
			if deleted {
				if err := /*uses lock*/ s.saveQueryWhitelist(); err != nil {
					s.logFatal("failed to save whitelist after rule deletion from webUI", err)
				}
				http.Redirect(w, r, "/rules", http.StatusSeeOther)
				return
			} else {
				http.Error(w, "rule not found", http.StatusNotFound)
				return
			}
		}

		patternLowercased := strings.ToLower(strings.TrimSpace(r.FormValue("pattern"))) //XXX: must be lowercased for matchPattern later on.
		typ := r.FormValue("type")
		id := r.FormValue("id")
		enabledStr := r.FormValue("enabled")
		enabledBool := enabledStr == "on" || enabledStr == "true" || enabledStr == "1"

		if patternLowercased == "" || typ == "" {
			http.Error(w, "Pattern and type required", http.StatusBadRequest)
			return
		}

		if err := validateDNSType(typ); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := validateRulePattern(patternLowercased); err != nil {
			http.Error(w, "Invalid pattern: "+err.Error(), http.StatusBadRequest)
			return
		}
		// id, if present, is a UUID; guard it the same way as in the delete path.
		if id != "" { //aka is this an EDIT attempt?
			if _, modified := sanitizeDomainInput(id); modified {
				http.Error(w, "id contains illegal characters", http.StatusBadRequest)
				return
			}
		}

		// Run the update/add logic inside a thread-safe closure that bubbles up errors
		err := func() error {
			s.ruleMutex.Lock()
			defer s.ruleMutex.Unlock()

			if id != "" { //this is an EDIT attempt
				//     // Edit: Find and update (search all types)
				// --- EDIT MODE ---
				var foundOldRule bool
				var oldType string
				var oldIndex int
				var oldPattern string

				// 1. Find where the rule currently lives
				for t, rules := range s.whitelist {
					for i, r := range rules {
						if r.ID == id {
							foundOldRule = true
							oldType = t
							oldIndex = i
							oldPattern = r.Pattern
							break
						}
					}
					if foundOldRule {
						break
					}
				}

				if !foundOldRule {
					return fmt.Errorf("rule not found")
				}

				// 2. Check for pattern conflicts in the TARGET type group
				for _, rule := range s.whitelist[typ] {
					if rule.ID != id && rule.Pattern == patternLowercased {
						return fmt.Errorf("rule with this pattern '%s' already exists for type %s", patternLowercased, typ)
					}
				}

				// if oldType == typ {
				//     // Type didn't change -> Update fully IN-PLACE without mutating underlying array
				//     oldEntries := whitelist[typ]
				//     newEntries := make([]RuleEntry, len(oldEntries))
				//     copy(newEntries, oldEntries)

				//     newEntries[oldIndex].Pattern = patternLowercased
				//     newEntries[oldIndex].Enabled = enabledBool

				//     whitelist[typ] = newEntries
				// } else {
				//     // Type changed -> Safely remove from old slice, safely prepend to new slice
				//     oldEntries := whitelist[oldType]
				//     newOldEntries := make([]RuleEntry, 0, len(oldEntries)-1)
				//     newOldEntries = append(newOldEntries, oldEntries[:oldIndex]...)
				//     newOldEntries = append(newOldEntries, oldEntries[oldIndex+1:]...)
				//     whitelist[oldType] = newOldEntries

				//     targetEntries := whitelist[typ]
				//     newRule := RuleEntry{ID: id, Pattern: patternLowercased, Enabled: enabledBool}

				//     newTargetEntries := make([]RuleEntry, 0, len(targetEntries)+1)
				//     newTargetEntries = append(newTargetEntries, newRule)
				//     newTargetEntries = append(newTargetEntries, targetEntries...)
				//     whitelist[typ] = newTargetEntries
				// }
				newRule := RuleEntry{ID: id, Pattern: patternLowercased, Enabled: enabledBool}
				if oldType == typ {
					// Type didn't change -> Update fully IN-PLACE cleanly using our new function
					s.whitelist[typ] = withRuleUpdatedAtIndex(s.whitelist[typ], oldIndex, newRule)
				} else {
					// Type changed -> Safely remove from old slice, safely prepend to new slice

					// 1. Remove from old slice using copy (avoids the ... unpack allocation loop)
					// oldEntries := whitelist[oldType]
					// newOldEntries := make([]RuleEntry, len(oldEntries)-1)
					// copy(newOldEntries[:oldIndex], oldEntries[:oldIndex])
					// copy(newOldEntries[oldIndex:], oldEntries[oldIndex+1:])
					// whitelist[oldType] = newOldEntries

					s.whitelist[oldType] = s.withRuleRemovedAt(s.whitelist[oldType], oldIndex)

					// 2. Prepend smoothly to the new category using your new function
					s.whitelist[typ] = s.withRulePrepended(s.whitelist[typ], newRule)
				}
				s.invalidateCacheForPattern(oldPattern)
				if oldPattern != patternLowercased {
					s.invalidateCacheForPattern(patternLowercased)
				}
				s.logger.Info("Rule edited via WebUI", slog.String("id", id), slog.String("new_pattern", patternLowercased), slog.Bool("enabled", enabledBool),
					slog.String("old_pattern", oldPattern))
			} else { // this is an ADD new rule
				// --- ADD MODE ---
				// Add new: Prevent duplicate (same type + pattern, case-insensitive)
				//lowerPattern := strings.ToLower(pattern)
				for _, rule := range s.whitelist[typ] {
					//if strings.ToLower(rule.Pattern) == lowerPattern {
					if rule.Pattern /*already lowercase!*/ == patternLowercased {
						//http.Error(w, "Rule with this pattern '"+patternLowercased+"' already exists for type "+typ, http.StatusConflict)
						return fmt.Errorf("rule with this pattern '%s' already exists for type %s", patternLowercased, typ)
					}
				}

				newID := s.newUniqueID(s.whitelist)
				newRule := RuleEntry{ID: newID, Pattern: patternLowercased, Enabled: enabledBool}
				// if _, ok := whitelist[typ]; !ok { //does the key for 'typ' not exist? make it
				//     whitelist[typ] = []Rule{}
				// }
				// // if whitelist[typ] == nil { // does the key for 'typ' not exist? OR it exists but has nil value
				// //     whitelist[typ] = []Rule{}
				// // }
				//config.Whitelist[typ] = append(config.Whitelist[typ], newRule)

				//whitelist[typ] = append(whitelist[typ] /*ok if nil*/, newRule)

				// whitelist[typ] = append([]RuleEntry{newRule}, whitelist[typ]...)

				// // Prepend cleanly by allocating a fresh slice wrapper with known capacity
				// targetEntries := whitelist[typ]
				// // newTargetEntries := make([]RuleEntry, 0, len(targetEntries)+1)
				// // newTargetEntries = append(newTargetEntries, newRule)
				// // newTargetEntries = append(newTargetEntries, targetEntries...)
				// newTargetEntries := make([]RuleEntry, len(targetEntries)+1)
				// // 1. Copy old entries into the new slice, starting at index 1
				// copy(newTargetEntries[1:], targetEntries)
				// // 2. Insert the new rule at index 0
				// newTargetEntries[0] = newRule
				// whitelist[typ] = newTargetEntries

				// Replaces all the manual make() and copy() steps with your new helper function
				s.whitelist[typ] = s.withRulePrepended(s.whitelist[typ], newRule)
				s.invalidateCacheForPattern(patternLowercased)
				s.logger.Info("Rule added via WebUI", slog.String("pattern", patternLowercased), slog.String("type", typ), slog.String("id", newID), slog.Bool("enabled", enabledBool))
			}
			return nil
		}() // lock released here
		// Handle any error returned by the thread-safe operations
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}

		if err := /*uses lock!*/ s.saveQueryWhitelist(); err != nil {
			s.logFatal("failed to save whitelist after rule add/edit from webUI", err)
		}
		http.Redirect(w, r, "/rules", http.StatusSeeOther)
	}
}

// withRuleRemovedAt safely returns a new slice with the RuleEntry at the given index removed,
// leaving the original underlying array completely untouched for concurrent readers.
func (s *Server) withRuleRemovedAt(entries []RuleEntry, index int) []RuleEntry {
	// If the slice is empty or index is out of bounds, return it safely
	if index < 0 || index >= len(entries) {
		return entries
	}

	newEntries := make([]RuleEntry, len(entries)-1)

	// Copy everything up to the index
	copy(newEntries[:index], entries[:index])

	// Copy everything after the index
	copy(newEntries[index:], entries[index+1:])

	s.logger.Warn("Deleted rule", slog.Any("rule", entries[index])) // XXX: slog.Any is no longer forbidden for this struct
	return newEntries
}

// SafeRuleAttr explicitly maps a RuleEntry struct to a safe slog.Attr group.
func SafeRuleAttr(key string, r RuleEntry) slog.Attr {
	return slog.Group(key,
		slog.String("id", r.ID),
		slog.String("pattern", r.Pattern),
		slog.Bool("enabled", r.Enabled),
	)
}

// withRulePrepended safely inserts a new RuleEntry at the beginning of a slice
// without mutating the underlying array of existing readers.
func (s *Server) withRulePrepended(entries []RuleEntry, newRule RuleEntry) []RuleEntry {
	newTargetEntries := make([]RuleEntry, len(entries)+1)

	// Copy old entries starting at index 1
	copy(newTargetEntries[1:], entries)

	// Drop the new item at index 0
	newTargetEntries[0] = newRule
	s.logger.Debug("Prepended rule", slog.Any("rule", newRule)) // XXX: slog.Any is no longer forbidden for this struct

	return newTargetEntries
}

// withRuleAppended safely inserts a new RuleEntry at the end of a slice
// without mutating the underlying array of existing readers.
func withRuleAppended(entries []RuleEntry, newBlock RuleEntry) []RuleEntry {
	newTargetEntries := make([]RuleEntry, len(entries)+1)

	// Copy old entries starting at index 0
	copy(newTargetEntries, entries)

	// Drop the new item at the very last index position
	newTargetEntries[len(entries)] = newBlock

	return newTargetEntries
}

// withRuleUpdatedAtIndex safely updates a rule at a specific index without mutating the original array.
func withRuleUpdatedAtIndex(entries []RuleEntry, index int, updatedRule RuleEntry) []RuleEntry {
	newEntries := make([]RuleEntry, len(entries))
	copy(newEntries, entries)
	newEntries[index] = updatedRule
	return newEntries
}

type HostView struct {
	Index      int
	Pattern    string
	IPsDisplay string // Pre-joined "1.1.1.1, 2.2.2.2"
}

// invalidateCacheForPattern surgically removes any cached DNS responses
// that match the given host pattern (handling wildcards correctly).
func (s *Server) invalidateCacheForPattern(pattern string) {
	if s.cacheStore == nil {
		return
	}
	for key := range s.cacheStore.Items() {
		// key format is "domain:type" (e.g., "router.local:A")
		parts := strings.SplitN(key, ":", 2)
		if len(parts) > 0 {
			domain := parts[0]
			if matchPattern(pattern, domain) {
				s.cacheStore.Delete(key)
				s.logger.Debug("Evicted cached record due to rule change",
					slog.String("key", key),
					slog.String("matched_pattern", pattern),
					slog.String("domain", domain))
			}
		}
	}
}

func (s *Server) invalidateCacheForBlacklistedIPs() {
	if s.cacheStore == nil {
		return
	}
	for key, item := range s.cacheStore.Items() {
		//packed, ok := item.Object.([]byte)
		entry, ok := item.Object.(CacheEntry)
		if !ok {
			continue
		}
		msg := entry.Msg
		if msg == nil {
			continue
		}
		//msg := new(dns.Msg)
		// if err := msg.Unpack(packed); err != nil {
		// 	continue
		// }

		shouldEvict := false
		for _, rr := range msg.Answer {
			if aRecord, ok := rr.(*dns.A); ok {
				if s.isBlacklistedIP(aRecord.A) { // Substitute with your actual IP-checking logic
					shouldEvict = true
					break
				}
			}
			if aaaaRecord, ok := rr.(*dns.AAAA); ok {
				if s.isBlacklistedIP(aaaaRecord.AAAA) {
					shouldEvict = true
					break
				}
			}
		}

		if shouldEvict {
			s.cacheStore.Delete(key)
			s.logger.Debug("Evicted cached response: contained newly blacklisted IP", slog.String("key", key))
		}
	}
}

func (s *Server) hostsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// 1. Snapshot the data under lock
		s.localHostsMu.RLock()
		viewData := make([]HostView, len(s.localHosts))
		for i, h := range s.localHosts {
			var ipsStr []string
			for _, ip := range h.IPs {
				ipsStr = append(ipsStr, ip.String())
			}
			viewData[i] = HostView{
				Index:      i,
				Pattern:    h.Pattern,
				IPsDisplay: strings.Join(ipsStr, ", "),
			}
		}
		s.localHostsMu.RUnlock() // Lock released!

		// 2. Render the page
		data := map[string]any{
			"Page":  "hosts",
			"Hosts": viewData,
		}

		// if err := uiTemplates.Execute(w, data); err != nil {
		//     s.logger.Error("template_error", SafeErr(err))
		// }
		s.renderTemplate(w, r, "hosts", data)
		return
	}

	if r.Method == "POST" {
		// --- DELETE ---
		if r.FormValue("delete") == "1" {
			pattern := strings.ToLower(strings.TrimSpace(r.FormValue("pattern")))
			if pattern == "" {
				http.Error(w, "pattern required for delete", http.StatusBadRequest)
				return
			}

			if err := validateRulePattern(pattern); err != nil {
				http.Error(w, "Invalid pattern: "+err.Error(), http.StatusBadRequest)
				return
			}

			deleted := false
			func() {
				s.localHostsMu.Lock()
				defer s.localHostsMu.Unlock()
				for i, rule := range s.localHosts {
					if rule.Pattern == pattern {
						s.localHosts = append(s.localHosts[:i], s.localHosts[i+1:]...)
						deleted = true
						break
					}
				}
			}()

			if deleted {
				// --- NEW: Invalidate the cache for the deleted pattern ---
				s.invalidateCacheForPattern(pattern)

				if err := s.saveLocalHosts(); err != nil {
					s.logFatal("failed to save local hosts after deletion", err)
				}
				http.Redirect(w, r, "/hosts", http.StatusSeeOther)
				return
			}
			http.Error(w, "host not found", http.StatusNotFound)
			return
		}

		// --- ADD / EDIT ---
		pattern := strings.ToLower(strings.TrimSpace(r.FormValue("pattern")))
		oldPattern := strings.ToLower(strings.TrimSpace(r.FormValue("old_pattern")))
		isEdit := r.FormValue("edit") == "1"

		if pattern == "" {
			http.Error(w, "hostname/pattern required", http.StatusBadRequest)
			return
		}
		//okTODO: are we accepting a pattern like /rules does here? or is it just a hostname? it's pattern!

		if err := validateRulePattern(pattern); err != nil {
			http.Error(w, "Invalid pattern: "+err.Error(), http.StatusBadRequest)
			return
		}
		// old_pattern (edit path) needs the same check.
		if isEdit && oldPattern != "" {
			if err := validateRulePattern(oldPattern); err != nil {
				http.Error(w, "Invalid old_pattern: "+err.Error(), http.StatusBadRequest)
				return
			}
		}

		ipsRaw := strings.Split(r.FormValue("ips"), ",")
		var netIPs []net.IP
		for _, ipStr := range ipsRaw {
			ipStr = strings.TrimSpace(ipStr)
			if ipStr == "" {
				continue
			}
			if ip := net.ParseIP(ipStr); ip != nil {
				netIPs = append(netIPs, ip)
			} else {
				http.Error(w, "invalid IP address: "+ipStr, http.StatusBadRequest)
				return
			}
		}

		if len(netIPs) == 0 {
			http.Error(w, "at least one valid IP required", http.StatusBadRequest)
			return
		}

		var conflictErr bool
		func() {
			s.localHostsMu.Lock()
			defer s.localHostsMu.Unlock()

			if isEdit {
				// Remove the old rule if editing
				for i, rule := range s.localHosts {
					if rule.Pattern == oldPattern {
						s.localHosts = append(s.localHosts[:i], s.localHosts[i+1:]...)
						break
					}
				}
				// Remove the target pattern if we renamed to an existing one (overwrite logic)
				for i, rule := range s.localHosts {
					if rule.Pattern == pattern {
						s.localHosts = append(s.localHosts[:i], s.localHosts[i+1:]...)
						break
					}
				}
			} else {
				// Prevent duplicates on explicit 'Add'
				for _, rule := range s.localHosts {
					if rule.Pattern == pattern {
						conflictErr = true
						return
					}
				}
			}

			if !conflictErr {
				s.localHosts = append(s.localHosts, LocalHostRule{Pattern: pattern, IPs: netIPs})
			}
		}()

		if conflictErr {
			http.Error(w, "Local host with this pattern already exists", http.StatusConflict)
			return
		}

		// --- NEW: Cache Invalidation ---
		// If this was an edit, purge the old pattern's cached entries
		if isEdit && oldPattern != "" {
			s.invalidateCacheForPattern(oldPattern)
		}
		// Always purge the new pattern so the local override takes immediate effect
		// (e.g., clearing out previous NXDOMAINs or external IPs)
		s.invalidateCacheForPattern(pattern)
		// -------------------------------

		if err := s.saveLocalHosts(); err != nil {
			s.logFatal("failed to save local hosts after add/edit", err)
		}

		http.Redirect(w, r, "/hosts", http.StatusSeeOther)
	}
}

// renderTemplate is a DRY helper to execute templates safely into a buffer
// before writing to the network, preventing "established connection aborted" errors
// from being logged as template execution failures.
func (s *Server) renderTemplate(w http.ResponseWriter, r *http.Request, pageName string, data map[string]any) {
	// Inject the CSRF token into the map
	if token, ok := r.Context().Value(csrfTokenKey).(string); ok {
		data["CSRFToken"] = token
	}

	var buf bytes.Buffer
	if err := uiTemplates.Execute(&buf, data); err != nil {
		s.logger.Error("template_render_failed",
			slog.String("page", pageName),
			SafeErr(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Set content type before writing the buffer
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if _, err := buf.WriteTo(w); err != nil {
		// Log as Debug/Info because this is usually just a client (browser)
		// closing the connection or refreshing the page mid-download.
		s.logger.Debug("client_disconnected_during_ui_write",
			slog.String("page", pageName),
			SafeErr(err))
	}
}

func (s *Server) getRecentBlocksCopy() []BlockedQuery {
	blocksCopy := func() []BlockedQuery {
		s.blockMutex.Lock()
		defer s.blockMutex.Unlock()

		// // Make a copy so we don't hold the lock while template renders
		// blocksCopy := make([]BlockedQuery, len(recentBlocks))
		// copy(blocksCopy, recentBlocks)

		blocksCopy := make([]BlockedQuery, 0, s.recentBlocksList.Len())
		// Walk the linked list from newest (front) to oldest (back)
		for e := s.recentBlocksList.Front(); e != nil; e = e.Next() {
			bq := e.Value.(*BlockedQuery)
			blocksCopy = append(blocksCopy, *bq) // value copy
		}

		return blocksCopy
	}() // defer triggers before this returned
	// Check live whitelist to see if these domains are currently unblocked
	s.ruleMutex.RLock()
	defer s.ruleMutex.RUnlock()
	for i := range blocksCopy {
		b := &blocksCopy[i]
		b.IsUnblocked = false
		if rules, ok := s.whitelist[b.Type]; ok {
			for _, r := range rules { //TODO: parsing all rules to find the matching one is ugly/slow, in theory, maybe a hash set would be better ? (or keeping it in a hashset as well? if so, keep it in an ordered list too, and appends kept at top(due to UI having Add Rule be at top of page))
				if r.Pattern == b.Domain && r.Enabled {
					b.IsUnblocked = true
					break
				}
			}
		}
	}
	return blocksCopy
}

func (s *Server) blocksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		data := map[string]any{
			"Page":           "blocks",
			"Blocks":         s.getRecentBlocksCopy(),
			"SuccessMessage": r.URL.Query().Get("success"),
			"ErrorMessage":   r.URL.Query().Get("error"),
			"EnteredValue":   r.URL.Query().Get("val"),
		}

		s.renderTemplate(w, r, "blocks", data)
		return
	}
	if r.Method == "POST" {
		raw := r.FormValue("domain")

		sanitized, modified := sanitizeDomainInput(raw)

		if modified || !isValidDNSName(sanitized) { // XXX: doesn't expect a pattern via Quick Unblock here, but an actual valid DNS query domain (and without ending in a dot)
			s.logger.Warn("Invalid domain input submitted via Quick Unblock",
				slog.String("raw", raw),
				slog.String("sanitized", sanitized),
				slog.Bool("modified", modified),
			)

			// // Re-render the form containing the error message and previous input
			// data := map[string]any{
			// 	"Page": "blocks",
			// 	// Re-fetch the blocks copy so we can re-render the page correctly with data
			// 	"Blocks":       getRecentBlocksCopy(),
			// 	"ErrorMessage": "Invalid domain format. Please enter a valid domain name.",
			// 	"EnteredValue": raw, // "Go's built-in html/template library provides context-aware contextual auto-escaping. When you write {{.EnteredValue}} inside your HTML source code, Go analyzes the context (knowing it sits inside raw text or an attribute) and automatically transforms dangerous characters like <, >, &, and " into their safe HTML entity representations."
			// }

			// renderTemplate(w, "blocks", data)

			errMsg := "Invalid domain format. Please enter a valid domain name."
			redirectURL := "/blocks?error=" + url.QueryEscape(errMsg) + "&val=" + url.QueryEscape(raw)
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)

			return
		}
		domainLowercased := strings.ToLower(sanitized) //XXX: must keep it lowercased for matchPattern() later on.

		// accept sanitized
		typ := r.FormValue("type")
		action := r.FormValue("action")
		var successMessage string // Hold our feedback text
		if domainLowercased != "" && typ != "" {
			func() { // anonymous function just for scoping defer
				s.ruleMutex.Lock()
				defer s.ruleMutex.Unlock()
				if action == "reblock" {
					for i, rule := range s.whitelist[typ] {
						if rule.Pattern == domainLowercased {
							if rule.Enabled {
								s.whitelist[typ][i].Enabled = false //XXX: mutates in place
								successMessage = fmt.Sprintf("Successfully re-blocked: paused rule for %s (%s).", domainLowercased, typ)
								s.logger.Info("Quick re-block: paused existing rule",
									slog.String("domainLowercased", domainLowercased),
									slog.String("DNSType", typ))
								s.invalidateCacheForPattern(domainLowercased)
							} else {
								successMessage = fmt.Sprintf("Rule for %s (%s) is already paused.", domainLowercased, typ)
							}
							break
						}
					}
				} else { //FIXME: assuming 'block' ?!
					found := false
					for i, rule := range s.whitelist[typ] {
						if rule.Pattern == domainLowercased {
							if !rule.Enabled {
								s.whitelist[typ][i].Enabled = true //XXX: mutates in place
								successMessage = fmt.Sprintf("Successfully unblocked: activated existing paused rule for %s (%s).", domainLowercased, typ)
								s.logger.Info("Quick unblock: enabled existing paused rule",
									slog.String("domainLowercased", domainLowercased),
									slog.String("DNSType", typ))
								s.invalidateCacheForPattern(domainLowercased)
							} else {
								successMessage = fmt.Sprintf("Rule for %s (%s) is already active.", domainLowercased, typ)
								s.logger.Info("Quick unblock: ignored, rule is already active",
									slog.String("domainLowercased", domainLowercased),
									slog.String("DNSType", typ))
							}
							found = true
							break
						}
					}

					if !found {
						newRule := RuleEntry{
							ID:      s.newUniqueID(s.whitelist),
							Pattern: domainLowercased,
							Enabled: true,
						}
						// whitelist[typ] = append(whitelist[typ], newRule)

						// Replace the standard append with your safe helper function
						s.whitelist[typ] = s.withRulePrepended(s.whitelist[typ], newRule)

						successMessage = fmt.Sprintf("Successfully unblocked: added new active rule for %s (%s).", domainLowercased, typ)
						s.logger.Info("Quick unblock: added new rule(ie. didn't already exist)",
							slog.String("domainLowercased", domainLowercased),
							slog.String("DNSType", typ))
						s.invalidateCacheForPattern(domainLowercased)
					}
				}
			}() // lock released here
			if err := /*uses lock*/ s.saveQueryWhitelist(); err != nil {
				s.logFatal("failed to save whitelist after rule that was blocked was deleted from the blocks handler in webUI", err)
			}
			// // Render the page directly with our success context!
			// data := map[string]any{
			// 	"Page":           "blocks",
			// 	"Blocks":         getRecentBlocksCopy(),
			// 	"SuccessMessage": successMessage,
			// }
			// renderTemplate(w, "blocks", data)

			http.Redirect(w, r, "/blocks?success="+url.QueryEscape(successMessage), http.StatusSeeOther)
			return
		}
		////http.Redirect(w, r, "/blocks", http.StatusSeeOther)
		//// Re-render the form with an explicit payload error message showing what was passed
		payloadDetails := fmt.Sprintf("Missing or corrupted data. (Processed Domain: %q, Type: %q)", domainLowercased, typ)
		// data := map[string]any{
		// 	"Page":         "blocks",
		// 	"Blocks":       getRecentBlocksCopy(),
		// 	"ErrorMessage": "Failed to process unblock request. " + payloadDetails,
		// }

		// renderTemplate(w, "blocks", data)
		errMsg := "Failed to process unblock request. " + payloadDetails
		http.Redirect(w, r, "/blocks?error="+url.QueryEscape(errMsg), http.StatusSeeOther)

		return
	}
}

// // Helper to keep things clean
// func renderLogPage(w http.ResponseWriter, r *http.Request, title, filePath, filter string) {
//     data, err := os.ReadFile(filePath)
//     if err != nil {
//         // If file doesn't exist yet, don't crash, just show empty
//         data = []byte("")
//     }

//     lines := strings.Split(string(data), "\n")
//     var filtered []string

//     searchLower := strings.ToLower(filter)
//     for _, line := range lines {
//         if line == "" {
//             continue
//         }
//         if filter == "" || strings.Contains(strings.ToLower(line), searchLower) {
//             filtered = append(filtered, line)
//         }
//     }

//     // We reverse them so the newest logs are at the top
//     for i, j := 0, len(filtered)-1; i < j; i, j = i+1, j-1 {
//         filtered[i], filtered[j] = filtered[j], filtered[i]
//     }

//     renderData := map[string]any{
//         "Page":    "logs",
//         "Path":    r.URL.Path, // Pass current path (e.g., "/logs" or "/queries")
//         "Title":   title,
//         "Filter":  filter,
//         "Content": strings.Join(filtered, "\n"),
//     }

//     //w.Header().Set("Content-Type", "text/html; charset=utf-8")
//     //uiTemplates.Execute(w, renderData)
//     renderTemplate(w, "logs", renderData)
// }

func (s *Server) renderLogPage(w http.ResponseWriter, r *http.Request, title, filePath, filter string) {
	file, err := os.Open(filePath)
	if err != nil {
		// Fallback if file doesn't exist yet
		s.renderTemplate(w, r, "logs", map[string]any{
			"Page": "logs", "Path": r.URL.Path, "Title": title, "Filter": filter, "Content": "No log entries found.",
		})
		return
	}
	defer file.Close()

	searchLower := strings.ToLower(filter)

	// Cap the output to the last 5000 matches to save RAM and prevent browser crashes
	var maxLines = s.config.UILogMaxLines
	ring := make([]string, maxLines)
	count := 0

	// Stream the file line-by-line instead of loading it all at once
	scanner := bufio.NewScanner(file)
	// This tells the scanner:
	// 1. Start with a 64KB internal buffer.
	// 2. Allow it to grow automatically up to 1MB if it finds a very long line.
	const maxCapacity = 1024 * 1024 // 1 MB
	lineBuf := make([]byte, 2*1024) // 2 KB initial size
	scanner.Buffer(lineBuf, maxCapacity)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		if searchLower == "" || strings.Contains(strings.ToLower(line), searchLower) {
			// Overwrite the oldest entry when we exceed maxLines
			ring[count%maxLines] = line
			count++
		}
	}

	// ALWAYS check for errors after the loop.
	// If a line was too long ( > 1MB), the scanner stops here.
	if err := scanner.Err(); err != nil {
		if err == bufio.ErrTooLong {
			s.logger.Error("A log line exceeded the bytes-per-line limit", slog.Int("line_limit_bytes", maxCapacity), slog.Int("line_number", count), slog.String("filename", filePath))
		}
	}

	// Extract the lines from the ring buffer in chronological order
	var filtered []string
	start := 0
	limit := count
	if count > maxLines {
		start = count % maxLines
		limit = maxLines
	}

	for i := 0; i < limit; i++ {
		filtered = append(filtered, ring[(start+i)%maxLines])
	}

	// Reverse so the newest lines are at the top
	for i, j := 0, len(filtered)-1; i < j; i, j = i+1, j-1 {
		filtered[i], filtered[j] = filtered[j], filtered[i]
	}

	var content string
	if err := scanner.Err(); err != nil {
		content = fmt.Sprintf("Error reading log: %v\n\n", err) + strings.Join(filtered, "\n")
	} else {
		content = strings.Join(filtered, "\n")
		// Add a helpful warning if we truncated the results
		if count > maxLines {
			content = fmt.Sprintf("... showing only the last %d out of %d matches to reduce RAM usage ...\n\n", maxLines, count) + content
		}
	}

	renderData := map[string]any{
		"Page":    "logs",
		"Path":    r.URL.Path,
		"Title":   title,
		"Filter":  filter,
		"Content": content,
	}

	s.renderTemplate(w, r, "logs", renderData)
}

func (s *Server) logsQueriesHandler(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("q")
	//no:// If they used the old 'domain' param, support it as a fallback
	// if filter == "" {
	//     filter = r.URL.Query().Get("domain")
	// }

	s.renderLogPage(w, r, "Query Logs", s.config.LogQueriesFile, filter)
}

func (s *Server) logsHandler(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("q")
	s.renderLogPage(w, r, "System & Error Logs", s.config.LogErrorsFile, filter)
}

func (s *Server) shutdown(exitCode int) {
	s.shutdownOnce.Do(func() { //guarantees that the code inside the function runs exactly once.
		s.logger.Info("Shutting down...")
		// 1. Cancel the context immediately so all other listeners stop
		s.cancel() //Calling cancel() multiple times is perfectly safe and is actually the expected behavior in Go. In case anything else just called cancel() itself (should be currently happening)
		s.logger.Debug("Context cancelled... this triggers DoH and webUI shutdowns in their own goroutines!")

		if s.cacheStore != nil {
			s.flushCache()
		}
		//doneTODO: webUI shutdown (done via cancel() above)
		//s.logger.Debug("webUI shutdown(fake)")
		//sleep 1 sec to allow "quitting on shutdown" message to show.
		// Wait 1 sec to allow graceful HTTP shutdowns and the "quitting" messages to show
		//time.Sleep(1000 * time.Millisecond)
		// ADD: Wait for all registered goroutines to signal they've exited
		s.logger.Debug("Waiting for goroutines to finish...")
		s.shutdownWG.Wait()
		s.logger.Debug("All goroutines exited.")
		//s.logger.Debug("waited 1 sec for port cleanup")

		// UnstickStdinRead(s.logger)
		// if !wincoe.WaitAnyKeyIfInteractive() {
		// 	s.logger.Debug("Didn't wait for keypress due to not an interactive/terminal.")
		// }
		// //bufio.NewReader(os.Stdin).ReadBytes('\n') //done: make it for any key not just Enter!
		// s.logger.Info("exitting with exit code", slog.Int("exitCode", exitCode))
		// os.Exit(exitCode)
		finalShutdownSequence(s.logger, exitCode)
		panic("BUG: shoulda been unreachable after finalShutdownSequence, which means it didn't os.Exit!")
	})
	panic("BUG: shoulda been unreachable after s.shutdownOnce.Do")
}

func finalShutdownSequence(logger *slog.Logger, exitCode int) {
	UnstickStdinRead(logger)
	if !wincoe.WaitAnyKeyIfInteractive() {
		logger.Debug("Didn't wait for keypress due to not an interactive/terminal.")
	}
	//bufio.NewReader(os.Stdin).ReadBytes('\n') //done: make it for any key not just Enter!
	logger.Info("exitting with exit code", slog.Int("exitCode", exitCode))
	os.Exit(exitCode)
}

// Add a global channel for fatal errors to trigger shutdown
var signalTheUnstick = make(chan struct{}, 1)
var isStdinReading atomic.Bool // needed so we know if to inject an Enter key or not, to unstuck it

// UnstickStdinRead is basically to avoid having to press a key twice when prompted to press a key to exit! due to reading for a key from two concurrent goroutines!
func UnstickStdinRead(logger *slog.Logger) {
	// Signal the channel safely
	select {
	case signalTheUnstick <- struct{}{}:
		//this is entered here only because the channel is buffered (size 1) and thus will send
		//s.logger.Debug("sent1")
	default:
		// Already shutting down
	}
	//s.logger.Debug("cont2")
	// Wake up watchKeys goroutine by injecting an Enter key event
	// into the console buffer. It will unblock Stdin.Read, see
	// abortedByUser is true, restore terminal state, and exit safely.
	if isStdinReading.Load() {
		logger.Debug("watchKeys is blocked in Stdin.Read; injecting console Enter")
		if err := wincoe.InjectConsoleEnter(); err != nil {
			//injecting a key here will cause the os.Stdin.Read(buf) below(in watchKeys) to exit
			logger.Warn("Signal injection failed. User must press a key one more time when prompted to exit.")
		}
	} else {
		logger.Debug("watchKeys is not in Stdin.Read; skipping console injection")
	}
}

func (s *Server) watchKeys(reloadFn func(), cleanExitFn func()) {
	fd := int(os.Stdin.Fd())

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return
	}
	// This defer is critical! It ensures the terminal exits RAW mode
	// when the goroutine finishes, preventing a corrupted command prompt.
	defer term.Restore(fd, oldState)

	buf := make([]byte, 3)

	for {
		// 1. Check if an external fatal error triggered a shutdown
		select {
		case <-signalTheUnstick:
			//XXX: this is to avoid waiting for an extra keypress when prompted to press a key to exit
			//s.logger.Debug("1 watchKeys exiting due to external fatal error")
			return
		default:
			// Continue to read
		}

		// 1. Mark that we are entering the blocking OS call
		isStdinReading.Store(true)
		n, err := os.Stdin.Read(buf)
		isStdinReading.Store(false) // 2. Mark that we came out (due to a key, Ctrl+C, or error)

		if err != nil || n == 0 {
			fmt.Print("?")
			continue
		}
		// 2. Check AGAIN immediately after waking up
		select {
		case <-signalTheUnstick:
			//XXX: this is to avoid waiting for an extra keypress when prompted to press a key to exit
			//s.logger.Debug("2 watchKeys woke up and saw external fatal error")
			return
		default:
		}
		fmt.Print(".") //noTODO: delete this? then the next 6 \n Print(s) as well

		// Ctrl+X (0x18)
		if buf[0] == 0x18 {
			fmt.Print("\n")
			s.logger.Info("Ctrl+X detected → clean exit")
			_ = term.Restore(fd, oldState)
			cleanExitFn()
		}

		// Ctrl+R (0x12)
		if buf[0] == 0x12 {
			fmt.Print("\n")
			s.logger.Info("Ctrl+R detected → reloading config")
			//_ = term.Restore(fd, oldState)
			// NO restore needed here because we want to stay in Raw mode
			// to catch the next keypress after the reload.
			reloadFn()
		}

		// Ctrl+C (0x03) or else can't break the program except with Ctrl+Break !
		if buf[0] == 0x03 {
			fmt.Print("\n")
			s.logger.Info("Ctrl+C detected → breaking gracefully")
			_ = term.Restore(fd, oldState)
			cleanExitFn()
		}

		// Alt+X / Alt+R → ESC + key
		if buf[0] == 0x1b && n >= 2 {
			switch buf[1] {
			case 'x', 'X':
				fmt.Print("\n")
				s.logger.Info("Alt+X detected → clean exit")
				_ = term.Restore(fd, oldState)
				cleanExitFn()
			case 'r', 'R':
				fmt.Print("\n")
				s.logger.Info("Alt+R detected → reloading config")
				//_ = term.Restore(fd, oldState)
				reloadFn()
			}
		}

		// Re-ensure raw mode if anything temporarily reset it
		_, err = term.MakeRaw(fd)
		if err != nil {
			fmt.Print("\n")
			s.logger.Error("Failed to make the terminal raw", SafeErr(err))
			return
		}
	}
}

func promptAndHashPassword(logger *slog.Logger) (string, error) {
	fd := int(os.Stdin.Fd())

	// 1. Create a channel to catch the Ctrl+C signal
	// keeping this abortChan separate from sigChan for some reason: "it is much safer and cleaner to keep them separate" - Geminig 3.5 Flash
	abortChan := make(chan os.Signal, 1)
	// Tell Go to stop routing signals to this channel when the function returns
	defer signal.Stop(abortChan)
	signal.Notify(abortChan, os.Interrupt, syscall.SIGTERM)

	// 2. Create a lifetime channel to clean up our goroutine if the user completes the prompt normally
	done := make(chan struct{})
	defer close(done)

	var abortedByUser atomic.Bool
	var injectionFailed atomic.Bool

	// 3. Spin up a background thread to watch for the abort signal
	go func() {
		select {
		case <-abortChan:
			fmt.Println()
			abortedByUser.Store(true)
			// If Ctrl+C is pressed, this case fires instantly
			logger.Debug("[Aborted] Password setup cancelled by user.")
			//shutdown(1)
			// Synthesize a dummy key event record (Carriage Return / Enter)

			// If Windows API fails or didn't write anything, flag it
			// Inject a dummy enter key to wake up the main thread
			if err := wincoe.InjectConsoleEnter(); err != nil {
				injectionFailed.Store(true)
			}
			return
		case <-done:
			// If the user types their password successfully, this case fires to exit cleanly
			return
		}
	}()

	logger.Debug("Prompting user to set a new password, on console")
	fmt.Print("Enter new WebUI password (or Ctrl+C to abort): ")
	pwd1, err := term.ReadPassword(fd)
	if abortedByUser.Load() {
		if injectionFailed.Load() {
			fmt.Println("(Note: Signal injection failed. You will need to press an extra key to clear the terminal prompt buffer.)")
		}
		return "", errors.New("action cancelled by user")
	}
	fmt.Println()
	if err != nil {
		return "", err
	}
	if len(pwd1) == 0 {
		return "", errors.New("password cannot be empty")
	}

	fmt.Print("Re-enter password to confirm: ")
	pwd2, err := term.ReadPassword(fd)
	if abortedByUser.Load() {
		if injectionFailed.Load() {
			fmt.Println("(Note: Signal injection failed. You will need to press an extra key to clear the terminal prompt buffer.)")
		}
		return "", errors.New("action cancelled by user")
	}
	fmt.Println()
	if err != nil {
		return "", err
	}

	if string(pwd1) != string(pwd2) {
		return "", fmt.Errorf("passwords do not match, len1:%d vs len2:%d", len(pwd1), len(pwd2))
	}

	// DefaultCost is 10, which is perfectly balanced for modern hardware
	hash, err := bcrypt.GenerateFromPassword(pwd1, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Safety fallback: if somehow the hash is still blank, DON'T allow access
		if s.config.WebUIPasswordHash == "" {
			panic("no webUI password was set, this shouldn't be possible, dev fail?")
			//next.ServeHTTP(w, r)
			//return
		}

		// Extract the Basic Auth credentials provided by the browser
		username, pass, ok := r.BasicAuth()
		if username != "" {
			s.logger.Warn("Username ignored.", slog.String("username", username))
		}

		// Compare the provided password against our stored bcrypt hash.
		// If headers are missing (!ok) or the password is wrong (err != nil), block them.
		if !ok || bcrypt.CompareHashAndPassword([]byte(s.config.WebUIPasswordHash), []byte(pass)) != nil {
			// This header triggers the browser's native login modal
			w.Header().Set("WWW-Authenticate", `Basic realm="dnsbollocks webUI aka Management Interface aka Control Panel"`)
			http.Error(w, "401 Unauthorized - WebUI Access Restricted", http.StatusUnauthorized)
			return
		}

		// Password is correct, let the request pass through to the target handler
		next.ServeHTTP(w, r)
	})
}
