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
	"maps"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"sync/atomic"
	"unsafe"

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
	"golang.org/x/net/http2"
	"golang.org/x/sys/windows"
	"golang.org/x/term"
	"golang.org/x/time/rate"

	"flag"
	"golang.org/x/crypto/bcrypt"

	"runtime/debug"
)

// Config holds the JSON configuration.
type Config struct {
	ListenDNS               string   `json:"listen_dns"    desc:"IP:port for the plain DNS (UDP and TCP) listener. Must be an IP literal, never a hostname."`
	ListenDoH               string   `json:"listen_doh"    desc:"IP:port for the local DNS-over-HTTPS (DoH) listener. Must be an IP literal. A TLS certificate is auto-generated for this IP."`
	ListenUI                string   `json:"listen_ui"     desc:"IP:port for the web admin UI. Must be an IP literal. TLS is auto-enabled for non-loopback addresses when webui_force_tls_on_non_localhost is true."`
	TLSCertFile             string   `json:"tls_cert_file" desc:"Path to the TLS certificate file (PEM format) used for local DoH and WebUI. Auto-generated as self-signed, if not on-disk."`
	TLSKeyFile              string   `json:"tls_key_file"  desc:"Path to the TLS private key file (PEM format) used for local DoH and WebUI. Auto-generated as self-signed, if not on-disk."`
	UpstreamURLs            []string `json:"upstream_urls" desc:"HTTPS URLs of upstream DoH resolvers (e.g. https://9.9.9.9/dns-query). Must use IP literals. Order determines failover priority. If you use the template '{builtin:clientexe}'(without the single quotes, doh) it will be replaced with the querying executable name (useful for NextDNS URLs)"`
	UpstreamSNIHostnames    []string `json:"upstream_sni_hostnames" desc:"TLS SNI hostnames corresponding to each upstream_urls entry (e.g. dns.quad9.net). Falls back to the URL host if omitted or shorter than upstream_urls."`
	UpstreamSelectionMode   string   `json:"upstream_selection_mode"    desc:"Strategy for querying upstreams: 'failover' (sticky, auto-heals), 'fastest' (race all, first valid wins), 'strict' (all must agree or query is dropped)."`
	UpstreamRetriesPerQuery int      `json:"upstream_retries_per_query" desc:"Additional retry attempts after the first try fails (0 = no retries; total tries = 1 + this value)."`
	BlockMode               string   `json:"block_mode"  desc:"Action for blocked queries: 'nxdomain' (return NXDOMAIN), 'ip_block' (return block_ip/block_ipv6 addresses), 'drop' (send no reply)."`
	//FIXME: probably can't but "block_mode" from above is hardcoded in the desc of the below two:
	BlockIP   string `json:"block_ip"    desc:"IPv4 address returned for blocked A queries when block_mode is 'ip_block' (typically 0.0.0.0)."`
	BlockIPv6 string `json:"block_ipv6"  desc:"IPv6 address returned for blocked AAAA queries when block_mode is 'ip_block' (typically ::)."`

	// Pre-parsed IPs for blazing fast performance and thread-safety
	BlockIPv4Parsed net.IP `json:"-"` // this isn't persisted to disk
	// Use net.IP directly; miekg/dns reads it safely
	BlockIPv6Parsed net.IP `json:"-"` // this isn't persisted to disk
	/*In Go, the json:"-" struct tag explicitly tells the standard library's json.Marshal and json.Unmarshal functions to completely ignore those fields.
	  When saving (json.Marshal): The encoder bypasses those fields entirely. They won't be included in the generated JSON string/file.
	  When loading (json.Unmarshal): The decoder skips right past them. Even if someone manually typed a "BlockIPv4Parsed" key into the JSON file, Go would ignore it and wouldn't modify the struct field.
	*/
	UpstreamURLsParsed []*url.URL `json:"-"` // Added: Keeps triplets grouped together
	UpstreamIPs        []string   `json:"-"` // Added: Keeps triplets grouped together
	UpstreamSNIs       []string   `json:"-"` // Added: Keeps triplets grouped together

	GlobalRateQPS           int    `json:"qps_rate_globally"    desc:"Maximum DNS queries per second across all clients combined (token-bucket sustained rate)."`
	GlobalBurstQPS          int    `json:"qps_burst_globally"   desc:"Maximum burst of DNS queries allowed globally above the sustained qps_rate_globally limit."`
	ClientRateQPS           int    `json:"qps_rate_per_client"  desc:"Maximum DNS queries per second allowed from a single client IP."`
	ClientBurstQPS          int    `json:"qps_burst_per_client" desc:"Maximum burst of DNS queries allowed from a single client IP above qps_rate_per_client."`
	CacheMinTTL             int    `json:"cache_min_ttl"        desc:"Minimum TTL (seconds) for any cached DNS response, overriding lower upstream TTLs. Hard floor is 10s."`
	CacheMaxEntries         int    `json:"cache_max_entries"    desc:"Maximum DNS cache entries. New entries are silently dropped when the limit is reached until expired entries are evicted."`
	WhitelistFile           string `json:"whitelist_file"       desc:"Path (relative to config.json) to the query-whitelist JSON file. Created automatically with an empty whitelist if absent."`
	BlacklistFile           string `json:"blacklist_file"       desc:"Path (relative to config.json) to the response-IP blacklist JSON file. Created automatically with safe defaults if absent."`
	HostsFile               string `json:"hosts_file"           desc:"Path (relative to config.json) to the local host-override JSON file. A domain must also match a whitelist rule before these overrides apply."`
	LogQueriesFile          string `json:"log_queries" desc:"Path to the DNS query-only log file (JSON lines). Created automatically."`
	LogEverythingFile       string `json:"log_file"    desc:"Path to the full system log file (JSON lines, all levels including debug). Created automatically."`
	ConsoleLogLevel         string `json:"console_log_level" desc:"Minimum log level printed to the console: 'debug', 'info', 'warn', or 'error'. File logs always receive all levels."`
	LogMaxSizeMB            int    `json:"log_max_size_mb"   desc:"Maximum log file size in megabytes before rotation. Rotated files are renamed with a sequential numeric suffix (.1, .2, ...)."`
	AllowRunAsAdmin         bool   `json:"allow_run_as_admin" desc:"If false (default), the process exits immediately when running with Windows administrator privileges as a safety guardrail."`
	BlockAAAAasEmptyNoError bool   `json:"block_aaaa_as_empty_noerror" desc:"Return NOERROR with an empty answer for blocked AAAA queries instead of NXDOMAIN, preventing Windows from caching the domain as non-existent and breaking IPv4 fallback (e.g. ssh to github.com)."`
	AllowHTTPSIfAAllowed    bool   `json:"allow_https_if_a_allowed"  desc:"If true, an HTTPS-type DNS query is automatically allowed whenever an A-type whitelist rule permits the same domain, without needing a separate HTTPS rule."`
	RemoveHTTPSIPv4Hints    bool   `json:"remove_https_ipv4_hints"   desc:"Strip ipv4hint and ipv6hint parameters from HTTPS DNS records in upstream responses, forcing clients to resolve IPs via A/AAAA queries instead of using embedded hints."`
	UseEDEInBlockedReply    bool   `json:"use_ede_in_blocked_reply"  desc:"Attach an EDNS0 Extended DNS Error (EDE) record to blocked responses so clients and diagnostic tools can see a human-readable reason for the block."`

	WebUIPasswordHash           string `json:"webui_password_hash"               desc:"Bcrypt hash of the web admin UI password. Set via --hash-password flag or the WebUI config page. Never store a plaintext password here."`
	WebUIPasswordBcryptCost     int    `json:"webui_password_bcrypt_cost"        desc:"Bcrypt cost factor used when hashing new passwords (minimum enforced: 12). Higher values are slower but more resistant to brute-force."`
	WebUIUseTLS                 bool   `json:"webui_use_tls"                     desc:"Serve the web admin UI over HTTPS using the auto-generated self-signed certificate. Strongly recommended for any non-loopback address."`
	WebUIForceTLSOnNonLocalhost bool   `json:"webui_force_tls_on_non_localhost"  desc:"Automatically promote webui_use_tls to true when listen_ui is bound to a non-loopback address, preventing the password from being transmitted as plaintext."`
	WebUIMaxLoginFailures       int    `json:"webui_max_login_failures"          desc:"Number of consecutive failed WebUI login attempts from a single IP before that IP is locked out."`
	WebUILoginLockoutSec        int    `json:"webui_login_lockout_sec"           desc:"Duration in seconds a client IP remains locked out after exceeding webui_max_login_failures."`
	WebUIReadHeaderTimeoutSec   int    `json:"webui_read_header_timeout_sec"     desc:"Seconds the WebUI HTTP server waits for a client to send request headers before closing the connection (Slowloris defence)."`
	WebUIReadTimeoutSec         int    `json:"webui_read_timeout_sec"            desc:"Seconds the WebUI HTTP server waits for a complete request body."`
	WebUIWriteTimeoutSec        int    `json:"webui_write_timeout_sec"           desc:"Seconds the WebUI HTTP server waits while writing the HTTP response to a client."`
	WebUIIdleTimeoutSec         int    `json:"webui_idle_timeout_sec"            desc:"Seconds the WebUI HTTP server keeps an idle keep-alive connection open. Auto-clamped to at least 2x webui_read_timeout_sec."`

	MaxConcurrentDNSTCPConns   int `json:"max_concurrent_dns_tcp_conns"    desc:"Maximum simultaneous DNS-over-TCP connections. Connections beyond this limit are rejected immediately to bound memory and goroutine count."`
	MaxConcurrentDNSUDPQueries int `json:"max_concurrent_dns_udp_queries"  desc:"Maximum DNS-over-UDP packets being processed concurrently. Excess packets are dropped rather than queued."`

	ClientTCPTimeoutSec          int `json:"client_tcp_timeout_sec" desc:"Per-operation timeout (seconds) for plain DNS TCP connections: reading the 2-byte length header, reading the body, and writing the response each receive this budget independently."`
	MaxRecentBlocks              int `json:"max_recent_blocks"      desc:"Maximum number of recently blocked domains tracked for the WebUI Blocks page (LRU eviction when full)."`
	LocalDoHReadHeaderTimeoutSec int `json:"local_doh_read_header_timeout_sec" desc:"Seconds the local DoH HTTPS listener waits for a client to send HTTP request headers."`
	LocalDoHReadTimeoutSec       int `json:"local_doh_read_timeout_sec"        desc:"Seconds the local DoH HTTPS listener waits for a complete HTTP request body."`
	LocalDoHWriteTimeoutSec      int `json:"local_doh_write_timeout_sec"       desc:"Seconds the local DoH HTTPS listener waits while writing the HTTP response."`
	LocalDoHIdleTimeoutSec       int `json:"local_doh_idle_timeout_sec"        desc:"Seconds the local DoH HTTPS listener keeps an idle keep-alive connection open. Auto-clamped to at least 2x local_doh_read_timeout_sec."`

	CertLogTimeoutSec        int `json:"cert_log_timeout_sec"          desc:"Timeout (seconds) for the diagnostic TLS probe that logs certificate chain details when an upstream TLS handshake fails."`
	UpstreamDialTimeoutSec   int `json:"upstream_dial_timeout_sec"     desc:"Timeout (seconds) for establishing a new TCP connection to an upstream DoH server."`
	UpstreamClientTimeoutSec int `json:"upstream_client_timeout_sec"   desc:"Overall timeout (seconds) for a single upstream DoH HTTP request including dial, headers, and body. Must be >= upstream_dial_timeout_sec."`
	UpstreamRetryBackoffMs   int `json:"upstream_retry_backoff_ms"     desc:"Milliseconds to wait between retry attempts to an upstream DoH server after a transient network failure."`

	UpstreamTCPKeepAliveSec      int `json:"upstream_tcp_keepalive_sec" desc:"Interval (seconds) for OS-level TCP Keep-Alive probes to detect dead upstream connections."`
	UpstreamH2ReadIdleTimeoutSec int `json:"upstream_h2_read_idle_timeout_sec" desc:"Time (seconds) an HTTP/2 connection must be idle before sending a health-check PING. Must be less than upstream_idle_conn_timeout_sec."`
	UpstreamH2PingTimeoutSec     int `json:"upstream_h2_ping_timeout_sec" desc:"Timeout (seconds) waiting for an HTTP/2 PING response before closing the zombie connection. Must be less than upstream_h2_read_idle_timeout_sec."`

	ServerGracefulShutdownSec int `json:"server_graceful_shutdown_sec" desc:"Time (seconds) to wait for active HTTP/DoH connections to finish during a reload or shutdown before forcefully severing them."`

	UpstreamIdleConnTimeoutSec  int `json:"upstream_idle_conn_timeout_sec"   desc:"Seconds to keep an idle upstream HTTP connection in the pool before closing it."`
	UpstreamMaxIdleConns        int `json:"upstream_max_idle_conns"          desc:"Global maximum idle upstream HTTP connections kept in the pool across all upstream hosts combined."`
	UpstreamMaxIdleConnsPerHost int `json:"upstream_max_idle_conns_per_host" desc:"Maximum idle upstream HTTP connections per upstream host. Auto-clamped to not exceed upstream_max_idle_conns."`

	DoHMaxRequestBodyBytes int `json:"doh_max_request_body_bytes" desc:"Maximum bytes accepted in an incoming DoH request body, guarding against memory exhaustion from oversized payloads."`
	DNSUDPBufferSize       int `json:"dns_udp_buffer_size"        desc:"Per-packet receive buffer size in bytes for UDP DNS (512–65535). 4096 safely handles modern EDNS0 payloads."`

	CacheJanitorIntervalMinutes int `json:"cachejanitor_interval_minutes" desc:"Interval in minutes at which the DNS cache background janitor sweeps for and removes expired entries."`
	CacheNegativeTTLSec         int `json:"cache_negative_ttl_sec" desc:"Seconds to cache SERVFAIL and other negative upstream responses, reducing retry storms during upstream outages."`

	FileWriterMaxRetries     int `json:"file_writer_max_retries" desc:"Maximum number of retries for atomic file writes. (Default: 6)"`
	FileWriterRetryBackoffMs int `json:"file_writer_retry_backoff_ms" desc:"Delay in milliseconds between file write retries. (Default: 100)"`

	BlockedResponseTTLSec    uint32 `json:"blocked_response_ttl_sec"       desc:"TTL (seconds) embedded in DNS records returned for blocked queries, controlling how long clients cache the block response."`
	LocalHostsOverrideTTLSec uint32 `json:"localhosts_override_ttl_sec" desc:"TTL (seconds) embedded in DNS records synthesised from the local host-override file (hosts2ip.json)."`

	UILogMaxLines int `json:"ui_log_max_lines" desc:"Maximum log lines shown per page in the WebUI log viewer. Older lines are omitted to prevent excessive RAM usage and browser freezes."`

	ExtraSafety bool `json:"extra_safety" desc:"Enable extra defensive checks: duplicate-entry detection in JSON files, power-loss staging files for atomic writes, and strict purging of malformed or duplicate rules on load. Recommended for production."`
}

// Server encapsulates all the state required to run the DNSbollocks application.
type Server struct {
	liveConfig    atomic.Pointer[Config] // resolved (runtime use) // shared with AdminUI, fileWriter, etc.
	liveRawConfig atomic.Pointer[Config] //tokens preserved (disk use) like "{file:id.key}" is preserved not resolved like liveConfig has it.
	//liveLogger    atomic.Pointer[slog.Logger] // shared with AdminUI, fileWriter, etc.
	logMgr *LoggerManager // owns liveLogger + log file handles

	// Upstream state
	upstreamMgr  *UpstreamManager
	dohForwarder DoHForwarder // used by handleDNSQuery — injectable in tests

	// Caching & Rate limiting
	// dnsCache    DNSCache
	// rateLimiter *ClientRateLimiter
	liveDNSCache atomic.Pointer[DNSCache]
	rateLimiter  *ClientRateLimiter

	// Data stores (each owns its own mutex).
	ruleStore    *RuleStore
	hostStore    *HostStore
	blacklist    *BlacklistStore
	recentBlocks *RecentBlocksTracker

	// fileWriteMu serialises all file-write calls across all stores.
	fileWriter wincoe.FileWriter
	//fileWriteMu sync.Mutex

	//dnsTCPSem chan struct{} // nil until startDNSListener; capacity = MaxConcurrentDNSTCPConns
	dnsTCPSem atomic.Pointer[chan struct{}]
	dnsUDPSem atomic.Pointer[chan struct{}]

	dnsListener atomic.Pointer[dnsListenerInstance]
	dohListener atomic.Pointer[dohListenerInstance] // Changed type
	uiListener  atomic.Pointer[uiListenerInstance]  // Changed type

	adminUI *AdminUI

	dohCert        tls.Certificate // used by DoH listener AND WebUI TLS
	certGeneration atomic.Uint64

	// Simple stats, FIXME.
	stats *expvar.Int

	// Lifecycle & Concurrency
	ctx          context.Context //the old backgroundCtx
	cancel       context.CancelFunc
	errChan      chan error
	shutdownWG   sync.WaitGroup
	shutdownOnce sync.Once

	reloadInProgress atomic.Bool

	reloadMu      sync.RWMutex
	onReloadHooks []func() // Subsystem actions to run on Ctrl+R / operator reloads

	exitFn func(int) // set to os.Exit by default; override in tests
}

// AdminUI handles all the web control panel routes.
type AdminUI struct {
	// logger       *slog.Logger
	// config       Config // Pass by value so UI can read it safely
	liveConfig    *atomic.Pointer[Config]
	liveRawConfig *atomic.Pointer[Config]
	liveLogger    *atomic.Pointer[slog.Logger]

	ruleStore    *RuleStore
	hostStore    *HostStore
	blacklist    *BlacklistStore
	loginTracker *LoginTracker
	recentBlocks *RecentBlocksTracker
	stats        *expvar.Int

	uiTemplates *template.Template

	// Callbacks for side-effects
	OnSaveWhitelist       func() error
	OnSaveBlacklist       func() error
	OnSaveHosts           func() error
	OnInvalidatePattern   func(pattern string)
	OnInvalidateBlacklist func()
	OnApplyConfig         func(cfg *Config) error

	//UI calls this when a fatal exception or manual admin shutdown occurs
	OnShutdown func(exitCode int)
	//getExpectedHost func() string // used by hostValidation
}

// pointer to live logger or default logger if uninited(bug)
func (s *Server) getLogger() *slog.Logger {
	if s.logMgr != nil {
		return s.logMgr.Get()
	}
	log := slog.Default()
	log.Error("BUG: Server.liveLogger wasn't inited, using default.")
	return log
}

// pointer to live Server.Config
func (s *Server) getConfig() *Config {
	c := s.liveConfig.Load()
	if c == nil {
		panic2("BUG: Server.liveConfig not initialized before use — NewServer must call liveConfig.Store()")
	}
	return c
}

// On init and every reload, swap atomically:
func (s *Server) applyConfig(cfg Config, rawCfg Config) {
	s.liveRawConfig.Store(&rawCfg)
	s.liveConfig.Store(&cfg)
	// fileWriter, AdminUI, etc. pick it up on their next read — nothing to call
}

// On init and every reload, swap atomically:
func (s *Server) applyLogger(l *slog.Logger) {
	s.logMgr.Set(l)
	// same — fileWriter reads liveLogger.Load() instead of holding its own copy
	bugLogger.Store(l) // keep free-function fallback logger in sync too
	wincoe.Logger = l  //and wincoe lib logger too
}

// bugLogger is a package-level fallback logger used only by free functions
// (not methods on Server/AdminUI) that need to log a BUG-class invariant
// violation immediately before panicking, but have no logger threaded to them.
// Kept in sync with the active logger via applyLogger. Falls back to
// slog.Default() before logging is initialized (mirrors Server.getLogger()'s
// own fallback behavior).
var bugLogger atomic.Pointer[slog.Logger]

func getBugLogger() *slog.Logger {
	if l := bugLogger.Load(); l != nil {
		return l
	}
	//def := slog.Default()
	def := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	wincoe.Logger = def //give wincoe lib a logger too
	return def
}

// NewServer initializes a new Server instance using pre-validated configurations.
func NewServer(logger *slog.Logger, resolvedCfg, rawCfg *Config) *Server {
	//func NewServer(logger *slog.Logger) *Server {
	s := &Server{
		ruleStore:    newRuleStore(),
		hostStore:    newHostStore(),
		blacklist:    newBlacklistStore(),
		recentBlocks: newRecentBlocksTracker(),
		//dnsTCPSem is set by startDNSListener after the config is loaded, not here.
		errChan: make(chan error, 10), // We use a buffer of (e.g.) 10 so multiple services failing at once won't block
		stats:   expvar.NewInt("blocks"),
		exitFn:  os.Exit,
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())

	s.logMgr = NewLoggerManager(logger) //TODO: this should happen in OldMain()
	s.applyLogger(logger)               // syncs bugLogger + wincoe.Logger

	//s.applyConfig(defaultConfig())
	//cfg := s.getConfig() //this is defaults here, btw!

	// Apply the true configuration immediately

	s.applyConfig(*resolvedCfg, *rawCfg)

	// fileWriter is now initialized flawlessly with the actual configuration settings!
	s.fileWriter = wincoe.NewWin11SafeFileWriter(
		/*so these 3 from cfg. have actually the default value for themselves because at this point, the server itself didn't even read the config yet! FIXME: must decouple config greading with NewServer starting also this means the s.shutdown(exitCode) too! */
		resolvedCfg.ExtraSafety,              //this is overwriten at loadMainConfig time which happens at Run() and at Ctrl+R aka reload.
		resolvedCfg.FileWriterMaxRetries,     //doneTODO: ^
		resolvedCfg.FileWriterRetryBackoffMs, //doneTODO: ^

		s.logMgr.Ptr())

	//s.failoverSelect = NewFailoverSelector(&s.liveLogger)
	// failoverSelect now lives inside UpstreamManager
	s.upstreamMgr = NewUpstreamManager(s.ctx, &s.liveConfig, s.logMgr.Ptr(), s.shutdown)
	s.dohForwarder = s.upstreamMgr

	return s // yes it escapes to heap
}

type FailoverSelector struct {
	liveLogger     *atomic.Pointer[slog.Logger]
	mu             sync.RWMutex
	activeIndex    int
	inFlightProbes sync.Map
	allFailed      bool // Tracks if the system is coming out of a total blackout
}

// NewFailoverSelector initializes the tracker starting at the first upstream (index 0)
func NewFailoverSelector(liveLogger *atomic.Pointer[slog.Logger]) *FailoverSelector {
	if liveLogger == nil {
		panic2("BUG: passed nil atomic pointer to logger but code assumes this is never nil, logger can be nil tho")
	}
	return &FailoverSelector{liveLogger: liveLogger, activeIndex: 0, allFailed: false}
}

// Upstream represents a single configured DoH target and handles its own network lifecycle.
type Upstream struct {
	// Client talks to the upstream
	Client *http.Client
	URL    *url.URL
	SNI    string
	//logger            *slog.Logger
	liveLogger                    *atomic.Pointer[slog.Logger]
	Retries                       int //RetriesPerQuery, so after first try, if fails, how many more to retry
	RetryBackoffDuration          time.Duration
	UpstreamClientTimeoutDuration time.Duration
	BackgroundCtx                 context.Context
	CertLogTimeoutSec             int
}

// pointer to live logger or default logger if uninited(bug)
func (u *Upstream) getLogger() *slog.Logger {
	if l := u.liveLogger.Load(); l != nil {
		return l
	}
	log := slog.Default()
	log.Error("BUG: Upstream.liveLogger wasn't inited, using default.")
	return log
}

// pointer to live logger or default logger if uninited(bug)
func (fs *FailoverSelector) getLogger() *slog.Logger {
	if l := fs.liveLogger.Load(); l != nil {
		return l
	}
	log := slog.Default()
	log.Error("BUG: FailoverSelector.liveLogger wasn't inited, using default.")
	return log
}

func (fs *FailoverSelector) Exchange(ctx context.Context, upstreams []Upstream, reqBytes []byte) (*dns.Msg, string, []string, error) {
	log := fs.getLogger()

	if len(upstreams) == 0 {
		return nil, "", nil, errors.New("no upstreams available")
	}

	// --- FIX: Create a local context to cancel orphaned parallel requests ---
	exchangeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// ------------------------------------------------------------------------

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
			// --- FIX: Pass exchangeCtx instead of ctx ---
			//By doing this, the moment your return res.resp, upstreams[res.index].URL.String(), failedUpstreams, nil executes, the defer cancel() is triggered. doSingleDoHRequest respects context cancellation under the hood (via http.NewRequestWithContext), so any active HTTP dials or reads being performed by the slower upstreams are instantly aborted, immediately returning the resources to your system.
			resp, err := target.doSingleDoHRequest(exchangeCtx, reqBytes) //target.Client, target.URL, target.SNI, reqBytes)

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
					log.Warn("💚 Global blackout resolved; upstreams are responding again",
						slog.String("url", target.URL.String()),
						slog.String("sni", target.SNI),
						slog.Int("index", idx),
					)
				} else if healed {
					log.Warn("⚙️ Primary upstream recovered; promoting back to active status",
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

	// Wait only until we get a definitive answer for the "real" query
	// (index == currentIdx), or any success arrives first (which can come
	// from a healing probe winning the race). We deliberately do NOT wait
	// for slower/hung probe goroutines to finish: a probe is purely
	// opportunistic healing and must never delay the critical fallback
	// path. Abandoned probe goroutines still run to completion in the
	// background — resChan is sized to numParallel so their sends never
	// block — and still apply their healing side-effect (fs.activeIndex
	// update) even though Exchange has stopped listening for their result.
	receivedResults := 0
	currentIdxAnswered := false
	for receivedResults < numParallel && !currentIdxAnswered {
		select {
		case res := <-resChan:
			receivedResults++

			if res.err == nil {
				// No locks needed here anymore! The goroutine already handled it.
				return res.resp, upstreams[res.index].URL.String(), failedUpstreams, nil
			}
			// // FIX 1: Explicit log when a parallel/primary upstream fails
			// log.Warn("⚠️ Upstream still failed; marking as failed", // XXX: this is unnecessary spam
			// 	slog.String("url", upstreams[res.index].URL.String()),
			// 	slog.String("sni", upstreams[res.index].SNI),
			// 	wincoe.SafeErr(res.err),
			// )
			// Track the failure
			failedUpstreams = append(failedUpstreams, upstreams[res.index].URL.String())

			if res.index == currentIdx {
				currentIdxAnswered = true
			}
		case <-ctx.Done():
			// Caller gave up. Abandoned in-flight goroutines (including any
			// probe) still run to completion and still apply their healing
			// side-effect; we just stop waiting on their results here.

			var wrapped error
			if cerr := ctx.Err(); cerr != nil { // it's non-nil but checking anyway :P
				wrapped = fmt.Errorf("caller gave up(context done): %w", cerr)
			} else {
				wrapped = nil
			}
			return nil, "", failedUpstreams, wrapped
		} //select
	}

	// 2. If ALL parallel attempts (0 through currentIdx) failed, only then do we
	// step down the list sequentially to find the next working backup.
	for i := currentIdx + 1; i < len(upstreams); i++ {
		// FIX 2: Prevent the instant fallback loop spam during a Ctrl+C shutdown
		if ctx.Err() != nil {
			return nil, "", failedUpstreams, fmt.Errorf("caller gave up(context done): %w", ctx.Err() /*non-nil*/)
		}
		target := upstreams[i]
		resp, err := target.doSingleDoHRequest(ctx, reqBytes)
		if err == nil {
			fs.mu.Lock()
			wasBlackout := fs.allFailed
			fs.allFailed = false // Connectivity restored by a fallback!
			// Only log if WE are the thread that is actively shifting the
			// state away from the stale index we started with.
			shouldLogFailover := !wasBlackout && (fs.activeIndex == currentIdx)
			fs.activeIndex = i
			fs.mu.Unlock()
			if wasBlackout { //nvmTODO: DRY(see the above copy)
				log.Warn("💚 Global blackout resolved; fallback upstream responding",
					slog.String("url", target.URL.String()),
					slog.String("sni", target.SNI),
					slog.Int("index", i),
				)
			} else if shouldLogFailover {
				// if 2 concurrent requests happen this would've otherwise been logged twice
				oldTarget := upstreams[currentIdx]
				// ⚠️ New log line for the standard failover case
				log.Warn("⚠️ Upstream failover; switching to a different(next in list) upstream DoH server",
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
		// FIX 3: Explicit log when a sequential fallback upstream fails
		log.Warn("⚠️ Fallback upstream failed; moving to next (if available)",
			slog.String("url", target.URL.String()),
			slog.String("sni", target.SNI),
			wincoe.SafeErr(err),
		)
		failedUpstreams = append(failedUpstreams, target.URL.String())
	} //for
	// If execution gets here, every single configured upstream failed
	fs.mu.Lock()
	fs.allFailed = true
	fs.activeIndex = 0 // retry from the first one next time
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

	if c.UpstreamSNIHostnames != nil {
		dst.UpstreamSNIHostnames = make([]string, len(c.UpstreamSNIHostnames))
		copy(dst.UpstreamSNIHostnames, c.UpstreamSNIHostnames)
	}

	//Deep-copy the newly added parsed triplets
	if c.UpstreamURLsParsed != nil {
		dst.UpstreamURLsParsed = make([]*url.URL, len(c.UpstreamURLsParsed))
		for i, v := range c.UpstreamURLsParsed {
			if v != nil {
				uCopy := *v
				if v.User != nil {
					uUser := *v.User
					uCopy.User = &uUser
				}
				dst.UpstreamURLsParsed[i] = &uCopy
			}
		}
	}
	if c.UpstreamIPs != nil {
		dst.UpstreamIPs = make([]string, len(c.UpstreamIPs))
		copy(dst.UpstreamIPs, c.UpstreamIPs)
	}
	if c.UpstreamSNIs != nil {
		dst.UpstreamSNIs = make([]string, len(c.UpstreamSNIs))
		copy(dst.UpstreamSNIs, c.UpstreamSNIs)
	}

	// Deep-copy net.IP byte slices
	if c.BlockIPv4Parsed != nil {
		dst.BlockIPv4Parsed = make(net.IP, len(c.BlockIPv4Parsed))
		copy(dst.BlockIPv4Parsed, c.BlockIPv4Parsed)
	}
	if c.BlockIPv6Parsed != nil {
		dst.BlockIPv6Parsed = make(net.IP, len(c.BlockIPv6Parsed))
		copy(dst.BlockIPv6Parsed, c.BlockIPv6Parsed)
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
	cfg := s.getConfig()
	log := s.getLogger()

	blacklistFileName := cfg.BlacklistFile
	if blacklistFileName == "" {
		panic2("BUG: dev. didn't set the default blacklist filename!")
	}
	blacklistFileName = filepath.Clean(blacklistFileName)
	s.fileWriter.CheckPowerLossFile(blacklistFileName)
	var shouldSave bool = false
	var raw []string
	data, err := os.ReadFile(blacklistFileName)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("read blacklist %q: %w", blacklistFileName, err)
		} else {
			log.Warn("Blacklist file not found → using built-in defaults", slog.String("file", blacklistFileName))
			raw = defaultResponseBlacklist() // see below
			shouldSave = true
		}
	} else {
		//actually this is kinda useless because there's only 1 key: 'response_blacklist', it's not testing the cidrs for dups here
		if dups, dupErr := detectDuplicateJSONObjectKeysAtTopLevelOnly(data); dupErr != nil {
			return fmt.Errorf("failed to scan blacklist file %q for duplicate keys: %w", blacklistFileName, dupErr)
		} else if len(dups) > 0 {
			for _, dup := range dups {
				log.Error("Duplicate key found in blacklist file (JSON silently kept only the last value; fix the file manually)",
					slog.String("duplicate_key", dup),
					slog.String("file", blacklistFileName))
			}
			if cfg.ExtraSafety {
				log.Error("ExtraSafety: refusing to continue with duplicate blacklist keys",
					slog.Int("duplicate_count", len(dups)))
				s.shutdown(5)
				panic2("BUG: unreachable")
			}
			log.Warn("Continuing despite duplicate blacklist keys — the JSON decoder kept an arbitrary value for each duplicate; consider fixing the file",
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
			if cfg.ExtraSafety {
				log.Error("Duplicate blacklist entry found", slog.String("entry", str))
			} else {
				log.Warn("Duplicate blacklist entry found, removing it", slog.String("entry", str))
			}
			if !shouldSave {
				shouldSave = true
			}
		}
	}
	dups := len(parsed) - len(deduped)
	if dups > 0 {
		if cfg.ExtraSafety {
			log.Error("ExtraSafety: Found duplicate CIDRs from blacklist file, it/they could be due to typos so silently removing it/them and overwriting the file might be a mistake!", slog.Int("found_count", len(parsed)-len(deduped)), slog.String("file", blacklistFileName))
			s.shutdown(5) //XXX: this will exit program here! //noFIXME: find a better way to "quit" than exit program here
			panic2("BUG: unreachable")
		} else {
			log.Info("Removed duplicate CIDRs from blacklist file", slog.Int("removed_count", len(parsed)-len(deduped)), slog.String("file", blacklistFileName))
			parsed = deduped
		}
	}

	s.blacklist.ReplaceAll(parsed)
	// ==========================================
	//   NEW: INJECT CACHE INVALIDATION HERE
	// ==========================================
	s.invalidateCacheForBlacklistedIPs()
	// ==========================================
	log.Info("Loaded CIDR entries from blacklist file", slog.Int("count", s.blacklist.Len()), slog.Int("duplicates", dups), slog.String("file", blacklistFileName))
	if shouldSave {
		if err := s.saveResponseBlacklist(); err != nil {
			return fmt.Errorf("failed to save blacklist file %q, err: %w", blacklistFileName, err)
		} else {
			log.Info("Saved blacklist file", slog.String("file", blacklistFileName))
		}
	}
	return nil
}

func (s *Server) saveResponseBlacklist() error {
	cfg := s.getConfig()
	log := s.getLogger()

	cidrs := s.getResponseBlacklist()
	jsonFileContents := BlacklistFileFormat{
		ResponseBlacklist: cidrs,
	}
	data, err := json.MarshalIndent(jsonFileContents, "", "  ")
	if err != nil {
		return fmt.Errorf("blacklist marshal failed: %w", err)
	}

	blacklistFileName := cfg.BlacklistFile
	if blacklistFileName == "" {
		panic2("BUG: bad coding: dev. didn't set the default blacklist filename!")
	}
	if err := s.fileWriter.SafeWriteFile(blacklistFileName, data, 0600); err != nil {
		return fmt.Errorf("cannot save/write blacklist file %q: %w", blacklistFileName, err)
	} else {
		log.Info("Saved blacklist file", slog.String("file", blacklistFileName))
	}
	return nil
}

// detectDuplicateJSONObjectKeysAtTopLevelOnly walks the top-level keys of a JSON object
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
//
// so "it detects duplicate top-level object keys, not arbitrary duplicate JSON keys."
func detectDuplicateJSONObjectKeysAtTopLevelOnly(data []byte) (duplicates []string, err error) {
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
	cfg := s.getConfig()
	log := s.getLogger()

	hostsFileName := cfg.HostsFile
	if hostsFileName == "" {
		panic2("BUG: didn't set the default hosts filename!")
	}
	hostsFileName = filepath.Clean(hostsFileName)
	s.fileWriter.CheckPowerLossFile(hostsFileName)
	data, err := os.ReadFile(hostsFileName)
	if os.IsNotExist(err) {
		log.Warn("Hosts file not found, starting with empty local hosts", slog.String("path", hostsFileName))
		// Pass nil or an empty slice to atomically reset the store
		s.hostStore.ReplaceAll(nil)
		s.flushCache()
		return s.saveLocalHosts() // creates empty default file
	}
	if err != nil {
		return fmt.Errorf("cannot read hosts file %q: %w", hostsFileName, err)
	}

	// Check for duplicate JSON keys BEFORE decoding into a map, because
	// Go's json.Decoder silently drops all but the last duplicate — our
	// post-decode seenPatterns check would never see them.
	if dups, dupErr := detectDuplicateJSONObjectKeysAtTopLevelOnly(data); dupErr != nil {
		return fmt.Errorf("failed to scan hosts file %q for duplicate keys: %w", hostsFileName, dupErr)
	} else if len(dups) > 0 {
		// A manually edited file with duplicate keys is almost certainly a
		// typo, so treat it the same way ExtraSafety treats other anomalies.
		for _, dup := range dups {
			log.Error("Duplicate key found in hosts file (JSON silently kept only the last value; fix the file manually)",
				slog.String("duplicate_pattern", dup),
				slog.String("path", hostsFileName))
		}
		if cfg.ExtraSafety {
			log.Error("ExtraSafety: refusing to continue with duplicate host keys",
				slog.Int("duplicate_count", len(dups)))
			s.shutdown(5)
			panic2("BUG: unreachable")
		}
		// Non-ExtraSafety: warn loudly but continue; the map will have kept
		// whichever value the JSON decoder chose (last-write-wins).
		log.Warn("Continuing despite duplicate host keys — the JSON decoder kept an arbitrary value for each duplicate key; consider fixing the file",
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
		// 		log.Warn("Invalid IP in hosts file, skipping", slog.String("ip", ipStr), slog.String("pattern", pat))
		// 	}
		// }
		// //TODO: check for dup patterns or hostnames, wtw we're using here.
		// if len(netIPs) > 0 {
		// 	parsed = append(parsed, LocalHostRule{Pattern: pat, IPs: netIPs})
		// }

		// Normalize pattern the same way the WebUI does: trim whitespace, strip
		// trailing FQDN dot, lowercase.  Track whether anything actually changed
		// so we can rewrite the file if needed.
		normalizedPat := NormalizeDomain(pat)
		if normalizedPat != pat {
			log.Warn("Normalized host pattern",
				slog.String("before", pat),
				slog.String("after", normalizedPat))
			changed++
		}

		if normalizedPat == "" {
			log.Warn("Purging host rule with empty pattern (after normalization)",
				slog.String("original_pattern", pat))
			removed++
			continue
		}

		if _, modified := sanitizeDomainInput(normalizedPat); modified {
			log.Error("Purging invalid host pattern containing illegal characters",
				slog.String("invalid_pattern", normalizedPat))
			removed++
			continue
		}

		if _, dup := seenPatterns[normalizedPat]; dup {
			log.Warn("Duplicate host pattern found, skipping/purging",
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
				log.Warn("Invalid IP in hosts file, skipping",
					slog.String("ip", ipStr),
					slog.String("pattern", normalizedPat))
			}
		}

		if len(netIPs) == 0 {
			log.Warn("Purging host rule with no valid IPs after filtering",
				slog.String("pattern", normalizedPat))
			removed++
			continue
		}

		parsed = append(parsed, LocalHostRule{Pattern: normalizedPat, IPs: netIPs})
	}

	if cfg.ExtraSafety && removed > 0 {
		log.Error("ExtraSafety: refusing to remove host rules due to potential typos "+
			"(fix them manually or set extra_safety to false)",
			slog.Uint64("removed_count", removed))
		s.shutdown(5)
		panic2("BUG: unreachable")
	}

	s.hostStore.ReplaceAll(parsed)
	s.flushCache()

	log.Info("Loaded host rules",
		slog.Int("count", s.hostStore.Len()),
		slog.Uint64("changed_count", changed),
		slog.Uint64("removed_count", removed),
		slog.String("path", hostsFileName))

	if changed > 0 || removed > 0 {
		return s.saveLocalHosts()
	}

	return nil
}

func (s *Server) saveLocalHosts() error {
	log := s.getLogger()
	cfg := s.getConfig()

	var data []byte
	var err error

	// 1. Snapshot the data in the raw map format under lock safely
	raw := s.hostStore.ToRawMap()
	// 2. Marshal to JSON (happens completely lock-free)
	data, err = json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("hosts file marshal failed: %w", err)
	}

	if err := s.fileWriter.SafeWriteFile(cfg.HostsFile, data, 0600); err != nil {
		return fmt.Errorf("cannot save/write hosts file %q: %w", cfg.HostsFile, err)
	}
	log.Info("Saved hosts file", slog.String("path", cfg.HostsFile))
	return nil
}

// getResponseBlacklist Helper – returns current list (snapshot copy)
func (s *Server) getResponseBlacklist() []string {
	return s.blacklist.List()
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
	cfg := s.getConfig()
	log := s.getLogger()

	var data []byte
	var err error

	// 1. Snapshot the data quickly under RLock to prevent blocking DNS queries during slow I/O
	data, err = json.MarshalIndent(s.ruleStore.Snapshot(), "", "  ")
	if err != nil {
		return fmt.Errorf("whitelist marshal failed: %w", err)
	}

	// 2. Serialize the disk write so concurrent WebUI saves don't corrupt the file
	whitelistFileName := cfg.WhitelistFile
	if whitelistFileName == "" {
		panic2("BUG: bad coding: dev. didn't set the default whitelist filename!")
	}
	if err := s.fileWriter.SafeWriteFile(whitelistFileName, data, 0600); err != nil {
		return fmt.Errorf("cannot save/write whitelist file %q: %w", whitelistFileName, err)
	}
	log.Info("Saved whitelist file", slog.String("filename", whitelistFileName))
	return nil
}

// Loads whitelist rules from dedicated file
func (s *Server) loadQueryWhitelist() error {
	cfg := s.getConfig()
	log := s.getLogger()

	whitelistFileName := cfg.WhitelistFile
	if whitelistFileName == "" {
		panic2("BUG: dev. didn't set the default whitelist filename!")
	}
	whitelistFileName = filepath.Clean(cfg.WhitelistFile)
	s.fileWriter.CheckPowerLossFile(whitelistFileName)
	data, err := os.ReadFile(whitelistFileName)
	if os.IsNotExist(err) {
		log.Warn("Whitelist file not found, starting with empty whitelist", slog.String("path", whitelistFileName))
		// Atomically set the internal map to an empty one
		s.ruleStore.ReplaceAll(make(map[string][]RuleEntry))
		s.flushCache()
		return s.saveQueryWhitelist() // create "empty" file; uses lock
	}
	if err != nil {
		return fmt.Errorf("cannot read whitelist file %q: %w", whitelistFileName, err)
	}
	if dups, dupErr := detectDuplicateJSONObjectKeysAtTopLevelOnly(data); dupErr != nil {
		return fmt.Errorf("failed to scan whitelist file %q for duplicate keys: %w", whitelistFileName, dupErr)
	} else if len(dups) > 0 {
		for _, dup := range dups {
			log.Error("Duplicate key found in whitelist file (JSON silently kept only the last value; fix the file manually)",
				slog.String("duplicate_key", dup),
				slog.String("path", whitelistFileName))
		}
		if cfg.ExtraSafety {
			log.Error("ExtraSafety: refusing to continue with duplicate whitelist keys",
				slog.Int("duplicate_count", len(dups)))
			s.shutdown(5)
			panic2("BUG: unreachable")
		}
		log.Warn("Continuing despite duplicate whitelist keys — the JSON decoder kept an arbitrary value for each duplicate; consider fixing the file",
			slog.Int("duplicate_count", len(dups)))
	}

	var rulesByType map[string][]RuleEntry
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&rulesByType); err != nil {
		return fmt.Errorf("failed to parse whitelist file '%q' (maybe it contains unsupported or typo-ed fields?), err: %w", whitelistFileName, err)
	}

	// ── Normalization (no lock needed; working on local variables) ──────────────
	// Count total rules for initial map capacity
	totalRules := 0
	for _, rules := range rulesByType {
		totalRules += len(rules)
	}
	seenIDs := make(map[string]struct{}, totalRules) // global across all types
	newRules := make(map[string][]RuleEntry, len(rulesByType))

	var changed uint64 = 0
	var removed uint64 = 0

	for typ, rules := range rulesByType {
		seenPatterns := make(map[string]struct{}, len(rules)) // only per DNS type ie. A, AAAA, HTTPS
		var cleaned []RuleEntry
		for i := range rules {
			r := &rules[i]
			// XXX: it may not have an ID set at this point
			if r.ID == "" {
				nid := generateUniqueRuleID(rulesByType, log) // still guards against rulesByType collisions
				// Also guard against IDs already assigned in this same load pass
				for _, alreadySeen := seenIDs[nid]; alreadySeen; _, alreadySeen = seenIDs[nid] {
					log.Warn("Generated ID collided with already-seen ID in this load pass, regenerating", slog.String("id", nid))
					nid = generateUniqueRuleID(rulesByType, log)
				}
				log.Warn("Making new not-already-existing ID for rule that had none", slog.String("id", nid))
				r.ID = nid
				changed++
			}
			//checks against all DNS types not just in 'typ'
			if _, duplicate := seenIDs[r.ID]; duplicate {
				log.Warn("Duplicate rule ID found, skipping/purging it", slog.String("id", r.ID))
				removed++
				continue // Skip appending this rule
			}
			seenIDs[r.ID] = struct{}{}

			//lowercase it and strip the dot at the end:
			new2 := NormalizeDomain(r.Pattern)
			if new2 != r.Pattern {
				log.Warn("Changed rule pattern", slog.Any("new_pattern", new2), slog.String("old_pattern", r.Pattern), slog.Any("original_rule", r))
				r.Pattern = new2
				changed++
			}
			// Check for empty or entirely invalid structures
			if r.Pattern == "" {
				log.Warn("Purging/deleting rule with empty pattern", slog.String("id", r.ID))
				removed++
				continue
			}

			// Validate using the allowed rule character set
			_, modified := sanitizeDomainInput(r.Pattern)
			if modified {
				log.Error("Purging/deleting invalid whitelist rule pattern containing illegal characters",
					slog.String("id", r.ID),
					slog.String("invalid_pattern", r.Pattern),
				)
				removed++
				continue // Purges/omits it from being appended to cleaned slice
			}

			if _, dup := seenPatterns[r.Pattern]; dup {
				log.Warn("Duplicate rule pattern found after normalization, skipping/purging it",
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

		newRules[typ] = cleaned
	} //for

	if cfg.ExtraSafety {
		if removed > 0 {
			log.Error("ExtraSafety: Refusing to remove rules due to potential typos(fix them manually or set extra_safety to false)", slog.Uint64("removed_count", removed))
			s.shutdown(5) //noFIXME: find a better way to "quit" than exit program here, but still preserve the exitcode=5 ?!
			panic2("BUG: unreachable")
		}
	}

	// ── Atomic swap ──────────────────────────────────────────────────────────────
	s.ruleStore.ReplaceAll(newRules)
	s.flushCache()

	hmn := s.ruleStore.CountAll()
	log.Info("Loaded whitelist and normalized(aka changed) or removed(if dup IDs) rules",
		slog.Int("types", len(newRules)),
		slog.Uint64("rules", hmn),
		slog.Uint64("changed_count", changed),
		slog.Uint64("removed_count", removed),
		slog.String("path", whitelistFileName),
	)
	if countRules(rulesByType)-removed != hmn {
		panic2("BUG: bad coding: lost some rules, shouldn't happen!")
	}

	if changed > 0 || removed > 0 {
		return s.saveQueryWhitelist() //uses lock!
	} else {
		return nil // no error
	}
}

const defaultCacheMinTTL = 300

// defaultConfig Every call produces a new map and slice backing array.
// must be func. or else(if configDefaults would be a 'var') the 'make' call/ref. will be shared and the []string{} too.
func defaultConfig() Config {
	cfg := Config{
		ListenDNS:               "127.0.0.1:53",
		ListenDoH:               "127.0.0.1:443",
		ListenUI:                "127.0.0.1:8080",
		TLSCertFile:             "cert.pem",
		TLSKeyFile:              "key.pem",
		UpstreamURLs:            []string{"https://9.9.9.9/dns-query", "https://1.1.1.1/dns-query"},
		UpstreamSNIHostnames:    []string{"dns.quad9.net", "cloudflare-dns.com"}, // if empty it uses the IP or host from the url which also works!
		UpstreamSelectionMode:   upstreamSelectionModeFailover,
		UpstreamRetriesPerQuery: 1, // 1 initial try(not counted) + 1 retry(counted here)
		BlockMode:               blockModeNXDOMAIN,
		BlockIP:                 "0.0.0.0",
		BlockIPv6:               "::", // Default unspecified IPv6

		GlobalRateQPS:  100,
		GlobalBurstQPS: 200, //100 worked for me, but heck, let's 2x it
		ClientRateQPS:  20,
		ClientBurstQPS: 50,

		CacheMinTTL:     defaultCacheMinTTL, //300 sec
		CacheMaxEntries: 10000,

		WhitelistFile: "query_whitelist.json",
		BlacklistFile: "response_blacklist.json",
		HostsFile:     "hosts2ip.json",

		LogQueriesFile:              "queries.log",
		LogEverythingFile:           "dnsbollocks.log",
		ConsoleLogLevel:             consoleLogLevelInfo,
		LogMaxSizeMB:                4095, // Rotation threshold
		AllowRunAsAdmin:             false,
		BlockAAAAasEmptyNoError:     true,
		AllowHTTPSIfAAllowed:        true,
		RemoveHTTPSIPv4Hints:        true,
		WebUIUseTLS:                 true,
		WebUIForceTLSOnNonLocalhost: true, //if WebUIUseTLS is false and ListenUI is non-localhost-like IP, then force WebUIUseTLS to true ?
		WebUIMaxLoginFailures:       5,
		WebUILoginLockoutSec:        5 * 60, // 5 minutes, in seconds

		WebUIReadHeaderTimeoutSec: 5,
		WebUIReadTimeoutSec:       15,
		WebUIWriteTimeoutSec:      15,
		WebUIIdleTimeoutSec:       60,

		MaxConcurrentDNSTCPConns:   50,
		MaxConcurrentDNSUDPQueries: 1000,

		// Centralized Network Parameter Defaults

		//this is per operation: o1) read 2 bytes, o2) read the body, o3) write the response; so each 3 operations get this timeout!
		ClientTCPTimeoutSec: 5,

		MaxRecentBlocks:              100,
		LocalDoHReadHeaderTimeoutSec: 3, // Snaps shut on slowloris quickly
		LocalDoHReadTimeoutSec:       30,
		LocalDoHWriteTimeoutSec:      30,
		//LocalDoHIdleTimeoutSec:       2 * LocalDoHReadTimeoutSec, //60, // Sane keep-alive for DoH

		//High-latency satellite, VPN, or cellular links will drop upstream queries and trigger premature failovers under a strict 3 or 5-second limit. Conversely, high-availability setups might require an aggressive sub-second timeout to switch nodes rapidly.
		UpstreamDialTimeoutSec:   3,
		UpstreamClientTimeoutSec: 5, // overall per-request timeout
		//When inspecting upstream certificates for error diagnostics, a hardcoded 5-second timeout on firewalled or highly congested links can block or drag out startup sequences and system health loops unnecessarily.
		CertLogTimeoutSec: 5,

		//Resource allocations vary heavily between environments. A low-powered embedded home router running this binary shouldn't maintain 100 idle network connections. On the other hand, heavy enterprise or multi-user environments will exhaust MaxIdleConnsPerHost: 10 instantly, resulting in severe socket thrashing and latency spikes.
		UpstreamIdleConnTimeoutSec:   90,
		UpstreamH2ReadIdleTimeoutSec: 5,
		UpstreamH2PingTimeoutSec:     3,
		UpstreamTCPKeepAliveSec:      15,
		ServerGracefulShutdownSec:    3,
		//UpstreamMaxIdleConns:        100,
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

		FileWriterMaxRetries:     6,
		FileWriterRetryBackoffMs: 100,

		//You added a smart truncation limit to prevent browser crashes when reading massive logs. However, some admins might have beefy machines and want to see 20,000 lines, while others might be running the UI on an old phone and need it capped at 1,000.
		UILogMaxLines: 5000,

		UseEDEInBlockedReply: true,

		ExtraSafety: true,

		WebUIPasswordHash:       "", // empty because it will be set at startup or loaded from disk, we don't want to have an already set up "dnsbollocks" pwd here, then it won't get asked at startup
		WebUIPasswordBcryptCost: 12,
	}
	//compute based on others
	cfg.LocalDoHIdleTimeoutSec = 2 * cfg.LocalDoHReadTimeoutSec
	cfg.UpstreamMaxIdleConns = 10 * cfg.UpstreamMaxIdleConnsPerHost
	if cfg.WebUIPasswordHash != "" {
		panic2("BUG: password hash shouldn't be set in defaults, else logic needs to be change in other places counting on this")
	}

	return cfg
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
		logger.Warn("EnableVirtualTerminalProcessing failed", wincoe.SafeErr(err)) //itwontFIXME: figure out if this would recuse infinitely
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
	_ = ctx
	return level >= h.Level
}

func (h *ColoredConsoleHandler) Handle(ctx context.Context, r slog.Record) error {
	_ = ctx
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
	case slog.LevelDebug: // already handled in an 'if' above
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

	if _, err := h.Out.Write(buf.Bytes()); err == nil {
		return nil
	} else {
		//wrapped
		return fmt.Errorf("failed to buffer of the colored console handler: %w", err)
	}
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

	if err := h.Handler.Handle(ctx, r); err == nil {
		return nil
	} else {
		return fmt.Errorf("handle query filter in webUI backend: %w", err)
	}
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
	case consoleLogLevelDebug, "d":
		return slog.LevelDebug
	case consoleLogLevelInfo, "i":
		return slog.LevelInfo
	case consoleLogLevelWarn, "warning", "w":
		return slog.LevelWarn
	case consoleLogLevelError, "e":
		return slog.LevelError
	default:
		//anything else means... Debug
		return slog.LevelDebug
	}
}

// Globals.

var dnsTypesPriority = []string{"A", "AAAA", "HTTPS", "MX", "NS"}

var dnsTypes = func() []string {
	seen := make(map[string]struct{}, len(dnsTypesPriority)+len(allDNSTypes))
	out := make([]string, 0, len(dnsTypesPriority)+len(allDNSTypes))
	for _, t := range append(dnsTypesPriority, allDNSTypes...) {
		if _, ok := seen[t]; !ok {
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	return out
}()

// full list no dups
var allDNSTypes = []string{
	//most used first
	"A",
	// "AAAA",  // dup on purpose
	// "HTTPS", // dup on purpose
	// "MX",    // dup on purpose
	// "NS",    // dup on purpose
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

// loginRecord tracks failed WebUI login attempts for a single client IP.
// All fields are guarded by Server.loginMu.
type loginRecord struct {
	failures    int       // consecutive failures in the current window
	lockedUntil time.Time // zero value means no active lockout
}

// ---- old slow way
var dnsNameRE = regexp.MustCompile(
	`^(?i)([a-z0-9_](?:[a-z0-9-]{0,61}[a-z0-9_])?\.)*[a-z0-9_](?:[a-z0-9-]{0,61}[a-z0-9_])?$`,
)

func isValidDNSName1(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	return dnsNameRE.MatchString(s)
}

// sanitizeDomainInput removes any characters not explicitly allowed.
// Safe for logs and DNS-related handling.
func sanitizeDomainInput1(input string) (sanitized string, modified bool) {
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

// ---- END of --- old slow way

// Helper for the fast-path parser
func isLetterOrDigit(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// New helper to allow underscores on label boundaries
func isLetterDigitOrUnderscore(c byte) bool {
	return isLetterOrDigit(c) || c == '_'
}

/*
NOTES:
DNS query uses only the ASCII form:

	letters a–z
	digits 0–9
	hyphen -
	underscore _
	dot .

What this enforces:

	Labels don’t start or end with -
	Labels can start or end with _
	Labels ≤ 63 chars
	Total length ≤ 253 chars
	ASCII-only DNS reality
*/
func isValidDNSName(s string) bool {
	l := len(s)
	if l == 0 || l > 253 {
		return false
	}

	lastDot := -1
	for i := 0; i <= l; i++ {
		isEnd := i == l
		var c byte
		if !isEnd {
			c = s[i]
		}

		if isEnd || c == '.' {
			partLen := i - lastDot - 1
			if partLen == 0 || partLen > 63 {
				return false // Labels must be 1-63 characters
			}

			// First character of the label (allows alphanumeric or underscore)
			first := s[lastDot+1]
			if !isLetterDigitOrUnderscore(first) {
				return false
			}

			// Last character of the label (allows alphanumeric or underscore)
			last := s[i-1]
			if !isLetterDigitOrUnderscore(last) {
				return false
			}

			// Middle characters can only be alphanumeric or hyphens
			for j := lastDot + 2; j < i-1; j++ {
				mid := s[j]
				if !isLetterOrDigit(mid) && mid != '-' {
					return false
				}
			}

			lastDot = i
		}
	}
	return true
}

func sanitizeDomainInput(input string) (sanitized string, modified bool) {
	// 1. Fast Path: Check if any invalid characters exist first.
	// We iterate over bytes instead of runes since valid DNS chars are entirely ASCII.
	validCount := 0
	for i := 0; i < len(input); i++ {
		c := input[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '-' || c == '{' || c == '}' || c == '*' || c == '!' || c == '?' || c == '_' {
			validCount++
		}
	}

	// If everything is valid, return the original string (Zero Allocation!)
	if validCount == len(input) {
		return input, false
	}

	// 2. Slow Path: Allocation is required to strip bad characters.
	var b strings.Builder
	b.Grow(validCount)
	for i := 0; i < len(input); i++ {
		c := input[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '-' || c == '{' || c == '}' || c == '*' || c == '!' || c == '?' || c == '_' {
			b.WriteByte(c)
		}
	}

	return b.String(), true
}

// validateRulePattern returns a non-nil error if the pattern contains characters
// outside the allowed set (as defined by sanitizeDomainInput).
// It does NOT enforce strict DNS name rules because patterns may contain
// wildcards: *, **, {*}, {**}, ?, !, and braces.
func validateRulePattern(pattern string) error {
	if pattern == "" {
		return errors.New("pattern cannot be empty")
	}
	if pattern != strings.ToLower(pattern) {
		return errors.New("pattern must be lowercase")
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

var uiTemplates0 = template.Must(template.ParseFS(templates.FS, "ui.html"))

//var uiTemplates = template.Must(template.New("").Parse(
//    `
//`))

const configFileName = "config.json"

func (s *Server) logFatal(msg string, err error) {
	log := s.getLogger()
	log.Error(msg, wincoe.SafeErr(err))
	s.shutdown(1)
	panic2("BUG: unreachable")
}

func (s *Server) logFatal2(msg string) {
	log := s.getLogger()
	log.Error(msg)
	s.shutdown(1)
	panic2("BUG: unreachable")
}

func (ui *AdminUI) logFatal(msg string, err error, args ...any) {
	log := ui.getLogger()
	// // 1. Log the severe error message
	args = append(args, wincoe.SafeErr(err)) //works for nil err too
	log.Error("FATAL WEB UI ERROR: "+msg, args...)

	// 2. Trigger the application shutdown if the callback is wired
	if ui.OnShutdown != nil {
		ui.OnShutdown(1) // Exit code 1 for crashes/errors
		panic2("BUG: AdminUI.OnShutdown returned but is designed to terminate execution")
	} else {
		panic2("BUG: Shutdown requested, but no shutdown handler is wired (likely in a test environment).")
	}
}

// getJSONTagByOffset finds a Config field by its memory offset and extracts its JSON key.
// Because it uses real field selectors, it is 100% safe for VS Code automated refactoring.
// example usage: getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIPasswordHash))
func getJSONTagByOffset(offset uintptr) string {
	// Fix 1: Using reflect.TypeFor[T]() instead of reflect.TypeOf(T{})
	typ := reflect.TypeFor[Config]()

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.Offset == offset {
			tag := field.Tag.Get("json")
			if tag == "" || tag == "-" {
				//no fallback
				panic2(fmt.Sprintf("BUG: Field %q isn't one that's used in the config file %q and shouldn't be attempted...", field.Name, configFileName))
				// return strings.ToLower(field.Name) //fallback
			}

			// Fix 2: Using strings.Cut instead of strings.Index and slicing
			// If a comma exists (e.g. "my_field,omitempty"), 'before' gets everything before it.
			// If no comma exists, 'before' gets the entire string.
			before, _, _ := strings.Cut(tag, ",")
			return before
		}
	}

	panic2(fmt.Sprintf("BUG: No field found at offset %d in Config struct", offset))
	panic(nil)
}

// OnReload registers an anonymous action to execute when a reload event is triggered
// OnReload registers a hook that is called after a config reload.
// Must only be called during startup before reload processing begins.
func (s *Server) OnReload(hook func()) {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	s.onReloadHooks = append(s.onReloadHooks, hook)
}

func (s *Server) runReloadHooks() {
	var hooks []func()

	// 1. Read-lock, safely clone the slice, and defer RUnlock inside the block
	func() {
		s.reloadMu.RLock()
		defer s.reloadMu.RUnlock()

		hooks = slices.Clone(s.onReloadHooks)
	}() // <-- Executed immediately

	// 2. Run the hooks safely outside the read lock
	for _, hook := range hooks {
		hook()
	}
}

// Reload via Ctrl+R aka reloadFn
func (s *Server) Reload() {
	log := s.getLogger()

	if !s.reloadInProgress.CompareAndSwap(false, true) {
		log.Warn("Reload already in progress")
		return
	} else {
		defer s.reloadInProgress.Store(false)
	}

	log.Debug("Reload triggered...")

	oldCfg := s.getConfig()
	oldJanitorInterval := oldCfg.CacheJanitorIntervalMinutes

	// 1. Load and validate the new config cleanly from disk using our decoupled helper
	resolvedCfg, rawCfg, needsSave, err := LoadAndValidateConfig(log, configFileName)
	if err != nil {
		// s.logFatal("main config ("+configFileName+") reload failed:", err)
		// panic2("BUG: unreachable")
		// Intercept fatal strings exactly as the old code did
		if strings.HasPrefix(err.Error(), "FATAL:") {
			log.Error(strings.TrimPrefix(err.Error(), "FATAL: "))
			finalShutdownSequence(log, 1, os.Exit)
			//TODO: maybe now we don't have to os.Exit ?
		} else {
			log.Error("Config reload failed, aborting reload, fix it and try again after.", wincoe.SafeErr(err))
			return
		}
	}
	log.Debug("main config reloaded", slog.String("filename", configFileName))

	// Apply the new config atomically
	s.applyConfig(*resolvedCfg, *rawCfg)

	// Update the fileWriter with the newly loaded safety parameters instantly
	s.fileWriter.SetExtraSafety(resolvedCfg.ExtraSafety)
	s.fileWriter.SetRetryParams(resolvedCfg.FileWriterMaxRetries, resolvedCfg.FileWriterRetryBackoffMs)

	if needsSave {
		if err := s.saveConfig(); err != nil {
			log.Error("Failed to save config during reload", wincoe.SafeErr(err))
		}
	}

	cfgNew := s.getConfig()
	if !cfgNew.AllowRunAsAdmin && isAdmin {
		s.logFatal2("Exiting: Elevated privileges detected. Rerun without admin or change the config setting.")
		panic2("BUG: unreachable")
	}

	// if err := s.loadQueryWhitelist(); err != nil {
	// 	s.logFatal("Whitelist ("+cfgNew.WhitelistFile+") reload failed:", err)
	// 	panic2("BUG: unreachable")
	// } else {
	// 	log.Debug("Whitelist reloaded", slog.String("filename", cfgNew.WhitelistFile))
	// }
	// if err := s.loadResponseBlacklist(); err != nil {
	// 	s.logFatal("Blacklist ("+cfgNew.BlacklistFile+") reload failed:", err)
	// 	panic2("BUG: unreachable")
	// } else {
	// 	log.Debug("Blacklist reloaded", slog.String("filename", cfgNew.BlacklistFile))
	// }
	// // Inside watchKeys, in the Ctrl+R lambda block:
	// if err := s.loadLocalHosts(); err != nil {
	// 	s.logFatal("Hosts ("+cfgNew.HostsFile+") reload failed:", err)
	// 	panic2("BUG: unreachable")
	// } else {
	// 	log.Debug("Local hosts reloaded", slog.String("filename", cfgNew.HostsFile))
	// }

	if err := s.loadDependentStores(); err != nil {
		s.logFatal("Dependent stores reload failed:", err)
		panic2("BUG: unreachable")
	} else {
		log.Debug("Dependent stores reloaded successfully")
	}

	// 2. Re-initialize logging (applies new console levels or log files)
	//We do this late here to keep same logger until reload is done-ish
	s.initFullLogging()
	log = s.getLogger() // Grab the newly initialized logger

	log.Info("Configuration files reloaded successfully")

	// 3. Flush the cache to apply new TTLs/rules
	s.flushCache()

	// 4. Update the rate limiter with new QPS settings
	s.rateLimiter.UpdateConfig(rateLimitConfigFrom(*cfgNew /*it's been updated*/))
	log.Debug("Rate limiter reinitialized")

	s.generateCertIfNeeded() // For DoH and webUI! just mutates certGeneration if needed

	s.upstreamMgr.ReInitDoHClients()

	//clearLoginLockouts()//wired in startWebUI

	if oldJanitorInterval != cfgNew.CacheJanitorIntervalMinutes {
		s.swapDNSCache(cfgNew.CacheJanitorIntervalMinutes, cfgNew.CacheMaxEntries)
		log.Warn("Cache janitor interval changed; cache instance replaced (all cached entries dropped)",
			slog.Int("old_interval_minutes", oldJanitorInterval),
			slog.Int("new_interval_minutes", cfgNew.CacheJanitorIntervalMinutes))
	}

	if oldCfg.MaxConcurrentDNSTCPConns != cfgNew.MaxConcurrentDNSTCPConns {
		s.swapDNSTCPSemaphore(cfgNew.MaxConcurrentDNSTCPConns)
		log.Debug("DNS TCP concurrent-connection limit updated",
			slog.Int("old_max", oldCfg.MaxConcurrentDNSTCPConns),
			slog.Int("new_max", cfgNew.MaxConcurrentDNSTCPConns))
	}

	if oldCfg.MaxConcurrentDNSUDPQueries != cfgNew.MaxConcurrentDNSUDPQueries {
		s.swapDNSUDPSemaphore(cfgNew.MaxConcurrentDNSUDPQueries)
		log.Debug("DNS UDP concurrent-query limit updated",
			slog.Int("old_max", oldCfg.MaxConcurrentDNSUDPQueries),
			slog.Int("new_max", cfgNew.MaxConcurrentDNSUDPQueries))
	}

	// The magic happens here: entirely data-driven rebinds.
	s.rebindDNSListener(dnsListenerParamsFrom(cfgNew))
	s.rebindDoHListener(s.dohListenerParamsFrom(cfgNew))
	s.rebindWebUIListener(s.uiListenerParamsFrom(cfgNew))

	// 6. Run external hooks (like clearing WebUI lockouts)
	log.Debug("Running on-reload hooks")
	// 2. TRIGGER HOOKS HERE: Notify any external components that signed up
	s.runReloadHooks()

	log.Info("Config reload complete. Listeners, cache, and connection limits rebound as needed.")
}

func (s *Server) Run() error {
	log := s.getLogger()

	// Signals setup FIRST: Catch interrupts from init onward
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)
	log.Debug("Signal channel ready - Ctrl+C to shutdown gracefully")

	// --- OS Console Event Handler Integration ---
	globalConsoleEventTrigger = func(eventName string) {
		logEvt := s.getLogger()
		logEvt.Warn("OS Console Event received, overriding for safe teardown", slog.String("event", eventName))

		// Triggers your exact sequence: cancels context, waits on WaitGroups, calls os.Exit()
		s.shutdown(0)
		panic2("BUG: unreachable")
	}

	// Strictly checking the return value (as promised!)
	ret, _, errCall := procSetConsoleCtrlHandler.Call(windows.NewCallback(consoleCtrlHandler), 1)
	if ret == 0 {
		s.logFatal("Failed to register Windows console termination handler", errCall)
		panic2("BUG: unreachable")
	} else {
		log.Debug("OS console termination handler successfully registered. Handling graceful shutdown for Ctrl+Break as well.")
	}
	// --------------------------------------------

	// if err := s.loadConfig(); err != nil {
	// 	s.logFatal("Config load failed:", err)
	// 	panic2("BUG: unreachable")
	// }
	// Get the configuration that was injected during NewServer
	cfg := s.getConfig() //XXX: it's way after s.loadConfig() !!
	//log.Info("Config loaded", slog.String("file", configFileName))

	if !cfg.AllowRunAsAdmin && isAdmin {
		s.logFatal2(fmt.Sprintf("Exiting: Elevated privileges detected. Rerun without admin or change the config setting %q in file %q.", getJSONTagByOffset(unsafe.Offsetof(Config{}.AllowRunAsAdmin)), configFileName))
		panic2("BUG: unreachable")
	}
	//log.Debug("Non-elevated mode confirmed") // no good, as we can be admin here!

	// Now we have the real config → switch to full logging
	log = s.initFullLogging() // ← this replaces the logger with files + correct console level(based on freshly loaded config settings from file) doneTODO: Ctrl+R would have to run this too!

	// Load dependent data stores NOW, using the correct full logger
	if err := s.loadDependentStores(); err != nil {
		s.logFatal("Dependent stores load failed:", err)
		panic2("BUG: unreachable")
	}

	s.swapDNSCache(cfg.CacheJanitorIntervalMinutes, cfg.CacheMaxEntries)
	log.Debug("Cache initialized")

	s.rateLimiter = newClientRateLimiter(s.ctx, rateLimitConfigFrom(*cfg /*it's a copy, not pointer to live*/), log)
	log.Debug("Rate limiter initialized")

	s.swapDNSTCPSemaphore(cfg.MaxConcurrentDNSTCPConns)
	log.Debug("DNS TCP concurrent-connection limit initialised", slog.Int("max_concurrent", cfg.MaxConcurrentDNSTCPConns))
	s.swapDNSUDPSemaphore(cfg.MaxConcurrentDNSUDPQueries)
	log.Debug("DNS UDP concurrent-connection limit initialised", slog.Int("max_concurrent", cfg.MaxConcurrentDNSUDPQueries))

	s.generateCertIfNeeded() // For DoH and webUI!

	s.upstreamMgr.InitDoHClients()
	// Sequential launches for ordered logging
	log.Debug("Launching listeners sequentially...")
	s.initAdminUI()

	// Pass params instead of raw config fields
	s.rebindDNSListener(dnsListenerParamsFrom(cfg))       // non-blocking, Blocks until init completes/fails
	s.rebindDoHListener(s.dohListenerParamsFrom(cfg))     // non-blocking, Blocks until init completes/fails
	go s.rebindWebUIListener(s.uiListenerParamsFrom(cfg)) //blocking but runs in goroutine so this line isn't blocking

	go s.watchKeys(s.Reload, // Ctrl+R aka reloadFn
		func() { // alt+x Ctrl+X etc. aka cleanExitFn
			log3 := s.getLogger()
			log3.Debug("Shutdown signal received, clean exit.")
			//doneFIXME: at least UDP DNS listener isn't shutdown while waiting for keypress to exit (after the shutdown(0) below) !!
			//cancel()    //doneFIXME: this triggers the below shutdown(4) !
			s.shutdown(0) // clean exit
			panic2("BUG: unreachable")
		},
	)

	//<-sigChan // Wait here - UI goroutine handles serving
	// 4. The Seamless Wait
	select {
	case sig := <-sigChan:
		log4 := s.getLogger()
		// Case A: User pressed Ctrl+C
		log4.Info("shutdown initiated by signal", slog.String("signal", sig.String()))
		// Proceed to graceful cleanup
		//cancel()      // Cancel context for graceful close
		s.shutdown(130) // Ctrl+C / SIGTERM → non-clean exit => exit code 130 (128+2 like in linux)
		panic2("BUG: unreachable")

	case err := <-s.errChan:
		log5 := s.getLogger()
		// Case B: A background goroutine (TCP/DoH) died
		log5.Error("CRITICAL: background service failure", wincoe.SafeErr(err))
		// You can choose to exit(1) here because a vital organ failed
		//cancel()    // Cancel context for graceful close
		s.shutdown(3) // some error happened
		panic2("BUG: unreachable")

	case <-s.ctx.Done():
		log6 := s.getLogger()
		// Case C: Context was cancelled elsewhere
		log6.Info("context cancelled, shutting down")
		//cancel()    // Cancel context for graceful close, this was already done since we hit this.
		s.shutdown(4) // some error happened
		panic2("BUG: unreachable")
	}
	panic2("BUG: forgot to handle a case? this should be unreachable")
	panic(nil)
}

func OldMain() {
	// log is the single source of truth. Every log event goes through ONE call here.
	// The multiHandler then fans it out to:
	//   - dnsbollocks.log (JSON, everything)
	//   - queries.log (JSON, only category=query)
	//   - console (colored text, >= ConsoleLogLevel)
	//
	// var log *slog.Logger
	// log starts as a bootstrap colored console logger (Info level).
	// It is replaced after loadConfig() with the full multi-handler (files + config level).
	// This guarantees the very first line of OldMain already uses log.
	var localLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug, //TODO: allow env. var. to dictate the level? but nothing right now uses this yet because initBootstrapLogging gets hit early!
	}))

	// wincoe.InstallCrashSink()
	// if true {
	//     panic2("deliberate panic")
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

	localLogger = initBootstrapLogging(localLogger) // ← FIRST LINE — colored console, log now exists
	// go func() {
	//     ticker := time.NewTicker(5 * time.Second)
	//     defer ticker.Stop()
	//     for range ticker.C {
	//         log.Debug("MARK")
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
		hash, err := promptAndHashPassword(localLogger, 12) // Hardcode safe minimum for CLI
		if err != nil {
			localLogger.Error("Failed to set password: ", wincoe.SafeErr(err))
			finalShutdownSequence(localLogger, 1, os.Exit)
		}
		//fmt.Printf("\nSuccess! Paste this exact string into your %s as the value for \"webui_password_hash\":\n%s\n", configFileName, hash)
		// Dynamic tag extraction
		var jsonTag string = getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIPasswordHash))
		fmt.Printf("\nSuccess! Paste this exact string into your %s as the value for %q:\n%s\n", configFileName, jsonTag, hash)
		localLogger.Debug("Generated new hash password(not logging it) via cmd line arg, not saved in config.", slog.String("config", configFileName))
		finalShutdownSequence(localLogger, 0, os.Exit)
	}

	// 1. Load and validate configuration decoupled from the Server struct
	resolvedCfg, rawCfg, shouldSaveConfig, err := LoadAndValidateConfig(localLogger, configFileName)
	if err != nil {
		// Intercept fatal strings exactly as the old code did
		if strings.HasPrefix(err.Error(), "FATAL:") {
			localLogger.Error(strings.TrimPrefix(err.Error(), "FATAL: "))
		} else {
			localLogger.Error("Config load failed", wincoe.SafeErr(err))
		}
		finalShutdownSequence(localLogger, 1, os.Exit)
	} else {
		localLogger.Info("Config loaded", slog.String("filename", configFileName))
	}

	// 2. Initialize the Server flawlessly using the resolved config
	srv := NewServer(localLogger, resolvedCfg, rawCfg)
	if shouldSaveConfig {
		// saveConfig internally calls s.getConfig(), which now has the fully updated data
		if err = srv.saveConfig(); err != nil {
			//			return fmt.Errorf("config save failed: %w", err)
			localLogger.Error("Failed to save initial configuration", wincoe.SafeErr(err))
			srv.shutdown(1)
		}
	}

	if err := srv.Run(); err != nil {
		localLogger.Error("Server exited with error", wincoe.SafeErr(err))
		srv.shutdown(1)
		panic2("BUG: unreachable")
	}

	localLogger.Error("unreachable")
	//cancel()     // Cancel context for graceful close
	srv.shutdown(44) // impossible to reach this, unless code was added later and shutdown/exit was forgotten above.
	panic2("BUG: unreachable")
}

const cacheMinTTLClamp = 10 // seconds

// LoadAndValidateConfig reads, parses, validates, and clamps the configuration.
// It is completely decoupled from the Server struct to allow pre-initialization.
func LoadAndValidateConfig(log *slog.Logger, cfgFname string) (*Config, *Config, bool, error) {
	// func (s *Server) loadMainConfig() error {
	//log := s.getLogger()
	//cfg := s.getConfig()
	//const cfgFname = configFileName
	if cfgFname == "" {
		return nil, nil, false, fmt.Errorf("given config file %q is empty", cfgFname)
	}
	log.Info("Loading config file", slog.String("config_file", cfgFname))
	var shouldSaveConfig = false
	// ---> FIX: Pre-populate the global config with defaults BEFORE reading/decoding
	// this way missing keys from config.json file will be set to default value!
	// 1. ALWAYS start by filling the global config with defaults.
	// This is critical because Decode only overwrites what is in the file.
	defaultCfg := defaultConfig()
	// //config = defaultConfig // deep copy, presumably!(it's shallow, but strings are immutable so it's acting like a deep-copy for them) doneFIXME?
	// //cfg = defaultConfig.Clone() // deep copy
	//XXX: config is already set to defaultConfig() is already set from the NewServer() call! TODO: the only issue is do we want defaults if loadMainConfig is called again during Server's lifetime ie. Ctrl+R aka reload
	//s.applyConfig(defaultConfig.Clone()) //deep copy

	// Create a local copy to decode into and validate.
	// This prevents live queries from reading a half-baked config.
	resolvedTempCfg := defaultCfg.Clone()
	rawTempCfg := defaultCfg.Clone()
	//newCfg := &tempCfg // Use a local pointer for all setup and decoding
	//defaultCfgClone := defaultConfig.Clone()
	//newCfg := &defaultCfgClone

	// resolvedCfg is the runtime representation; tokens expanded, clamping applied below.
	var resolvedCfg *Config
	// rawCfg is the on-disk representation; never clamp/mutate for runtime convenience here.
	var rawCfg *Config = &rawTempCfg

	// s.fileWriter.SetExtraSafety(defaultCfg.ExtraSafety)                                               //using default cfg.ExtraSafety until read from disk, this is already set to this default in the NewServer constructor tho
	// s.fileWriter.SetRetryParams(defaultCfg.FileWriterMaxRetries, defaultCfg.FileWriterRetryBackoffMs) //TODO: ensure defautlConfig had sanitizeAndValidateConfig run on it

	// s.fileWriter.CheckPowerLossFile(cfgFname) //a default Config was already set at birth(even tho we also set it here, above, this one we set above isn't in effect yet), or kept the previously loaded one, those values are used by any child callers that use Server's Config during loadMainConfig() until the new config is atomically swapped in(at the end tho)

	// Temporarily spin up a file writer solely to check for power-loss corruption
	// using the default safety settings before we attempt to read the file.
	{
		var tempLogger atomic.Pointer[slog.Logger]
		tempLogger.Store(log)
		tempFW := wincoe.NewWin11SafeFileWriter(defaultCfg.ExtraSafety, defaultCfg.FileWriterMaxRetries, defaultCfg.FileWriterRetryBackoffMs, &tempLogger)
		tempFW.CheckPowerLossFile(cfgFname)
	}

	data, err := os.ReadFile(cfgFname)
	if err != nil {
		if !os.IsNotExist(err) {
			// Permission denied, locked, or other I/O error — never auto-create
			return nil, nil, false, fmt.Errorf("config file %q exists but cannot be read: %w", cfgFname, err)
		}
		// True "not found"
		if isAdmin {
			return nil, nil, false, fmt.Errorf("config file %q not found; refusing to create a new config file with defaults due to running as Admin!"+
				" because you're likely just in the wrong dir like %%WINDIR%%\\System32\\", cfgFname)
		}

		// not admin, auto create config file with defaults
		//doneFIXME: make sure it's not found not just don't have read permission (but could have write!)
		log.Warn("Config file not found; using defaults and creating new file", slog.String("config_file", cfgFname))
		// Defaults
		// REMOVED: config = DefaultConfig() because it is already set above
		//config = DefaultConfig()
		resolvedCfg = &resolvedTempCfg // XXX: the default config doesn't get template substitution eg. {file:X} or {env:Y}
		//rawCfg = &rawTempCfg
		shouldSaveConfig = true
	} else {
		// Strip "_description_*" keys written by marshalConfigWithDescriptions so that
		// DisallowUnknownFields does not reject them and the duplicate-key scanner
		// does not flag them as anomalies.
		var stripErr error
		data, stripErr = stripConfigDescriptionKeys(data)
		if stripErr != nil {
			return nil, nil, false, fmt.Errorf("failed to strip description keys from config file %q: %w", cfgFname, stripErr)
		}

		// Duplicate config keys (e.g. "extra_safety" appearing twice) are silently
		// last-write-wins in Go's json.Decoder.  Catch them before decoding.
		// cfg.ExtraSafety is not yet populated from the file at this point, so
		// we always treat duplicate config keys as a hard error regardless of that
		// setting — a config with duplicate keys is unambiguously a hand-edit mistake.
		if dups, dupErr := detectDuplicateJSONObjectKeysAtTopLevelOnly(data); dupErr != nil {
			return nil, nil, false, fmt.Errorf("failed to scan config file %q for duplicate keys: %w", cfgFname, dupErr)
		} else if len(dups) > 0 {
			for _, dup := range dups {
				log.Error("Duplicate key found in config file (JSON silently kept only the last value; fix the file manually)",
					slog.String("duplicate_key", dup),
					slog.String("config_file", cfgFname))
			}
			return nil, nil, false, fmt.Errorf("config file %q contains %d duplicate key(s); fix the file and restart", cfgFname, len(dups))
		}

		// 2. First, check for unknown fields and decode into 'config'
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields() // This is why we use NewDecoder
		//var theReadConfig Config = DefaultConfig()

		//nottrueanymoreFIXME: any reload into existing config would race with other readers of config.* values, in theory, as this isn't mutex protected.

		// dec.Decode will now overwrite ONLY the fields present in the JSON.
		// Missing fields will retain the values from DefaultConfig().
		if err = dec.Decode(&rawCfg); err != nil {
			//if err = dec.Decode(&theReadConfig); err != nil {
			log.Error("Config file has typos or unknown fields", slog.String("file", cfgFname), wincoe.SafeErr(err))
			return nil, nil, false, fmt.Errorf("Config has typos or unknown fields: %w", err)
		}

		// rawCfg is the on-disk representation; never clamp/mutate for runtime convenience here.
		//rawCfg = &tempCfg //doneTODO: this assignment and the one in the above 'if' branch, this being the 'else' can be DRY-ed into one assignment before the 'if'

		// resolvedCfg is the runtime representation; tokens expanded, clamping applied below.
		var err3 error
		resolvedCfg, err3 = resolveConfigTags(rawCfg)
		if err3 != nil {
			log.Error("Configuration substitution failed", slog.String("file", cfgFname), wincoe.SafeErr(err3))
			return nil, nil, false, fmt.Errorf("config substitution failed: %w", err3)
		}
		// 3. Second, check for MISSING fields (No manual list!)
		// We decode into a map just to see which keys exist in the JSON.
		var presentKeys map[string]any
		if err2 := json.Unmarshal(data, &presentKeys); err2 != nil {
			panic2(fmt.Sprintf("BUG: shouldn't happen since decoding into Config worked! err:%v", err2))
			//return err
		}

		// 3. Check for MISSING fields
		// Use reflection to compare the struct's "json" tags against the map

		// Use TypeFor[T] (Go 1.22+) and VisibleFields (Go 1.17+)
		missing := []string{}
		t := reflect.TypeFor[Config]()
		// reflect.Indirect safely handles both values and pointers (like *Config)
		v := reflect.Indirect(reflect.ValueOf(resolvedCfg))
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
			log.Warn("Config file has missing keys - using default values for those keys", slog.String("config_file", cfgFname),
				SafeStringSlice("missing", missing),
			)
			shouldSaveConfig = true
		}
	}

	//s.fileWriter.SetExtraSafety(resolvedCfg.ExtraSafety) //uses newly loaded config settings ie. cfg.ExtraSafety
	////s.fileWriter.SetRetryParams(defaultConfig.FileWriterMaxRetries, defaultConfig.FileWriterRetryBackoffMs) Can't do this here because it's not validated yet, good thing sanitizeAndValidateConfig below doesn't use this (assuming logger doesn't either)

	//Use the unified sanitization/validation helper ---
	changed, errVal := sanitizeAndValidateConfig(log, resolvedCfg, rawCfg, &defaultCfg, false)
	if errVal != nil {
		// // Intercept fatal strings and crash exactly as the old code did
		// if strings.HasPrefix(errVal.Error(), "FATAL:") {
		// 	s.logFatal2(strings.TrimPrefix(errVal.Error(), "FATAL: "))
		// }
		return nil, nil, false, errVal
	}
	if changed {
		shouldSaveConfig = true

		{ //if something did change, see if it changes again, then we know defaultConfig() or conditions within sanitize*() are broken!
			//XXX: run it again to see if the defaultConfig() was broken with respect to the conditions within sanitizeAndValidateConfig, because once it passed thru it, if u run it again it wouldn't change anything! this check for defaultConfig() only works on the settings that the prev. run changed! so it won't detect anything if they weren't changed.
			changed2, errVal2 := sanitizeAndValidateConfig(log, resolvedCfg, rawCfg, &defaultCfg, false)
			if errVal2 != nil {
				// // Intercept fatal strings and crash exactly as the old code did
				// if strings.HasPrefix(errVal2.Error(), "FATAL:") {
				// 	s.logFatal2(strings.TrimPrefix(errVal2.Error(), "FATAL: "))
				// }
				return nil, nil, false, errVal2
			}
			if changed2 {
				panic2("BUG: defaultConfig() has values that break the conditions within sanitizeAndValidateConfig, they must be changed; or the conditions in sanitizeAndValidateConfig are inconsistent(less likely)")
			}
		}
	}

	// //(re)apply newly loaded validated/clamped config settings for fileWriter
	// //TODO: make these 2 lines into a helper function and call that here and in another place above
	// s.fileWriter.SetExtraSafety(resolvedCfg.ExtraSafety)
	// s.fileWriter.SetRetryParams(resolvedCfg.FileWriterMaxRetries, resolvedCfg.FileWriterRetryBackoffMs)

	// Enforce password setup if it's missing from the config
	if resolvedCfg.WebUIPasswordHash == "" {
		log.Warn("No WebUI password configured. Securing WebUI now...")
		fmt.Println("\n========================================================")
		fmt.Println("   INITIAL SETUP: SECURING YOUR WEB CONTROL PANEL ")
		fmt.Println("========================================================")
		hash, err2 := promptAndHashPassword(log, resolvedCfg.WebUIPasswordBcryptCost)
		if err2 != nil {
			// s.logFatal2("Failed to setup password (aborted): " + err2.Error())
			// panic2("BUG: unreachable")
			return nil, nil, false, fmt.Errorf("FATAL: failed to setup password (aborted): %w", err2)
		}

		// Update live config instance
		resolvedCfg.WebUIPasswordHash = hash
		rawCfg.WebUIPasswordHash = hash

		log.Info("WebUI password successfully set.")
		if !shouldSaveConfig {
			shouldSaveConfig = true
		}
	}

	// // Apply the fully validated config atomically
	// // 2. APPLY THE VALIDATED CONFIG ATOMICALLY
	// // From this exact microsecond, all new DNS queries will use the clamped, safe config.
	// s.liveRawConfig.Store(rawCfg)
	// s.applyConfig(*resolvedCfg)
	// if shouldSaveConfig {
	// 	// saveConfig internally calls s.getConfig(), which now has the fully updated data
	// 	if err = s.saveConfig(); err != nil {
	// 		return fmt.Errorf("config save failed: %w", err)
	// 	}
	// }
	// 4. LOG STRATEGY
	// Add your new clear architectural description line here:
	switch resolvedCfg.UpstreamSelectionMode {
	case upstreamSelectionModeStrict:
		log.Info("Upstream DNS strategy initialized: STRICT MATCH MODE (All upstreams queried; queries will be safely dropped if response IPs mismatch to protect against manipulation/spoofing; WARNING: Virtually unusable on standard networks due to false-positive drops caused by modern CDNs, Geo-DNS routing, and load balancers returning different IPs for identical queries.).")
	case upstreamSelectionModeFailover:
		log.Info("Upstream DNS strategy initialized: FAILOVER MODE (Sticky sequence tracking; queries the current active upstream and all higher-priority(first in list are higher prio.) failed upstreams in parallel to eliminate timeout penalties while instantly healing and restoring primary upstreams the moment they recover.).")
	case upstreamSelectionModeFastest:
		//nolint:gocritic // Reason: Keeping 'fastest' explicit for readability
		fallthrough
	default:
		log.Info("Upstream DNS strategy initialized: FASTEST WINS MODE (Racing upstreams concurrently; the first successful response is accepted immediately to optimize for CDNs, Geo-DNS, and speed).")
	}
	//so above was load config.json
	return resolvedCfg, rawCfg, shouldSaveConfig, nil
}

// loadDependentStores loads the secondary JSON files (whitelist, blacklist, hosts).
// It assumes the main Config is already safely loaded and applied.
func (s *Server) loadDependentStores() error {
	log := s.getLogger()
	cfg := s.getConfig()
	//func (s *Server) loadConfig() error {
	// var err error = s.loadMainConfig()
	// if err != nil {
	// 	return err
	// }
	// After decoding and applying config, because these use it:
	// 3. LOAD DEPENDENT FILES
	// Now that s.getConfig() returns the NEW config, these will use the correct file paths.
	if err := s.loadQueryWhitelist(); err != nil {
		return err
	} else {
		log.Debug("Whitelist reloaded", slog.String("filename", cfg.WhitelistFile))
	}
	if err := s.loadResponseBlacklist(); err != nil {
		return err
	} else {
		log.Debug("Blacklist reloaded", slog.String("filename", cfg.BlacklistFile))
	}
	if err := s.loadLocalHosts(); err != nil {
		return err
	} else {
		log.Debug("Local hosts reloaded", slog.String("filename", cfg.HostsFile))
	}

	return nil
}

// helper to return host (IP or hostname) from an URL
func hostFromURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("failed to parse rawurl %q err: %w", raw, err /*non-nil*/)
	}
	host := u.Hostname() // Built-in method strips the port safely
	if strings.TrimSpace(host) == "" {
		return "", fmt.Errorf("hostname/IP is empty for %q", raw)
	}
	return host, nil
}

// // SaveConfig safely marshals and writes the configuration to disk.
// // It is completely decoupled from the Server struct.
// func SaveConfig(log *slog.Logger, rawCfg *Config) error {
func (s *Server) saveConfig() error {
	log := s.getLogger()
	//log.Debug("saving config...")

	rawCfg := s.liveRawConfig.Load()
	if rawCfg == nil {
		// Defensive: should never happen in normal operation.
		panic2("BUG: saveConfig called before liveRawConfig was initialised")
	}

	data, err := marshalConfigWithDescriptions(rawCfg)
	if err != nil {
		return fmt.Errorf("config marshal failed: %w", err)
	}
	if err := s.fileWriter.SafeWriteFile(configFileName, data, 0600); err != nil {
		return fmt.Errorf("config write failed: %w", err)
	}
	log.Info("Saved config file", slog.String("config_file", configFileName))
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

// initLogging creates the single log with three destinations.
// Called once after config is loaded (files and console level are known).
func (s *Server) initFullLogging() *slog.Logger {
	cfg := s.getConfig()
	log := s.getLogger()

	consoleLevel := parseConsoleLogLevel(cfg.ConsoleLogLevel)

	var logWriters []*rotatingLogWriter // collected for Close() registration

	// Simple rotation on each log line write (respects your LogMaxSizeMB)
	openLog := func(path string) io.Writer {
		if path == "" {
			panic2("BUG: empty logging filename: '" + path + "'")
		}
		path = filepath.Clean(path)

		writer, err := newRotatingLogWriter(path, cfg.LogMaxSizeMB, log)
		if err != nil {
			// We are still in bootstrap phase → use the bootstrap logger so the error is colored
			log.Error("cannot open log file", slog.String("file", path), wincoe.SafeErr(err))
			s.shutdown(1) // Keep your existing fatal shutdown here if the initial boot fails
			panic2("BUG: unreachable")
		}

		// We can safely trigger a manual size check/rotation on boot here just in case!
		// The next Write() will rotate it automatically anyway if it's over the limit.
		writer.RotateIfNeeded()
		logWriters = append(logWriters, writer) // register for cleanup
		return writer
	}

	fullHandler := slog.NewJSONHandler(openLog(cfg.LogEverythingFile), &slog.HandlerOptions{
		Level:       slog.LevelDebug, // full log gets EVERYTHING
		ReplaceAttr: stripColorTags,  // Strips tags safely for files
	})

	consoleH := NewColoredConsoleHandler(consoleLevel, log) // now uses the real config level

	queryH := queryFilterHandler{
		Handler: slog.NewJSONHandler(openLog(cfg.LogQueriesFile), &slog.HandlerOptions{
			ReplaceAttr: stripColorTags, // Strips tags safely for files
		}),
	}

	improvedLogger := slog.New(multiHandler{ // <-- this REPLACES the global, but it's only used by Server struct and its children
		handlers: []slog.Handler{fullHandler, consoleH, queryH},
	})

	// Reinit closes old rotating writers (if any) and registers the new ones.
	closers := make([]io.Closer, len(logWriters))
	for i, w := range logWriters {
		closers[i] = w
	}
	if err := s.logMgr.Reinit(improvedLogger, closers...); err != nil {
		s.getLogger().Warn("error closing old log files during logger reinit", wincoe.SafeErr(err))
	}

	//s.applyLogger(improvedLogger) // all consumers automatically see the new logger; Reinit now does the atomic store, pluse the 2 lines below
	bugLogger.Store(improvedLogger)
	wincoe.Logger = improvedLogger
	log = s.getLogger() //to use the new logger on the below log line!

	log.Info("Logging initialized",
		slog.String("full_log", cfg.LogEverythingFile),
		slog.String("queries_log", cfg.LogQueriesFile),
		slog.String("console_level", cfg.ConsoleLogLevel),
	)
	return log
}

func getNextLogBackupName(basePath string) string {
	for i := 1; ; i++ {
		backupName := fmt.Sprintf("%s.%d", basePath, i)
		if _, err := os.Stat(backupName); os.IsNotExist(err) {
			return backupName
		}
		// Put a hard cap to avoid infinite loops in extreme edge cases
		if i >= 10000 {
			return fmt.Sprintf("%s.%d", basePath, time.Now().Unix())
		}
	}
}

func countRules(wl map[string][]RuleEntry) uint64 {
	var total uint64 = 0
	for _, rs := range wl {
		total += uint64(len(rs))
	}
	return total
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

func panic2(msg string) {
	getBugLogger().Error(msg)
	panic(msg)
}

// it's assumed that pattern and name are already lowercase(d) or uppercase(d), if not they won't match due to char case difference.
func matchPattern1(pattern, name string) bool {
	if !isLowerASCII(pattern) {
		panic2("BUG: pattern was " + pattern + " which isn't lowercased, so bad coding somewhere!")
	}
	if !isLowerASCII(name) {
		panic2("BUG: name was " + name + " which isn't lowercased, so bad coding somewhere!")
	}

	// Fallback to recursive matching for other tokens ({*}, *, ?, !, literal text)
	return recursiveMatch1(pattern, name)
}

// recursiveMatch handles all tokens recursively.
func recursiveMatch1(pattern, name string) bool {
	for len(pattern) > 0 {
		switch {
		case strings.HasPrefix(pattern, "{**}"):
			// consume 1+ chars including dots
			pattern = pattern[4:]
			if len(name) < 1 {
				return false
			}
			for i := 1; i <= len(name); i++ {
				if recursiveMatch1(pattern, name[i:]) {
					return true
				}
			}
			return false

		case strings.HasPrefix(pattern, "**"):
			// consume 0+ chars including dots
			pattern = pattern[2:]
			if len(name) == 0 {
				return recursiveMatch1(pattern, "")
			}
			for i := 0; i <= len(name); i++ {
				if recursiveMatch1(pattern, name[i:]) {
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
				if recursiveMatch1(pattern, name[i:]) {
					return true
				}
			}
			return false

		case strings.HasPrefix(pattern, "*"):
			// consume 0+ chars, stop at dot
			pattern = pattern[1:]
			if len(name) == 0 {
				return recursiveMatch1(pattern, "")
			}
			for i := 0; i <= len(name); i++ {
				if i < len(name) && name[i] == '.' {
					if recursiveMatch1(pattern, name[i:]) {
						return true
					}
					break
				}
				if recursiveMatch1(pattern, name[i:]) {
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

type tokenKind int

const (
	tokLiteral           tokenKind = iota // Exact character match
	tokStar                               // * (0+ chars, stops at .)
	tokBracketStar                        // {*}  (1+ chars, stops at .)
	tokDoubleStar                         // ** (0+ chars, includes .)
	tokBracketDoubleStar                  // {**} (1+ chars, includes .)
	tokQuestion                           // ?    (exactly 1 char, not .)
	tokExclamation                        // !    (exactly 1 char, any)
)

type patternToken struct {
	kind tokenKind
	char byte // Only used if kind == tokLiteral
}

// tokenizePattern converts the rule pattern into an optimized slice of match actions.
func tokenizePattern(pattern string) []patternToken {
	var tokens []patternToken
	i := 0
	for i < len(pattern) {
		if strings.HasPrefix(pattern[i:], "{**}") {
			tokens = append(tokens, patternToken{kind: tokBracketDoubleStar})
			i += 4
		} else if strings.HasPrefix(pattern[i:], "**") {
			tokens = append(tokens, patternToken{kind: tokDoubleStar})
			i += 2
		} else if strings.HasPrefix(pattern[i:], "{*}") {
			tokens = append(tokens, patternToken{kind: tokBracketStar})
			i += 3
		} else if strings.HasPrefix(pattern[i:], "*") {
			tokens = append(tokens, patternToken{kind: tokStar})
			i += 1
		} else if strings.HasPrefix(pattern[i:], "?") {
			tokens = append(tokens, patternToken{kind: tokQuestion})
			i += 1
		} else if strings.HasPrefix(pattern[i:], "!") {
			tokens = append(tokens, patternToken{kind: tokExclamation})
			i += 1
		} else {
			tokens = append(tokens, patternToken{kind: tokLiteral, char: pattern[i]})
			i += 1
		}
	}
	return tokens
}

// matchPattern implements a strictly bounded, non-recursive wildcard match.
// It maps out state transitions layer-by-layer for each token against the target domain name.
// It is completely immune to stack overflows and exponential backtracking DoS.
func matchPattern(pattern, name string) bool {
	if !isLowerASCII(pattern) {
		panic2("BUG: pattern was " + pattern + " which isn't lowercased, so bad coding somewhere!")
	}
	if !isLowerASCII(name) {
		panic2("BUG: name was " + name + " which isn't lowercased, so bad coding somewhere!")
	}

	if pattern == "" && name == "" {
		return true
	}

	tokens := tokenizePattern(pattern)
	numChars := len(name)

	// We only need two rows to track matching states across token iterations.
	// prevRow tracks matches for tokens[0...i-1]
	// currRow tracks matches for tokens[0...i]
	prevRow := make([]bool, numChars+1)
	currRow := make([]bool, numChars+1)

	// Base case: An empty pattern matches an empty domain string
	prevRow[0] = true

	for _, tok := range tokens {
		// Update the 0-th column: a token can match an empty domain string
		// only if it and all prior tokens are 0-length wildcards.
		if tok.kind == tokStar || tok.kind == tokDoubleStar {
			currRow[0] = prevRow[0]
		} else {
			currRow[0] = false
		}

		for j := 1; j <= numChars; j++ {
			ch := name[j-1]

			switch tok.kind {
			case tokLiteral:
				// Must match exactly
				currRow[j] = prevRow[j-1] && (ch == tok.char)

			case tokQuestion:
				// Exactly 1 char, not '.'
				currRow[j] = prevRow[j-1] && (ch != '.')

			case tokExclamation:
				// Exactly 1 char, unconditionally
				currRow[j] = prevRow[j-1]

			case tokStar:
				// 0+ chars, stops at '.'
				// Match 0 chars (prevRow[j]) OR consume 1+ chars (currRow[j-1]) if not '.'
				currRow[j] = prevRow[j] || (currRow[j-1] && ch != '.')

			case tokDoubleStar:
				// 0+ chars, includes '.'
				// Match 0 chars (prevRow[j]) OR consume 1+ chars unconditionally (currRow[j-1])
				currRow[j] = prevRow[j] || currRow[j-1]

			case tokBracketStar:
				// 1+ chars, stops at '.'
				// Match exactly 1 (prevRow[j-1]) OR >1 (currRow[j-1]), provided it's not '.'
				currRow[j] = (prevRow[j-1] || currRow[j-1]) && (ch != '.')

			case tokBracketDoubleStar:
				// 1+ chars, includes '.'
				// Match exactly 1 (prevRow[j-1]) OR >1 (currRow[j-1]) unconditionally
				currRow[j] = prevRow[j-1] || currRow[j-1]
			}
		}

		// Shift current row states to previous row for the next token cycle
		copy(prevRow, currRow)

		// Explicitly zero out the current row buffer to avoid state leakage
		for j := range currRow {
			currRow[j] = false
		}
	}

	// The final element of prevRow represents whether the full token set matches the full domain
	return prevRow[numChars]
}

// generate a cert that's valid for both local DoH listener and for webUI
func (s *Server) generateCertIfNeeded() {
	log := s.getLogger()
	cfg := s.getConfig()

	log.Debug("check if cert is valid or needs regen")
	certFile := cfg.TLSCertFile
	keyFile := cfg.TLSKeyFile

	needsRegen := false

	var err error
	// Extract the host/IP from the DoH listener address
	dohHost, _, err := net.SplitHostPort(cfg.ListenDoH)
	if err != nil {
		dohHost = cfg.ListenDoH
	}

	// Extract the host/IP from the Web UI listener address
	uiHost, _, err := net.SplitHostPort(cfg.ListenUI)
	if err != nil {
		uiHost = cfg.ListenUI
	}

	//In Go, net.ParseIP is a strict parser. It does not perform DNS lookups; it only checks if the string is a valid IPv4 or IPv6 literal. If you pass it "localhost", it returns nil.

	// STRICT IP ENFORCEMENT: Hostnames are strictly forbidden because
	// they cannot be resolved before this local DNS proxy actually starts.
	if net.ParseIP(dohHost) == nil {
		panic2("BUG: config error: config.ListenDoH host part MUST be an IP literal. Hostnames are forbidden. Invalid value: " + dohHost)
	}

	if net.ParseIP(uiHost) == nil {
		panic2("BUG: config error: config.ListenUI host part MUST be an IP literal. Hostnames are forbidden. Invalid value: " + uiHost)
	}

	// Build the list of requiredHosts/IPs that must be covered by the certificate
	// Build the deduplicated required-hosts slice.
	requiredHosts := []string{dohHost}
	if cfg.WebUIUseTLS && uiHost != dohHost {
		// WebUI host is only relevant when TLS is enabled for the WebUI.
		// When WebUI runs plain HTTP, it never uses s.dohCert, so no SAN needed.
		//also dedup
		requiredHosts = append(requiredHosts, uiHost)
	}

	// 2. Check if cert exists and is still valid for this IP
	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		// File missing or unreadable
		log.Warn("Cert file doesn't exist", slog.String("file", certFile), wincoe.SafeErr(err)) // no \n
		needsRegen = true
	} else {
		// Parse the PEM
		block, _ := pem.Decode(certBytes)
		if block == nil {
			log.Warn("Cert file had empty decoded block.", slog.String("file", certFile)) // no \n
			needsRegen = true
		} else {
			cert, err2 := x509.ParseCertificate(block.Bytes)
			if err2 != nil {
				log.Warn("Cert file failed parsing", slog.String("file", certFile), wincoe.SafeErr(err2)) // no \n
				needsRegen = true
			} else {
				// Verify that ALL required hosts are present in the existing certificate's SAN list
				for _, h := range requiredHosts {
					found := false
					parsedIP := net.ParseIP(h)
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
							if name == h {
								found = true
								break
							}
						}
					}
					if !found {
						log.Warn("Cert identity mismatch", slog.String("want", h), slog.Any("haveIPs", cert.IPAddresses), slog.Any("haveDNSNames", cert.DNSNames))
						needsRegen = true
						break
					}
				}
			}
		}
	}

	// 3. Regen if necessary
	if needsRegen {
		log.Warn("Due to above, regenerating self-signed cert ...", slog.String("public_key_aka_cert_file", certFile), slog.String("private_key_file", keyFile),
			slog.Any("hosts", requiredHosts))
		if err = s.generateCert(certFile, keyFile, requiredHosts); err != nil {
			//done: need to unify logging errors in log and on console somehow, this printf and errorLogger thing is a mess.
			s.logFatal("cert generation failed", err)
			panic2("BUG: unreachable")
		}
		s.certGeneration.Add(1) // <-- Increment here instead of returning true
		// Build proper guidance message based on whether Web UI TLS is enabled
		var msg strings.Builder
		msg.WriteString("Cert generated: make sure you trust it in clients. ")
		if cfg.WebUIUseTLS {
			fmt.Fprintf(&msg, "For browsers, load the Web UI HTTPS URL: https://%s/ and add a certificate exception, or manually trust this endpoint via your browser's Certificate Manager. ", cfg.ListenUI)
		} else {
			fmt.Fprintf(&msg, "Web UI is configured with unencrypted HTTP: http://%s/ . ", cfg.ListenUI)
		}
		fmt.Fprintf(&msg, "For DoH clients, specify the server URL: https://%s/dns-query", cfg.ListenDoH)
		log.Warn(msg.String(),
			slog.String("doh_url", fmt.Sprintf("https://%s/dns-query", cfg.ListenDoH)),
			slog.String(getJSONTagByOffset(unsafe.Offsetof(Config{}.ListenUI)), cfg.ListenUI))
	} else {
		log.Debug("Existing cert is valid for host. Skipping generation.", slog.Any("hosts", requiredHosts))
	}

	// Load cert/key into global for reuse
	log.Info("Loading cert/key for DoH and Web UI...")

	s.dohCert, err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		s.logFatal("cert_load_failed", err)
		panic2("BUG: unreachable")
	}
	log.Info("Success - loaded into tls.Certificate")
}

// 'host' can be localhost or 127.0.0.1 for example, but it won't be looked up!
func (s *Server) generateCert(certFileNameNoPath, keyFileNameNoPath string, hosts []string) error {
	log := s.getLogger()
	if certFileNameNoPath == "" || keyFileNameNoPath == "" {
		panic2("BUG: unexpected empty filename(s) for cert,key: '" + certFileNameNoPath + "','" + keyFileNameNoPath + "'")
	}
	if len(hosts) == 0 {
		panic2("BUG: generateCert: hosts slice is empty — nothing to put in the SAN")
	}
	certFileNameNoPath = filepath.Clean(certFileNameNoPath)
	keyFileNameNoPath = filepath.Clean(keyFileNameNoPath)
	// From crypto/tls/generate_cert.go; edge: Ensure unique serial, valid for 10y
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("key gen failed: %w", err)
	}
	serial := big.NewInt(0)
	// Strip hyphens so it's a valid hex string
	hexUUID := strings.ReplaceAll(uuid.New().String(), "-", "")
	serial.SetString(hexUUID, 16) // Unique serial
	certTemplate := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"DNSbollocks ie. Local DNS Proxy"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour * 10),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,  //"Explicitly write the Basic Constraints extension into the certificate metadata, and mark IsCA as false(or as it's set below)."
		IsCA:                  false, // Defaults to false if not specified
	}

	// Populate IPAddresses and DNSNames dynamically for all requested hosts
	// Deduplicate hosts before adding to SAN to avoid malformed certs.
	seenIPs := make(map[string]struct{})
	seenDNS := make(map[string]struct{})
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			key := ip.String() // normalise e.g. "::1" vs "0:0:0:0:0:0:0:1"
			if _, dup := seenIPs[key]; !dup {
				seenIPs[key] = struct{}{}
				certTemplate.IPAddresses = append(certTemplate.IPAddresses, ip)
			}
		} else {
			if _, dup := seenDNS[host]; !dup {
				seenDNS[host] = struct{}{}
				certTemplate.DNSNames = append(certTemplate.DNSNames, host)
			}
		}
	}
	if len(certTemplate.IPAddresses) == 0 && len(certTemplate.DNSNames) == 0 {
		// All hosts were empty or whitespace after trimming — programmer error.
		panic2(fmt.Sprintf("BUG: generateCert: no valid SANs could be built from hosts %v", hosts))
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("cert create failed: %w", err)
	}

	// not this way: #nosec G304
	certOut, err := os.Create(certFileNameNoPath)
	if err != nil {
		return fmt.Errorf("cert write failed: %w", err)
	} else {
		defer func() {
			if closeErr := certOut.Close(); closeErr != nil {
				log.Error("failed to close cert public key file (incompletely written to disk then?)", wincoe.SafeErr(closeErr), slog.String("filename", certFileNameNoPath))
			}
		}()
	}
	if err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("pem encode cert failed: %w", err)
	}

	//keyOut, err := os.Create(keyFile)
	// 2. Fix the Key Permissions: Replace os.Create(keyFile) with this:
	// not this way: #nosec G304  but this way filepath.Clean(
	keyOut, err := os.OpenFile(keyFileNameNoPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("key write failed: %w", err)
	} else {
		defer func() {
			if closeErr := keyOut.Close(); closeErr != nil {
				log.Error("failed to close cert private key file (incompletely written to disk then?)", wincoe.SafeErr(closeErr), slog.String("filename", keyFileNameNoPath))
			}
		}()
	}
	// Extract the raw bytes explicitly so we can zero them
	privBytes := x509.MarshalPKCS1PrivateKey(priv)

	// Ensure the bytes are wiped from memory when this function exits
	defer clear(privBytes)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("pem encode key failed: %w", err)
	}
	// Prevent the garbage collector from cleaning up the original RSA struct prematurely
	runtime.KeepAlive(priv)
	return nil
}

//type contextKey string

// const clientInfoKey contextKey = "clientInfo"
type clientInfoKey struct{}

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

func (s *Server) makeClientInfoContext(ctx context.Context, protocol string, clientAddr net.Addr, pid uint32, exe string, err error) context.Context {
	log := s.getLogger()

	var services []string
	var serviceInfo string
	if err != nil {
		log.Warn("couldn't get pid and exe name",
			slog.String("proto", protocol),
			//slog.String("clientAddr", clientAddr.String()),
			SafeAddr("clientAddr", clientAddr),
			wincoe.SafeErr(err))
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

	log.Debug("client connected",
		slog.String("proto", protocol),
		//slog.String("clientAddr", clientAddr.String()),
		SafeAddr("clientAddr", clientAddr),
		slog.Int64("pid", int64(pid)),
		slog.String("exe", exe),
		slog.String("services", serviceInfo),
		wincoe.SafeErr(err),
	)

	// Create a specific context for THIS packet
	return context.WithValue(ctx, clientInfoKey{}, clientMetadata{
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
	log := s.getLogger()

	if clientAddr == nil {
		panic2("BUG: nil ClientAddr in handleUDP, not possible?!")
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		// Edge: Invalid packet (common in floods)
		log.Warn("invalid DNS UDP packet (couldn't Unpack) thus dropped/ignored", wincoe.SafeErr(err))
		return
	}
	// 1. EXTRACT MAX UDP SIZE
	// Default to standard 512 bytes, but check if the client provided an EDNS0 OPT record.
	maxUDPSize := 512
	if clientOpt := msg.IsEdns0(); clientOpt != nil {
		maxUDPSize = int(clientOpt.UDPSize())
	}

	resp := s.handleDNSQuery(ctx, msg, clientAddr.String())
	if resp == nil {
		cfg := s.getConfig()
		log.Debug("Dropped UDP DNS response (is BlockMode 'drop' ?)", slog.String("BlockMode", cfg.BlockMode))
		return // BlockMode is "drop", so Drop
	}

	// 2. TRUNCATE IF NECESSARY
	// If the response exceeds the client's max UDP size, miekg/dns will
	// strip excess records and automatically set the TC (Truncated) bit.
	resp.Truncate(maxUDPSize)
	/* press Alt+z in vscode to see long lines wrapped, press again to get back ie. toggle.
	Safe Fallbacks: If maxUDPSize happens to be set dangerously low by a broken client, miekg/dns's .Truncate() method internally enforces the RFC minimum of 512 bytes, so you don't have to worry about adding sanity checks for tiny bounds.
	TCP Handoff: When a large response gets truncated, the client sees the TC bit flip to true. They will immediately drop the UDP response, open a new TCP connection to your server (which hits your handleTCP listener where the limit is 65k bytes), and get the full, untruncated response.
	*/

	pack, err := resp.Pack()
	if err != nil {
		log.Warn("failed to pack DNS UDP packet response thus not sent", wincoe.SafeErr(err))
		return
	}
	wroteN, err := ln.WriteToUDP(pack, clientAddr)
	if err != nil {
		log.Warn("failed to write to UDP the DNS packet response", wincoe.SafeErr(err), slog.Int("wrote_bytes", wroteN), slog.Int("shoulda_written", len(pack)))
		return
	}
}

// is for Incoming Client Connections ie. send us a DNS Query via TCP port 53
func (s *Server) handleTCP(ctx context.Context, conn net.Conn) {
	cfg := s.getConfig()
	log := s.getLogger()

	defer conn.Close() //nolint:errcheck // best-effort close, nothing to do on error

	var timeoutDuration time.Duration = time.Duration(cfg.ClientTCPTimeoutSec) * time.Second
	const maxDNSTCPPacketSize = 65535 //nopeTODO: make this configurable in config.json ; It's the RFC 1035 hard limit (65535); not a tunable

	// --- 1. READ THE LENGTH HEADER ---
	// We give the client 5 seconds to send just these 2 bytes.
	if err1 := conn.SetReadDeadline(time.Now().Add(timeoutDuration)); err1 != nil {
		log.Warn("failed to set read deadline for length header, thus dropped/ignored", wincoe.SafeErr(err1), slog.Duration("deadline", timeoutDuration))
		return
	}

	const TWO = 2
	buf := make([]byte, TWO)
	if n, err := io.ReadFull(conn, buf); err != nil {
		var netErr net.Error
		//if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		if errors.As(err, &netErr) && netErr.Timeout() {
			log.Warn("DNS TCP: client connected but sent no data before deadline "+
				"(idle connection, port scanner, or client that opened then abandoned)",
				SafeAddr("client", conn.RemoteAddr()),
				slog.Duration("read_timeout", timeoutDuration),
			)
		} else {
			log.Warn("couldn't read 2 bytes from TCP DNS connection, thus dropped/ignored",
				wincoe.SafeErr(err),
				slog.Int("read_bytes", n),
				slog.Int("wanted_to_read_bytes", TWO),
				slog.Duration("timeout", timeoutDuration),
			)
		}
		return
	}

	length := int(binary.BigEndian.Uint16(buf))
	if length > cfg.DoHMaxRequestBodyBytes || length == 0 { // Edge: Oversize packet
		log.Warn("invalid packet length in TCP DNS connection, thus dropped/ignored", slog.Int("actual_bytes", length), slog.Int("max", maxDNSTCPPacketSize),
			slog.Int("min", 1))
		return
	}

	// --- 2. READ THE BODY ---
	// We REFRESH the deadline. The client gets a fresh 5 seconds
	// to finish sending the actual DNS message.
	//_ = conn.SetReadDeadline(time.Now().Add(timeoutDuration))
	if err1 := conn.SetReadDeadline(time.Now().Add(timeoutDuration)); err1 != nil {
		log.Warn("failed to set read deadline for body, thus dropped/ignored", wincoe.SafeErr(err1), slog.Duration("deadline", timeoutDuration))
		return
	}
	wire := make([]byte, length)
	if n, err := io.ReadFull(conn, wire); err != nil {
		log.Warn("couldn't read some bytes from TCP DNS connection, thus dropped/ignored", wincoe.SafeErr(err), slog.Int("read_bytes", n), slog.Int("wanted_to_read_bytes", length),
			slog.Duration("timeout", timeoutDuration))
		return
	}

	// --- 3. PROCESS ---
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		log.Warn("invalid DNS TCP packet (couldn't Unpack) thus dropped/ignored", wincoe.SafeErr(err))
		return
	}

	resp := s.handleDNSQuery(ctx, msg, conn.RemoteAddr().String())
	// --- 4. WRITE THE RESPONSE ---
	if resp != nil {
		pack, err1 := resp.Pack() // Ignore err
		if err1 != nil {
			log.Warn("failed to pack DNS TCP packet response thus not sent", wincoe.SafeErr(err1))
			return
		}
		// Prepare the output (length + payload)
		out := new(bytes.Buffer)
		err2 := binary.Write(out, binary.BigEndian, uint16(len(pack))) // Single err return
		if err2 != nil {
			log.Warn("failed to write-to-the-buffer the pack len (2 bytes) of the TCP DNS packet response", wincoe.SafeErr(err2))
			return
		}
		out.Write(pack)
		// Set a WRITE deadline. This prevents a "slow receiver" from
		// hanging your goroutine forever while you try to push data.
		if err3 := conn.SetWriteDeadline(time.Now().Add(timeoutDuration)); err3 != nil {
			log.Warn("failed to set write TCP deadline, thus dropped/ignored", wincoe.SafeErr(err3), slog.Duration("deadline", timeoutDuration))
			return
		}
		wroteN, err4 := conn.Write(out.Bytes())
		if err4 != nil {
			log.Warn("failed to write to TCP the DNS packet response body, thus dropped/ignored", wincoe.SafeErr(err4), slog.Int("wrote_bytes", wroteN),
				slog.Int("shoulda_written", len(pack)), slog.Duration("timeout", timeoutDuration))
			return
		}
		return
	} // else it's nil like if BlockMode is "drop"
	log.Debug("No TCP DNS response to write, likely due to BlockMode being 'drop' ?!")
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
	panic2("BUG: critical system error: failed to generate secure random entropy")
	panic(nil)
}

type CacheEntry struct {
	Msg   *dns.Msg
	State UpstreamState
}

func (s *Server) dohHandler(w http.ResponseWriter, r *http.Request) {
	cfg := s.getConfig()
	log := s.getLogger()

	ctx := r.Context() // Get the request context

	var err error
	// IP verification before resolving
	remoteHost, _, splitErr := net.SplitHostPort(r.RemoteAddr)
	if splitErr != nil {
		remoteHost = r.RemoteAddr
	}
	if net.ParseIP(remoteHost) == nil {
		panic2("BUG: dohHandler: net.ResolveTCPAddr requires an IP. r.RemoteAddr is not a valid IP: " + r.RemoteAddr)
	}

	// 1. Identify the client immediately, before replying.
	//Since you are performing the PID lookup inside the handler (before sending the response), the TCP connection is guaranteed to be in the ESTABLISHED state.
	// Firefox is sitting there waiting for its DNS-over-HTTPS answer, so it's the perfect time to "catch" it in the Windows TCP table.
	remoteTCP, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err == nil {
		log.Debug("client connected(early logging)",
			slog.String("proto", "DoH"),
			//slog.String("clientAddr", remoteTCP.String()),
			SafeAddr("clientAddr", remoteTCP),
		)
		// Use our TCP PID helper
		pid, exe, pErr := wincoe.PidAndExeForTCP(remoteTCP)
		// wincoe.Smashy()
		ctx = s.makeClientInfoContext(ctx, "DoH", remoteTCP, pid, exe, pErr)
	} else {
		log.Warn("DoH: could not resolve remote addr", slog.String("addr", r.RemoteAddr))
		//FIXME: this is a bigger problem than a WARN, if it happens! but an ERROR here would make it mix with the red colored blocked requests, thus harder to be seen!
		//TODO: see if we can trigger this! and/or think of what happens if it happens!
	}

	if r.Method != http.MethodPost && r.Method != http.MethodGet { //"POST" "GET"
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body []byte

	if r.Method == http.MethodPost { //"POST" {
		// Limit incoming DoH payload to 64KB to prevent memory exhaustion attacks
		r.Body = http.MaxBytesReader(w, r.Body, int64(cfg.DoHMaxRequestBodyBytes))
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
	resp := s.handleDNSQuery(ctx, msg, r.RemoteAddr /*field not method*/)
	if resp == nil { //can happen when BlockMode is "drop" so nvmFIXME? "For DoH the HTTP connection is already accepted; 503 is the only correct response for drop mode"
		log.Warn("empty DNS response, replying to client with service unavailable", slog.String("client", r.RemoteAddr))
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	pack, err := resp.Pack()
	if err != nil {
		log.Warn("doh_pack_response_to_client_failed", wincoe.SafeErr(err), slog.String("client", r.RemoteAddr))
		// Return a 500 error to the DoH client
		http.Error(w, "Failed to pack DNS response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Content-Length", fmt.Sprint(len(pack)))
	w.WriteHeader(http.StatusOK)
	wroteN, err := w.Write(pack)
	if err != nil {
		log.Warn("failed to write the DoH reply to client (the DNS packet response body)", wincoe.SafeErr(err), slog.Int("wrote_bytes", wroteN), slog.Int("shoulda_written", len(pack)))
		return
	}
}

func (s *Server) handleDNSQuery(ctx context.Context, msg *dns.Msg, clientAddr string) *dns.Msg {
	cfg := s.getConfig()
	log := s.getLogger()
	//This is the important one — without capturing it once, a reload landing between the cachee-hit check and a later Set for the same request could write into a freshly-swapped (empty) cachee generation while having read from the old one.
	cachee := s.getCache()

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
	if allowed, reason := s.rateLimiter.Allow(clientAddr); !allowed {
		log.Warn(reason, slog.String("client", clientAddr))
		sfr := servfailResponse(msg)
		s.logQuery(ctx, clientAddr, domain, qtype, reason, "", nil, sfr, UpstreamState{Strategy: "rateLimited"})
		return sfr
	}

	matchedID, matched := s.ruleStore.MatchForType(qtype, domain)
	if !matched && cfg.AllowHTTPSIfAAllowed && qtype == "HTTPS" {
		matchedID, matched = s.ruleStore.MatchForType("A", domain)
	}

	if !matched {
		s.stats.Add(1)
		s.recentBlocks.Record(domain, qtype, cfg.MaxRecentBlocks)
		blocked := s.blockResponse(msg)
		s.logQuery(ctx, clientAddr, domain, qtype, blockedSTR, "", nil, blocked, UpstreamState{Strategy: "blockedByLackOfRuleAllowingIt"})
		return blocked
	}

	// Cache (edge: Negative responses cached short)
	key := domain + ":" + qtype

	//fmt.Printf("checking '%s' key in cache\n", key)
	if entry, ok := cachee.Get(key); ok {
		//entry := cachedIf.(CacheEntry)
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
	// Local hosts check (was: s.localHostsMu.RLock / range s.localHosts)
	if matchedIPs, ok := s.hostStore.Match(domain); ok {
		resp := new(dns.Msg)
		resp.SetReply(msg)
		resp.Authoritative = true
		resp.RecursionAvailable = true

		for _, ip := range matchedIPs {
			isIPv4 := ip.To4() != nil

			if qtype == "A" && isIPv4 {
				rr := new(dns.A)
				rr.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: cfg.LocalHostsOverrideTTLSec}
				rr.A = ip
				resp.Answer = append(resp.Answer, rr)
			} else if qtype == "AAAA" && !isIPv4 {
				rr := new(dns.AAAA)
				rr.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: cfg.LocalHostsOverrideTTLSec}
				rr.AAAA = ip
				resp.Answer = append(resp.Answer, rr)
			}
		}

		// Cache this override so subsequent queries bypass the pattern loop
		upstreamState5 := UpstreamState{Strategy: "etc_hosts"}
		cachee.Set(key, CacheEntry{
			Msg:   resp.Copy(),
			State: upstreamState5,
		}, time.Duration(cfg.LocalHostsOverrideTTLSec)*time.Second) //doneTODO: configurable cache time and dns record aka ttl time? (see above)

		s.logQuery(ctx, clientAddr, domain, qtype, localHostOverride, "", extractIPs(resp), resp, upstreamState5)
		return resp
	}
	// --- END Local Hosts Override ---

	// Forward to upstream DNS
	// 1. Save the original client ID
	oldID := msg.Id
	msg.Id = getSecureID() // 2. Generate a random ID for the upstream query (helps prevent cache poisoning)
	// 3. DO THE ACTUAL UPSTREAM QUERY
	resp, upstreamState3 := s.dohForwarder.ForwardToDoH(ctx, msg)
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
		cachee.Set(key, CacheEntry{
			Msg:   negResp.Copy(),
			State: upstreamState3,
		}, time.Duration(cfg.CacheNegativeTTLSec)*time.Second) // time to cache negatives
		return negResp
	}

	//ips := extractIPs(resp) //before 'resp' gets mutated, and its IPs deleted.
	// Use a copy of the original upstream response so we can log exactly what they tried to send
	originalCopy := resp.Copy()
	originalIPs := extractIPs(originalCopy)
	// Filter
	filtered, filterReason := filterResponse(log, resp, cfg.RemoveHTTPSIPv4Hints, getJSONTagByOffset(unsafe.Offsetof(Config{}.RemoveHTTPSIPv4Hints)), s.blacklist) // XXX: resp gets mutated here!
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
	expiry := max(computeTTLForCaching(filtered), time.Duration(cfg.CacheMinTTL)*time.Second)

	// Store a copy in the cache, not the pointer you are about to return
	//cacheStore.Set(key, filtered.Copy(), expiry)
	cachee.Set(key, CacheEntry{
		Msg:   filtered.Copy(),
		State: upstreamState3,
	}, expiry)

	ips := extractIPs(filtered)
	s.logQuery(ctx, clientAddr, domain, qtype, forwardedSTR, matchedID, ips, filtered, upstreamState3)

	return filtered
}

func computeTTLForCaching(msg *dns.Msg) time.Duration {
	//To correctly handle upstream negative caching responses (like NXDOMAIN or NODATA), we need to check both the Answer section and the Ns (Authority) section. Additionally, if an SOA (Start of Authority) record is found in the Authority section, RFC 2308 mandates that the negative cache TTL should be capped by the SOA's Minttl value.
	var minTTL uint32 = 3600 // Default 1 hour,  not: //86400 // 24 hours

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
		minTTL = defaultCacheMinTTL // * time.Second
	}
	if minTTL < cacheMinTTLClamp { //XXX: hardcoded minimum aka floor of 10 seconds TTL
		minTTL = cacheMinTTLClamp
	}
	return time.Duration(minTTL) * time.Second
}

// Version is a global variable that can be overwritten at build time like this: go build -ldflags="-X 'github.com/workturnedplay/dnsbollocks/internal/dnsbollocks.Version=$(git describe --tags --always)'" -o dnsbollocks.exe
// see .\build.bat which does this already.
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
		suffix += "-0." + vcsTime // cantFIXME: Hardcodes the '0' generation counter before the timestamp (can't read/get it apparently) "Go's debug.ReadBuildInfo doesn't expose it; nothing to do" - Claude Sonnet 4.6 Low Thinking
	}
	// Avoid duplicating the hash if the base version string already includes it
	if vcsRevision != "" && !strings.Contains(baseVersion, vcsRevision) {
		suffix += "-" + vcsRevision
	}
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

const templateClientExe = "{builtin:clientexe}"

// Global variable to hold the exact string Go's net/url produces
var templateClientExeEscaped string

func init() {
	// Parse a dummy URL containing the token to see exactly how Go encodes it
	dummy, err := url.Parse("https://localhost/" + templateClientExe)
	if err == nil {
		// dummy.String() yields "https://localhost/%7Bbuiltin:clientexe%7D"
		templateClientExeEscaped = strings.TrimPrefix(dummy.String(), "https://localhost/")
	} else {
		// Fallback just in case
		templateClientExeEscaped = "%7Bbuiltin:clientexe%7D"
	}
}

func (u *Upstream) doSingleDoHRequest(ctx context.Context, reqBytes []byte) (*dns.Msg, error) {
	log := u.getLogger()

	if u.Client == nil {
		panic2(fmt.Sprintf("BUG: dev fail: dohClient is still nil at calling doSingleDoHRequest! shouldn't happen! upstreamURL=%s SNI=%s", u.URL, u.SNI))
	}

	retries := u.Retries //cfg.UpstreamRetriesPerQuery
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
			// reqCtx, cancelReq := context.WithCancel(ctx)
			//NOTTRUEXXX: when the upstream IP is set to Deny in portmaster firewall after it worked before, without this context.WithTimeout it will hang forever until Ctrl+C cancels context then you see all the logs that show it was stuck. This is the only way.
			// 1. Derive a timed-out context from your incoming request context (reqCtx)
			reqCtx, cancelReq := context.WithTimeout(ctx, u.UpstreamClientTimeoutDuration)
			// Crucial: always defer cancel to prevent context leaks!
			// defer cancel() NO

			// If the server shuts down while this request is in-flight, cancel it.
			// stopWatch() frees the AfterFunc's internal resources once we no longer need it.
			stopWatch := context.AfterFunc(u.BackgroundCtx, cancelReq)

			// Use a flag to track if responsibility for calling cancelReq() has been handed off
			var handedOver bool
			defer func() {
				if !handedOver {
					stopWatch() // prevent AfterFunc from firing; safe no-op if already fired
					cancelReq() // Clean up immediately on panic or retryable error
				}
			}()

			// // 2. Spin up a quick monitor to cancel the request if the application shuts down
			// go func() {
			// 	select {
			// 	case <-u.BackgroundCtx.Done(): //this must be Server.ctx or s.ctx former backgroundCtx
			// 		cancelReq() // Aborts the HTTP request immediately on Ctrl+C
			// 	case <-reqCtx.Done():
			// 		// Normal exit when the request finishes or client disconnects
			// 	}
			// }()

			// 3. Pass the merged context to the HTTP request

			// create request with supplied context so caller controls deadline/cancel
			targetURLStr := u.URL.String()
			// Check if the user configured either variant of the placeholder in their upstream URL
			if strings.Contains(targetURLStr, templateClientExe) || strings.Contains(targetURLStr, templateClientExeEscaped) {
				exeName := "unknown-process"

				// Extract the metadata from the context
				if info, ok := ctx.Value(clientInfoKey{}).(clientMetadata); ok && info.exe != "" {
					//// Optionally strip the .exe extension for cleaner NextDNS logs
					//exeName = strings.TrimSuffix(info.exe, ".exe")
					exeName = info.exe

					// URL-encode the executable name to prevent malformed requests
					exeName = url.PathEscape(exeName)
				}

				// Inject the executable name by replacing both potential string variations
				targetURLStr = strings.ReplaceAll(targetURLStr, templateClientExe, exeName)
				targetURLStr = strings.ReplaceAll(targetURLStr, templateClientExeEscaped, exeName)
			}

			// Build the request using the dynamically generated URL
			var e error
			req, e = http.NewRequestWithContext(reqCtx, http.MethodPost /*"POST"*/, targetURLStr, bytes.NewReader(reqBytes))
			if e != nil {
				// Wrap the error to give it context and satisfy wrapcheck
				return true, fmt.Errorf("failed to create DoH HTTP request: %w", e /*non-nil*/)
			}

			req.Header.Set("Content-Type", "application/dns-message")
			if u.SNI != "" {
				req.Host = u.SNI
			}

			log2 := u.getLogger()
			log2.Debug("Attempting request to upstream", slog.String("url", targetURLStr), slog.String("sni", u.SNI))
			// Capture the HTTP client execution
			//nolint:bodyclose // it's closed but later, outside of this func and outside of 'for', if resp != nil only.
			resp, err4ClientDo = u.Client.Do(req) // this is concurrency safe
			if err4ClientDo == nil {
				//success
				//cancelCurrentReq = cancelReq // Hand off the cancellation function to the outer scope
				// Hand ownership to outer scope. stopWatch must also be called there
				// to free AfterFunc resources once the response body is consumed.
				cancelCurrentReq = func() {
					stopWatch()
					cancelReq()
				}
				handedOver = true // Detach this iteration's deferred cleanup
			}
			return false, nil
		}()

		// If NewRequestWithContext failed, abort immediately just like the original logic
		if failedToCreateRequest {
			return nil, errReq
		}

		// If client.Do succeeded, we can stop retrying
		if err4ClientDo == nil { //XXX: if you change or move this, the logic below changes drastically! be careful
			//success!
			break
		}

		//so we're here because the request error-ed

		// decide if error is transient/retryable
		// common retryable errors: temporary network errors, EOF, connection reset
		var netErr net.Error
		isRetryable := errors.Is(err4ClientDo, io.EOF) || errors.Is(err4ClientDo, io.ErrUnexpectedEOF) ||
			errors.Is(err4ClientDo, syscall.ECONNRESET) || // Since you are on Windows, syscall.ECONNRESET is actually mapped to the Windows-specific WSAECONNRESET code internally by the Go net package, so errors.Is will work correctly across platforms if you ever decide to compile this for Linux/macOS too.
			errors.Is(err4ClientDo, syscall.ECONNREFUSED) ||
			(errors.As(err4ClientDo, &netErr) && netErr.Timeout()) //netErr.Timeout(): This is the "official" way to check for timeouts now. It covers both the network dial timing out and your http.Client.Timeout.

		if isRetryable {
			log.Error("doh_post_transient_error for this query", wincoe.SafeErr(err4ClientDo),
				slog.Int("current_try", attempt), slog.Int("max_tries", maxTries),
				//slog.Any("query", req),
				SafeRequestAttr("query", req),
				slog.Bool("will_retry", attempt < maxTries))

			// 🔴 FIX #1: If this was the last attempt, return the REAL error immediately!
			// This prevents falling through to the bottom of the function.
			if attempt >= maxTries {
				return nil, fmt.Errorf("exhausted %d/%d tries to upstream DoH, last request's err: %w", attempt, maxTries, err4ClientDo /*non-nil here*/)
			}
			if u.RetryBackoffDuration <= 0 {
				u.RetryBackoffDuration = time.Duration(100) * time.Millisecond
				log.Warn("BUG: retry backoff timer is set to <= 0 , preventing hang by using 100ms", slog.Duration("retrybackoff_duration", u.RetryBackoffDuration))
			} else if u.RetryBackoffDuration >= time.Duration(5)*time.Second {
				log.Warn("RetryBackoffDuration is >= 5 sec", slog.Duration("retrybackoff_duration", u.RetryBackoffDuration))
			}
			// small backoff: sleep a bit but respect context
			select {
			case <-time.After(u.RetryBackoffDuration):
				log.Debug("Retrying after backoff", SafeRequestAttr("query", req), slog.Duration("retrybackoff_duration", u.RetryBackoffDuration))
				//exits select
			case <-ctx.Done():
				log.Debug("doh sensed client quit during retry backoff...")
				return nil, fmt.Errorf("doh sensed client quit during retry backoff... ctx.err: %w", ctx.Err() /*non-nil guaranteed*/)
			case <-u.BackgroundCtx.Done():
				log.Debug("doh sensed quit during retry backoff...")
				return nil, fmt.Errorf("doh sensed quit during retry backoff... bkgctx.err: %w", u.BackgroundCtx.Err() /*non-nil guaranteed*/)
			}
			continue //next try
		} //if
		// non-retryable error
		// --- NEW DIAGNOSTIC BLOCK ---
		if strings.Contains(err4ClientDo.Error(), "tls:") || strings.Contains(err4ClientDo.Error(), "x509:") {
			log.Error("TLS verification failed when tried to query upstream DNS server",
				slog.String("url", u.URL.String()),
				slog.String("sni_used", u.SNI),
				wincoe.SafeErr(err4ClientDo))

			// Run a manual probe to see what the server is actually sending
			u.logCertDetails() //targetURL.Hostname(), targetURL.Port(), sni)
		} else {
			log.Error("Failed to query upstream DNS server",
				slog.String("url", u.URL.String()),
				slog.String("sni_used", u.SNI),
				wincoe.SafeErr(err4ClientDo))
		}
		// --- END DIAGNOSTIC BLOCK ---
		return nil, fmt.Errorf("failed to send the HTTP request to the upstream DoH server %q, err: %w", u.URL.String(), err4ClientDo /*non-nil here*/)
	} //for retries

	// --- THE CODE BELOW ONLY EXECUTES ON SUCCESSFUL BREAK ---

	// ✅ Ensure the active context gets cancelled when the outer function returns
	if cancelCurrentReq != nil {
		defer cancelCurrentReq()
	}

	if resp == nil {
		// last attempt produced no response (shouldn't happen), treat as failure
		log.Error("doh_no_response")
		return nil, errors.New("no response")
	} else {
		defer resp.Body.Close() //nolint:errcheck // best-effort close, nothing to do on error
	}

	// ✅ This will now execute perfectly! The context is guaranteed to stay alive here.
	body, err4ReadAll := io.ReadAll(resp.Body)
	if err4ReadAll != nil {
		log.Error("doh_readbody_failed", wincoe.SafeErr(err4ReadAll))
		return nil, fmt.Errorf("failed to read upstream DoH response body: %w", err4ReadAll /*non-nil here*/)
	}

	// debug/log non-200 or unexpected content-type
	if resp.StatusCode != 200 {
		log.Error("doh_upstream_status", slog.String("status", resp.Status))
		return nil, fmt.Errorf("upstream status %s", resp.Status)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "application/dns-message" {
		log.Error("doh_upstream_content_type isn't the expected application/dns-message", slog.String("content_type", ct))
	}
	if len(body) < 12 {
		log.Error("doh_upstream_body_too_short", slog.Int("len", len(body)))
	}

	upMsg := new(dns.Msg)
	if err4Unpack := upMsg.Unpack(body); err4Unpack != nil {
		n := len(body)
		log.Error("doh_unpack_failed", wincoe.SafeErr(err4Unpack),
			slog.String("body_hex", fmt.Sprintf("Upstream body (hex, first %d): %x", n, body[:n])),
			slog.String("body_text", fmt.Sprintf("Upstream body (text, first %d): %q", n, body[:n])),
		)
		return nil, fmt.Errorf("failed to unpack response body for upstream DoH %q, err: %w", u.URL.String(), err4Unpack /*non-nil here*/)
	}
	return upMsg, nil
}

func (u *Upstream) logCertDetails() { //(ip, port, sni string) {
	log := u.getLogger()

	port := u.URL.Port()
	if port == "" {
		//TODO: replace all panics with logFatal() ?
		panic2("BUG: dev fail: port is empty but shoulda been set in validateUpstream() to 443")
	}
	addr := net.JoinHostPort(u.URL.Hostname(), port)

	dialer := &net.Dialer{Timeout: time.Duration(u.CertLogTimeoutSec) * time.Second}
	// XXX: We use InsecureSkipVerify: true ONLY for this probe so we can read the cert
	// that was otherwise rejected.
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         u.SNI,
		InsecureSkipVerify: true, //nolint:gosec // needed for what we wanna use this for, read above.
	})

	if err != nil {
		log.Error("Diagnostic probe failed", slog.String("addr", addr), wincoe.SafeErr(err))
		return
	} else {
		defer conn.Close() //nolint:errcheck // best-effort close, nothing to do on error
	}

	state := conn.ConnectionState()
	log.Info("--- TLS Diagnostic Probe ---", slog.String("remote_addr", addr), slog.String("sni_sent", u.SNI))

	for i, cert := range state.PeerCertificates {
		log.Info(fmt.Sprintf("Certificate [%d] in chain", i),
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
	cfg := s.getConfig()

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
	if cfg.BlockAAAAasEmptyNoError && len(msg.Question) > 0 && msg.Question[0].Qtype == dns.TypeAAAA && cfg.BlockMode == blockModeNXDOMAIN {
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
	switch cfg.BlockMode { //XXX: it's already lowercased!
	case blockModeNXDOMAIN:
		msg.SetRcode(msg, dns.RcodeNameError) // this is NXDOMAIN
	case blockModeIPBlock: //, "block_ip", "ipblock", "blockip":
		ttl := cfg.BlockedResponseTTLSec
		qtype := msg.Question[0].Qtype
		switch qtype {
		case dns.TypeA:
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
			rr.A = cfg.BlockIPv4Parsed // Thread-safe shared reference copy
			msg.Answer = []dns.RR{rr}
			msg.SetRcode(msg, dns.RcodeSuccess)
		case dns.TypeAAAA:
			rr := new(dns.AAAA)
			rr.Hdr = dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
			rr.AAAA = cfg.BlockIPv6Parsed // Thread-safe shared reference copy
			msg.Answer = []dns.RR{rr}
			msg.SetRcode(msg, dns.RcodeSuccess)
		default:
			// non A or AAAA during this BlockMode?
			/*
				According to the DNS specifications (RFC 2308), if a domain name exists (i.e., it has an A or AAAA record), a query for any other record type on that same name (like TXT, MX, or SRV) must return NOERROR with an empty answer section (known as a NODATA response).
				If you return NXDOMAIN (Name Error) for a TXT query on a domain where you just returned an IP address for an A query, downstream caching servers or the Windows dnscache service will cache that the entire domain does not exist. This will break your blocking mechanism or cause intermittent resolution failures.
			*/
			// For MX, TXT, etc., return an explicit NODATA response
			// (Success with 0 answers) because the domain "exists" in our ip_block view.
			msg.Answer = []dns.RR{}
			msg.SetRcode(msg, dns.RcodeSuccess)
		}

	case blockModeDrop:
		return nil
	default:
		panic2(fmt.Sprintf("BUG: validated BlockMode reached impossible value, %q", cfg.BlockMode))
		// log := s.getLogger()
		// log.Warn("Unknown BlockMode in config file, falling back to NXDOMAIN", slog.String("blockmode", cfg.BlockMode))
		// // fallback to nxdomain
		// msg.SetRcode(msg, dns.RcodeNameError)
	}

	msg.Authoritative = true
	msg.RecursionAvailable = true

	// Re-allocate the OPT "envelope" but use the static EDE logic

	// 1. ALWAYS create the OPT "envelope" and calculate the safe UDP size.
	// This is a crucial network optimization (EDNS0 Flag Day) that you want
	// to send regardless of whether EDE text is enabled or not.
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

	// Only allocate memory for EDE and set the DNSSEC OK bit if the feature is actually enabled.
	if cfg.UseEDEInBlockedReply {
		opt.SetDo() // Set the "DNSSEC OK" bit; some browsers require this to process OPT records
		// this EDE for firefox, not needed but should be easier for the user to see why DNS didn't work.
		// 1. Manually build the EDE struct using the global variables
		ede := &dns.EDNS0_EDE{
			InfoCode:  edeCode,
			ExtraText: edeText,
		}

		// You can reuse a global EDE struct here IF it is never modified
		opt.Option = []dns.EDNS0{ede}
	}

	// 3. Append the envelope to the response
	msg.Extra = append(msg.Extra, opt)

	return msg
}

const NODATA string = "upstream_nodata"
const BlockedZeroIP string = "blocked_ZeroIP"
const BlockedBlacklistedIP string = "blocked_blacklisted_ip"
const StrippedRRSIG string = "stripped_rrsig"

const BlockedByUpstream string = "blockedByUpstream_ZeroIP"

// mutates the passed arg
func filterResponse(log *slog.Logger, msg *dns.Msg, removeHTTPSIPv4Hints bool, configKeyName string, blacklist IPChecker) (*dns.Msg, string) {
	//log := s.getLogger()

	if msg == nil {
		panic2("BUG: msg was nil, unexpected bad programming/code ;p")
	}
	if len(msg.Question) == 0 {
		panic2("BUG: no DNS question! unexpected bad programming/code ;p")
	}

	q := msg.Question[0]
	qtype := dns.TypeToString[q.Qtype] // Map lookup

	// If upstream naturally returned NOERROR with 0 answers (NODATA), let it through!
	if len(msg.Answer) == 0 && len(msg.Ns) == 0 && len(msg.Extra) == 0 {
		return msg, NODATA
	}

	var dropReasons []string

	// Define a local closure to process any arbitrary DNS section
	filterSection := func(records []dns.RR, sectionName string) []dns.RR {
		var good []dns.RR
		for _, rr := range records {
			if keep, modifiedRR, reason := processRR(log, rr, removeHTTPSIPv4Hints, configKeyName, blacklist); keep {
				good = append(good, modifiedRR)
			} else {
				// Captures and mutates 'dropReasons' from the outer scope automatically
				dropReasons = append(dropReasons, reason)

				log.Warn("Dropped "+sectionName+" from upstream",
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
		log.Warn("response_filtered_all", slog.String("query_type", qtype), slog.String("domain", q.Name),
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
func processRR(log *slog.Logger, rr dns.RR, removeHTTPSIPv4Hints bool, configKeyName string, blacklist IPChecker) (bool, dns.RR, string) {
	// cfg := s.getConfig()
	// log := s.getLogger()

	switch r := rr.(type) {
	case *dns.A:
		if r.A.IsUnspecified() { // Matches 0.0.0.0
			return false, nil, BlockedZeroIP
		}
		if blacklist.Contains(r.A) {
			return false, nil, BlockedBlacklistedIP
		}
		return true, r, ""

	case *dns.AAAA:
		if r.AAAA.IsUnspecified() { // Matches ::
			return false, nil, BlockedZeroIP
		}
		if blacklist.Contains(r.AAAA) {
			return false, nil, BlockedBlacklistedIP
		}
		return true, r, ""

	// Look for HTTPS records (Type 65)
	case *dns.HTTPS:
		//doneTODO: make this configurable in config.json so only if 'true' do this:
		if removeHTTPSIPv4Hints {
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
					log.Warn("Dropping IP hint from the HTTPS reply",
						slog.String("param", param.String() /*non nil*/),
						slog.String("config_filename", configFileName),
						slog.String("config_key_name", configKeyName),
					)
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
	} //switch

	//XXXnolint:unreachable // (can't get rid of warning, so i guess not keeping panic here)
	//panic2("BUG: some unhandled case fell thru from switch/ifelse?")
	//panic(nil)
}

func extractIPs(msg *dns.Msg) []string {
	var ips []string
	if msg != nil { // if BlockMode is not "drop"
		for _, rr := range msg.Answer {
			switch r := rr.(type) {
			case *dns.A:
				ips = append(ips, r.A.String())
			case *dns.AAAA:
				ips = append(ips, r.AAAA.String())
			}
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
func formatColorTags(s, baseColor string) string {
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
	_ = groups
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

// SafeStringSlice returns a race-safe, structured slog.Attr group.
// It explicitly handles string quoting for items with spaces without using reflection.
// All this is to avoid using slog.Any which can race when passed networking structs that are modified by other goroutines
func SafeStringSlice(key string, slice []string) slog.Attr {
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
	log := s.getLogger()

	if ctx == nil {
		log.Error("BUG: bad coding: logQuery called with nil context", // should never happen
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
	//     log.Warn("coding_fail: logQuery called without metadata in context",
	//         slog.String("client", client),
	//         slog.String("domain", domain))
	// } else {
	// --- NEW: Pull the PID/Exe info from the context backpack ---
	if info, ok := ctx.Value(clientInfoKey{}).(clientMetadata); ok {
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
				wincoe.SafeErr(info.err),
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
		log.Warn("coding_fail: logQuery called without metadata in context",
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
	log.Log(ctx, slog.LevelInfo, "logged_query", attrs...)
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

func (ui *AdminUI) responseBlacklistHandler(w http.ResponseWriter, r *http.Request) {
	log := ui.getLogger()

	if r.Method == http.MethodGet { //"GET" {
		cidrs := ui.getResponseBlacklist()
		views := make([]BlacklistView, len(cidrs))
		for i, c := range cidrs {
			views[i] = BlacklistView{Index: i, CIDR: c}
		}
		data := map[string]any{
			"ResponseBlacklist": views,
		}
		ui.renderTemplate(w, r, "response-blacklist", data)
		return
	}

	if r.Method == http.MethodPost { //"POST" {
		action := r.FormValue("action")

		switch action { //doneFIXME: could use tagged switch on action QF1003 default
		case "add":
			cidrStr := strings.TrimSpace(r.FormValue("cidr"))
			if cidrStr != "" {
				_, n, err := net.ParseCIDR(cidrStr)
				if err != nil {
					// Fallback: if they just enter an IP, auto-convert it to CIDR
					ip := net.ParseIP(cidrStr)
					if ip != nil {
						if ip.To4() != nil {
							_, n, _ = net.ParseCIDR(cidrStr + "/32") //nolint:errcheck // IP is already validated above
						} else {
							_, n, _ = net.ParseCIDR(cidrStr + "/128") //nolint:errcheck // IP is already validated above
						}
					}
				}

				if n != nil {
					// Using the clean add helper method with natural defer unlock
					if ui.blacklist.TryAdd(n) { //added so it didn't exist
						log.Info("Successfully added IP/CIDR to response blacklist via WebUI", slog.String("cidr", n.String()))
						if err := ui.OnSaveBlacklist(); err != nil {
							ui.logFatal("failed to save response blacklist after add from webUI", err)
							panic2("BUG: unreachable")
						}
						// Instantly evict cached entries that contain the newly blacklisted IP
						ui.OnInvalidateBlacklist()
					} else {
						log.Warn("Failed to add IP/CIDR to blacklist: already exists", slog.String("cidr", n.String()))
					}
				} else {
					log.Warn("Failed to add IP/CIDR to blacklist: invalid format", slog.String("input", cidrStr))
					http.Error(w, "Invalid IP or CIDR format", http.StatusBadRequest)
					return
				}
			} else {
				log.Warn("Failed to add IP/CIDR to blacklist: empty input")
			}
		case "edit":
			oldCIDR := strings.TrimSpace(r.FormValue("old_cidr"))
			newCIDRStr := strings.TrimSpace(r.FormValue("cidr"))

			if oldCIDR == "" || newCIDRStr == "" {
				log.Warn("Failed to edit blacklist entry: old_cidr and cidr required",
					slog.String("old_cidr", oldCIDR), slog.String("cidr", newCIDRStr))
				http.Error(w, "old_cidr and cidr required", http.StatusBadRequest)
				return
			}

			_, n, err := net.ParseCIDR(newCIDRStr)
			if err != nil {
				ip := net.ParseIP(newCIDRStr)
				if ip != nil {
					var err2 error
					if ip.To4() != nil {
						_, n, err2 = net.ParseCIDR(newCIDRStr + "/32")
					} else {
						_, n, err2 = net.ParseCIDR(newCIDRStr + "/128")
					}
					if err2 != nil {
						panic2("BUG: impossible" + err2.Error())
					}
				}
			}
			if n == nil {
				log.Warn("Failed to edit blacklist entry: invalid IP/CIDR format", slog.String("input", newCIDRStr))
				http.Error(w, "Invalid IP or CIDR format", http.StatusBadRequest)
				return
			}

			// 1. Attempt to update the rule list (Source of Truth) first
			if err := ui.blacklist.TryEdit(oldCIDR, n); err != nil {
				log.Warn("Failed to edit blacklist entry", wincoe.SafeErr(err),
					slog.String("old_cidr", oldCIDR), slog.String("new_cidr", n.String()))
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			log.Info("Successfully edited response blacklist entry via WebUI",
				slog.String("old_cidr", oldCIDR), slog.String("new_cidr", n.String()))

			// 2. Only clear the cache if the edit actually succeeded!
			ui.OnInvalidateBlacklist()

			if err := ui.OnSaveBlacklist(); err != nil {
				ui.logFatal("failed to save response blacklist after edit from webUI", err)
				panic2("BUG: unreachable")
			}
		case "delete":
			cidrStr := strings.TrimSpace(r.FormValue("cidr"))
			// 1. Remove the CIDR from the rules list (Source of Truth)
			// Using the clean delete helper method with natural defer unlock
			if ui.tryDeleteBlacklistIP(cidrStr) { //it got deleted
				log.Info("Successfully deleted IP/CIDR from response blacklist via WebUI", slog.String("cidr", cidrStr))
				// 2. Global flush of the cache so it re-reads the updated rules list
				ui.OnInvalidateBlacklist()
				if err := ui.OnSaveBlacklist(); err != nil {
					ui.logFatal("failed to save response blacklist after delete from webUI", err)
					panic2("BUG: unreachable")
				}
			} else {
				log.Warn("Failed to delete IP/CIDR from blacklist: not found", slog.String("cidr", cidrStr))
			}

		default:
			log.Warn("Response blacklist handler received unknown action", slog.String("action", action))
		} //switch
		http.Redirect(w, r, "/response-blacklist", http.StatusSeeOther)
	}
}

// tryDeleteBlacklistIP removes a CIDR string match from the blacklist slice.
// Returns true if the target was found and deleted, false otherwise.
func (ui *AdminUI) tryDeleteBlacklistIP(cidrStr string) bool {
	return ui.blacklist.TryDelete(cidrStr)
}

// Add this helper to Server
func (ui *AdminUI) checkBlacklistMatches(n *net.IPNet) []string {
	return ui.blacklist.CheckMatches(n)
}

func (ui *AdminUI) responseBlacklistCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	log := ui.getLogger()

	cidrStr := strings.TrimSpace(r.URL.Query().Get("cidr"))
	if cidrStr == "" {
		if _, err := w.Write([]byte(`{"matches":[]}`)); err != nil {
			log.Debug("client disconnected before write completed", wincoe.SafeErr(err))
		}
		return
	}

	// Parse incoming string to a network block
	_, n, err := net.ParseCIDR(cidrStr)
	if err != nil {
		ip := net.ParseIP(cidrStr)
		if ip != nil {
			if ip.To4() != nil {
				_, n, _ = net.ParseCIDR(cidrStr + "/32") //nolint:errcheck // IP is already validated above
			} else {
				_, n, _ = net.ParseCIDR(cidrStr + "/128") //nolint:errcheck // IP is already validated above
			}
		}
	}

	matches := []string{} // 👈 Initialize explicitly empty
	if n != nil {
		matches = ui.checkBlacklistMatches(n)
	}

	// Return array of matching filters to frontend
	if err := json.NewEncoder(w).Encode(map[string][]string{"matches": matches}); err != nil {
		log.Debug("failed to encode/write json response", wincoe.SafeErr(err))
	}
}

// faviconHandler serves an empty response for /favicon.ico.
// Browsers fire this request automatically on every page load, before
// credentials are established.  Returning 204 (rather than letting the
// request fall through to authMiddleware) prevents phantom auth-failure
// log entries and stops those requests from consuming failure-counter
// slots in the login rate limiter.
// 204 is preferred over 404 here: some browsers retry 404 favicon
// aggressively, whereas they treat 204 as "acknowledged, nothing to
// cache" and back off quickly.
func faviconHandler(w http.ResponseWriter, _ *http.Request) {
	// Root-level assets have no ?v= query parameter.
	// Use a 1-day max-age for prod, but bypass completely in local dev.
	cacheCtrl := "public, max-age=86400"
	if v := GetVersion(); strings.Contains(v, "+dirty") || strings.Contains(v, "dev") {
		cacheCtrl = "no-cache, no-store, must-revalidate"
	}

	w.Header().Set("Cache-Control", cacheCtrl)

	//[ ] 404 Not Found Browser retries every ~few minutes across sessions
	//[x] 204 No Content aka http.StatusNoContent Browser backs off quickly; effectively treats it as "I hear you, there's nothing here", but still retries on each page (re)load
	//[ ] 200 + actual .icoBrowser caches per Cache-Control; ideal but requires embedding an icon
	w.WriteHeader(http.StatusNoContent)
}

// robotsTxtHandler serves a permissive disallow-all robots.txt.
// Like favicon.ico, browsers and crawlers may request this automatically.
// Serving it outside auth prevents spurious failure-counter hits.
func (ui *AdminUI) robotsTxtHandler(w http.ResponseWriter, _ *http.Request) {
	cacheCtrl := "public, max-age=86400" // 1-day cache for production crawlers
	if v := GetVersion(); strings.Contains(v, "+dirty") || strings.Contains(v, "dev") {
		cacheCtrl = "no-cache, no-store, must-revalidate"
	}

	w.Header().Set("Cache-Control", cacheCtrl)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("User-agent: *\nDisallow: /\n")); err != nil {
		log := ui.getLogger()
		log.Debug("client disconnected before write completed", wincoe.SafeErr(err))
	}
}

func (ui *AdminUI) SetupRoutes(boundAddr string, usedTLS bool) http.Handler {
	// ── Inner mux: all routes that require authentication ────────────────
	innerMux := http.NewServeMux()
	// 2. Make the / handler strict
	innerMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// If it's literally exactly "/", redirect to the dashboard (e.g., /stats or /logs)
		if r.URL.Path == "/" {
			//load /stats page by default.
			http.Redirect(w, r, "/stats", http.StatusSeeOther)
			return
		}

		// If it's anything else (like /typo), return a standard 404
		http.NotFound(w, r)
	})
	innerMux.HandleFunc("/stats", ui.statsHandler)
	innerMux.HandleFunc("/rules", ui.rulesHandler)
	innerMux.HandleFunc("/hosts", ui.hostsHandler)
	innerMux.HandleFunc("/blocks", ui.blocksHandler) // XXX: changing this "/blocks" requires changing more occurrences in other places in the uiTemplates as well!
	innerMux.HandleFunc("/response-blacklist", ui.responseBlacklistHandler)
	innerMux.HandleFunc("/response-blacklist/check", ui.responseBlacklistCheckHandler)
	innerMux.HandleFunc("/logs", ui.logsHandler)
	innerMux.HandleFunc("/logs_queries", ui.logsQueriesHandler)
	innerMux.HandleFunc("/config", ui.configHandler)
	innerMux.Handle("/debug/vars", expvar.Handler()) // Stats endpoint

	// Determine cache strategy based on build state
	//immutable is safe here specifically because the content is compile-time embedded — a new binary means a new ?v= value means a fresh fetch regardless of what the browser has cached.
	cacheCtrl := "public, max-age=31536000, immutable"
	if v := GetVersion(); strings.Contains(v, "+dirty") || strings.Contains(v, "dev") {
		// Local development mode: force browser to always request the latest file changes
		cacheCtrl = "no-cache, no-store, must-revalidate"
	}

	innerMux.Handle("/static/app.js", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", cacheCtrl)
		http.ServeFileFS(w, r, templates.StaticFS, "app.js")
	}))
	innerMux.Handle("/static/style.css", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", cacheCtrl)
		http.ServeFileFS(w, r, templates.StaticFS, "style.css")
	}))
	innerMux.Handle("/static/arrow-down.svg", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
		// immutable is safe here specifically because the content is compile-time embedded — a new binary means a new ?v= value means a fresh fetch regardless of what the browser has cached.
		w.Header().Set("Cache-Control", cacheCtrl)
		http.ServeFileFS(w, r, templates.StaticFS, "arrow-down.svg")
	}))

	// ── Outer mux: browser-automatic routes that must bypass auth ────────
	// These are requests browsers fire silently before the user has had a
	// chance to enter credentials.  Letting them hit authMiddleware would
	// silently burn failure-counter slots on every single page load.
	outerMux := http.NewServeMux()
	// outerMux.HandleFunc("/favicon.ico", ui.hostValidationFunc(boundAddr, faviconHandler))
	// outerMux.HandleFunc("/robots.txt", ui.hostValidationFunc(boundAddr, robotsTxtHandler))
	outerMux.Handle(
		"/favicon.ico",
		ui.securityHeadersMiddleware(
			ui.fetchMetadataWhitelistMiddleware(
				ui.hostValidationMiddleware(boundAddr, http.HandlerFunc(faviconHandler))),
		),
	)

	outerMux.Handle(
		"/robots.txt",
		ui.securityHeadersMiddleware(
			ui.fetchMetadataWhitelistMiddleware(
				ui.hostValidationMiddleware(boundAddr, http.HandlerFunc(ui.robotsTxtHandler))),
		),
	)

	// Everything else goes through sechead->hostvalid->auth → CSRF → inner mux.
	var h http.Handler = innerMux
	h = ui.csrfMiddleware(h)
	h = ui.originValidationMiddleware(boundAddr, usedTLS, h)
	h = ui.authMiddleware(h)
	h = ui.hostValidationMiddleware(boundAddr, h)
	h = ui.fetchMetadataWhitelistMiddleware(h)
	h = ui.securityHeadersMiddleware(h)
	outerMux.Handle("/", h)
	//outerMux.Handle("/", ui.hostValidation(ui.authMiddleware(ui.csrfMiddleware(innerMux))))
	return outerMux
}
func (ui *AdminUI) fetchMetadataWhitelistMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		site := r.Header.Get("Sec-Fetch-Site")
		mode := r.Header.Get("Sec-Fetch-Mode")

		// 1. If the browser is old and doesn't support Fetch Metadata,
		// let it pass through to your regular CSRF / Origin defenses.
		if site == "" {
			next.ServeHTTP(w, r)
			return
		}

		// 2. WHITELIST: Internal requests & direct user actions
		// - "same-origin": Clicking a button/link inside your own app
		// - "none": User typed the URL in the address bar, clicked a bookmark,
		//   or launched it from a terminal/script.
		/*
			Sec-Fetch-Site
			same-origin: The request was made from the exact same origin (same protocol, domain, and port).
			same-site: The request was made from a same-site origin (e.g., a subdomain like api.example.com fetching from example.com).
			cross-site: The request was made from an entirely different site (e.g., evil.com fetching from your localhost app).
			none: The request was initiated by the user explicitly (e.g., typing the URL into the address bar, clicking a bookmark, or loading a local file).
		*/
		if site == "same-origin" || site == "none" || site == "same-site" {
			next.ServeHTTP(w, r)
			return
		}

		// 3. WHITELIST: Cross-site top-level navigation
		// If another site links to your WebUI, we want to allow the user to
		// actually click that link and land on your page.
		// BUT we ONLY allow it for safe, state-less read methods (GET/HEAD).
		/*
			Sec-Fetch-Mode
			Maps: Used for HTML document navigation requests (e.g., when you click a link to a new page, submit a standard form, or type a URL).
			cors: Used for standard cross-origin requests, like a JavaScript fetch() or Axios call that expects CORS headers.
			no-cors: Used for limited requests that don't require CORS validation, such as loading an image via an <img> tag, a script via <script>, or CSS via <link>.
			same-origin: Used when a request is strictly internal and doesn't need cross-origin logic.
			websocket: Used when establishing a WebSocket connection.
		*/
		if mode == "navigate" && (r.Method == http.MethodGet || r.Method == http.MethodPost || r.Method == http.MethodHead) {
			next.ServeHTTP(w, r)
			return
		}
		if mode == "no-cors" /*favicon.ico*/ && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			next.ServeHTTP(w, r)
			return
		}

		log := ui.getLogger()
		// 4. DENY EVERYTHING ELSE BY DEFAULT
		// This instantly destroys cross-site malicious API calls (fetch/xhr),
		// cross-site form POSTs, iframes, and sneaky <img> tags.
		log.Warn("Blocked unauthorized cross-site request via Fetch Metadata",
			slog.String("path", r.URL.Path),
			slog.String("method", r.Method),
			slog.String("site", site),
			slog.String("mode", mode),
		)
		http.Error(w, "403 Forbidden - Cross-Site Request Blocked", http.StatusForbidden)
	})
}
func (ui *AdminUI) originValidationMiddleware(expectedHost string, useTLS bool, next http.Handler) http.Handler {
	expectedScheme := "http"
	if useTLS {
		expectedScheme = "https"
	}

	expectedOrigin := expectedScheme + "://" + expectedHost

	// isSafeReferer returns true only when the Referer URL's scheme+host
	// exactly matches our expected origin. Used as fallback when Origin is
	// absent or null. Referer can be spoofed by non-browser clients, but
	// that's fine — our CSRF token is the primary mutation guard; this is
	// defence-in-depth for browser-originated requests.
	isSafeReferer := func(ref string) bool {
		if ref == "" {
			return false
		}
		u, err := url.Parse(ref)
		if err != nil {
			return false
		}
		return strings.EqualFold(u.Scheme, expectedScheme) &&
			strings.EqualFold(u.Host, expectedHost)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// // Only protect state-changing requests.
		// switch r.Method {
		// case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		// 	//exit switch
		// default:
		// 	next.ServeHTTP(w, r)
		// 	return
		// }

		// if origin := r.Header.Get("Origin"); origin != "" {
		// 	if origin == "null" { //yes firefox(at least) sends this
		// 		ui.getLogger().Debug("missing origin context ie. it's \"null\" (literally), allowing(for now)",
		// 			slog.String("method", r.Method),
		// 			slog.String("Origin", origin),
		// 			slog.String("expected_Origin", expectedOrigin))
		// 		//allowing
		// 	} else if !strings.EqualFold(origin, expectedOrigin) {
		// 		ui.getLogger().Debug("Invalid Origin",
		// 			slog.String("method", r.Method),
		// 			slog.String("Origin", origin),
		// 			slog.String("expected_Origin", expectedOrigin))
		// 		//disallow
		// 		http.Error(w,
		// 			fmt.Sprintf("Invalid Origin for method %q got: %q expected: %q", r.Method, origin, expectedOrigin),
		// 			http.StatusForbidden)
		// 		return
		// 	}

		// 	//allowing
		// 	next.ServeHTTP(w, r)
		// 	return
		// }

		// // Fallback for clients that omit Origin.
		// if ref := r.Referer(); ref != "" {
		// 	//only if has referer check it
		// 	u, err := url.Parse(ref)
		// 	if err == nil &&
		// 		strings.EqualFold(u.Scheme, expectedScheme) &&
		// 		strings.EqualFold(u.Host, expectedHost) {
		// 		next.ServeHTTP(w, r)
		// 		return
		// 	}
		// }
		// //no origin and no or bad referrer
		// http.Error(w, "Missing or invalid Origin/Referer", http.StatusForbidden)

		log := ui.getLogger()

		//this part is obsolete now
		secFetchSite := r.Header.Get("Sec-Fetch-Site")
		secFetchMode := r.Header.Get("Sec-Fetch-Mode")

		// If the request explicitly comes from a different site (not your UI)...
		if secFetchSite == "cross-site" || secFetchSite == "cross-origin" {
			// ...and it is not a normal top-level page navigation (like typing the URL or clicking a bookmark)
			if secFetchMode != "navigate" {
				log.Warn("Blocked cross-site request via Fetch Metadata",
					slog.String("path", r.URL.Path),
					slog.String("sec_fetch_site", secFetchSite),
				)
				http.Error(w, "403 Forbidden - Cross-Site Request Blocked", http.StatusForbidden)
				return
			}
		}

		origin := r.Header.Get("Origin")

		switch {
		case origin == "null":
			// "null" arrives from two very different sources:
			//
			//   BENIGN:  Firefox emits null for some same-origin form POSTs
			//            (localhost, certain privacy modes, non-TLS origins).
			//            These requests carry a valid same-origin Referer.
			//
			//   ATTACK:  <iframe sandbox="allow-scripts allow-forms"> also
			//            produces a null origin but, crucially, its Referer
			//            policy is "no-referrer", so Referer is empty.
			//
			// Distinguishing them via Referer is therefore sound.
			if isSafeReferer(r.Referer()) {
				log.Debug("null Origin allowed via matching Referer (expected for Firefox same-origin form quirk)",
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.String("referer", r.Referer()),
				)
				next.ServeHTTP(w, r)
				return
			}
			log.Warn("Blocked request with null Origin and missing/mismatched Referer — possible sandboxed-iframe attack",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("referer", r.Referer()),
				slog.String("client", r.RemoteAddr),
			)
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return

		case origin != "":
			// A real Origin header is present. Browsers send this for:
			//   - all cross-origin requests (fetch, XHR)
			//   - same-origin POST/PUT/DELETE/PATCH (most browsers)
			//   - same-origin GET via fetch() — inconsistent across browsers
			//
			// Check it for all methods, not just mutations. A cross-origin
			// fetch() GET with credentials still makes the request even though
			// the response is opaque to the attacker; rejecting it outright is
			// cheaper and cleaner than relying solely on the CORS-header absence.
			if !strings.EqualFold(origin, expectedOrigin) {
				log.Warn("Blocked cross-origin request",
					slog.String("origin", origin),
					slog.String("expected_origin", expectedOrigin),
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.String("client", r.RemoteAddr),
				)
				http.Error(w, "403 Forbidden - cross-origin request rejected", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return

		default:
			// No Origin header at all. Normal for:
			//   - Direct browser navigation (address bar, bookmark, Enter)
			//   - curl / non-browser API clients
			//   - <script src>, <link>, <img> tags (which can't read HTML responses anyway)
			//   - Some same-origin navigations in older browsers
			//
			// For safe (idempotent) methods: allow unconditionally. Cross-origin
			// no-Origin GETs cannot read the response (no CORS headers served),
			// and X-Frame-Options + CSP frame-ancestors block iframe embedding.
			//
			// For mutations (POST etc.): require a valid Referer as a secondary
			// signal. The CSRF token in csrfMiddleware is the primary guard here.
			isSafeMethod := r.Method == http.MethodGet ||
				r.Method == http.MethodHead ||
				r.Method == http.MethodOptions

			if isSafeMethod {
				next.ServeHTTP(w, r)
				return
			}

			if isSafeReferer(r.Referer()) {
				next.ServeHTTP(w, r)
				return
			}

			log.Warn("Blocked mutation request: no Origin header and missing/mismatched Referer",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("referer", r.Referer()),
				slog.String("client", r.RemoteAddr),
			)
			http.Error(w, "403 Forbidden - missing or invalid Origin/Referer", http.StatusForbidden)
			return
		}
	})
}

func (ui *AdminUI) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()

		// Prevent embedding the UI in <iframe>, <frame>, <object>, etc.
		// CSP is the modern standard; X-Frame-Options helps older browsers.
		//h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		//object-src 'none' — disables old plugins (<object>, <embed>). Not hugely relevant today, but harmless and recommended.
		//base-uri 'none' — prevents an injected <base> tag from rewriting relative URLs.
		h.Set("Content-Security-Policy",
			//"default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",//fails loading CSS and js stuff
			//(connect-src 'self' covers the fetch('/response-blacklist/check?...') call you already do client-side.)
			// "default-src 'none'; script-src 'self'; style-src 'self'; "+
			// 	"img-src 'self'; connect-src 'self'; form-action 'self'; "+
			// 	"object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
			"default-src 'none'; "+
				"script-src 'self'; "+
				"style-src 'self'; "+
				"img-src 'self'; "+
				"connect-src 'self'; "+

				/*
					Content-Security-Policy: The page’s settings blocked the loading of a resource (media-src) at data: because it violates the following directive: “default-src 'none'”
					Content-Security-Policy: The page’s settings blocked the loading of a resource (media-src) at data: because it violates the following directive: “media-src http: file:”
				*/
				//"media-src 'self' data:; "+ //(untested) <--- Restores peace with NoScript placeholders XXX: Adding "media-src 'self' data:;" tells the browser: "It's completely fine to execute audio/video tags coming from our own domain or from local data-blobs loaded inside the browser." This satisfies NoScript's safety checks completely, and your console logs will be perfectly quiet again.
				"media-src 'none'; "+ // <--- Explicitly locked down, NoScript will complain like:

				"frame-ancestors 'none'; "+
				"form-action 'self'; "+
				"object-src 'none'; "+
				"base-uri 'none'; ",
		)
		h.Set("X-Frame-Options", "DENY")

		// Prevent MIME sniffing.
		h.Set("X-Content-Type-Options", "nosniff")

		// Never send the page URL in the Referer header when navigating away.
		//h.Set("Referrer-Policy", "no-referrer")//bad, Origin: null for own POSTs won't send any referrer
		h.Set("Referrer-Policy", "same-origin")

		next.ServeHTTP(w, r)
	})
}

func (ui *AdminUI) hostValidationMiddleware(expectedHost string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Host, expectedHost) {
			http.Error(w, "Invalid Host header", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// func (ui *AdminUI) hostValidation(next http.Handler) http.Handler {

// 	//by default use the host:port from config.json
// 	var expected string = ui.getConfig().ListenUI
// 	if boundAddr != "" {
// 		expected = boundAddr
// 	}

// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		if ui.getExpectedHost != nil {
// 			//use the saved boundAddr from startWebUIListenerInstance
// 			expected = ui.getExpectedHost()
// 		}
// 		if !strings.EqualFold(r.Host, expected) {
// 			http.Error(w, "Invalid Host header", http.StatusForbidden)
// 			return
// 		}

// 		next.ServeHTTP(w, r)
// 	})
// }

// const csrfTokenKey contextKey = "csrfToken"
type csrfTokenKey struct{}

func (ui *AdminUI) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log := ui.getLogger()
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
		ctx := context.WithValue(r.Context(), csrfTokenKey{}, token)
		r = r.WithContext(ctx)

		// 3. Validate the token on all state-changing POST requests
		if r.Method == http.MethodPost { //"POST" {
			formToken := r.FormValue("csrf_token")
			if formToken == "" || formToken != token {
				// Capture everything safely in local variables immediately (optional, but clean)
				//because the request is completely isolated to this single thread of execution at this moment, you can read any field or header from r with zero risk of a data race.
				clientIP := r.RemoteAddr
				targetPath := r.URL.Path
				targetHost := r.Host
				originHeader := r.Header.Get("Origin")
				refererHeader := r.Header.Get("Referer")
				userAgent := r.Header.Get("User-Agent")

				log.Warn("CSRF token validation failed; dropping request",
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

func (ui *AdminUI) statsHandler(w http.ResponseWriter, r *http.Request) {
	cfg := ui.getConfig()
	data := map[string]any{
		"Blocks":       ui.stats.String(),
		"UpstreamURLs": cfg.UpstreamURLsParsed,
		"UpstreamSNIs": cfg.UpstreamSNIHostnames,
		"UpstreamIPs":  cfg.UpstreamIPs,
	}
	ui.renderTemplate(w, r, "stats", data)
}

// RuleStore manages the in-memory DNS query whitelist.
// Persistence (loadQueryWhitelist / saveQueryWhitelist) stays on Server.
type RuleStore struct {
	mu    sync.Mutex                             // Serializes writers (Add, Update, Delete, ReplaceAll)
	rules atomic.Pointer[map[string][]RuleEntry] // type -> rules
}

// only use once, before server start, never on reloads(Ctrl+R) tho
func newRuleStore() *RuleStore {
	rs := &RuleStore{}
	empty := make(map[string][]RuleEntry)
	rs.rules.Store(&empty)
	return rs
}

// cloneRuleMap creates a shallow copy of the map.
// The underlying slices are also safe because all our mutators
// (withRulePrepended, withRuleRemovedAt, withRuleUpdatedAtIndex)
// return completely new slice allocations.
func cloneRuleMap(orig map[string][]RuleEntry) map[string][]RuleEntry {
	clone := make(map[string][]RuleEntry, len(orig))
	for k, v := range orig {
		clone[k] = v
	}
	return clone
}

// ReplaceAll atomically swaps in a freshly-loaded/normalized ruleset.
func (rs *RuleStore) ReplaceAll(newRules map[string][]RuleEntry) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.rules.Store(&newRules)
}

// Snapshot returns a full deep copy (for the web UI and for saving).
func (rs *RuleStore) Snapshot() map[string][]RuleEntry {
	// 100% lock-free read
	current := *rs.rules.Load()
	out := make(map[string][]RuleEntry, len(current))
	for key, entries := range current {
		// Copy the slice to prevent modification of the underlying array
		newSlice := make([]RuleEntry, len(entries))
		copy(newSlice, entries)
		out[key] = newSlice
	}
	return out
}

// MatchForType returns (id, true) if an enabled rule in qtype matches domain.
func (rs *RuleStore) MatchForType(qtype, domain string) (id string, ok bool) {
	// 100% lock-free read
	current := *rs.rules.Load()
	for _, rule := range current[qtype] {
		if rule.Enabled && matchPattern(rule.Pattern, domain) {
			return rule.ID, true
		}
	}
	return "", false
}

// CountAll returns the total rule count across all types.
func (rs *RuleStore) CountAll() uint64 {
	// 100% lock-free read
	current := *rs.rules.Load()
	return countRules(current)
}

// AddRule adds a new rule and returns its generated ID.
// Returns an error if a rule with the same pattern already exists for that type.
func (rs *RuleStore) AddRule(typ, pattern string, enabled bool, logger *slog.Logger) (id string, err error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	current := *rs.rules.Load()
	for _, rule := range current[typ] {
		if rule.Pattern == pattern {
			return "", fmt.Errorf("rule with pattern %q already exists for type %s", pattern, typ)
		}
	}
	id = generateUniqueRuleID(current, logger)
	newRule := RuleEntry{ID: id, Pattern: pattern, Enabled: enabled}

	next := cloneRuleMap(current)
	next[typ] = withRulePrepended(next[typ], newRule, logger)
	rs.rules.Store(&next)

	logger.Info("Rule added", slog.String("pattern", pattern), slog.String("type", typ),
		slog.String("id", id), slog.Bool("enabled", enabled))
	return id, nil
}

// DeleteRule removes the rule with the given ID from the given type.
// Returns the deleted pattern (for cache invalidation) or an error if not found.
func (rs *RuleStore) DeleteRule(typ, id string, logger *slog.Logger) (pattern string, err error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	current := *rs.rules.Load()
	rules, ok := current[typ]
	if !ok {
		return "", fmt.Errorf("rule not found: id=%s type=%s", id, typ)
	}
	for i, rule := range rules {
		if rule.ID == id {
			next := cloneRuleMap(current)
			next[typ] = withRuleRemovedAt(rules, i, logger)
			rs.rules.Store(&next)
			return rule.Pattern, nil
		}
	}
	return "", fmt.Errorf("rule not found: id=%s type=%s", id, typ)
}

// UpdateRule finds the rule by ID anywhere in the store, updates it (possibly
// changing its type), and returns the old type and old pattern for cache invalidation.
func (rs *RuleStore) UpdateRule(id, newType, newPattern string, enabled bool, logger *slog.Logger) (oldType, oldPattern string, err error) {
	if id == "" {
		panic2(fmt.Sprintf("BUG: attempted to update a rule with empty id passed-in, rule with newType %q and newPattern %q", newType, newPattern))
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()

	current := *rs.rules.Load()

	var foundType string
	var foundIndex int
	found := false
	for t, rules := range current {
		for i, r := range rules {
			if r.ID == id {
				foundType, foundIndex, oldPattern, found = t, i, r.Pattern, true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		return "", "", fmt.Errorf("rule not found: id=%s", id)
	}

	// Check for duplicate pattern in the target type, excluding the rule being edited.
	for _, rule := range current[newType] {
		if rule.ID != id && rule.Pattern == newPattern {
			return "", "", fmt.Errorf("rule with pattern %q already exists for type %s", newPattern, newType)
		}
	}

	oldType = foundType
	newRule := RuleEntry{ID: id, Pattern: newPattern, Enabled: enabled}

	next := cloneRuleMap(current)

	if foundType == newType {
		// Type didn't change -> Update cleanly
		next[newType] = withRuleUpdatedAtIndex(next[newType], foundIndex, newRule, logger)
	} else {
		// Type changed -> Safely remove from old slice, safely prepend to new slice
		next[foundType] = withRuleRemovedAt(next[foundType], foundIndex, logger)
		next[newType] = withRulePrepended(next[newType], newRule, logger)
	}
	rs.rules.Store(&next)

	logger.Info("Rule updated", slog.String("id", id),
		slog.String("new_pattern", newPattern), slog.Bool("enabled", enabled),
		slog.String("old_pattern", oldPattern))
	return oldType, oldPattern, nil
}

// SetEnabled enables or disables the first rule matching domain+type.
// Returns (found, changed): changed=false when already in the desired state.
func (rs *RuleStore) SetEnabled(typ, domain string, enabled bool) (found, changed bool) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	current := *rs.rules.Load()

	for i, rule := range current[typ] {
		if rule.Pattern != domain {
			continue
		}

		if rule.Enabled == enabled {
			return true, false
		}

		// We can no longer mutate the rule in-place because readers
		// might be actively iterating this slice lock-free!
		next := cloneRuleMap(current)
		updatedRule := rule
		updatedRule.Enabled = enabled
		next[typ] = withRuleUpdatedAtIndex(next[typ], i, updatedRule, nil)
		rs.rules.Store(&next)

		return true, true
	}
	return false, false
}

// HostStore manages local hostname overrides.
type HostStore struct {
	mu    sync.RWMutex
	hosts []LocalHostRule
}

func newHostStore() *HostStore { return &HostStore{} }

func (hs *HostStore) ReplaceAll(hosts []LocalHostRule) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	hs.hosts = hosts
}

// Match returns the IPs for the first rule whose pattern matches domain, or nil.
func (hs *HostStore) Match(domain string) ([]net.IP, bool) {
	hs.mu.RLock()
	defer hs.mu.RUnlock()
	for _, rule := range hs.hosts {
		if matchPattern(rule.Pattern, domain) {
			return rule.IPs, true
		}
	}
	return nil, false
}

// Snapshot returns HostView slices for the web UI.
func (hs *HostStore) Snapshot() []HostView {
	hs.mu.RLock()
	defer hs.mu.RUnlock()
	out := make([]HostView, len(hs.hosts))
	for i, h := range hs.hosts {
		ips := make([]string, len(h.IPs))
		for j, ip := range h.IPs {
			ips[j] = ip.String()
		}
		out[i] = HostView{Index: i, Pattern: h.Pattern, IPsDisplay: strings.Join(ips, ", ")}
	}
	return out
}

// ToRawMap converts the host rules back to a flat map format for serialization.
func (hs *HostStore) ToRawMap() map[string][]string {
	hs.mu.RLock()
	defer hs.mu.RUnlock()

	raw := make(map[string][]string, len(hs.hosts))
	for _, rule := range hs.hosts {
		var ips []string
		// rule.IPs is a slice of net.IP, convert each to string
		for _, ip := range rule.IPs {
			ips = append(ips, ip.String())
		}
		raw[rule.Pattern] = ips
	}
	return raw
}

// AddHost appends a new rule. Returns an error if the pattern already exists.
func (hs *HostStore) AddHost(pattern string, ips []net.IP) error {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	for _, rule := range hs.hosts {
		if rule.Pattern == pattern {
			return fmt.Errorf("local host with pattern %q already exists", pattern)
		}
	}
	hs.hosts = append(hs.hosts, LocalHostRule{Pattern: pattern, IPs: ips})
	return nil
}

// EditHost replaces (old→new). It removes the old pattern (if it differs from new),
// removes any existing rule for the new pattern, then appends the updated rule.
func (hs *HostStore) EditHost(oldPattern, newPattern string, ips []net.IP) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	hs.hosts = deleteHostEntry(hs.hosts, oldPattern)
	hs.hosts = deleteHostEntry(hs.hosts, newPattern) // evict any collision
	hs.hosts = append(hs.hosts, LocalHostRule{Pattern: newPattern, IPs: ips})
}

// DeleteHost removes the rule with the given pattern. Returns true if found.
func (hs *HostStore) DeleteHost(pattern string) bool {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	before := len(hs.hosts)
	hs.hosts = deleteHostEntry(hs.hosts, pattern)
	return len(hs.hosts) < before
}

func (hs *HostStore) Len() int {
	hs.mu.RLock()
	defer hs.mu.RUnlock()
	return len(hs.hosts)
}

// deleteHostEntry is an unexported in-place-safe helper (no lock, caller holds it).
func deleteHostEntry(hosts []LocalHostRule, pattern string) []LocalHostRule {
	for i, rule := range hosts {
		if rule.Pattern == pattern {
			return append(hosts[:i], hosts[i+1:]...)
		}
	}
	return hosts
}

// BlacklistStore manages the response-IP blacklist.
type BlacklistStore struct {
	mu   sync.RWMutex
	nets []*net.IPNet // parsed and ready-to-use form
}

func newBlacklistStore() *BlacklistStore { return &BlacklistStore{} }

func (bs *BlacklistStore) ReplaceAll(nets []*net.IPNet) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.nets = nets
}

func (bs *BlacklistStore) Contains(ip net.IP) bool {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	for _, n := range bs.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Snapshot returns a shallow copy of the raw *net.IPNet pointers for lock-free logic.
func (bs *BlacklistStore) Snapshot() []*net.IPNet {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	cp := make([]*net.IPNet, len(bs.nets))
	copy(cp, bs.nets)
	return cp
}

// List returns a string slice representation of the CIDRs for the Web UI.
func (bs *BlacklistStore) List() []string {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	out := make([]string, len(bs.nets))
	for i, n := range bs.nets {
		out[i] = n.String()
	}
	return out
}

// TryAdd adds the CIDR if not already present. Returns true if added.
func (bs *BlacklistStore) TryAdd(n *net.IPNet) bool {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	for _, existing := range bs.nets {
		if existing.String() == n.String() {
			return false // Already exists
		}
	}
	//bs.nets = append(bs.nets, n)//appends
	// Prepend so newly added entries show up first, mirroring RuleStore.AddRule's behavior.
	bs.nets = append([]*net.IPNet{n}, bs.nets...)
	return true // Added successfully
}

// TryEdit replaces an existing CIDR entry (matched by its exact string form) with a new one,
// moving the edited entry to the front of the list. Returns an error if oldCIDR isn't found,
// or if newNet's string form collides with a different existing entry.
func (bs *BlacklistStore) TryEdit(oldCIDR string, newNet *net.IPNet) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	idx := -1
	for i, existing := range bs.nets {
		if existing.String() == oldCIDR {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("entry not found: %q", oldCIDR)
	}

	newStr := newNet.String()
	if newStr != oldCIDR {
		for i, existing := range bs.nets {
			if i != idx && existing.String() == newStr {
				return fmt.Errorf("entry %q already exists", newStr)
			}
		}
	}

	bs.nets = append(bs.nets[:idx:idx], bs.nets[idx+1:]...)
	bs.nets = append([]*net.IPNet{newNet}, bs.nets...)
	return nil
}

// TryDelete removes the matching CIDR string. Returns true if removed.
func (bs *BlacklistStore) TryDelete(cidrStr string) bool {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	for i, existing := range bs.nets {
		if existing.String() == cidrStr {
			// 1. Slide elements left to overwrite index i
			bs.nets = append(bs.nets[:i], bs.nets[i+1:]...)

			// 2. Clear the old trailing slot to let the Garbage Collector free the memory!
			bs.nets = bs.nets[:len(bs.nets):cap(bs.nets)] // Optional: strictly bounds checking
			if len(bs.nets) < cap(bs.nets) {
				// Since bs.nets shrank by 1, the old last element is at the new len(bs.nets)
				bs.nets[:len(bs.nets)+1][len(bs.nets)] = nil
			}
			return true
		}
	}
	return false
}

// CheckMatches returns all existing CIDRs that are equal to or contain n's IP.
func (bs *BlacklistStore) CheckMatches(n *net.IPNet) []string {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	matches := []string{} // 👈 Initialize explicitly empty
	for _, existing := range bs.nets {
		if existing.String() == n.String() || existing.Contains(n.IP) {
			matches = append(matches, existing.String())
		}
	}
	return matches
}

func (bs *BlacklistStore) Len() int {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return len(bs.nets)
}

// RecentBlocksTracker keeps a bounded LRU of recently blocked queries.
type RecentBlocksTracker struct {
	mu  sync.Mutex
	lst *list.List
	m   map[string]*list.Element
}

func newRecentBlocksTracker() *RecentBlocksTracker {
	return &RecentBlocksTracker{
		lst: list.New(),
		m:   make(map[string]*list.Element),
	}
}

// Record adds or bumps a recent block entry, evicting the oldest if over maxBlocks.
func (t *RecentBlocksTracker) Record(domain, qtype string, maxBlocks int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := domain + ":" + qtype
	if elem, ok := t.m[key]; ok {
		// We already have this block. Update the time and bump it to the front.
		// (Zero allocations!)
		if bq, ok := elem.Value.(*BlockedQuery); ok {
			bq.Time = time.Now()
		} else {
			// Log a severe bug: something else got put in this list!
			panic2("BUG: not of *BlockedQuery type")
		}
		t.lst.MoveToFront(elem)
		return
	}
	// Brand new block. Add to the front of our list and map.
	elem := t.lst.PushFront(&BlockedQuery{Domain: domain, Type: qtype, Time: time.Now()})
	t.m[key] = elem
	// Evict the oldest item if we exceed the tracked limit
	for t.lst.Len() > maxBlocks {
		back := t.lst.Back()
		if back == nil {
			break
		}
		bq, ok := back.Value.(*BlockedQuery)
		if !ok {
			panic2("BUG: not2 of *BlockedQuery type")
		}
		delete(t.m, bq.Domain+":"+bq.Type)
		t.lst.Remove(back)
	}
}

// Snapshot returns a copy of recent blocks, with IsUnblocked populated via the provided checker.
func (t *RecentBlocksTracker) Snapshot(isUnblocked func(domain, qtype string) bool) []BlockedQuery {
	var result []BlockedQuery

	// 1. Lock, copy data under lock, and defer unlock using an anonymous function block
	func() {
		t.mu.Lock()
		defer t.mu.Unlock()

		result = make([]BlockedQuery, 0, t.lst.Len())
		for e := t.lst.Front(); e != nil; e = e.Next() {
			if bq, ok := e.Value.(*BlockedQuery); ok {
				result = append(result, *bq)
			} else {
				panic2("BUG: not of *BlockedQuery type")
			}
		}
	}() // <-- Execute the anonymous function immediately

	// 2. Perform the unblock checks safely outside of the lock
	for i := range result {
		b := &result[i]
		b.IsUnblocked = isUnblocked(b.Domain, b.Type)
	}
	return result
}

// LoginTracker records login failures and enforces per-IP lockout.
type LoginTracker struct {
	mu      sync.Mutex
	records map[string]*loginRecord // guarded by loginMu; lazily cleaned on access
}

func newLoginTracker() *LoginTracker {
	return &LoginTracker{records: make(map[string]*loginRecord)}
}

func (lt *LoginTracker) IsAllowed(clientIP string, maxFailures int) (allowed bool, remaining int, lockedUntil time.Time) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	rec, ok := lt.records[clientIP]
	if !ok {
		return true, maxFailures, time.Time{}
	}
	now := time.Now()
	// Still within an active lockout window?
	if !rec.lockedUntil.IsZero() && now.Before(rec.lockedUntil) {
		return false, 0, rec.lockedUntil
	}
	// Lockout has expired: lazily reset so subsequent checks start clean.
	if !rec.lockedUntil.IsZero() {
		rec.failures = 0
		rec.lockedUntil = time.Time{}
	}
	rem := maxFailures - rec.failures
	if rem < 0 {
		rem = 0
	}
	return true, rem, time.Time{}
}

func (lt *LoginTracker) RecordFailure(clientIP string, maxFailures, lockoutSec int) (lockedOut bool, lockedUntil time.Time, totalFailures int) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	now := time.Now()
	rec, ok := lt.records[clientIP]
	if !ok {
		rec = &loginRecord{}
		lt.records[clientIP] = rec
	}

	// Expired lockout: start a fresh window.
	if !rec.lockedUntil.IsZero() && now.After(rec.lockedUntil) {
		rec.failures = 0
		rec.lockedUntil = time.Time{}
	}

	// Already in an active lockout: report state without incrementing further.
	if !rec.lockedUntil.IsZero() && now.Before(rec.lockedUntil) {
		return true, rec.lockedUntil, rec.failures
	}

	rec.failures++
	totalFailures = rec.failures

	if rec.failures >= maxFailures {
		rec.lockedUntil = now.Add(time.Duration(lockoutSec) * time.Second)
		return true, rec.lockedUntil, totalFailures
	}
	return false, time.Time{}, totalFailures
}

func (lt *LoginTracker) RecordSuccess(clientIP string) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	delete(lt.records, clientIP)
}

// ClearAll wipes all records and returns how many were removed.
func (lt *LoginTracker) ClearAll() int {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	n := len(lt.records)
	lt.records = make(map[string]*loginRecord)
	return n
}

type RuleView struct {
	Type    string
	ID      string
	Pattern string
	Enabled bool
}

func (ui *AdminUI) rulesHandler(w http.ResponseWriter, r *http.Request) {
	log := ui.getLogger()

	if r.Method == http.MethodGet { //"GET" {
		// Flatten the map into a single slice for unified table rendering
		rulesSnapshot := ui.ruleStore.Snapshot() // Safe, independent copy

		// 1. Extract and sort the keys (DNS Types) to stop random UI shuffling
		// Preallocate the slice with the exact capacity needed
		types := make([]string, 0, len(rulesSnapshot))
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
			"DNSTypes": dnsTypes,
			"Rules":    flatRules, // Passing the flattened slice now
		}

		ui.renderTemplate(w, r, "rules", data)
		return
	}

	if r.Method == http.MethodPost { //"POST"
		// Handle delete requests
		if r.FormValue("delete") == "1" {
			id := r.FormValue("id")
			typ := r.FormValue("type")

			if id == "" || typ == "" {
				log.Warn("Failed to delete rule: id and type required", slog.String("id", id), slog.String("type", typ))
				http.Error(w, "id and type required for delete", http.StatusBadRequest)
				return
			}
			if err := validateDNSType(typ); err != nil {
				log.Warn("Failed to delete rule: invalid DNS type", slog.String("type", typ), wincoe.SafeErr(err))
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// id is a UUID used only as a map key; sanitize it against injection just in case.
			if _, modified := sanitizeDomainInput(id); modified {
				log.Warn("Failed to delete rule: id contains illegal characters", slog.String("id", id))
				http.Error(w, "id contains illegal characters", http.StatusBadRequest)
				return
			}

			pattern, err := ui.ruleStore.DeleteRule(typ, id, log)
			if err != nil {
				log.Warn("Failed to delete rule: rule not found", slog.String("id", id), slog.String("type", typ))
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			log.Info("Successfully deleted rule via WebUI", slog.String("id", id), slog.String("type", typ))
			ui.OnInvalidatePattern(pattern)
			if err := /*uses lock*/ ui.OnSaveWhitelist(); err != nil {
				ui.logFatal("failed to save whitelist after rule deletion from webUI", err)
				panic2("BUG: unreachable")
			}
			http.Redirect(w, r, "/rules", http.StatusSeeOther)
			return
		} //end delete

		patternNormalized := NormalizeDomain(r.FormValue("pattern")) //XXX: must be lowercased for matchPattern later on.
		typ := r.FormValue("type")
		id := r.FormValue("id")
		enabledStr := r.FormValue("enabled")
		enabledBool := enabledStr == "on" || enabledStr == "true" || enabledStr == "1"

		if patternNormalized == "" || typ == "" {
			log.Warn("Failed to add/edit rule: Pattern and type required", slog.String("patternLowercased", patternNormalized), slog.String("type", typ))
			http.Error(w, "Pattern and type required", http.StatusBadRequest)
			return
		}

		if err := validateDNSType(typ); err != nil {
			log.Warn("Failed to add/edit rule: invalid DNS type", slog.String("type", typ), wincoe.SafeErr(err))
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := validateRulePattern(patternNormalized); err != nil {
			log.Warn("Failed to add/edit rule: invalid pattern", slog.String("pattern", patternNormalized), wincoe.SafeErr(err))
			http.Error(w, "Invalid pattern: "+err.Error(), http.StatusBadRequest)
			return
		}

		// id, if present, is a UUID; guard it the same way as in the delete path.
		if id != "" { //this is an EDIT attempt
			//     // Edit: Find and update (search all types)
			// --- EDIT MODE ---
			if _, modified := sanitizeDomainInput(id); modified {
				log.Warn("Failed to add/edit rule: id contains illegal characters", slog.String("id", id))
				http.Error(w, "id contains illegal characters", http.StatusBadRequest)
				return
			}
			_, oldPattern, err := ui.ruleStore.UpdateRule(id, typ, patternNormalized, enabledBool, log)
			if err != nil {
				log.Warn("Failed to edit rule", wincoe.SafeErr(err), slog.String("id", id), slog.String("type", typ), slog.String("old_pattern", oldPattern), slog.String("new_pattern", patternNormalized))
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}

			ui.OnInvalidatePattern(oldPattern)
			if oldPattern != patternNormalized {
				ui.OnInvalidatePattern(patternNormalized)
			}
			log.Info("Rule edited via WebUI", slog.String("id", id), slog.String("type", typ), slog.String("new_pattern", patternNormalized), slog.Bool("enabled", enabledBool),
				slog.String("old_pattern", oldPattern))
		} else { // this is an ADD new rule, FIXME: it's implicit (not edit not delete, thus assuming Add!)
			// --- ADD MODE ---
			// // Add new: Prevent duplicate (same type + pattern, case-insensitive)

			newID, err := ui.ruleStore.AddRule(typ, patternNormalized, enabledBool, log)
			if err != nil {
				log.Warn("Failed to add rule", wincoe.SafeErr(err), slog.String("newID", newID), slog.String("type", typ), slog.String("patternLowercased", patternNormalized))
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			ui.OnInvalidatePattern(patternNormalized)
			log.Info("Rule added via WebUI", slog.String("patternLowercased", patternNormalized), slog.String("type", typ), slog.String("newID", newID), slog.Bool("enabled", enabledBool))
		}

		if err := /*uses lock!*/ ui.OnSaveWhitelist(); err != nil {
			ui.logFatal("failed to save whitelist after rule add/edit from webUI", err)
			panic2("BUG: unreachable")
		}
		http.Redirect(w, r, "/rules", http.StatusSeeOther)
	}
}

// withRuleRemovedAt safely returns a new slice with the RuleEntry at the given index removed,
// leaving the original underlying array completely untouched for concurrent readers.
func withRuleRemovedAt(entries []RuleEntry, index int, logger *slog.Logger) []RuleEntry {
	// If the slice is empty or index is out of bounds, return it safely
	if index < 0 || index >= len(entries) {
		return entries
	}

	newEntries := make([]RuleEntry, len(entries)-1)

	// Copy everything up to the index
	copy(newEntries[:index], entries[:index])

	// Copy everything after the index
	copy(newEntries[index:], entries[index+1:])
	if logger != nil { //TODO: many other places need this guard, so maybe make helper ?
		logger.Warn("Deleted rule", slog.Any("rule", entries[index])) // XXX: slog.Any is no longer forbidden for this struct
	}
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

// generateUniqueRuleID generates a UUID not already present in an arbitrary rule map.
// Used by loadQueryWhitelist (which works on a local copy) and by RuleStore methods
// (which call this while holding the write lock).
func generateUniqueRuleID(existingRules map[string][]RuleEntry, logger *slog.Logger) string {
	existing := make(map[string]struct{})
	for _, rules := range existingRules {
		for _, r := range rules {
			existing[r.ID] = struct{}{}
		}
	}
	const triesOnCollision = 10
	for try := 1; try <= triesOnCollision; try++ {
		id := uuid.New().String()[:8] // Grab only the first 8 characters of the UUID
		if _, collision := existing[id]; !collision {
			return id
		}
		logger.Warn("UUID collision in generateUniqueRuleID, regenerating",
			slog.String("id", id), slog.Int("try", try), slog.Int("max_tries", triesOnCollision))
	}
	//panic2(fmt.Sprintf("BUG: UUID collision limit reached(after %d retries) — check RNG or storage", triesOnCollision-1))
	msg := fmt.Sprintf("BUG: UUID collision limit reached(after %d retries) — check RNG or storage", triesOnCollision-1)
	logger.Error(msg, slog.Int("retries", triesOnCollision-1))
	panic(msg)
}

// withRulePrepended safely inserts a new RuleEntry at the beginning of a slice
// without mutating the underlying array of existing readers.
func withRulePrepended(entries []RuleEntry, newRule RuleEntry, logger *slog.Logger) []RuleEntry {
	newTargetEntries := make([]RuleEntry, len(entries)+1)

	// Copy old entries starting at index 1
	copy(newTargetEntries[1:], entries)

	// Drop the new item at index 0
	newTargetEntries[0] = newRule
	if logger != nil {
		logger.Debug("Prepended rule", slog.Any("rule", newRule)) // XXX: slog.Any is no longer forbidden for this RuleEntry struct
	}

	return newTargetEntries
}

// withRuleUpdatedAtIndex safely updates a rule at a specific index without mutating the original array.
func withRuleUpdatedAtIndex(entries []RuleEntry, index int, updatedRule RuleEntry, logger *slog.Logger) []RuleEntry {
	newEntries := make([]RuleEntry, len(entries))
	copy(newEntries, entries)
	oldRule := newEntries[index]
	newEntries[index] = updatedRule
	if logger != nil {
		logger.Debug("Updated rule", slog.Any("new_rule", updatedRule), slog.Any("old_rule", oldRule)) // XXX: slog.Any is no longer forbidden for this RuleEntry struct
	}
	return newEntries
}

type BlacklistView struct {
	Index int
	CIDR  string
}

type HostView struct {
	Index      int
	Pattern    string
	IPsDisplay string // Pre-joined "1.1.1.1, 2.2.2.2"
}

// invalidateCacheForPattern surgically removes any cached DNS responses
// that match the given host pattern (handling wildcards correctly).
func (s *Server) invalidateCacheForPattern(pattern string) {
	c := s.liveDNSCache.Load()
	if c == nil {
		return
	}
	cachee := *c
	log := s.getLogger()

	for key := range cachee.Items() {
		// key format is "domain:type" (e.g., "router.local:A")
		parts := strings.SplitN(key, ":", 2)
		if len(parts) > 0 {
			domain := parts[0]
			if matchPattern(pattern, domain) {
				cachee.Delete(key)
				log.Debug("Evicted cached record due to rule change",
					slog.String("key", key),
					slog.String("matched_pattern", pattern),
					slog.String("domain", domain))
			}
		}
	}
}

func (s *Server) invalidateCacheForBlacklistedIPs() {
	c := s.liveDNSCache.Load()
	if c == nil {
		return
	}
	cachee := *c
	log := s.getLogger()

	// 1. Grab a snapshot of pointers under a microsecond single lock
	//Instead of a single s.blacklist.Contains(ip) call hitting a mutex over and over, you pull the whole list out once into blacklistedNets. Then, inside the loops, you do plain, local array iterations (for _, netEntry := range blacklistedNets).
	blacklistedNets := s.blacklist.Snapshot()

	for key, item := range cachee.Items() { //iterates on a snapshot of cache
		entry, ok := item.Object.(CacheEntry)
		if !ok {
			continue
		}
		msg := entry.Msg
		if msg == nil {
			continue
		}

		shouldEvict := false
		for _, rr := range msg.Answer {
			if aRecord, ok := rr.(*dns.A); ok {
				// 👇 Loop through your snapshot slice lock-free
				for _, netEntry := range blacklistedNets {
					if netEntry.Contains(aRecord.A) {
						shouldEvict = true
						break
					}
				}
			}
			if aaaaRecord, ok := rr.(*dns.AAAA); ok {
				// 👇 Same thing for IPv6 records
				for _, netEntry := range blacklistedNets {
					if netEntry.Contains(aaaaRecord.AAAA) {
						shouldEvict = true
						break
					}
				}
			}
		}

		if shouldEvict {
			cachee.Delete(key)
			log.Debug("Evicted cached response: contained newly blacklisted IP", slog.String("key", key))
		}
	}
}

func (ui *AdminUI) hostsHandler(w http.ResponseWriter, r *http.Request) {
	log := ui.getLogger()

	if r.Method == http.MethodGet { //"GET" {
		// 1 & 2. Get the thread-safe snapshot and build the template data
		data := map[string]any{
			//"Page":  "hosts",
			"Hosts": ui.hostStore.Snapshot(),
		}

		ui.renderTemplate(w, r, "hosts", data)
		return
	}

	if r.Method == http.MethodPost { //"POST" {
		// --- DELETE ---
		if r.FormValue("delete") == "1" {
			patternLowercased := strings.ToLower(strings.TrimSpace(r.FormValue("pattern")))
			if patternLowercased == "" {
				log.Warn("Failed to delete local host: pattern required")
				http.Error(w, "pattern required for delete", http.StatusBadRequest)
				return
			}

			if err := validateRulePattern(patternLowercased); err != nil {
				log.Warn("Failed to delete local host: invalid pattern", slog.String("pattern", patternLowercased), wincoe.SafeErr(err))
				http.Error(w, "Invalid pattern: "+err.Error(), http.StatusBadRequest)
				return
			}

			if ui.hostStore.DeleteHost(patternLowercased) {
				log.Info("Successfully deleted local host override via WebUI", slog.String("pattern", patternLowercased))
				// --- NEW: Invalidate the cache for the deleted pattern ---
				ui.OnInvalidatePattern(patternLowercased)

				if err := ui.OnSaveHosts(); err != nil {
					ui.logFatal("failed to save local hosts after deletion", err)
					panic2("BUG: unreachable")
				}
				http.Redirect(w, r, "/hosts", http.StatusSeeOther)
				return
			}

			log.Warn("Failed to delete local host: host not found", slog.String("pattern", patternLowercased))
			http.Error(w, "host not found", http.StatusNotFound)
			return
		}

		// --- ADD / EDIT ---
		patternLowercased := strings.ToLower(strings.TrimSpace(r.FormValue("pattern")))
		oldPatternLowercased := strings.ToLower(strings.TrimSpace(r.FormValue("old_pattern")))
		isEdit := r.FormValue("edit") == "1"

		if patternLowercased == "" {
			log.Warn("Failed to add/edit local host: hostname required")
			http.Error(w, "hostname/pattern required", http.StatusBadRequest)
			return
		}
		//okTODO: are we accepting a pattern like /rules does here? or is it just a hostname? it's pattern!

		if err := validateRulePattern(patternLowercased); err != nil {
			log.Warn("Failed to add/edit local host: invalid pattern", slog.String("pattern", patternLowercased), wincoe.SafeErr(err))
			http.Error(w, "Invalid pattern: "+err.Error(), http.StatusBadRequest)
			return
		}
		// old_pattern (edit path) needs the same check.
		if isEdit && oldPatternLowercased != "" {
			if err := validateRulePattern(oldPatternLowercased); err != nil {
				log.Warn("Failed to edit local host: invalid old_pattern", slog.String("old_pattern", oldPatternLowercased), wincoe.SafeErr(err))
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
				log.Warn("Failed to add/edit local host: invalid IP address", slog.String("ip", ipStr))
				http.Error(w, "invalid IP address: "+ipStr, http.StatusBadRequest)
				return
			}
		}

		if len(netIPs) == 0 {
			log.Warn("Failed to add/edit local host: no valid IP required", slog.String("pattern", patternLowercased))
			http.Error(w, "at least one valid IP required", http.StatusBadRequest)
			return
		}

		var err error = nil
		if isEdit {
			ui.hostStore.EditHost(oldPatternLowercased, patternLowercased, netIPs)
		} else {
			//it's Add (Delete was handled above)
			err = ui.hostStore.AddHost(patternLowercased, netIPs)
		}

		if err != nil {
			log.Warn("Failed to add/edit local host:", wincoe.SafeErr(err), slog.String("pattern", patternLowercased), slog.Any("IPs", netIPs))
			http.Error(w, "Local host with this pattern already exists", http.StatusConflict)
			return
		}

		// --- NEW: Cache Invalidation ---
		// If this was an edit, purge the old pattern's cached entries, if different than new pattern
		if isEdit && oldPatternLowercased != "" && oldPatternLowercased != patternLowercased {
			ui.OnInvalidatePattern(oldPatternLowercased)
		}
		// Always purge the new pattern so the local override takes immediate effect
		// (e.g., clearing out previous NXDOMAINs or external IPs)
		ui.OnInvalidatePattern(patternLowercased) //doneFIXME: pattern here could be same as oldPattern, avoid purging twice?
		// -------------------------------
		log.Info("Successfully added/edited local host override via WebUI", slog.String("pattern", patternLowercased), slog.Int("ip_count", len(netIPs)))

		if err := ui.OnSaveHosts(); err != nil {
			ui.logFatal("failed to save local hosts after add/edit", err)
			panic2("BUG: unreachable")
		}

		http.Redirect(w, r, "/hosts", http.StatusSeeOther)
	}
}

// renderTemplate is a DRY helper to execute templates safely into a buffer
// before writing to the network, preventing "established connection aborted" errors
// from being logged as template execution failures.
func (ui *AdminUI) renderTemplate(w http.ResponseWriter, r *http.Request, pageName string, data map[string]any) {
	log := ui.getLogger()
	data["Page"] = pageName //Page aka TemplateName (tho the latter isn't used, but AI might suggest it mistakenly)
	data["Path"] = r.URL.Path
	data["Version"] = GetVersion() //cache-busting

	// Inject the CSRF token into the map
	if token, ok := r.Context().Value(csrfTokenKey{}).(string); ok {
		data["CSRFToken"] = token
	}

	var buf bytes.Buffer
	if err := ui.uiTemplates.Execute(&buf, data); err != nil {
		log.Error("template_render_failed",
			slog.String("page", pageName),
			wincoe.SafeErr(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Set content type before writing the buffer
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if _, err := buf.WriteTo(w); err != nil {
		// Log as Debug/Info because this is usually just a client (browser)
		// closing the connection or refreshing the page mid-download.
		log.Debug("client_disconnected_during_ui_write",
			slog.String("page", pageName),
			wincoe.SafeErr(err))
	}
}

func (ui *AdminUI) getRecentBlocksCopy() []BlockedQuery {
	snapshot := ui.ruleStore.Snapshot()
	return ui.recentBlocks.Snapshot(func(domain, qtype string) bool {
		// Check whitelist to see if these domains are currently unblocked
		for _, rule := range snapshot[qtype] { //TODO: parsing all rules to find the matching one is ugly/slow, in theory, maybe a hash set would be better ? (or keeping it in a hashset as well? if so, keep it in an ordered list too, and appends kept at top(due to UI having Add Rule be at top of page))
			if rule.Pattern == domain && rule.Enabled {
				return true
			}
		}
		return false
	})
}

func (ui *AdminUI) blocksHandler(w http.ResponseWriter, r *http.Request) {
	log := ui.getLogger()

	if r.Method == http.MethodGet { //"GET" {
		data := map[string]any{
			//"Page":           "blocks",
			"Blocks":         ui.getRecentBlocksCopy(),
			"SuccessMessage": r.URL.Query().Get("success"),
			"ErrorMessage":   r.URL.Query().Get("error"),
			"EnteredValue":   r.URL.Query().Get("val"),
		}

		ui.renderTemplate(w, r, "blocks", data)
		return
	}
	if r.Method == http.MethodPost { //"POST" {
		raw := r.FormValue("domain")

		sanitized, modified := sanitizeDomainInput(raw)

		if modified || !isValidDNSName(sanitized) { // XXX: doesn't expect a pattern via Quick Unblock here, but an actual valid DNS query domain (and without ending in a dot)
			log.Warn("Invalid domain input submitted via Quick Unblock",
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
			switch action {
			case "reblock":
				found, changed := ui.ruleStore.SetEnabled(typ, domainLowercased, false)
				if found && changed {
					successMessage = fmt.Sprintf("Successfully re-blocked: paused rule for %s (%s).", domainLowercased, typ)
					log.Info("Quick re-block via WebUI: paused existing rule",
						slog.String("domainLowercased", domainLowercased),
						slog.String("DNSType", typ))
					ui.OnInvalidatePattern(domainLowercased)
				} else if found {
					successMessage = fmt.Sprintf("Rule for %s (%s) is already paused.", domainLowercased, typ)
				}
			case "unblock":
				found, changed := ui.ruleStore.SetEnabled(typ, domainLowercased, true)
				if found && changed {
					successMessage = fmt.Sprintf("Successfully unblocked: activated existing paused rule for %s (%s).", domainLowercased, typ)
					log.Info("Quick unblock via WebUI: enabled existing paused rule",
						slog.String("domainLowercased", domainLowercased),
						slog.String("DNSType", typ))
					ui.OnInvalidatePattern(domainLowercased)
				} else if found {
					successMessage = fmt.Sprintf("Rule for %s (%s) is already active.", domainLowercased, typ)
					log.Info("Quick unblock via WebUI: ignored, rule is already active",
						slog.String("domainLowercased", domainLowercased),
						slog.String("DNSType", typ))
				} else {
					newID, addErr := ui.ruleStore.AddRule(typ, domainLowercased, true, log)
					if addErr == nil {
						_ = newID
						successMessage = fmt.Sprintf("Successfully unblocked: added new active rule for %s (%s).", domainLowercased, typ)
						log.Info("Quick unblock via WebUI: added new rule(ie. didn't already exist)",
							slog.String("domainLowercased", domainLowercased),
							slog.String("DNSType", typ))
						ui.OnInvalidatePattern(domainLowercased)
					} else {
						panic2(fmt.Sprintf("BUG: couldn't AddRule because already exists which means logic is broken as it shouldn't exist here, or some other error happened in AddRule, typ %s domainLowercased %s", typ, domainLowercased))
					}
				}
			default:
				log.Warn("Failed quick unblock/reblock via WebUI: invalid action specified", slog.String("action", action))
				// Reject any unauthorized or malformed action values
				http.Error(w, "Invalid action specified", http.StatusBadRequest)
				return //oh this was bugged before, it was exitting only the inner anon-func!
			} //switch

			if err := /*uses lock*/ ui.OnSaveWhitelist(); err != nil {
				ui.logFatal("failed to save whitelist after rule that was blocked was deleted from the blocks handler in webUI", err)
				panic2("BUG: unreachable")
			}
			http.Redirect(w, r, "/blocks?success="+url.QueryEscape(successMessage), http.StatusSeeOther)
			return
		}

		payloadDetails := fmt.Sprintf("Missing or corrupted data. (Processed Domain: %q, Type: %q)", domainLowercased, typ)

		log.Warn("Failed quick unblock/reblock via WebUI: missing domain or type", slog.String("domain", domainLowercased), slog.String("type", typ))

		// renderTemplate(w, "blocks", data)
		errMsg := "Failed to process unblock request. " + payloadDetails
		http.Redirect(w, r, "/blocks?error="+url.QueryEscape(errMsg), http.StatusSeeOther)

		return
	}
}

func (ui *AdminUI) renderLogPage(w http.ResponseWriter, r *http.Request, title, filePath, filter string) {
	cfg := ui.getConfig()
	log := ui.getLogger()

	file, err := os.Open(filePath)
	if err != nil {
		// Fallback if file doesn't exist yet
		ui.renderTemplate(w, r, "logs", map[string]any{
			//"Page": "logs",
			//"Path":  r.URL.Path,
			"Title": title, "Filter": filter, "Content": "No log entries found.",
		})
		return
	} else {
		defer func() {
			if closeErr := file.Close(); closeErr != nil {
				log.Error("failed to close log file", wincoe.SafeErr(closeErr), slog.String("filename", filePath))
			}
		}()
	}

	searchLower := strings.ToLower(filter)

	// Cap the output to the last 5000 matches to save RAM and prevent browser crashes
	var maxLines = cfg.UILogMaxLines
	ring := make([]string, maxLines)
	count := 0

	// 1. Get stats and check size
	var didSeek bool
	stat, err := file.Stat()
	if err == nil {
		const maxReadBytes = 20 * 1024 * 1024 // 20MB Lookback Limit
		if stat.Size() > maxReadBytes {
			startOffset := stat.Size() - maxReadBytes
			// 2. Seek to the lookback offset with error checking
			if _, err2 := file.Seek(startOffset, io.SeekStart); err2 == nil {
				didSeek = true
			} else {
				log.Warn("failed to seek ahead in log", slog.String("log_file", filePath), slog.Int64("seek_to_offset", startOffset))
				// Fallback: If seeking fails, reset to the beginning so the UI doesn't break
				if _, err3 := file.Seek(0, io.SeekStart); err3 != nil {
					log.Warn("failed to seek back to beginning in log", slog.String("log_file", filePath))
				}
			}
			// // Read until the next newline to ensure we don't parse a truncated string
			// bufio.NewReader(file).ReadBytes('\n')
			/*
				When you instantiate a temporary bufio.NewReader(file), it creates an internal buffer (typically 4KB) and eagerly reads a large block from the file to satisfy your ReadBytes('\n') request.
				Even if your first newline is only 50 bytes away, the remaining ~4046 bytes inside that reader's internal buffer are thrown away when the object is discarded. When you call scanner := bufio.NewScanner(file) right after, the scanner reads from the file descriptor's current position (which has advanced by 4KB), causing a chunk of your logs to silently disappear from the WebUI.
			*/
		}
	}

	// Stream the file line-by-line instead of loading it all at once
	scanner := bufio.NewScanner(file)
	// This tells the scanner:
	// 1. Start with a 64KB internal buffer.
	// 2. Allow it to grow automatically up to 1MB if it finds a very long line.
	const maxCapacity = 1024 * 1024 // 1 MB
	lineBuf := make([]byte, 2*1024) // 2 KB initial size
	scanner.Buffer(lineBuf, maxCapacity)

	// 4. If we successfully jumped into the middle of a large file,
	// discard the very first scanned line since it's likely truncated.
	if didSeek {
		if !scanner.Scan() {
			if parseErr := scanner.Err(); parseErr != nil {
				// Fallback: If scanning the first chunk fails, you could log it
				// or reset, though scanner will stop execution gracefully.\
				log.Warn("failed to read the first line after seeking in the log", slog.String("log_file", filePath), wincoe.SafeErr(parseErr))
			}
		}
	}

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
		if errors.Is(err, bufio.ErrTooLong) {
			log.Error("A log line exceeded the bytes-per-line limit", slog.Int("line_limit_bytes", maxCapacity), slog.Int("line_number", count), slog.String("filename", filePath))
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
		"Title":   title,
		"Filter":  filter,
		"Content": content,
	}

	ui.renderTemplate(w, r, "logs", renderData)
}

func (ui *AdminUI) logsQueriesHandler(w http.ResponseWriter, r *http.Request) {
	cfg := ui.getConfig()

	filter := r.URL.Query().Get("q")
	//no:// If they used the old 'domain' param, support it as a fallback
	// if filter == "" {
	//     filter = r.URL.Query().Get("domain")
	// }

	ui.renderLogPage(w, r, "Query Logs", cfg.LogQueriesFile, filter)
}

func (ui *AdminUI) logsHandler(w http.ResponseWriter, r *http.Request) {
	cfg := ui.getConfig()
	filter := r.URL.Query().Get("q")
	ui.renderLogPage(w, r, "System & Error Logs", cfg.LogEverythingFile, filter)
}

func (s *Server) shutdown(exitCode int) {
	log := s.getLogger()

	s.shutdownOnce.Do(func() { //guarantees that the code inside the function runs exactly once.
		log.Info("Shutting down...")
		// 1. Cancel the context immediately so all other listeners stop
		s.cancel() //Calling cancel() multiple times is perfectly safe and is actually the expected behavior in Go. In case anything else just called cancel() itself (should be currently happening)
		log.Debug("Context cancelled... this triggers DoH and webUI shutdowns in their own goroutines!")

		s.flushCache()
		//doneTODO: webUI shutdown (done via cancel() above)
		//log.Debug("webUI shutdown(fake)")
		//sleep 1 sec to allow "quitting on shutdown" message to show.
		// Wait 1 sec to allow graceful HTTP shutdowns and the "quitting" messages to show
		//time.Sleep(1000 * time.Millisecond)
		// ADD: Wait for all registered goroutines to signal they've exited
		log.Debug("Waiting for goroutines to finish...")
		s.shutdownWG.Wait()
		log.Debug("All goroutines exited.")
		//log.Debug("waited 1 sec for port cleanup")

		// UnstickStdinRead(log)
		// if !wincoe.WaitAnyKeyIfInteractive() {
		// 	log.Debug("Didn't wait for keypress due to not an interactive/terminal.")
		// }
		// //bufio.NewReader(os.Stdin).ReadBytes('\n') //done: make it for any key not just Enter!
		// log.Info("exitting with exit code", slog.Int("exitCode", exitCode))
		// os.Exit(exitCode)
		finalShutdownSequence(log, exitCode, s.exitFn)
		panic2("BUG: shoulda been unreachable after finalShutdownSequence, which means it didn't os.Exit!")
	})
	panic2("BUG: shoulda been unreachable after s.shutdownOnce.Do")
}

func finalShutdownSequence(logger *slog.Logger, exitCode int, exitFn func(int)) {
	UnstickStdinRead(logger)
	// NEW: Check if the OS is forcefully terminating us
	if skipInteractivePause.Load() {
		logger.Debug("Skipping 'Press any key' pause because OS is forcefully terminating the session.")
	} else { //nolint:gocritic // i want the braces
		// Normal exit (like Ctrl+C or clean UI shutdown) - pause as usual
		if !wincoe.WaitAnyKeyIfInteractive() {
			logger.Debug("Didn't wait for keypress due to not an interactive/terminal.")
		}
	} //ifelse

	logger.Info("exitting with exit code", slog.Int("exitCode", exitCode))
	//os.Exit(exitCode)
	exitFn(exitCode)
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
		//log.Debug("sent1")
	default:
		// Already shutting down
	}
	//log.Debug("cont2")
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
	} else {
		// This defer is critical! It ensures the terminal exits RAW mode
		// when the goroutine finishes, preventing a corrupted command prompt.
		defer func() {
			log2 := s.getLogger()
			if err := term.Restore(fd, oldState); err != nil {
				log2.Warn("failed to restore terminal state", wincoe.SafeErr(err))
			}
		}()
	}

	buf := make([]byte, 3)

	for {
		log2 := s.getLogger()
		// 1. Check if an external fatal error triggered a shutdown
		select {
		case <-signalTheUnstick:
			//XXX: this is to avoid waiting for an extra keypress when prompted to press a key to exit
			//log.Debug("1 watchKeys exiting due to external fatal error")
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
			//log.Debug("2 watchKeys woke up and saw external fatal error")
			return
		default:
		}
		fmt.Print(".") //noTODO: delete this? then the next 6 \n Print(s) as well

		// Ctrl+X (0x18)
		if buf[0] == 0x18 {
			fmt.Print("\n")
			log2.Info("Ctrl+X detected → clean exit")
			if err2 := term.Restore(fd, oldState); err2 != nil {
				log2.Warn("failed to restore terminal state", wincoe.SafeErr(err2))
			}
			cleanExitFn()
		}

		// Ctrl+R (0x12)
		if buf[0] == 0x12 {
			fmt.Print("\n")
			log2.Info("Ctrl+R detected → reloading config")
			//_ = term.Restore(fd, oldState)
			// NO restore needed here because we want to stay in Raw mode
			// to catch the next keypress after the reload.
			reloadFn()
		}

		// Ctrl+C (0x03) or else can't break the program except with Ctrl+Break !
		if buf[0] == 0x03 {
			fmt.Print("\n")
			log2.Info("Ctrl+C detected → breaking gracefully")
			if err2 := term.Restore(fd, oldState); err2 != nil {
				log2.Warn("failed to restore terminal state", wincoe.SafeErr(err2))
			}
			cleanExitFn()
		}

		// Alt+X / Alt+R → ESC + key
		if buf[0] == 0x1b && n >= 2 {
			switch buf[1] {
			case 'x', 'X':
				fmt.Print("\n")
				log2.Info("Alt+X detected → clean exit")
				if err2 := term.Restore(fd, oldState); err2 != nil {
					log2.Warn("failed to restore terminal state", wincoe.SafeErr(err2))
				}
				cleanExitFn()
			case 'r', 'R':
				fmt.Print("\n")
				log2.Info("Alt+R detected → reloading config")
				//_ = term.Restore(fd, oldState)
				reloadFn()
			}
		}

		// Re-ensure raw mode if anything temporarily reset it
		_, err = term.MakeRaw(fd)
		if err != nil {
			fmt.Print("\n")
			log2.Error("Failed to make the terminal raw", wincoe.SafeErr(err))
			return
		}
	}
}

func promptAndHashPassword(logger *slog.Logger, cost int) (string, error) {
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
		return "", fmt.Errorf("failed to read password from the terminal: %w", err /*non-nil here*/)
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
		return "", fmt.Errorf("failed to re-read password from the terminal: %w", err /*non-nil here*/)
	}

	//if string(pwd1) != string(pwd2) {
	if !bytes.Equal(pwd1, pwd2) {
		return "", fmt.Errorf("passwords do not match, len1:%d vs len2:%d", len(pwd1), len(pwd2))
	}

	// DefaultCost is 10, which is perfectly balanced for modern hardware
	hash, err := bcrypt.GenerateFromPassword(pwd1, cost)
	if err != nil {
		return "", fmt.Errorf("failed to generate bcrypt from password with cost %d, err: %w", cost, err /*non-nil here*/)
	}

	return string(hash), nil
}

// isLoginAllowed reports whether the given client IP is currently permitted
// to attempt WebUI authentication.
//
// Returns:
//   - allowed: false when the IP is within an active lockout window.
//   - attemptsRemaining: failures still allowed before lockout (0 if locked).
//   - lockedUntil: when the lockout expires (zero if not locked).
//
// Expired lockout windows are reset lazily on the first call after expiry.
func (ui *AdminUI) isLoginAllowed(clientIP string) (allowed bool, attemptsRemaining int, lockedUntil time.Time) {
	cfg := ui.getConfig()

	return ui.loginTracker.IsAllowed(clientIP, cfg.WebUIMaxLoginFailures)
}

// recordLoginFailure increments the failure counter for the given IP and
// issues a lockout if the configured threshold is reached.
//
// Returns:
//   - lockedOut: true if this failure triggered (or the IP is already in) a lockout.
//   - lockedUntil: expiry time of the lockout (zero if not locked).
//   - totalFailures: cumulative failure count for this IP in the current window.
func (ui *AdminUI) recordLoginFailure(clientIP string) (lockedOut bool, lockedUntil time.Time, totalFailures int) {
	cfg := ui.getConfig()

	return ui.loginTracker.RecordFailure(clientIP, cfg.WebUIMaxLoginFailures, cfg.WebUILoginLockoutSec)
}

// recordLoginSuccess clears any accumulated failure record for the given IP.
// Call after every successful authentication so a legitimate user is never
// permanently locked out due to an earlier typo streak.
func (ui *AdminUI) recordLoginSuccess(clientIP string) {
	log := ui.getLogger()

	ui.loginTracker.RecordSuccess(clientIP)
	log.Info("Login success", slog.String("client", clientIP))
}

func (ui *AdminUI) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log := ui.getLogger()
		cfg := ui.getConfig()

		// Safety fallback: if somehow the hash is still blank, DON'T allow access
		if cfg.WebUIPasswordHash == "" {
			panic2("BUG: no webUI password was set, this shouldn't be possible, dev fail?")
		}

		// Extract bare IP (without port) as the per-client rate-limit key.
		clientIP, _, splitErr := net.SplitHostPort(r.RemoteAddr)
		if splitErr != nil {
			// r.RemoteAddr should always be host:port for TCP, but be defensive.
			clientIP = r.RemoteAddr
			log.Warn("WebUI auth: could not split RemoteAddr into host:port",
				slog.String("remoteAddr", r.RemoteAddr),
				wincoe.SafeErr(splitErr))
		}

		// ── Rate-limit gate ──────────────────────────────────────────────────
		if allowed, _, lockedUntil := ui.isLoginAllowed(clientIP); !allowed {
			retryAfterSecs := int(time.Until(lockedUntil).Seconds()) + 1
			log.Warn("WebUI login rejected: IP is rate-limited",
				slog.String("clientIP", clientIP),
				slog.Time("locked_until", lockedUntil),
				slog.Int("retry_after_sec", retryAfterSecs),
			)
			w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfterSecs))
			http.Error(w, "429 Too Many Requests — Too many failed login attempts. Try again later.", http.StatusTooManyRequests)
			return
		}

		// FIX: Check if the browser hasn't attempted to send credentials yet
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="dnsbollocks webUI aka Management Interface aka Control Panel"`)
			http.Error(w, "401 Unauthorized - WebUI Access Restricted", http.StatusUnauthorized)
			return
		}

		// ── Credential check ─────────────────────────────────────────────────
		// Extract the Basic Auth credentials provided by the browser
		username, pass, ok := r.BasicAuth()
		if username != "" {
			log.Warn("WebUI login: username field is not used and was ignored",
				slog.String("username", username),
				slog.String("clientIP", clientIP))
		}

		// Compare the provided password against our stored bcrypt hash.
		// If headers are missing (!ok) or the password is wrong (err != nil), block them.
		// Only log and record a failure if credentials were provided but are invalid
		if !ok || bcrypt.CompareHashAndPassword([]byte(cfg.WebUIPasswordHash), []byte(pass)) != nil {
			// Record the failure and get count/lockout state for logging.
			lockedOut, newLockedUntil, totalFailures := ui.recordLoginFailure(clientIP)

			// Best-effort: identify the connecting process so operators can
			// distinguish an automated brute-force tool from a human typo.
			var pid uint32
			var exe string
			var pidExeLookupErr error
			// IP verification before resolving
			remoteHostAuth, _, splitErrAuth := net.SplitHostPort(r.RemoteAddr)
			if splitErrAuth != nil {
				remoteHostAuth = r.RemoteAddr
			}
			if net.ParseIP(remoteHostAuth) == nil {
				panic2("BUG: authMiddleware: net.ResolveTCPAddr requires an IP. r.RemoteAddr is not a valid IP: " + r.RemoteAddr)
			}

			if remoteTCP, tcpErr := net.ResolveTCPAddr("tcp", r.RemoteAddr); tcpErr == nil {
				pid, exe, pidExeLookupErr = wincoe.PidAndExeForTCP(remoteTCP)
			}

			remaining := cfg.WebUIMaxLoginFailures - totalFailures
			if remaining < 0 {
				remaining = 0
			}

			logAttrs := []any{
				slog.String("clientIP", clientIP),
				slog.Int("total_failures_this_window", totalFailures),
				slog.Int("attempts_remaining_before_lockout", remaining),
				slog.Uint64("pid", uint64(pid)),
				slog.String("exe", exe),
				wincoe.SafeErr2("pid_exe_lookup_err", pidExeLookupErr),
			}
			if lockedOut {
				retryAfterSecs := int(time.Until(newLockedUntil).Seconds()) + 1
				logAttrs = append(logAttrs,
					slog.Bool("now_locked_out", true),
					slog.Time("locked_until", newLockedUntil),
					slog.Int("lockout_duration_sec", cfg.WebUILoginLockoutSec),
					slog.Int("retry_after_this_many_seconds", retryAfterSecs),
				)
				log.Warn("WebUI login failed — IP is now locked out", logAttrs...)
				//http.Error(w, "401 Unauthorized - WebUI Access Restricted", http.StatusUnauthorized)

				//doneFIXME: technically I'd have to dup some code from above here to include the Retry-After
				w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfterSecs))
				http.Error(w, "429 Too Many Requests — Too many failed login attempts. Try again later.", http.StatusTooManyRequests)
				return
			} else {
				log.Warn("WebUI login failed", logAttrs...)
				//try again by doing the below dialog
			}

			// This header triggers the browser's native login modal
			w.Header().Set("WWW-Authenticate", `Basic realm="dnsbollocks webUI aka Management Interface aka Control Panel"`)
			http.Error(w, "401 Unauthorized - WebUI Access Restricted", http.StatusUnauthorized)
			return
		}

		// ── Success ──────────────────────────────────────────────────────────
		// Clear any prior failure streak so a legitimate user is never stuck
		// in a lockout after recovering from a typo run.
		ui.recordLoginSuccess(clientIP)
		// Password is correct, let the request pass through to the target handler
		next.ServeHTTP(w, r)
	})
}

// clearLoginLockouts resets ALL WebUI login failure records, including any
// active lockouts.  Call this on operator-triggered reloads (Ctrl+R) so a
// legitimate operator who locked themselves out with a typo streak doesn't
// have to restart the server.
//
// The map is replaced rather than iterated so the operation is O(1)
// regardless of how many IPs had recorded failures.
func (ui *AdminUI) clearLoginLockouts() {
	log := ui.getLogger()

	n := ui.loginTracker.ClearAll()
	if n > 0 {
		log.Warn("WebUI login lockouts cleared by operator reload",
			slog.Int("cleared_entry_count", n))
	} else {
		log.Debug("WebUI login lockouts cleared by operator reload (none were active)")
	}
}

// RateLimitConfig is the subset of Config relevant to rate limiting.
// Extracted so ClientRateLimiter can be constructed and tested without a full Config.
type RateLimitConfig struct {
	GlobalQPS   int
	GlobalBurst int
	ClientQPS   int
	ClientBurst int
}

// get a copy of the source
func rateLimitConfigFrom(cfg Config) RateLimitConfig {
	return RateLimitConfig{
		GlobalQPS:   cfg.GlobalRateQPS,
		GlobalBurst: cfg.GlobalBurstQPS,
		ClientQPS:   cfg.ClientRateQPS,
		ClientBurst: cfg.ClientBurstQPS,
	}
}

// lruClientEntry wraps the limiter with the client's IP so we can
// delete it from the map during an LRU eviction from the linked list.
type lruClientEntry struct {
	ip      string
	limiter *rate.Limiter
}

// ClientRateLimiter enforces a global QPS cap and a per-client QPS cap.
// It uses a strict LRU cache to bound memory usage and prevent OOM crashes
// during spoofed UDP floods or port scans.
type ClientRateLimiter struct {
	global *rate.Limiter
	cfg    RateLimitConfig
	logger *slog.Logger

	// LRU State
	mu      sync.Mutex
	maxSize int
	ll      *list.List
	cache   map[string]*list.Element
}

func newClientRateLimiter(ctx context.Context, cfg RateLimitConfig, logger *slog.Logger) *ClientRateLimiter {
	_ = ctx //TODO: because Context is no longer needed since we dropped the background janitor, remove it as arg?!
	return &ClientRateLimiter{
		global:  rate.NewLimiter(rate.Limit(cfg.GlobalQPS), cfg.GlobalBurst),
		cfg:     cfg,
		logger:  logger,
		maxSize: 10000, // Hard memory cap: 10k unique IPs is plenty and uses < 2MB of RAM
		ll:      list.New(),
		cache:   make(map[string]*list.Element),
	}
}

// Allow checks both the global and per-client rate limits for the given
// clientAddr (host:port or bare IP).
// Returns (true, "") on success, or (false, reason) where reason is one of
// the existing rate-limit sentinel strings used for logging and query tracking.
func (rl *ClientRateLimiter) Allow(clientAddr string) (allowed bool, reason string) {
	if !rl.global.Allow() {
		return false, globalRateLimitExceeded
	}
	// 1. Extract only the IP address to strip away the ephemeral port
	clientIP, _, err := net.SplitHostPort(clientAddr)
	if err != nil {
		// Fallback safety: if string parsing fails, default back to the raw string
		rl.logger.Warn("couldn't split clientAddr into host:port for per-client rate limiter key, using as-is",
			slog.String("clientAddr", clientAddr))
		clientIP = clientAddr
	}
	// 2. If it's any loopback address (127.x.x.x or ::1), collapse it to "localhost" to avoid one .exe which could be using many IPs in range of 127.0.0.0/8 as the request sender.
	// 2. Collapse loopback addresses to prevent bypassing limits
	if parsed := net.ParseIP(clientIP); parsed != nil && parsed.IsLoopback() {
		clientIP = "localhost"
	}

	// 3. Thread-safe LRU management with guaranteed deferred unlock
	limiter := rl.getOrCreateLimiter(clientIP)

	if !limiter.Allow() {
		return false, clientRateLimitExceeded
	}
	return true, ""
}

// getOrCreateLimiter looks up the client's limiter or creates a new one if missing.
// It uses a deferred unlock to guarantee mutex release while keeping the critical section small.
func (rl *ClientRateLimiter) getOrCreateLimiter(clientIP string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Cache Hit: Move to front and return
	if elem, ok := rl.cache[clientIP]; ok {
		rl.ll.MoveToFront(elem)
		entry, ok := elem.Value.(*lruClientEntry)
		if !ok {
			panic2("BUG: not of *lruClientEntry type")
		}
		if entry == nil {
			panic2("BUG: nil *lruClientEntry")
		}
		return entry.limiter
	}

	// Cache Miss: Create a new bucket
	entry := &lruClientEntry{
		ip:      clientIP,
		limiter: rate.NewLimiter(rate.Limit(rl.cfg.ClientQPS), rl.cfg.ClientBurst),
	}
	elem := rl.ll.PushFront(entry)
	rl.cache[clientIP] = elem

	//TODO: add per exe limit, not just per IP limit; already have global limit though as 'rate_qps' in config.json

	// Enforce hard memory cap via LRU Eviction
	if rl.ll.Len() > rl.maxSize {
		oldest := rl.ll.Back()
		if oldest != nil {
			rl.ll.Remove(oldest)
			oldEntry, ok := oldest.Value.(*lruClientEntry)
			if !ok {
				panic2("BUG: not of *lruClientEntry type")
			}
			delete(rl.cache, oldEntry.ip)
		}
	}

	return entry.limiter
}

// DNSCache is the caching contract used by the query handler.
// The interface makes it trivial to inject a fake in tests
// (no-op, always-miss, always-hit, recording, etc.)
// without touching go-cache at all.
type DNSCache interface {
	Get(key string) (CacheEntry, bool)
	Set(key string, entry CacheEntry, d time.Duration)
	Delete(key string)
	Flush()
	// Items is used by cache-invalidation walks.
	// Returns the underlying go-cache item map so existing
	// item.Object type assertions keep working.
	Items() map[string]cache.Item
	ItemCount() int
}

// goCacheStore adapts patrickmn/go-cache to DNSCache.
// All type assertions against interface{} are confined here;
// callers work with concrete CacheEntry values.
type goCacheStore struct {
	c          *cache.Cache
	maxEntries int
}

func newGoCacheStore(janitorInterval time.Duration, maxEntries int) DNSCache {
	return &goCacheStore{
		c:          cache.New(janitorInterval, janitorInterval),
		maxEntries: maxEntries,
	}
}

func (s *goCacheStore) Get(key string) (CacheEntry, bool) {
	v, ok := s.c.Get(key)
	if !ok {
		return CacheEntry{}, false
	}
	if entry, ok := v.(CacheEntry); ok {
		return entry, true
	} else {
		panic2("BUG: not of CacheEntry type")
	}
	panic(nil)
}

func (s *goCacheStore) Set(key string, e CacheEntry, d time.Duration) {
	if s.maxEntries > 0 && s.c.ItemCount() >= s.maxEntries {
		s.c.DeleteExpired() // Try to make room first
		if s.c.ItemCount() >= s.maxEntries {
			return // Cache is full, safely drop the new entry to prevent memory leaks
		}
	}
	s.c.Set(key, e, d)
}

func (s *goCacheStore) Delete(key string)            { s.c.Delete(key) }
func (s *goCacheStore) Flush()                       { s.c.Flush() }
func (s *goCacheStore) Items() map[string]cache.Item { return s.c.Items() }
func (s *goCacheStore) ItemCount() int               { return s.c.ItemCount() }

func (ui *AdminUI) getLogger() *slog.Logger {
	if ui.liveLogger != nil {
		if l := ui.liveLogger.Load(); l != nil {
			return l
		}
	}
	log := slog.Default()
	log.Error("BUG: AdminUI.liveLogger wasn't inited, using default.")
	return log
}

// pointer to live Server.Config via AdminUI
func (ui *AdminUI) getConfig() *Config {
	c := ui.liveConfig.Load()
	if c == nil {
		panic2("BUG: AdminUI.liveConfig not initialized before use — NewServer must call liveConfig.Store()")
	}
	return c
}

func NewAdminUI(
	// logger *slog.Logger,
	// cfg Config,
	liveConfig *atomic.Pointer[Config],
	liveRawConfig *atomic.Pointer[Config],
	liveLogger *atomic.Pointer[slog.Logger],
	rs *RuleStore,
	hs *HostStore,
	bl *BlacklistStore,
	lt *LoginTracker,
	rb *RecentBlocksTracker,
	stats *expvar.Int,
	//upstreamIPs []string,
	tpls *template.Template,
) *AdminUI {
	return &AdminUI{
		// logger:       logger,
		// config:       cfg,
		liveConfig:    liveConfig,
		liveRawConfig: liveRawConfig,
		liveLogger:    liveLogger,
		ruleStore:     rs,
		hostStore:     hs,
		blacklist:     bl,
		loginTracker:  lt,
		recentBlocks:  rb,
		stats:         stats,
		//upstreamIPs:  upstreamIPs,
		uiTemplates: tpls,
	}
}

// Add this directly to admin_ui.go
func (ui *AdminUI) getResponseBlacklist() []string {
	return ui.blacklist.List()
}

// IPChecker defines the interface for checking if an IP is blacklisted, allowing easy mocking in tests.
type IPChecker interface {
	Contains(ip net.IP) bool
}

type UpstreamManager struct {
	liveConfig *atomic.Pointer[Config]
	liveLogger *atomic.Pointer[slog.Logger]
	serverCtx  context.Context // server lifetime ctx for Upstream.BackgroundCtx

	dohTransportsPtrs []*http.Transport //protected by dohMu, used only to clean up during reinit via initDoHClient
	//upstreamsPtr      atomic.Pointer[[]Upstream] // Combines clients, URLs, and SNIs safely
	activeSet atomic.Pointer[upstreamSet] // ← the atomic pair
	buildMu   sync.Mutex                  // prevents concurrent builds only
	// dohMu     sync.Mutex                  // Only used for initialization/reloads

	//UM calls this when a fatal exception or manual admin shutdown occurs
	OnShutdown func(exitCode int)
}

func NewUpstreamManager(serverCtx context.Context, liveConfig *atomic.Pointer[Config], liveLogger *atomic.Pointer[slog.Logger], shutdownFunc func(exitCode int)) *UpstreamManager {
	if serverCtx == nil {
		panic2("BUG: NewUpstreamManager: nil serverCtx")
	}
	if liveConfig == nil {
		panic2("BUG: NewUpstreamManager: nil liveConfig pointer")
	}
	if liveLogger == nil {
		panic2("BUG: NewUpstreamManager: nil liveLogger pointer")
	}
	um := &UpstreamManager{
		serverCtx:  serverCtx,
		liveConfig: liveConfig,
		liveLogger: liveLogger,
		//Pass the server's shutdown method directly
		OnShutdown: shutdownFunc,
	}
	//NewUpstreamManager no longer constructs a FailoverSelector upfront — it's created fresh inside buildSet:
	//um.failoverSelect = NewFailoverSelector(liveLogger)
	return um
}

func (um *UpstreamManager) getLogger() *slog.Logger {
	if l := um.liveLogger.Load(); l != nil {
		return l
	}
	log := slog.Default()
	log.Error("BUG: UpstreamManager.liveLogger wasn't inited, using default.")
	return log
}

func (um *UpstreamManager) getConfig() *Config {
	c := um.liveConfig.Load()
	if c == nil {
		panic2("BUG: UpstreamManager.liveConfig not initialized before use")
	}
	return c
}

// due to presumed config changes ie. UpstreamManager.liveConfig, update the 'cached' inner state of the upstreamIPs, upstreamSNIs and upstreamURLs
func (um *UpstreamManager) updateInnerState() error {
	cfg := um.getConfig()
	//hmmokFIXME: it's not actually protected from 'cfg' being modified during this tiny 2-assignment window; "Wrong — cfg is an atomically-loaded *Config; Config is immutable once stored; snapshots are safe" -  Claude Sonnet 4.6 Low Thinking
	snapSNI := cfg.UpstreamSNIHostnames
	snapURL := cfg.UpstreamURLs

	cfg.UpstreamURLsParsed = nil
	cfg.UpstreamIPs = nil
	cfg.UpstreamSNIs = nil

	if len(cfg.UpstreamURLs) == 0 {
		return errors.New("upstream_urls list is empty")
	}

	for i, rawURL := range snapURL {
		u, err := url.Parse(rawURL)
		if err != nil || u.Scheme != "https" {
			return fmt.Errorf("invalid upstream URL (must be https): %s", rawURL)
		}
		port := u.Port()
		if port == "" {
			port = "443" // since we're allowing only https scheme, this should always be 443
			// log.Warn("Using implied port for DoH upstream due to unspecified port and scheme",
			//     slog.String("implied_port", ImpliedPort),
			//     slog.Any("upstreamURL", u))
			// This is how you add the port back into the URL object
			u.Host = net.JoinHostPort(u.Hostname(), port)
		}
		if u.Port() == "" {
			panic2("BUG: dev fail: port is empty")
		}
		cfg.UpstreamURLsParsed = append(cfg.UpstreamURLsParsed, u)

		ip := u.Hostname()
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("upstream host must be IP literal (no resolution): %s", ip)
		}
		cfg.UpstreamIPs = append(cfg.UpstreamIPs, ip)
		cfg.UpstreamSNIs = append(cfg.UpstreamSNIs, snapSNI[i])
	}

	return nil
}

// ForwardToDoH uses the preinitialized dohClient and supports one retry on transient network errors.
func (um *UpstreamManager) ForwardToDoH(ctx context.Context, req *dns.Msg) (*dns.Msg, UpstreamState) {
	cfg := um.getConfig()
	log := um.getLogger()

	var upstreamState1 UpstreamState
	upstreamState1.Strategy = cfg.UpstreamSelectionMode

	reqBytes, err := req.Pack()
	if err != nil {
		log.Error("doh_prepost_pack_failed", wincoe.SafeErr(err))
		return nil, upstreamState1
	}

	// 1. Load the thread-safe slice of Upstream objects atomically
	// upstreamsPtr := um.upstreamsPtr.Load()
	// if upstreamsPtr == nil {
	// 	u := um.InitDoHClients()
	// 	upstreamsPtr = &u
	// }
	// upstreams := *upstreamsPtr
	set := um.GetOrBuildSet()
	upstreams := set.upstreams
	failover := set.failover

	type result struct {
		msg *dns.Msg
		err error
		idx int // Useful for tracking which upstream won or failed
	}

	switch cfg.UpstreamSelectionMode {
	case upstreamSelectionModeStrict:
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
				panic2(fmt.Sprintf("BUG: dev fail: dohClient %d is still nil after init! upstreamURL=%s SNI=%s",
					i, upstream.URL, upstream.SNI)) //um.upstreamURLs[i], um.upstreamSNIs[i]))
			}
			wg.Add(1)
			go func(idx int, target Upstream) {
				defer wg.Done()
				msg, err := target.doSingleDoHRequest(ctx, reqBytes)
				results[idx] = result{msg: msg, err: err, idx: idx}
			}(i, upstream)
		}

		wg.Wait()

		var reference *dns.Msg
		var refIdx int

		// Compare responses
		for i, res := range results {
			strURL := upstreams[i].URL.String()
			if res.err != nil || res.msg == nil {
				log.Error("upstream failed or returned nil",
					slog.String("url", strURL), // um.upstreamURLs[i].String()),
					wincoe.SafeErr(res.err),
				)
				upstreamState1.FailedUpstreams = append(upstreamState1.FailedUpstreams, strURL)
				return nil, upstreamState1 // Refuse to resolve if any upstream completely fails
			}

			if reference == nil {
				reference = res.msg
				refIdx = i
				upstreamState1.UpstreamUsed = strURL
			} else {
				if !compareDNSResponses(reference, res.msg) {
					// Mismatch means failure to agree
					upstreamState1.FailedUpstreams = append(upstreamState1.FailedUpstreams, strURL)

					// Extract IPs for the log message
					refIPs := extractIPs(reference)
					curIPs := extractIPs(res.msg)
					log.Warn("upstream DNS response mismatch! dropping query to protect client",
						slog.String("query", req.Question[0].Name),
						slog.String("upstream_DoH_url1", upstreams[refIdx].URL.String()), //um.upstreamURLs[refIdx].String()),
						SafeStringSlice("ips_returned1", refIPs),
						slog.String("upstream_DoH_url2", strURL),
						SafeStringSlice("ips_returned2", curIPs),
						slog.String("reference", reference.String()),
						slog.String("current", res.msg.String()),
					)
					return nil, upstreamState1 // Drop the query because of answer discrepancy
				}
			}
		}

		return reference, upstreamState1

	case upstreamSelectionModeFailover:
		// ==========================================
		// FAILOVER MODE: Priority-based with active healing
		// ==========================================
		resp, used, failed, err := failover.Exchange(ctx, upstreams, reqBytes)
		upstreamState1.UpstreamUsed = used
		upstreamState1.FailedUpstreams = failed
		if err != nil {
			log.Error("failover selection failed", wincoe.SafeErr(err))
			return nil, upstreamState1
		}
		return resp, upstreamState1

	case upstreamSelectionModeFastest:
		//nolint:gocritic // Reason: Keeping 'fastest' explicit for readability
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
				panic2(fmt.Sprintf("BUG: dev fail: dohClient %d is still nil after init! upstreamURL=%s SNI=%s",
					i, upstream.URL, upstream.SNI)) //um.upstreamURLs[i], um.upstreamSNIs[i]))
			}
			go func(idx int, target Upstream) {
				msg, err := target.doSingleDoHRequest(ctx, reqBytes)
				resChan <- result{msg: msg, err: err, idx: idx}
			}(i, upstream)
		}

		var lastErr error
		for range len(upstreams) {
			res := <-resChan
			strURL := upstreams[res.idx].URL.String()
			// If we got a valid DNS response (even an NXDOMAIN), return it immediately
			if res.err == nil && res.msg != nil {
				upstreamState1.UpstreamUsed = strURL //um.upstreamURLs[res.idx].String()
				return res.msg, upstreamState1
			}
			upstreamState1.FailedUpstreams = append(upstreamState1.FailedUpstreams, strURL) //um.upstreamURLs[res.idx].String())
			// Keep track of the error in case they ALL fail
			if res.err != nil {
				lastErr = res.err
			}
		}

		// If we reach here, every single upstream request failed
		log.Error("all upstreams failed to provide a valid response",
			wincoe.SafeErr2("last_err", lastErr),
		)
		return nil, upstreamState1
	}
}

// upstreamSet is an immutable snapshot of clients + their failover selector.
// It is replaced atomically on reload, so ForwardToDoH always sees a
// consistent pair — never new clients with stale failover or vice versa.
type upstreamSet struct {
	upstreams []Upstream
	failover  *FailoverSelector
}

// InitDoHClients to be run first time
// can panic/shutdown
func (um *UpstreamManager) InitDoHClients() {
	_ = um.buildSet(false)
}

// ReInitDoHClients to be run on reload
// can panic/shutdown
func (um *UpstreamManager) ReInitDoHClients() {
	_ = um.buildSet(true)
}

// GetOrBuildSet will init if not already done so
// can panic/shutdown
func (um *UpstreamManager) GetOrBuildSet() *upstreamSet {
	set := um.activeSet.Load()
	if set == nil {
		set = um.buildSet(false)
	}
	return set
}

// can panic/shutdown
func (um *UpstreamManager) buildSet(rebuild bool) *upstreamSet {
	log := um.getLogger()
	log.Debug("starting UpstreamManager.buildSet()")
	// 3. LOCK (Slow path, ensures only one goroutine builds the client)
	um.buildMu.Lock()
	defer um.buildMu.Unlock()

	if rebuild {
		um.activeSet.Store(nil)
	} else {
		// double-check: another goroutine may have built while we waited
		// 4. DOUBLE CHECK
		// While we were waiting for the lock, someone else might
		// have finished the initialization. Check again.
		if s := um.activeSet.Load(); s != nil {
			return s
		}
	}

	cfg := um.getConfig()
	if err := um.updateInnerState(); err != nil {
		log.Error("Upstream validation failed:", wincoe.SafeErr(err))
		// 2. Trigger the application shutdown if the callback is wired
		if um.OnShutdown != nil {
			um.OnShutdown(1) // Exit code 1 for crashes/errors
			panic2("BUG: UpstreamManager.OnShutdown returned but is designed to terminate execution")
		} else {
			panic2("BUG: Shutdown requested, but no shutdown handler is wired (likely in a test environment).")
		}
	}
	log.Debug("Upstreams (re)validated",
		SafeStringSlice("upstreamURLs", cfg.UpstreamURLs), //FIXME: use the one from um.
		SafeStringSlice("upstreamSNIs", cfg.UpstreamSNIHostnames),
		SafeStringSlice("upstreamIPs", cfg.UpstreamIPs),
	)

	// close old idle connections
	for _, dT := range um.dohTransportsPtrs {
		if dT != nil {
			var sn string
			if dT.TLSClientConfig != nil {
				sn = dT.TLSClientConfig.ServerName
			} else {
				sn = "<nil>"
			}
			log.Debug("Closing any potential idle DoH connections", slog.String("tls_servername", sn))
			dT.CloseIdleConnections()
		}
	}
	um.dohTransportsPtrs = nil
	// --- PRE-COMPUTE DIAL ADDRESS ONCE ---
	var newUpstreams []Upstream
	for i, u := range cfg.UpstreamURLsParsed {
		ip := cfg.UpstreamIPs[i]
		port := u.Port()
		if port == "" {
			panic2("BUG: dev fail: port is empty but shoulda been set in ValidateUpstream() to 443")
		}
		// Create the final "IP:Port" string once
		// Pre-joining prevents doing string manipulation inside the DialContext closure
		dialAddr := net.JoinHostPort(ip, port)
		sniHost := cfg.UpstreamSNIs[i]
		if sniHost == "" {
			panic2("BUG: dev fail: SNIHostname shouldn't be empty, upstream host=" + dialAddr)
		}

		t := &http.Transport{
			// Dial raw TCP to the chosen IP so we don't perform DNS resolution here.
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := &net.Dialer{
					Timeout: time.Duration(cfg.UpstreamDialTimeoutSec) * time.Second,
					// Encourages OS-level keep-alives
					KeepAlive: time.Duration(cfg.UpstreamTCPKeepAliveSec) * time.Second, //doneTODO: const or configurable?
					// doneFIXME: does this mean it will never be seen as idle conn? thus cfg.UpstreamIdleConnTimeoutSec will not be enforced?  no
					/*
						1. Does KeepAlive prevent IdleConnTimeout from working?

						No, it does not prevent it. You should absolutely keep both, as they operate at completely different layers of the network stack and look for entirely different things.

						    IdleConnTimeout is an Layer 7 (Application) concept: In Go's http.Transport, a connection is considered "idle" when there are no active HTTP requests or responses running across it. Go keeps track of this using internal timestamps.

						    KeepAlive is a Layer 4 (Transport/TCP) concept: This tells the operating system's TCP stack to send tiny, empty tracking probes to the remote server to ensure the physical line hasn't been cut.

						Because TCP Keep-Alive probes are handled entirely by the operating system (below Go's application layer), Go does not count them as HTTP traffic. If you set an IdleConnTimeout of 90 seconds and a KeepAlive of 15 seconds, and you stop browsing the web:

						    Every 15 seconds, the OS will silently exchange a TCP keep-alive ping with the server. Go's HTTP layer doesn't see or care about this.

						    At the 90-second mark, Go realizes no actual HTTP requests have used this connection. Go will cleanly close the connection, ignoring the fact that the TCP stack was keeping it warm.
					*/
				}
				// Use the pre-computed dialAddr captured via closure!
				log.Debug("opening new TCP socket for upstream DoH", slog.String("dialAddr", dialAddr))
				conn, err := d.DialContext(ctx, network, dialAddr)
				if err != nil {
					return nil, fmt.Errorf("failed to dial new TCP socket for upstream DoH, addr:%s err: %w", dialAddr, err /*non-nil here*/)
				}

				//return d.DialContext(ctx, network, dialAddr)

				// Wrap the connection with a strict write deadline (e.g., 5 seconds).
				// Match this to your cfg.UpstreamClientTimeoutSec or use a sensible default.
				return &rwTimeoutConn{
					Conn:    conn,
					timeout: time.Duration(cfg.UpstreamClientTimeoutSec) * time.Second,
				}, nil
			},
			TLSClientConfig: &tls.Config{
				ServerName:         sniHost,
				InsecureSkipVerify: false,
			},
			Proxy:               nil,  // avoid proxy interference
			ForceAttemptHTTP2:   true, // allow http2 negotiation via ALPN (needed for 9.9.9.9 due to it saying this "This server implements RFC 8484 - DNS Queries over HTTP, and requires HTTP/2 in accordance with section 5.2 of the RFC."
			IdleConnTimeout:     time.Duration(cfg.UpstreamIdleConnTimeoutSec) * time.Second,
			MaxIdleConns:        cfg.UpstreamMaxIdleConns,
			MaxIdleConnsPerHost: cfg.UpstreamMaxIdleConnsPerHost,
		}
		// --- NEW: Proactive HTTP/2 Health Checks ---
		// This extracts the hidden HTTP/2 transport and configures PING frames.
		t2, err := http2.ConfigureTransports(t)
		if err == nil {
			// If the connection is idle (no reads) for 5 seconds, send an HTTP/2 PING.
			t2.ReadIdleTimeout = time.Duration(cfg.UpstreamH2ReadIdleTimeoutSec) * time.Second //doneTODO: shall we make this configurable in config.json or base it on something that already exists and makes sense to be based on? and/or on the below t2.PingTimeout for any clamps?
			// If the upstream doesn't ACK the PING within 2 seconds, destroy the zombie connection.
			t2.PingTimeout = time.Duration(cfg.UpstreamH2PingTimeoutSec) * time.Second //doneTODO: shall we make this configurable in config.json or base it on something that already exists and makes sense to be based on? and/or on the above t2.ReadIdleTimeout for any clamps? Also how does this fare with the dialer's KeepAlive of 15 sec from above? do we need to change things or their timeout values to make these work well together?
		}

		um.dohTransportsPtrs = append(um.dohTransportsPtrs, t)
		if um.dohTransportsPtrs[i] != t {
			panic2("BUG: dev fail: dohTransportsPtrs[i] != t")
		}

		// Bundle everything this specific upstream needs to execute queries completely independently
		newUpstreams = append(newUpstreams, Upstream{
			Client: &http.Client{
				Timeout:   time.Duration(cfg.UpstreamClientTimeoutSec) * time.Second,
				Transport: t,
			},
			URL:                           u,
			SNI:                           sniHost,
			liveLogger:                    um.liveLogger,
			Retries:                       cfg.UpstreamRetriesPerQuery,
			RetryBackoffDuration:          time.Duration(cfg.UpstreamRetryBackoffMs /*clamped later on, at use-site*/) * time.Millisecond,
			UpstreamClientTimeoutDuration: time.Duration(cfg.UpstreamClientTimeoutSec /*used as is, good or bad, tho clamped in loadMainConfig()*/) * time.Second,
			BackgroundCtx:                 um.serverCtx,
			CertLogTimeoutSec:             cfg.CertLogTimeoutSec,
		})
	}

	newSet := &upstreamSet{
		upstreams: newUpstreams,
		failover:  NewFailoverSelector(um.liveLogger), // fresh: activeIndex=0, allFailed=false
	}
	// 6. ATOMIC STORE
	um.activeSet.Store(newSet)
	log.Info("DoH clients initialized", slog.Int("count", len(newUpstreams)))
	return newSet
}

// DoHForwarder is the testable seam around UpstreamManager.ForwardToDoH.
// Swap in a mock to exercise handleDNSQuery without any real network calls.
type DoHForwarder interface {
	ForwardToDoH(ctx context.Context, req *dns.Msg) (*dns.Msg, UpstreamState)
}

func (rl *ClientRateLimiter) UpdateConfig(cfg RateLimitConfig) {
	// Update the global token bucket limits
	rl.global.SetLimit(rate.Limit(cfg.GlobalQPS))
	rl.global.SetBurst(cfg.GlobalBurst)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.cfg = cfg
	// Flush existing per-client limiters so they immediately pick up the new config
	rl.ll.Init()
	rl.cache = make(map[string]*list.Element)
}

// rwTimeoutConn wraps a net.Conn to enforce a strict timeout on every Read and Write call.
// This prevents HTTP/1.1 and HTTP/2 loops from hanging indefinitely on blackholed connections.
type rwTimeoutConn struct {
	net.Conn
	timeout time.Duration
}

func (c *rwTimeoutConn) Read(b []byte) (int, error) {
	if c.timeout > 0 {
		if err := c.Conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
			return 0, fmt.Errorf("failed to set read deadline (%d) on upstream conn: %w", c.timeout, err)
		}
	}
	n, err := c.Conn.Read(b)
	if err != nil {
		return n, fmt.Errorf("failed to read from net connection: %w", err)
	}
	return n, nil
}

func (c *rwTimeoutConn) Write(b []byte) (int, error) {
	if c.timeout > 0 {
		if err := c.Conn.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
			// Return 0 bytes written and wrap the error so the caller knows exactly what failed
			return 0, fmt.Errorf("failed to set write deadline (%d) on upstream conn, err: %w", c.timeout, err)
		}
	}
	n, err := c.Conn.Write(b)
	if err == nil {
		return n, nil
	} else {
		return n, fmt.Errorf("failed to write to the net connection: %w", err)
	}
}

// type httpListenerInstance struct {
// 	addr     string
// 	useTLS   bool
// 	listener net.Listener
// 	srv      *http.Server
// 	cancel   context.CancelFunc
// 	wg       sync.WaitGroup
// }

func (s *Server) getCache() DNSCache {
	c := s.liveDNSCache.Load()
	if c == nil {
		panic2("BUG: Server.liveDNSCache not initialized before use — Run() must call swapDNSCache() before listeners start")
	}
	return *c
}

func (s *Server) swapDNSCache(janitorIntervalMinutes, maxEntries int) {
	newCache := newGoCacheStore(time.Duration(janitorIntervalMinutes)*time.Minute, maxEntries)
	s.liveDNSCache.Store(&newCache)
}
func (s *Server) flushCache() {
	log := s.getLogger()

	c := s.liveDNSCache.Load()
	if c != nil {
		(*c).Flush()
		log.Debug("Cache flushed/deleted.")
	} else {
		log.Debug("Cache wasn't inited so can't be flushed here.")
	}
}

func (s *Server) swapDNSTCPSemaphore(maxConns int) {
	// ── Semaphore init ───────────────────────────────────────────────────
	// Must happen before the accept goroutine starts so every Accept() can
	// immediately check capacity.  loadConfig has already validated the
	// value, but defend against a zero here just in case.
	sem := make(chan struct{}, maxConns)
	s.dnsTCPSem.Store(&sem)
}

func (s *Server) acquireDNSTCPSlot() (release func(), ok bool) {
	// ── Concurrent-connection gate ───────────────────────────────
	// Non-blocking try: if all slots are occupied, close the new
	// connection immediately rather than queuing another goroutine.
	// This bounds memory and goroutine count under idle-scanner load.

	sem := *s.dnsTCPSem.Load()
	select {
	case sem <- struct{}{}:
		// Slot acquired
		return func() { <-sem }, true
	default:
		return nil, false
	}
}

func (s *Server) swapDNSUDPSemaphore(maxConns int) {
	sem := make(chan struct{}, maxConns)
	s.dnsUDPSem.Store(&sem)
}

func (s *Server) acquireDNSUDPSlot() (release func(), ok bool) {
	sem := *s.dnsUDPSem.Load()
	select {
	case sem <- struct{}{}:
		// Slot acquired
		return func() { <-sem }, true
	default:
		return nil, false
	}
}

func (s *Server) runDNSUDPLoop(ctx context.Context, udpLn *net.UDPConn) {
	log2 := s.getLogger()
	log2.Info("UDP DNS listening success", slog.String("addr", udpLn.LocalAddr().String()))

	udpPool := sync.Pool{
		//Zero-Allocation Happy Path: Reading an incoming packet, processing it, and handling it in a goroutine now requires zero new heap allocations for the packet data.
		//Thread Safety: Because each goroutine gets its own buffer straight from the pool, there are no race conditions with the ReadFromUDP loop overwriting data while the goroutine parses it.
		//Memory Bound: Under high bursts, the pool will scale up automatically to handle concurrent connections, but once traffic settles, the Go runtime will garbage collect the unused buffered slices in the pool automatically.
		New: func() any {
			cfg2 := s.getConfig()
			// Use a 4096-byte buffer to safely accommodate modern EDNS0 UDP packets
			b := make([]byte, cfg2.DNSUDPBufferSize)
			return &b // Return a pointer to avoid interface conversion allocation
		},
	}
	//TheFor:
	for {
		log3 := s.getLogger()
		// 2. Grab a buffer pointer from the pool
		bufPtr, ok := udpPool.Get().(*[]byte)
		if !ok {
			panic2("BUG: not of *[]byte type")
		}
		if bufPtr == nil {
			panic2("BUG: somehow stored a nil in cache")
		}
		buf := *bufPtr

		n, clientAddr, err2 := udpLn.ReadFromUDP(buf)
		if err2 != nil {
			udpPool.Put(bufPtr) // Return buffer on error
			select {
			case <-ctx.Done():
				// to see this you've to wait like 1 sec in shutdown() or that "press a key" msg does it.
				log3.Debug("UDP DNS listener is quitting due to shutdown/rebind...")
				return // Quit on shutdown
			default:
				log3.Warn("UDP DNS listener udp_read_error", wincoe.SafeErr(err2))
				continue // Real network error, keep trying
			}
		}

		log3.Debug("client connected(early logging)",
			slog.String("proto", "UDP"),
			SafeAddr("clientAddr", clientAddr),
		)

		if n > len(buf) {
			udpPool.Put(bufPtr) // Clean up before panicking
			log3.Error("BUG: ReadFromUDP returned n > dns_udp_buffer_size (from config); dropping packet",
				slog.Int("n", n),
				slog.Int("dns_udp_buffer_size", len(buf)),
				SafeAddr("client", clientAddr),
			)
			continue
		}
		//XXX: this below(until the goroutine) slows down things here before going to the next ReadFromUDP aka client (above) again! could move these into the below goroutine but then XXX: it's gonna be too late to get the pid of the exe that just did this connection because it's gone from the list of UDP conns!
		//^ "Valid tradeoff — PID lookup must happen before the goroutine or you lose the connection from the OS table; intentional" -Claude

		pid, exe, err2 := wincoe.PidAndExeForUDP(clientAddr)
		// NOTE: deliberately rooted in s.ctx, not the per-listener instance ctx — an in-flight
		// query's upstream forwarding should only be cancelled by full process shutdown, not
		// by this specific listener instance being torn down during a hot rebind.
		udpPacketCtx := s.makeClientInfoContext(s.ctx, "UDP", clientAddr, pid, exe, err2)

		// --- ADD SEMAPHORE CHECK HERE ---
		release, ok := s.acquireDNSUDPSlot()
		if !ok {
			udpPool.Put(bufPtr) // Don't forget to recycle the buffer!
			sem := *s.dnsUDPSem.Load()
			log3.Warn("DNS UDP concurrent query limit reached; dropping packet",
				slog.Int("max_concurrent", cap(sem)),
				SafeAddr("rejected_client", clientAddr),
			)
			continue
		}
		// --------------------------------

		// TRACK INDIVIDUAL REQUESTS:
		s.shutdownWG.Add(1)
		go func(pCtx context.Context, data []byte, bufferPtr *[]byte, addr *net.UDPAddr, ln *net.UDPConn, rel func()) {
			defer s.shutdownWG.Done()
			defer udpPool.Put(bufferPtr) // 4. Recycle buffer when the handler finishes
			defer rel()                  // Release the slot when the goroutine exits
			s.handleUDP(pCtx, data, addr, ln)
		}(udpPacketCtx, buf[:n], bufPtr, clientAddr, udpLn, release)
	} //infinite 'for'
}

func (s *Server) runDNSTCPLoop(ctx context.Context, tcpLn *net.TCPListener) {
	log2 := s.getLogger()
	log2.Info("TCP DNS listening", slog.String("address", tcpLn.Addr().String()))

	for {
		log3 := s.getLogger()

		conn, err := tcpLn.Accept()
		if err != nil {
			// if context canceled, exit cleanly
			select {
			case <-ctx.Done():
				log3.Debug("TCP DNS listener is quitting due to shutdown/rebind...")
				return
			default:
				// non-temporary error: log, backoff a bit to avoid hot loop, continue

				log3.Warn("tcp_accept_error", wincoe.SafeErr(err))
				continue
			}
		}

		// ── Concurrent-connection gate ───────────────────────────────
		// Non-blocking try: if all slots are occupied, close the new
		// connection immediately rather than queuing another goroutine.
		// This bounds memory and goroutine count under idle-scanner load.
		release, ok := s.acquireDNSTCPSlot()
		if !ok {
			sem := *s.dnsTCPSem.Load()
			log3.Warn("DNS TCP connection limit reached; rejecting new connection",
				slog.Int("max_concurrent", cap(sem)),
				SafeAddr("rejected_client", conn.RemoteAddr()),
			)
			conn.Close() //nolint:errcheck // best-effort close, nothing to do on error
			continue
		}

		tcpPacketCtx := s.ctx // see UDP-side note above: rooted in full server lifetime, not the listener instance's
		// 1. Get the remote address as a *net.TCPAddr
		clientAddr, ok2 := conn.RemoteAddr().(*net.TCPAddr)
		log3.Debug("client connected(early logging)",
			slog.String("proto", "TCP"),
			SafeAddr("clientAddr", conn.RemoteAddr()),
		)
		if !ok2 {
			//doneFIXME: when can this happen?! "With a plain net.TCPListener, conn.RemoteAddr() is always *net.TCPAddr; effectively unreachable" - Claude Sonnet 4.6 Low Thinking
			log3.Error("BUG: could not cast remote addr to TCPAddr", SafeAddr("addr", conn.RemoteAddr()))
			// XXX: tcpPacketCtx stays as s.ctx; goroutine will still close conn and release the semaphore via defer.
		} else {
			//itisnecessarysonothingtodoFIXME: this slows down things here until it's ready to tcpLn.Accept() (above) again!
			// 2. Call your new TCP PID/Exe helper

			pid, exe, pidErr := wincoe.PidAndExeForTCP(clientAddr)
			tcpPacketCtx = s.makeClientInfoContext(tcpPacketCtx, "TCP", clientAddr, pid, exe, pidErr)
		}
		// accepted a connection; handle in new goroutine

		//XXX: tcpPacketCtx is passed as arg(instead of as above commented out code) because: "Because that goroutine might not start instantly, the loop might move on to the next connection before the first goroutine actually reads the value of tcpPacketCtx." - Gemini 3 Thinking
		// TRACK INDIVIDUAL CONNECTIONS:

		s.shutdownWG.Add(1)
		go func(c net.Conn, pCtx context.Context, rel func()) {
			defer s.shutdownWG.Done() // This fires when handleTCP returns

			defer rel() // always release the slot

			defer c.Close() //nolint:errcheck // best-effort close, nothing to do on error

			s.handleTCP(pCtx, c)
		}(conn, tcpPacketCtx, release)
	}
}

// networkForIP returns the network string for the given IP host and transport family.
// family must be "tcp" or "udp".
// Returns "tcp4"/"udp4" for IPv4 literals, "tcp6"/"udp6" for everything else.
// Always use this instead of bare "tcp"/"udp" when binding to an explicit IP literal
// so the OS cannot silently pick an unexpected address family on dual-stack hosts.
func networkForIP(host, family string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		return family + "4"
	}
	return family + "6"
}

// non-blocking! listens on both UDP and TCP ports 53
func (s *Server) startDNSListenerInstance(params dnsListenerParams) (*dnsListenerInstance, error) {
	log := s.getLogger()
	addr := params.Addr
	log.Debug("Starting DNS listener", slog.String("addr", addr))

	// Verify it's an IP before UDP/TCP resolution
	addrHost, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		addrHost = addr
	}
	if net.ParseIP(addrHost) == nil {
		panic2("BUG: startDNSListenerInstance: listener bind address must be a valid IP literal: " + addr)
	}

	udpNet := networkForIP(addrHost, "udp") // "udp4" or "udp6" — prevents dual-stack ambiguity
	log.Debug("Attempting UDP bind for DNS listener...", slog.String("udp_type", udpNet))
	// Assuming addr is a string like "127.0.0.1:53"
	udpAddr, err := net.ResolveUDPAddr(udpNet, addr)
	if err != nil {
		return nil, fmt.Errorf("invalid %q address %q: %w", udpNet, addr, err)
	}
	udpConn, err := net.ListenUDP(udpNet, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("%q bind/listen failed for %q: %w", udpNet, addr, err)
	}

	tcpNet := networkForIP(addrHost, "tcp") // "tcp4" or "tcp6" — prevents dual-stack ambiguity
	log.Debug("Attempting TCP bind for DNS listener...", slog.String("tcp_type", tcpNet))
	tcpAddr, err := net.ResolveTCPAddr(tcpNet, addr) // parses, no DNS for literal IPs, doneabovewithSplitFIXME: this shouldn't attempt to DNS resolve the hostname!
	if err != nil {
		udpConn.Close() //nolint:errcheck // best-effort close, nothing to do on error
		return nil, fmt.Errorf("invalid %q address %q: %w", tcpNet, addr, err)
	}
	tcpLn, err := net.ListenTCP(tcpNet, tcpAddr) // returns *net.TCPListener
	if err != nil {
		udpConn.Close() //nolint:errcheck // best-effort close, nothing to do on error
		return nil, fmt.Errorf("%q bind/listen failed for %q: %w", tcpNet, addr, err)
	}

	instCtx, cancel := context.WithCancel(s.ctx)
	inst := &dnsListenerInstance{params: params, udp: udpConn, tcp: tcpLn, cancel: cancel}

	inst.wg.Add(1)
	go func() {
		defer inst.wg.Done()
		<-instCtx.Done()
		udpConn.Close() //nolint:errcheck // best-effort close, nothing to do on error

		// This wakes up Accept() with an error safely
		tcpLn.Close() //nolint:errcheck // best-effort close, nothing to do on error
	}()

	inst.wg.Add(1)
	s.shutdownWG.Add(1)
	go func() {
		defer inst.wg.Done()
		defer s.shutdownWG.Done()
		s.runDNSUDPLoop(instCtx, udpConn)
	}()

	inst.wg.Add(1)
	s.shutdownWG.Add(1)
	go func() {
		defer inst.wg.Done()
		defer s.shutdownWG.Done()
		s.runDNSTCPLoop(instCtx, tcpLn)
	}()

	return inst, nil
}

// non-blocking!
func (s *Server) rebindDNSListener(params dnsListenerParams) {
	old := s.dnsListener.Load()
	if old != nil && old.params == params {
		s.getLogger().Debug("DNS rebind/relisten not done, params are same")
		return
	}
	newInst, err := s.startDNSListenerInstance(params)
	if err != nil {
		s.logFatal(fmt.Sprintf("DNS listener (re)ind to %+v failed", params), err)
		panic2("BUG: unreachable")
	}
	s.dnsListener.Store(newInst)
	if old != nil {
		old.cancel()
		old.wg.Wait()
	}
}

// non-blocking!
func (s *Server) startDoHListenerInstance(params dohListenerParams) (*dohListenerInstance, error) {
	log := s.getLogger()

	addr := params.Addr
	log.Debug("Starting DoH listener", slog.String("address", addr))
	dohHost, _, dohSplitErr := net.SplitHostPort(addr)
	if dohSplitErr != nil {
		// sanitizeAndValidateConfig already verified this is a valid host:port IP literal
		panic2("BUG: startDoHListenerInstance: invalid addr " + addr)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", s.dohHandler)

	tlsCfg := tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{s.getCert()}, // Use loaded cert, doneFIXME: ensure it was loaded or fail-fast here before tls.Listen(which would have to be torn down if this fails)
	}
	listener, err := tls.Listen(networkForIP(dohHost, "tcp"), addr, &tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("DoH listener failed to bind/listen on %q: %w", addr, err)
	}

	//doneFIXME: XXX: in the future(so now lol) if i ever do reload config.json These structs bake the values in upon initialization. A hot-reload of s.liveConfig will not magically update the HTTP server's timeouts or the active TLS certificates. To actually apply changes to these specific parameters, you would need to tear down the listener and start a new one (a true server restart). ok, we're already doing the relisten, but make sure we do it even when only these cfg values change! or do it unconditionally!

	srv := &http.Server{
		Handler: mux,
		// ReadHeaderTimeout: 3 * time.Second,                                     // Specifically kills slowloris
		// ReadTimeout:       time.Duration(params.ReadTimeoutSec) * time.Second,  // Workaround for CPU/timer bug
		// WriteTimeout:      time.Duration(params.WriteTimeoutSec) * time.Second, // Optional, for responses
		// IdleTimeout:       time.Duration(params.ReadTimeoutSec) * 2 * time.Second,
		ReadHeaderTimeout: time.Duration(params.ReadHeaderTimeoutSec) * time.Second,
		ReadTimeout:       time.Duration(params.ReadTimeoutSec) * time.Second,
		WriteTimeout:      time.Duration(params.WriteTimeoutSec) * time.Second,
		IdleTimeout:       time.Duration(params.IdleTimeoutSec) * time.Second,
	}

	instCtx, cancel := context.WithCancel(s.ctx)
	inst := &dohListenerInstance{params: params, listener: listener, srv: srv, cancel: cancel}

	/*
	       When you call go func(), you aren't running the function immediately. You are telling the Go scheduler: "Hey, when you have a spare millisecond, please start this task."

	       If Add(1) is inside: There is a tiny window of time where the goroutine is "scheduled" but hasn't actually started running.
	       If your shutdown() function calls Wait() during that tiny window, the WaitGroup counter is still 0. The program thinks there is no work to wait for and exits immediately,
	       killing the goroutine before it even begins.

	       If Add(1) is outside: You increment the counter before the goroutine is even created. This ensures that Wait() will see a counter of at least 1,
	       effectively "blocking the exit" until that goroutine starts, runs, and eventually calls Done().

	   The Rule of Thumb: Always Add() in the "parent" goroutine and Done() in the "child" goroutine.
	*/
	inst.wg.Add(1)
	s.shutdownWG.Add(1)
	// Listen for the global shutdown signal to gracefully close the DoH server
	go func() {
		defer inst.wg.Done()
		defer s.shutdownWG.Done() // Signal this watcher is finished
		<-instCtx.Done()
		log := s.getLogger()
		cfg := s.getConfig()
		log.Debug("Shutting down DoH listener instance...", slog.String("addr", addr))
		// Give it a max of 3 seconds to finish existing requests before force closing
		shutdownCtx, cancelDown := context.WithTimeout(context.Background(), time.Duration(cfg.ServerGracefulShutdownSec)*time.Second)
		defer cancelDown()
		if err := srv.Shutdown(shutdownCtx); /*this call returns*/ err != nil && !errors.Is(err, context.Canceled) {
			log.Warn("DoH server shutdown error", wincoe.SafeErr(err))
		}
	}()

	inst.wg.Add(1)
	s.shutdownWG.Add(1)
	go func() {
		defer inst.wg.Done()
		defer s.shutdownWG.Done() // Signal the server is officially stopped
		// Graceful close on shutdown
		defer listener.Close() //nolint:errcheck // best-effort close, nothing to do on error
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.getLogger().Error("doh_serve_failed", wincoe.SafeErr(err), slog.String("addr", addr))
			s.errChan <- fmt.Errorf("DoH server failed on %q: %w", addr, err)
		}
	}()

	s.getLogger().Info("DoH listening", slog.String("address", addr))
	return inst, nil
}

// non-blocking!
func (s *Server) rebindDoHListener(params dohListenerParams) {
	old := s.dohListener.Load()
	if old != nil && old.params == params {
		s.getLogger().Debug("DoH rebind/relisten not done, params are same")
		return
	}
	newInst, err := s.startDoHListenerInstance(params)
	if err != nil {
		s.logFatal(fmt.Sprintf("DoH listener (re)bind to %+v failed", params), err)
		panic2("BUG: unreachable")
	}
	s.dohListener.Store(newInst)
	if old != nil {
		old.cancel()
		old.wg.Wait()
	}
}

func (s *Server) initAdminUI() {
	ui := NewAdminUI(
		&s.liveConfig,
		&s.liveRawConfig,
		s.logMgr.Ptr(),
		s.ruleStore,
		s.hostStore,
		s.blacklist,
		newLoginTracker(),
		s.recentBlocks,
		s.stats,
		uiTemplates0,
	)
	// Wire up the side-effects
	ui.OnSaveWhitelist = s.saveQueryWhitelist
	ui.OnSaveBlacklist = s.saveResponseBlacklist
	ui.OnSaveHosts = s.saveLocalHosts
	ui.OnInvalidatePattern = s.invalidateCacheForPattern
	ui.OnInvalidateBlacklist = s.invalidateCacheForBlacklistedIPs
	ui.OnApplyConfig = func(cfg *Config) error {
		// 1. Convert struct to JSON with inline documentation descriptions
		newData, err := marshalConfigWithDescriptions(cfg)
		if err != nil {
			return fmt.Errorf("marshal error: %w", err)
		}

		// 2. Commit to disk
		if err := s.fileWriter.SafeWriteFile(configFileName, newData, 0600); err != nil {
			return fmt.Errorf("config write due to [Apply] button, failed: %w", err)
		}

		// 3. Trigger hot-reload logic here...
		s.Reload()
		return nil
	}
	//Pass the server's shutdown method directly
	ui.OnShutdown = s.shutdown
	// ui.getExpectedHost = s.currentUIExpectedHost // used by hostValidation

	// Clear any WebUI login lockouts so an operator who locked
	// themselves out with a typo streak can recover via Ctrl+R
	// without restarting the server.
	// WIRE THIS UP: Register Server -> UI event notification!
	s.OnReload(ui.clearLoginLockouts)

	s.adminUI = ui
}

// // return the host:port that the webUI is listening on, which is expected to be in requests (used by hostValidation middleware)
// func (s *Server) currentUIExpectedHost() string {
// 	inst := s.uiListener.Load()
// 	if inst == nil {
// 		return ""
// 	}
// 	return inst.expectedHost
// }

// isCertLoaded reports whether cert was successfully populated by
// tls.LoadX509KeyPair (or equivalent). A zero-value tls.Certificate{}
// has a nil Certificate chain and nil PrivateKey; feeding it to
// tls.Config.Certificates produces SSL_ERROR_NO_CYPHER_OVERLAP on clients
// with zero server-side error output — the worst silent failure mode.
func isCertLoaded(cert *tls.Certificate) bool {
	return len(cert.Certificate) > 0 && cert.PrivateKey != nil
}

// ensureCert is a defence-in-depth guard that must be called at the top of
// every TLS listener start function. It guarantees s.dohCert is valid before
// any tls.Config is constructed.
//
// Normal path: generateCertIfNeeded was already called during Run(); this
// check passes immediately at zero cost.
//
// Recovery path (startup-order bug or future refactor forgets the call):
// we call generateCertIfNeeded now, log a warning so the bug is visible,
// and then re-check. If the cert is STILL zero after generation — which
// would mean tls.LoadX509KeyPair returned a zero struct without erroring,
// a condition that should be impossible — we panic with a clear diagnosis
// rather than proceeding into a silent SSL handshake failure.
func (s *Server) ensureCert() {
	if isCertLoaded(&s.dohCert) {
		return // normal fast path
	}

	log := s.getLogger()
	log.Warn("BUG: TLS cert not loaded before listener start (generateCertIfNeeded was never called or ran out of order); attempting emergency generation now")
	s.generateCertIfNeeded()

	if !isCertLoaded(&s.dohCert) {
		// generateCertIfNeeded calls logFatal (→ s.shutdown + os.Exit) on any
		// load/generation failure, so reaching here means tls.LoadX509KeyPair
		// returned without error but produced an empty struct — impossible in
		// practice but guard it anyway.
		panic2("BUG: s.dohCert is still zero after generateCertIfNeeded(); " +
			"tls.LoadX509KeyPair succeeded but returned no certificate chain — " +
			"cannot start TLS listeners")
	}

	log.Info("Emergency cert generation succeeded; TLS listener can now start")
}

// returns a copy of the cert
func (s *Server) getCert() tls.Certificate {
	s.ensureCert()
	return s.dohCert
}

func (s *Server) startWebUIListenerInstance(params uiListenerParams) (*uiListenerInstance, error) {
	if s.adminUI == nil {
		panic2("BUG: startWebUIListenerInstance called before initAdminUI")
	}
	addr := params.Addr
	uiHost, _, uiSplitErr := net.SplitHostPort(addr)
	if uiSplitErr != nil {
		// sanitizeAndValidateConfig already verified this is a valid host:port IP literal
		panic2("BUG: startWebUIListenerInstance: invalid addr " + addr)
	}
	baseListener, err := net.Listen(networkForIP(uiHost, "tcp"), addr) //doneFIXME: use tcp4 if it's ipv4 or tcp6 if it's ipv6, read the description for net.Listen
	if err != nil {
		return nil, fmt.Errorf("UI listener failed to bind/listen on %q: %w", addr, err)
	}
	// 2. Adaptive Upgrading: Intercept listener if TLS is requested
	var finalListener net.Listener = baseListener
	scheme := "http"
	if params.UseTLS {
		tlsCfg := tls.Config{
			//In Go, a tls.Certificate struct is entirely read-only once it has been loaded into memory. When you pass it to tls.Config, the underlying crypto libraries only read its public certificate chains and private key blocks to perform cryptographic handshakes with incoming clients.
			Certificates: []tls.Certificate{s.getCert()}, // Reuse the keypair directly! well it's a copy now
			MinVersion:   tls.VersionTLS12,
		}
		// Wrap the basic TCP listener inside Go's built-in TLS protocol filter
		finalListener = tls.NewListener(baseListener, &tlsCfg)
		scheme = "https"
	}

	// BETTER APPROACH: Query the active listener for its real bound address.
	// This is guaranteed to be split-safe, and correctly exposes the port
	// if the user passes ":0" for a dynamically allocated port.
	boundAddr := baseListener.Addr().String() //doneTODO: save this and use it for hostValidation middleware
	srv := &http.Server{
		Handler: s.adminUI.SetupRoutes(boundAddr, params.UseTLS),
		//doneTODO: make this configurable?
		// ReadHeaderTimeout: 5 * time.Second,
		// ReadTimeout:       15 * time.Second,
		// WriteTimeout:      15 * time.Second,
		// IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: time.Duration(params.ReadHeaderTimeoutSec) * time.Second,
		ReadTimeout:       time.Duration(params.ReadTimeoutSec) * time.Second,
		WriteTimeout:      time.Duration(params.WriteTimeoutSec) * time.Second,
		IdleTimeout:       time.Duration(params.IdleTimeoutSec) * time.Second,
	}

	instCtx, cancel := context.WithCancel(s.ctx)

	inst := &uiListenerInstance{params: params,
		listener: finalListener,
		//expectedHost: boundAddr,
		srv:    srv,
		cancel: cancel,
	}

	inst.wg.Add(1)
	// Listen for the global shutdown signal to gracefully close the Web UI
	s.shutdownWG.Add(1)
	go func() {
		defer inst.wg.Done()
		defer s.shutdownWG.Done()
		<-instCtx.Done()
		log := s.getLogger()
		log.Debug("Shutting down Web UI listener instance...", slog.String("addr", addr))
		shutdownCtx, cancelDown := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancelDown()
		if err2 := srv.Shutdown(shutdownCtx); /*this call returns*/ err2 != nil && !errors.Is(err2, context.Canceled) {
			log.Warn("webUI server shutdown error", wincoe.SafeErr(err2))
		}
	}()

	inst.wg.Add(1)
	s.shutdownWG.Add(1)
	go func() {
		defer inst.wg.Done()
		defer s.shutdownWG.Done()
		// Graceful close
		defer finalListener.Close() //nolint:errcheck // best-effort close, nothing to do on error
		if err2 := srv.Serve(finalListener); err2 != nil && !errors.Is(err2, http.ErrServerClosed) {
			log := s.getLogger()
			log.Error("ui_serve_failed", wincoe.SafeErr(err2), slog.String("addr", addr))
			s.errChan <- fmt.Errorf("webUI server failed on %q: %w", addr, err2)
		}
	}()

	// Split the address for the logger to maintain your existing clean log output
	host, portStr, err := net.SplitHostPort(boundAddr)
	if err != nil {
		panic2(fmt.Sprintf("BUG: this wasn't supposed to fail, boundAddr=%s err:%v", boundAddr, err))
	}
	log := s.getLogger()
	log.Info("Web UI listening",
		slog.String("scheme", scheme),
		slog.String("host", host),
		slog.String("port", portStr),
		slog.String("url", fmt.Sprintf("%s://%s", scheme, boundAddr)),
	)

	log.Info("Interactive controls available: Ctrl+X to clean exit, Ctrl+R to reload config, Ctrl+C to break gracefully")

	return inst, nil
}

func (s *Server) rebindWebUIListener(params uiListenerParams) {
	old := s.uiListener.Load()
	if old != nil && old.params == params {
		s.getLogger().Debug("webUI rebind/relisten not done, params are same")
		return
	}
	newInst, err := s.startWebUIListenerInstance(params)
	if err != nil {
		s.logFatal(fmt.Sprintf("WebUI listener (re)bind to %+v failed", params), err)
		panic2("BUG: unreachable")
	}
	s.uiListener.Store(newInst)
	if old != nil {
		old.cancel()
		old.wg.Wait()
	}
}

type dnsListenerParams struct {
	Addr string
}

func dnsListenerParamsFrom(cfg *Config) dnsListenerParams {
	return dnsListenerParams{Addr: cfg.ListenDNS}
}

type dohListenerParams struct {
	Addr                 string
	ReadHeaderTimeoutSec int
	ReadTimeoutSec       int
	WriteTimeoutSec      int
	IdleTimeoutSec       int
	CertGeneration       uint64
}

func (s *Server) dohListenerParamsFrom(cfg *Config) dohListenerParams {
	return dohListenerParams{
		Addr:                 cfg.ListenDoH,
		ReadHeaderTimeoutSec: cfg.LocalDoHReadHeaderTimeoutSec,
		ReadTimeoutSec:       cfg.LocalDoHReadTimeoutSec,
		WriteTimeoutSec:      cfg.LocalDoHWriteTimeoutSec,
		IdleTimeoutSec:       cfg.LocalDoHIdleTimeoutSec,
		CertGeneration:       s.certGeneration.Load(),
	}
}

type uiListenerParams struct {
	Addr                 string
	UseTLS               bool
	ReadHeaderTimeoutSec int
	ReadTimeoutSec       int
	WriteTimeoutSec      int
	IdleTimeoutSec       int
	CertGeneration       uint64
}

func (s *Server) uiListenerParamsFrom(cfg *Config) uiListenerParams {
	return uiListenerParams{
		Addr:                 cfg.ListenUI,
		UseTLS:               cfg.WebUIUseTLS,
		ReadHeaderTimeoutSec: cfg.WebUIReadHeaderTimeoutSec,
		ReadTimeoutSec:       cfg.WebUIReadTimeoutSec,
		WriteTimeoutSec:      cfg.WebUIWriteTimeoutSec,
		IdleTimeoutSec:       cfg.WebUIIdleTimeoutSec,
		CertGeneration:       s.certGeneration.Load(),
	}
}

// Replace your existing listener structs with these:
type dnsListenerInstance struct {
	params dnsListenerParams
	udp    *net.UDPConn
	tcp    *net.TCPListener
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type dohListenerInstance struct {
	params   dohListenerParams
	listener net.Listener
	srv      *http.Server
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

type uiListenerInstance struct {
	params   uiListenerParams
	listener net.Listener
	//expectedHost string // baseListener.Addr().String() this is used to limit r.Host to only these aka hostValidation middleware! r is request
	srv    *http.Server
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type rotatingLogWriter struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	file     *os.File
	size     int64
	logger   *slog.Logger
}

func newRotatingLogWriter(path string, maxMB int, logger *slog.Logger) (*rotatingLogWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file %q: %w", path, err)
	}

	var size int64
	if stat, err := f.Stat(); err == nil {
		size = stat.Size()
	}

	// Calculate maxBytes (0 means no limit)
	maxBytes := int64(maxMB) * 1024 * 1024
	if maxMB <= 0 {
		maxBytes = 0 // no limit
	}

	return &rotatingLogWriter{
		path:     path,
		maxBytes: maxBytes,
		file:     f,
		size:     size,
		logger:   logger,
	}, nil
}

func (w *rotatingLogWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return 0, errors.New("log file is not open")
	}
	w.rotateIfNeededYouHoldLock()

	n, err = w.file.Write(p)
	w.size += int64(n)
	if err == nil {
		return n, nil
	} else {
		return n, fmt.Errorf("failed to write to the rotating logger file: %w", err)
	}
}

// must be done under lock!
func (w *rotatingLogWriter) rotateIfNeededYouHoldLock() {
	// Check if rotation is needed
	if w.maxBytes > 0 && w.size >= w.maxBytes {
		w.rotateYouHoldLock()
	}
}
func (w *rotatingLogWriter) RotateIfNeeded() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rotateIfNeededYouHoldLock()
}

// must be done under lock!
func (w *rotatingLogWriter) rotateYouHoldLock() {
	if w.file == nil {
		w.logger.Error("Log rotation failed: log file isn't open yet")
		return
	}

	// 1. Close the current file so Windows doesn't block the rename
	if err := w.file.Close(); err != nil {
		w.logger.Error("Log rotation failed: could not close current log file", slog.String("path", w.path), wincoe.SafeErr(err))
		w.file = nil // clear stale handle so reopenOriginal() starts from a known state
		w.reopenOriginal()
		return
	}
	// Clear the now-closed handle immediately. From this point on, every error
	// path calls reopenOriginal(); if that also fails, w.file stays nil and
	// Write() returns the informative "log file is not open" sentinel rather
	// than a cryptic OS error from writing to a dead file descriptor.
	w.file = nil

	// 2. Determine the dynamic backup name (.1, .2, etc.)
	backupPath := getNextLogBackupName(w.path)

	// 3. Rename the file
	if err := os.Rename(w.path, backupPath); err != nil {
		w.logger.Error("Log rotation failed: rename error", slog.String("path", w.path), slog.String("backup", backupPath), wincoe.SafeErr(err))
		w.reopenOriginal()
		return
	}

	// 4. Attempt to create the fresh log file
	newFile, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		w.logger.Warn("Log rotation failed to create new file; rolling back to previous log", slog.String("path", w.path), wincoe.SafeErr(err))

		// 5. ROLLBACK: Rename it back if creating the new one failed
		if rbErr := os.Rename(backupPath, w.path); rbErr != nil {
			w.logger.Error("CRITICAL: Log rotation rollback failed! Logs may be detached.", slog.String("from", backupPath), slog.String("to", w.path), wincoe.SafeErr(rbErr))
		}

		w.reopenOriginal()
		return
	}

	// Success!
	w.file = newFile
	w.size = 0
	w.logger.Info("Rotated log file", slog.String("path", w.path), slog.String("backup_path", backupPath))
}

// reopenOriginal is a safety net to ensure we always have an open file handle
// to write to, even if rotation or rollback fails.
func (w *rotatingLogWriter) reopenOriginal() {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		w.logger.Error("CRITICAL: Failed to reopen original log file after rotation failure", slog.String("path", w.path), wincoe.SafeErr(err))
	} else {
		w.file = f
	}
}

type ConfigFieldView struct {
	Key   string
	Value string
	Type  string
	Desc  string
	//Options    string // Comma-separated list for dropdowns
	IsPassword bool // Flag to trigger password masking and confirmation
}

func (ui *AdminUI) getConfigFields() []ConfigFieldView {
	cfg := ui.getRawConfig()
	log := ui.getLogger()
	v := reflect.ValueOf(*cfg)
	t := v.Type()
	var fields []ConfigFieldView

	// Dynamically fetch tags so we don't hardcode them!
	// tagUpstreamMode := getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamSelectionMode))
	// tagLogLevel := getJSONTagByOffset(unsafe.Offsetof(Config{}.ConsoleLogLevel))
	// tagBlockMode := getJSONTagByOffset(unsafe.Offsetof(Config{}.BlockMode))
	tagWebUIPwd := getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIPasswordHash))

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		jsonTag := field.Tag.Get("json")
		if jsonTag == "" || jsonTag == "-" {
			continue
		}
		tagKey := strings.Split(jsonTag, ",")[0]

		val := v.Field(i)
		var strVal string
		var typ string

		kind := val.Kind()
		//nolint:exhaustive // We intentionally only process specific primitive types for the UI.
		switch kind {
		case reflect.String:
			strVal = val.String()
			typ = "string"
		case reflect.Int, reflect.Int64, reflect.Int32:
			strVal = fmt.Sprintf("%d", val.Int())
			typ = "int"
		case reflect.Uint, reflect.Uint64, reflect.Uint32:
			strVal = fmt.Sprintf("%d", val.Uint())
			typ = "int"
		case reflect.Bool:
			strVal = fmt.Sprintf("%t", val.Bool())
			typ = "bool"
		case reflect.Slice:
			kind2 := val.Type().Elem().Kind()
			if kind2 == reflect.String {
				var sl []string
				for j := 0; j < val.Len(); j++ {
					sl = append(sl, val.Index(j).String())
				}
				strVal = strings.Join(sl, ", ")
				typ = "[]string"
			} else {
				// Log an explicit warning so you immediately catch un-renderable
				// config slices during development or expansion.
				log.Error("BUG: Config UI generator skipped unsupported non-string slice field",
					slog.String("field", tagKey),
					slog.String("element_type", kind2.String()))
				panic2("BUG: dev must add some code, see the above logged error")
				//continue // Skip non-string slices
			}
		default:
			// Log it so developers know they added an unsupported config type,
			// but safely continue so the UI doesn't crash.
			log.Error("BUG: Config UI generator skipped unsupported field type",
				"field", tagKey,
				"kind", kind.String())
			panic2("BUG: dev must add some code, see the above logged error")
			//continue
		}

		// // Inject dynamic UI constraints based on the resolved tags
		// options := ""
		isPwd := false

		// if tagKey == tagUpstreamMode {
		// 	options = "fastest,failover,strict"
		// } else if tagKey == tagLogLevel {
		// 	options = "debug,info,warn,error"
		// } else if tagKey == tagBlockMode {
		// 	options = "nxdomain,ip_block,drop"
		// } else
		if tagKey == tagWebUIPwd {
			isPwd = true
			strVal = placeHolderPassword // Mask it from the browser completely!
		}

		fields = append(fields, ConfigFieldView{
			Key:   tagKey,
			Value: strVal,
			Type:  typ,
			Desc:  field.Tag.Get("desc"),
			//Options: options,
			IsPassword: isPwd,
		})
	}

	// for i, field := range fields {
	// 	if field.Key == "webui_password_hash" && field.Value != "" {
	// 		fields[i].Value = placeHolderPassword // Mask it from the browser completely!
	// 	}
	// }

	sort.Slice(fields, func(i, j int) bool {
		return fields[i].Key < fields[j].Key
	})

	return fields
}

// This is explicitly intended to hide the pwd hash from webUI view.
const placeHolderPassword = "********"

func (ui *AdminUI) configHandler(w http.ResponseWriter, r *http.Request) {
	log := ui.getLogger()

	if r.Method == http.MethodGet {
		// Optimistic-concurrency version token: embed the config file's mod-time
		// so the browser can send it back on Apply and we can detect staleness.
		var configVersion string
		if fi, statErr := os.Stat(configFileName); statErr == nil {
			configVersion = fmt.Sprintf("%d", fi.ModTime().UnixNano())
		} else if os.IsNotExist(statErr) {
			configVersion = "0" // file not yet created — first-time setup
		} else {
			log.Warn("configHandler: could not stat config file for version token", wincoe.SafeErr(statErr))
			configVersion = "0"
		}

		data := map[string]any{
			"Fields": ui.getConfigFields(),

			"ConfigVersion": configVersion,

			//Dynamically inject the UpstreamURLs JSON tag
			"UpstreamURLsKey": getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamURLs)),
			// Injected so app.js never hard-codes json tag strings.
			// If a Config field is renamed, only the struct tag changes; JS follows automatically.
			"KeyUpstreamSelectionMode": getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamSelectionMode)),
			"KeyConsoleLogLevel":       getJSONTagByOffset(unsafe.Offsetof(Config{}.ConsoleLogLevel)),
			"KeyBlockMode":             getJSONTagByOffset(unsafe.Offsetof(Config{}.BlockMode)),
			"KeyWebUIPasswordHash":     getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIPasswordHash)),
			// Valid option values for select-type fields, comma-separated so app.js never
			// hard-codes enum strings. Changing a constant in Go propagates automatically.
			"OptsUpstreamSelectionMode": strings.Join([]string{
				upstreamSelectionModeFastest,
				upstreamSelectionModeFailover,
				upstreamSelectionModeStrict,
			}, ","),
			"OptsConsoleLogLevel": strings.Join([]string{
				consoleLogLevelDebug,
				consoleLogLevelInfo,
				consoleLogLevelWarn,
				consoleLogLevelError,
			}, ","),
			"OptsBlockMode": strings.Join([]string{
				blockModeNXDOMAIN,
				blockModeIPBlock,
				blockModeDrop,
			}, ","),
		}
		ui.renderTemplate(w, r, "config", data)
		return
	}

	if r.Method == http.MethodPost {
		action := r.FormValue("action")
		if action == "apply" {
			payload := r.FormValue("payload")
			if payload == "" {
				http.Error(w, "empty payload", http.StatusBadRequest)
				return
			}

			var changes map[string]any
			if err := json.Unmarshal([]byte(payload), &changes); err != nil {
				log.Warn("Invalid JSON in config apply", wincoe.SafeErr(err))
				http.Error(w, "invalid JSON payload", http.StatusBadRequest)
				return
			}

			// Optimistic concurrency: refuse to apply if config.json was written to
			// disk after this page was loaded (e.g. a Ctrl+R reload, a concurrent
			// WebUI session, or a manual file edit). The client sends back the
			// mod-time token it received when the page was served.
			//
			// "0" means the file didn't exist when the page loaded (first-time
			// setup), so there is nothing to conflict with. Empty means an old
			// cached page that predates this feature; skip silently for
			// backward-compatibility.
			submittedVersion := r.FormValue("config_version")
			if submittedVersion != "" && submittedVersion != "0" {
				if fi, statErr := os.Stat(configFileName); statErr == nil {
					currentVersion := fmt.Sprintf("%d", fi.ModTime().UnixNano())
					if currentVersion != submittedVersion {
						log.Warn("WebUI config apply rejected: config.json changed on disk since the page was loaded",
							slog.String("page_load_version", submittedVersion),
							slog.String("current_disk_version", currentVersion),
							slog.String("client", r.RemoteAddr),
						)
						http.Error(w,
							"Conflict: config.json was modified on disk since you loaded this page.\n"+
								"This can happen after a Ctrl+R reload, a concurrent session, or a manual file edit.\n"+
								"Please refresh the page (F5) to load the latest config, then re-apply your changes.",
							http.StatusConflict,
						)
						return
					}
				} else if !os.IsNotExist(statErr) {
					// stat failed for an unexpected reason — fail safe rather than
					// silently allowing a potentially conflicting write.
					log.Error("configHandler: stat failed during conflict check", wincoe.SafeErr(statErr))
					http.Error(w, "Internal error: could not verify config file version.", http.StatusInternalServerError)
					return
				}
				//else:
				// os.IsNotExist → file was deleted between page-load and apply;
				// treat as a fresh create and allow the save.
			}
			/*
				Why this works correctly for every case:
				Scenario: Normal single-user apply
				Outcome: Versions match → apply proceeds

				Ctrl+R reload happened between page-load and Apply
				Mod-time changed → 409, user sees clear message

				Manual config.json edit on disk
				Same as above

				Two browser tabs, one applies first
				Second tab's Apply gets 409; after F5 it gets fresh token

				First-time setup (file didn't exist at page-load)
				Token is "0" → check skipped → file created

				Old cached JS (no config_version field sent)
				Empty string → check skipped → backward-compatible

				Successful apply + page redirect
				Page reload fetches new token → subsequent edits work normally
			*/

			// --- NEW HASHING INTERCEPTOR ---
			// Fetch the exact tag for the password field
			tagWebUIPwd := getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIPasswordHash))
			// Hash plaintext password before applying, same as before.
			if plainPwd, ok := changes[tagWebUIPwd].(string); ok {
				// Bcrypt hashes start with $2a$ or $2b$. If it doesn't, assume it's plaintext and hash it.
				//doneTODO: find out why this isn't needed here: && plainPwd != placeHolderPassword  so it's due to displayed vs edited being different areas even tho they seem to be in the same place in the UI.
				if plainPwd != "" && !strings.HasPrefix(plainPwd, "$2") {
					// Fetch current configured cost
					cost := ui.getConfig().WebUIPasswordBcryptCost
					//log.Debug("Hashing the webUI-entered plaintext password, ie. it's not a hash already", slog.Int("cost", cost))
					log.Debug("Hashing the webUI-entered plaintext password", slog.Int("cost", cost), slog.String(configFileName, tagWebUIPwd))
					hashBytes, hashErr := bcrypt.GenerateFromPassword([]byte(plainPwd), cost)
					if hashErr != nil {
						log.Error("Failed to hash new webui password", wincoe.SafeErr(hashErr), slog.Int("cost", cost), slog.String(configFileName, tagWebUIPwd))
						http.Error(w, "failed to hash new password", http.StatusInternalServerError)
						return
					}
					changes[tagWebUIPwd] = string(hashBytes)
				} else if plainPwd == "" { //|| plainPwd == placeHolderPassword {//nah, shouldn't check for this!
					// The input was empty, meaning the user didn't want to change their password.

					// === HEAL INSTEAD OF DELETE ===
					// Force the browser's empty change to inherit our trusted memory state.
					// Even if the disk file was wiped a millisecond ago, maps.Copy will
					// overwrite that vacuum with this valid hash.
					//log.Debug("Will keep using the old password/hash.")
					log.Debug("Password unchanged; retaining active memory hash", slog.String(configFileName, tagWebUIPwd))
					changes[tagWebUIPwd] = ui.getRawConfig().WebUIPasswordHash
				}
			}
			// --- END INTERCEPTOR ---

			// XXX: Parse existing file to preserve unknown keys and overall structure
			data, err11 := os.ReadFile(configFileName)
			if err11 != nil {
				log.Error("Failed to read config file for update", wincoe.SafeErr(err11))
				http.Error(w, "failed to read existing config", http.StatusInternalServerError)
				return
			}
			// === ADD THIS BLOCK (exact parallel to loadMainConfig) ===
			var stripErr error
			data, stripErr = stripConfigDescriptionKeys(data)
			if stripErr != nil {
				log.Error("failed to strip description keys from config file before WebUI update", wincoe.SafeErr(stripErr))
				http.Error(w, "failed to process config file (strip descriptions)", http.StatusInternalServerError)
				return
			}
			// Optional: you could also run the duplicate-key check here for extra safety,
			// but it's not strictly required since we're about to re-validate anyway.
			var raw map[string]any
			if err2 := json.Unmarshal(data, &raw); err2 != nil {
				log.Error("Failed to parse existing config file", wincoe.SafeErr(err2))
				http.Error(w, "failed to parse existing config", http.StatusInternalServerError)
				return
			}

			// Overlay the staged changes
			maps.Copy(raw, changes)
			// for k, v := range changes {
			// 	raw[k] = v
			// }

			// Work from the raw config so tokens like {file:id.key} are preserved.
			rawCfg := ui.getRawConfig().Clone()

			if err := applyConfigChangesToStruct(&rawCfg, raw); err != nil {
				log.Warn("Failed to apply config changes", wincoe.SafeErr(err))
				http.Error(w, "invalid field value: "+err.Error(), http.StatusBadRequest)
				return
			}

			// Marshal the struct — field order follows Config declaration, not A-Z.
			newData, err12 := json.MarshalIndent(rawCfg, "", "  ")
			if err12 != nil {
				log.Error("Failed to marshal updated config", wincoe.SafeErr(err12))
				http.Error(w, "failed to marshal updated config", http.StatusInternalServerError)
				return
			}

			// DRY-RUN VALIDATION: Prevent a bad config from causing a fatal panic on Reload()
			testCfg := defaultConfig()
			dec := json.NewDecoder(bytes.NewReader(newData))
			dec.DisallowUnknownFields()
			if err6 := dec.Decode(&testCfg); err6 != nil {
				//TODO: needs better validation here! but I guess Reload() is doing the proper validation!
				log.Warn("Validation failed for new config", wincoe.SafeErr(err6))
				http.Error(w, "Validation failed (check format/types): "+err6.Error(), http.StatusBadRequest)
				return
			}
			// Resolve tags in the dry-run so hard-checks don't crash on the literal {file:...} string
			resolved, err5 := resolveConfigTags(&testCfg)
			if err5 != nil {
				http.Error(w, "Validation failed (tag resolution): "+err5.Error(), http.StatusBadRequest)
				return
			}

			// --- RUN UNIFIED SANITIZE AND VALIDATE ---
			// Ensure it receives identical clamping, normalization, and bounds checking.
			defCfg := defaultConfig()
			_, errValid := sanitizeAndValidateConfig(log, resolved, &rawCfg, &defCfg, true)
			if errValid != nil {
				http.Error(w, "Validation failed: "+errValid.Error(), http.StatusBadRequest)
				return
			}

			// Commit to disk and trigger hot-reload
			if ui.OnApplyConfig != nil {
				if err7 := ui.OnApplyConfig(&rawCfg); err7 != nil {
					log.Error("Failed to apply config (that is: save&reload)", wincoe.SafeErr(err7))
					http.Error(w, "Failed to save/reload config: "+err7.Error(), http.StatusInternalServerError)
					return
				}
			}

			log.Info("Config updated&saved via WebUI successfully")
			http.Redirect(w, r, "/config", http.StatusSeeOther)
			return
		}
	}
}

// isLoopbackBindHost reports whether the host portion of a "host:port" listen
// address is loopback. Deliberately conservative: 0.0.0.0/:: are NOT loopback
// (they bind every interface, public ones included) and an unparseable host
// (bare hostname other than "localhost") is treated as NOT loopback, so that
// ambiguous cases fall on the side of requiring TLS.
func isLoopbackBindHost(listenAddr string) bool {
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		host = listenAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return strings.EqualFold(host, "localhost")
}

var (
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procSetConsoleCtrlHandler = kernel32.NewProc("SetConsoleCtrlHandler")

	// Global bridge so our Win32 callback can reach your Server instance
	globalConsoleEventTrigger func(eventName string)

	// NEW: Flag to bypass the "Press any key" pause during forced teardowns
	skipInteractivePause atomic.Bool
)

// consoleCtrlHandler must be a top-level function with no free variables for windows.NewCallback()
func consoleCtrlHandler(ctrlType uint32) uintptr {
	const (
		CtrlCEvent        = windows.CTRL_C_EVENT        //0
		CtrlBreakEvent    = windows.CTRL_BREAK_EVENT    //1
		CtrlCloseEvent    = windows.CTRL_CLOSE_EVENT    //2
		CtrlLogoffEvent   = windows.CTRL_LOGOFF_EVENT   //5
		CtrlShutdownEvent = windows.CTRL_SHUTDOWN_EVENT //6
	)

	var eventName string
	switch ctrlType {
	case CtrlCEvent:
		eventName = "CTRL_C_EVENT (Ctrl+C)" //it's the sigChan one that triggers tho (this one does only while in shutdown())
	case CtrlBreakEvent:
		eventName = "CTRL_BREAK_EVENT (Ctrl+Break)"
	case CtrlCloseEvent:
		skipInteractivePause.Store(true) // <-- Bypass pause! Console is closing.
		eventName = "CTRL_CLOSE_EVENT (Console Window Closed)"
	case CtrlLogoffEvent:
		skipInteractivePause.Store(true) // <-- Bypass pause! User is logging out.
		eventName = "CTRL_LOGOFF_EVENT (User Logoff)"
	case CtrlShutdownEvent:
		skipInteractivePause.Store(true) // <-- Bypass pause! OS is shutting down.
		eventName = "CTRL_SHUTDOWN_EVENT (System Shutdown)"
	default:
		// Return 0 (FALSE) for unhandled events so Windows continues standard routing
		return 0
	}

	if globalConsoleEventTrigger != nil {
		// This will block, eventually calling os.Exit() from inside your shutdown sequence.
		// This is required. If we returned 1 immediately, the OS would kill the process mid-cleanup.
		globalConsoleEventTrigger(eventName)
	}

	return 1 // TRUE (Though os.Exit will usually fire before we ever reach this line)
}

var reservedNames = map[string]struct{}{
	"CON": {}, "PRN": {}, "AUX": {}, "NUL": {},
	"COM1": {}, "COM2": {}, "COM3": {}, "COM4": {}, "COM5": {},
	"COM6": {}, "COM7": {}, "COM8": {}, "COM9": {},
	"LPT1": {}, "LPT2": {}, "LPT3": {}, "LPT4": {}, "LPT5": {},
	"LPT6": {}, "LPT7": {}, "LPT8": {}, "LPT9": {},
}

// resolveConfigTags returns a deep-copied *Config with every {file:...} and
// {env:...} token in string and []string fields expanded to its real value.
// The input raw is never mutated; all changes live in the returned copy.
func resolveConfigTags(raw *Config) (*Config, error) {
	if raw == nil {
		return nil, errors.New("nil config")
	}
	resolved0 := raw.Clone()
	resolved := &resolved0

	v := reflect.ValueOf(resolved).Elem()
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		jsonTag := field.Tag.Get("json")
		if jsonTag == "" || jsonTag == "-" {
			continue
		}
		jsonKey := strings.Split(jsonTag, ",")[0]
		val := v.Field(i)

		//The reflection loop is not constructing a new Config. It's only modifying certain fields in place.
		vk := val.Kind()
		switch vk { //nolint:exhaustive //only handing the cases that we know are template-able
		case reflect.String:
			str := val.String()
			resolvedStr, isTag, err := resolveTag(str)
			if isTag {
				if err != nil {
					return nil, fmt.Errorf("field %q resolution failed: %w", jsonKey, err)
				}
				val.SetString(resolvedStr)
			}
		case reflect.Slice:
			if val.Type().Elem().Kind() != reflect.String {
				panic2(fmt.Sprintf("BUG: dev-unhandled case for reflect.Slice that isn't string but it's %q", vk))
				continue
			}
			for j := 0; j < val.Len(); j++ {
				str := val.Index(j).String()
				resolvedStr, isTag, err := resolveTag(str)
				if isTag {
					if err != nil {
						return nil, fmt.Errorf("field %q[%d] resolution failed: %w", jsonKey, j, err)
					}
					val.Index(j).SetString(resolvedStr)
				}
			}
		case reflect.Int, reflect.Bool, reflect.Int8, reflect.Int16, reflect.Int32,
			reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32,
			reflect.Uint64, reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
			//already copied by clone, ignore
		default:
			panic2(fmt.Sprintf("BUG: dev-unhandled case for val.Kind() of %q", vk))
		} //switch
	}
	return resolved, nil
}

// applyConfigChangesToStruct applies the key→value pairs from changes (as
// produced by json.Unmarshal into map[string]any) onto cfg using the json
// struct tags to locate each field.  Only fields whose json tag appears in
// changes are touched; all others are left intact.
// Supported field kinds: string, int/int32/int64, uint/uint32/uint64, bool,
// []string.  Any other kind returns an error.
func applyConfigChangesToStruct(cfg *Config, changes map[string]any) error {
	v := reflect.ValueOf(cfg).Elem()
	t := v.Type()

	// Build a reverse map: json-key → field index, for O(len(changes)) total
	// work instead of O(len(changes)*len(fields)).
	tagToIdx := make(map[string]int, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		key := strings.Split(tag, ",")[0]
		tagToIdx[key] = i
	}

	for jsonKey, rawVal := range changes {
		idx, ok := tagToIdx[jsonKey]
		if !ok {
			return fmt.Errorf("applyConfigChangesToStruct: unknown config key %q", jsonKey)
		}
		fv := v.Field(idx)

		switch fv.Kind() { //nolint:exhaustive // we error on the unsupported ones
		case reflect.String:
			s, ok := rawVal.(string)
			if !ok {
				return fmt.Errorf("field %q: expected string, got %T", jsonKey, rawVal)
			}
			fv.SetString(s)

		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			switch n := rawVal.(type) {
			case float64:
				fv.SetInt(int64(n))
			case int:
				fv.SetInt(int64(n))
			case int64:
				fv.SetInt(n)
			default:
				return fmt.Errorf("field %q: expected int, got %T", jsonKey, rawVal)
			}

		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			switch n := rawVal.(type) {
			case float64:
				if n < 0 {
					return fmt.Errorf("field %q: negative value %v for unsigned field", jsonKey, n)
				}
				fv.SetUint(uint64(n))
			case uint64:
				fv.SetUint(n)
			default:
				return fmt.Errorf("field %q: expected uint, got %T", jsonKey, rawVal)
			}

		case reflect.Bool:
			b, ok := rawVal.(bool)
			if !ok {
				return fmt.Errorf("field %q: expected bool, got %T", jsonKey, rawVal)
			}
			fv.SetBool(b)

		case reflect.Slice:
			if fv.Type().Elem().Kind() != reflect.String {
				return fmt.Errorf("field %q: non-string slice fields are not supported in config edits", jsonKey)
			}
			switch arr := rawVal.(type) {
			case []any:
				strs := make([]string, len(arr))
				for i, item := range arr {
					s, ok := item.(string)
					if !ok {
						return fmt.Errorf("field %q[%d]: expected string element, got %T", jsonKey, i, item)
					}
					strs[i] = s
				}
				fv.Set(reflect.ValueOf(strs))
			case []string:
				cp := make([]string, len(arr))
				copy(cp, arr)
				fv.Set(reflect.ValueOf(cp))
			default:
				return fmt.Errorf("field %q: expected []string, got %T", jsonKey, rawVal)
			}

		default:
			panic2(fmt.Sprintf("field %q: unsupported kind %s", jsonKey, fv.Kind())) //yeah we panic instead!
			return fmt.Errorf("field %q: unsupported kind %s", jsonKey, fv.Kind())
		}
	}
	return nil
}

func (s *Server) getRawConfig() *Config {
	if c := s.liveRawConfig.Load(); c != nil {
		return c
	}
	panic2("BUG: Server.liveRawConfig not initialized before use")
	panic(nil)
}

func (ui *AdminUI) getRawConfig() *Config {
	if ui.liveRawConfig != nil {
		if c := ui.liveRawConfig.Load(); c != nil {
			return c
		}
		panic2("BUG: AdminUI.liveRawConfig.Config isn't inited, should point to the Server.liveRawConfig.Config")
	}
	panic2("BUG: AdminUI.liveRawConfig isn't inited, should point to the Server.liveRawConfig")
	panic(nil)
}

// sanitizeAndValidateConfig handles validation, clamping, and cleaning of configuration fields.
// It is used by both loadMainConfig (on disk load) and configHandler (on WebUI apply) to ensure
// identical constraint enforcement and normalization.
func sanitizeAndValidateConfig(log *slog.Logger, resolvedCfg, rawCfg, defaultCfg *Config, isWebUI bool) (bool, error) {
	var shouldSaveConfig bool

	tagWebUIUseTLS := getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIUseTLS))
	tagWebUIForceTLS := getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIForceTLSOnNonLocalhost))
	tagListenUI := getJSONTagByOffset(unsafe.Offsetof(Config{}.ListenUI))

	boundToLoopback := isLoopbackBindHost(resolvedCfg.ListenUI)

	switch {
	case !resolvedCfg.WebUIUseTLS && !boundToLoopback && resolvedCfg.WebUIForceTLSOnNonLocalhost:
		log.Warn(tagWebUIUseTLS+" was false while "+tagListenUI+" is bound off-loopback; "+
			"auto-promoting to TLS so the bcrypt-checked WebUI password isn't sent as plaintext(thus sniffable) "+
			"Basic-Auth over the network. Set "+tagWebUIForceTLS+" to false to override.",
			slog.String("listen_ui", resolvedCfg.ListenUI))
		resolvedCfg.WebUIUseTLS = true
		rawCfg.WebUIUseTLS = true
		shouldSaveConfig = true //hmm, self-heals?!

	case !resolvedCfg.WebUIUseTLS && !boundToLoopback:
		log.Error(tagWebUIUseTLS+" and "+tagWebUIForceTLS+" are both false while bound off-loopback; "+
			"the WebUI password will be sent in PLAINTEXT (Basic-Auth is base64, not encryption) "+
			"to anyone who can observe this network segment.",
			slog.String("listen_ui", resolvedCfg.ListenUI))

	case !resolvedCfg.WebUIUseTLS && boundToLoopback:
		log.Warn(tagWebUIUseTLS+" is false. Even on loopback, Basic-Auth sends the password as base64 "+
			"(not encrypted) to any other local process/user that can observe loopback traffic.",
			slog.String("listen_ui", resolvedCfg.ListenUI))
	}
	tagWebUIPasswordBcryptCost := getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIPasswordBcryptCost))
	if was := resolvedCfg.WebUIPasswordBcryptCost; was < 12 {
		fallback := 12
		if defaultCfg.WebUIPasswordBcryptCost >= 12 {
			fallback = defaultCfg.WebUIPasswordBcryptCost
		}
		resolvedCfg.WebUIPasswordBcryptCost = fallback
		rawCfg.WebUIPasswordBcryptCost = fallback
		log.Warn(tagWebUIPasswordBcryptCost+" clamped to secure minimum", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	// =========================================================================
	// Group 1: WebUI Server Timeouts & Rate Limits
	// =========================================================================
	tagWebUIReadHeader := getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIReadHeaderTimeoutSec))
	if was := resolvedCfg.WebUIReadHeaderTimeoutSec; was <= 0 {
		fallback := defaultCfg.WebUIReadHeaderTimeoutSec
		resolvedCfg.WebUIReadHeaderTimeoutSec = fallback
		rawCfg.WebUIReadHeaderTimeoutSec = fallback
		log.Warn(tagWebUIReadHeader+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagWebUIRead := getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIReadTimeoutSec))
	if was := resolvedCfg.WebUIReadTimeoutSec; was <= 0 {
		fallback := defaultCfg.WebUIReadTimeoutSec
		resolvedCfg.WebUIReadTimeoutSec = fallback
		rawCfg.WebUIReadTimeoutSec = fallback
		log.Warn(tagWebUIRead+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagWebUIWrite := getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIWriteTimeoutSec))
	if was := resolvedCfg.WebUIWriteTimeoutSec; was <= 0 {
		fallback := defaultCfg.WebUIWriteTimeoutSec
		resolvedCfg.WebUIWriteTimeoutSec = fallback
		rawCfg.WebUIWriteTimeoutSec = fallback
		log.Warn(tagWebUIWrite+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagWebUIIdle := getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIIdleTimeoutSec))
	if was := resolvedCfg.WebUIIdleTimeoutSec; was <= resolvedCfg.WebUIReadTimeoutSec {
		fallback := resolvedCfg.WebUIReadTimeoutSec * 2
		resolvedCfg.WebUIIdleTimeoutSec = fallback
		rawCfg.WebUIIdleTimeoutSec = fallback
		log.Warn(tagWebUIIdle+" clamped(to double the read timeout) to prevent aggressive keep-alive disconnects", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagWebUIMaxLoginFailures := getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIMaxLoginFailures))
	if was := resolvedCfg.WebUIMaxLoginFailures; was <= 0 {
		fallback := defaultCfg.WebUIMaxLoginFailures
		resolvedCfg.WebUIMaxLoginFailures = fallback
		rawCfg.WebUIMaxLoginFailures = fallback
		log.Warn(tagWebUIMaxLoginFailures+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagWebUILoginLockoutSec := getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUILoginLockoutSec))
	if was := resolvedCfg.WebUILoginLockoutSec; was <= 0 {
		fallback := defaultCfg.WebUILoginLockoutSec
		resolvedCfg.WebUILoginLockoutSec = fallback
		rawCfg.WebUILoginLockoutSec = fallback
		log.Warn(tagWebUILoginLockoutSec+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	// =========================================================================
	// Group 2: Local DoH Server Timeouts
	// =========================================================================
	tagDoHHeader := getJSONTagByOffset(unsafe.Offsetof(Config{}.LocalDoHReadHeaderTimeoutSec))
	if was := resolvedCfg.LocalDoHReadHeaderTimeoutSec; was <= 0 {
		fallback := defaultCfg.LocalDoHReadHeaderTimeoutSec
		resolvedCfg.LocalDoHReadHeaderTimeoutSec = fallback
		rawCfg.LocalDoHReadHeaderTimeoutSec = fallback
		log.Warn(tagDoHHeader+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagDoHRead := getJSONTagByOffset(unsafe.Offsetof(Config{}.LocalDoHReadTimeoutSec))
	if was := resolvedCfg.LocalDoHReadTimeoutSec; was <= 0 {
		fallback := defaultCfg.LocalDoHReadTimeoutSec
		resolvedCfg.LocalDoHReadTimeoutSec = fallback
		rawCfg.LocalDoHReadTimeoutSec = fallback
		log.Warn(tagDoHRead+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagDoHWrite := getJSONTagByOffset(unsafe.Offsetof(Config{}.LocalDoHWriteTimeoutSec))
	if was := resolvedCfg.LocalDoHWriteTimeoutSec; was <= 0 {
		fallback := defaultCfg.LocalDoHWriteTimeoutSec
		resolvedCfg.LocalDoHWriteTimeoutSec = fallback
		rawCfg.LocalDoHWriteTimeoutSec = fallback
		log.Warn(tagDoHWrite+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagDoHIdle := getJSONTagByOffset(unsafe.Offsetof(Config{}.LocalDoHIdleTimeoutSec))
	if was := resolvedCfg.LocalDoHIdleTimeoutSec; was <= resolvedCfg.LocalDoHReadTimeoutSec {
		fallback := resolvedCfg.LocalDoHReadTimeoutSec * 2
		resolvedCfg.LocalDoHIdleTimeoutSec = fallback
		rawCfg.LocalDoHIdleTimeoutSec = fallback
		log.Warn(tagDoHIdle+" clamped(to double the read timeout) to prevent premature keep-alive drops", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	// =========================================================================
	// Group 3: Upstream Client & Connection Pools
	// =========================================================================
	tagUpstreamDialTimeoutSec := getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamDialTimeoutSec))
	if was := resolvedCfg.UpstreamDialTimeoutSec; was <= 0 {
		fallback := defaultCfg.UpstreamDialTimeoutSec
		resolvedCfg.UpstreamDialTimeoutSec = fallback
		rawCfg.UpstreamDialTimeoutSec = fallback
		log.Warn(tagUpstreamDialTimeoutSec+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagUpstreamClientTimeoutSec := getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamClientTimeoutSec))
	// Constraint A: Absolute lower bound check
	if was := resolvedCfg.UpstreamClientTimeoutSec; was <= 0 {
		fallback := defaultCfg.UpstreamClientTimeoutSec
		resolvedCfg.UpstreamClientTimeoutSec = fallback
		rawCfg.UpstreamClientTimeoutSec = fallback
		log.Warn(tagUpstreamClientTimeoutSec+" clamped (prevents infinite hanging client connections)", slog.Int("was", was), slog.Int("clamp", fallback))
	}
	// Constraint B: Relational validation check (Sequential, never an 'else if')
	if was := resolvedCfg.UpstreamClientTimeoutSec; was < resolvedCfg.UpstreamDialTimeoutSec {
		fallback := resolvedCfg.UpstreamDialTimeoutSec
		resolvedCfg.UpstreamClientTimeoutSec = fallback
		rawCfg.UpstreamClientTimeoutSec = fallback
		log.Warn(tagUpstreamClientTimeoutSec+" clamped (cannot be less than dial timeout "+tagUpstreamDialTimeoutSec+")",
			slog.Int("was", was), slog.Int("clamp", fallback))
	}

	// 1. TCP KeepAlive (Absolute Floor)
	tagUpstreamTCPKeepAlive := getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamTCPKeepAliveSec))
	if was := resolvedCfg.UpstreamTCPKeepAliveSec; was <= 0 {
		fallback := defaultCfg.UpstreamTCPKeepAliveSec // e.g., 15
		resolvedCfg.UpstreamTCPKeepAliveSec = fallback
		rawCfg.UpstreamTCPKeepAliveSec = fallback
		log.Warn(tagUpstreamTCPKeepAlive+" clamped (must be > 0)", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	// 2. HTTP/2 Read Idle Timeout
	tagH2ReadIdle := getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamH2ReadIdleTimeoutSec))
	if was := resolvedCfg.UpstreamH2ReadIdleTimeoutSec; was <= 0 {
		fallback := defaultCfg.UpstreamH2ReadIdleTimeoutSec // e.g., 5
		resolvedCfg.UpstreamH2ReadIdleTimeoutSec = fallback
		rawCfg.UpstreamH2ReadIdleTimeoutSec = fallback
		log.Warn(tagH2ReadIdle+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}
	// Constraint B: If H2 Read Idle >= Global HTTP Idle, the HTTP connection is closed
	// before the H2 health ping ever gets a chance to fire.
	if was := resolvedCfg.UpstreamH2ReadIdleTimeoutSec; was >= resolvedCfg.UpstreamIdleConnTimeoutSec {
		fallback := resolvedCfg.UpstreamIdleConnTimeoutSec / 2
		if fallback < 1 {
			fallback = 1
		}
		resolvedCfg.UpstreamH2ReadIdleTimeoutSec = fallback
		rawCfg.UpstreamH2ReadIdleTimeoutSec = fallback
		log.Warn(tagH2ReadIdle+" clamped (must trigger before the connection is closed by "+
			getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamIdleConnTimeoutSec))+")",
			slog.Int("was", was), slog.Int("clamp", fallback))
	}

	// 3. HTTP/2 Ping Timeout
	tagH2PingTimeout := getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamH2PingTimeoutSec))
	if was := resolvedCfg.UpstreamH2PingTimeoutSec; was <= 0 {
		fallback := defaultCfg.UpstreamH2PingTimeoutSec // e.g., 2
		resolvedCfg.UpstreamH2PingTimeoutSec = fallback
		rawCfg.UpstreamH2PingTimeoutSec = fallback
		log.Warn(tagH2PingTimeout+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}
	// Constraint B: You don't want a ping timeout to be longer than the interval between pings
	if was := resolvedCfg.UpstreamH2PingTimeoutSec; was >= resolvedCfg.UpstreamH2ReadIdleTimeoutSec {
		fallback := resolvedCfg.UpstreamH2ReadIdleTimeoutSec - 1
		if fallback < 1 {
			fallback = 1
		}
		resolvedCfg.UpstreamH2PingTimeoutSec = fallback
		rawCfg.UpstreamH2PingTimeoutSec = fallback
		log.Warn(tagH2PingTimeout+" clamped (cannot be >= to the H2 read idle timeout)",
			slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagServerShutdown := getJSONTagByOffset(unsafe.Offsetof(Config{}.ServerGracefulShutdownSec))
	if was := resolvedCfg.ServerGracefulShutdownSec; was <= 0 {
		// No complex relational constraints needed here, just a sane floor.
		fallback := defaultCfg.ServerGracefulShutdownSec // e.g., 3
		resolvedCfg.ServerGracefulShutdownSec = fallback
		rawCfg.ServerGracefulShutdownSec = fallback
		log.Warn(tagServerShutdown+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagCertLogTimeoutSec := getJSONTagByOffset(unsafe.Offsetof(Config{}.CertLogTimeoutSec))
	if was := resolvedCfg.CertLogTimeoutSec; was <= 0 {
		fallback := defaultCfg.CertLogTimeoutSec
		resolvedCfg.CertLogTimeoutSec = fallback
		rawCfg.CertLogTimeoutSec = fallback
		log.Warn(tagCertLogTimeoutSec+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagUpstreamRetryBackoffMs := getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamRetryBackoffMs))
	if was := resolvedCfg.UpstreamRetryBackoffMs; was <= 0 {
		fallback := defaultCfg.UpstreamRetryBackoffMs
		resolvedCfg.UpstreamRetryBackoffMs = fallback
		rawCfg.UpstreamRetryBackoffMs = fallback
		log.Warn(tagUpstreamRetryBackoffMs+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagUpstreamRetriesPerQuery := getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamRetriesPerQuery))
	if was := resolvedCfg.UpstreamRetriesPerQuery; was < 0 {
		fallback := defaultCfg.UpstreamRetriesPerQuery
		resolvedCfg.UpstreamRetriesPerQuery = fallback
		rawCfg.UpstreamRetriesPerQuery = fallback
		log.Warn(tagUpstreamRetriesPerQuery+" clamped (cannot be negative)", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagUpstreamIdleConnTimeout := getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamIdleConnTimeoutSec))
	if was := resolvedCfg.UpstreamIdleConnTimeoutSec; was <= 0 {
		fallback := defaultCfg.UpstreamIdleConnTimeoutSec
		resolvedCfg.UpstreamIdleConnTimeoutSec = fallback
		rawCfg.UpstreamIdleConnTimeoutSec = fallback
		log.Warn(tagUpstreamIdleConnTimeout+" clamped (connections stay open indefinitely or drop unpredictably)", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagUpstreamMaxIdleConns := getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamMaxIdleConns))
	if was := resolvedCfg.UpstreamMaxIdleConns; was <= 0 {
		fallback := defaultCfg.UpstreamMaxIdleConns
		resolvedCfg.UpstreamMaxIdleConns = fallback
		rawCfg.UpstreamMaxIdleConns = fallback
		log.Warn(tagUpstreamMaxIdleConns+" clamped (disables global keep-alive reuse)", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagUpstreamMaxIdleConnsPerHost := getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamMaxIdleConnsPerHost))
	// Constraint A: Absolute lower bound check
	if was := resolvedCfg.UpstreamMaxIdleConnsPerHost; was <= 0 {
		fallback := defaultCfg.UpstreamMaxIdleConnsPerHost
		resolvedCfg.UpstreamMaxIdleConnsPerHost = fallback
		rawCfg.UpstreamMaxIdleConnsPerHost = fallback
		log.Warn(tagUpstreamMaxIdleConnsPerHost+" clamped (Go default of 2 severely throttles throughput)", slog.Int("was", was), slog.Int("clamp", fallback))
	}
	// Constraint B: Relational validation check (Sequential, never an 'else if')
	if was := resolvedCfg.UpstreamMaxIdleConnsPerHost; was > resolvedCfg.UpstreamMaxIdleConns {
		// Defensive check: Per-host pool limit can't realistically exceed global pool limit
		fallback := resolvedCfg.UpstreamMaxIdleConns
		resolvedCfg.UpstreamMaxIdleConnsPerHost = fallback
		rawCfg.UpstreamMaxIdleConnsPerHost = fallback
		log.Warn(tagUpstreamMaxIdleConnsPerHost+" clamped (cannot exceed "+tagUpstreamMaxIdleConns+")",
			slog.Int("was", was),
			slog.Int("clamp", fallback),
			slog.Int(tagUpstreamMaxIdleConns, resolvedCfg.UpstreamMaxIdleConns),
		)
	}

	// =========================================================================
	// Group 4: Local Client & Server Buffer Safeguards
	// =========================================================================
	tagMaxConcurrentDNSTCPConns := getJSONTagByOffset(unsafe.Offsetof(Config{}.MaxConcurrentDNSTCPConns))
	if was := resolvedCfg.MaxConcurrentDNSTCPConns; was <= 0 {
		fallback := defaultCfg.MaxConcurrentDNSTCPConns
		resolvedCfg.MaxConcurrentDNSTCPConns = fallback
		rawCfg.MaxConcurrentDNSTCPConns = fallback
		log.Warn(tagMaxConcurrentDNSTCPConns+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagMaxConcurrentDNSUDPQueries := getJSONTagByOffset(unsafe.Offsetof(Config{}.MaxConcurrentDNSUDPQueries))
	if was := resolvedCfg.MaxConcurrentDNSUDPQueries; was <= 0 {
		fallback := defaultCfg.MaxConcurrentDNSUDPQueries
		resolvedCfg.MaxConcurrentDNSUDPQueries = fallback
		rawCfg.MaxConcurrentDNSUDPQueries = fallback
		log.Warn(tagMaxConcurrentDNSUDPQueries+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagClientTCPTimeoutSec := getJSONTagByOffset(unsafe.Offsetof(Config{}.ClientTCPTimeoutSec))
	if was := resolvedCfg.ClientTCPTimeoutSec; was <= 0 {
		fallback := defaultCfg.ClientTCPTimeoutSec
		resolvedCfg.ClientTCPTimeoutSec = fallback
		rawCfg.ClientTCPTimeoutSec = fallback
		log.Warn(tagClientTCPTimeoutSec+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagDoHMaxRequestBodyBytes := getJSONTagByOffset(unsafe.Offsetof(Config{}.DoHMaxRequestBodyBytes))
	if was := resolvedCfg.DoHMaxRequestBodyBytes; was <= 0 {
		fallback := defaultCfg.DoHMaxRequestBodyBytes
		resolvedCfg.DoHMaxRequestBodyBytes = fallback
		rawCfg.DoHMaxRequestBodyBytes = fallback
		log.Warn(tagDoHMaxRequestBodyBytes+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagDNSUDPBufferSize := getJSONTagByOffset(unsafe.Offsetof(Config{}.DNSUDPBufferSize))
	if was := resolvedCfg.DNSUDPBufferSize; was < 512 || was > 65535 {
		fallback := defaultCfg.DNSUDPBufferSize
		resolvedCfg.DNSUDPBufferSize = fallback
		rawCfg.DNSUDPBufferSize = fallback
		log.Warn(tagDNSUDPBufferSize+" clamped (must be within standard Ethernet bounds 512-65535)", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	// =========================================================================
	// Group 5: Core Engine Limits & Cache Operations
	// =========================================================================
	tagGlobalRateQPS := getJSONTagByOffset(unsafe.Offsetof(Config{}.GlobalRateQPS))
	if was := resolvedCfg.GlobalRateQPS; was <= 0 {
		fallback := defaultCfg.GlobalRateQPS
		resolvedCfg.GlobalRateQPS = fallback
		rawCfg.GlobalRateQPS = fallback
		log.Warn(tagGlobalRateQPS+" clamped (must be greater than 0)", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagGlobalBurstQPS := getJSONTagByOffset(unsafe.Offsetof(Config{}.GlobalBurstQPS))
	// Constraint A: Absolute lower bound check
	if was := resolvedCfg.GlobalBurstQPS; was <= 0 {
		fallback := defaultCfg.GlobalBurstQPS
		resolvedCfg.GlobalBurstQPS = fallback
		rawCfg.GlobalBurstQPS = fallback
		log.Warn(tagGlobalBurstQPS+" clamped (must be greater than 0)", slog.Int("was", was), slog.Int("clamp", fallback))
	}
	// Constraint B: Relational check (Executed sequentially, NEVER as an 'else if')
	if was := resolvedCfg.GlobalBurstQPS; was < resolvedCfg.GlobalRateQPS {
		fallback := resolvedCfg.GlobalRateQPS
		resolvedCfg.GlobalBurstQPS = fallback
		rawCfg.GlobalBurstQPS = fallback
		log.Warn(tagGlobalBurstQPS+" clamped (cannot be less than "+tagGlobalRateQPS+")", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagClientRateQPS := getJSONTagByOffset(unsafe.Offsetof(Config{}.ClientRateQPS))
	if was := resolvedCfg.ClientRateQPS; was <= 0 {
		fallback := defaultCfg.ClientRateQPS
		resolvedCfg.ClientRateQPS = fallback
		rawCfg.ClientRateQPS = fallback
		log.Warn(tagClientRateQPS+" clamped (must be greater than 0)", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagClientBurstQPS := getJSONTagByOffset(unsafe.Offsetof(Config{}.ClientBurstQPS))
	// Constraint A: Absolute lower bound check
	if was := resolvedCfg.ClientBurstQPS; was <= 0 {
		fallback := defaultCfg.ClientBurstQPS
		resolvedCfg.ClientBurstQPS = fallback
		rawCfg.ClientBurstQPS = fallback
		log.Warn(tagClientBurstQPS+" clamped (must be greater than 0)", slog.Int("was", was), slog.Int("clamp", fallback))
	}
	// Constraint B: Relational check (Executed sequentially, NEVER as an 'else if')
	if was := resolvedCfg.ClientBurstQPS; was < resolvedCfg.ClientRateQPS {
		fallback := resolvedCfg.ClientRateQPS
		resolvedCfg.ClientBurstQPS = fallback
		rawCfg.ClientBurstQPS = fallback
		log.Warn(tagClientBurstQPS+" clamped (cannot be less than "+tagClientRateQPS+")", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagCacheMinTTL := getJSONTagByOffset(unsafe.Offsetof(Config{}.CacheMinTTL))
	if was := resolvedCfg.CacheMinTTL; was < cacheMinTTLClamp {
		resolvedCfg.CacheMinTTL = cacheMinTTLClamp
		rawCfg.CacheMinTTL = cacheMinTTLClamp
		log.Warn(tagCacheMinTTL+" clamped to safe minimum", slog.Int("was", was), slog.Int("clamp", cacheMinTTLClamp))
	}

	tagCacheMaxEntries := getJSONTagByOffset(unsafe.Offsetof(Config{}.CacheMaxEntries))
	if was := resolvedCfg.CacheMaxEntries; was <= 0 {
		fallback := defaultCfg.CacheMaxEntries
		resolvedCfg.CacheMaxEntries = fallback
		rawCfg.CacheMaxEntries = fallback
		log.Warn(tagCacheMaxEntries+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagCacheJanitorIntervalMinutes := getJSONTagByOffset(unsafe.Offsetof(Config{}.CacheJanitorIntervalMinutes))
	if was := resolvedCfg.CacheJanitorIntervalMinutes; was <= 0 {
		fallback := defaultCfg.CacheJanitorIntervalMinutes
		resolvedCfg.CacheJanitorIntervalMinutes = fallback
		rawCfg.CacheJanitorIntervalMinutes = fallback
		log.Warn(tagCacheJanitorIntervalMinutes+" clamped to safe minimum interval", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagCacheNegativeTTLSec := getJSONTagByOffset(unsafe.Offsetof(Config{}.CacheNegativeTTLSec))
	if was := resolvedCfg.CacheNegativeTTLSec; was < 0 {
		fallback := defaultCfg.CacheNegativeTTLSec
		resolvedCfg.CacheNegativeTTLSec = fallback
		rawCfg.CacheNegativeTTLSec = fallback
		log.Warn(tagCacheNegativeTTLSec+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagFileWriterMaxRetries := getJSONTagByOffset(unsafe.Offsetof(Config{}.FileWriterMaxRetries))
	if was := resolvedCfg.FileWriterMaxRetries; was <= 0 { //TODO: shouldn't we support 0 retries? aka 1 try if fails fails, no retrying!?!
		fallback := defaultCfg.FileWriterMaxRetries
		resolvedCfg.FileWriterMaxRetries = fallback
		rawCfg.FileWriterMaxRetries = fallback
		log.Warn(tagFileWriterMaxRetries+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagFileWriterRetryBackoffMs := getJSONTagByOffset(unsafe.Offsetof(Config{}.FileWriterRetryBackoffMs))
	if was := resolvedCfg.FileWriterRetryBackoffMs; was <= 0 {
		fallback := defaultCfg.FileWriterRetryBackoffMs
		resolvedCfg.FileWriterRetryBackoffMs = fallback
		rawCfg.FileWriterRetryBackoffMs = fallback
		log.Warn(tagFileWriterRetryBackoffMs+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagBlockedResponseTTLSec := getJSONTagByOffset(unsafe.Offsetof(Config{}.BlockedResponseTTLSec))
	if was := resolvedCfg.BlockedResponseTTLSec; was <= 0 { // so 0 means defaults hmm... TODO: shall we do this for others too? < 0 is defaults for some others
		fallback := defaultCfg.BlockedResponseTTLSec
		resolvedCfg.BlockedResponseTTLSec = fallback
		rawCfg.BlockedResponseTTLSec = fallback
		log.Warn(tagBlockedResponseTTLSec+" clamped", slog.Uint64("was", uint64(was)), slog.Uint64("clamp", uint64(fallback)))
	}

	tagLocalHostsOverrideTTLSec := getJSONTagByOffset(unsafe.Offsetof(Config{}.LocalHostsOverrideTTLSec))
	if was := resolvedCfg.LocalHostsOverrideTTLSec; was == 0 {
		fallback := defaultCfg.LocalHostsOverrideTTLSec
		resolvedCfg.LocalHostsOverrideTTLSec = fallback
		rawCfg.LocalHostsOverrideTTLSec = fallback
		log.Warn(tagLocalHostsOverrideTTLSec+" clamped", slog.Uint64("was", uint64(was)), slog.Uint64("clamp", uint64(fallback)))
	}

	tagMaxRecentBlocks := getJSONTagByOffset(unsafe.Offsetof(Config{}.MaxRecentBlocks))
	if was := resolvedCfg.MaxRecentBlocks; was <= 0 {
		fallback := defaultCfg.MaxRecentBlocks
		resolvedCfg.MaxRecentBlocks = fallback
		rawCfg.MaxRecentBlocks = fallback
		log.Warn(tagMaxRecentBlocks+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagUILogMaxLines := getJSONTagByOffset(unsafe.Offsetof(Config{}.UILogMaxLines))
	if was := resolvedCfg.UILogMaxLines; was <= 0 {
		fallback := defaultCfg.UILogMaxLines
		resolvedCfg.UILogMaxLines = fallback
		rawCfg.UILogMaxLines = fallback
		log.Warn(tagUILogMaxLines+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	tagLogMaxSizeMB := getJSONTagByOffset(unsafe.Offsetof(Config{}.LogMaxSizeMB))
	if was := resolvedCfg.LogMaxSizeMB; was <= 0 {
		fallback := defaultCfg.LogMaxSizeMB
		resolvedCfg.LogMaxSizeMB = fallback
		rawCfg.LogMaxSizeMB = fallback
		log.Warn(tagLogMaxSizeMB+" clamped", slog.Int("was", was), slog.Int("clamp", fallback))
	}

	// =========================================================================
	// IP Strings Parsing & Post-Processing Operations
	// =========================================================================
	/*
		In Go's standard library, net.ParseIP() always returns a 16-byte slice for any valid address it reads, whether it's IPv4 or IPv6:
		If you pass it an IPv6 address like "::", it returns 16 bytes of zeros ([0, 0, ... 0]).
		If you pass it an IPv4 address like "127.0.0.1", it returns a 16-byte slice containing an IPv4-mapped IPv6 address (12 bytes of padding followed by 127, 0, 0, 1).
	*/
	{ // tiny scope to prevent locals from leaking
		// Validate and parse BlockIP (IPv4)
		ipV4Raw := net.ParseIP(resolvedCfg.BlockIP)
		ip4 := ipV4Raw.To4()
		if ip4 != nil {
			resolvedCfg.BlockIPv4Parsed = ip4
			rawCfg.BlockIPv4Parsed = ip4
		} else {
			tag := getJSONTagByOffset(unsafe.Offsetof(Config{}.BlockIP))
			msg := fmt.Sprintf("Invalid IPv4 address %q for %q in config file %q", resolvedCfg.BlockIP, tag, configFileName)
			log.Error(msg, slog.String(tag, resolvedCfg.BlockIP))
			return shouldSaveConfig, fmt.Errorf("%s", msg)
		}

		// Validate and parse BlockIPv6 (IPv6)
		ipV6Raw := net.ParseIP(resolvedCfg.BlockIPv6)
		isIPv6 := ipV6Raw != nil && ipV6Raw.To4() == nil
		if isIPv6 {
			resolvedCfg.BlockIPv6Parsed = ipV6Raw
			rawCfg.BlockIPv6Parsed = ipV6Raw
		} else {
			tag := getJSONTagByOffset(unsafe.Offsetof(Config{}.BlockIPv6))
			msg := fmt.Sprintf("Invalid IPv6 address %q for %q in config file %q", resolvedCfg.BlockIPv6, tag, configFileName)
			log.Error(msg, slog.String(tag, resolvedCfg.BlockIPv6))
			return shouldSaveConfig, fmt.Errorf("%s", msg)
		}
	} //end tiny scope

	// //TODO: do I have to set the parseds to rawCfg too?!
	// if ip := net.ParseIP(resolvedCfg.BlockIP); ip != nil && ip.To4() != nil {
	// 	resolvedCfg.BlockIPv4Parsed = ip.To4()
	// 	rawCfg.BlockIPv4Parsed = ip.To4()
	// } else {
	// 	const IP0 = "0.0.0.0"
	// 	const zero = 0
	// 	resolvedCfg.BlockIP = IP0
	// 	rawCfg.BlockIP = IP0
	// 	resolvedCfg.BlockIPv4Parsed = net.IPv4(zero, zero, zero, zero).To4()
	// 	rawCfg.BlockIPv4Parsed = resolvedCfg.BlockIPv4Parsed // TODO: hopefully no need to have diff. instances of this here?
	// }

	// // Clean up and pre-parse IPv6
	// if ip := net.ParseIP(resolvedCfg.BlockIPv6); ip != nil && ip.To16() != nil {
	// 	resolvedCfg.BlockIPv6Parsed = ip.To16()
	// 	rawCfg.BlockIPv6Parsed = ip.To16() // TODO: do we need this to be same instance for equals to say equals anywhere?
	// } else {
	// 	const IPv6Zero = "::"
	// 	resolvedCfg.BlockIPv6 = IPv6Zero
	// 	resolvedCfg.BlockIPv6Parsed = net.ParseIP(IPv6Zero).To16()
	// 	rawCfg.BlockIPv6Parsed = resolvedCfg.BlockIPv6Parsed // TODO: hopefully no need to have diff. instances of this here?
	// }

	// Validate ListenDoH host is a literal IP (required for TLS cert SAN)
	tagListenDoH := getJSONTagByOffset(unsafe.Offsetof(Config{}.ListenDoH))
	if doHHost, _, splitErr := net.SplitHostPort(resolvedCfg.ListenDoH); splitErr != nil {
		return shouldSaveConfig, fmt.Errorf("%q %q is not a valid host:port, actually must be IP:port, err: %w", tagListenDoH, resolvedCfg.ListenDoH, splitErr)
	} else if net.ParseIP(doHHost) == nil {
		return shouldSaveConfig, fmt.Errorf("%q host %q must be an IP literal with no surrounding spaces (not a hostname(because we can't look it up without DNS)) for TLS cert generation", tagListenDoH, doHHost)
	}
	//tagListenUI := getJSONTagByOffset(unsafe.Offsetof(Config{}.ListenUI)) // dup
	if uiHost, _, splitErr := net.SplitHostPort(resolvedCfg.ListenUI); splitErr != nil {
		return shouldSaveConfig, fmt.Errorf("%q %q is not a valid host:port, actually must be IP:port, err: %w", tagListenUI, resolvedCfg.ListenUI, splitErr)
	} else if net.ParseIP(uiHost) == nil {
		return shouldSaveConfig, fmt.Errorf("%q host %q must be an IP literal with no surrounding spaces (not a hostname(because we can't look it up without DNS)) for TLS cert generation", tagListenUI, uiHost)
	}

	resolvedCfg.ConsoleLogLevel = strings.ToLower(strings.TrimSpace(resolvedCfg.ConsoleLogLevel))
	switch resolvedCfg.ConsoleLogLevel {
	case consoleLogLevelDebug, "d", consoleLogLevelInfo, "i", consoleLogLevelWarn, "warning", "w", consoleLogLevelError, "e":
		// Valid
	default:
		msg := fmt.Sprintf("Unknown console_log_level %q in config file %q. Allowed values: debug, info, warn, error",
			resolvedCfg.ConsoleLogLevel,
			configFileName,
		)
		log.Error(msg, slog.String("console_log_level", resolvedCfg.ConsoleLogLevel))
		return shouldSaveConfig, fmt.Errorf("%s", msg)
	}
	rawCfg.ConsoleLogLevel = resolvedCfg.ConsoleLogLevel

	resolvedCfg.BlockMode = strings.ToLower(resolvedCfg.BlockMode) //XXX: lowercasing this for future comparisons to be easier!
	switch resolvedCfg.BlockMode {
	case blockModeNXDOMAIN:
		// already canonical

	case blockModeIPBlock:
		// already canonical

	case "block_ip", "ipblock", "blockip": //aka aliases
		resolvedCfg.BlockMode = blockModeIPBlock
		shouldSaveConfig = true

	case blockModeDrop:
		// already canonical

	default:
		msg := fmt.Sprintf("Unknown BlockMode %q in config file %q, must be one of these: %q, %q, %q",
			resolvedCfg.BlockMode,
			configFileName,
			blockModeNXDOMAIN,
			blockModeIPBlock,
			blockModeDrop,
		)
		log.Error(msg, slog.String("blockmode", resolvedCfg.BlockMode))
		return shouldSaveConfig, fmt.Errorf("%s", msg)
	}
	rawCfg.BlockMode = resolvedCfg.BlockMode
	//TODO: see if I've to shouldSaveConfig for anything else here, above maybe?

	// Validate UpstreamSelectionMode. Unknown values (e.g. from a hand-edited config) are
	// reset to the safe default so the server starts rather than refusing to boot.
	resolvedCfg.UpstreamSelectionMode = strings.ToLower(strings.TrimSpace(resolvedCfg.UpstreamSelectionMode))
	switch resolvedCfg.UpstreamSelectionMode {
	case upstreamSelectionModeFastest, upstreamSelectionModeFailover, upstreamSelectionModeStrict:
		// valid — no action required
	default:
		msg := fmt.Sprintf("Unknown upstream_selection_mode %q in config file %q, must be one of these: %q, %q, %q",
			resolvedCfg.UpstreamSelectionMode,
			configFileName,
			upstreamSelectionModeFastest,
			upstreamSelectionModeFailover,
			upstreamSelectionModeStrict,
		)
		log.Error(msg, slog.String("upstream_selection_mode", resolvedCfg.UpstreamSelectionMode))
		return shouldSaveConfig, fmt.Errorf("%s", msg)
	}
	rawCfg.UpstreamSelectionMode = resolvedCfg.UpstreamSelectionMode

	// Hard-check URLs unconditionally to prevent downstream panics
	for i, rawURL := range resolvedCfg.UpstreamURLs {
		if _, err := url.Parse(rawURL); err != nil {
			return shouldSaveConfig, fmt.Errorf("invalid upstream URL at index %d: %w", i, err)
		}
		if _, err := hostFromURL(rawURL); err != nil {
			return shouldSaveConfig, fmt.Errorf("invalid upstream host at index %d: %w", i, err)
		}
	}

	if len(resolvedCfg.UpstreamSNIHostnames) > len(resolvedCfg.UpstreamURLs) {
		const msg = "there are more SNIs vs URLs for upstream, only the opposite is allowed ( >= URLs than SNIs which then inherit the SNI from URLs)"
		log.Warn(msg)
		return shouldSaveConfig, fmt.Errorf("%s", msg)
	}
	// Ensure SNIHostnames has the same length as UpstreamURLs, falling back to the URL's hostname
	for i := len(resolvedCfg.UpstreamSNIHostnames); i < len(resolvedCfg.UpstreamURLs); i++ {
		host, err2 := hostFromURL(resolvedCfg.UpstreamURLs[i])
		if err2 != nil {
			log.Warn("invalid upstream URL during SNI fill", slog.Int("index", i), wincoe.SafeErr(err2))
			return shouldSaveConfig, fmt.Errorf("invalid upstream URL at index %d: %w", i, err2)
		}
		rawCfg.UpstreamSNIHostnames = append(rawCfg.UpstreamSNIHostnames, host)
		resolvedCfg.UpstreamSNIHostnames = append(resolvedCfg.UpstreamSNIHostnames, host)
		shouldSaveConfig = true
	}
	//FIXME: this is weird, what are we doing here below vs above?!
	for i := range resolvedCfg.UpstreamURLs {
		if resolvedCfg.UpstreamSNIHostnames[i] != "" {
			continue
		}
		host, err2 := hostFromURL(resolvedCfg.UpstreamURLs[i])
		if err2 != nil {
			log.Error("invalid upstream URL", slog.Int("at_index", i), wincoe.SafeErr(err2))
			return shouldSaveConfig, fmt.Errorf("invalid upstream URL at index %d: %w", i, err2)
		}
		rawCfg.UpstreamSNIHostnames[i] = host
		resolvedCfg.UpstreamSNIHostnames[i] = host
		shouldSaveConfig = true
	}
	log.Debug("Using upstream SNI hostnames:",
		SafeStringSlice("SNI_hostnames", resolvedCfg.UpstreamSNIHostnames),
	)

	// Helper closure to apply the cleaning and track if a save is needed
	checkAndClean := func(resolvedTarget, rawTarget *string, configKey, fallback string) error {
		if cleaned, changed := cleanFileName(log, *resolvedTarget, configKey, fallback); changed {
			if *resolvedTarget != *rawTarget {
				errStr := fmt.Sprintf("Won't overwrite template %q with cleaned value %q, you must do it manually then rerun.", *rawTarget, cleaned)
				if isWebUI {
					return errors.New(errStr)
				} else {
					return errors.New("FATAL: " + errStr)
				}
			}
			*resolvedTarget = cleaned
			*rawTarget = cleaned
			if !shouldSaveConfig {
				shouldSaveConfig = true
			}
		}
		return nil
	}

	if err := checkAndClean(&resolvedCfg.BlacklistFile, &rawCfg.BlacklistFile, getJSONTagByOffset(unsafe.Offsetof(Config{}.BlacklistFile)), defaultCfg.BlacklistFile); err != nil {
		return shouldSaveConfig, err
	}
	if err := checkAndClean(&resolvedCfg.WhitelistFile, &rawCfg.WhitelistFile, getJSONTagByOffset(unsafe.Offsetof(Config{}.WhitelistFile)), defaultCfg.WhitelistFile); err != nil {
		return shouldSaveConfig, err
	}
	if err := checkAndClean(&resolvedCfg.LogQueriesFile, &rawCfg.LogQueriesFile, getJSONTagByOffset(unsafe.Offsetof(Config{}.LogQueriesFile)), defaultCfg.LogQueriesFile); err != nil {
		return shouldSaveConfig, err
	}
	if err := checkAndClean(&resolvedCfg.LogEverythingFile, &rawCfg.LogEverythingFile, getJSONTagByOffset(unsafe.Offsetof(Config{}.LogEverythingFile)), defaultCfg.LogEverythingFile); err != nil {
		return shouldSaveConfig, err
	}
	if err := checkAndClean(&resolvedCfg.HostsFile, &rawCfg.HostsFile, getJSONTagByOffset(unsafe.Offsetof(Config{}.HostsFile)), defaultCfg.HostsFile); err != nil {
		return shouldSaveConfig, err
	}

	if err := checkAndClean(&resolvedCfg.TLSCertFile, &rawCfg.TLSCertFile, getJSONTagByOffset(unsafe.Offsetof(Config{}.TLSCertFile)), defaultCfg.TLSCertFile); err != nil {
		return shouldSaveConfig, err
	}
	if err := checkAndClean(&resolvedCfg.TLSKeyFile, &rawCfg.TLSKeyFile, getJSONTagByOffset(unsafe.Offsetof(Config{}.TLSKeyFile)), defaultCfg.TLSKeyFile); err != nil {
		return shouldSaveConfig, err
	}

	if isWebUI && resolvedCfg.WebUIPasswordHash == "" {
		//only for webUI case, non-webUI will ask for pwd to be set on startup, after this!
		tagWebUIPwd := getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIPasswordHash))
		return shouldSaveConfig, errors.New(tagWebUIPwd + " cannot be empty at this point")
	}

	return shouldSaveConfig, nil
}

// cleanFileName returns the cleaned filename and a boolean indicating if the original was modified.
// //extracted this method to be a free function so the standalone logic can use it independently
func cleanFileName(log *slog.Logger, original, configKey, fallback string) (string, bool) {
	if original == "" {
		if fallback == "" {
			msg := fmt.Sprintf("BUG: dev fail: passed empty filename to clean for config key %q and the fallback was also empty!", configKey)
			log.Error(msg, slog.String("config_key", configKey))
			panic(msg)
		}
		log.Warn("Bad filename in config, used fallback",
			slog.String("for_config_key", configKey),
			slog.String("bad_filename", original),
			slog.String("fallback_filename", fallback))

		// Ensure the fallback itself is clean before returning
		cleaned := filepath.Clean(fallback) //FIXME: not a fan of having to call Clean twice; for DRY purposes.
		if cleaned != fallback {
			msg := fmt.Sprintf("BUG: dev fail: fallback(%q) for config key %q had to be cleaned into %q", fallback, configKey, cleaned)
			log.Error(msg, slog.String("config_key", configKey), slog.String("fallback_filename", fallback), slog.String("filename_cleaned", cleaned))
			panic(msg)
		}
		return cleaned, true
	}

	cleaned := filepath.Clean(original)
	// Reject Windows reserved device names (CON, NUL, COM1, etc.).
	// filepath.Base handles any directory prefix; TrimRight strips trailing
	// dots and spaces that Windows itself strips before resolving the name.
	baseName := strings.ToUpper(strings.TrimRight(filepath.Base(cleaned), ". "))
	if _, reserved := reservedNames[baseName]; reserved {
		log.Warn("Config filename is a reserved Windows device name; using fallback",
			slog.String("for_config_key", configKey),
			slog.String("reserved_filename", cleaned),
			slog.String("fallback_filename", fallback))
		return filepath.Clean(fallback), true
	}
	if cleaned != original {
		log.Debug("Cleaned filename from config file",
			slog.String("config_key", configKey),
			slog.String("filename_before", original),
			slog.String("filename_after", cleaned))
		return cleaned, true
	}

	return original, false
}

// NormalizeDomain returns a clean, lowercased domain pattern suitable for rules/hosts.
// Handles trailing dot, whitespace, IDN safety (future).
func NormalizeDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	// // Future: punycode / IDN validation here
	// if s == "" {
	// 	return ""
	// }
	return s
}

const (
	blockModeNXDOMAIN = "nxdomain"
	blockModeIPBlock  = "ip_block"
	blockModeDrop     = "drop"
)

// upstreamSelectionMode* are the only valid values for Config.UpstreamSelectionMode.
// They are used in Go logic, in the sanitizeAndValidateConfig validator, and injected
// into the HTML template so app.js never hard-codes these strings.
const (
	upstreamSelectionModeFailover = "failover"
	upstreamSelectionModeFastest  = "fastest"
	upstreamSelectionModeStrict   = "strict"
)

// consoleLogLevel* are the canonical values for Config.ConsoleLogLevel understood by
// parseConsoleLogLevel. Aliases ("d", "w", "e") remain accepted for human convenience
// but these constants are the only values written to disk and shown in the WebUI.
const (
	consoleLogLevelDebug = "debug"
	consoleLogLevelInfo  = "info"
	consoleLogLevelWarn  = "warn"
	consoleLogLevelError = "error"
)

// Changed quantifier from + to * to allow matching empty tags like {file:}
var configTagRegex = regexp.MustCompile(`\{(file|env):([^{}]*)\}`)

// resolveTag extracts the content of {file:filename} or {env:VAR} which may appear multiple times within a string.
// tag aka template
// It returns the resolved text, a boolean indicating if a tag was found, and an error if it fails.
func resolveTag(input string) (resolved string, isTag bool, err error) {
	var firstErr error
	matchedAny := false

	// Find and replace all instances of {file:...} or {env:...}
	resolved = configTagRegex.ReplaceAllStringFunc(input, func(match string) string {
		matchedAny = true // Track that we encountered at least one tag syntax
		// If we've already hit an error on a previous tag in this string, skip processing
		if firstErr != nil {
			return match
		}

		// Extract the type (file/env) and the value inside the tag
		matches := configTagRegex.FindStringSubmatch(match)
		if len(matches) != 3 {
			return match
		}

		tagType := matches[1]
		tagValue := strings.TrimSpace(matches[2])

		// Explicitly catch empty or whitespace-only tags
		if tagValue == "" {
			firstErr = fmt.Errorf("empty followup inside {%s:} tag, should be {%s:SOMETHINGHERE}", tagType, tagType)
			return match
		}

		switch tagType {
		case "file":
			filename := strings.TrimRight(tagValue, ". ")
			filename = strings.ToUpper(filename)
			// Strict directory traversal prevention
			if strings.ContainsAny(filename, `/\:`) {
				firstErr = fmt.Errorf("path separators not allowed in {file:...} — must be in same directory: %q", filename)
				return match
			}
			if _, bad := reservedNames[filename]; bad {
				firstErr = fmt.Errorf("reserved Windows filename original: %q, processed:%q", tagValue, filename)
				return match
			}
			configDir := filepath.Dir(configFileName)
			path := filepath.Join(configDir, filename) //only look for the file in same dir as config.json
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				firstErr = fmt.Errorf("failed to read external config file %q: %w", path, readErr)
				return match
			}
			// Trim trailing newlines commonly found in text files
			return strings.TrimSpace(string(data))

		case "env":
			val, ok := os.LookupEnv(tagValue)
			if !ok {
				firstErr = fmt.Errorf("required environment variable %q is not set", tagValue)
				return match
			}
			//trim spaces around the value
			return strings.TrimSpace(val)
		}

		return match
	})

	// If any of the inline tags failed, return the error but preserve matchedAny as true
	if firstErr != nil {
		return "", matchedAny, firstErr
	}

	return resolved, matchedAny, nil
}

// marshalConfigWithDescriptions produces a JSON encoding of cfg with each
// field preceded by a "_description_<key>" entry containing the field's
// `desc` struct tag.  The result is valid standard JSON and is fully
// round-trippable: stripConfigDescriptionKeys removes the description
// entries before the standard decoder processes the file on load.
func marshalConfigWithDescriptions(cfg *Config) ([]byte, error) {
	t := reflect.TypeOf(*cfg)
	v := reflect.ValueOf(*cfg)

	var buf bytes.Buffer
	buf.WriteString("{\n")

	first := true
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		jsonTag := field.Tag.Get("json")
		if jsonTag == "" || jsonTag == "-" {
			continue
		}
		jsonKey, _, _ := strings.Cut(jsonTag, ",")
		if jsonKey == "" || jsonKey == "-" {
			continue
		}

		if !first {
			buf.WriteString(",\n")
		}
		first = false

		// Write the _description_ entry if a desc tag is present.
		if desc := field.Tag.Get("desc"); desc != "" {
			descKeyBytes, err := json.Marshal("_description_" + jsonKey)
			if err != nil {
				return nil, fmt.Errorf("marshalConfigWithDescriptions: marshal desc key for %q: %w", jsonKey, err)
			}
			descValBytes, err := json.Marshal(desc)
			if err != nil {
				return nil, fmt.Errorf("marshalConfigWithDescriptions: marshal desc value for %q: %w", jsonKey, err)
			}
			buf.WriteString("  ")
			buf.Write(descKeyBytes)
			buf.WriteString(": ")
			buf.Write(descValBytes)
			buf.WriteString(",\n")
		}

		// Write the real field.
		keyBytes, err := json.Marshal(jsonKey)
		if err != nil {
			return nil, fmt.Errorf("marshalConfigWithDescriptions: marshal key %q: %w", jsonKey, err)
		}
		valBytes, err := json.Marshal(v.Field(i).Interface())
		if err != nil {
			return nil, fmt.Errorf("marshalConfigWithDescriptions: marshal value for %q: %w", jsonKey, err)
		}
		// Re-indent multi-line values (slices, objects) to match surrounding 2-space indent.
		var indented bytes.Buffer
		if err := json.Indent(&indented, valBytes, "  ", "  "); err != nil {
			return nil, fmt.Errorf("marshalConfigWithDescriptions: indent value for %q: %w", jsonKey, err)
		}
		buf.WriteString("  ")
		buf.Write(keyBytes)
		buf.WriteString(": ")
		buf.Write(indented.Bytes())
	}

	buf.WriteString("\n}")
	return buf.Bytes(), nil
}

// stripConfigDescriptionKeys removes all "_description_*" (and any other "_*")
// top-level keys from the raw JSON bytes before the standard decoder processes
// the config file.  This lets DisallowUnknownFields work correctly even when
// the file was written by marshalConfigWithDescriptions.
//
// It also re-encodes through a map[string]json.RawMessage, which loses the
// original key order — that is intentional and harmless for loading.
func stripConfigDescriptionKeys(data []byte) ([]byte, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("stripConfigDescriptionKeys: unmarshal: %w", err)
	}
	for k := range raw {
		if strings.HasPrefix(k, "_") {
			delete(raw, k)
		}
	}
	out, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("stripConfigDescriptionKeys: re-marshal: %w", err)
	}
	return out, nil
}

// Close syncs and closes the underlying log file.
// The writer must not be used after Close returns.
func (w *rotatingLogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	if err := w.file.Sync(); err != nil {
		w.logger.Warn("log file sync on close failed", wincoe.SafeErr(err))
	}
	err := w.file.Close()
	w.file = nil
	if err == nil {
		return nil
	} else {
		return fmt.Errorf("rotatingLogWriter.Close() failed: %w", err)
	}
}

// LoggerManager owns the active *slog.Logger and any underlying file handles
// (rotatingLogWriters) so callers can reinitialise or close them cleanly.
//
// Child components (AdminUI, UpstreamManager, …) receive a pointer to the
// inner atomic so they always read the latest logger without holding a
// reference to LoggerManager itself.
type LoggerManager struct {
	ptr     atomic.Pointer[slog.Logger]
	mu      sync.Mutex
	closers []io.Closer // rotating log writers registered by Reinit
}

// NewLoggerManager creates a manager seeded with the given bootstrap logger.
// No file handles are registered; call Reinit once real log files are open.
func NewLoggerManager(bootstrap *slog.Logger) *LoggerManager {
	lm := &LoggerManager{}
	lm.ptr.Store(bootstrap)
	return lm
}

// Get returns the current logger, falling back to slog.Default() if uninitialised
// (should never happen in production but guards tests that build Server partially).
func (lm *LoggerManager) Get() *slog.Logger {
	if l := lm.ptr.Load(); l != nil {
		return l
	}
	slog.Default().Error("BUG: LoggerManager.ptr is nil, using slog.Default()")
	return slog.Default()
}

// Ptr returns a pointer to the inner atomic so child structs (AdminUI,
// UpstreamManager, wincoe.FileWriter …) can receive a stable reference
// that always reflects the latest logger after a Reinit.
func (lm *LoggerManager) Ptr() *atomic.Pointer[slog.Logger] {
	return &lm.ptr
}

// Set atomically swaps the logger without touching file handles.
// Use Reinit when the swap accompanies new file handles.
func (lm *LoggerManager) Set(l *slog.Logger) {
	lm.ptr.Store(l)
}

// Reinit atomically swaps the logger, registers new closers (typically
// *rotatingLogWriter instances), and closes the previously registered ones.
// It is safe to call on config reload.
func (lm *LoggerManager) Reinit(l *slog.Logger, newClosers ...io.Closer) error {
	lm.mu.Lock()
	old := lm.closers
	lm.closers = newClosers
	lm.mu.Unlock()

	lm.ptr.Store(l) // readers see the new logger from this point

	var errs []error
	for _, c := range old {
		if err := c.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Close closes all registered file handles. Safe to call multiple times.
// Call this in tests after the server is done so temporary directories
// can be deleted.
func (lm *LoggerManager) Close() error {
	lm.mu.Lock()
	closers := lm.closers
	lm.closers = nil
	lm.mu.Unlock()

	var errs []error
	for _, c := range closers {
		if err := c.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
