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
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"expvar"
	"maps"
	"math"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"sync/atomic"
	"unsafe"

	"fmt"
	"html/template"
	"io"
	stdlog "log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
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
	"golang.org/x/net/idna"
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
	ListenUI                string   `json:"listen_ui"     desc:"IP:port for the web admin UI. Must be a specific interface IP literal (not the 0.0.0.0/:: wildcard, which would make the WebUI unreachable). TLS is auto-enabled for non-loopback addresses when webui_force_tls_on_non_localhost is true."`
	TLSCertFile             string   `json:"tls_cert_file" desc:"filename(no path!) of the TLS certificate file (PEM format), stored next to config.json, used for local DoH and WebUI. Auto-generated as self-signed, if not on-disk."`
	TLSKeyFile              string   `json:"tls_key_file"  desc:"filename(no path!) of the TLS private key file (PEM format), stored next to config.json, used for local DoH and WebUI. Auto-generated as self-signed, if not on-disk."`
	UpstreamURLs            []string `json:"upstream_urls" desc:"HTTPS URLs of upstream DoH resolvers (e.g. https://9.9.9.9/dns-query). Must use IP literals. Order determines failover priority. If you use the template '{builtin:clientexe}'(without the single quotes, doh) it will be replaced with the querying executable name (useful for NextDNS URLs)"`
	UpstreamSNIHostnames    []string `json:"upstream_sni_hostnames" desc:"TLS SNI hostnames corresponding to each upstream_urls entry (e.g. dns.quad9.net). Falls back to the URL host if omitted or shorter than upstream_urls."`
	UpstreamSelectionMode   string   `json:"upstream_selection_mode"    desc:"Strategy for querying upstreams: 'failover' (sticky, auto-heals), 'fastest' (race all, first valid wins), 'strict' (all must agree or query is dropped)."`
	UpstreamRetriesPerQuery int      `json:"upstream_retries_per_query" desc:"Additional retry attempts after the first try fails (0 = no retries; total tries = 1 + this value)."`
	BlockMode               string   `json:"block_mode"  desc:"Action for blocked queries: 'nxdomain' (return NXDOMAIN), 'ip_block' (return block_ip/block_ipv6 addresses), 'drop' (for DoH clients it actually replies with 503 Service Unavailable, otherwise it will just cause long waits/timeouts for clients by not replying anything, TODO: maybe remove this drop mode)."`
	//WhitelistMode           bool     `json:"whitelist_mode" desc:"If true (default), the default policy is deny-all-except-whitelisted: a query is only allowed if it matches an enabled whitelist rule (or a local host override). If false, the default policy is allow-all-except-blocklisted: whitelist rules are ignored for the allow/deny decision and every query is allowed by default. In BOTH modes the query blocklist (query_blocklist_file / query_blocklist_external_hosts_file), and the response IP blacklist for the actual returned IPs, are always checked first and always take priority over this policy."`
	WhitelistMode bool `json:"whitelist_mode" desc:"If true (default), the default policy is deny-all-except-whitelisted: a query is only allowed if it matches an enabled whitelist rule (or a local host override). If false, the default policy is allow-all-except-blocklisted: whitelist rules play no role in the allow/deny decision and every query is allowed by default. In BOTH modes the query blocklist (query_blocklist_file / query_blocklist_external_hosts_file) is always checked first and always takes priority over this policy, and the response-IP blacklist is always applied to the actual returned IPs regardless of mode."`
	//cantFIXME: probably can't but "block_mode" from above is hardcoded in the desc of the below two: // cantFIXME: Go struct tags must be string literals.
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

	// FieldModifiedAt records, for each JSON config key that has ever been
	// changed via the WebUI's /config Apply action, the timestamp of that
	// most recent change — powering the "Last Modified" column on the
	// WebUI config page, mirroring the identical column already present for
	// Rules/Local Hosts/Response Blacklist (see RuleEntry.ModifiedAt,
	// LocalHostRule.ModifiedAt, BlacklistRecord.ModifiedAt).
	//
	// Persisted on disk as "_modified_at_<key>" top-level JSON entries
	// (mirroring the existing "_description_<key>" convention written by
	// marshalConfigWithDescriptions and stripped the same way on load — see
	// extractFieldModifiedAtTimestamps/stripConfigDescriptionKeys), NOT as a
	// literal Config field — hence json:"-" here. A field with no recorded
	// entry (never edited via the WebUI, e.g. still at its on-disk/default
	// value, or a fresh install) simply has no map entry and displays "—"
	// (see formatModifiedAt). A field last changed via direct hand-editing
	// of config.json (bypassing the WebUI) keeps whatever timestamp was
	// last recorded by the WebUI, if any — an accepted limitation, the same
	// class of best-effort metadata already tolerated for the
	// legacy-migration timestamps in loadLocalHosts/loadResponseBlacklist/
	// loadRuleStoreFile.
	FieldModifiedAt map[string]time.Time `json:"-"`

	GlobalRateQPS                    int    `json:"qps_rate_globally"    desc:"Maximum DNS queries per second across all clients combined (token-bucket sustained rate)."`
	GlobalBurstQPS                   int    `json:"qps_burst_globally"   desc:"Maximum burst of DNS queries allowed globally above the sustained qps_rate_globally limit."`
	ClientRateQPS                    int    `json:"qps_rate_per_client"  desc:"Maximum DNS queries per second allowed from a single client IP."`
	ClientBurstQPS                   int    `json:"qps_burst_per_client" desc:"Maximum burst of DNS queries allowed from a single client IP above qps_rate_per_client."`
	WebUIRateQPS                     int    `json:"webui_qps_rate_globally"    desc:"Maximum WebUI HTTP requests per second across all clients combined (token-bucket sustained rate). Independent of qps_rate_globally, which only governs DNS query traffic."`
	WebUIBurstQPS                    int    `json:"webui_qps_burst_globally"   desc:"Maximum burst of WebUI HTTP requests allowed globally above the sustained webui_qps_rate_globally limit."`
	WebUIClientRateQPS               int    `json:"webui_qps_rate_per_client"  desc:"Maximum WebUI HTTP requests per second allowed from a single client IP."`
	WebUIClientBurstQPS              int    `json:"webui_qps_burst_per_client" desc:"Maximum burst of WebUI HTTP requests allowed from a single client IP above webui_qps_rate_per_client."`
	CacheMinTTL                      uint32 `json:"cache_min_ttl"        desc:"Minimum TTL (seconds) for any cached DNS response, overriding lower upstream TTLs. 0 means no minimum (upstream TTL is respected, which if 0 means don't cache)."`
	CacheMaxEntries                  int    `json:"cache_max_entries"    desc:"Maximum DNS cache entries. New entries are silently dropped when the limit is reached until expired entries are evicted."`
	WhitelistFile                    string `json:"whitelist_file"       desc:"filename(no path!) of the query-whitelist JSON file, stored next to config.json. Created automatically with an empty whitelist if absent. Only consulted when whitelist_mode is true; the query blocklist is always checked first and always takes priority over these rules."`
	BlacklistFile                    string `json:"blacklist_file"       desc:"filename(no path!) of the response-IP blacklist JSON file, stored next to config.json. Created automatically with safe defaults if absent."`
	HostsFile                        string `json:"hosts_file"           desc:"filename(no path!) of the local host-override JSON file, stored next to config.json. Resolved locally without needing to match the whitelist rules first. The query blocklist is checked before this and takes priority over it, unless local_hosts_override_query_blocklist is true."`
	QueryBlocklistFile               string `json:"query_blocklist_file" desc:"filename(no path!) of the dnsbollocks-owned, mutable query-blocklist override JSON file, stored next to config.json. Holds 'block' patterns (always block a query outright, regardless of whitelist_mode or any whitelist rule) and 'except' patterns (cancel a block coming ONLY from query_blocklist_external_hosts_file — never from a 'block' pattern here, and never bypassing the normal whitelist/default policy on their own). Always checked first, before whitelist rules and local host overrides (see local_hosts_override_query_blocklist). Created automatically with an empty ruleset if absent."`
	QueryBlocklistExternalHostsFile  string `json:"query_blocklist_external_hosts_file" desc:"optional path to a read-only, standard hosts-file (e.g. StevenBlack Hosts) used as an additional query-blocklist source; unlike other file settings this is NOT restricted to a bare filename (it can be absolute, or relative to the working directory) since dnsbollocks never writes to it. Syntax per line: '<IPv4|IPv6> <host> [<alias> ...]'; '#' starts a comment through end-of-line, even mid-line. Only lines whose mapping IP is the unspecified address (0.0.0.0 or ::) contribute hostnames to the block set — this is the conventional blocklist signal used by StevenBlack Hosts and similar files. Lines with any other mapping IP (e.g. 127.0.0.1 localhost, ::1 localhost, 255.255.255.255 broadcasthost) are deliberately ignored for blocking (still counted/logged as non-standard) so ordinary hosts-file loopback/broadcast entries never false-positive-block. The mapped IP is never used as a DNS answer from this layer; intentional local overrides belong in hosts_file. Matches exact hostnames only (no wildcards) — put dnsbollocks-specific wildcard patterns in query_blocklist_file instead. Empty (default) disables this layer entirely. A local 'except' pattern in query_blocklist_file can cancel a block coming from this file, but never bypasses whitelist_mode/whitelist rules on its own."`
	LocalHostsOverrideQueryBlocklist bool   `json:"local_hosts_override_query_blocklist" desc:"If false (default), the query blocklist (query_blocklist_file / query_blocklist_external_hosts_file) is checked before local host overrides (hosts_file), so a blocklisted domain stays blocked even if it also has a local host override. If true, a matching local host override is resolved directly and the query blocklist is skipped entirely for that query."`
	LogDir                           string `json:"log_dir" desc:"Directory where all log files will be saved. Can be absolute or relative(to config dir). If empty aka \"\" then it defaults_to/uses config dir(which is current directory when exe was started). Log file names will be stripped of any folder paths and forced into this directory."`
	LogQueriesFile                   string `json:"log_queries" desc:"filename(no path!) to the DNS query-only log file (JSON lines). Created automatically."`
	LogQueriesSimpleFile             string `json:"log_queries_simple" desc:"filename(no path!) to a simple, plain-text (non-JSON) per-query log file: one line per query formatted as 'timestamp type domain action ips-list'. Created automatically. Complements log_queries for fast human scanning; cross-reference the identical timestamp in log_queries for exe/protocol/rule-id/timing details."`
	LogEverythingFile                string `json:"log_file"    desc:"filename(no path!) to the full system log file (JSON lines, all levels including debug). Created automatically."`
	ConsoleLogLevel                  string `json:"console_log_level" desc:"Minimum log level printed to the console: 'debug', 'info', 'warn', or 'error'. File logs always receive all levels."`
	LogMaxSizeMB                     int    `json:"log_max_size_mb"   desc:"Maximum log file size in megabytes before rotation. Rotated files are renamed with a sequential numeric suffix (.1, .2, ...)."`
	AllowRunAsAdmin                  bool   `json:"allow_run_as_admin" desc:"If false (default), the process exits immediately when running with Windows administrator privileges as a safety guardrail."`
	HideConsole                      bool   `json:"hide_console" desc:"If true, detaches from the console window entirely at startup (equivalent in effect to a -H=windowsgui build)(for max.effect run it from a .lnk not from a .bat unless you append an & in the .bat): no console window is shown and no console I/O is possible for the remainder of this run. Interactive features (initial password-setup prompt, Ctrl+R/Ctrl+X/Ctrl+C/Alt+V keyboard shortcuts) become unavailable once detached, so webui_password_hash must already be set beforehand (e.g. run --hash-password once with this off first). Use the WebUI instead: Apply & Reload replaces Ctrl+R, and the Shutdown button on the Stats page replaces Ctrl+X. Logging continues to the configured log files unaffected. Re-checked only at startup, never on reload; toggling this requires a full process restart to take effect."`
	BlockAAAAasEmptyNoError          bool   `json:"block_aaaa_as_empty_noerror" desc:"Return NOERROR with an empty answer for blocked AAAA queries instead of NXDOMAIN, preventing Windows from caching the domain as non-existent and breaking IPv4 fallback (e.g. ssh to github.com)."`
	AllowHTTPSIfAAllowed             bool   `json:"allow_https_if_a_allowed"  desc:"If true, an HTTPS-type DNS query is automatically allowed whenever an A-type whitelist rule permits the same domain, without needing a separate HTTPS rule."`
	RemoveHTTPSIPHints               bool   `json:"remove_https_ip_hints"     desc:"Strip ipv4hint and ipv6hint parameters from HTTPS DNS records in upstream responses, forcing clients to resolve IPs via A/AAAA queries instead of using embedded hints."`
	UseEDEInBlockedReply             bool   `json:"use_ede_in_blocked_reply"  desc:"Attach an EDNS0 Extended DNS Error (EDE) record to blocked responses so clients and diagnostic tools can see a human-readable reason for the block."`

	WebUIPasswordHash              string `json:"webui_password_hash"               desc:"Bcrypt hash of the web admin UI password. Set via --hash-password flag or the WebUI config page. Never store a plaintext password here."`
	WebUIPasswordBcryptCost        int    `json:"webui_password_bcrypt_cost"        desc:"Bcrypt cost factor used when hashing new passwords (minimum enforced: 4, max is 31). Higher values are slower but more resistant to brute-force."`
	WebUIUseTLS                    bool   `json:"webui_use_tls"                     desc:"Serve the web admin UI over HTTPS using the auto-generated self-signed certificate. Strongly recommended for any non-loopback address."`
	WebUIForceTLSOnNonLocalhost    bool   `json:"webui_force_tls_on_non_localhost"  desc:"Automatically promote webui_use_tls to true when listen_ui is bound to a non-loopback address, preventing the password from being transmitted as plaintext."`
	WebUIMaxLoginFailures          int    `json:"webui_max_login_failures"          desc:"Number of consecutive failed WebUI login attempts from a single IP before that IP is locked out."`
	WebUILoginLockoutSec           int    `json:"webui_login_lockout_sec"           desc:"Duration in seconds a client IP remains locked out after exceeding webui_max_login_failures."`
	WebUIAuthSessionMode           string `json:"webui_auth_session_mode"            desc:"How the WebUI forces Basic-Auth clients to periodically re-enter credentials: 'legacy' (default) never forces it — the browser keeps sending its cached credential until it exits. 'session_cookie' issues an HMAC-signed, HttpOnly cookie alongside a successful login; once webui_auth_session_timeout_minutes elapses since that cookie was (re)issued, the next request is rejected with 401 (forcing the browser to evict its cached credential and re-prompt) and a fresh cookie is issued so the immediate retry succeeds. 'time_bucket' rotates the WWW-Authenticate realm string every webui_auth_session_timeout_minutes so a browser whose cached credential is keyed to a now-stale realm can no longer auto-supply it and must re-prompt; needs no cookies, but forces every connected client to re-prompt at the same moment."`
	WebUIAuthSessionTimeoutMinutes int    `json:"webui_auth_session_timeout_minutes" desc:"Minutes before webui_auth_session_mode ('session_cookie' or 'time_bucket') forces WebUI Basic-Auth clients to re-authenticate. Ignored when webui_auth_session_mode is 'legacy'."`
	WebUIReadHeaderTimeoutSec      int    `json:"webui_read_header_timeout_sec"     desc:"Seconds the WebUI HTTP server waits for a client to send request headers before closing the connection (Slowloris defence)."`
	WebUIReadTimeoutSec            int    `json:"webui_read_timeout_sec"            desc:"Seconds the WebUI HTTP server waits for a complete request body."`
	WebUIWriteTimeoutSec           int    `json:"webui_write_timeout_sec"           desc:"Seconds the WebUI HTTP server waits while writing the HTTP response to a client."`
	WebUIIdleTimeoutSec            int    `json:"webui_idle_timeout_sec"            desc:"Seconds the WebUI HTTP server keeps an idle keep-alive connection open. Auto-clamped to at least 2x webui_read_timeout_sec."`

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

	CacheJanitorIntervalMinutes int    `json:"cachejanitor_interval_minutes" desc:"Interval in minutes at which the DNS cache background janitor sweeps for and removes expired entries."`
	CacheNegativeTTLSec         uint32 `json:"cache_negative_ttl_sec" desc:"Seconds to cache SERVFAIL and other negative upstream responses (respecting RFC 2308 tho), reducing retry storms during upstream outages. 0 means don't cache."`

	FileWriterMaxRetries     int `json:"file_writer_max_retries" desc:"Maximum number of retries for atomic file writes. (Default: 6)"`
	FileWriterRetryBackoffMs int `json:"file_writer_retry_backoff_ms" desc:"Delay in milliseconds between file write retries. (Default: 100)"`

	BlockedResponseTTLSec    uint32 `json:"blocked_response_ttl_sec"       desc:"TTL (seconds) embedded in DNS records returned for blocked queries, controlling how long clients cache the block response. 0 means instruct clients not to cache the blocked response at all; blocked responses are also stored in this proxy's own internal cache for this amount for time."`
	LocalHostsOverrideTTLSec uint32 `json:"localhosts_override_ttl_sec" desc:"TTL (seconds) embedded in DNS records synthesised from the local host-override file (hosts2ip.json), and how long this proxy's own internal cache retains that synthesized response. 0 means don't cache the response internally (every query re-evaluates the override fresh) and instructs clients not to cache it either."`

	UILogMaxLines int `json:"ui_log_max_lines" desc:"Maximum log lines shown per page in the WebUI log viewer. Older lines are omitted to prevent excessive RAM usage and browser freezes."`

	ClientMetadataLookupSlowWarnThresholdMs int `json:"client_metadata_lookup_slow_warn_threshold_ms" desc:"Milliseconds a per-query client PID/executable-name/service-list lookup (used for {builtin:clientexe} substitution and for attributing a DNS query to the requesting process in logs) must take before a 'slow lookup' warning is logged. These OS-level lookups legitimately take longer on slower hardware or under heavier system load, so raise this if you see frequent slow-lookup warnings on an otherwise healthy machine. 0 disables these warnings entirely."`

	ExtraSafety bool `json:"extra_safety" desc:"Enable extra defensive checks: duplicate-entry detection in JSON files, power-loss staging files for atomic writes, and strict purging of malformed or duplicate rules on load. Recommended for production."`
}

// LiveConfigs a wrapper struct
type LiveConfigs struct {
	Resolved *Config // resolved (runtime use) // shared with AdminUI, fileWriter, etc.
	Raw      *Config //tokens preserved (disk use) like "{file:id.key}" is preserved not resolved like liveConfig has it.
	// liveConfig    atomic.Pointer[Config]
	// liveRawConfig atomic.Pointer[Config]
}

// Server encapsulates all the state required to run the DNSbollocks application.
type Server struct {
	rt *Runtime // owns LogMgr + FileWriter; injected by NewServer
	// File writes are serialised through rt.FileWriter which owns its own mutex.

	liveConfigs atomic.Pointer[LiveConfigs]

	// Upstream state
	upstreamMgr  *UpstreamManager
	dohForwarder DoHForwarder // used by handleDNSQuery — injectable in tests

	// Caching & Rate limiting
	// dnsCache    DNSCache
	// rateLimiter *ClientRateLimiter
	liveDNSCache atomic.Pointer[goCacheStore]
	rateLimiter  *ClientRateLimiter

	// Data stores (each owns its own mutex).
	ruleStore    *RuleStore
	hostStore    *HostStore
	blacklist    *BlacklistStore
	recentBlocks *RecentBlocksTracker
	// recentAllowed mirrors recentBlocks but records recently ALLOWED
	// queries instead (see handleDNSQuery, which records into it whenever a
	// query is allowed, regardless of whitelist_mode). Powers the WebUI's
	// dedicated TheAllowsPage page (Recent Allows) — the sibling of TheBlocksPage
	// (Recent Blocks) — letting an operator see, and optionally add a
	// query-blocklist "block" rule for, any domain that was just resolved,
	// whether it was allowed via a whitelist rule/local host override
	// (whitelist_mode=true) or simply because whitelist_mode is off.
	recentAllowed *RecentBlocksTracker

	// queryBlocklistStore holds the mutable "block"/"except" override rules
	// for the query-blocklist feature (implemented in this same file — see
	// checkQueryBlocklist, loadQueryBlocklist/saveQueryBlocklist, and
	// queryBlocklistHandler); reuses *RuleStore verbatim, with "block"/"except"
	// used as the map key in place of a DNS record type.
	queryBlocklistStore *RuleStore
	// externalBlocklist holds the current snapshot of the read-only external
	// hosts-file source (see loadExternalQueryBlocklist / ExternalHostsBlocklistSource).
	// A never-loaded (zero-value) pointer is treated identically to "not configured".
	externalBlocklist atomic.Pointer[ExternalHostsBlocklistSource]

	// forwardInFlightMu/forwardInFlight coalesce concurrent identical
	// upstream forwards (same domain+qtype cache key) into a single request,
	// so a burst of duplicate queries arriving right after a cache entry
	// expires doesn't each independently hammer the upstream resolver. See
	// forwardInFlightEntry's doc comment.
	forwardInFlightMu sync.Mutex
	forwardInFlight   map[string]*forwardInFlightEntry

	//dnsTCPSem is set by startDNSListener after the config is loaded, not here.
	dnsTCPSem atomic.Pointer[chan struct{}]
	dnsUDPSem atomic.Pointer[chan struct{}]

	dnsListener atomic.Pointer[dnsListenerInstance]
	dohListener atomic.Pointer[dohListenerInstance] // Changed type
	uiListener  atomic.Pointer[uiListenerInstance]  // Changed type

	adminUI *AdminUI

	dohCert tls.Certificate // used by DoH listener AND WebUI TLS
	// dohCertMu guards dohCert. generateCertIfNeeded() (write side) isn't
	// currently reachable concurrently with getCert()/ensureCert() (read
	// side) given today's call graph (Reload() is single-flight and does
	// both sequentially on one goroutine), but that's an implicit invariant
	// of the surrounding code rather than something this field enforces
	// itself — cheap to harden now rather than rely on nobody ever adding a
	// per-request call site to getCert() later.
	dohCertMu      sync.RWMutex
	certGeneration atomic.Uint64

	// blockedQueries is an expvar counter of policy-block responses that were
	// synthesised by blockAndCacheQuery (query-blocklist hit, or lack of an
	// enabled whitelist rule in whitelist_mode). Cache hits of a previously
	// synthesised blocked entry do not re-increment; upstream-response-filtered
	// blocks (response-IP blacklist / zero-IP) are counted separately only in
	// the query log, not here. Exposed via expvar as "blocked_queries".
	blockedQueries *expvar.Int

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

	autoRestart atomic.Bool // Flag to indicate an automatic restart is requested

	// tableMutationMu serializes every mutation (add/edit/delete, single-item
	// or batched via /apply-tables) of the whitelist/hosts/response-blacklist
	// tables against both each other AND against Reload()'s config-swap +
	// dependent-store reload. The latter is essential, not optional: Reload()
	// holds this exact mutex from right before it swaps in a new live Config
	// (which can change WhitelistFile/HostsFile/BlacklistFile) through the
	// end of loadDependentStores() reloading those files from their
	// (possibly just-changed) paths. Without that, a WebUI table-mutation
	// handler racing that exact window could read the just-swapped new file
	// path while its own in-memory store still reflects data loaded from the
	// OLD path, and overwrite the new path's on-disk content with stale
	// data — silently destroying whatever the new file legitimately
	// contained. See loadDependentStores's and Reload's own doc comments.
	tableMutationMu sync.Mutex
}

// AdminUI handles all the web control panel routes.
type AdminUI struct {
	// logger       *slog.Logger
	// config       Config // Pass by value so UI can read it safely
	// liveConfig    *atomic.Pointer[Config]
	// liveRawConfig *atomic.Pointer[Config]
	liveConfigs *atomic.Pointer[LiveConfigs]
	liveLogger  *atomic.Pointer[slog.Logger]

	// logMgr, if non-nil, is used by the /logs* handlers to read back which
	// on-disk log paths the currently active logger was actually opened
	// against (see LoggerManager.ActiveLogPaths and activeLogFilePath),
	// rather than trusting the live Config's paths — the two can diverge
	// after a Reload() whose logging reconfiguration failed partway through.
	// nil is tolerated (falls back to the live Config) for callers/tests
	// that construct AdminUI without a full Runtime.
	logMgr *LoggerManager

	ruleStore    *RuleStore
	hostStore    *HostStore
	blacklist    *BlacklistStore
	loginTracker *LoginTracker

	// queryBlocklistStore/externalBlocklist mirror the identically-named
	// Server fields (implemented in this same file — see checkQueryBlocklist
	// and related functions) — set directly by initAdminUI after
	// construction, exactly like ui.rateLimiter below, rather than
	// added to NewAdminUI's parameter list, so existing test call sites that
	// construct AdminUI directly don't need updating. Both are nil-safe: a
	// nil queryBlocklistStore or externalBlocklist means "feature not wired
	// up in this environment" and the /query-blocklist POST handler reports
	// 503 rather than panicking.
	queryBlocklistStore *RuleStore
	externalBlocklist   *atomic.Pointer[ExternalHostsBlocklistSource]
	recentBlocks        *RecentBlocksTracker
	// recentAllowed mirrors Server.recentAllowed — see that field's doc
	// comment. Set directly by initAdminUI after construction (like
	// queryBlocklistStore below), rather than added to NewAdminUI's
	// parameter list, so existing test call sites that construct AdminUI
	// directly don't need updating. nil is nil-safe: getRecentAllowedCopy
	// and buildIsLocallyBlockedPredicate simply behave as "no entries" /
	// "never blocked".
	recentAllowed  *RecentBlocksTracker
	blockedQueries *expvar.Int

	// rateLimiter enforces a global + per-client-IP cap on WebUI HTTP request
	// volume, independent of loginTracker (only throttles failed logins) and
	// independent of Server.rateLimiter (DNS query traffic). Wired up by
	// initAdminUI(); nil is treated as "not configured yet" by
	// webUIRateLimitMiddleware rather than causing a panic.
	rateLimiter *ClientRateLimiter

	// verifiedAuthCache lets authMiddleware skip the (deliberately expensive)
	// bcrypt comparison for repeat requests carrying the exact same
	// Authorization header that already verified successfully very recently.
	// See its doc comment for why this doesn't weaken brute-force resistance.
	verifiedAuthCache *verifiedAuthCache

	// csrfSecret is a random, process-lifetime-only HMAC key used to sign
	// and verify CSRF cookie tokens (see verifyCSRFToken's doc comment).
	// Never persisted or logged; a fresh one is generated every process
	// start via NewAdminUI.
	csrfSecret []byte

	// sessionAuthSecret is a random, process-lifetime-only HMAC key used to
	// sign/verify the WebUI's session-expiry cookie for
	// webui_auth_session_mode='session_cookie' (see
	// newSessionAuthToken/verifySessionAuthToken and
	// AdminUI.proceedAfterAuthSuccess). Kept independent from csrfSecret so
	// the two concerns never share key material. Never persisted or logged;
	// a fresh one is generated every process start via NewAdminUI.
	sessionAuthSecret []byte

	// configApplyMu serializes the entire check-version -> read -> merge ->
	// validate -> write -> reload sequence in configHandler's "apply" action
	// against itself (e.g. two browser tabs applying config.json changes at
	// the same time), closing a TOCTOU race the mtime-based version check
	// alone cannot close on its own. See configHandler's use of it.
	configApplyMu sync.Mutex

	uiTemplates *template.Template

	// Callbacks for side-effects
	OnSaveWhitelist       func() error
	OnSaveBlacklist       func() error
	OnSaveHosts           func() error
	OnSaveQueryBlocklist  func() error
	OnInvalidatePattern   func(pattern string)
	OnInvalidatePatterns  func(patterns map[string]struct{})
	OnInvalidateBlacklist func()
	OnApplyConfig         func(cfg *Config) error
	// OnReloadConfig triggers a full config/dependent-file reload without
	// modifying config.json first — the WebUI equivalent of pressing Ctrl+R
	// at the console. Wired directly to Server.Reload in initAdminUI.
	OnReloadConfig func() error
	// OnClearCache empties the internal DNS response cache immediately,
	// without touching rules/hosts/blocklists. Wired directly to
	// Server.flushDNSCache in initAdminUI.
	OnClearCache func()

	//UI calls this when a fatal exception or manual admin shutdown occurs
	OnShutdown func(exitCode int)
	//getExpectedHost func() string // used by hostValidation

	// tableMutationMu is a pointer to the owning Server's tableMutationMu —
	// see that field's doc comment for the invariant this protects.
	tableMutationMu *sync.Mutex
}

// pointer to live logger via Runtime
func (s *Server) getLogger() *slog.Logger {
	if s.rt == nil {
		log := wincoe.GetBugLogger()
		log.Error("BUG: Server.rt not initialized")
		return log
	}

	return s.rt.Logger()
}

// pointer to live Server.Config
func (s *Server) getConfig() *Config {
	c := s.getLiveConfigs().Resolved
	if c == nil {
		panic2("BUG: Server.liveConfigs.Load().Resolved not initialized before use")
		panic(nil)
	}
	return c
}

func (s *Server) getLiveConfigs() *LiveConfigs {
	both := s.liveConfigs.Load()
	if both == nil {
		panic2("BUG: Server.liveConfigs not initialized before use — NewServer must call liveConfigs.Store()")
		panic(nil)
	}
	return both
}
func (s *Server) getRawConfig() *Config {
	if c := s.getLiveConfigs().Raw; c != nil {
		return c
	}
	panic2("BUG: Server.liveRawConfig not initialized before use")
	panic(nil)
}

// On init and every reload, swap atomically:
// cfg's derived, runtime-only fields (UpstreamURLsParsed, UpstreamIPs, UpstreamSNIs) are
// expected to already be fully populated by the caller (via sanitizeAndValidateConfig,
// through LoadAndValidateConfig) before this is called, so no reader ever observes a live
// Config with those fields nil/stale — see parseAndValidateUpstreams's doc comment.
func (s *Server) applyConfig(cfg, rawCfg Config) {
	// s.liveRawConfig.Store(&rawCfg)
	// s.liveConfig.Store(&cfg)
	s.liveConfigs.Store(&LiveConfigs{
		Resolved: &cfg,
		Raw:      &rawCfg,
	})
	// fileWriter, AdminUI, etc. pick it up on their next read — nothing to call
}

// NewServer initializes a new Server instance using a fully configured Runtime
// and pre-validated configurations. The Runtime (LogMgr + FileWriter) must be
// set up by the caller (OldMain) before NewServer is called.
func NewServer(rt *Runtime, resolvedCfg, rawCfg *Config) *Server {
	if rt == nil {
		panic2("BUG: NewServer called with nil Runtime")
	}
	s := &Server{
		rt:                  rt,
		ruleStore:           newRuleStore(),
		hostStore:           newHostStore(),
		blacklist:           newBlacklistStore(),
		queryBlocklistStore: newRuleStore(),
		recentBlocks:        newRecentBlocksTracker(),
		recentAllowed:       newRecentBlocksTracker(),
		forwardInFlight:     make(map[string]*forwardInFlightEntry),
		//dnsTCPSem is set by startDNSListener after the config is loaded, not here.
		errChan:        make(chan error, 10), // We use a buffer of (e.g.) 10 so multiple services failing at once won't block
		blockedQueries: expvar.NewInt("blocked_queries"),
		exitFn:         os.Exit,
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())

	// Apply the true configuration immediately
	s.applyConfig(*resolvedCfg, *rawCfg)

	// failoverSelect now lives inside UpstreamManager
	s.upstreamMgr = NewUpstreamManager(s.ctx, &s.liveConfigs, s.rt.LogMgr.Ptr(), s.shutdown, s.rt.FlushLogsForShutdown)
	s.dohForwarder = s.upstreamMgr

	return s // yes it escapes to heap
}

type FailoverSelector struct {
	liveLogger     *atomic.Pointer[slog.Logger]
	mu             sync.RWMutex
	activeIndex    int
	inFlightProbes sync.Map
	allFailed      bool   // Tracks if the system is coming out of a total blackout
	flushLogs      func() // may be nil; see recoverAndFlushLogs
}

// NewFailoverSelector initializes the tracker starting at the first upstream (index 0)
func NewFailoverSelector(liveLogger *atomic.Pointer[slog.Logger], flushLogs func()) *FailoverSelector {
	if liveLogger == nil {
		panic2("BUG: passed nil atomic pointer to logger but code assumes this is never nil, logger can be nil tho")
	}
	return &FailoverSelector{liveLogger: liveLogger, activeIndex: 0, allFailed: false, flushLogs: flushLogs}
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
	return wincoe.GetLoggerOrFallback(u.liveLogger, "Upstream.liveLogger")
}

// pointer to live logger or default logger if uninited(bug)
func (fs *FailoverSelector) getLogger() *slog.Logger {
	return wincoe.GetLoggerOrFallback(fs.liveLogger, "FailoverSelector.liveLogger")
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
		index       int
		resp        *dns.Msg
		resolvedURL string
		err         error
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
				resChan <- result{index: i, resp: nil, resolvedURL: upstreams[i].URL.String(), err: errors.New("skipped: probe already in flight")}
				continue
			}
		}
		go func(idx int, wasProbe bool) {
			defer recoverAndFlushLogs(fs.flushLogs)
			// Clean up the probe lock when this request finishes
			if wasProbe {
				defer fs.inFlightProbes.Delete(idx)
			}
			// 1. Safe, single struct resolution instead of parallel slices
			target := upstreams[idx]
			// --- FIX: probes must outlive this specific Exchange() call ---
			// exchangeCtx is cancelled via the deferred cancel() the instant
			// Exchange returns (e.g. because a *different*, non-probe upstream
			// answered first). That's exactly what we want for the "real"
			// (non-probe) attempt at idx==currentIdx: once we have an answer
			// there's no reason to keep that request alive.
			//
			// A probe (idx < currentIdx, opportunistically re-trying a
			// previously-failed higher-priority upstream to detect recovery)
			// is intentionally designed to keep running in the background
			// after Exchange returns — see the healing logic below and the
			// ctx.Done() branch further down, which both explicitly document
			// that probes must survive past this call. If probes shared
			// exchangeCtx, the moment Exchange returned they'd be killed
			// instantly via context cancellation propagation, and the
			// promotion/healing side-effect could never fire. So probes get a
			// context that is only bounded by the upstream's own client
			// timeout and by full server shutdown (via target.BackgroundCtx,
			// which doSingleDoHRequest already watches internally via
			// context.AfterFunc), never by this particular Exchange() call's
			// lifetime.
			var reqCtx context.Context
			if wasProbe {
				reqCtx = target.BackgroundCtx
			} else {
				reqCtx = exchangeCtx
			}
			resp, resolvedURL, err := target.doSingleDoHRequest(reqCtx, reqBytes)

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
						slog.String("url", resolvedURL),
						slog.String("sni", target.SNI),
						slog.Int("index", idx),
					)
				} else if healed {
					log.Warn("⚙️ Primary upstream recovered; promoting back to active status",
						slog.String("url", resolvedURL),
						slog.String("sni", target.SNI),
						slog.Int("index", idx),
					)
				}
			}
			// 2. Push to the channel last
			resChan <- result{index: idx, resp: resp, resolvedURL: resolvedURL, err: err}
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
				return res.resp, res.resolvedURL, failedUpstreams, nil
			}
			// // FIX 1: Explicit log when a parallel/primary upstream fails
			// log.Warn("⚠️ Upstream still failed; marking as failed", // XXX: this is unnecessary spam
			// 	slog.String("url", upstreams[res.index].URL.String()),
			// 	slog.String("sni", upstreams[res.index].SNI),
			// 	wincoe.SafeErr(res.err),
			// )
			// Track the failure
			failedUpstreams = append(failedUpstreams, res.resolvedURL)

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
		resp, resolvedURL, err := target.doSingleDoHRequest(ctx, reqBytes)
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
					slog.String("url", resolvedURL),
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
					slog.String("new_url", resolvedURL),
					slog.String("sni", target.SNI),
				)
			}
			return resp, resolvedURL, failedUpstreams, nil
		}
		// FIX 3: Explicit log when a sequential fallback upstream fails
		log.Warn("⚠️ Fallback upstream failed; moving to next (if available)",
			slog.String("url", resolvedURL),
			slog.String("sni", target.SNI),
			wincoe.SafeErr(err),
		)
		failedUpstreams = append(failedUpstreams, resolvedURL)
	} //for
	// If execution gets here, every single configured upstream failed
	fs.mu.Lock()
	fs.allFailed = true
	fs.activeIndex = 0 // retry from the first one next time
	fs.mu.Unlock()
	return nil, "", failedUpstreams, errors.New("all upstreams failed to respond")
}

// cloneURLSlice returns a deep copy of urls (each *url.URL, and its embedded *url.Userinfo
// if present, copied independently) so the returned slice shares no backing memory — not
// even the pointed-to url.URL structs — with the input. Used by Config.Clone() and by
// sanitizeAndValidateConfig's upstream-derived-field population, both of which need
// resolvedCfg's and rawCfg's UpstreamURLsParsed slices to never alias each other.
func cloneURLSlice(urls []*url.URL) []*url.URL {
	if urls == nil {
		return nil
	}
	out := make([]*url.URL, len(urls))
	for i, v := range urls {
		if v != nil {
			uCopy := *v
			if v.User != nil {
				uUser := *v.User
				uCopy.User = &uUser
			}
			out[i] = &uCopy
		}
	}
	return out
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
	dst.UpstreamURLsParsed = cloneURLSlice(c.UpstreamURLsParsed)
	if c.UpstreamIPs != nil {
		dst.UpstreamIPs = make([]string, len(c.UpstreamIPs))
		copy(dst.UpstreamIPs, c.UpstreamIPs)
	}
	if c.UpstreamSNIs != nil {
		dst.UpstreamSNIs = make([]string, len(c.UpstreamSNIs))
		copy(dst.UpstreamSNIs, c.UpstreamSNIs)
	}

	if c.FieldModifiedAt != nil {
		dst.FieldModifiedAt = make(map[string]time.Time, len(c.FieldModifiedAt))
		for k, v := range c.FieldModifiedAt {
			dst.FieldModifiedAt[k] = v
		}
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
	// Enabled mirrors RuleEntry.Enabled: a disabled host override is kept on
	// disk and shown in the WebUI, but never matched by HostStore.Match, so
	// an operator can temporarily suspend an override (e.g. to let a domain
	// resolve normally again) without deleting and later re-typing it.
	Enabled bool
	// ModifiedAt is the timestamp of this host override's most recent
	// add/edit, populating the WebUI's sortable "Last Modified" column. See
	// HostFileEntry for its on-disk (hosts2ip.json) counterpart.
	ModifiedAt time.Time
}

// HostFileEntry is the on-disk representation of a single local host-override
// rule in hosts2ip.json: the target IP(s), whether the override is currently
// active (see LocalHostRule.Enabled), plus the timestamp of the most recent
// add/edit (see LocalHostRule.ModifiedAt), used to populate the WebUI's
// sortable "Last Modified" column.
type HostFileEntry struct {
	IPs        []string  `json:"ips"`
	Enabled    bool      `json:"enabled"`
	ModifiedAt time.Time `json:"modified_at"`
}

// parseHostFileEntry decodes a single hosts2ip.json value in either the
// current format (a HostFileEntry object with "ips", "enabled", and
// "modified_at") or the legacy format (a bare JSON array of IP strings, used
// by every dnsbollocks release before the "Last Modified" WebUI column was
// added). A legacy entry's ModifiedAt is left at the zero value; the caller
// (loadLocalHosts) fills in time.Now() so the on-disk file migrates to the
// current format on the next save — mirroring how loadQueryWhitelist
// migrates a rule with a missing/empty ID.
//
// migrated reports whether the "enabled" field was absent from the input:
// both legacy bare-array entries and current-format objects written before
// the "Enabled" WebUI toggle existed lack it. In either case Enabled
// defaults to true (every entry was implicitly always active before this
// feature existed), and the caller should flag the file for a rewrite so the
// now-explicit value gets persisted.
func parseHostFileEntry(raw json.RawMessage) (entry HostFileEntry, migrated bool, err error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return HostFileEntry{}, false, errors.New("empty value")
	}
	switch trimmed[0] {
	case '[':
		var ips []string
		if err := json.Unmarshal(raw, &ips); err != nil {
			return HostFileEntry{}, false, fmt.Errorf("failed to parse legacy (bare IP array) host entry: %w", err)
		}
		return HostFileEntry{IPs: ips, Enabled: true}, true, nil
	case '{':
		var decoded struct {
			IPs        []string  `json:"ips"`
			Enabled    *bool     `json:"enabled"`
			ModifiedAt time.Time `json:"modified_at"`
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if decErr := d.Decode(&decoded); decErr != nil {
			return HostFileEntry{}, false, fmt.Errorf("failed to parse host entry: %w", decErr)
		}
		enabledWasMissing := decoded.Enabled == nil
		enabled := true
		if !enabledWasMissing {
			enabled = *decoded.Enabled
		}
		return HostFileEntry{IPs: decoded.IPs, Enabled: enabled, ModifiedAt: decoded.ModifiedAt}, enabledWasMissing, nil
	default:
		return HostFileEntry{}, false, fmt.Errorf("unrecognized JSON value shape (expected array or object), starts with %q", trimmed[0])
	}
}

// RuleEntry represents a whitelist rule.
type RuleEntry struct {
	ID      string `json:"id"`
	Pattern string `json:"pattern"`
	Enabled bool   `json:"enabled"`
	// ModifiedAt is the timestamp of this rule's most recent add/edit
	// (including an enable/disable toggle via the /blocks quick-unblock
	// flow), populating the WebUI's sortable "Last Modified" column.
	ModifiedAt time.Time `json:"modified_at"`
}

// LogValue makes RuleEntry 100% immune to dangerous reflection data races.
// When you pass RuleEntry to slog.Any, slog runs this function instead of reflecting.
// alternatively use SafeRuleAttr() helper
func (r RuleEntry) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", r.ID),
		slog.String("pattern", r.Pattern),
		slog.Bool("enabled", r.Enabled),
		slog.Time("modified_at", r.ModifiedAt),
	)
}

// BlacklistRecord pairs a parsed CIDR/IP network with whether it is
// currently active and the timestamp of its most recent add/edit, so the
// WebUI can display and sort by "Last Modified" the same way Rules and
// Local Hosts do, and can temporarily suspend an entry without deleting it.
// This is BlacklistStore's internal in-memory representation;
// BlacklistFileEntry is its on-disk counterpart.
type BlacklistRecord struct {
	Net        *net.IPNet
	Enabled    bool
	ModifiedAt time.Time
}

// BlacklistFileEntry is the on-disk representation of a single response-IP
// blacklist entry in response_blacklist.json.
type BlacklistFileEntry struct {
	CIDR       string    `json:"cidr"`
	Enabled    bool      `json:"enabled"`
	ModifiedAt time.Time `json:"modified_at"`
}

// BlacklistFileFormat represents the strict on-disk structure of response_blacklist.json
type BlacklistFileFormat struct {
	ResponseBlacklist []BlacklistFileEntry `json:"response_blacklist"`
}

// parseBlacklistFileEntry decodes a single response_blacklist.json array
// element in either the current format (a BlacklistFileEntry object with
// "cidr", "enabled", and "modified_at") or the legacy format (a bare
// CIDR/IP string, used by every dnsbollocks release before the "Last
// Modified" WebUI column was added). A legacy entry's ModifiedAt is left at
// the zero value; the caller (loadResponseBlacklist) fills in time.Now() so
// the on-disk file migrates to the current format on the next save —
// mirroring parseHostFileEntry's identical migration for hosts2ip.json.
//
// migrated reports whether the "enabled" field was absent from the input
// (see parseHostFileEntry's identical migrated return for the full
// rationale); Enabled defaults to true in that case.
func parseBlacklistFileEntry(raw json.RawMessage) (entry BlacklistFileEntry, migrated bool, err error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return BlacklistFileEntry{}, false, errors.New("empty value")
	}
	switch trimmed[0] {
	case '"':
		var cidr string
		if err := json.Unmarshal(raw, &cidr); err != nil {
			return BlacklistFileEntry{}, false, fmt.Errorf("failed to parse legacy (bare string) blacklist entry: %w", err)
		}
		return BlacklistFileEntry{CIDR: cidr, Enabled: true}, true, nil
	case '{':
		var decoded struct {
			CIDR       string    `json:"cidr"`
			Enabled    *bool     `json:"enabled"`
			ModifiedAt time.Time `json:"modified_at"`
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if decErr := d.Decode(&decoded); decErr != nil {
			return BlacklistFileEntry{}, false, fmt.Errorf("failed to parse blacklist entry: %w", decErr)
		}
		enabledWasMissing := decoded.Enabled == nil
		enabled := true
		if !enabledWasMissing {
			enabled = *decoded.Enabled
		}
		return BlacklistFileEntry{CIDR: decoded.CIDR, Enabled: enabled, ModifiedAt: decoded.ModifiedAt}, enabledWasMissing, nil
	default:
		return BlacklistFileEntry{}, false, fmt.Errorf("unrecognized JSON value shape (expected string or object), starts with %q", trimmed[0])
	}
}

// Call once during startup (inside loadConfig or after it)
// loadResponseBlacklist loads response_blacklist.json into the in-memory
// BlacklistStore. Callers must hold s.tableMutationMu for the duration of
// this call — see loadDependentStores's doc comment for why.
func (s *Server) loadResponseBlacklist() error {
	cfg := s.getConfig()
	log := s.getLogger()

	blacklistFileName := cfg.BlacklistFile
	if blacklistFileName == "" {
		panic2("BUG: dev. didn't set the default blacklist filename!")
	}
	blacklistFileName = filepath.Clean(blacklistFileName)
	s.rt.FileWriter.CheckPowerLossFile(blacklistFileName)
	var shouldSave bool = false
	var rawEntries []BlacklistFileEntry
	data, err := os.ReadFile(blacklistFileName)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("read blacklist %q: %w", blacklistFileName, err)
		} else {
			log.Warn("Blacklist file not found → using built-in defaults", slog.String("file", blacklistFileName))
			now := time.Now()
			for _, cidr := range defaultResponseBlacklist() {
				rawEntries = append(rawEntries, BlacklistFileEntry{CIDR: cidr, Enabled: true, ModifiedAt: now})
			}
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

		// Read the existing entries as RawMessage first because the on-disk
		// format is intentionally backward-compatible:
		//   - legacy: "192.168.0.0/16"
		//   - current: {"cidr":"192.168.0.0/16","modified_at":"..."}
		//
		// Decoding directly into []BlacklistFileEntry would reject the legacy
		// string representation before parseBlacklistFileEntry gets a chance
		// to migrate it.
		var file struct {
			ResponseBlacklist []json.RawMessage `json:"response_blacklist"`
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err = dec.Decode(&file); err != nil {
			return fmt.Errorf("failed to parse blacklist file '%q' (maybe it contains unsupported or typo-ed fields?), err: %w", blacklistFileName, err)
		}

		rawEntries = make([]BlacklistFileEntry, 0, len(file.ResponseBlacklist))
		for i, rawEntry := range file.ResponseBlacklist {
			entry, migrated, parseErr := parseBlacklistFileEntry(rawEntry)
			if parseErr != nil {
				return fmt.Errorf(
					"failed to parse blacklist entry %d in %q: %w",
					i,
					blacklistFileName,
					parseErr,
				)
			}
			if migrated {
				shouldSave = true
			}
			rawEntries = append(rawEntries, entry)
		}
	}

	parsed := make([]BlacklistRecord, 0, len(rawEntries))
	// fail-fast if the response blacklist has malformed CIDR addresses
	for _, entry := range rawEntries {
		_, n, cidrErr := net.ParseCIDR(entry.CIDR)
		if cidrErr != nil {
			return fmt.Errorf("invalid CIDR %q in %q: %w", entry.CIDR, blacklistFileName, cidrErr)
		}
		modifiedAt := entry.ModifiedAt
		if modifiedAt.IsZero() {
			// Legacy entry (predates the "Last Modified" WebUI column, or a
			// hand-edited/bare-string file) — migrate it to a real timestamp
			// so it sorts sensibly and the file gets rewritten in the
			// current format, mirroring parseHostFileEntry's identical
			// migration for hosts2ip.json.
			modifiedAt = time.Now()
			shouldSave = true
		}
		parsed = append(parsed, BlacklistRecord{Net: n, Enabled: entry.Enabled, ModifiedAt: modifiedAt})
	}

	// Optional: after parsing, clean up duplicates (just in case)
	seen := make(map[string]struct{}, len(parsed))
	deduped := parsed[:0]
	for _, rec := range parsed {
		str := rec.Net.String()
		if _, exists := seen[str]; !exists {
			seen[str] = struct{}{}
			deduped = append(deduped, rec)
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

	records := s.blacklist.Snapshot()
	entries := make([]BlacklistFileEntry, len(records))
	for i, rec := range records {
		entries[i] = BlacklistFileEntry{CIDR: rec.Net.String(), Enabled: rec.Enabled, ModifiedAt: rec.ModifiedAt}
	}
	jsonFileContents := BlacklistFileFormat{
		ResponseBlacklist: entries,
	}
	data, err := json.MarshalIndent(jsonFileContents, "", "  ")
	if err != nil {
		return fmt.Errorf("blacklist marshal failed: %w", err)
	}

	blacklistFileName := cfg.BlacklistFile
	if blacklistFileName == "" {
		panic2("BUG: bad coding: dev. didn't set the default blacklist filename!")
	}
	if err := s.rt.FileWriter.SafeWriteFile(blacklistFileName, data, 0600); err != nil {
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

// loadLocalHosts loads hosts2ip.json into the in-memory HostStore. Callers
// must hold s.tableMutationMu for the duration of this call — see
// loadDependentStores's doc comment for why.
func (s *Server) loadLocalHosts() error {
	cfg := s.getConfig()
	log := s.getLogger()

	hostsFileName := cfg.HostsFile
	if hostsFileName == "" {
		panic2("BUG: didn't set the default hosts filename!")
	}
	hostsFileName = filepath.Clean(hostsFileName)
	s.rt.FileWriter.CheckPowerLossFile(hostsFileName)
	data, err := os.ReadFile(hostsFileName)
	if os.IsNotExist(err) {
		log.Warn("Hosts file not found, starting with empty local hosts", slog.String("path", hostsFileName))
		// Pass nil or an empty slice to atomically reset the store
		s.hostStore.ReplaceAll(nil)
		s.flushDNSCache()
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

	var rawEntries map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	if err = dec.Decode(&rawEntries); err != nil {
		return fmt.Errorf("failed to parse hosts file %q: %w", hostsFileName, err)
	}

	var parsed []LocalHostRule
	var changed uint64
	var removed uint64
	seenPatterns := make(map[string]struct{}, len(rawEntries))

	for pat, rawEntry := range rawEntries {
		hostEntry, enabledMigrated, parseErr := parseHostFileEntry(rawEntry)
		if parseErr != nil {
			log.Error("Purging host entry with unparseable value",
				slog.String("pattern", pat),
				wincoe.SafeErr(parseErr))
			removed++
			continue
		}
		ips := hostEntry.IPs
		modifiedAt := hostEntry.ModifiedAt
		if modifiedAt.IsZero() {
			// Legacy entry (predates the "Last Modified" WebUI column, or a
			// hand-edited file) — migrate it to a real timestamp so it sorts
			// sensibly and the file gets rewritten in the current format.
			modifiedAt = time.Now()
			changed++
		}
		if enabledMigrated {
			// Entry predates the "Enabled" WebUI toggle (or is a legacy
			// bare-IP-array entry) — it was implicitly always active, so
			// Enabled already defaults to true; just flag the file for a
			// rewrite so the now-explicit value gets persisted.
			changed++
		}

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

		// Convert any hand-edited Unicode (IDN) pattern (e.g. "café.com") into
		// punycode/ASCII so it can ever match a real (always-ASCII) DNS query,
		// instead of being silently purged below as containing "illegal
		// characters".
		idnEncoded, wasIDN, idnErr := punycodeEncodePattern(normalizedPat)
		if idnErr != nil {
			log.Error("Purging host pattern with invalid unicode",
				slog.String("invalid_pattern", normalizedPat),
				wincoe.SafeErr(idnErr))
			removed++
			continue
		} else if wasIDN {
			log.Warn("Converted unicode host pattern to punycode",
				slog.String("unicode_pattern", normalizedPat),
				slog.String("punycode_pattern", idnEncoded))
			normalizedPat = idnEncoded
			changed++
		}

		if normalizedPat == "" {
			log.Warn("Purging host rule with empty pattern (after normalization)",
				slog.String("original_pattern", pat))
			removed++
			continue
		}

		if _, modified := sanitizeDomainInput(normalizedPat); modified {
			attrs := []any{slog.String("invalid_pattern", normalizedPat)}
			if wasIDN {
				attrs = append(attrs, slog.String("invalid_pattern_idn", pat))
			}
			log.Error("Purging invalid host pattern containing illegal characters", attrs...)
			removed++
			continue
		}

		if len(normalizedPat) > maxRulePatternLength {
			attrs := []any{
				slog.Int("pattern_length", len(normalizedPat)),
				slog.Int("max_length", maxRulePatternLength),
				slog.String("pattern", normalizedPat),
			}
			if wasIDN {
				attrs = append(attrs, slog.String("pattern_idn", pat))
			}
			log.Error("Purging host pattern exceeding maximum length", attrs...)
			removed++
			continue
		}

		if _, dup := seenPatterns[normalizedPat]; dup {
			log.Warn("Duplicate host pattern found, skipping/purging",
				slog.String("pattern", normalizedPat),
				slog.String("pattern_idn", idnEncoded),
			)
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
					slog.String("pattern", normalizedPat),
					slog.String("pattern_idn", idnEncoded),
				)
			}
		}

		if len(netIPs) == 0 {
			log.Warn("Purging host rule with no valid IPs after filtering",
				slog.String("pattern", normalizedPat),
				slog.String("pattern_idn", idnEncoded),
			)
			removed++
			continue
		}

		parsed = append(parsed, LocalHostRule{Pattern: normalizedPat, IPs: netIPs, Enabled: hostEntry.Enabled, ModifiedAt: modifiedAt})
	}

	if cfg.ExtraSafety && removed > 0 {
		log.Error("ExtraSafety: refusing to remove host rules due to potential typos "+
			"(fix them manually or set extra_safety to false)",
			slog.Uint64("removed_count", removed))
		s.shutdown(5)
		panic2("BUG: unreachable")
	}

	s.hostStore.ReplaceAll(parsed)
	s.flushDNSCache()

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

	if err := s.rt.FileWriter.SafeWriteFile(cfg.HostsFile, data, 0600); err != nil {
		return fmt.Errorf("cannot save/write hosts file %q: %w", cfg.HostsFile, err)
	}
	log.Info("Saved hosts file", slog.String("path", cfg.HostsFile))
	return nil
}

// // getResponseBlacklist Helper – returns current list (snapshot copy)
// func (s *Server) getResponseBlacklist() []string {
// 	return s.blacklist.List()
// }

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

// saveRuleStoreFile marshals store's current snapshot and writes it to
// fileName. humanName is used only for log/error messages (e.g. "whitelist",
// "query blocklist") so the same implementation can serve every RuleStore-
// backed on-disk file this project has (currently the whitelist and the
// mutable query-blocklist override — see query_blocklist.go).
func (s *Server) saveRuleStoreFile(store *RuleStore, fileName, humanName string) error {
	log := s.getLogger()

	// 1. Snapshot the data quickly under RLock to prevent blocking DNS queries during slow I/O
	data, err := json.MarshalIndent(store.Snapshot(), "", "  ")
	if err != nil {
		return fmt.Errorf("%s marshal failed: %w", humanName, err)
	}

	// 2. Serialize the disk write so concurrent WebUI saves don't corrupt the file
	if fileName == "" {
		panic2(fmt.Sprintf("BUG: bad coding: dev. didn't set the default %s filename!", humanName))
	}
	if err := s.rt.FileWriter.SafeWriteFile(fileName, data, 0600); err != nil {
		return fmt.Errorf("cannot save/write %s file %q: %w", humanName, fileName, err)
	}
	log.Info("Saved "+humanName+" file", slog.String("filename", fileName))
	return nil
}

func (s *Server) saveQueryWhitelist() error {
	return s.saveRuleStoreFile(s.ruleStore, s.getConfig().WhitelistFile, "whitelist")
}

// loadRuleStoreFile loads a RuleStore-backed on-disk JSON file (see
// saveRuleStoreFile's doc comment) into store, normalizing/validating every
// entry exactly the way loadQueryWhitelist always has: assigning missing
// IDs and ModifiedAt timestamps, normalizing and IDN-encoding patterns,
// purging invalid/duplicate/oversized patterns, and re-saving the file if
// anything was migrated or purged. cfg.ExtraSafety still governs whether a
// purge is refused outright (shutting down rather than silently dropping
// possibly-typo'd entries) exactly as for the whitelist.
//
// Callers must hold s.tableMutationMu for the duration of this call — see
// loadDependentStores's doc comment for why.
func (s *Server) loadRuleStoreFile(store *RuleStore, fileName, humanName string) error {
	cfg := s.getConfig()
	log := s.getLogger()

	if fileName == "" {
		panic2(fmt.Sprintf("BUG: dev. didn't set the default %s filename!", humanName))
	}
	fileName = filepath.Clean(fileName)
	s.rt.FileWriter.CheckPowerLossFile(fileName)
	data, err := os.ReadFile(fileName)
	if os.IsNotExist(err) {
		log.Warn(humanName+" file not found, starting empty", slog.String("path", fileName))
		// Atomically set the internal map to an empty one
		store.ReplaceAll(make(map[string][]RuleEntry))
		s.flushDNSCache()
		return s.saveRuleStoreFile(store, fileName, humanName) // create "empty" file; uses lock
	}
	if err != nil {
		return fmt.Errorf("cannot read %s file %q: %w", humanName, fileName, err)
	}
	if dups, dupErr := detectDuplicateJSONObjectKeysAtTopLevelOnly(data); dupErr != nil {
		return fmt.Errorf("failed to scan %s file %q for duplicate keys: %w", humanName, fileName, dupErr)
	} else if len(dups) > 0 {
		for _, dup := range dups {
			log.Error("Duplicate key found in "+humanName+" file (JSON silently kept only the last value; fix the file manually)",
				slog.String("duplicate_key", dup),
				slog.String("path", fileName))
		}
		if cfg.ExtraSafety {
			log.Error("ExtraSafety: refusing to continue with duplicate "+humanName+" keys",
				slog.Int("duplicate_count", len(dups)))
			s.shutdown(5)
			panic2("BUG: unreachable")
		}
		log.Warn("Continuing despite duplicate "+humanName+" keys — the JSON decoder kept an arbitrary value for each duplicate; consider fixing the file",
			slog.Int("duplicate_count", len(dups)))
	}

	var rulesByType map[string][]RuleEntry
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&rulesByType); err != nil {
		return fmt.Errorf("failed to parse %s file '%q' (maybe it contains unsupported or typo-ed fields?), err: %w", humanName, fileName, err)
	}

	// ── Normalization (no lock needed; working on local variables) ──
	// Count total rules for initial map capacity
	totalRules := 0
	for _, rules := range rulesByType {
		totalRules += len(rules)
	}
	seenIDs := make(map[string]struct{}, totalRules) // global across all categories/types
	newRules := make(map[string][]RuleEntry, len(rulesByType))

	var changed uint64
	var removed uint64

	for typ, rules := range rulesByType {
		seenPatterns := make(map[string]struct{}, len(rules)) // per category/type only ie. per DNS type ie. A, AAAA, HTTPS
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
			if r.ModifiedAt.IsZero() {
				// Legacy rule (predates the "Last Modified" WebUI column, or a
				// hand-edited file) — migrate it to a real timestamp so it
				// sorts sensibly and the file gets rewritten in the current
				// format, mirroring the identical migration in
				// loadLocalHosts/loadResponseBlacklist.
				r.ModifiedAt = time.Now()
				changed++
			}
			//checks against all categories/types not just in 'typ'
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

			// Convert any hand-edited Unicode (IDN) pattern (e.g. "café.com")
			// into punycode/ASCII so it can ever match a real (always-ASCII)
			// DNS query, instead of being silently purged below as containing
			// "illegal characters".
			idnEncoded, wasIDN, idnErr := punycodeEncodePattern(r.Pattern)
			if idnErr != nil {
				log.Error("Purging/deleting "+humanName+" rule pattern with invalid unicode",
					slog.String("id", r.ID),
					slog.String("invalid_pattern", r.Pattern),
					wincoe.SafeErr(idnErr),
				)
				removed++
				continue
			} else if wasIDN {
				log.Warn("Converted unicode rule pattern to punycode",
					slog.String("id", r.ID),
					slog.String("unicode_pattern", r.Pattern),
					slog.String("punycode_pattern", idnEncoded))
				r.Pattern = idnEncoded
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
				attrs := []any{
					slog.String("id", r.ID),
					slog.String("invalid_pattern", r.Pattern),
				}
				if wasIDN {
					displayPat, _ := punycodeDecodePatternForDisplay(r.Pattern)
					attrs = append(attrs, slog.String("pattern_idn", displayPat))
				}
				log.Error("Purging/deleting invalid "+humanName+" rule pattern containing illegal characters", attrs...)
				removed++
				continue // Purges/omits it from being appended to cleaned slice
			}

			if len(r.Pattern) > maxRulePatternLength {
				attrs := []any{
					slog.String("id", r.ID),
					slog.Int("pattern_length", len(r.Pattern)),
					slog.Int("max_length", maxRulePatternLength),
				}
				if wasIDN {
					displayPat, _ := punycodeDecodePatternForDisplay(r.Pattern)
					attrs = append(attrs, slog.String("pattern_idn", displayPat))
				}
				log.Error("Purging/deleting "+humanName+" rule pattern exceeding maximum length", attrs...)
				removed++
				continue
			}

			if _, dup := seenPatterns[r.Pattern]; dup {
				log.Warn("Duplicate rule pattern found after normalization, skipping/purging it",
					slog.String("id", r.ID),
					slog.String("pattern", r.Pattern),
					slog.String("punycode_pattern", idnEncoded),
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

	if cfg.ExtraSafety && removed > 0 {
		log.Error("ExtraSafety: Refusing to remove "+humanName+" rules due to potential typos(fix them manually or set extra_safety to false)", slog.Uint64("removed_count", removed))

		s.shutdown(5) //noFIXME: find a better way to "quit" than exit program here, but still preserve the exitcode=5 ?!
		panic2("BUG: unreachable")
	}
	// ── Atomic swap ──
	store.ReplaceAll(newRules)
	s.flushDNSCache()

	hmn := store.CountAll()
	log.Info("Loaded "+humanName+" and normalized(aka changed) or removed(if dup IDs) rules",
		slog.Int("types", len(newRules)),
		slog.Uint64("rules", hmn),
		slog.Uint64("changed_count", changed),
		slog.Uint64("removed_count", removed),
		slog.String("path", fileName),
	)
	if countRules(rulesByType)-removed != hmn {
		panic2("BUG: bad coding: lost some rules, shouldn't happen!")
	}

	if changed > 0 || removed > 0 {
		return s.saveRuleStoreFile(store, fileName, humanName)
	}
	return nil
}

// Loads whitelist rules from dedicated file. Callers must hold
// s.tableMutationMu for the duration of this call — see
// loadDependentStores's doc comment for why.
func (s *Server) loadQueryWhitelist() error {
	return s.loadRuleStoreFile(s.ruleStore, s.getConfig().WhitelistFile, "whitelist")
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
		WhitelistMode:           true,
		BlockIP:                 "0.0.0.0",
		BlockIPv6:               "::", // Default unspecified IPv6

		GlobalRateQPS:  100,
		GlobalBurstQPS: 200, //100 worked for me, but heck, let's 2x it
		ClientRateQPS:  20,
		ClientBurstQPS: 100, //since it's portmaster.exe aka the firewall, even if it's just Firefox starting up on a previously opened page that's being reloaded(and firefox has DNS cache off), it still seems to hit this 50.

		// WebUI request-rate limiting is intentionally much stricter than the
		// DNS path above: this is a human-operated control panel plus occasional
		// polling JS, not a high-throughput resolver, so a flood of requests is
		// almost certainly abusive rather than legitimate traffic.
		WebUIRateQPS:        20,
		WebUIBurstQPS:       40,
		WebUIClientRateQPS:  5,
		WebUIClientBurstQPS: 20,

		CacheMinTTL:     defaultCacheMinTTL, //300 sec
		CacheMaxEntries: 10000,

		WhitelistFile:                   "query_whitelist.json",
		BlacklistFile:                   "response_blacklist.json",
		HostsFile:                       "hosts2ip.json",
		QueryBlocklistFile:              "query_blocklist.json",
		QueryBlocklistExternalHostsFile: "", // disabled by default

		LogDir:                           "", //in config dir
		LogQueriesFile:                   "queries.log",
		LogQueriesSimpleFile:             "queries_simple.log",
		LogEverythingFile:                "dnsbollocks.log",
		ConsoleLogLevel:                  consoleLogLevelInfo,
		LogMaxSizeMB:                     4095, // Rotation threshold
		AllowRunAsAdmin:                  false,
		HideConsole:                      false,
		BlockAAAAasEmptyNoError:          true,
		AllowHTTPSIfAAllowed:             true,
		LocalHostsOverrideQueryBlocklist: false,
		RemoveHTTPSIPHints:               true,
		WebUIUseTLS:                      true,
		WebUIForceTLSOnNonLocalhost:      true, //if WebUIUseTLS is false and ListenUI is non-localhost-like IP, then force WebUIUseTLS to true ?
		WebUIMaxLoginFailures:            5,
		WebUILoginLockoutSec:             5 * 60, // 5 minutes, in seconds
		WebUIAuthSessionMode:             webUIAuthSessionModeSessionCookie,
		WebUIAuthSessionTimeoutMinutes:   30,

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

		// Matches the threshold this warning previously used unconditionally;
		// raise it on slower hardware to quiet spurious warnings, or set to 0
		// to disable these warnings entirely.
		ClientMetadataLookupSlowWarnThresholdMs: 10,

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

// // initBootstrapLogging sets up a colored console-only logger for the earliest messages.
// // Called as the FIRST thing in OldMain, before anything else.
// func initBootstrapLogging(logger *slog.Logger) *slog.Logger {
// 	if logger == nil {
// 		panic2("passed nil logger as arg to initBootstrapLogging")
// 	}
// 	// Use the exact same colored handler you already have (it gracefully falls back if no console)
// 	bootstrapLevel := slog.LevelDebug // hard-coded for bootstrap — only ~8 lines anyway

// 	// Skip the colored console handler entirely when no console is attached
// 	// (e.g. a -H=windowsgui build): there is nowhere for it to render.
// 	if wincoe.HasConsole() {
// 		logger = slog.New(NewColoredConsoleHandler(bootstrapLevel, logger))
// 	}

// 	// This line is now the very first log in the entire program
// 	logger.Info("DNSbollocks starting... (bootstrap-logging inited)", slog.String("version", GetVersion()))
// 	return logger
// }

// -----------------------------------------------------------------------------
// Colored console handler (Windows-only, uses your exact color request)
// -----------------------------------------------------------------------------

// XXX: bad Go v1.26.0 causes a crash(heisenbug), the cause is this https://github.com/golang/go/issues/77975#issuecomment-4021553575 and fix appears to be commit 6ab37c1ca59664375786fb2f3c122eb3db98e433 (addon) also seen in https://go-review.googlesource.com/c/go/+/753040 well the cause is this commit first: https://github.com/golang/go/commit/1a44be4cecdc742ac6cce9825f9ffc19857c99f3 )! See also: https://gist.github.com/bradfitz/46c4b69ee8d6db639f3f7bf52594675a

type ColoredConsoleHandler struct {
	Level   slog.Level
	Out     io.Writer
	Mu      *sync.Mutex
	Counter *uint64 // Shared counter to track alternating rows
	// LastLogTime tracks when the previous console line was printed, shared (via pointer)
	// across every clone produced by WithAttrs/WithGroup so gap detection works correctly
	// regardless of which clone logs next. Guarded by Mu, exactly like Counter.
	LastLogTime *time.Time
	Attrs       []slog.Attr
	Group       string
}

func NewColoredConsoleHandler(level slog.Level, logger *slog.Logger) slog.Handler {
	// Activate Windows VT Processing globally, but only if a console is
	// actually attached -- attempting this with none (a -H=windowsgui
	// build, or after hide_console detaches it) always fails and is
	// pointless overhead on every reinit of this handler (every config
	// Reload rebuilds it). Callers (initBootstrapLogging,
	// LoggerManager.ApplyConfig) already skip constructing this handler at
	// all in that case; this is defense-in-depth for any future call site.
	if wincoe.HasConsole() {
		if err := wincoe.EnableVirtualTerminalProcessing(); err != nil {
			logger.Warn("EnableVirtualTerminalProcessing failed", wincoe.SafeErr(err)) //itwontFIXME: figure out if this would recuse infinitely
		}
	}

	var c uint64          // Initialize the shared counter (escapes to heap, doh)
	var lastLog time.Time // zero value means "no previous console line yet"; escapes to heap
	return &ColoredConsoleHandler{
		Level:       level,
		Out:         os.Stdout,
		Mu:          &sync.Mutex{},
		Counter:     &c, // Share pointer across clones
		LastLogTime: &lastLog,
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

	// Compute the gap-announcement line (if any) BEFORE anything else touches
	// h.LastLogTime, so it always reflects the silence strictly preceding this line.
	gapLine := h.buildGapAnnouncementYouHoldLock(r.Time)

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

	if gapLine != "" {
		buf.WriteString(gapLine)
	}

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
		case "failed_upstreams":
			// Only ever logged when non-empty (see logQuery), so its mere presence
			// always signals at least one upstream failure for this query.
			valColor = "\x1b[91m" // Red
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
		Level:       h.Level,
		Out:         h.Out,
		Mu:          h.Mu,
		Counter:     h.Counter,     // Carry over the counter pointer
		LastLogTime: h.LastLogTime, // Carry over the shared gap-detection timestamp
		Attrs:       append(h.Attrs[:len(h.Attrs):len(h.Attrs)], attrs...),
		Group:       h.Group,
	}
}

func (h *ColoredConsoleHandler) WithGroup(name string) slog.Handler {
	prefix := h.Group
	if name != "" {
		prefix += name + "."
	}
	return &ColoredConsoleHandler{
		Level:       h.Level,
		Out:         h.Out,
		Mu:          h.Mu,
		Counter:     h.Counter,     // Carry over the counter pointer
		LastLogTime: h.LastLogTime, // Carry over the shared gap-detection timestamp
		Attrs:       h.Attrs,
		Group:       prefix,
	}
}

// consoleLogGapAnnounceThreshold is the minimum silence between two console log lines
// before ColoredConsoleHandler.Handle prints a "... <duration> later ..." separator
// line, making long gaps in the live console feed (an idle server, a hang, etc.)
// visually obvious while scrolling back through history.
const consoleLogGapAnnounceThreshold = 30 * time.Second

// buildGapAnnouncementYouHoldLock returns a rendered "... <duration> later ..." line if
// at least consoleLogGapAnnounceThreshold has passed since the previous console log
// line, or "" if there's no previous line yet or the gap is too short to call out.
// Caller must hold h.Mu; it both reads and unconditionally updates h.LastLogTime, so a
// stale/mixed read is never observed even under concurrent Handle() calls.
func (h *ColoredConsoleHandler) buildGapAnnouncementYouHoldLock(now time.Time) string {
	if h.LastLogTime == nil {
		return "" // defensive: only ever nil if a ColoredConsoleHandler{} was hand-built
	}
	if now.IsZero() {
		now = time.Now()
	}

	var line string
	if !h.LastLogTime.IsZero() {
		if gap := now.Sub(*h.LastLogTime); gap >= consoleLogGapAnnounceThreshold {
			line = fmt.Sprintf("\x1b[90m... %s later ...\x1b[0m\n", formatLogGapDuration(gap))
		}
	}
	*h.LastLogTime = now
	return line
}

// formatLogGapDuration renders d as "H hours, M minutes, S seconds" (omitting any
// leading zero-valued unit) for the gap-announcement line. Sub-second precision is
// deliberately dropped — the whole point is to make LONG silences obvious at a glance,
// not to provide stopwatch-grade timing.
func formatLogGapDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	totalSeconds := int64(d / time.Second)
	hours := totalSeconds / 3600
	minutes := (totalSeconds % 3600) / 60
	seconds := totalSeconds % 60

	var parts []string
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%d hour%s", hours, pluralSuffix(hours)))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%d minute%s", minutes, pluralSuffix(minutes)))
	}
	if seconds > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%d second%s", seconds, pluralSuffix(seconds)))
	}
	return strings.Join(parts, ", ")
}

func pluralSuffix(n int64) string {
	if n == 1 {
		return ""
	}
	return "s"
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
	Domain        string    `json:"domain"`
	DomainDisplay string    `json:"-"` // Unicode display form for the WebUI; computed on read, same as Domain when not an IDN
	Type          string    `json:"type"`
	Time          time.Time `json:"time"`
	IsUnblocked   bool      `json:"-"` // dynamically set for the UI: whether the whitelist layer currently allows this exact domain+type (see buildIsUnblockedPredicate)

	// The following are also dynamically computed for the UI (see
	// AdminUI.populateQueryBlocklistRowState, called from both
	// getRecentBlocksCopy and getRecentAllowedCopy) and reflect the query
	// blocklist layer's CURRENT, independently re-evaluated state for this
	// domain, which may differ from (and can combine with) the whitelist
	// layer's state above. A local "block" match always wins and can never
	// be cancelled by an "except" pattern (see checkQueryBlocklist's doc
	// comment), so the local and external sub-layers are reported
	// independently here rather than collapsed into one flag, letting the
	// /blocks and /allows pages show a distinct, honest control for
	// whichever sub-layer(s) actually apply instead of a button that might
	// silently do nothing.
	QueryBlocklistLocalBlocked     bool   `json:"-"` // an enabled local "block" pattern currently matches this domain
	QueryBlocklistLocalRuleID      string `json:"-"` // ID of that matching rule (set only if QueryBlocklistLocalBlocked)
	QueryBlocklistExternalListed   bool   `json:"-"` // this domain is present in the read-only external hosts-file source
	QueryBlocklistExternalExcepted bool   `json:"-"` // an enabled local "except" rule currently cancels the external-source block (only meaningful if QueryBlocklistExternalListed)
}

// loginRecord tracks failed WebUI login attempts for a single client IP.
// All fields are guarded by Server.loginMu.
type loginRecord struct {
	failures    int       // consecutive failures in the current window
	lockedUntil time.Time // zero value means no active lockout
}

// // ---- old slow way
// var dnsNameRE = regexp.MustCompile(
// 	`^(?i)([a-z0-9_](?:[a-z0-9-]{0,61}[a-z0-9_])?\.)*[a-z0-9_](?:[a-z0-9-]{0,61}[a-z0-9_])?$`,
// )

// func isValidDNSName1(s string) bool {
// 	if len(s) == 0 || len(s) > 253 {
// 		return false
// 	}
// 	return dnsNameRE.MatchString(s)
// }

// // sanitizeDomainInput removes any characters not explicitly allowed.
// // Safe for logs and DNS-related handling.
// func sanitizeDomainInput1(input string) (sanitized string, modified bool) {
// 	const allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-{}*!?_"

// 	var b strings.Builder
// 	b.Grow(len(input)) // safe over-allocation, but done only one allocation not more than once as it could happen without it.

// 	for _, r := range input {
// 		if strings.ContainsRune(allowed, r) {
// 			b.WriteRune(r)
// 		}
// 	}

// 	sanitized = b.String()
// 	modified = sanitized != input
// 	// Uses named returns — do not return explicit values. like: return "something", modified
// 	return
// }

// // ---- END of --- old slow way

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

// maxRulePatternLength bounds whitelist/host pattern length. matchPattern's DP
// algorithm costs O(pattern_tokens * domain_length) per rule per query, so an
// unbounded pattern would add permanent per-query CPU overhead for as long as
// the rule exists, since it's evaluated against every DNS query.
const maxRulePatternLength = 512

// validateRulePattern returns a non-nil error if the pattern contains characters
// outside the allowed set (as defined by sanitizeDomainInput).
// It does NOT enforce strict DNS name rules because patterns may contain
// wildcards: *, **, {*}, {**}, ?, !, and braces.
func validateRulePattern(pattern string) error {
	if pattern == "" {
		return errors.New("pattern cannot be empty")
	}
	if len(pattern) > maxRulePatternLength {
		return fmt.Errorf("pattern exceeds maximum length of %d characters", maxRulePatternLength)
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

// resolveLogDir returns the directory that log files should live in, given
// Config.LogDir's raw value: an empty string (the default) means "the same
// directory as config.json", matching Config.LogDir's own desc tag ("If
// empty aka \"\" then it defaults_to/uses config dir").
func resolveLogDir(logDir string) string {
	if logDir == "" {
		return filepath.Dir(configFileName)
	}
	return logDir
}

// resolveLogFilePath computes the full on-disk path for a log file given the
// configured log directory (Config.LogDir) and a bare filename (Config.LogDir's
// desc tag documents that log filenames never carry a path component of their
// own). This is the single source of truth for turning a Config log-file
// field into an actual on-disk path, shared by:
//   - the very-early bootstrap logger in OldMain (before config.json has even
//     been fully validated),
//   - LoggerManager.ApplyConfig, which opens the real, rotating log writers,
//   - AdminUI's log-viewer handlers (renderLogPage), which read those same
//     files back for display in the WebUI.
//
// Routing every one of those call sites through this single function means
// they can never again disagree about where a given log file actually lives.
func resolveLogFilePath(logDir, filename string) string {
	return filepath.Join(resolveLogDir(logDir), filename) // filepath.Join already Cleans the result
}

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

// logPersistFailure logs a failure to persist an already-successfully-mutated
// in-memory store (whitelist, local hosts, or response blacklist) to disk,
// without crashing the process via logFatal. By the time any of
// OnSaveWhitelist/OnSaveHosts/OnSaveBlacklist is called, the corresponding
// in-memory store has already been updated, so DNS resolution continues
// correctly with the new state; only the on-disk copy failed to update and
// may therefore be stale (reverting to the pre-change value) if the process
// restarts before the next successful save. A full process shutdown over a
// single disk I/O hiccup would take down DNS resolution entirely, which is a
// substantially worse outcome than a stale on-disk file — unlike logFatal,
// which stays reserved for invariant violations where continuing to run
// risks serving corrupted or inconsistent state.
// Returns a wrapped error suitable for surfacing directly to the WebUI caller.
func (ui *AdminUI) logPersistFailure(what string, err error) error {
	log := ui.getLogger()
	log.Error("Failed to persist "+what+" to disk; in-memory state was already updated but NOT saved — the change may be lost on restart",
		slog.String("store", what),
		wincoe.SafeErr(err))
	return fmt.Errorf("failed to save %s to disk (your change was applied in memory but NOT persisted; it may be lost on restart): %w", what, err)
}

// redirectWithPersistFailure redirects to path with the given persistence
// failure surfaced as an "error" query-string message, matching how
// respondBlocksResult already signals a failed /blocks action to the no-JS
// fallback page. Used by the single-item /rules, /hosts, and
// /response-blacklist POST handlers when the in-memory mutation already
// succeeded but writing it to disk failed: unlike an outright validation
// failure (still handled via http.Error further up each handler), this
// always redirects — never renders a bare error page — so the browser
// reloads the page and reflects the mutation, which IS already live,
// instead of leaving the operator looking at a stale pre-change view while
// being told their change simply "failed". See logPersistFailure's doc
// comment for why the message itself is careful to say "applied but not
// persisted" rather than just "failed".
func redirectWithPersistFailure(w http.ResponseWriter, r *http.Request, path string, err error) {
	http.Redirect(w, r, path+"?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
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

// errReloadAlreadyInProgress is returned by Server.Reload when a concurrent
// reload is already running; the newly requested reload is skipped entirely
// rather than queued. Callers (e.g. the WebUI's Apply path) must not treat
// this as success, since none of the pending changes were applied by this call.
var errReloadAlreadyInProgress = errors.New("reload already in progress")

// Reload via Ctrl+R aka reloadFn. Returns a non-nil error if the reload was
// skipped or aborted (a concurrent reload was already running, or the new
// config.json failed to load/validate), so callers — notably the WebUI's
// [Apply & Reload] button via OnApplyConfig — can distinguish that from an
// actual successful reload instead of always reporting success. Every
// failure path here is already logged internally before returning.
func (s *Server) Reload() error {
	log := s.getLogger()

	if !s.reloadInProgress.CompareAndSwap(false, true) {
		log.Warn("Reload already in progress")
		return errReloadAlreadyInProgress
	} else {
		defer s.reloadInProgress.Store(false)
	}

	log.Debug("Reload function triggered...")

	oldCfg := s.getConfig()
	// 1. Group the exact fields that require a full cache rebuild if they change
	oldCacheState := struct{ Janitor, Max int }{
		oldCfg.CacheJanitorIntervalMinutes,
		oldCfg.CacheMaxEntries,
	}
	// oldJanitorInterval := oldCfg.CacheJanitorIntervalMinutes
	// oldMaxCacheEntries := oldCfg.CacheMaxEntries

	// 1. Load and validate the new config cleanly from disk using our decoupled helper
	resolvedCfg, rawCfg, needsSave, err := LoadAndValidateConfig(log, configFileName, s.rt.FileWriter, false)
	if err != nil {
		// Unlike OldMain's initial load — where every LoadAndValidateConfig error
		// (FATAL-prefixed or not) exits the process because there is no
		// previously-running server to fall back to — Reload() always has a
		// known-good config already live and actively serving DNS/WebUI traffic at
		// this exact point, and nothing has been mutated yet here (applyConfig,
		// listener rebinds, cert regen, dependent-store reloads etc. all happen
		// further below). So a LoadAndValidateConfig failure here — including a
		// "FATAL:"-prefixed one, e.g. an unresolved config template or an aborted
		// interactive password prompt — is never fatal to the running server: it
		// only aborts this specific reload attempt, exactly like any other reload
		// failure. The admin can fix config.json and retry (Ctrl+R) without any
		// downtime. (Contrast this with the s.logFatal(...) call on
		// loadDependentStores() failure further below, which correctly still exits:
		// by that point s.applyConfig has already swapped in the new config, so
		// continuing on a dependent-store load failure would risk running with
		// mismatched config/whitelist/blacklist/hosts state.)
		log.Error("Config reload failed, aborting reload, fix it and try again after.", wincoe.SafeErr(err))
		return fmt.Errorf("config reload aborted (config.json failed to load/validate): %w", err)
	}
	log.Debug("main config reloaded", slog.String("filename", configFileName))

	// Hold tableMutationMu from here through the end of this reload so a
	// concurrent WebUI table-mutation handler (rulesHandler, hostsHandler,
	// responseBlacklistHandler, applyTablesHandler — every one of which
	// holds this exact same mutex for its entire mutate+persist duration)
	// can never observe the config swap below mid-flight. See
	// loadDependentStores's doc comment for the full race this closes.
	// This does mean a table-mutation handler can occasionally have to wait
	// out an entire reload (including listener rebinds) before proceeding;
	// that's an acceptable, bounded cost (Reload is rare, and any fatal
	// exit reached while this lock is held is itself already bounded by
	// server_graceful_shutdown_sec) for closing a real data-loss race.
	s.tableMutationMu.Lock()
	defer s.tableMutationMu.Unlock()

	// Apply the new config atomically
	s.applyConfig(*resolvedCfg, *rawCfg)

	// 2. Re-initialize logging (applies new console levels or log files)
	// Done late to keep the same logger until reload is mostly complete.
	if err := s.rt.LogMgr.ApplyConfig(resolvedCfg); err != nil {
		log.Error("Failed to apply logging config during reload; logging may be stale", wincoe.SafeErr(err))
		// The core config is already live; log the error but do not abort the reload.
		// The logger itself keeps writing to whichever paths its last
		// successful ApplyConfig call opened — LogMgr.ActiveLogPaths still
		// reports those — and AdminUI's /logs* handlers read that instead of
		// the live Config, so the WebUI log viewer keeps showing the real,
		// actively-written log (with a warning banner) rather than silently
		// looking empty at the new, never-opened path. See
		// AdminUI.activeLogFilePath's doc comment.
	}
	log = s.getLogger() // Grab the newly initialized logger

	// Update the fileWriter with the newly loaded safety parameters instantly
	s.rt.ApplyFileWriterParams(resolvedCfg)

	if needsSave {
		if err := s.saveConfig(); err != nil {
			log.Error("Failed to save config during reload", wincoe.SafeErr(err))
		}
	}

	cfgNew := s.getConfig()
	if !cfgNew.AllowRunAsAdmin && isAdmin {
		s.logFatal2("Exiting: Reload() detected elevated privileges. Rerun without admin or change the config setting.")
		panic2("BUG: unreachable")
	}
	// NOTE: cfgNew.HideConsole is intentionally NOT re-checked here (or
	// anywhere else in Reload()). Detaching the console is a one-way,
	// boot-time-only step performed once in OldMain right after the
	// initial config load; toggling hide_console via the WebUI updates
	// config.json but requires a full process restart to take effect.

	// // Actually: ok nvm this is a bad idea below, stderr is used by logs and stuff.
	// // Handle dynamic hide_console toggles
	// if oldCfg.HideConsole != cfgNew.HideConsole {
	// 	if cfgNew.HideConsole {
	// 		if wincoe.HasConsole() {
	// 			log.Info(configKeyNameForHideConsole + " toggled to true; detaching from the console immediately.")
	// 			if freeErr := wincoe.FreeConsole(); freeErr != nil {
	// 				log.Warn(configKeyNameForHideConsole+": FreeConsole failed", wincoe.SafeErr(freeErr))
	// 			}
	// 		} else {
	// 			log.Debug(configKeyNameForHideConsole + " toggled to true; but already not having a console(due to a prev. setting or built this way), so nothing to do.")
	// 		}
	// 	} else {
	// 		log.Warn(fmt.Sprintf("The '%s' setting was toggled to false. Note: showing a hidden console again requires a full process restart to take effect.", configKeyNameForHideConsole))
	// 	}
	// }
	if oldCfg.HideConsole != cfgNew.HideConsole {
		if cfgNew.HideConsole {
			if wincoe.HasConsole() {
				log.Warn(configKeyNameForHideConsole + " toggled to true; but this setting only has effect after restart, auto-restarting now...")
				s.issueAutoRestart()
				return nil // Abort the rest of the reload (cache swap, listener rebinds, etc.) since we are replacing the process entirely
			} else {
				log.Debug(configKeyNameForHideConsole + " toggled to true; but already not having a console(due to a prev. setting or built this way), so nothing to do.")
			}
		} else {
			if wincoe.HasConsole() {
				log.Warn(fmt.Sprintf("The '%s' setting was toggled to false. But console is already shown, so nothing to do", configKeyNameForHideConsole))
			} else {
				log.Warn(fmt.Sprintf("The '%s' setting was toggled to false. Note: showing a hidden console again requires a full process restart to take effect, auto-restarting now...", configKeyNameForHideConsole))
				s.issueAutoRestart()
				return nil // Abort the rest of the reload (cache swap, listener rebinds, etc.) since we are replacing the process entirely
			}
		}
	}

	newCacheState := struct{ Janitor, Max int }{
		cfgNew.CacheJanitorIntervalMinutes,
		cfgNew.CacheMaxEntries,
	}
	// 2. Compare the entire struct at once
	if oldCacheState != newCacheState {
		//must happen before loadDependentStores() because inside it tries to flush it and it's nil
		s.swapDNSCache(cfgNew.CacheJanitorIntervalMinutes, cfgNew.CacheMaxEntries)
		log.Warn("Cache settings changed thus cache instance replaced (all cached entries dropped)",
			slog.Int("old_interval", oldCacheState.Janitor),
			slog.Int("new_interval", newCacheState.Janitor),
			slog.Int("old_max", oldCacheState.Max),
			slog.Int("new_max", newCacheState.Max),
		)
	}
	// 3. Flush the cache to apply new TTLs/rules
	s.flushDNSCache()

	if err := s.loadDependentStores(); err != nil {
		s.logFatal("Dependent stores reload failed:", err)
		panic2("BUG: unreachable")
	} else {
		log.Debug("Dependent stores reloaded successfully")
	}

	log.Info("All configuration files reloaded successfully")

	// 4. Update the rate limiter with new QPS settings
	s.rateLimiter.UpdateConfig(rateLimitConfigFrom(*cfgNew /*it's been updated*/))
	log.Debug("Rate limiter reinitialized")

	if s.adminUI != nil && s.adminUI.rateLimiter != nil {
		s.adminUI.rateLimiter.UpdateConfig(webUIRateLimitConfigFrom(*cfgNew))
		log.Debug("WebUI rate limiter reinitialized")
	}

	s.generateCertIfNeeded() // For DoH and webUI! just mutates certGeneration if needed

	s.upstreamMgr.ReInitDoHClients()

	//clearLoginLockouts()//wired in startWebUI

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
	return nil
}

func (s *Server) Run(sigChan chan os.Signal) error {
	log := s.getLogger()

	// Signal handling was already registered on sigChan as early as possible
	// in OldMain (before config loading, before this Server even existed), so
	// a Ctrl+C during the potentially lengthy boot sequence is queued by the
	// Go runtime rather than falling through to the default disposition
	// (immediate termination, skipping any buffered log flush). We just take
	// over reading from that same channel here.
	defer signal.Stop(sigChan)
	log.Debug("Signal channel ready - Ctrl+C to shutdown gracefully")

	// --- OS Console Event Handler Integration ---
	globalConsoleEventTrigger = func(eventName string, exitCode int) {
		logEvt := s.getLogger()
		logEvt.Warn("OS Console Event received, overriding for safe teardown",
			slog.String("event", eventName), slog.Int("exitcode", exitCode))

		// Triggers your exact sequence: cancels context, waits on WaitGroups, calls os.Exit()
		s.shutdown(exitCode)
		panic2("BUG: unreachable")
	}

	res1 := wincoe.RegisterCtrlHandler(consoleCtrlHandler)
	if res1.Failed() {
		if wincoe.HasConsole() {
			s.logFatal("Failed to register Windows console termination handler", res1.Err)
			panic2("BUG: unreachable")
			panic(nil)
		} else {
			// Non-fatal: this must never take down the whole server, most
			// notably because it can legitimately fail (or simply be moot) when
			// no console is attached (hide_console, or a -H=windowsgui build)
			// -- a scenario this handler exists to help with in the first
			// place. Graceful shutdown is still reachable via SIGINT/SIGTERM
			// below and, for a headless run, via the WebUI's Shutdown button.
			log.Warn("Failed to register Windows console termination handler; continuing without it because there's no console", wincoe.SafeErr(res1.Err))
		}
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

	// Full logging is already initialized by OldMain via rt.LogMgr.ApplyConfig
	// before NewServer and Run are called. Nothing to do here.

	s.swapDNSCache(cfg.CacheJanitorIntervalMinutes, cfg.CacheMaxEntries)
	log.Debug("Cache initialized")

	// Load dependent data stores NOW, using the correct full logger. Hold
	// tableMutationMu for the duration, matching Reload()'s identical
	// requirement — see loadDependentStores's doc comment for why, even
	// though nothing can race this specific call this early in startup
	// (the WebUI listener isn't accepting connections yet).
	s.tableMutationMu.Lock()
	loadErr := s.loadDependentStores()
	s.tableMutationMu.Unlock()
	if loadErr != nil {
		s.logFatal("Dependent stores load failed:", loadErr)
		panic2("BUG: unreachable")
	}

	s.rateLimiter = newClientRateLimiter( /*s.ctx, */ rateLimitConfigFrom(*cfg /*it's a copy, not pointer to live*/), log)
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
		func(code int) { // alt+x Ctrl+X etc. aka cleanExitFn
			log3 := s.getLogger()
			log3.Debug("Shutdown signal received, clean exit.")
			//doneFIXME: at least UDP DNS listener isn't shutdown while waiting for keypress to exit (after the shutdown(0) below) !!
			//cancel()    //doneFIXME: this triggers the below shutdown(4) !
			s.shutdown(code) // clean exit
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

// peekBootstrapLogSettings performs a best-effort, unvalidated read of
// config.json purely to recover which log directory and log filename the
// full, validated config will eventually resolve to, so this process's very
// first log lines — written before LoadAndValidateConfig has run at all —
// land in the same file the rest of this run will use. It intentionally
// skips every one of LoadAndValidateConfig's real validation steps
// (duplicate-key detection, description-key stripping, etc.), with one
// narrow exception: log_dir and log_file are each passed through resolveTag
// on a best-effort basis (silently keeping the caller-supplied default on
// any resolution error), so a {file:...}/{env:...}-templated value still
// resolves to the same directory/filename the real, fully-validated config
// load will use moments later. A malformed, corrupt, or not-yet-existing config.json
// simply leaves the two returned values at defaultDir/defaultFile, exactly
// like an absent file would, since the real parse — which DOES report a
// proper, actionable error either to the console or to this same bootstrap
// log file — runs moments later in LoadAndValidateConfig.
func peekBootstrapLogSettings(defaultDir, defaultFile string) (logDir, logFile string) {
	logDir, logFile = defaultDir, defaultFile
	data, err := os.ReadFile(configFileName)
	if err != nil {
		return logDir, logFile
	}
	var peek map[string]any
	if json.Unmarshal(data, &peek) != nil {
		return logDir, logFile
	}
	if val, ok := peek[getJSONTagByOffset(unsafe.Offsetof(Config{}.LogDir))].(string); ok {
		if resolved, _, resolveErr := resolveTag(val); resolveErr == nil {
			logDir = resolved
		}
	}
	if val, ok := peek[getJSONTagByOffset(unsafe.Offsetof(Config{}.LogEverythingFile))].(string); ok && val != "" {
		if resolved, _, resolveErr := resolveTag(val); resolveErr == nil {
			logFile = resolved
		}
	}
	return logDir, logFile
}

func OldMain() {
	//must do this first because localLogger below uses os.Stderr which is set here:
	handlesErr := EnsureConsoleHandles()

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
	envLvlStr := strings.ToLower(strings.TrimSpace(os.Getenv("DNSBOLLOCKS_BOOTSTRAP_LOG_LEVEL")))
	var envLvl slog.Level
	switch envLvlStr {
	case "info", "i":
		envLvl = slog.LevelInfo
	case "warn", "warning", "w":
		envLvl = slog.LevelWarn
	case "error", "e":
		envLvl = slog.LevelError
	default:
		envLvl = slog.LevelDebug // hard-coded for bootstrap
	}

	// Determine where this process's very-first log lines should land,
	// before config.json has even been fully loaded and validated. Always
	// start from a best-effort peek of config.json (see
	// peekBootstrapLogSettings's doc comment), then let an auto-restarting
	// parent's explicit env vars override either piece. This is what lets a
	// hide_console-detached child — which will never have a console to fall
	// back on if config parsing itself then fails — still honor whatever
	// log_dir the parent was actually configured with, instead of silently
	// reverting to the config-file directory the way an env-var-only,
	// peek-skipping scheme previously did.
	const defaultBootLogFilename = "dnsbollocks.log" // should match the one in Config.LogEverythingFile
	bootLogDir, bootLogFilename := peekBootstrapLogSettings(filepath.Dir(configFileName), defaultBootLogFilename)
	if envLog := os.Getenv("DNSBOLLOCKS_BOOTSTRAP_LOG_FILE"); envLog != "" {
		// The parent process explicitly passes the correct log file to use.
		// Overwriting any peeked value here is intentional so the child logs
		// to the most up-to-date configured destination after a config reload.
		bootLogFilename = envLog
	}
	if envDir, ok := os.LookupEnv("DNSBOLLOCKS_BOOTSTRAP_LOG_DIR"); ok {
		bootLogDir = envDir
	}

	// Force base filename only to prevent path traversal / arbitrary file writes during early boot
	baseName := filepath.Base(filepath.Clean(bootLogFilename))
	if baseName == "." || baseName == string(filepath.Separator) {
		baseName = defaultBootLogFilename
	}

	// Ensure the log directory exists before opening the file
	targetDir := resolveLogDir(bootLogDir)
	if err := os.MkdirAll(targetDir, 0755); err != nil { //If path is already a directory, MkdirAll does nothing and returns nil.
		panic2(fmt.Sprintf("failed to create log directory %q: %v", targetDir, err))
	}

	finalBootLogPath := resolveLogFilePath(bootLogDir, baseName)

	var bootLogFile *os.File
	// Open with FILE_SHARE_READ|FILE_SHARE_WRITE implicitly via Go os.OpenFile on Windows
	if f, err := os.OpenFile(finalBootLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600); err == nil {
		bootLogFile = f
	} else {
		// Best-effort only: on a hide_console-detached restart there may be
		// no console for this diagnostic to reach either, but on a normal
		// boot it at least explains why early logs won't be written to disk
		// this run.
		fmt.Fprintf(os.Stderr, "warning: failed to open bootstrap log file %q: %v\n", finalBootLogPath, err)
	}

	timeReplacer := func(groups []string, a slog.Attr) slog.Attr {
		// Intercept the built-in time key
		if a.Key == slog.TimeKey && len(groups) == 0 {
			t := a.Value.Time()
			// ".0000000" forces exactly 7 digits of zero-padded fractional seconds
			formattedTime := t.Format(TimeStampsFormat) //"2006-01-02T15:04:05.0000000Z07:00")
			return slog.String(slog.TimeKey, formattedTime)
		}
		return a
	}

	// var localLogger = slog.New(slog.NewTextHandler(logDest, &slog.HandlerOptions{
	// 	Level: envLvl,
	// 	ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
	// 		// Intercept the built-in time key
	// 		if a.Key == slog.TimeKey && len(groups) == 0 {
	// 			t := a.Value.Time()
	// 			// ".0000000" forces exactly 7 digits of zero-padded fractional seconds
	// 			formattedTime := t.Format(TimeStampsFormat) //"2006-01-02T15:04:05.0000000Z07:00")
	// 			return slog.String(slog.TimeKey, formattedTime)
	// 		}
	// 		return a
	// 	},
	// }))

	var handlers []slog.Handler

	// [RESOLVED FIXME 3]: Multiplex properly so the file stays pure JSON while the console gets colors.
	if wincoe.HasConsole() {
		if err := wincoe.EnableVirtualTerminalProcessing(); err != nil {
			panic2(fmt.Sprintf("EnableVirtualTerminalProcessing failed, err:%v", err))
			panic(nil)
		}
		handlers = append(handlers, NewColoredConsoleHandler(envLvl, nil))
	} else {
		handlers = append(handlers, slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: envLvl, ReplaceAttr: timeReplacer}))
	}

	if bootLogFile != nil {
		handlers = append(handlers, slog.NewJSONHandler(bootLogFile, &slog.HandlerOptions{Level: envLvl, ReplaceAttr: timeReplacer}))
	}

	// Inject the PID globally across all early bootstrap handlers
	var localLogger = slog.New(multiHandler{handlers: handlers}).With(slog.Int("pid", os.Getpid()))
	if localLogger == nil {
		panic2("BUG: unexpected nil return from initBootstrapLogging")
	}
	localLogger.Info("DNSbollocks starting... (bootstrap-logging inited)", slog.String("version", GetVersion()))

	// Wire the global fallback logger immediately so any panic2/getBugLogger call
	// during bootstrap uses the default
	wincoe.SetBugLogger(localLogger)
	wincoe.SetLogger(localLogger)

	if handlesErr != nil {
		localLogger.Warn("new process((re)iterating1of3): failed to set the handles", wincoe.SafeErr(handlesErr))
	} else {
		localLogger.Debug("new process((re)iterating1of3): console handles were set ok")
	}

	// Defensive: If this process was spawned by an auto-restart, wait for the parent to die
	// so that file locks (loggers) and TCP/UDP ports are completely released by Windows.
	if os.Getenv("DNSBOLLOCKS_IS_RESTARTING") == "1" {
		const waitMilliseconds = 15000
		const waitDuration time.Duration = waitMilliseconds * time.Millisecond // 15 seconds is plenty of time for the parent to exit cleanly

		waitedSuccessfully := false

		// //doneFIXME: the dnsbollocks.log file format is different due to this line(and any potential ones like it), see how all are json except this?:
		// //{"time":"2026-08-05T14:46:17.6567118+02:00","level":"INFO","msg":"exitting with exit code","pid":10220,"exitCode":0}
		// //time="2026-08-05 14:46:17.906651600+02:00 CEST" level=DEBUG msg="new process: Waiting for the old process to exit..." wait_duration=1s
		// //{"time":"2026-08-05T14:46:18.9146614+02:00","level":"INFO","msg":"Logging (re)initialized","pid":10280,"full_log":"dnsbollocks.log","queries_log":"queries.log","queries_simple_log":"queries_simple.log","console_level":"debug"}

		// localLogger.Debug("new process: Waiting for the old process to exit...", slog.Duration("wait_duration", waitHowLong))
		// os.Setenv("DNSBOLLOCKS_IS_RESTARTING", "0") //or else it might get inherited by a future process run? unsure, can't think atm heh
		// time.Sleep(waitHowLong)

		// if os.Getenv("DNSBOLLOCKS_NO_WAIT") == "1" {
		// eventOpened := false

		// 1. Try Event-based synchronization first (deterministic flush wait)
		if syncEventName := os.Getenv("DNSBOLLOCKS_SYNC_EVENT"); syncEventName != "" {
			if eventNamePtr, err := windows.UTF16PtrFromString(syncEventName); err == nil {
				//At Spawn: The event is guaranteed to exist the exact millisecond the child process boots up because old process made it before spawning! search for windows.CreateEvent( !
				//so the only way it doesn't exist here is if old process exited already by this time, which is what 'else' block catches!
				// 0x00100000 is SYNCHRONIZE access, required for WaitForSingleObject
				if hEvent, err := windows.OpenEvent(windows.SYNCHRONIZE, false, eventNamePtr); err == nil {
					func() {
						defer wincoe.CloseHandleLogged(&hEvent, "OldMain:WaitForSingleObject hEvent the flush logs event from old process")
						localLogger.Debug("new process: Waiting deterministically for parent to flush logs...")
						// Block precisely until the parent fires SetEvent() (Max 15 seconds safety net)
						if event, waitErr := windows.WaitForSingleObject(hEvent, waitMilliseconds); waitErr != nil {
							localLogger.Warn("new process: while waiting for flush event of old process, WaitForSingleObject encountered an error", wincoe.SafeErr(waitErr))
						} else {
							if event == uint32(windows.WAIT_TIMEOUT) {
								localLogger.Warn("new process: Timed out waiting for parent process' flush event.",
									slog.Duration("waited_duration", waitMilliseconds),
								)
							}
							// Whether it woke up instantly or timed out after 15s,
							// the wait phase is complete. Prevent cascading fallback delays.
							waitedSuccessfully = true
						}
					}() //call
					// eventOpened = true
				} else {
					// OpenEvent failed. This means the old process already closed its
					// handles and exited. Because it's gone, its file locks are already
					// released by the OS kernel. We can proceed instantly with zero delay!
					localLogger.Debug("new process: Sync event already dissolved (parent already exited). Proceeding immediately.")
				}
			} else {
				localLogger.Error("failed to UFT16 this", slog.String("syncEventName", syncEventName))
			}
		}

		// 2. Fallback: If event was missing or dissolved, try waiting on the Parent Process PID handle
		if !waitedSuccessfully {
			// Fallback just in case the OS failed to create/open the event
			// if !eventOpened {
			//okTODO:the event could've been reap'd by OS if old process exited too quickly, we should ensure the old PID is gone
			// }

			// localLogger.Debug("new process: Skipping full wait for parent process because it paused for interactive keypress. Yielding briefly for log flush...")
			// time.Sleep(500 * time.Millisecond) // Give parent a tiny window to finish flushLogs
			// //okFIXME: we need to make this dependent on somehow the parent having finished the flushing! I dno how atm, but it should be doable!
			// } else {
			if parentPIDStr := os.Getenv("DNSBOLLOCKS_PARENT_PID"); parentPIDStr != "" {
				// [FIXED G115]: Validate that parentPID fits within uint32 bounds before casting
				const rangeMin = 1
				const rangeMax = math.MaxUint32
				if parentPID, err := strconv.Atoi(parentPIDStr); err == nil && parentPID >= rangeMin && parentPID <= rangeMax {
					// const SYNCHRONIZE = 0x00100000
					if hProcess, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(parentPID)); err == nil {
						func() {
							defer wincoe.CloseHandleLogged(&hProcess, "OldMain:OpenProcess hProcess for old pid")

							// defer func() { //okFIXME: this should run sooner!
							// 	saved := hProcess
							// 	hProcess = 0
							// 	// wincoe.CloseHandle(saved)
							// 	// Defensive error handling for CloseHandle
							// 	if closeErr := windows.CloseHandle(saved); closeErr != nil {
							// 		localLogger.Debug("new process: failed to close parent process handle", wincoe.SafeErr(closeErr))
							// 	}
							// }()
							localLogger.Debug("new process: Waiting for the old process to exit...", slog.Int("parent_pid", parentPID))

							// Block exactly until parent dies (Max 15 seconds safety net)
							if event, waitErr := windows.WaitForSingleObject(hProcess, waitMilliseconds); waitErr != nil {
								localLogger.Warn("new process: WaitForSingleObject encountered an error", wincoe.SafeErr(waitErr))
							} else {
								if event == uint32(windows.WAIT_TIMEOUT) {
									localLogger.Warn("new process: Timed out waiting for parent process to exit.")
								}
								// Whether it woke up instantly or timed out after 15s,
								// the wait phase is complete. Prevent cascading fallback delays.
								waitedSuccessfully = true
							}
						}() //call
					} else {
						// localLogger.Warn("new process: Could not open parent process handle, waiting briefly instead.", wincoe.SafeErr(err), slog.Duration("wait_duration", waitDuration))
						// time.Sleep(waitDuration)

						// OpenProcess failing confirms the old process is already fully dead and gone
						localLogger.Debug("new process: Parent process already dead (OpenProcess failed). Proceeding immediately.")
						waitedSuccessfully = true
					}
				} else {
					localLogger.Error("new process: Invalid or out-of-range parent PID string, waiting briefly instead.",
						slog.String("pid_str", parentPIDStr),
						slog.Int("range_min", rangeMin), slog.Int("range_max", rangeMax),
						slog.Duration("wait_duration", waitDuration))
					time.Sleep(waitDuration)
				}
			} else {
				localLogger.Debug("new process: Waiting for the old process to exit...",
					slog.Duration("wait_duration", waitDuration))
				time.Sleep(waitDuration)
			}
		}

		// 3. Ultimate Fallback: If neither kernel handle could be opened, fallback to a brief sleep
		if waitedSuccessfully {
			localLogger.Debug("new process: done waiting.")
		} else {
			localLogger.Debug("new process: Falling back to brief sleep for parent exit...", slog.Duration("wait_duration", waitDuration))
			time.Sleep(waitDuration)
		}

		// Clean up the environment for any future sub-processes
		os.Setenv("DNSBOLLOCKS_IS_RESTARTING", "0")
		os.Setenv("DNSBOLLOCKS_PARENT_PID", "")
		os.Setenv("DNSBOLLOCKS_SYNC_EVENT", "")
		os.Setenv("DNSBOLLOCKS_BOOTSTRAP_LOG_DIR", "")
		os.Setenv("DNSBOLLOCKS_BOOTSTRAP_LOG_FILE", "")
		// os.Setenv("DNSBOLLOCKS_NO_WAIT", "")
	}

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

	// localLogger = initBootstrapLogging(localLogger) // ← FIRST LINE — colored console, log now exists

	// Wire the global fallback logger immediately so any panic2/getBugLogger call
	// during bootstrap uses the colored bootstrap logger, not the silent default.
	wincoe.SetBugLogger(localLogger)
	wincoe.SetLogger(localLogger)

	if handlesErr != nil {
		localLogger.Warn("new process((re)iterating2of3): failed to set the handles", wincoe.SafeErr(handlesErr))
	} else {
		localLogger.Debug("new process((re)iterating2of3): console handles were set ok")
	}

	// go func() {//doneTODO: get this back but maybe every 5 minutes or 10 or 1? but see to properly shut it down tho.
	//     ticker := time.NewTicker(5 * time.Second)
	//     defer ticker.Stop()
	//     for range ticker.C {
	//         log.Debug("MARK")
	//     }
	// }()

	// Register OS signal handling (Ctrl+C / SIGTERM) as early as possible —
	// well before config loading, logger initialization, or Server creation —
	// so a signal arriving during that potentially lengthy bootstrap window is
	// queued by the Go runtime's signal machinery instead of falling through
	// to the default disposition (immediate process termination, which would
	// skip flushing any buffered log lines written so far). The same channel
	// is threaded through to Server.Run(), which is the first place actually
	// equipped to act on it via the full graceful-shutdown sequence.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// ── 1. Build the Runtime (long-lived infrastructure) ─
	// The LogManager starts with the bootstrap logger; ApplyConfig will upgrade
	// it once the real config is validated.
	logMgr := NewLoggerManager(localLogger)
	if logMgr == nil {
		panic2("BUG: unexpected nil return from NewLoggerManager")
	}
	defer func() {
		if r := recover(); r != nil {
			// We caught a raw panic. Flush the logs first!
			if err := logMgr.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "warning2: error flushing/closing log writers during shutdown: %v\n", err)
			}
			// Then re-throw the panic so the program still crashes
			// and prints the stack trace to os.Stderr as expected.
			panic(r)
		}
	}()

	// Create a default FileWriter for the bootstrap phase (config not yet loaded).
	// It shares the LogManager's atomic pointer so it always sees the current logger.
	defCfg := defaultConfig()
	fileWriter := wincoe.NewWin11SafeFileWriter(
		defCfg.ExtraSafety,
		defCfg.FileWriterMaxRetries,
		defCfg.FileWriterRetryBackoffMs,
		logMgr.Ptr(),
	)

	rt := &Runtime{
		LogMgr:     logMgr,
		FileWriter: fileWriter,
	}

	// defer func() {//kinda late, maybe, ctually no, because this affects only log files, not eg. console.
	// 	if r := recover(); r != nil {
	// 		// We caught a raw panic. Flush the logs first!
	// 		rt.FlushLogsForShutdown()

	// 		// Then re-throw the panic so the program still crashes
	// 		// and prints the stack trace to os.Stderr as expected.
	// 		panic(r)
	// 	}
	// }()

	// ── 2. Handle CLI flags ─
	//flag.Parse() // For future flags
	hashCmd := flag.Bool("hash-password", false, "Securely prompt for a password, output the bcrypt hash, and exit")
	flag.Parse()
	if *hashCmd {
		hash, err := promptAndHashPassword(localLogger, 12) // Hardcode safe minimum for CLI
		if err != nil {
			localLogger.Error("Failed to set password: ", wincoe.SafeErr(err))
			finalShutdownSequence(localLogger, 1, os.Exit, rt.FlushLogsForShutdown)
		}
		//fmt.Printf("\nSuccess! Paste this exact string into your %s as the value for \"webui_password_hash\":\n%s\n", configFileName, hash)
		// Dynamic tag extraction
		var jsonTag string = getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIPasswordHash))
		fmt.Printf("\nSuccess! Paste this exact string into your %s as the value for %q:\n%s\n", configFileName, jsonTag, hash)
		localLogger.Debug("Generated new hash password(not logging it) via cmd line arg, not saved in config.", slog.String("config", configFileName))
		finalShutdownSequence(localLogger, 0, os.Exit, rt.FlushLogsForShutdown)
	}

	// ── 3. Load and validate configuration
	resolvedCfg, rawCfg, shouldSaveConfig, err := LoadAndValidateConfig(rt.Logger(), configFileName, rt.FileWriter, true)
	if err != nil {
		// Intercept fatal strings exactly as the old code did
		if strings.HasPrefix(err.Error(), "FATAL:") {
			rt.Logger().Error(strings.TrimPrefix(err.Error(), "FATAL: "))
		} else {
			rt.Logger().Error("Config load failed", wincoe.SafeErr(err))
		}
		finalShutdownSequence(rt.Logger(), 1, os.Exit, rt.FlushLogsForShutdown)
	} else {
		rt.Logger().Info("Config loaded", slog.String("filename", configFileName))
	}

	if resolvedCfg.HideConsole {
		if wincoe.HasConsole() {
			rt.Logger().Info(configKeyNameForHideConsole + " is enabled; detaching from the console now. Further console output will be silently dropped; monitor the configured log files or the WebUI instead.")
			if freeErr := wincoe.FreeConsole(); freeErr != nil {
				rt.Logger().Warn(configKeyNameForHideConsole+": FreeConsole failed; continuing with the console still attached", wincoe.SafeErr(freeErr))
			}
		} else {
			rt.Logger().Debug(configKeyNameForHideConsole + " is enabled but no console was attached to begin with (e.g. a -H=windowsgui build); nothing to do")
		}
	}

	// ── 4. Apply the validated config to the Runtime infrastructure ──
	// Update FileWriter safety settings now that we have the real config values.
	rt.ApplyFileWriterParams(resolvedCfg)

	// Close the temporary bootstrap log file handle so the real LoggerManager can own it cleanly
	if bootLogFile != nil {
		bootLogFile.Close()
	}

	// Initialize full logging (file handlers, correct console level).
	// After this call, bugLogger and wincoe.Logger are updated to the full logger.
	if err2 := rt.LogMgr.ApplyConfig(resolvedCfg); err2 != nil {
		rt.Logger().Error("Failed to initialize full logging", wincoe.SafeErr(err2))
		finalShutdownSequence(rt.Logger(), 1, os.Exit, rt.FlushLogsForShutdown)
	}

	// ── 5. Create and run the Server
	srv := NewServer(rt, resolvedCfg, rawCfg)
	if srv == nil {
		panic2("BUG: unexpected NewServer returned nil Server instance")
	}
	if shouldSaveConfig {
		// saveConfig internally calls s.getConfig(), which now has the fully updated data
		if err = srv.saveConfig(); err != nil {
			//			return fmt.Errorf("config save failed: %w", err)
			rt.Logger().Error("Failed to save initial configuration", wincoe.SafeErr(err))
			srv.shutdown(1)
		}
	}

	if handlesErr != nil {
		rt.Logger().Warn("new process((re)iterating3of3): failed to set the handles", slog.Any("err", handlesErr))
	} else {
		rt.Logger().Debug("new process((re)iterating3of3): console handler were set ok")
	}

	if err3 := srv.Run(sigChan); err3 != nil {
		rt.Logger().Error("Server exited with error", wincoe.SafeErr(err3))
		srv.shutdown(1)
		panic2("BUG: unreachable")
	}

	rt.Logger().Error("unreachable")
	//cancel()     // Cancel context for graceful close
	srv.shutdown(44) // impossible to reach this, unless code was added later and shutdown/exit was forgotten above.
	panic2("BUG: unreachable")
}

//const cacheMinTTLClamp = 10 // seconds

// LoadAndValidateConfig reads, parses, validates, and clamps the configuration.
// fw is used for CheckPowerLossFile; if nil a temporary FileWriter is created
// with default settings (appropriate for the first call before config is loaded).
// allowInteractivePasswordSetup gates the interactive console password prompt used
// when webui_password_hash is empty. Pass true only for the initial OldMain() boot
// sequence; every other caller (currently just Reload()) must pass false, since
// Reload can run from the Ctrl+R raw-terminal-reading loop (where re-entering the
// prompt's own terminal handling would fight over the same console state) or from
// an HTTP handler goroutine via the WebUI's Apply button (where there is no console
// reader waiting for input at all, so the prompt would simply hang forever).
func LoadAndValidateConfig(log *slog.Logger, cfgFname string, fw wincoe.FileWriter, allowInteractivePasswordSetup bool) (*Config, *Config, bool, error) {
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
	// s.fileWriter.SetRetryParams(defaultCfg.FileWriterMaxRetries, defaultCfg.FileWriterRetryBackoffMs) //TODO: ensure defaultConfig had sanitizeAndValidateConfig run on it

	// s.fileWriter.CheckPowerLossFile(cfgFname) //a default Config was already set at birth(even tho we also set it here, above, this one we set above isn't in effect yet), or kept the previously loaded one, those values are used by any child callers that use Server's Config during loadMainConfig() until the new config is atomically swapped in(at the end tho)

	// Temporarily spin up a file writer solely to check for power-loss corruption
	// using the default safety settings before we attempt to read the file.
	{
		checkFW := fw
		if checkFW == nil {
			var lp atomic.Pointer[slog.Logger]
			lp.Store(log)
			checkFW = newDefaultFileWriter(&lp)
		}
		checkFW.CheckPowerLossFile(cfgFname) //this panics if .powerloss file exists!
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

		// A leftover .bak from a prior SafeWriteFile-based save may mean the real
		// config.json was accidentally deleted/renamed rather than genuinely
		// missing for the first time. We don't block startup on it (that would be
		// too disruptive for what may be a legitimate first-run), but surface it
		// loudly so the operator notices before we silently create a fresh
		// defaults file over what might be recoverable state.
		if _, bakErr := os.Stat(cfgFname + wincoe.BackupFileExtension); bakErr == nil {
			log.Warn("Config file not found, but a backup file exists; if this is unexpected, restore it before continuing",
				slog.String("config_file", cfgFname),
				slog.String("backup_file", cfgFname+wincoe.BackupFileExtension))
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
		// Preserve the original, unstripped bytes so field-level "last
		// modified" timestamps (see Config.FieldModifiedAt's doc comment)
		// can be recovered below — stripConfigDescriptionKeys removes every
		// underscore-prefixed top-level key, including these.
		originalData := data

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

		// Recover each field's last-WebUI-modification timestamp (see
		// Config.FieldModifiedAt's doc comment) from the original,
		// unstripped bytes. Must happen before resolveConfigTags below so
		// resolvedCfg inherits a deep copy of it via Config.Clone().
		modifiedAtMap, modAtErr := extractFieldModifiedAtTimestamps(log, originalData)
		if modAtErr != nil {
			return nil, nil, false, fmt.Errorf("failed to extract field-modified-at timestamps from config file %q: %w", cfgFname, modAtErr)
		}
		rawCfg.FieldModifiedAt = modifiedAtMap

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

	// Enforce password setup if it's missing from the config
	if resolvedCfg.WebUIPasswordHash == "" {
		if !allowInteractivePasswordSetup {
			// See the allowInteractivePasswordSetup doc comment above: only the
			// initial OldMain() boot may block on this interactive prompt. Any other
			// caller (Reload()) gets a clean, immediately-abortable error instead of
			// an indefinite/racy stdin read.
			return nil, nil, false, fmt.Errorf(
				"webui_password_hash is empty in %q; interactive password setup only runs during the initial startup sequence; "+
					"set webui_password_hash manually (e.g. via the --hash-password flag; or via webUI) before triggering a reload",
				cfgFname)
		}
		log.Warn("No WebUI password configured. Securing WebUI now...")
		fmt.Println("\n========================================================")
		fmt.Println("   INITIAL SETUP: SECURING YOUR WEB CONTROL PANEL ")
		fmt.Println("========================================================")
		hash, err2 := promptAndHashPassword(log, resolvedCfg.WebUIPasswordBcryptCost)
		if err2 != nil {
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
//
// Callers MUST hold s.tableMutationMu for the entire duration of this call
// (Reload() and Run() both do). This is what makes applyConfig()'s
// config-swap (which can change WhitelistFile/HostsFile/BlacklistFile)
// atomic, as a unit, with respect to any WebUI table-mutation handler
// (rulesHandler, hostsHandler, responseBlacklistHandler, applyTablesHandler)
// that reads the live config's file-path fields while persisting its own
// in-memory mutations — without this, a table-mutation handler racing a
// Reload that also changes a dependent-file path could overwrite the
// newly-selected file's on-disk content with data that was actually loaded
// from the OLD path, silently destroying whatever the new file legitimately
// contained.
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
	if err := s.loadQueryBlocklist(); err != nil {
		return err
	} else {
		log.Debug("Query blocklist reloaded", slog.String("filename", cfg.QueryBlocklistFile))
	}
	// Never fatal — see loadExternalQueryBlocklist's doc comment.
	s.loadExternalQueryBlocklist()

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

func getNextLogBackupName(basePath string) (string, error) {
	const maxNumberOfRotations = 10000 // Intentionally not config.json-configurable: exposing this invites an operator setting it too low (silent wraparound/overwrite of old rotated logs) for little benefit; the timestamp-suffix fallback below already prevents silent data loss if this cap is ever actually reached.
	for i := 1; ; i++ {
		backupName := fmt.Sprintf("%s.%d", basePath, i)
		if _, err := os.Stat(backupName); os.IsNotExist(err) {
			return backupName, nil
		}
		// Put a hard cap to avoid infinite loops in extreme edge cases
		if i >= maxNumberOfRotations {
			return fmt.Sprintf("%s.%d", basePath, time.Now().Unix()), fmt.Errorf("at max number of rotations %d, cannot rotate! Clean up some of the early files first", maxNumberOfRotations)
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
	wincoe.GetBugLogger().Error(msg)
	panic(msg)
}

// // it's assumed that pattern and name are already lowercase(d) or uppercase(d), if not they won't match due to char case difference.
// func matchPattern1(pattern, name string) bool {
// 	if !isLowerASCII(pattern) {
// 		panic2("BUG: pattern was " + pattern + " which isn't lowercased, so bad coding somewhere!")
// 	}
// 	if !isLowerASCII(name) {
// 		panic2("BUG: name was " + name + " which isn't lowercased, so bad coding somewhere!")
// 	}

// 	// Fallback to recursive matching for other tokens ({*}, *, ?, !, literal text)
// 	return recursiveMatch1(pattern, name)
// }

// // recursiveMatch1 handles all tokens recursively.
// func recursiveMatch1(pattern, name string) bool {
// 	for len(pattern) > 0 {
// 		switch {
// 		case strings.HasPrefix(pattern, "{**}"):
// 			// consume 1+ chars including dots
// 			pattern = pattern[4:]
// 			if len(name) < 1 {
// 				return false
// 			}
// 			for i := 1; i <= len(name); i++ {
// 				if recursiveMatch1(pattern, name[i:]) {
// 					return true
// 				}
// 			}
// 			return false

// 		case strings.HasPrefix(pattern, "**"):
// 			// consume 0+ chars including dots
// 			pattern = pattern[2:]
// 			if len(name) == 0 {
// 				return recursiveMatch1(pattern, "")
// 			}
// 			for i := 0; i <= len(name); i++ {
// 				if recursiveMatch1(pattern, name[i:]) {
// 					return true
// 				}
// 			}
// 			return false

// 		case strings.HasPrefix(pattern, "{*}"):
// 			// consume 1+ chars, stop at dot
// 			pattern = pattern[3:]
// 			max3 := 0
// 			for j := 0; j < len(name) && name[j] != '.'; j++ {
// 				max3 = j + 1
// 			}
// 			if max3 < 1 {
// 				return false
// 			}
// 			for i := 1; i <= max3; i++ {
// 				if recursiveMatch1(pattern, name[i:]) {
// 					return true
// 				}
// 			}
// 			return false

// 		case strings.HasPrefix(pattern, "*"):
// 			// consume 0+ chars, stop at dot
// 			pattern = pattern[1:]
// 			if len(name) == 0 {
// 				return recursiveMatch1(pattern, "")
// 			}
// 			for i := 0; i <= len(name); i++ {
// 				if i < len(name) && name[i] == '.' {
// 					if recursiveMatch1(pattern, name[i:]) {
// 						return true
// 					}
// 					break
// 				}
// 				if recursiveMatch1(pattern, name[i:]) {
// 					return true
// 				}
// 			}
// 			return false

// 		case strings.HasPrefix(pattern, "?"):
// 			// consume exactly 1 char, not dot
// 			if len(name) == 0 || name[0] == '.' {
// 				return false
// 			}
// 			pattern = pattern[1:]
// 			name = name[1:]

// 		case strings.HasPrefix(pattern, "!"):
// 			// consume exactly 1 char, any
// 			if len(name) == 0 {
// 				return false
// 			}
// 			pattern = pattern[1:]
// 			name = name[1:]

// 		default:
// 			// literal char match
// 			if len(name) == 0 || pattern[0] != name[0] {
// 				return false
// 			}
// 			pattern = pattern[1:]
// 			name = name[1:]
// 		}
// 	}

// 	return len(name) == 0
// }

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

	// // We only need two rows to track matching states across token iterations.
	// // prevRow tracks matches for tokens[0...i-1]
	// // currRow tracks matches for tokens[0...i]
	// prevRow := make([]bool, numChars+1)
	// currRow := make([]bool, numChars+1)

	if numChars > 253 {
		// Defense-in-depth: handleDNSQuery already rejects any query domain
		// over 253 chars via isValidDNSName before ever reaching RuleStore/
		// HostStore matching, and the stack-allocated 256-bool buffers below
		// assume this bound. Rather than trust every current and future call
		// site to enforce that invariant perfectly — a single malformed or
		// directly-constructed oversized name reaching here would otherwise
		// crash the whole server — treat it as a non-match instead: no rule
		// pattern can ever legitimately need to match a name this long anyway.
		wincoe.GetBugLogger().Warn(fmt.Sprintf("the DNS name %q is %d chars long which is > 253", name, numChars)) //goodenoughTODO: log this somehow, might need a dedicated bugs.log file in addition to wherever panic2 logs them
		return false
	}
	// We only need two rows to track matching states across token iterations.
	// Since DNS names max out at 253 chars, stack-allocate 256 to eliminate GC pressure.
	var prevRowBuf, currRowBuf [256]bool
	prevRow := prevRowBuf[:numChars+1]
	currRow := currRowBuf[:numChars+1]

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

// certKeyPairValid reports whether the on-disk private key at keyFile is
// currently a usable match for cert: the key file must exist and parse as an
// RSA private key (matching the PKCS1 encoding generateCert always writes),
// its public component must match cert's own public key, and cert's validity
// window (NotBefore/NotAfter) must currently cover time.Now(). This exists
// because generateCertIfNeeded's SAN-coverage check alone cannot detect a
// deleted/mismatched key.pem or an expired cert.pem — both leave the SAN
// check happily passing right up until the later tls.LoadX509KeyPair call
// fails fatally, or (for expiry) until a TLS client rejects the handshake.
// On failure, reason is a short, human-readable explanation suitable for a
// Warn log line explaining why regeneration is about to happen.
func certKeyPairValid(cert *x509.Certificate, keyFile string) (ok bool, reason string) {
	if cert == nil {
		return false, "nil certificate"
	}

	now := time.Now()
	if now.Before(cert.NotBefore) {
		return false, fmt.Sprintf("certificate is not yet valid (NotBefore=%s)", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return false, fmt.Sprintf("certificate has expired (NotAfter=%s)", cert.NotAfter)
	}

	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return false, fmt.Sprintf("private key file unreadable: %v", err)
	}
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return false, "private key file has an empty or invalid PEM block"
	}
	privKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return false, fmt.Sprintf("private key failed to parse as PKCS1 RSA: %v", err)
	}

	certPub, ok2 := cert.PublicKey.(*rsa.PublicKey)
	if !ok2 {
		return false, fmt.Sprintf("certificate's public key is not RSA (got %T)", cert.PublicKey)
	}
	if certPub.N.Cmp(privKey.N) != 0 || certPub.E != privKey.E {
		return false, "private key does not match the certificate's public key"
	}

	return true, ""
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

				// SAN coverage alone doesn't guarantee this cert/key pair is
				// actually usable: the private key file could be missing,
				// unparseable, or simply not match this certificate (e.g. an
				// operator swapped in an unrelated key.pem), or the
				// certificate's own validity window might no longer cover
				// "now" (expired, or not-yet-valid due to a clock/backup
				// restore issue). None of that is visible from the SAN check
				// above, so verify it explicitly before deciding to skip
				// regeneration — see certKeyPairValid's doc comment.
				if !needsRegen {
					if ok, reason := certKeyPairValid(cert, keyFile); !ok {
						log.Warn("Existing cert/key pair is not currently usable; regenerating",
							slog.String("reason", reason),
							slog.String("cert_file", certFile),
							slog.String("key_file", keyFile))
						needsRegen = true
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
	log.Debug("Loading cert/key for DoH and Web UI...")

	loadedCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		s.logFatal("cert_load_failed", err)
		panic2("BUG: unreachable")
	}
	s.dohCertMu.Lock()
	s.dohCert = loadedCert
	s.dohCertMu.Unlock()
	log.Debug("Success - loaded into tls.Certificate")
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
	//
	// Windows note: os.OpenFile's mode bits only approximate POSIX permissions
	// (Go maps them to the read-only attribute on Windows, not real ACLs), and
	// O_TRUNC on an EXISTING file preserves whatever ACLs that file already
	// had. If a lower-privileged process ever previously created a placeholder
	// key.pem with weak permissions, truncating it in place would silently
	// keep those weak ACLs on the brand-new private key. Removing the old file
	// first (best-effort; a missing file is fine) and creating fresh with
	// O_EXCL instead of O_TRUNC ensures the new key file always gets the
	// parent directory's default-inherited ACLs rather than a stale,
	// possibly-weaker security descriptor.
	if rmErr := os.Remove(keyFileNameNoPath); rmErr != nil && !os.IsNotExist(rmErr) {
		return fmt.Errorf("failed to remove existing key file %q before regenerating it: %w", keyFileNameNoPath, rmErr)
	}
	keyOut, err := os.OpenFile(keyFileNameNoPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
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

type ClientMetadataFuture struct {
	wg   sync.WaitGroup
	done chan struct{} // closed once info is fully populated; enables a non-blocking peek via TryExe
	info clientMetadata
}

// TryExe reports the resolved executable name without blocking the caller.
// It returns ("", false) if the underlying OS-level PID/exe lookup hasn't
// finished yet. Callers that can tolerate an occasional "unknown" exe name in
// exchange for never blocking (e.g. logging a rate-limited request) should use
// this instead of Wait()ing on the WaitGroup — see handleDNSQuery's rate-limit
// branch for why blocking there is actively harmful under a UDP flood.
func (f *ClientMetadataFuture) TryExe() (exe string, ready bool) {
	select {
	case <-f.done:
		return f.info.exe, true
	default:
		return "", false
	}
}

// logIfSlowMetadataLookup logs a "slow lookup" warning via
// wincoe.GetBugLogger if elapsed is at or above
// cfg.ClientMetadataLookupSlowWarnThresholdMs. A configured threshold of 0
// (or less) disables these warnings entirely — see that field's doc comment
// for why a fixed hardcoded threshold doesn't work well across machines of
// very different speeds: what's "slow" on a fast desktop is routine on a
// budget or loaded box, and a hardcoded threshold would either spam the log
// on slower hardware or fail to flag a genuine slowdown on fast hardware.
func logIfSlowMetadataLookup(cfg *Config, what string, elapsed time.Duration) {
	thresholdMs := cfg.ClientMetadataLookupSlowWarnThresholdMs
	if thresholdMs <= 0 {
		return
	}
	if elapsed >= time.Duration(thresholdMs)*time.Millisecond {
		wincoe.GetBugLogger().Warn("slow "+what+" in startMetadataLookup",
			slog.Duration("elapsed", elapsed),
			slog.Int("threshold_ms", thresholdMs),
		)
	}
}

func (s *Server) startMetadataLookup(ctx context.Context, protocol string, clientAddr net.Addr) context.Context {
	future := &ClientMetadataFuture{done: make(chan struct{})}
	future.info.protocol = protocol
	future.info.clientAddr = clientAddr
	future.info.startTime = time.Now() // Capture start time
	future.wg.Add(1)

	s.GoSafe(func() {
		defer future.wg.Done()
		defer close(future.done)
		var pid uint32
		var exe string
		var err error
		log := s.getLogger()
		cfg := s.getConfig()

		switch protocol {
		case "UDP":
			if udpAddr, ok := clientAddr.(*net.UDPAddr); ok {
				start := time.Now()
				pid, exe, err = wincoe.PidAndExeForUDP(udpAddr)
				logIfSlowMetadataLookup(cfg, "wincoe.PidAndExeForUDP()", time.Since(start))
			}
		case "TCP", "DoH":
			if tcpAddr, ok := clientAddr.(*net.TCPAddr); ok {
				start := time.Now()
				pid, exe, err = wincoe.PidAndExeForTCP(tcpAddr)
				logIfSlowMetadataLookup(cfg, "wincoe.PidAndExeForTCP()", time.Since(start))
			}
		}

		future.info.pid = pid
		future.info.exe = exe
		future.info.err = err
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
		} else { //err==nil
			start := time.Now()
			services, err2 := wincoe.GetServiceNamesFromPIDCached(pid)
			logIfSlowMetadataLookup(cfg, "wincoe.GetServiceNamesFromPIDCached()", time.Since(start))
			future.info.services, future.info.err = services, err2
			if err2 != nil {
				serviceInfo = fmt.Sprintf("err=%v", err)
			} else {
				serviceInfo = fmt.Sprintf("%v", services)
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
	})

	return context.WithValue(ctx, clientInfoKey{}, future)
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

// Listeners...

func (s *Server) handleUDP(ctx context.Context, wire []byte, clientAddr *net.UDPAddr, ln *net.UDPConn) {
	log := s.getLogger()

	if clientAddr == nil {
		panic2("BUG: nil ClientAddr in handleUDP, not possible?!")
	}
	reqMsg := new(dns.Msg)
	if err := reqMsg.Unpack(wire); err != nil {
		// Edge: Invalid packet (common in floods)
		log.Warn("invalid DNS UDP packet (couldn't Unpack) thus dropped/ignored", wincoe.SafeErr(err))
		return
	}
	// 1. EXTRACT MAX UDP SIZE
	// Default to standard 512 bytes, but check if the client provided an EDNS0 OPT record.
	cfg := s.getConfig()
	maxUDPSize := 512
	if clientOpt := reqMsg.IsEdns0(); clientOpt != nil {
		maxUDPSize = int(clientOpt.UDPSize())
	}
	// Clamp against our own configured UDP buffer size so a client that
	// advertises an unreasonably large UDP payload capability (up to 65535)
	// can never make us attempt to transmit a reply bigger than we're
	// configured to expect. Sending an oversized UDP datagram risks IP
	// fragmentation, which many NATs/firewalls silently drop instead of the
	// client cleanly receiving the TC (truncated) bit and falling back to
	// TCP.
	if maxUDPSize > cfg.DNSUDPBufferSize {
		maxUDPSize = cfg.DNSUDPBufferSize
	}

	resp := s.handleDNSQuery(ctx, reqMsg, clientAddr.String())
	if resp == nil {
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

	//plain TCP DNS packets have a strict RFC 1035 hard limit of 65,535 bytes
	const maxDNSTCPPacketSize = 65535 //nopeTODO: make this configurable in config.json ; It's the RFC 1035 hard limit (65535); not a tunable;

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
	if length > cfg.DoHMaxRequestBodyBytes || length > maxDNSTCPPacketSize || length <= 0 { // Edge: Oversize packet
		log.Warn("invalid packet length in TCP DNS connection, thus dropped/ignored",
			slog.Int("actual_length", length),
			slog.Int("maxDNSTCPPacketSize", maxDNSTCPPacketSize),
			slog.Int(getJSONTagByOffset(unsafe.Offsetof(Config{}.GlobalRateQPS)), cfg.DoHMaxRequestBodyBytes),
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
	reqMsg := new(dns.Msg)
	if err := reqMsg.Unpack(wire); err != nil {
		log.Warn("invalid DNS TCP packet (couldn't Unpack) thus dropped/ignored", wincoe.SafeErr(err))
		return
	}

	resp := s.handleDNSQuery(ctx, reqMsg, conn.RemoteAddr().String())
	// --- 4. WRITE THE RESPONSE ---
	if resp != nil {
		pack, err1 := resp.Pack() // Ignore err
		if err1 != nil {
			log.Warn("failed to pack DNS TCP packet response thus not sent", wincoe.SafeErr(err1))
			return
		}
		if len(pack) > math.MaxUint16 {
			// Handle the error appropriately for your server (e.g., logging)
			log.Warn("packet size exceeds uint16 limit", "size", len(pack))
			return
		}
		// Prepare the output (length + payload)
		out := new(bytes.Buffer)
		err2 := binary.Write(out, binary.BigEndian, uint16(len(pack))) //nolint:gosec // G115: size validated just a few lines above
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
	log.Debug("No TCP DNS response to write, likely due to BlockMode being 'drop' ?!", slog.String("BlockMode", cfg.BlockMode))
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

// forwardInFlightEntry coordinates a single in-progress upstream forward
// attempt for one cache key (domain+qtype), so a burst of concurrently
// arriving identical queries for a newly-expired/never-cached entry — a
// classic "thundering herd" — coalesces into one upstream request instead of
// one independent upstream request per packet. Mirrors the exact same
// in-flight-coalescing pattern wincoe.GetServiceNamesFromPIDCached already
// uses for an analogous problem (concurrent PID->service-name lookups).
type forwardInFlightEntry struct {
	done chan struct{} // closed once the leader has finished this key's attempt
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
		// Use our TCP PID helper, moved
		//pid, exe, pErr := wincoe.PidAndExeForTCP(remoteTCP)
		// wincoe.Smashy()
		//ctx = s.makeClientInfoContext(ctx, "DoH", remoteTCP, pid, exe, pErr)
		ctx = s.startMetadataLookup(ctx, "DoH", remoteTCP)
	} else {
		log.Warn("DoH: could not resolve remote addr", slog.String("addr", r.RemoteAddr))
		//FIXME: this is a bigger problem than a WARN, if it happens! but an ERROR here would make it mix with the red colored blocked requests, thus harder to be seen!
		//TODO: see if we can trigger this! and/or think of what happens if it happens!
	}

	if r.Method != http.MethodPost && r.Method != http.MethodGet { //"POST" "GET"
		log.Warn("DoH request rejected: Method not allowed",
			slog.String("method", r.Method),
			slog.String("client", r.RemoteAddr))
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
		// Bound the encoded query length before decoding so a client can't force
		// large allocations/CPU work via an oversized "dns" param; base64url needs
		// ceil(4*N/3) chars to encode N raw bytes, so this mirrors the same cap
		// doh_max_request_body_bytes already enforces on the POST path above.
		if len(encoded) > base64.RawURLEncoding.EncodedLen(cfg.DoHMaxRequestBodyBytes) {
			log.Warn("DoH GET request rejected: Encoded query too large",
				slog.String("client", r.RemoteAddr),
				slog.Int("encoded_len", len(encoded)),
				slog.Int("max", cfg.DoHMaxRequestBodyBytes),
				slog.String("config.json", getJSONTagByOffset(unsafe.Offsetof(Config{}.DoHMaxRequestBodyBytes))),
			)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		body, err = base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			log.Warn("DoH GET request rejected: Invalid base64 'dns' param",
				wincoe.SafeErr(err),
				slog.String("client", r.RemoteAddr),
				slog.String("base64_dns_param", encoded), //XXX: hmmm, should I not log this in case wtw prints this could be exploited by printing it?!
			)
			http.Error(w, "Invalid GET param", http.StatusBadRequest)
			return
		}
	}
	if err != nil || len(body) == 0 {
		log.Warn("DoH request rejected: Empty or unreadable body",
			wincoe.SafeErr(err),
			slog.Int("body_len", len(body)),
			slog.String("client", r.RemoteAddr))
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	reqMsg := new(dns.Msg)
	if err2 := reqMsg.Unpack(body); err2 != nil {
		log.Warn("DoH request rejected: Failed to unpack DNS query",
			wincoe.SafeErr(err2),
			slog.String("client", r.RemoteAddr))
		http.Error(w, fmt.Sprintf("Failed to unpack DNS query, err:%v", err2), http.StatusBadRequest)
		return
	}
	resp := s.handleDNSQuery(ctx, reqMsg, r.RemoteAddr /*field not method*/)
	if resp == nil { //can happen when BlockMode is "drop" so nvmFIXME? "For DoH the HTTP connection is already accepted; 503 is the only correct response for drop mode"
		if cfg.BlockMode != blockModeDrop {
			log.Warn("empty DNS response, replying to DoH client with: 503 Service Unavailable", slog.String("client", r.RemoteAddr))
		}
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

	// RFC 8484 §5.1: advertise how long this response may be cached by any
	// intermediate HTTP cache, derived from the DNS answer's own TTL — the
	// same clamped-to-floor computation already used for our own DNS cache
	// (see computeTTLForCaching), so both caching layers agree on freshness.
	cacheSeconds := int(computeTTLForCaching(resp).Seconds())
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", cacheSeconds))
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Content-Length", fmt.Sprint(len(pack)))
	w.WriteHeader(http.StatusOK)
	wroteN, err := w.Write(pack) //nolint:gosec // G705: this writes a DNS wire-format response (application/dns-message), not HTML
	if err != nil {
		log.Warn("failed to write the DoH reply to client (the DNS packet response body)", wincoe.SafeErr(err), slog.Int("wrote_bytes", wroteN), slog.Int("shoulda_written", len(pack)))
		return
	}
}

// stripHTTPSPortPrefix recognizes an RFC 9460 §9 "port-prefixed" HTTPS
// record name of the form "_<port>._https.<target>" (queried by some
// clients, e.g. browsers, when connecting to a non-standard port) and, if
// domain matches that exact syntax, returns <target> and true.
//
// The syntax requires, in order: a first label consisting of a single
// leading underscore followed by one or more ASCII digits (the port number,
// which must additionally fall within 0-65535); a second label that is
// exactly "_https"; and at least one further label (the target name).
// Anything that doesn't match this precisely — including a bare leading
// underscore with no digits, non-numeric "port" text, or "_https" not
// immediately following the port label — is left untouched (ok=false),
// since it isn't actually a port-prefixed HTTPS lookup at all.
//
// domain must already be lowercased and have any trailing root dot stripped
// (as handleDNSQuery does before calling this).
func stripHTTPSPortPrefix(domain string) (target string, ok bool) {
	if !strings.HasPrefix(domain, "_") {
		return domain, false
	}
	labels := strings.SplitN(domain, ".", 3)
	if len(labels) != 3 {
		return domain, false
	}
	portLabel, httpsLabel, rest := labels[0], labels[1], labels[2]

	portDigits := strings.TrimPrefix(portLabel, "_")
	if portDigits == "" {
		return domain, false // bare "_" with no digits after it
	}
	for i := 0; i < len(portDigits); i++ {
		if portDigits[i] < '0' || portDigits[i] > '9' {
			return domain, false
		}
	}
	portNum, err := strconv.Atoi(portDigits)
	if err != nil || portNum < 0 || portNum > 65535 {
		return domain, false
	}

	if httpsLabel != "_https" {
		return domain, false
	}
	if rest == "" {
		return domain, false
	}
	return rest, true
}

// stripECSOption removes any EDNS0 Client Subnet (ECS) option (RFC 7871)
// from msg's OPT pseudo-record, if present, mutating msg in place.
//
// This proxy resolves on behalf of every client as a single shared
// resolver, and caches upstream answers under a domain+qtype key that is
// shared across every client. If a client's own stub resolver attaches an
// ECS option carrying its subnet, some upstream providers tailor (e.g. for
// CDN/geo-routing purposes) their answer to that specific subnet — and if
// that subnet-specific answer were then cached under the shared key, every
// OTHER client sharing this proxy would transparently receive it too,
// regardless of their own network location. Stripping ECS before a query is
// ever forwarded keeps every upstream answer subnet-independent, which is
// what makes domain+qtype a safe, globally-shared cache key in the first
// place.
func stripECSOption(msg *dns.Msg) {
	opt := msg.IsEdns0()
	if opt == nil {
		return
	}
	kept := opt.Option[:0]
	for _, o := range opt.Option {
		if _, isECS := o.(*dns.EDNS0_SUBNET); isECS {
			continue
		}
		kept = append(kept, o)
	}
	opt.Option = kept
}

func (s *Server) handleDNSQuery(ctx context.Context, reqMsg *dns.Msg, clientAddr string) *dns.Msg {
	cfg := s.getConfig()
	// log := s.getLogger()
	//This is the important one — without capturing it once, a reload landing between the cachee-hit check and a later Set for the same request could write into a freshly-swapped (empty) cachee generation while having read from the old one.
	cachee := s.getCache()

	if len(reqMsg.Question) != 1 {
		return formerrResponse(reqMsg)
	}
	q := reqMsg.Question[0]
	domain := strings.ToLower(strings.TrimSuffix(q.Name, ".")) //XXX: must lowercase it for matchPattern below! at least.
	if domain == "" || !isValidDNSName(domain) {               // Edge: Empty domain
		return formerrResponse(reqMsg)
	}
	qtype := dns.TypeToString[q.Qtype] // Map lookup

	// Cache key is derived from domain+qtype alone (see stripECSOption's doc
	// comment below for why every client shares one cache key here); computed
	// once, up front, so both the "blocked by lack of whitelist rule" branch
	// further below and the main allowed-query cache lookup can share it
	// instead of maintaining two independently-computed key strings.
	key := domain + ":" + qtype

	// Strip any client-supplied EDNS0 Client Subnet (ECS) option before this
	// query ever reaches an upstream or gets cached — see stripECSOption's
	// doc comment for why sharing one cache key (domain+qtype) across every
	// client requires every upstream answer to be subnet-independent.
	stripECSOption(reqMsg)

	// Rate limit
	if allowed, reason := s.rateLimiter.Allow(clientAddr); !allowed {
		/*
			Zero Network Bottlenecks: The moment rateLimiter.Allow rejects a packet, servfailResponse(reqMsg) is generated and returned instantly. Your semaphore slots (dnsUDPSem/dnsTCPSem) are freed immediately, successfully absorbing massive UDP floods without stalling the resolver.
			No More <pending_lookup>: The closure captures the ctx and safely invokes future.wg.Wait() on its own time. The console warning will now gracefully wait for the Win32 OS-level API to resolve the PID and output the actual executable name.
			Safe Memory Footprint: Go's goroutines are incredibly cheap (~2KB). Even if you drop 10,000 packets per second during a brutal flood and the OS lookups take 100ms each, you'll only peak at ~20MB of transient memory for these background logging routines before the garbage collector sweeps them away.
		*/
		// 1. Shed the network load instantly to free the concurrency slot.
		sfr := servfailResponse(reqMsg)

		// 2. Offload the warning log to a background goroutine.
		// This eliminates the `<pending_lookup>` issue without blocking the hot path.
		s.GoSafe(func() {
			// Re-fetch the logger just like s.logQuery does, ensuring we don't
			// write to a closed file if a config reload happens mid-wait.
			log := s.getLogger()
			var exeName string = unknownExePlaceHolder
			if future, ok := ctx.Value(clientInfoKey{}).(*ClientMetadataFuture); ok {
				// // Non-blocking peek only: a rate-limited request must never wait on
				// // the synchronous OS-level PID/exe lookup. Blocking here (as this
				// // used to do via future.wg.Wait()) would tie up this goroutine's
				// // concurrency-limiter slot (dnsUDPSem/dnsTCPSem) waiting on the OS
				// // instead of freeing it immediately once rate-limited, which under a
				// // UDP flood defeats the entire point of rate-limiting: shedding load
				// // fast. An occasional "<pending_lookup>" in this one log line is a
				// // fine trade for that. FIXME: not so sure about that! May need to revisit this maybe postpone logQuery itself, or log it with pending but then log it again when finished?!
				// if exe, ready := future.TryExe(); ready {
				// 	if exe != "" {
				// 		exeName = exe
				// 	}
				// } else {
				// 	exeName = "<pending_lookup>"
				// }
				//future.wg.Wait() // Wait safely in the background! blocks unconditionally! Because logQuery uses s.GoSafe, this goroutine is added to s.shutdownWG. If the Win32 call hangs forever, this goroutine hangs forever, which means s.shutdownWG.Wait() inside your s.shutdown() method will deadlock. Your server will refuse to shut down gracefully and will hang indefinitely.
				select {
				case <-future.done:
					// log with metadata
					if future.info.exe != "" {
						exeName = future.info.exe
					}
				case <-s.ctx.Done():
					// server is shutting down, abort the wait
					log.Warn("Not waiting for a pid/exe metadata to be resolved due to server is shutting down, but will still log the query below, with exe name as " + exeName)
					// return
				case <-time.After(clientMetadataLookupTimeout):
					// The OS API hung. Abort to prevent a permanent goroutine memory leak.
					log.Warn("timed out waiting for client pid/exe metadata lookup for logging, but will still log the query below, with exe name as "+exeName,
						slog.String("clientAddr", clientAddr), slog.Duration("timeout", clientMetadataLookupTimeout))
					// exeName remains its default fallback (e.g., "<unknown_exe>")
				}
			} //if

			// Dynamically fetch config tags and values based on which limit was tripped
			var rateTag, burstTag string
			var rateVal, burstVal int

			if reason == globalRateLimitExceeded {
				rateTag = getJSONTagByOffset(unsafe.Offsetof(Config{}.GlobalRateQPS))
				burstTag = getJSONTagByOffset(unsafe.Offsetof(Config{}.GlobalBurstQPS))
				rateVal = cfg.GlobalRateQPS
				burstVal = cfg.GlobalBurstQPS
			} else { // clientRateLimitExceeded
				rateTag = getJSONTagByOffset(unsafe.Offsetof(Config{}.ClientRateQPS))
				burstTag = getJSONTagByOffset(unsafe.Offsetof(Config{}.ClientBurstQPS))
				rateVal = cfg.ClientRateQPS
				burstVal = cfg.ClientBurstQPS
			}

			displayDomain, wasIDN := punycodeDecodePatternForDisplay(domain)
			attrs := []any{
				slog.String("client", clientAddr),
				slog.String("domain", domain), // Always ASCII/Punycode (the true wire format)
				slog.String("exe", exeName),
				slog.Int(rateTag, rateVal),
				slog.Int(burstTag, burstVal),
			}
			if wasIDN {
				attrs = append(attrs, slog.String("domain_idn", displayDomain)) // Unicode representation for logs
			}
			log.Warn(reason, attrs...)
		}) //GoSafe

		// sfr := servfailResponse(reqMsg)
		// 3. s.logQuery also uses GoSafe internally, so this remains fully non-blocking.
		s.logQuery(ctx, clientAddr, domain, qtype, reason, "", nil, sfr, UpstreamState{Strategy: "rateLimited"})
		return sfr
	} //!allowed
	log := s.getLogger()

	// RFC 9460 §9 port-prefixed HTTPS record names.
	//
	// Modern clients (e.g. Firefox 152.0.6) may query "_<port>._https.<target>" for
	// non-standard ports. For local /hosts overrides we strip the RFC 9460
	// prefix so a host entry for <target> also applies to these lookups.
	// If no local override matches, the query proceeds through the normal
	// whitelist and upstream resolution path unchanged.
	/*
			The behavior then becomes:

		/hosts contains example.com
		_8443._https.example.com uses that local override. ✅
		/hosts doesn't contain it
		fall through to the normal whitelist. ✅
		if the whitelist contains a rule matching _8443._https.example.com, it forwards upstream. ✅
		if not, it's blocked exactly like any other query. ✅
	*/
	baseDomainForHostMatch := domain
	//if qtype == "HTTPS" {
	if stripped, ok := stripHTTPSPortPrefix(domain); ok {
		baseDomainForHostMatch = stripped
	}
	//}

	//log.Debug(fmt.Sprintf("Checking host-override match for %q (type %q), original query %q", baseDomainForHostMatch, qtype, domain)) //okTODO: remove, this was temporary!

	// Local host overrides in /hosts are authoritative on their own and never
	// gated behind the /rules whitelist: gating them would either let a stale
	// /rules pattern block an override that should work, or - worse - keep
	// permitting resolution after a /hosts pattern is edited/removed, purely
	// because the OLD pattern still happens to satisfy some unrelated /rules
	// entry. So check it first, unconditionally.
	hostIPs, hostMatched := s.hostStore.Match(baseDomainForHostMatch)

	// Query blocklist (see query_blocklist.go) is evaluated before whitelist
	// rules and — unless local_hosts_override_query_blocklist is true —
	// before local host overrides too, since it's meant to be a hard
	// override of last resort ("block no matter what else says otherwise").
	// See Server.checkQueryBlocklist's doc comment for the two-layer
	// precedence rules within this feature itself.
	if !cfg.LocalHostsOverrideQueryBlocklist || !hostMatched {
		if blockReason, blockMatchedID, qblocked := s.checkQueryBlocklist(baseDomainForHostMatch); qblocked {
			if entry, ok := cachee.Get(key); ok {
				return s.respondFromCache(ctx, entry, reqMsg, clientAddr, domain, qtype, blockMatchedID)
			}
			return s.blockAndCacheQuery(ctx, cfg, cachee, reqMsg, clientAddr, domain, qtype, key, blockReason, blockMatchedID, "queryBlocklist", true)
		}
	}

	var matchedID string
	var allowed bool
	if cfg.WhitelistMode {
		allowed = hostMatched
		if !allowed {
			//normal check against the whitelist(aka the /rules page in webUI):
			matchedID, allowed = s.ruleStore.MatchForType(qtype, domain)
			if !allowed && cfg.AllowHTTPSIfAAllowed && qtype == "HTTPS" {
				matchedID, allowed = s.ruleStore.MatchForType("A", domain)
			}
		}
	} else {
		// Blacklist mode ("allow all except query-blocklisted, or
		// response-blacklisted once the actual upstream answer is known"):
		// the query blocklist above is the only thing that can block a
		// query before it's forwarded; whitelist rules play no role in the
		// allow/deny decision here. A rule match, if any, is still recorded
		// purely for logging/rule-ID attribution.
		allowed = true
		// MatchForType's ok is intentionally discarded: in blacklist mode a
		// match is recorded only for logging/rule-ID attribution, never for
		// the allow/deny decision (allowed stays true either way).
		matchedID, _ = s.ruleStore.MatchForType(qtype, domain)
		if matchedID == "" && cfg.AllowHTTPSIfAAllowed && qtype == "HTTPS" {
			matchedID, _ = s.ruleStore.MatchForType("A", domain)
		}
	}

	// Record every allowed query — regardless of whitelist_mode — for the
	// WebUI's TheAllowsPage (Recent Allows) page; see recentAllowed's doc
	// comment. Defensive nil-check: NewServer always initializes this, but
	// some tests construct a bare &Server{...} directly, bypassing
	// NewServer (mirrors the identical s.forwardInFlight nil-check
	// elsewhere in this function).
	if allowed && s.recentAllowed != nil {
		s.recentAllowed.Record(domain, qtype, cfg.MaxRecentBlocks)
	}

	if !allowed {
		// A domain blocked by policy deserves a cache entry just like any other
		// response — see Config.BlockedResponseTTLSec's desc tag ("blocked
		// responses are also stored in this proxy's own internal cache for this
		// amount of time"), which already documented this but the code never
		// actually did it for this branch (only the "upstream returned a
		// blacklisted/zero IP" branch further below cached its blocked result).
		// A cache hit is checked first so a domain whitelisted later is served
		// fresh again: every WebUI rule add/edit/delete already calls
		// invalidateCacheForPattern/invalidateCacheForPatterns, which evicts
		// exactly this kind of now-stale "blocked" entry.
		if entry, ok := cachee.Get(key); ok {
			return s.respondFromCache(ctx, entry, reqMsg, clientAddr, domain, qtype, "")
		}
		recordRecentBlock := !s.shouldSkipAAAARecentBlockEntry(cfg, qtype, domain)
		return s.blockAndCacheQuery(ctx, cfg, cachee, reqMsg, clientAddr, domain, qtype, key, blockedSTR, "", "blockedByLackOfRuleAllowingIt", recordRecentBlock)
	}

	// Cache (edge: Negative responses cached short)
	// Intentionally keyed by the lowercased 'domain' (not the original, possibly
	// mixed-case query name) so every casing variant of the same query name (e.g.
	// "example.com", "Example.COM", "EXAMPLE.com") shares one cache entry instead of
	// one entry per casing variant seen. See adjustResponseCaseToQuery below for how
	// the served response still gets the CURRENT query's exact casing on a cache hit.
	// (key was already computed earlier, right after qtype, so the "blocked by
	// lack of whitelist rule" branch above can share it.)
	// key := domain + ":" + qtype

	//fmt.Printf("checking '%s' key in cache\n", key)
	if entry, ok := cachee.Get(key); ok {
		return s.respondFromCache(ctx, entry, reqMsg, clientAddr, domain, qtype, matchedID)
	}

	// --- START Local Hosts Override ---
	if hostMatched {
		switch qtype {
		case "A", "AAAA", "HTTPS":
			// Handled below
		default:
			// Domain exists in local overrides, but this record type is unhandled.
			// Do not panic. Just fall through. The loop below won't match the type,
			// resulting in an empty NOERROR (NODATA) response. This correctly tells
			// the client the domain exists but lacks this specific record type.
			log.Debug("Returning NODATA for unhandled host-override query type", slog.String("DNS_query_type", qtype))
		} //switch

		resp := new(dns.Msg)
		resp.SetReply(reqMsg) // this sets Rcode=RcodeSuccess aka 0
		resp.Authoritative = true
		resp.RecursionAvailable = true

		for _, ip := range hostIPs {
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
			} else if qtype == "HTTPS" {
				// FIX D: Synthesize Type 65 HTTPS records locally.
				// This prevents aggressive clients (like Apple devices) from bypassing
				// the proxy when they receive an empty NODATA response for the HTTPS DNS query.
				rr := new(dns.HTTPS)
				rr.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: cfg.LocalHostsOverrideTTLSec}
				rr.Priority = 1

				// RFC 9460 forbids Target="." for port-prefixed queries.
				// Point it explicitly back to the base domain.
				if baseDomainForHostMatch != domain {
					rr.Target = baseDomainForHostMatch + "."
				} else {
					rr.Target = "."
				}

				/*
					While your Target fix is perfectly spec-compliant, modern browsers and the Windows 11 dnscache service are incredibly picky about HTTPS records (Type 65). If a record is in "ServiceMode" (Priority = 1), strict parsers expect an ALPN (Application-Layer Protocol Negotiation) hint. Without it, they might deem the record "incomplete" for a secure connection and drop the entire DNS resolution sequence.
					To bulletproof your synthesized record against strict OS/browser parsers, inject the SVCBAlpn parameter right above your IP hints:
					 - Gemini 3.1 Pro
				*/
				// Tell strict clients which HTTP protocols we speak
				rr.Value = append(rr.Value, &dns.SVCBAlpn{Alpn: []string{"h2", "http/1.1"}})

				// Inject the overridden IP directly into the SVCB hints
				if isIPv4 {
					rr.Value = append(rr.Value, &dns.SVCBIPv4Hint{Hint: []net.IP{ip}})
				} else {
					rr.Value = append(rr.Value, &dns.SVCBIPv6Hint{Hint: []net.IP{ip}})
				}
				resp.Answer = append(resp.Answer, rr)
			} //if
		} //for
		//itisdoneFIXME: what if none of the above 3 applied? we currently return empty?! unsure if this makes sense or is valid reply?!
		//"According to RFC 2308, if a domain exists (because it's in our hosts2ip.json) but the requested record type doesn't exist for it, the correct response is a NODATA response (an RcodeSuccess with 0 answer records)." - Gemini 3.1 Pro

		upstreamState5 := UpstreamState{Strategy: "etc_hosts"}
		// Cache this override so subsequent queries bypass the pattern loop
		if cfg.LocalHostsOverrideTTLSec > 0 {
			cachee.Set(key, CacheEntry{
				Msg:   resp.Copy(),
				State: upstreamState5,
			}, time.Duration(cfg.LocalHostsOverrideTTLSec)*time.Second)
		}

		s.logQuery(ctx, clientAddr, domain, qtype, localHostOverride, "", extractIPs(resp), resp, upstreamState5)
		return resp
	}
	// --- END Local Hosts Override ---

	// --- Request coalescing (thundering-herd protection) ---
	// A burst of concurrent packets for the same still-uncached domain+qtype
	// (e.g. right after this key's cache entry expires) would otherwise each
	// independently trigger their own upstream DoH request. Coalesce them:
	// only the first ("leader") actually forwards and populates the cache;
	// concurrent followers wait for it to finish and re-check the cache
	// instead of firing a redundant upstream request. See
	// forwardInFlightEntry's doc comment and todonow.txt "Cache Miss
	// Thundering Herd".
	s.forwardInFlightMu.Lock()
	if s.forwardInFlight == nil {
		// Defensive: NewServer always initializes this map, but some tests
		// construct a bare &Server{...} directly, bypassing NewServer.
		s.forwardInFlight = make(map[string]*forwardInFlightEntry)
	}
	if entry, inFlight := s.forwardInFlight[key]; inFlight {
		s.forwardInFlightMu.Unlock()
		<-entry.done
		if cached, ok := cachee.Get(key); ok {
			return s.respondFromCache(ctx, cached, reqMsg, clientAddr, domain, qtype, matchedID)
		}
		// The leader's result wasn't cached (e.g. a blocked/filtered response
		// — see filterResponse's nil-case handling further below, which is
		// intentionally not cached); fall through and forward independently
		// ourselves rather than looping, to avoid ever waiting twice.
	} else {
		leaderEntry := &forwardInFlightEntry{done: make(chan struct{})}
		s.forwardInFlight[key] = leaderEntry
		s.forwardInFlightMu.Unlock()
		defer func() {
			s.forwardInFlightMu.Lock()
			delete(s.forwardInFlight, key)
			s.forwardInFlightMu.Unlock()
			close(leaderEntry.done)
		}()
	}

	// Forward to upstream DNS
	// 1. Save the original client ID
	oldID := reqMsg.Id
	reqMsg.Id = getSecureID() // 2. Generate a random ID for the upstream query (helps prevent cache poisoning)
	// 3. DO THE ACTUAL UPSTREAM QUERY
	resp, upstreamState3 := s.dohForwarder.ForwardToDoH(ctx, reqMsg)
	// 4. Restore the original ID so the client's DNS resolver accepts the answer
	reqMsg.Id = oldID // unconditionally restore so any msg-derived error response carries the right ID
	if resp != nil {
		resp.Id = oldID // Restores the ID for the upstream's response object
	}
	//Gemini 3 Thinking: "The ID Matching is a "defense in depth" move. By using a random ID for the journey to Quad9 and back, you decouple your internal network's IDs from the public internet,
	// making it much harder for someone to inject fake DNS responses into your proxy."

	// if resp == nil || resp.Rcode != dns.RcodeSuccess {
	// 	ips := []string{}
	// 	if resp != nil {
	// 		ips = append(ips, fmt.Sprintf("dns.Rcode:%d", resp.Rcode))
	// 	}
	// 	negResp := servfailResponse(reqMsg)
	// 	s.logQuery(ctx, clientAddr, domain, qtype, forwardedButFailedSoSERVFAIL, matchedID, ips, negResp, upstreamState3)
	// 	// Cache negatives short
	// 	// Store a copy of the negative response as well
	// 	cachee.Set(key, CacheEntry{
	// 		Msg:   negResp.Copy(),
	// 		State: upstreamState3,
	// 	}, time.Duration(cfg.CacheNegativeTTLSec)*time.Second) // time to cache negatives
	// 	return negResp
	// }

	// FIX: Handle complete network failures (resp == nil)
	if resp == nil {
		negResp := servfailResponse(reqMsg)
		s.logQuery(ctx, clientAddr, domain, qtype, forwardedButFailedSoSERVFAIL, matchedID, nil, negResp, upstreamState3)
		if cfg.CacheNegativeTTLSec > 0 {
			cachee.Set(key, CacheEntry{
				Msg:   negResp.Copy(),
				State: upstreamState3,
			}, time.Duration(cfg.CacheNegativeTTLSec)*time.Second)
		}
		return negResp
	}

	// FIX: Handle valid negative responses from upstream (NXDOMAIN, REFUSED, etc.)
	if resp.Rcode != dns.RcodeSuccess {
		ips := []string{fmt.Sprintf("dns.Rcode:%d", resp.Rcode)}
		// Log exactly what the upstream told us
		s.logQuery(ctx, clientAddr, domain, qtype, forwardedGotNegativeResponse, matchedID, ips, resp, upstreamState3)

		// Cache negative responses. RFC 2308 caps negative caching at the
		// authoritative zone's SOA MINIMUM (and the SOA record's own TTL);
		// computeTTLForCaching already derives that cap from the Answer/Ns
		// sections the same way the successful-response cache path below
		// does. Take the min() of that cap and our own configured
		// cache_negative_ttl_sec so a large/misconfigured
		// cache_negative_ttl_sec can never outlive what the zone itself says
		// is safe. The common case — a short, deliberately-conservative
		// cache_negative_ttl_sec default — is unaffected, since it's already
		// far shorter than any real SOA minimum.
		negativeTTL := min(computeTTLForCaching(resp), time.Duration(cfg.CacheNegativeTTLSec)*time.Second)
		if negativeTTL > 0 {
			cachee.Set(key, CacheEntry{
				Msg:   resp.Copy(),
				State: upstreamState3,
			}, negativeTTL)
		}

		return resp
	}

	//ips := extractIPs(resp) //before 'resp' gets mutated, and its IPs deleted.
	// Use a copy of the original upstream response so we can log exactly what they tried to send
	originalCopy := resp.Copy()
	originalIPs := extractIPs(originalCopy)
	// Filter
	filtered, filterReason := filterResponse(log, resp, cfg.RemoveHTTPSIPHints, s.blacklist) // XXX: resp gets mutated here!
	if filtered == nil {
		// filterReason now holds exact info like "blockedByUpstream_ZeroIP" or "dns_rebinding_protection"

		s.logQuery(ctx, clientAddr, domain, qtype,
			filterReason+originalSTR, //blockedByUpstream_ORIGINAL //doneFIXME: this here is a guess because the upstream answer was filtered out likely due to having an IP like 0.0.0.0 returned, but could also be any of the blocked IPs specified in the config like 127.0.0.1/8 or 192.168.0.0/16 therefore this could mean the upstream tried to return a local or LAN IP but we stripped it out and we should notify accordingly! not just say that upstream blocked the hostname request which it only does if IP was 0.0.0.0 and nothing else.
			matchedID, originalIPs, originalCopy, upstreamState3)
		blocked := s.blockResponse(reqMsg)
		blockedIPs := extractIPs(blocked)
		s.logQuery(ctx, clientAddr, domain, qtype,
			filterReason+returnedModifiedSTR, //doneFIXME: this here is a guess because the upstream answer was filtered out likely due to having an IP like 0.0.0.0 returned, but could also be any of the blocked IPs specified in the config like 127.0.0.1/8 or 192.168.0.0/16 therefore this could mean the upstream tried to return a local or LAN IP but we stripped it out and we should notify accordingly! not just say that upstream blocked the hostname request which it only does if IP was 0.0.0.0 and nothing else.
			matchedID, blockedIPs, blocked, upstreamState3)

		//The Bug: You return blocked directly to the client, but you never cache it.
		//Because it isn't cached, the forwardInFlight leader finishes, unlocks the followers, and the followers check the cache. They miss the cache, and all of them instantly hammer the upstream resolver again. If a malicious script aggressively queries a domain that resolves to a blacklisted IP, it will bypass your cache entirely and DoS your upstream provider.
		//The Fix: Cache the blocked response using your cfg.BlockedResponseTTLSec or cfg.CacheNegativeTTLSec before returning it:
		if cfg.BlockedResponseTTLSec > 0 { // Or whatever negative TTL applies
			cachee.Set(key, CacheEntry{
				Msg:   blocked.Copy(),
				State: upstreamState3,
			}, time.Duration(cfg.BlockedResponseTTLSec)*time.Second)
		}
		return blocked
	}

	// Cache with clamped TTL
	expiry := max(computeTTLForCaching(filtered), time.Duration(cfg.CacheMinTTL)*time.Second)

	// Store a copy in the cache, not the pointer you are about to return
	// Cache with clamped TTL
	if expiry > 0 {
		cachee.Set(key, CacheEntry{
			Msg:   filtered.Copy(),
			State: upstreamState3,
		}, expiry)
	}

	ips := extractIPs(filtered)
	s.logQuery(ctx, clientAddr, domain, qtype, forwardedSTR, matchedID, ips, filtered, upstreamState3)

	return filtered
}

const unknownExePlaceHolder string = "<unknown_exe>"
const unknownExePlaceHolderForURL string = "unknown-process"

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
	// if minTTL < cacheMinTTLClamp { //XXX: hardcoded minimum aka floor of 10 seconds TTL
	// 	minTTL = cacheMinTTLClamp
	// }
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
					if t, err := time.Parse(TimeStampsFormat /*time.RFC3339*/, setting.Value); err == nil {
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
	Strategy string `json:"strategy"`
	// UpstreamUsed and FailedUpstreams hold the fully-resolved URL(s) actually sent on the
	// wire for this query (with any {builtin:clientexe} placeholder already substituted),
	// not the raw, still-templated upstream_urls config entry.
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

// classifyRetryableDoHError reports whether err is one of the network-level
// failure modes doSingleDoHRequest treats as transient/retryable, and if so,
// a short machine-readable reason string for structured logging. This exists
// because the raw error text alone (wincoe.SafeErr(err)) can look identical
// for causes with very different remediation: a request that hit its own
// upstream_client_timeout_sec budget (context.DeadlineExceeded) reads the
// same at a glance as a genuinely slow/unreachable upstream reported as a
// plain OS-level network timeout, even though the fix differs (raise the
// configured timeout vs. investigate the upstream/network path). Logging the
// specific classification alongside the error removes that ambiguity without
// having to parse error strings by hand.
func classifyRetryableDoHError(err error) (reason string, retryable bool) {
	if err == nil {
		panic2("BUG: unexpected err arg is nil")
	}
	switch {
	case errors.Is(err, io.EOF):
		return "eof", true
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected_eof", true
	case errors.Is(err, syscall.ECONNRESET):
		// Since we're Windows-only, syscall.ECONNRESET is actually mapped to
		// the Windows-specific WSAECONNRESET code internally by the Go net
		// package, so errors.Is works correctly here.
		return "econnreset", true
	case errors.Is(err, syscall.ECONNREFUSED):
		return "econnrefused", true
	default:
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			if errors.Is(err, context.DeadlineExceeded) {
				// The request's own context (bounded by
				// Upstream.UpstreamClientTimeoutDuration, see below) expired
				// before the upstream answered — a configured-timeout issue,
				// not necessarily a dead/unreachable upstream.
				return "context_deadline_exceeded", true
			}
			// A lower-level OS/network timeout (e.g. TCP dial or read/write
			// deadline) rather than our own context budget expiring.
			return "network_timeout", true
		}
		return "", false
	}
}

// maxUpstreamDoHResponseBytes bounds how many bytes doSingleDoHRequest will
// ever read from a single upstream DoH HTTP response body. Real DNS response
// messages (even generous ones with many DNSSEC signatures) are dwarfed by
// this; it exists purely as a defensive backstop against a compromised or
// badly misconfigured upstream returning a multi-gigabyte payload, which
// would otherwise force io.ReadAll to buffer the entire thing in memory and
// could exhaust available RAM well before this proxy ever got a chance to
// reject it as malformed.
const maxUpstreamDoHResponseBytes = 4 * 1024 * 1024 // 4 MiB

// clientMetadataLookupTimeout bounds how long doSingleDoHRequest will wait for
// startMetadataLookup's client PID/exe resolution to finish when a
// {builtin:clientexe} upstream URL template needs the real value. The
// underlying Win32 APIs (PidAndExeForUDP/PidAndExeForTCP) accept no context
// and cannot be cancelled, so an OS-level hang there would otherwise stall
// this DNS query indefinitely; see todonow.txt "Uncancellable Goroutine Leak
// in Metadata Lookup".
const clientMetadataLookupTimeout = 2 * time.Second

// doSingleDoHRequest performs one upstream DoH HTTP round trip (with its own bounded
// retry loop), returning the parsed DNS response, the fully-resolved request URL that
// was actually used on the wire (with any {builtin:clientexe} placeholder already
// substituted), and an error. The resolved URL is always populated, even on failure,
// since it's computed before the request is ever sent.
func (u *Upstream) doSingleDoHRequest(ctx context.Context, reqBytes []byte) (*dns.Msg, string, error) {
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
	var cancelCurrentReq func()     // Track the active context cancel function across scopes
	var resolvedTargetURLStr string // the exact URL used on the wire for this attempt (post {builtin:clientexe} substitution)

	//for attempt := range maxTries { // starts from 0 !
	for attempt := 1; attempt <= maxTries; attempt++ {
		// Use an anonymous function wrapper so 'defer' operates on a per-iteration scope
		failedToCreateRequest, errReq := func() (bool, error) {
			// 1. Resolve the target URL BEFORE starting the per-request timeout clock
			// below, so a (normally fast, but not instant) client-metadata lookup —
			// only relevant when {builtin:clientexe} is configured — never eats into
			// the actual network-operation timeout budget.
			// create request with supplied context so caller controls deadline/cancel
			targetURLStr := u.URL.String()
			// (the {builtin:clientexe} substitution block that follows stays exactly
			// as fixed above, unchanged, still reading the outer ctx not reqCtx)
			// 1. Pass the merged context to the HTTP request
			// Check if the user configured either variant of the placeholder in their upstream URL
			if strings.Contains(targetURLStr, templateClientExe) || strings.Contains(targetURLStr, templateClientExeEscaped) {
				var exeName string = unknownExePlaceHolderForURL //"unknown-process"

				// Extract the metadata from the context. startMetadataLookup always
				// stores a *ClientMetadataFuture (never a bare clientMetadata value),
				// since the real pid/exe/service lookup runs concurrently in its own
				// goroutine and may still be in flight here. Asserting the wrong
				// (non-pointer) type silently failed every single time, which is why
				// {builtin:clientexe} always substituted "unknown-process" no matter
				// how fast the real lookup completed elsewhere (e.g. by the time
				// logQuery ran, which asserts the correct type and does show the
				// real exe name).
				if future, ok := ctx.Value(clientInfoKey{}).(*ClientMetadataFuture); ok {
					//XXX: caveat so when using {builtin:clientexe} int he upstream url, the network request waits/depends on Windows API to resolve the pid->exe mapping of the client which issues the request before starting the DNS query (network request)
					// Bounded wait: the underlying Win32 PID/exe lookup has no
					// cancellation support, so a hung OS call could otherwise
					// stall this DNS query forever. Cap the wait and fall
					// back to the placeholder name if it doesn't finish in
					// time.
					select {
					case <-future.done:
					case <-time.After(clientMetadataLookupTimeout):
						log.Warn("timed out waiting for client pid/exe metadata lookup; using placeholder exe name for {builtin:clientexe}",
							slog.Duration("timeout", clientMetadataLookupTimeout))
					}
					if future.info.exe != "" {
						//// Optionally strip the .exe extension for cleaner NextDNS logs
						//exeName = strings.TrimSuffix(future.info.exe, ".exe")
						exeName = future.info.exe

						// URL-encode the executable name to prevent malformed requests
						exeName = url.PathEscape(exeName)
					}
				} else {
					log.Warn("BUG: Failed to get future metadata from the context in doSingleDoHRequest(), did the type change again?!")
				}

				// Inject the executable name by replacing both potential string variations
				targetURLStr = strings.ReplaceAll(targetURLStr, templateClientExe, exeName)
				targetURLStr = strings.ReplaceAll(targetURLStr, templateClientExeEscaped, exeName)
			}

			resolvedTargetURLStr = targetURLStr

			// 2. Create a transient request context derived from the client's ctx
			// reqCtx, cancelReq := context.WithCancel(ctx)
			//NOTTRUEXXX: when the upstream IP is set to Deny in portmaster firewall after it worked before, without this context.WithTimeout it will hang forever until Ctrl+C cancels context then you see all the logs that show it was stuck. This is the only way.
			// 3. Derive a timed-out context from your incoming request context (reqCtx)
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

			// Build the request using the dynamically generated URL
			var e error
			// G704 (gosec SSRF via taint analysis) fires because targetURLStr isn't a literal.
			// It's safe: parseAndValidateUpstreams already restricts every configured upstream to
			// the https scheme with an IP-literal host before any Upstream value is ever
			// constructed (see UpstreamManager.buildSet), and the only dynamic substitution done
			// above ({builtin:clientexe}) only ever touches the path/query, never the scheme or
			// host, so this can never be redirected toward an unintended destination.
			req, e = http.NewRequestWithContext(reqCtx, http.MethodPost /*"POST"*/, targetURLStr, bytes.NewReader(reqBytes)) //nolint:gosec // G704: see comment above, host is a validated IP literal
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
			} else if resp != nil {
				// net/http's Client.Do can, in rare cases (certain redirect-
				// policy failures or HTTP/2 stream errors), return BOTH a
				// non-nil Response and a non-nil error. Every error path
				// below discards resp entirely, so close its body now —
				// otherwise the underlying connection/socket leaks.
				if closeErr := resp.Body.Close(); closeErr != nil {
					log2.Debug("failed to close stray response body on doSingleDoHRequest error path", wincoe.SafeErr(closeErr))
				}
				resp = nil
			}
			return false, nil
		}() //so it's called here!

		// If NewRequestWithContext failed, abort immediately just like the original logic
		if failedToCreateRequest {
			return nil, resolvedTargetURLStr, errReq
		}

		// If client.Do succeeded, we can stop retrying
		if err4ClientDo == nil { //XXX: if you change or move this, the logic below changes drastically! be careful
			//success!
			break
		}

		//so we're here because the request error-ed

		// decide if error is transient/retryable
		// common retryable errors: temporary network errors, EOF, connection reset
		retryReason, isRetryable := classifyRetryableDoHError(err4ClientDo)

		if isRetryable {
			log.Error("doh_post_transient_error for this query", wincoe.SafeErr(err4ClientDo),
				slog.String("retry_reason", retryReason),
				slog.Int("current_try", attempt), slog.Int("max_tries", maxTries),
				//slog.Any("query", req),
				SafeRequestAttr("query", req),
				slog.Bool("will_retry", attempt < maxTries))

			// 🔴 FIX #1: If this was the last attempt, return the REAL error immediately!
			// This prevents falling through to the bottom of the function.
			if attempt >= maxTries {
				return nil, resolvedTargetURLStr, fmt.Errorf("exhausted %d/%d tries to upstream DoH, last request's err: %w", attempt, maxTries, err4ClientDo /*non-nil here*/)
			}
			if u.RetryBackoffDuration <= 0 {
				u.RetryBackoffDuration = time.Duration(100) * time.Millisecond
				log.Warn("BUG: retry backoff timer is set to <= 0 , preventing hang by using 100ms", slog.Duration("retrybackoff_duration", u.RetryBackoffDuration))
			} else if u.RetryBackoffDuration >= time.Duration(5)*time.Second {
				log.Warn("RetryBackoffDuration is >= 5 sec", slog.Duration("retrybackoff_duration", u.RetryBackoffDuration))
			}
			// small backoff: sleep a bit but respect context
			timer := time.NewTimer(u.RetryBackoffDuration)
			select {
			case <-timer.C:
				log.Debug("Retrying after backoff", SafeRequestAttr("query", req), slog.Duration("retrybackoff_duration", u.RetryBackoffDuration))
				//exits select
			case <-ctx.Done():
				timer.Stop()
				log.Debug("doh sensed client quit during retry backoff...")
				return nil, resolvedTargetURLStr, fmt.Errorf("doh sensed client quit during retry backoff... ctx.err: %w", ctx.Err() /*non-nil guaranteed*/)
			case <-u.BackgroundCtx.Done():
				timer.Stop()
				log.Debug("doh sensed quit during retry backoff...")
				return nil, resolvedTargetURLStr, fmt.Errorf("doh sensed quit during retry backoff... bkgctx.err: %w", u.BackgroundCtx.Err() /*non-nil guaranteed*/)
			}
			continue //next try
		} //if
		// non-retryable error
		// --- NEW DIAGNOSTIC BLOCK ---
		if strings.Contains(err4ClientDo.Error(), "tls:") || strings.Contains(err4ClientDo.Error(), "x509:") {
			log.Error("TLS verification failed when tried to query upstream DNS server",
				slog.String("url", resolvedTargetURLStr),
				slog.String("sni_used", u.SNI),
				wincoe.SafeErr(err4ClientDo))

			// Run a manual probe to see what the server is actually sending
			u.logCertDetails() //targetURL.Hostname(), targetURL.Port(), sni)
		} else {
			log.Error("Failed to query upstream DNS server",
				slog.String("url", resolvedTargetURLStr),
				slog.String("sni_used", u.SNI),
				wincoe.SafeErr(err4ClientDo))
		}
		// --- END DIAGNOSTIC BLOCK ---
		return nil, resolvedTargetURLStr, fmt.Errorf("failed to send the HTTP request to the upstream DoH server %q, err: %w", resolvedTargetURLStr, err4ClientDo /*non-nil here*/)
	} //for retries

	// --- THE CODE BELOW ONLY EXECUTES ON SUCCESSFUL BREAK ---

	// ✅ Ensure the active context gets cancelled when the outer function returns
	if cancelCurrentReq != nil {
		defer cancelCurrentReq()
	}

	if resp == nil {
		// last attempt produced no response (shouldn't happen), treat as failure
		log.Error("doh_no_response")
		return nil, resolvedTargetURLStr, errors.New("no response")
	} else {
		defer resp.Body.Close() //nolint:errcheck // best-effort close, nothing to do on error
	}

	// ✅ This will now execute perfectly! The context is guaranteed to stay alive here.
	// Cap how much we'll ever read from a single upstream response: see
	// maxUpstreamDoHResponseBytes's doc comment for why this exists as a
	// defensive backstop against a compromised/misconfigured upstream.
	limitedBody := io.LimitReader(resp.Body, maxUpstreamDoHResponseBytes+1)
	body, err4ReadAll := io.ReadAll(limitedBody)
	if err4ReadAll != nil {
		log.Error("doh_readbody_failed", wincoe.SafeErr(err4ReadAll))
		return nil, resolvedTargetURLStr, fmt.Errorf("failed to read upstream DoH response body: %w", err4ReadAll /*non-nil here*/)
	}
	if len(body) > maxUpstreamDoHResponseBytes {
		log.Error("doh_upstream_response_too_large",
			slog.Int("body_len", len(body)),
			slog.Int("max_allowed_bytes", maxUpstreamDoHResponseBytes))
		return nil, resolvedTargetURLStr, fmt.Errorf("upstream DoH response body exceeded maximum allowed size of %d bytes", maxUpstreamDoHResponseBytes)
	}

	// debug/log non-200 or unexpected content-type
	if resp.StatusCode != 200 {
		log.Error("doh_upstream_status", slog.String("status", resp.Status))
		return nil, resolvedTargetURLStr, fmt.Errorf("upstream status %s", resp.Status)
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
		return nil, resolvedTargetURLStr, fmt.Errorf("failed to unpack response body for upstream DoH %q, err: %w", resolvedTargetURLStr, err4Unpack /*non-nil here*/)
	}
	return upMsg, resolvedTargetURLStr, nil
}

func (u *Upstream) logCertDetails() { //(ip, port, sni string) {
	log := u.getLogger()

	port := u.URL.Port()
	if port == "" {
		//TODO: replace all panics with logFatal() ? or maybe not, gotta think more about this, for one logFatail isn't as obvious that it panics.
		panic2("BUG: dev fail: port is empty but shoulda been set in validateUpstream() to 443")
	}
	addr := net.JoinHostPort(u.URL.Hostname(), port)

	dialer := &net.Dialer{Timeout: secondsToDuration(u.CertLogTimeoutSec)}
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
	// EDNS0(OPT) presence must match too: one upstream echoing back an OPT
	// pseudo-record while another omits it entirely means the two responses
	// are not actually identical on the wire, even if their Answer sections
	// happen to match byte-for-byte. Strict mode exists to catch exactly this
	// kind of subtle inconsistency between upstreams.
	if (a.IsEdns0() != nil) != (b.IsEdns0() != nil) {
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

func (s *Server) blockResponse(reqMsg *dns.Msg) *dns.Msg {
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
	if cfg.BlockAAAAasEmptyNoError && len(reqMsg.Question) > 0 && reqMsg.Question[0].Qtype == dns.TypeAAAA &&
		cfg.BlockMode == blockModeNXDOMAIN {
		//(cfg.BlockMode == blockModeNXDOMAIN || cfg.BlockMode == blockModeDrop) {//commented out for "drop" because: "Use NXDOMAIN for fast fallback; Drop accepts timeout penalty for true stealth."
		resp := new(dns.Msg)
		resp.SetReply(reqMsg)
		resp.Rcode = dns.RcodeSuccess
		resp.Answer = []dns.RR{}
		resp.Ns = []dns.RR{}
		resp.Extra = []dns.RR{}
		resp.Authoritative = true
		resp.RecursionAvailable = true
		// short TTL negative AAAA response is effectively encoded by empty answer; caching handled by caller
		return resp
	}

	// Build the response as a fresh dns.Msg derived from reqMsg via SetReply
	// (mirrors servfailResponse/formerrResponse), rather than mutating reqMsg
	// itself and returning it: reqMsg is the caller's own query object, and
	// blockResponse must never alias the two together.
	resp := new(dns.Msg)
	resp.SetReply(reqMsg)

	//in Go, implicit 'break' after each 'case'
	switch cfg.BlockMode { //XXX: it's already lowercased!
	case blockModeNXDOMAIN:
		resp.SetRcode(resp, dns.RcodeNameError) // this is NXDOMAIN
	case blockModeIPBlock: //, "block_ip", "ipblock", "blockip":
		ttl := cfg.BlockedResponseTTLSec
		qtype := resp.Question[0].Qtype
		switch qtype {
		case dns.TypeA:
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: resp.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
			// Clone rather than alias cfg.BlockIPv4Parsed: that slice is shared across every
			// blocked query until the next Reload(). Assigning it directly would let any future
			// code that mutates rr.A's bytes in place (rather than replacing the slice) silently
			// corrupt the shared config value for every subsequent blocked response.
			rr.A = append(net.IP(nil), cfg.BlockIPv4Parsed...)
			resp.Answer = []dns.RR{rr}
			resp.SetRcode(resp, dns.RcodeSuccess)
		case dns.TypeAAAA:
			rr := new(dns.AAAA)
			rr.Hdr = dns.RR_Header{Name: resp.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
			// See the rr.A clone comment in the TypeA case above — identical aliasing hazard.
			rr.AAAA = append(net.IP(nil), cfg.BlockIPv6Parsed...)
			resp.Answer = []dns.RR{rr}
			resp.SetRcode(resp, dns.RcodeSuccess)
		default:
			// non A or AAAA during this BlockMode?
			/*
				According to the DNS specifications (RFC 2308), if a domain name exists (i.e., it has an A or AAAA record), a query for any other record type on that same name (like TXT, MX, or SRV) must return NOERROR with an empty answer section (known as a NODATA response).
				If you return NXDOMAIN (Name Error) for a TXT query on a domain where you just returned an IP address for an A query, downstream caching servers or the Windows dnscache service will cache that the entire domain does not exist. This will break your blocking mechanism or cause intermittent resolution failures.
			*/
			// For MX, TXT, etc., return an explicit NODATA response
			// (Success with 0 answers) because the domain "exists" in our ip_block view.
			resp.Answer = []dns.RR{}
			resp.SetRcode(resp, dns.RcodeSuccess)
		}

	case blockModeDrop:
		return nil
	default:
		panic2(fmt.Sprintf("BUG: validated BlockMode reached impossible value, %q", cfg.BlockMode))
	}

	resp.Authoritative = true
	resp.RecursionAvailable = true

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
	if clientOpt := reqMsg.IsEdns0(); clientOpt != nil {
		if clientOpt.UDPSize() < ourMax {
			ourMax = clientOpt.UDPSize() // Respect the client's smaller limit
		}
	}

	// 3. Set the advertised size
	opt.SetUDPSize(ourMax)
	// 1232 is the "EDNS0 Flag Day" recommended value
	// It prevents IP fragmentation on modern networks
	//opt.SetUDPSize(1232) // Safer modern size, affects only current response. "What it actually does: When a client sends a query, it often includes its own OPT record saying "I can accept up to X bytes." By responding with SetUDPSize(1232), you are saying "I am sending this reply, and I'm letting you know my maximum limit is 1232."", "Future Queries: It does not bind future queries to that size. Each request/response pair is independent."

	// Only allocate memory for the EDE option if the feature is actually enabled.
	// Note: we deliberately never call opt.SetDo() here. The DO ("DNSSEC OK") bit
	// only signals that the sender wants/accepts DNSSEC data; it has no bearing on
	// whether a client parses the OPT pseudo-record at all (that's controlled purely
	// by the OPT record's presence, independent of any flag inside it). Setting DO
	// on a reply we never validated or forwarded any DNSSEC data for would be
	// misleading, and the old "some browsers require this to process OPT records"
	// justification for setting it is folklore, not accurate.
	if cfg.UseEDEInBlockedReply {
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
	resp.Extra = append(resp.Extra, opt)

	return resp
}

const NODATA string = "upstream_nodata"
const BlockedZeroIP string = "blocked_ZeroIP"
const BlockedBlacklistedIP string = "blocked_blacklisted_ip"
const StrippedRRSIG string = "stripped_rrsig"

const BlockedByUpstream string = "blockedByUpstream_ZeroIP"

// mutates the passed arg
func filterResponse(log *slog.Logger, respMsg *dns.Msg, removeHTTPSIPHints bool, blacklist IPChecker) (*dns.Msg, string) {
	//log := s.getLogger()

	if respMsg == nil {
		panic2("BUG: msg was nil, unexpected bad programming/code ;p")
	}
	if len(respMsg.Question) == 0 {
		panic2("BUG: no DNS question! unexpected bad programming/code ;p")
	}

	q := respMsg.Question[0]
	qtype := dns.TypeToString[q.Qtype] // Map lookup

	// If upstream naturally returned NOERROR with 0 answers (NODATA), let it through!
	if len(respMsg.Answer) == 0 && len(respMsg.Ns) == 0 && len(respMsg.Extra) == 0 {
		return respMsg, NODATA
	}

	var dropReasons []string

	// Define a local closure to process any arbitrary DNS section
	filterSection := func(records []dns.RR, sectionName string) []dns.RR {
		var good []dns.RR
		for _, rr := range records {
			if keep, modifiedRR, reason := processRR(log, rr, removeHTTPSIPHints, blacklist); keep {
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
	respMsg.Answer = filterSection(respMsg.Answer, "inAnswer")
	respMsg.Ns = filterSection(respMsg.Ns, "inNs")
	respMsg.Extra = filterSection(respMsg.Extra, "inExtra")

	//if len(msg.Answer) == 0 { // this dropped HTTPS replies and they were thus not seen at all, so seen as blockedbyUpstream
	if len(respMsg.Answer) == 0 && len(respMsg.Ns) == 0 && len(respMsg.Extra) == 0 {
		domain := strings.ToLower(strings.TrimSuffix(q.Name, "."))
		displayDomain, wasIDN := punycodeDecodePatternForDisplay(domain)

		attrs := []any{
			slog.String("query_type", qtype),
			slog.String("domain", domain),
			SafeStringSlice("drop_reasons", dropReasons),
		}
		if wasIDN {
			attrs = append(attrs, slog.String("domain_idn", displayDomain))
		}
		log.Warn("response_filtered_all", attrs...)

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
	return respMsg, ""
}

// httpsHintIPs returns the IP list carried by an SVCBIPv4Hint or SVCBIPv6Hint
// HTTPS/SVCB parameter, and whether param was actually one of those two
// types. Used by processRR to apply response-blacklist filtering to hint IPs
// even when remove_https_ip_hints is false (hints aren't unconditionally
// stripped in that case, so a blacklisted IP embedded in one must still be
// caught the same way a plain A/AAAA record would be).
func httpsHintIPs(param dns.SVCBKeyValue) ([]net.IP, bool) {
	switch h := param.(type) {
	case *dns.SVCBIPv4Hint:
		return h.Hint, true
	case *dns.SVCBIPv6Hint:
		return h.Hint, true
	default:
		return nil, false
	}
}

// containsBlacklistedIP reports whether any IP in ips matches blacklist.
func containsBlacklistedIP(ips []net.IP, blacklist IPChecker) bool {
	for _, ip := range ips {
		if blacklist.Contains(ip) {
			return true
		}
	}
	return false
}

// filters out unwanteds like the IPs that are returned or ip hints in HTTPS dns types.
// mutates the passed arg!
func processRR(log *slog.Logger, rr dns.RR, removeHTTPSIPHints bool, blacklist IPChecker) (bool, dns.RR, string) {
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
		// 1. Defend against a typed nil pointer passing through the interface type-switch
		if r == nil {
			panic2("BUG: what? r is nil in switch r := rr.(type)  where rr is of type dns.RR interface")
		}

		// 2. Defend against a nil RR Header while fetching the queried domain name
		var domain string
		if header := r.Header(); header != nil {
			domain = header.Name
		}

		// Filter the SVCB/HTTPS parameters. Two independent reasons a hint
		// parameter can be dropped here:
		//   1. remove_https_ip_hints unconditionally strips every ipv4hint/
		//      ipv6hint (Keys 4/6), forcing IP lookup via A/AAAA instead.
		//   2. Regardless of that setting, a hint embedding an IP that's on
		//      the response blacklist must never bypass filtering just
		//      because it's carried inside an HTTPS/SVCB record instead of a
		//      plain A/AAAA record — the same BlockedBlacklistedIP invariant
		//      already enforced for ordinary answers above.
		newParams := make([]dns.SVCBKeyValue, 0, len(r.Value))
		for _, param := range r.Value {
			k := param.Key()

			//doneTODO: make this configurable in config.json so only if 'true' do this:
			if removeHTTPSIPHints && (k == dns.SVCB_IPV4HINT || k == dns.SVCB_IPV6HINT) {
				displayDomain, wasIDN := punycodeDecodePatternForDisplay(domain)
				attrs := []any{
					slog.String("domain", domain),   // if domain is "claude.ai."
					slog.String("target", r.Target), // then target is "." here
					slog.String("param", param.String() /*non nil*/),
					slog.String("config_filename", configFileName),
					slog.String("config_key_name", getJSONTagByOffset(unsafe.Offsetof(Config{}.RemoveHTTPSIPHints))),
				}
				if wasIDN {
					attrs = append(attrs, slog.String("domain_idn", displayDomain))
				}
				log.Warn("Dropping IP hint from the HTTPS reply", attrs...)
				continue
			}

			if hintIPs, isHint := httpsHintIPs(param); isHint && containsBlacklistedIP(hintIPs, blacklist) {
				displayDomain, wasIDN := punycodeDecodePatternForDisplay(domain)
				attrs := []any{
					slog.String("domain", domain),
					slog.String("target", r.Target),
					slog.String("param", param.String() /*non nil*/),
				}
				if wasIDN {
					attrs = append(attrs, slog.String("domain_idn", displayDomain))
				}
				log.Warn("Dropping HTTPS IP hint containing a blacklisted IP", attrs...)
				continue
			}

			newParams = append(newParams, param)
		}
		r.Value = newParams
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

// adjustResponseCaseToQuery rewrites the Question section and the owner name
// of every Answer- and Ns-section RR that matches the query case-insensitively
// so it echoes the exact case the client queried with.
//
// This exists because the DNS cache is intentionally keyed by the
// lowercased domain (see handleDNSQuery's "key := domain + ..." line), so a
// single cache entry is shared across every casing variant of the same
// query instead of paying for one cache entry per casing variant. That
// means a cached Msg's Answer/Ns owner names still carry whichever client's
// casing first populated the entry, even after the Question section is
// rewritten to the current query's casing. Some strict or 0x20-aware
// clients expect the owner name(s) that directly answer the query to echo
// the same case as the question, so this fixes that up at serve time
// instead of keying the cache by exact case.
//
// Only records whose owner name equals queryName case-insensitively are
// touched, which deliberately leaves CNAME-chain target records alone: once
// a chain like "left.example CNAME right.example" is followed, the next
// record's owner name ("right.example") is a distinct name from the
// original query with no defined casing relationship to it.
func adjustResponseCaseToQuery(msg, reqMsg *dns.Msg) {
	if msg == nil || reqMsg == nil || len(reqMsg.Question) == 0 {
		return
	}

	queryName := reqMsg.Question[0].Name

	// Preserve ORIGINAL client casing in Question section (critical for strict clients)
	// "Question is the main RFC requirement. Most clients only care about Question."
	if len(msg.Question) > 0 {
		msg.Question[0].Name = queryName // echo exact client casing
	}

	fixSection := func(rrs []dns.RR) {
		for _, rr := range rrs {
			hdr := rr.Header()
			if hdr == nil {
				continue
			}
			if hdr.Name != queryName && strings.EqualFold(hdr.Name, queryName) {
				hdr.Name = queryName
			}
		}
	}
	fixSection(msg.Answer)
	fixSection(msg.Ns)
	//The Bug: You missed the Extra (Additional) section. If the upstream provider returns an A/AAAA glue record or an EDNS0 OPT record in the Extra section that happens to match the query name, its casing will not be adjusted. Extremely strict 0x20-aware stub resolvers might reject the packet if the casing in the Extra section mismaths the Question section.
	//The Fix: Add fixSection(msg.Extra) for completeness.
	fixSection(msg.Extra)
}

const originalSTR string = "_ORIGINAL"
const returnedModifiedSTR string = "_RETURNEDMODIFIED"
const forwardedButFailedSoSERVFAIL string = "forwarded_but_FAILED_so_SERVFAIL"
const forwardedGotNegativeResponse string = "forwarded_negative_response"
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
	BlockedBlacklistedIP + originalSTR: "\x1b[91m", // Bright Red
	BlockedBlacklistedIP + returnedModifiedSTR: "\x1b[91m", // Bright Red
	BlockedByUpstream + originalSTR:            "\x1b[91m", // Bright Red
	BlockedByUpstream + returnedModifiedSTR:    "\x1b[91m", // Bright Red
	forwardedButFailedSoSERVFAIL:               "\x1b[91m", // Bright Red
	forwardedGotNegativeResponse:               "\x1b[91m", // Bright Red
	localHostOverride:                          "\x1b[96m", // Bright Cyan
	queryBlockedLocalSTR:                       "\x1b[81m", // Bright Red
	queryBlockedExternalSTR:                    "\x1b[81m", // Bright Red
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
	// 1. Force zero-padded timestamp (7 decimal places for Windows precision)
	if a.Key == slog.TimeKey && len(groups) == 0 {
		t := a.Value.Time()
		formattedTime := t.Format(TimeStampsFormat) //"2006-01-02T15:04:05.0000000Z07:00")
		return slog.String(slog.TimeKey, formattedTime)
	}

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

// formatSimpleQueryLogLine renders a single line for the plain-text
// simple-queries log (Config.LogQueriesSimpleFile): "<RFC3339Nano timestamp>
// <type> <domain> <action> <ips>". ips is rendered via %v to match Go's
// default slice formatting (e.g. "[1.2.3.4]", or "[]" when empty),
// deliberately kept dead simple for fast human scanning, unlike the
// structured JSON log_queries file which carries far more detail (exe,
// protocol, rule ID, timing, etc.) under the same timestamp.
func formatSimpleQueryLogLine(ts time.Time, typ, domain, action string, ips []string) string {
	// return fmt.Sprintf("%s %s %s %s %v\n", ts.Format(time.RFC3339Nano), typ, domain, action, ips)//The jagged alignment happens because Go's built-in time.RFC3339Nano format uses .999999999 for fractional seconds under the hood. In Go's time formatting rules, 9s mean "omit trailing zeroes," which results in a variable-length string depending on the exact nanosecond.

	// Replaced time.RFC3339Nano with a custom format using .000000000
	// to force fixed-width trailing zeroes for perfect column alignment.
	return fmt.Sprintf("%s %s %s %s %v\n", ts.Format(TimeStampsFormat /*"2006-01-02T15:04:05.000000000Z07:00"*/), typ, domain, action, ips)
}

const TimeStampsFormat string = "2006-01-02T15:04:05.0000000Z07:00" //old: "2006-01-02 15:04:05.000000000-07:00 MST" // older: /*time.RFC3339*/

func (s *Server) logQuery(ctx context.Context, client, domain, typ, action, ruleID string, ips []string, respMsg *dns.Msg, upstreamState2 UpstreamState) {
	log := s.getLogger()

	if ctx == nil {
		log.Error("BUG: bad coding: logQuery called with nil context", // should never happen
			slog.String("client", client),
			slog.String("domain", domain))
		return
	}

	// Captured once, then formatted twice below in two different layouts
	// (TimeStampsFormat for the JSON logs, RFC3339Nano for the plain-text
	// simple-queries log) so both logs record the identical instant even
	// though they display it differently.
	now := time.Now()
	ts := now.Format(TimeStampsFormat)

	// domain arrives already in wire format (ASCII/punycode for IDNs, since
	// that's what real DNS queries always contain). Show the human-readable
	// Unicode form as the primary "domain" log field to match what the WebUI
	// displays, and only add "domain_punycode" when the two actually differ
	// (i.e. this really is an IDN domain) — a plain ASCII domain has nothing
	// extra worth logging twice.
	displayDomain, domainIsIDN := punycodeDecodePatternForDisplay(domain)

	var respMsgStr string
	if respMsg != nil { //XXX: must do it here, else it will race!
		respMsgStr = respMsg.String()
	}

	// Fire and forget logging so the DNS response isn't delayed
	s.GoSafe(func() {
		// Re-fetch the live logger here, at the moment this goroutine actually
		// runs, rather than reusing the one captured above when logQuery was
		// called synchronously. A config Reload can swap in a new logger (and
		// close the old one's async log writer) at any point between when this
		// goroutine is spawned and when it actually gets scheduled/executes;
		// logging through the stale, since-closed logger silently drops the
		// line and prints a "log was closed" warning instead.
		log := s.getLogger()
		var attrs []any = []any{
			slog.String("domain", displayDomain),
			slog.String("type", typ),
			slog.String("action", action),
		}
		if domainIsIDN {
			attrs = append(attrs, slog.String("domain_punycode", domain))
		}

		if future, ok := ctx.Value(clientInfoKey{}).(*ClientMetadataFuture); ok {
			var exeName string = unknownExePlaceHolder
			// future.wg.Wait()//so this blocks forever, in theory, do I need to FIXME ? yea
			select {
			case <-future.done:
				// Lookups completed normally
				// log with metadata
				if future.info.exe != "" {
					exeName = future.info.exe
				}
			case <-s.ctx.Done():
				// server is shutting down, abort the wait
				log.Warn("Not waiting for an exe to be resolved due to server is shutting down, but will still log the query below")
				//return
			case <-time.After(clientMetadataLookupTimeout):
				// The OS API hung. Abort to prevent a permanent goroutine memory leak.
				log.Warn("timed out waiting for client pid/exe metadata lookup for logging",
					slog.String("client", client), slog.Duration("timeout", clientMetadataLookupTimeout))
				// exeName remains its default fallback (e.g., "<unknown_exe>")
			}
			//if info, ok := ctx.Value(clientInfoKey{}).(clientMetadata); ok {
			info := future.info
			elapsed := time.Since(info.startTime)
			attrs = append(attrs,
				slog.String("exe", exeName))
			//To avoid cluttering the console, at least.
			numServices := len(info.services)
			if numServices != 0 {
				attrs = append(attrs,
					SafeStringSlice("services", info.services),
					slog.Int("num_services", numServices),
				)
			}
			attrs = append(attrs,
				slog.String("proto", info.protocol),
				SafeAddr("clientAddr", info.clientAddr),
				slog.Uint64("pid", uint64(info.pid)),
			)
			if info.err != nil {
				attrs = append(attrs,
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

		if respMsgStr != "" {
			// NOTE: despite the historical field name this used, respMsgStr is
			// populated for every logged query action (cache hits, successful
			// forwards, etc.), not only blocked ones — it's set above whenever
			// respMsg != nil, which is true for essentially every action except
			// BlockMode "drop". Use a name that reflects that.
			attrs = append(attrs, slog.String("dns_response", respMsgStr))
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

		// Also append a single plain-text line to the simple-queries log
		// (see Config.LogQueriesSimpleFile) — deliberately NOT routed
		// through slog/JSON, for fast human scanning. Cross-reference the
		// identical timestamp in log_queries (queries.log) for exe/
		// protocol/rule-id/timing details.
		if simpleW := s.rt.SimpleQueriesWriter(); simpleW != nil {
			line := formatSimpleQueryLogLine(now, typ, displayDomain, action, ips)
			if _, werr := simpleW.Write([]byte(line)); werr != nil {
				log.Debug("failed to write to simple queries log", wincoe.SafeErr(werr))
			}
		}

		log.Log(ctx, slog.LevelInfo, "logged_query", attrs...)
	})
} //func

func servfailResponse(reqMsg *dns.Msg) *dns.Msg {
	// reqMsg.SetRcode(reqMsg, dns.RcodeServerFailure)
	// reqMsg.RecursionAvailable = true
	// return reqMsg
	resp := new(dns.Msg)
	resp.SetReply(reqMsg)
	resp.SetRcode(resp, dns.RcodeServerFailure)
	resp.RecursionAvailable = true
	return resp
}

func formerrResponse(reqMsg *dns.Msg) *dns.Msg {
	// reqMsg.SetRcode(reqMsg, dns.RcodeFormatError)
	// return reqMsg
	resp := new(dns.Msg)
	resp.SetReply(reqMsg)
	resp.SetRcode(resp, dns.RcodeFormatError)
	return resp
}

func (ui *AdminUI) responseBlacklistHandler(w http.ResponseWriter, r *http.Request) {
	const allowedMethods = "GET, HEAD, POST, OPTIONS"
	if writeAllowHeaderResponse(w, r, allowedMethods) {
		return
	}

	if r.Method == http.MethodGet || r.Method == http.MethodHead { //"GET" or "HEAD"
		records := ui.blacklist.Snapshot()
		views := make([]BlacklistView, len(records))
		for i, rec := range records {
			views[i] = BlacklistView{Index: i, CIDR: rec.Net.String(), Enabled: rec.Enabled, ModifiedAtDisplay: formatModifiedAt(rec.ModifiedAt)}
		}
		data := map[string]any{
			"ResponseBlacklist": views,
			"SuccessMessage":    r.URL.Query().Get("success"),
			"ErrorMessage":      r.URL.Query().Get("error"),
		}
		ui.renderTemplate(w, r, "response-blacklist", data)
		return
	} //end "GET" or "HEAD"

	if r.Method == http.MethodPost { //"POST" {
		// See the identical lock in rulesHandler's POST branch for why this
		// single-item path must also serialize against Reload()/batch-apply.
		ui.tableMutationMu.Lock()
		defer ui.tableMutationMu.Unlock()

		fields := map[string]string{
			"action":   r.FormValue("action"),
			"cidr":     r.FormValue("cidr"),
			"old_cidr": r.FormValue("old_cidr"),
			"enabled":  r.FormValue("enabled"),
		}

		status, err := ui.processBlacklistChange(fields, ui.OnInvalidateBlacklist)
		if err != nil {
			//log.X lines are inside processBlacklistChange()
			http.Error(w, err.Error(), status)
			return
		}

		if err := ui.OnSaveBlacklist(); err != nil {
			redirectWithPersistFailure(w, r, "/response-blacklist", ui.logPersistFailure("response blacklist", err))
			return
		}
		http.Redirect(w, r, "/response-blacklist", http.StatusSeeOther)
		return
	} //end "POST"

	ui.rejectUnsupportedMethod(w, r, allowedMethods)
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

// blacklistCheckResponse is the consistent JSON envelope returned by
// responseBlacklistCheckHandler for every outcome: success (ok:true, with
// Matches, possibly empty) and failure (ok:false, with Error and an
// appropriate non-2xx HTTP status), so callers can distinguish "genuinely no
// overlap" from "the input itself was rejected" instead of both silently
// looking identical.
type blacklistCheckResponse struct {
	OK      bool     `json:"ok"`
	Matches []string `json:"matches,omitempty"`
	Error   string   `json:"error,omitempty"`
}

func (ui *AdminUI) responseBlacklistCheckHandler(w http.ResponseWriter, r *http.Request) {
	const allowedMethods = "GET, HEAD, OPTIONS"
	if writeAllowHeaderResponse(w, r, allowedMethods) {
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		ui.rejectUnsupportedMethod(w, r, allowedMethods)
		return
	}

	log := ui.getLogger()

	writeJSON := func(status int, resp blacklistCheckResponse) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Debug("failed to encode/write json response", wincoe.SafeErr(err))
		}
	}

	cidrStr := strings.TrimSpace(r.URL.Query().Get("cidr"))
	if cidrStr == "" {
		writeJSON(http.StatusOK, blacklistCheckResponse{OK: true, Matches: []string{}})
		return
	}

	// Parse incoming string to a network block, accepting either a bare IP
	// (auto-widened to /32 or /128) or an explicit CIDR.
	_, n, err := net.ParseCIDR(cidrStr)
	if err != nil {
		if ip := net.ParseIP(cidrStr); ip != nil {
			if ip.To4() != nil {
				_, n, _ = net.ParseCIDR(cidrStr + "/32") //nolint:errcheck // IP is already validated above
			} else {
				_, n, _ = net.ParseCIDR(cidrStr + "/128") //nolint:errcheck // IP is already validated above
			}
		}
	}
	if n == nil {
		writeJSON(http.StatusBadRequest, blacklistCheckResponse{
			OK:    false,
			Error: fmt.Sprintf("invalid IP address or CIDR: %q", cidrStr),
		})
		return
	}

	// checkBlacklistMatches (via BlacklistStore.CheckMatches) always returns
	// a non-nil, possibly-empty slice.
	writeJSON(http.StatusOK, blacklistCheckResponse{OK: true, Matches: ui.checkBlacklistMatches(n)})
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

const TheAllowsPage string = "/allows"
const TheBlocksPage string = "/blocks"

func (ui *AdminUI) SetupRoutes(boundAddr string, usedTLS bool) http.Handler {
	// ── Inner mux: all routes that require authentication ─
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
	innerMux.HandleFunc("/control", ui.controlHandler)
	innerMux.HandleFunc("/rules", ui.rulesHandler)
	innerMux.HandleFunc("/hosts", ui.hostsHandler)
	innerMux.HandleFunc(TheBlocksPage, ui.blocksHandler) // XXX: changing this TheBlocksPage requires changing more occurrences in other places in the uiTemplates as well!
	innerMux.HandleFunc(TheAllowsPage, ui.allowsHandler) // Sibling of TheBlocksPage (Recent Allows vs Recent Blocks); same XXX note applies.
	innerMux.HandleFunc("/response-blacklist", ui.responseBlacklistHandler)
	innerMux.HandleFunc("/response-blacklist/check", ui.responseBlacklistCheckHandler)
	innerMux.HandleFunc("/query-blocklist", ui.queryBlocklistHandler)
	innerMux.HandleFunc("/apply-tables", ui.applyTablesHandler)
	innerMux.HandleFunc("/logs", ui.logsHandler)
	innerMux.HandleFunc("/logs_queries", ui.logsQueriesHandler)
	innerMux.HandleFunc("/logs_queries_simple", ui.logsQueriesSimpleHandler)
	innerMux.HandleFunc("/config", ui.configHandler)
	innerMux.HandleFunc("/shutdown", ui.shutdownHandler)
	innerMux.HandleFunc("/csrf-token", ui.csrfTokenHandler)
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

	// ── Outer mux: browser-automatic routes that must bypass auth ──
	// These are requests browsers fire silently before the user has had a
	// chance to enter credentials.  Letting them hit authMiddleware would
	// silently burn failure-counter slots on every single page load.
	outerMux := http.NewServeMux()
	// outerMux.HandleFunc("/favicon.ico", ui.hostValidationFunc(boundAddr, faviconHandler))
	// outerMux.HandleFunc("/robots.txt", ui.hostValidationFunc(boundAddr, robotsTxtHandler))
	outerMux.Handle(
		"/favicon.ico",
		ui.securityHeadersMiddleware(
			ui.requestBodyLimitMiddleware(
				ui.fetchMetadataWhitelistMiddleware(
					ui.hostValidationMiddleware(boundAddr, http.HandlerFunc(faviconHandler)))),
		),
	)

	outerMux.Handle(
		"/robots.txt",
		ui.securityHeadersMiddleware(
			ui.requestBodyLimitMiddleware(
				ui.fetchMetadataWhitelistMiddleware(
					ui.hostValidationMiddleware(boundAddr, http.HandlerFunc(ui.robotsTxtHandler)))),
		),
	)

	// Everything else goes through sechead->hostvalid->auth → CSRF → inner mux.
	var h http.Handler = innerMux
	h = ui.authMiddleware(h) // costly bcrypt here
	h = ui.csrfMiddleware(h)
	h = ui.originValidationMiddleware(boundAddr, usedTLS, h)
	h = ui.hostValidationMiddleware(boundAddr, h)
	h = ui.fetchMetadataWhitelistMiddleware(h)
	h = ui.requestBodyLimitMiddleware(h)
	h = ui.securityHeadersMiddleware(h)
	outerMux.Handle("/", h)
	//outerMux.Handle("/", ui.hostValidation(ui.authMiddleware(ui.csrfMiddleware(innerMux))))

	// Rate-limit absolutely everything, including the unauthenticated
	// favicon/robots bypass routes registered above, before any other WebUI
	// processing runs. This is deliberately the outermost layer: it must
	// reject a flood before host validation, auth, or CSRF checks spend any
	// CPU/log volume on it.
	return ui.webUIRateLimitMiddleware(outerMux)
}

// webUIRateLimitMiddleware enforces a global and per-client-IP request-rate
// cap on all WebUI traffic, independent of loginTracker (which only
// throttles *failed* login attempts) and independent of Server.rateLimiter
// (which governs DNS query traffic, an entirely different resource). Without
// this, nothing bounded how many HTTP requests per second a single client —
// or the sum of all clients — could send to the control panel: a runaway
// script or attacker could hammer authenticated, disk-writing endpoints
// (staging rule/host/blacklist changes, the /config apply path, etc.) as
// fast as the network allowed.
//
// A nil ui.rateLimiter (e.g. a test harness that constructs AdminUI directly
// without going through initAdminUI()'s post-construction wiring) is treated
// as "not yet configured" and allows all requests through rather than
// panicking, matching this codebase's general nil-safety conventions (see
// wincoe.GetLoggerOrFallback).
func (ui *AdminUI) webUIRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ui.rateLimiter == nil {
			next.ServeHTTP(w, r)
			return
		}

		// FIX: Strip ephemeral port before rate-limiting the WebUI
		clientIP := getCleanIP(r.RemoteAddr, func(splitErr error) {
			log := ui.getLogger()
			log.Warn("WebUI webUIRateLimitMiddleware: could not split RemoteAddr into host:port",
				slog.String("remoteAddr", r.RemoteAddr),
				wincoe.SafeErr(splitErr))
		})

		allowed, reason := ui.rateLimiter.Allow(clientIP)
		if !allowed {
			log := ui.getLogger()
			log.Warn("WebUI request rejected: rate limit exceeded",
				slog.String("reason", reason),
				slog.String("client", clientIP),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
			)
			w.Header().Set("Retry-After", "1")
			http.Error(w, "429 Too Many Requests — WebUI request rate limit exceeded. Slow down and try again shortly.", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
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

		// Intentional defense-in-depth duplication: fetchMetadataWhitelistMiddleware
		// already rejects most cross-site requests earlier in the chain (see
		// SetupRoutes), but this check keeps originValidationMiddleware safe on
		// its own — e.g. if it's ever reused standalone, or the middleware order
		// in SetupRoutes changes — so it is NOT dead/obsolete code; keep it.
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

func (ui *AdminUI) requestBodyLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil ||
			(r.Method != http.MethodPost &&
				r.Method != http.MethodPut &&
				r.Method != http.MethodPatch) {
			next.ServeHTTP(w, r)
			return
		}

		limit := maxWebUIFormBodyBytes
		if r.URL.Path == "/apply-tables" {
			limit = maxWebUIBatchBodyBytes
		}

		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

func (ui *AdminUI) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()

		// Authenticated HTML/API responses may contain CSRF tokens, logs,
		// configuration values, and other operator-only state. Static assets are
		// versioned separately and retain their existing cache policy.
		if !strings.HasPrefix(r.URL.Path, "/static/") &&
			r.URL.Path != "/favicon.ico" &&
			r.URL.Path != "/robots.txt" {
			h.Set("Cache-Control", "no-store")
			h.Set("Pragma", "no-cache")
		}

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
				"media-src 'none'; "+ // <--- Explicitly locked down, NoScript will complain like: (I forgot to add this)

				"frame-src 'none'; "+
				"worker-src 'none'; "+
				"manifest-src 'none'; "+

				//Do not add upgrade-insecure-requests; it could interfere with intentional HTTP loopback operation. TODO: maybe add this upgrade-insecure-requests only when it's known https? r.TLS!=nil(is the way used in another place) ?!

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

// newCSRFSecret generates a fresh, process-lifetime-only HMAC key used to
// sign/verify CSRF tokens — see verifyCSRFToken's doc comment for why a
// signed token is required instead of trusting a bare cookie value at face
// value. Panics if the OS CSPRNG is unavailable, mirroring getSecureID's
// rationale elsewhere in this file: a predictable/absent entropy source
// here would make every CSRF token forgeable, so failing loudly beats
// silently running with a weak or zero-value secret.
// newRandomSecret returns n cryptographically random bytes, or panics if the
// OS CSPRNG is unavailable — mirrors getSecureID's rationale elsewhere in
// this file: a predictable/absent entropy source here would make every
// derived secret forgeable, so failing loudly beats silently running with a
// weak or zero-value secret.
func newRandomSecret(n int) []byte {
	secret := make([]byte, n)
	if _, err := rand.Read(secret); err != nil {
		panic2("BUG: critical system error: failed to generate random secret: " + err.Error())
	}
	return secret
}

func newCSRFSecret() []byte {
	return newRandomSecret(32)
}

// newCSRFToken produces a fresh CSRF token of the form "<nonce>.<hmac>",
// both base64url-encoded, where hmac = HMAC-SHA256(nonce, secret).
func newCSRFToken(secret []byte) string {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		panic2("BUG: critical system error: failed to generate CSRF token nonce: " + err.Error())
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(nonce)
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(nonce) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// verifyCSRFToken reports whether token carries a valid HMAC signature under
// secret, i.e. whether THIS server (not some other party) generated it.
//
// Without this check, csrfMiddleware would blindly trust whatever value
// happens to be in the request's csrf_token cookie as the source of truth —
// including one an attacker planted there. Cookies do not carry port
// granularity (RFC 6265): a cookie set for host "127.0.0.1" is shared across
// every port on that host, so any other local program a victim's browser
// can be made to visit (e.g. a malicious page on http://127.0.0.1:<other
// port>/) can plant an attacker-known csrf_token value via its own
// Set-Cookie response, even though this cookie is HttpOnly (HttpOnly only
// blocks client-side JS from reading/writing it — it does nothing to stop a
// *different* HTTP response on the same host from setting it). If the
// server then trusted that planted value as correct, the attacker — who
// knows the value they planted — could include the identical token in a
// forged cross-site form submission and defeat the double-submit CSRF
// defense entirely (classic CSRF token fixation).
//
// Requiring a valid signature closes this: an attacker who doesn't know
// this process's in-memory secret cannot forge a token the server will
// accept, so a fixated cookie is simply rejected and replaced.
func verifyCSRFToken(token string, secret []byte) bool {
	nonceB64, sigB64, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}
	nonce, err := base64.RawURLEncoding.DecodeString(nonceB64)
	if err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(nonce)
	expected := mac.Sum(nil)
	return hmac.Equal(sig, expected)
}

// webUISessionAuthCookieBaseName is the cookie name used to carry the
// signed session-issued-at timestamp for webui_auth_session_mode=
// 'session_cookie' (see AdminUI.proceedAfterAuthSuccess). The name sent to
// the browser is prefixed with "__Host-" over HTTPS, mirroring
// csrfCookieName's identical host-locking rationale.
const webUISessionAuthCookieBaseName = "webui_session_auth"

// sessionAuthCookieClockSkewTolerance permits a small amount of forward
// clock skew so a cookie whose signed timestamp appears to be a few seconds
// "in the future" (relative to a slightly-fast/slow local clock, or simple
// request-processing latency) isn't spuriously rejected as invalid.
const sessionAuthCookieClockSkewTolerance = 5 * time.Second

// newSessionAuthSecret generates a fresh, process-lifetime-only HMAC key
// used to sign/verify the WebUI's session-expiry cookie (see
// newSessionAuthToken/verifySessionAuthToken and
// Config.WebUIAuthSessionMode's doc comment), kept independent from
// csrfSecret so the two concerns never share key material.
func newSessionAuthSecret() []byte {
	return newRandomSecret(32)
}

// newSessionAuthToken produces a fresh session-expiry cookie value of the
// form "<timestamp>.<hmac>", both base64url-encoded, where
// hmac = HMAC-SHA256(timestamp, secret) and timestamp is issuedAt's Unix
// seconds. Mirrors newCSRFToken's shape/rationale.
func newSessionAuthToken(secret []byte, issuedAt time.Time) string {
	ts := strconv.FormatInt(issuedAt.Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ts))
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString([]byte(ts)) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// verifySessionAuthToken reports whether token carries a validly-signed
// timestamp under secret (i.e. was minted by THIS server, not forged or
// tampered with — see verifyCSRFToken's doc comment for the identical
// cookie-fixation rationale this guards against), and if so returns the
// timestamp it encodes.
func verifySessionAuthToken(token string, secret []byte) (issuedAt time.Time, ok bool) {
	tsB64, sigB64, cut := strings.Cut(token, ".")
	if !cut {
		return time.Time{}, false
	}
	tsBytes, err := base64.RawURLEncoding.DecodeString(tsB64)
	if err != nil {
		return time.Time{}, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return time.Time{}, false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(tsBytes)
	expected := mac.Sum(nil)
	if !hmac.Equal(sig, expected) {
		return time.Time{}, false
	}
	sec, perr := strconv.ParseInt(string(tsBytes), 10, 64)
	if perr != nil {
		return time.Time{}, false
	}
	return time.Unix(sec, 0), true
}

// defaultWWWAuthenticateRealm is the static realm string used for WebUI
// Basic-Auth challenges when webui_auth_session_mode is not 'time_bucket'.
const defaultWWWAuthenticateRealm = "dnsbollocks webUI aka Management Interface aka Control Panel"

// currentAuthRealm returns the realm string to use in a WWW-Authenticate
// challenge for this request. In every mode except 'time_bucket' this is a
// fixed string; in 'time_bucket' mode it rotates once per
// webui_auth_session_timeout_minutes (see Config.WebUIAuthSessionMode's doc
// comment), which is what lets a browser's realm-keyed Basic-Auth
// credential cache go stale and force a fresh prompt once the bucket
// advances.
func (ui *AdminUI) currentAuthRealm() string {
	cfg := ui.getConfig()
	if cfg.WebUIAuthSessionMode != webUIAuthSessionModeTimeBucket {
		return defaultWWWAuthenticateRealm
	}
	timeoutSec := int64(cfg.WebUIAuthSessionTimeoutMinutes) * 60
	if timeoutSec <= 0 {
		// Defensive: sanitizeAndValidateConfig clamps this to > 0.
		timeoutSec = 60
	}
	bucket := time.Now().Unix() / timeoutSec
	return fmt.Sprintf("%s [slot %d]", defaultWWWAuthenticateRealm, bucket)
}

// sessionAuthCookieName returns the cookie name used for the session-expiry
// timestamp cookie, mirroring csrfCookieName's identical __Host- prefixing
// rule (only usable, and only sent, over HTTPS).
func (ui *AdminUI) sessionAuthCookieName(r *http.Request) string {
	if r.TLS != nil {
		return "__Host-" + webUISessionAuthCookieBaseName
	}
	return webUISessionAuthCookieBaseName
}

// setSessionAuthCookie issues a fresh, HMAC-signed session-expiry cookie
// timestamped at issuedAt.
func (ui *AdminUI) setSessionAuthCookie(w http.ResponseWriter, r *http.Request, issuedAt time.Time) {
	http.SetCookie(w,
		//nolint:gosec // HttpOnly and SameSite are set; Secure is conditional on HTTPS support, mirroring getOrCreateCSRFToken's identical cookie.
		&http.Cookie{
			Name:     ui.sessionAuthCookieName(r),
			Value:    newSessionAuthToken(ui.sessionAuthSecret, issuedAt),
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   r.TLS != nil,
		},
	)
}

// sessionAuthCookieFresh reports whether r carries a validly-signed
// session-expiry cookie issued within the last timeoutMinutes.
func (ui *AdminUI) sessionAuthCookieFresh(r *http.Request, timeoutMinutes int) bool {
	cookie, err := r.Cookie(ui.sessionAuthCookieName(r))
	if err != nil || cookie.Value == "" {
		return false
	}
	issuedAt, ok := verifySessionAuthToken(cookie.Value, ui.sessionAuthSecret)
	if !ok {
		return false
	}
	now := time.Now()
	if issuedAt.After(now.Add(sessionAuthCookieClockSkewTolerance)) {
		return false // cookie claims to be issued in the future; reject defensively
	}
	timeout := time.Duration(timeoutMinutes) * time.Minute
	if timeout <= 0 {
		// Defensive: sanitizeAndValidateConfig clamps this to > 0.
		timeout = time.Minute
	}
	return now.Sub(issuedAt) <= timeout
}

// proceedAfterAuthSuccess finalizes a successful WebUI Basic-Auth
// verification: it clears any prior failed-login streak for clientIP, then
// enforces the configured session-expiry policy (see
// Config.WebUIAuthSessionMode's doc comment). It returns true if the
// request should proceed to the protected handler; false if it has already
// written a 401 response itself (session_cookie mode only, when the
// existing session cookie is missing/expired — a fresh cookie is issued
// alongside that 401 so the browser's immediate credential re-submission,
// triggered by the 401, succeeds on the very next request) and the caller
// must not call next.ServeHTTP.
func (ui *AdminUI) proceedAfterAuthSuccess(w http.ResponseWriter, r *http.Request, clientIP string) bool {
	// Clear any prior failure streak so a legitimate user is never stuck in
	// a lockout after recovering from a typo run.
	ui.recordLoginSuccess(clientIP)

	cfg := ui.getConfig()
	if cfg.WebUIAuthSessionMode != webUIAuthSessionModeSessionCookie {
		return true
	}
	if ui.sessionAuthCookieFresh(r, cfg.WebUIAuthSessionTimeoutMinutes) {
		return true
	}

	log := ui.getLogger()
	log.Info("WebUI session cookie missing/expired or cookies aren't allowed in browser; forcing credential re-prompt",
		slog.String("client", clientIP),
		slog.Int("timeout_minutes", cfg.WebUIAuthSessionTimeoutMinutes))

	// Issue a fresh cookie alongside this 401: the browser evicts its cached
	// Basic-Auth credential upon receiving 401 and immediately re-submits it
	// (prompting the user if needed), and that retry request will carry this
	// freshly-issued cookie, passing the freshness check above and starting a
	// new session window.
	ui.setSessionAuthCookie(w, r, time.Now())
	w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", ui.currentAuthRealm()))
	http.Error(w, "401 Unauthorized - WebUI session expired(or cookies aren't allowed in browser), please re-authenticate", http.StatusUnauthorized)
	return false
}

type csrfTokenKey struct{}

func (ui *AdminUI) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log := ui.getLogger()
		//cfg := ui.getConfig()

		token := ui.getOrCreateCSRFToken(w, r)

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
				w.Header().Set("X-DNSbollocks-Error", "csrf")
				http.Error(w, "403 Forbidden - CSRF Verification Failed", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (ui *AdminUI) statsHandler(w http.ResponseWriter, r *http.Request) {
	const allowedMethods = "GET, HEAD, OPTIONS"
	if writeAllowHeaderResponse(w, r, allowedMethods) {
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		ui.rejectUnsupportedMethod(w, r, allowedMethods)
		return
	}

	cfg := ui.getConfig()
	data := map[string]any{
		"PID":            os.Getpid(),
		"BlockedQueries": ui.blockedQueries.String(),
		"UpstreamURLs":   cfg.UpstreamURLsParsed,
		"UpstreamSNIs":   cfg.UpstreamSNIHostnames,
		"UpstreamIPs":    cfg.UpstreamIPs,
	}
	ui.renderTemplate(w, r, "stats", data)
}

// controlHandler serves the /control page, which groups process-lifecycle
// actions (currently just Shutdown) separately from the purely informational,
// read-only /stats page.
func (ui *AdminUI) controlHandler(w http.ResponseWriter, r *http.Request) {
	const allowedMethods = "GET, HEAD, POST, OPTIONS"
	if writeAllowHeaderResponse(w, r, allowedMethods) {
		return
	}
	log := ui.getLogger()

	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		ui.renderTemplate(w, r, "control", map[string]any{
			"SuccessMessage": r.URL.Query().Get("success"),
			"ErrorMessage":   r.URL.Query().Get("error"),
		})
		return
	}

	if r.Method == http.MethodPost {
		action := r.FormValue("action")
		switch action {
		case "reload":
			if ui.OnReloadConfig == nil {
				log.Error("BUG: WebUI config reload requested but no reload handler is wired (likely in a test environment)")
				http.Error(w, "config reload is not available in this environment", http.StatusServiceUnavailable)
				return
			}
			if err := ui.OnReloadConfig(); err != nil {
				log.Warn("WebUI-triggered config reload failed", wincoe.SafeErr(err))
				http.Redirect(w, r, "/control?error="+url.QueryEscape("Reload failed: "+err.Error()), http.StatusSeeOther)
				return
			}
			log.Info("Config reload triggered via WebUI")
			http.Redirect(w, r, "/control?success="+url.QueryEscape("Configuration reloaded successfully."), http.StatusSeeOther)
			return

		case "clear_cache":
			if ui.OnClearCache == nil {
				log.Error("BUG: WebUI DNS-cache clear requested but no handler is wired (likely in a test environment)")
				http.Error(w, "clearing the DNS cache is not available in this environment", http.StatusServiceUnavailable)
				return
			}
			ui.OnClearCache()
			log.Info("DNS cache cleared via WebUI")
			http.Redirect(w, r, "/control?success="+url.QueryEscape("DNS cache cleared."), http.StatusSeeOther)
			return

		default:
			log.Warn("Control handler received unknown action", slog.String("action", action))
			http.Error(w, fmt.Sprintf("unknown action %q", action), http.StatusBadRequest)
			return
		}
	}

	ui.rejectUnsupportedMethod(w, r, allowedMethods)
}

// RuleStore manages the in-memory DNS query whitelist.
// Persistence (loadQueryWhitelist / saveQueryWhitelist) stays on Server.
type RuleStore struct {
	mu         sync.Mutex                             // Serializes writers (Add, Update, Delete, ReplaceAll)
	rules      atomic.Pointer[map[string][]RuleEntry] // type -> rules
	generation atomic.Uint64
}

func (rs *RuleStore) Generation() uint64 {
	return rs.generation.Load()
}

// only use once, before server start, never on reloads(Ctrl+R) tho
func newRuleStore() *RuleStore {
	rs := &RuleStore{}
	empty := make(map[string][]RuleEntry)
	rs.rules.Store(&empty)
	rs.generation.Add(1)
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
	rs.generation.Add(1)
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

// HasExactEnabledPattern reports whether an enabled rule with a pattern
// EXACTLY equal to pattern (byte-for-byte, no wildcard expansion) exists in
// typ.
//
// This exists because several WebUI display predicates need to answer "is
// there a rule that SetEnabled/quickToggleExactRule could actually find and
// toggle for this exact pattern", not "would a query for this domain
// currently match some rule" (which MatchForType answers, wildcards
// included). Conflating the two let a wildcard rule (e.g. "*.example.com")
// make the UI believe a specific domain (e.g. "sub.example.com") had its own
// togglable rule, when in fact SetEnabled's exact-pattern lookup would find
// nothing and the "Re-block"/"Unblock" button would silently fail. See
// buildIsUnblockedPredicate's doc comment for the original report of this
// class of bug.
func (rs *RuleStore) HasExactEnabledPattern(typ, pattern string) bool {
	// 100% lock-free read
	current := *rs.rules.Load()
	for _, rule := range current[typ] {
		if rule.Enabled && rule.Pattern == pattern {
			return true
		}
	}
	return false
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
	newRule := RuleEntry{ID: id, Pattern: pattern, Enabled: enabled, ModifiedAt: time.Now()}

	next := cloneRuleMap(current)
	next[typ] = withRulePrepended(next[typ], newRule, logger)
	rs.rules.Store(&next)
	rs.generation.Add(1)

	//logger.Info("Rule added", slog.String("pattern", pattern), slog.String("type", typ),
	//slog.String("id", id), slog.Bool("enabled", enabled))
	displayPattern, wasIDN := punycodeDecodePatternForDisplay(pattern)
	attrs := []any{slog.String("pattern", pattern), slog.String("type", typ), slog.String("id", id), slog.Bool("enabled", enabled)}
	if wasIDN {
		attrs = append(attrs, slog.String("pattern_idn", displayPattern))
	}
	logger.Debug("Rule added", attrs...)
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
		if rule.ID != id {
			continue
		}
		next := cloneRuleMap(current)
		next[typ] = withRuleRemovedAt(rules, i, logger)
		rs.rules.Store(&next)
		rs.generation.Add(1)
		return rule.Pattern, nil
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
	newRule := RuleEntry{ID: id, Pattern: newPattern, Enabled: enabled, ModifiedAt: time.Now()}

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
	rs.generation.Add(1)

	// logger.Info("Rule updated", slog.String("id", id),
	// 	slog.String("new_pattern", newPattern), slog.Bool("enabled", enabled),
	// 	slog.String("old_pattern", oldPattern))
	displayNew, newIsIDN := punycodeDecodePatternForDisplay(newPattern)
	displayOld, oldIsIDN := punycodeDecodePatternForDisplay(oldPattern)

	attrs := []any{slog.String("id", id), slog.String("new_pattern", newPattern), slog.String("old_pattern", oldPattern), slog.Bool("enabled", enabled)}
	if newIsIDN {
		attrs = append(attrs, slog.String("new_pattern_idn", displayNew))
	}
	if oldIsIDN {
		attrs = append(attrs, slog.String("old_pattern_idn", displayOld))
	}

	logger.Info("Rule updated", attrs...)
	return oldType, oldPattern, nil
}

// setEnabledWhere is the shared implementation behind SetEnabled (matches by
// exact pattern) and SetEnabledByID (matches by ID): it finds the first rule
// in typ satisfying match, and enables/disables it if not already in that
// state. Returns the matched rule's pattern (empty if not found) alongside
// (found, changed).
func (rs *RuleStore) setEnabledWhere(typ string, match func(RuleEntry) bool, enabled bool, logger *slog.Logger) (pattern string, found, changed bool) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	current := *rs.rules.Load()

	for i, rule := range current[typ] {
		if !match(rule) {
			continue
		}

		if rule.Enabled == enabled {
			return rule.Pattern, true, false
		}

		// We can no longer mutate the rule in-place because readers
		// might be actively iterating this slice lock-free!
		next := cloneRuleMap(current)
		updatedRule := rule
		updatedRule.Enabled = enabled
		updatedRule.ModifiedAt = time.Now()
		next[typ] = withRuleUpdatedAtIndex(next[typ], i, updatedRule, logger)
		rs.rules.Store(&next)
		rs.generation.Add(1)

		return rule.Pattern, true, true
	}
	return "", false, false
}

// SetEnabled enables or disables the first rule whose pattern exactly equals
// domain, within typ. Returns (found, changed): changed=false when already
// in the desired state.
func (rs *RuleStore) SetEnabled(typ, domain string, enabled bool, logger *slog.Logger) (found, changed bool) {
	_, found, changed = rs.setEnabledWhere(typ, func(r RuleEntry) bool { return r.Pattern == domain }, enabled, logger)
	return found, changed
}

// SetEnabledByID enables or disables the rule with the given ID within typ,
// regardless of its pattern (exact or wildcard). Unlike SetEnabled (matching
// by exact pattern text — the convention the whitelist/except quick unblock
// flows use, see quickToggleExactRule), this looks the rule up directly by
// its stable ID, letting a caller that already resolved the ID via
// MatchForType (a wildcard-aware match) toggle precisely the rule that
// actually matched, no matter its pattern shape. Returns the matched rule's
// pattern (empty if not found), which callers commonly need afterward for
// cache invalidation.
func (rs *RuleStore) SetEnabledByID(typ, id string, enabled bool, logger *slog.Logger) (pattern string, found, changed bool) {
	return rs.setEnabledWhere(typ, func(r RuleEntry) bool { return r.ID == id }, enabled, logger)
}

// HostStore manages local hostname overrides.
type HostStore struct {
	mu         sync.RWMutex
	hosts      []LocalHostRule
	generation atomic.Uint64
}

func (hs *HostStore) Generation() uint64 {
	return hs.generation.Load()
}

func newHostStore() *HostStore { return &HostStore{} }

func (hs *HostStore) ReplaceAll(hosts []LocalHostRule) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	hs.hosts = hosts
	hs.generation.Add(1)
}

// Match returns the IPs for the first ENABLED rule whose pattern matches
// domain, or nil. A disabled override (see LocalHostRule.Enabled) is
// skipped entirely, so the query falls through to the whitelist/upstream
// path exactly as if the override didn't exist.
func (hs *HostStore) Match(domain string) ([]net.IP, bool) {
	hs.mu.RLock()
	defer hs.mu.RUnlock()
	for _, rule := range hs.hosts {
		if rule.Enabled && matchPattern(rule.Pattern, domain) {
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
		displayPattern, _ := punycodeDecodePatternForDisplay(h.Pattern)
		out[i] = HostView{
			Index:             i,
			Pattern:           h.Pattern,
			PatternDisplay:    displayPattern,
			IPsDisplay:        strings.Join(ips, ", "),
			Enabled:           h.Enabled,
			ModifiedAtDisplay: formatModifiedAt(h.ModifiedAt),
			// ModifiedAtSort:    modifiedAtSortValue(h.ModifiedAt),
		}
	}
	return out
}

// ToRawMap converts the host rules to the on-disk hosts2ip.json format,
// pairing each pattern's IP list with its last-modified timestamp (see
// HostFileEntry).
func (hs *HostStore) ToRawMap() map[string]HostFileEntry {
	hs.mu.RLock()
	defer hs.mu.RUnlock()

	raw := make(map[string]HostFileEntry, len(hs.hosts))
	for _, rule := range hs.hosts {
		var ips []string
		// rule.IPs is a slice of net.IP, convert each to string
		for _, ip := range rule.IPs {
			ips = append(ips, ip.String())
		}
		raw[rule.Pattern] = HostFileEntry{IPs: ips, Enabled: rule.Enabled, ModifiedAt: rule.ModifiedAt}
	}
	return raw
}

// AddHost appends a new, enabled rule. Returns an error if the pattern already exists.
func (hs *HostStore) AddHost(pattern string, ips []net.IP) error {
	return hs.AddHostWithEnabled(pattern, ips, true)
}

// AddHostWithEnabled mirrors AddHost but lets the caller specify the
// enabled state explicitly (used by the WebUI's Add form, which lets the
// operator add a host override already paused via the "Enabled" checkbox).
// Returns an error if the pattern already exists.
func (hs *HostStore) AddHostWithEnabled(pattern string, ips []net.IP, enabled bool) error {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	for _, rule := range hs.hosts {
		if rule.Pattern == pattern {
			return fmt.Errorf("local host with pattern %q already exists", pattern)
		}
	}
	hs.hosts = append(hs.hosts, LocalHostRule{Pattern: pattern, IPs: ips, Enabled: enabled, ModifiedAt: time.Now()})
	hs.generation.Add(1)
	return nil
}

// EditHost replaces (old→new) with Enabled=true. Returns an error if the new
// pattern already exists and is different from the old pattern.
func (hs *HostStore) EditHost(oldPattern, newPattern string, ips []net.IP) error {
	return hs.EditHostWithEnabled(oldPattern, newPattern, ips, true)
}

// EditHostWithEnabled mirrors EditHost but lets the caller specify the
// enabled state explicitly (used by the WebUI's Edit form, which preserves
// or toggles the row's "Enabled" checkbox).
func (hs *HostStore) EditHostWithEnabled(oldPattern, newPattern string, ips []net.IP, enabled bool) error {
	hs.mu.Lock()
	defer hs.mu.Unlock()

	// Check for collision if the pattern is being renamed
	if oldPattern != newPattern {
		for _, rule := range hs.hosts {
			if rule.Pattern == newPattern {
				return fmt.Errorf("local host with pattern %q already exists", newPattern)
			}
		}
	}

	hs.hosts = deleteHostEntry(hs.hosts, oldPattern)
	hs.hosts = deleteHostEntry(hs.hosts, newPattern) // safe eviction
	hs.hosts = append(hs.hosts, LocalHostRule{Pattern: newPattern, IPs: ips, Enabled: enabled, ModifiedAt: time.Now()})
	hs.generation.Add(1)
	return nil
}

// DeleteHost removes the rule with the given pattern. Returns true if found.
func (hs *HostStore) DeleteHost(pattern string) bool {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	before := len(hs.hosts)
	hs.hosts = deleteHostEntry(hs.hosts, pattern)
	// return len(hs.hosts) < before
	removed := len(hs.hosts) < before
	if removed {
		hs.generation.Add(1)
	}
	return removed
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
	mu         sync.RWMutex
	records    []BlacklistRecord
	generation atomic.Uint64
}

func (bs *BlacklistStore) Generation() uint64 {
	return bs.generation.Load()
}

func newBlacklistStore() *BlacklistStore { return &BlacklistStore{} }

// ReplaceAll atomically swaps in a freshly-loaded set of blacklist records.
func (bs *BlacklistStore) ReplaceAll(records []BlacklistRecord) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.records = records
	bs.generation.Add(1)
}

func (bs *BlacklistStore) Contains(ip net.IP) bool {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	for _, rec := range bs.records {
		if rec.Enabled && rec.Net.Contains(ip) {
			return true
		}
	}
	return false
}

// Snapshot returns a shallow copy of the current blacklist records for lock-free logic.
func (bs *BlacklistStore) Snapshot() []BlacklistRecord {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	cp := make([]BlacklistRecord, len(bs.records))
	copy(cp, bs.records)
	return cp
}

// List returns a string slice representation of the CIDRs for the Web UI.
func (bs *BlacklistStore) List() []string {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	out := make([]string, len(bs.records))
	for i, rec := range bs.records {
		out[i] = rec.Net.String()
	}
	return out
}

// TryAdd adds the CIDR (enabled) if not already present. Returns true if added.
func (bs *BlacklistStore) TryAdd(n *net.IPNet) bool {
	return bs.TryAddWithEnabled(n, true)
}

// TryAddWithEnabled mirrors TryAdd but lets the caller specify the enabled
// state explicitly (used by the WebUI's Add form).
func (bs *BlacklistStore) TryAddWithEnabled(n *net.IPNet, enabled bool) bool {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	for _, existing := range bs.records {
		if existing.Net.String() == n.String() {
			return false // Already exists
		}
	}
	// Prepend so newly added entries show up first, mirroring RuleStore.AddRule's behavior.
	bs.records = append([]BlacklistRecord{{Net: n, Enabled: enabled, ModifiedAt: time.Now()}}, bs.records...)
	bs.generation.Add(1)
	return true // Added successfully
}

// TryEdit replaces an existing CIDR entry (matched by its exact string form) with a new,
// enabled one, moving the edited entry to the front of the list and refreshing its
// ModifiedAt timestamp. Returns an error if oldCIDR isn't found, or if newNet's string
// form collides with a different existing entry.
func (bs *BlacklistStore) TryEdit(oldCIDR string, newNet *net.IPNet) error {
	return bs.TryEditWithEnabled(oldCIDR, newNet, true)
}

// TryEditWithEnabled mirrors TryEdit but lets the caller specify the enabled
// state explicitly (used by the WebUI's Edit form).
func (bs *BlacklistStore) TryEditWithEnabled(oldCIDR string, newNet *net.IPNet, enabled bool) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	idx := -1
	for i, existing := range bs.records {
		if existing.Net.String() == oldCIDR {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("entry not found: %q", oldCIDR)
	}

	newStr := newNet.String()
	if newStr != oldCIDR {
		for i, existing := range bs.records {
			if i != idx && existing.Net.String() == newStr {
				return fmt.Errorf("entry %q already exists", newStr)
			}
		}
	}

	bs.records = append(bs.records[:idx:idx], bs.records[idx+1:]...)
	bs.records = append([]BlacklistRecord{{Net: newNet, Enabled: enabled, ModifiedAt: time.Now()}}, bs.records...)
	bs.generation.Add(1)
	return nil
}

// TryDelete removes the matching CIDR string. Returns true if removed.
func (bs *BlacklistStore) TryDelete(cidrStr string) bool {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	for i, existing := range bs.records {
		if existing.Net.String() != cidrStr {
			continue
		}
		// 1. Slide elements left to overwrite index i
		bs.records = append(bs.records[:i], bs.records[i+1:]...)

		// 2. Clear the old trailing slot to let the Garbage Collector free the memory!
		bs.records = bs.records[:len(bs.records):cap(bs.records)] // Optional: strictly bounds checking
		if len(bs.records) < cap(bs.records) {
			// Since bs.records shrank by 1, the old last element is at the new len(bs.records)
			bs.records[:len(bs.records)+1][len(bs.records)] = BlacklistRecord{}
		}
		bs.generation.Add(1)
		return true
	}
	return false
}

// CheckMatches returns all existing CIDRs that are equal to or contain n's IP.
func (bs *BlacklistStore) CheckMatches(n *net.IPNet) []string {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	matches := []string{} // 👈 Initialize explicitly empty
	for _, existing := range bs.records {
		if existing.Net.String() == n.String() || existing.Net.Contains(n.IP) {
			matches = append(matches, existing.Net.String())
		}
	}
	return matches
}

func (bs *BlacklistStore) Len() int {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return len(bs.records)
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

// ClearBefore removes blocked queries that occurred at or before cutoff AND are NOT
// currently unblocked, as reported by isUnblocked(domain, qtype). Entries the operator
// has temporarily unblocked (still showing the WebUI's "Re-block (Pause)" button rather
// than "Unblock X") are deliberately preserved, so "Clear Shown Blocks" can never
// silently discard the one piece of UI state that lets the operator undo a quick-unblock
// later. Returns the number of items actually removed.
func (t *RecentBlocksTracker) ClearBefore(cutoff time.Time, isUnblocked func(domain, qtype string) bool) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	cleared := 0
	var next *list.Element

	for e := t.lst.Front(); e != nil; e = next {
		next = e.Next()
		bq, ok := e.Value.(*BlockedQuery)
		if !ok {
			panic2("BUG: not of *BlockedQuery type")
		}
		// The block happened at or before the page render time, and it isn't
		// currently sitting in a temporarily-unblocked state.
		if !bq.Time.After(cutoff) && !isUnblocked(bq.Domain, bq.Type) {
			delete(t.m, bq.Domain+":"+bq.Type)
			t.lst.Remove(e)
			cleared++
		}
	}
	return cleared
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

// Snapshot returns a copy of recent blocks, with IsUnblocked (the whitelist
// layer's state) populated via the provided checker. The query-blocklist
// layer's fields (QueryBlocklistLocalBlocked etc.) are NOT populated here —
// see AdminUI.populateQueryBlocklistRowState / getRecentBlocksCopy, which
// fills those in as a separate pass after calling this.
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

// loginTrackerMaxEntries bounds worst-case memory growth of LoginTracker.records.
// Each entry is tiny, but without a cap, an attacker able to complete a real TCP
// handshake from a very large number of distinct source IPs (unlike UDP DNS
// traffic, a WebUI login attempt cannot be spoofed — the attacker needs a real,
// completed connection, e.g. via a botnet) and send repeated malformed or
// incorrect Basic-Auth requests would otherwise grow this map without bound
// until the process runs out of memory. Least-recently-touched entries are
// evicted first once the cap is reached.
const loginTrackerMaxEntries = 10000

// LoginTracker records login failures and enforces per-IP lockout.
type LoginTracker struct {
	mu      sync.Mutex
	records map[string]*loginRecord  // guarded by mu; lazily cleaned on access
	lru     *list.List               // front = most recently touched clientIP
	lruElem map[string]*list.Element // clientIP -> its element in lru
}

func newLoginTracker() *LoginTracker {
	return &LoginTracker{
		records: make(map[string]*loginRecord),
		lru:     list.New(),
		lruElem: make(map[string]*list.Element),
	}
}

// touchLocked records clientIP as the most-recently-used entry, evicting the
// least-recently-used one (from both records and the LRU tracking structures)
// if the tracker is now over loginTrackerMaxEntries. Caller must hold lt.mu.
func (lt *LoginTracker) touchLocked(clientIP string) {
	if elem, ok := lt.lruElem[clientIP]; ok {
		lt.lru.MoveToFront(elem)
		return
	}
	elem := lt.lru.PushFront(clientIP)
	lt.lruElem[clientIP] = elem
	if lt.lru.Len() > loginTrackerMaxEntries {
		oldest := lt.lru.Back()
		if oldest == nil {
			return
		}
		lt.lru.Remove(oldest)
		if ip, ok := oldest.Value.(string); ok {
			delete(lt.lruElem, ip)
			delete(lt.records, ip)
		}
	}
}

// forgetLocked removes clientIP from both the records map and the LRU
// tracking structures. Caller must hold lt.mu.
func (lt *LoginTracker) forgetLocked(clientIP string) {
	delete(lt.records, clientIP)
	if elem, ok := lt.lruElem[clientIP]; ok {
		lt.lru.Remove(elem)
		delete(lt.lruElem, clientIP)
	}
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
	lt.touchLocked(clientIP)

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
	lt.forgetLocked(clientIP)
}

// ClearAll wipes all records and returns how many were removed.
func (lt *LoginTracker) ClearAll() int {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	n := len(lt.records)
	lt.records = make(map[string]*loginRecord)
	lt.lru = list.New()
	lt.lruElem = make(map[string]*list.Element)
	return n
}

// formatModifiedAt renders t for the WebUI's "Last Modified" columns (Rules,
// Local Hosts, Response Blacklist) in a fixed-width, lexicographically
// sortable format ("2006-01-02 15:04:05"), so the existing generic
// string-based column sort in app.js's setupTableSorting already produces
// correct chronological order with no separate hidden sort key needed. A
// zero time.Time (should not normally occur post-migration, but defensively
// handled) renders as "—".
func formatModifiedAt(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	// return t.Local().Format("2006-01-02 15:04:05")
	// return t.Format("2006-01-02 15:04:05.000000000") //uses current timezone; nanos
	return t.Format("2006-01-02 15:04:05.000") //uses current timezone; millis
	// return t.UTC().Format("2006-01-02 15:04:05.000000000") //timezone independent but also off by hours!
}

type RuleView struct {
	Type              string
	ID                string
	Pattern           string
	Enabled           bool
	ModifiedAtDisplay string
}

// writeAllowHeaderResponse responds to an HTTP OPTIONS probe with 204 No
// Content and the given Allow header value, and reports whether it did so
// (true means the caller should return immediately). Centralizing this in
// one helper keeps the exact set of methods a route supports declared in a
// single place instead of duplicated as a literal string in every handler.
func writeAllowHeaderResponse(w http.ResponseWriter, r *http.Request, allowed string) bool {
	if r.Method != http.MethodOptions {
		return false
	}
	w.Header().Set("Allow", allowed)
	w.WriteHeader(http.StatusNoContent)
	return true
}

// rejectUnsupportedMethod logs and replies with 405 Method Not Allowed for a
// request whose method wasn't matched by any branch earlier in the handler.
// Per RFC 7231 §7.4.1 a 405 response should include an Allow header listing
// the supported methods, which this also sets.
func (ui *AdminUI) rejectUnsupportedMethod(w http.ResponseWriter, r *http.Request, allowed string) {
	log := ui.getLogger()
	log.Warn("Unsupported HTTP method for this route",
		slog.String("method", r.Method),
		slog.String("URL", r.URL.String()),
		slog.String("allowed", allowed))
	w.Header().Set("Allow", allowed)
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

func (ui *AdminUI) rulesHandler(w http.ResponseWriter, r *http.Request) {
	const allowedMethods = "GET, HEAD, POST, OPTIONS"
	if writeAllowHeaderResponse(w, r, allowedMethods) {
		return
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead { //"GET" or "HEAD"
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
				displayPattern, _ := punycodeDecodePatternForDisplay(rule.Pattern)
				flatRules = append(flatRules, RuleView{
					Type:              typ,
					ID:                rule.ID,
					Pattern:           displayPattern,
					Enabled:           rule.Enabled,
					ModifiedAtDisplay: formatModifiedAt(rule.ModifiedAt),
				})
			}
		}

		data := map[string]any{
			"DNSTypes":       dnsTypes,
			"Rules":          flatRules, // Passing the flattened slice now
			"SuccessMessage": r.URL.Query().Get("success"),
			"ErrorMessage":   r.URL.Query().Get("error"),
		}

		ui.renderTemplate(w, r, "rules", data)
		return
	} //end "GET" or "HEAD"

	if r.Method == http.MethodPost { //"POST"
		// Serialize against a concurrent config Reload's loadQueryWhitelist()
		// (or a concurrent /apply-tables batch), exactly like applyTablesHandler
		// already does — this single-item path mutates+persists the same
		// RuleStore and is reachable whenever JavaScript is disabled (the
		// staged-batch UI is a JS-only affordance; see ui.html's noscript banner).
		ui.tableMutationMu.Lock()
		defer ui.tableMutationMu.Unlock()

		fields := map[string]string{
			"delete":  r.FormValue("delete"),
			"id":      r.FormValue("id"),
			"edit":    r.FormValue("edit"),
			"type":    r.FormValue("type"),
			"pattern": r.FormValue("pattern"),
			"enabled": r.FormValue("enabled"),
		}

		status, err := ui.processRuleChange(fields, ui.OnInvalidatePattern)
		if err != nil {
			//log.X happens inside the process*Change() above
			http.Error(w, err.Error(), status)
			return
		}

		if err := /*uses lock*/ ui.OnSaveWhitelist(); err != nil {
			redirectWithPersistFailure(w, r, "/rules", ui.logPersistFailure("whitelist", err))
			return
		}
		http.Redirect(w, r, "/rules", http.StatusSeeOther)
		return
	} //end "POST"
	ui.rejectUnsupportedMethod(w, r, allowedMethods)
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
	if logger != nil { //TODO: many other places need this guard, so maybe make helper ? and if it is nil log to stderr?!
		logger.Debug("Deleted rule", slog.Any("rule", entries[index])) // XXX: slog.Any is no longer forbidden for this struct
	}
	return newEntries
}

// SafeRuleAttr explicitly maps a RuleEntry struct to a safe slog.Attr group.
func SafeRuleAttr(key string, r RuleEntry) slog.Attr {
	return slog.Group(key,
		slog.String("id", r.ID),
		slog.String("pattern", r.Pattern),
		slog.Bool("enabled", r.Enabled),
		slog.Time("modified_at", r.ModifiedAt),
	)
}

// generateUniqueRuleID generates a UUID not already present in an arbitrary rule map.
// Used by loadQueryWhitelist (which works on a local copy) and by RuleStore methods
// (which call this while holding the write lock).
func generateUniqueRuleID(existingRules map[string][]RuleEntry, logger *slog.Logger) string {
	if logger == nil {
		panic2("BUG2: unexpected nil logger passed to generateUniqueRuleID")
	}
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

	// The short, 8-hex-char ID space is only 32 bits of entropy, so exhausting
	// triesOnCollision short-ID attempts can genuinely happen once the
	// whitelist grows large (ordinary birthday-paradox math, well before the
	// rule count approaches 2^32) — it is not actually a "should never
	// happen" bug, so crashing the entire DNS server over an ID-generation
	// retry budget would be disproportionate. Fall back to a full,
	// untruncated UUID (122 bits of randomness), whose collision probability
	// against any realistic rule count is negligible.
	for try := 1; try <= triesOnCollision; try++ {
		id := uuid.New().String()
		if _, collision := existing[id]; !collision {
			logger.Warn("Exhausted short-ID retries; fell back to a full-length UUID to guarantee uniqueness",
				slog.String("id", id), slog.Int("short_id_tries", triesOnCollision))
			return id
		}
	}

	// Reaching here means even full-length UUIDs are colliding, which really
	// would indicate a broken RNG or corrupted storage — that remains a hard
	// panic.
	msg := fmt.Sprintf("BUG: UUID collision limit reached even with full-length UUIDs after %d additional retries — check RNG or storage", triesOnCollision)
	logger.Error(msg, slog.Int("retries", triesOnCollision))
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
	Index             int
	CIDR              string
	Enabled           bool
	ModifiedAtDisplay string
}

type HostView struct {
	Index             int
	Pattern           string // ASCII/punycode identity — used for delete and old_pattern forms
	PatternDisplay    string // Unicode form for display/editing (same as Pattern when not an IDN)
	IPsDisplay        string // Pre-joined "1.1.1.1, 2.2.2.2"
	Enabled           bool   // whether this override is currently active (see LocalHostRule.Enabled)
	ModifiedAtDisplay string // Human-readable last-modified timestamp (see formatModifiedAt)
	// ModifiedAtSort    string // Unix-nanoseconds sort key for the "Last Modified" column (see modifiedAtSortValue)
}

// invalidateCacheForPattern surgically removes any cached DNS responses
// that match the given host pattern (handling wildcards correctly).
func (s *Server) invalidateCacheForPattern(pattern string) {
	cachee := s.getCache()
	log := s.getLogger()

	for key := range cachee.Items() {
		// key format is "domain:type" (e.g., "router.local:A")
		parts := strings.SplitN(key, ":", 2)
		if len(parts) > 0 {
			domain := parts[0]
			if matchPattern(pattern, domain) {
				cachee.Delete(key)
				// log.Debug("Evicted cached record due to rule change",
				// 	slog.String("key", key),
				// 	slog.String("matched_pattern", pattern),
				// 	slog.String("domain", domain))
				// Inside the eviction loop:
				displayPattern, patIsIDN := punycodeDecodePatternForDisplay(pattern)
				displayDomain, domIsIDN := punycodeDecodePatternForDisplay(domain)

				attrs := []any{slog.String("key", key), slog.String("matched_pattern", pattern), slog.String("domain", domain)}
				if patIsIDN {
					attrs = append(attrs, slog.String("matched_pattern_idn", displayPattern))
				}
				if domIsIDN {
					attrs = append(attrs, slog.String("domain_idn", displayDomain))
				}

				log.Debug("Evicted cached record due to rule change", attrs...)
			}
		}
	}
}

// invalidateCacheForPatterns is the batch counterpart of
// invalidateCacheForPattern: it performs a SINGLE pass over the DNS cache,
// evicting any entry whose domain matches ANY of the given patterns. Used
// by applyTablesHandler so that committing a large batch of staged
// rule/host changes costs one O(cache_size) scan total instead of one
// O(cache_size) scan per changed entry.
func (s *Server) invalidateCacheForPatterns(patterns map[string]struct{}) {
	if len(patterns) == 0 {
		return
	}
	cachee := s.getCache()
	log := s.getLogger()

	for key := range cachee.Items() {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) == 0 {
			continue
		}
		domain := parts[0]
		for pattern := range patterns {
			if matchPattern(pattern, domain) {
				cachee.Delete(key)
				log.Debug("Evicted cached record due to batch rule/host change",
					slog.String("key", key),
					slog.String("matched_pattern", pattern),
					slog.String("domain", domain))
				break
			}
		}
	}
}

// invalidateCacheForBlacklistedIPs invalidates every DNS cache entry whose
// contents could have been produced under the PREVIOUS blacklist state,
// following any add/edit/delete mutation to the response blacklist.
//
// This must be a full cache flush, not a surgical scan for currently-
// blacklisted IPs in cached Answer sections: a domain that was blocked
// because its upstream response contained a blacklisted IP is cached as the
// SYNTHETIC blockResponse() output (an NXDOMAIN or the configured block_ip,
// e.g. 0.0.0.0/::), not as the original filtered-out response — so the
// actual blacklisted IP is never present in the cached entry to scan for in
// the first place. A surgical "does this cached Answer still contain an IP
// that's still in the CURRENT blacklist" scan can therefore never detect
// that a blocked response's underlying cause was just removed (the
// blacklist entry is gone by the time this runs), silently keeping a
// domain blocked until its cache entry naturally expires — the inverse of
// what an admin just asked for by deleting the entry. The same blind spot
// also applies to HTTPS/SVCB ipv4hint/ipv6hint values when
// remove_https_ip_hints is false, since those never surface as *dns.A/AAAA
// records either. A full flush sidesteps all of this by construction.
//
// This is only reachable from single-item and batch WebUI blacklist
// mutations; on config Reload() the entire cache is already flushed
// unconditionally before the blacklist file is reloaded (see Reload()'s
// call to flushDNSCache before loadDependentStores), and at startup the
// cache is freshly created and empty, so this is a no-op in both of those
// cases regardless of implementation.
func (s *Server) invalidateCacheForBlacklistedIPs() {
	s.flushDNSCache()
}

func (ui *AdminUI) hostsHandler(w http.ResponseWriter, r *http.Request) {
	const allowedMethods = "GET, HEAD, POST, OPTIONS"
	if writeAllowHeaderResponse(w, r, allowedMethods) {
		return
	}

	/*
		(press alt+z to toggle line-wrapping to can read this, then toggle it back)
		According to the official HTTP specifications (RFC 7231), any endpoint that supports GET is technically supposed to support HEAD as well, returning identical headers but omitting the response body.
		If you want to be perfectly spec-compliant, Go makes it incredibly easy. You don't have to write any special code to strip the HTML layout for a HEAD request; Go's net/http server does it for you automatically. If a handler writes a body during a HEAD request, Go intercepts it, calculates the headers (like Content-Length), and drops the body before it hits the wire.
	*/
	// 2. Handle Read-Only requests
	if r.Method == http.MethodGet || r.Method == http.MethodHead { //"GET" or "HEAD"
		// 1 & 2. Get the thread-safe snapshot and build the template data
		data := map[string]any{
			//"Page":  "hosts",
			"Hosts":                            ui.hostStore.Snapshot(),
			"LocalHostsOverrideQueryBlocklist": ui.getConfig().LocalHostsOverrideQueryBlocklist,
			"SuccessMessage":                   r.URL.Query().Get("success"),
			"ErrorMessage":                     r.URL.Query().Get("error"),
		}

		ui.renderTemplate(w, r, "hosts", data)
		return
	} //end "GET" or "HEAD"

	if r.Method == http.MethodPost { //"POST" {
		// See the identical lock in rulesHandler's POST branch for why this
		// single-item path must also serialize against Reload()/batch-apply.
		ui.tableMutationMu.Lock()
		defer ui.tableMutationMu.Unlock()

		fields := map[string]string{
			"delete":      r.FormValue("delete"),
			"pattern":     r.FormValue("pattern"),
			"old_pattern": r.FormValue("old_pattern"),
			"edit":        r.FormValue("edit"),
			"ips":         r.FormValue("ips"),
			"enabled":     r.FormValue("enabled"),
		}

		status, err := ui.processHostChange(fields, ui.OnInvalidatePattern)
		if err != nil {
			http.Error(w, err.Error(), status)
			return
		}

		if err := ui.OnSaveHosts(); err != nil {
			redirectWithPersistFailure(w, r, "/hosts", ui.logPersistFailure("local hosts", err))
			return
		}
		http.Redirect(w, r, "/hosts", http.StatusSeeOther)
		return
	} // end of "POST"

	ui.rejectUnsupportedMethod(w, r, allowedMethods)
}

// renderTemplate is a DRY helper to execute templates safely into a buffer
// before writing to the network, preventing "established connection aborted" errors
// from being logged as template execution failures.
// tableVersionToken returns the current combined optimistic-concurrency
// version token for a rules/hosts/response-blacklist table: the in-memory
// store's own mutation-generation counter (catches a race against a
// concurrent WebUI mutation or Reload()) composed with the backing JSON
// file's on-disk modification time (additionally catches the file being
// changed by something OTHER than this process — a hand-edit or an
// external tool — that the in-memory generation counter alone has no way to
// see; mirrors the identical mtime-based approach configHandler already
// uses for config.json's own optimistic-concurrency check).
//
// The returned string is opaque to every caller on both ends: app.js only
// ever compares it for exact equality and never parses it, so this format
// can change freely without touching app.js. path is the table's backing
// file (cfg.WhitelistFile / cfg.HostsFile / cfg.BlacklistFile).
func tableVersionToken(generation uint64, path string) string {
	mtimeToken := "0"
	if fi, err := os.Stat(path); err == nil {
		mtimeToken = strconv.FormatInt(fi.ModTime().UnixNano(), 10)
	}
	// A stat failure for any reason (including "doesn't exist yet") falls
	// back to "0", exactly like configHandler's identical config.json
	// version check: there's no reliable mtime to compare against right
	// now, and refusing every apply outright until a transient issue
	// clears would be worse than occasionally missing a concurrent external
	// edit in that narrow window.
	return strconv.FormatUint(generation, 10) + ":" + mtimeToken
}

// queryBlocklistVersionToken returns the current optimistic-concurrency
// version token for the query-blocklist table (see tableVersionToken),
// mirroring RulesVersion/HostsVersion/BlacklistVersion for the whitelist,
// hosts, and response-blacklist tables. Returns "0" if the query-blocklist
// feature isn't wired up in this environment (nil ui.queryBlocklistStore —
// see that field's doc comment on AdminUI).
func (ui *AdminUI) queryBlocklistVersionToken() string {
	if ui.queryBlocklistStore == nil {
		return "0"
	}
	return tableVersionToken(ui.queryBlocklistStore.Generation(), ui.getConfig().QueryBlocklistFile)
}

func (ui *AdminUI) renderTemplate(w http.ResponseWriter, r *http.Request, pageName string, data map[string]any) {
	log := ui.getLogger()
	data["Page"] = pageName //Page aka TemplateName (tho the latter isn't used, but AI might suggest it mistakenly)
	data["Path"] = r.URL.Path
	data["Version"] = GetVersion() //cache-busting

	cfg := ui.getConfig()
	data["RulesVersion"] = tableVersionToken(ui.ruleStore.Generation(), cfg.WhitelistFile)
	data["HostsVersion"] = tableVersionToken(ui.hostStore.Generation(), cfg.HostsFile)
	data["BlacklistVersion"] = tableVersionToken(ui.blacklist.Generation(), cfg.BlacklistFile)
	data["QueryBlocklistVersion"] = ui.queryBlocklistVersionToken()

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

// buildIsUnblockedPredicate reports whether a specific (domain, qtype)
// recent-block entry currently has its OWN enabled whitelist rule — i.e.
// whether the operator specifically unblocked THIS entry, not merely
// whether a query for it would resolve right now.
//
// This deliberately does NOT also treat an HTTPS entry as "unblocked"
// merely because AllowHTTPSIfAAllowed lets an A rule for the same domain
// authorize HTTPS queries too (see handleDNSQuery's identical fallback):
// that fallback is a DNS-resolution-time convenience, not a statement that
// an HTTPS rule exists to pause. Conflating the two made the /blocks page
// show a stale HTTPS entry as "Re-block (Pause)" — implying there was an
// active HTTPS rule to pause — when no such rule was ever created, so
// clicking Re-block silently did nothing (SetEnabled found no HTTPS rule
// to disable).
//
// This also deliberately checks for an EXACT-pattern rule (via
// RuleStore.HasExactEnabledPattern), not merely whether some rule —
// possibly a wildcard like "*.example.com" — would currently match this
// domain (which MatchForType, wildcards included, would report). The
// /blocks page's "Re-block (Pause)" button can only ever act on an exact
// pattern (via SetEnabled/quickToggleExactRule), so reporting "unblocked"
// based on a broader wildcard match let the button appear even though
// clicking it would find no matching rule to disable and fail silently.
func (ui *AdminUI) buildIsUnblockedPredicate() func(domain, qtype string) bool {
	return func(domain, qtype string) bool {
		return ui.ruleStore.HasExactEnabledPattern(qtype, domain)
	}
}

func (ui *AdminUI) getRecentBlocksCopy() []BlockedQuery {
	blocks := ui.recentBlocks.Snapshot(ui.buildIsUnblockedPredicate())
	for i := range blocks {
		blocks[i].DomainDisplay, _ = punycodeDecodePatternForDisplay(blocks[i].Domain)
		ui.populateQueryBlocklistRowState(&blocks[i])
	}
	return blocks
}

// buildIsLocallyBlockedPredicate mirrors buildIsUnblockedPredicate but for
// the query-blocklist "block" layer, used by the /allows page's "Clear
// Shown Allows" action: an entry the operator just blocked via the quick
// "Block" button stays visible (still showing "Unblock (Pause)") rather
// than being cleared out from under them.
func (ui *AdminUI) buildIsLocallyBlockedPredicate() func(domain, qtype string) bool {
	return func(domain, _ string) bool {
		if ui.queryBlocklistStore == nil {
			return false
		}
		_, matched := ui.queryBlocklistStore.MatchForType(queryBlockCategoryBlock, domain)
		return matched
	}
}

// buildIsQueryBlocklistUnblockedPredicate reports whether a specific (domain,
// qtype) recent-block entry is no longer blocked by the query-blocklist layer
// (see checkQueryBlocklist) — i.e. the operator has since disabled the local
// "block" rule that matched it, or added/enabled an "except" rule cancelling
// an external-source block. Mirrors buildIsUnblockedPredicate's whitelist-layer
// semantics ("does this entry currently have an active control to re-block
// it") so ClearBefore preserves exactly the entries still worth showing an
// operator a revert control for.
func (ui *AdminUI) buildIsQueryBlocklistUnblockedPredicate() func(domain, qtype string) bool {
	return func(domain, _ string) bool {
		if ui.queryBlocklistStore != nil {
			if _, ok := ui.queryBlocklistStore.MatchForType(queryBlockCategoryBlock, domain); ok {
				return false // still locally blocked
			}
		}
		if ui.externalBlocklist != nil && ui.externalBlocklist.Load().Contains(domain) {
			if ui.queryBlocklistStore != nil {
				// Exact-pattern (see RuleStore.HasExactEnabledPattern's doc
				// comment): mirrors QueryBlocklistExternalExcepted / the
				// "Re-block (Pause)" button's own exact-match requirement, so
				// a domain only excepted via a broader wildcard rule is
				// treated the same as "still blocked" here too, and its
				// recent-blocks entry is preserved (not cleared) exactly as
				// if no except rule existed at all.
				if ui.queryBlocklistStore.HasExactEnabledPattern(queryBlockCategoryExcept, domain) {
					return true // excepted -> currently unblocked, has a Re-block control
				}
			}
			return false // still blocked by the external source, no except in effect
		}
		return true // not blocked by either query-blocklist sub-layer anymore
	}
}

// buildIsRecentBlockUnblockedPredicate returns the isUnblocked predicate used
// by "Clear Shown Blocks" (see recentBlocks.ClearBefore) for the /blocks
// page's "Recent Blocks" list. A recorded block there can come from either
// the query blocklist (checkQueryBlocklist, active regardless of
// whitelist_mode) or, only when whitelist_mode is true, from lacking an
// enabled whitelist rule (see handleDNSQuery). An entry is preserved from
// clearing if EITHER layer that could have caused it currently has it
// unblocked, so whichever revert control the operator used stays visible.
func (ui *AdminUI) buildIsRecentBlockUnblockedPredicate() func(domain, qtype string) bool {
	qbUnblocked := ui.buildIsQueryBlocklistUnblockedPredicate()
	if !ui.getConfig().WhitelistMode {
		// Outside whitelist_mode, whitelist rules never cause a recentBlocks
		// entry (see handleDNSQuery's allowed=true short-circuit), so
		// checking them here would only add noise.
		return qbUnblocked
	}
	whitelistUnblocked := ui.buildIsUnblockedPredicate()
	return func(domain, qtype string) bool {
		return whitelistUnblocked(domain, qtype) || qbUnblocked(domain, qtype)
	}
}

// getRecentAllowedCopy mirrors getRecentBlocksCopy but sources its entries
// from ui.recentAllowed instead of ui.recentBlocks — used for the
// dedicated TheAllowsPage page ("Recent Allows"), populated regardless of
// whitelist_mode (see recentAllowed's doc comment). IsUnblocked is always
// left at its zero value (false) here since the whitelist-based
// unblock/reblock concept doesn't apply to this list; only the
// query-blocklist "block" state (QueryBlocklistLocalBlocked et al.,
// populated below) is meaningful.
func (ui *AdminUI) getRecentAllowedCopy() []BlockedQuery {
	if ui.recentAllowed == nil {
		return nil
	}
	allowed := ui.recentAllowed.Snapshot(func(_, _ string) bool { return false })
	for i := range allowed {
		allowed[i].DomainDisplay, _ = punycodeDecodePatternForDisplay(allowed[i].Domain)
		ui.populateQueryBlocklistRowState(&allowed[i])
	}
	return allowed
}

// populateQueryBlocklistRowState fills bq's four QueryBlocklist* fields by
// re-evaluating the query-blocklist layer live against bq.Domain — never
// from any cached/stored state — mirroring exactly how buildIsUnblockedPredicate
// re-evaluates the whitelist layer live for the same row. Safe to call with a
// nil ui.queryBlocklistStore/externalBlocklist (both simply leave every field
// at its zero value, i.e. "this layer isn't blocking/configured"), matching
// checkQueryBlocklist's own nil-safety.
func (ui *AdminUI) populateQueryBlocklistRowState(bq *BlockedQuery) {
	if ui.queryBlocklistStore != nil {
		if id, ok := ui.queryBlocklistStore.MatchForType(queryBlockCategoryBlock, bq.Domain); ok {
			bq.QueryBlocklistLocalBlocked = true
			bq.QueryBlocklistLocalRuleID = id
		}
	}
	if ui.externalBlocklist != nil && ui.externalBlocklist.Load().Contains(bq.Domain) {
		bq.QueryBlocklistExternalListed = true
		if ui.queryBlocklistStore != nil {
			// Deliberately exact-pattern (see RuleStore.HasExactEnabledPattern's
			// doc comment): the "Re-block (Pause)" button this flag drives
			// disables the except rule via an exact-pattern SetEnabled call
			// (quickToggleExactRule), which a wildcard except rule matching
			// bq.Domain only via wildcard expansion could not actually satisfy.
			if ui.queryBlocklistStore.HasExactEnabledPattern(queryBlockCategoryExcept, bq.Domain) {
				bq.QueryBlocklistExternalExcepted = true
			}
		}
	}
}

// blocksAjaxHeader is the custom header the /blocks, /allows, and
// /query-blocklist pages' JS sets on their background fetch() calls (see
// the shared js-block-action-form wiring in app.js) so their handlers can
// respond with a plain status code instead of a redirect+querystring,
// avoiding a full page reload for every Unblock/Re-block/Block/Except click.
const blocksAjaxHeader = "X-DNSBollocks-Ajax"

func isBlocksAjaxRequest(r *http.Request) bool {
	return r.Header.Get(blocksAjaxHeader) == "1"
}

// respondBlocksResult replies to a /blocks, /allows, or /query-blocklist quick-action
// POST either with a redirect back to whichever page issued the request, carrying
// success/error
// query params (progressive-enhancement fallback for non-JS clients,
// preserving the existing full-page-reload behavior) or, for background/AJAX
// requests (see isBlocksAjaxRequest), with a plain status code and short text
// body so the caller can update the UI in place without a full page reload.
func respondBlocksResult(log *slog.Logger, w http.ResponseWriter, r *http.Request, redirectPath string, ok bool, status int, message, enteredValue string) {
	if isBlocksAjaxRequest(r) {
		// Always treat AJAX block-action responses as plain text.
		// This eliminates any XSS surface (G705) and matches what the
		// frontend (app.js) expects in .textContent / .block-action-feedback.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if ok {
			w.WriteHeader(http.StatusOK)
			// message comes from server-controlled strings or safe user input
			// that has already been validated. No HTML escaping needed for text/plain.
			if _, err := io.WriteString(w, message); err != nil { //nolint:gosec // G705 XSS via taint analysis (gosec) // it's handled
				// Client disconnected — common and harmless for fire-and-forget status updates.
				log.Debug("client disconnected before AJAX status write completed",
					wincoe.SafeErr(err))
			}
		} else {
			//http.Error(w, message, status)

			// Use our own path so we keep the Content-Type we just set and
			// don't let http.Error force text/html.
			w.WriteHeader(status)
			if _, err := io.WriteString(w, message); err != nil { //nolint:gosec // G705 XSS via taint analysis (gosec) // it's handled
				log.Debug("client disconnected before AJAX error write", wincoe.SafeErr(err))
			}
		}
		return
	}
	// Redirect back to whichever page issued this POST (either TheBlocksPage or
	// TheAllowsPage — this helper is shared by both blocksHandler and
	// allowsHandler) rather than a hardcoded path, so the non-AJAX
	// (progressive-enhancement) fallback always lands the user back on the
	// page they were actually using.
	if ok {
		http.Redirect(w, r, redirectPath+"?success="+url.QueryEscape(message), http.StatusSeeOther)
		return
	}
	redirectURL := redirectPath + "?error=" + url.QueryEscape(message)
	if enteredValue != "" {
		redirectURL += "&val=" + url.QueryEscape(enteredValue)
	}
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (ui *AdminUI) blocksHandler(w http.ResponseWriter, r *http.Request) {
	const allowedMethods = "GET, HEAD, POST, OPTIONS"
	if writeAllowHeaderResponse(w, r, allowedMethods) {
		return
	}
	log := ui.getLogger()

	if r.Method == http.MethodGet || r.Method == http.MethodHead { //"GET" or "HEAD" {
		cfg := ui.getConfig()
		data := map[string]any{
			"Blocks":         ui.getRecentBlocksCopy(),
			"WhitelistMode":  cfg.WhitelistMode,
			"SuccessMessage": r.URL.Query().Get("success"),
			"ErrorMessage":   r.URL.Query().Get("error"),
			"EnteredValue":   r.URL.Query().Get("val"),
			// Inject current timestamp as a string so it easily embeds in the HTML
			"RenderTime": fmt.Sprintf("%d", time.Now().UnixNano()),
		}

		ui.renderTemplate(w, r, "blocks", data)
		return
	} //end GET HEAD

	if r.Method == http.MethodPost { //"POST" {
		action := r.FormValue("action")

		switch action {
		case "reblock_qb", "unblock_qb", "disable_qb_local_rule":
			if ui.queryBlocklistStore == nil || ui.OnSaveQueryBlocklist == nil {
				log.Error("BUG: query-blocklist /blocks POST action reached without queryBlocklistStore/OnSaveQueryBlocklist wired", slog.String("action", action))
				respondBlocksResult(log, w, r, TheBlocksPage, false, http.StatusServiceUnavailable, "query blocklist is not available in this environment", "")
				return
			}
		}

		// --- Handle the Clear action ---
		if action == "clear" {
			cutoffStr := r.FormValue("cutoff")
			cutoffNano, err := strconv.ParseInt(cutoffStr, 10, 64)
			if err != nil {
				log.Warn("Failed to clear blocks: invalid cutoff timestamp", slog.String("cutoff", cutoffStr), wincoe.SafeErr(err))
				respondBlocksResult(log, w, r, TheBlocksPage, false, http.StatusBadRequest, "Invalid cutoff timestamp.", "")
				return
			}
			cutoff := time.Unix(0, cutoffNano)

			// Only clear rows that no longer have an active revert control
			// (still actively blocked by whichever layer caused them).
			// Rows still showing a Re-block/Unblock control are preserved
			// — see buildIsRecentBlockUnblockedPredicate's doc comment.
			cleared := ui.recentBlocks.ClearBefore(cutoff, ui.buildIsRecentBlockUnblockedPredicate())
			msg := fmt.Sprintf("Cleared %d recent block(s) from the list.", cleared)
			log.Info("WebUI: Cleared visible recent blocks", slog.Int("cleared", cleared))

			respondBlocksResult(log, w, r, TheBlocksPage, true, http.StatusOK, msg, "")
			return
		}
		// --- END Clear action ---

		// Quick unblock/reblock mutates the RuleStore (whitelist) or the
		// query-blocklist RuleStore and persists it, exactly like the
		// single-item /rules POST path — serialize against a concurrent
		// Reload()/batch-apply for the same reason (see the lock in
		// rulesHandler's POST branch).
		ui.tableMutationMu.Lock()
		defer ui.tableMutationMu.Unlock()

		raw := r.FormValue("domain")
		domainLowercased, displayDomain, sanitizeErr := sanitizeBlocksQuickActionDomain(raw)
		if sanitizeErr != nil {
			log.Warn("Invalid domain input submitted via Quick Unblock (blocks)",
				slog.String("raw", raw), wincoe.SafeErr(sanitizeErr))
			respondBlocksResult(log, w, r, TheBlocksPage, false, http.StatusBadRequest, "Invalid domain format. Please enter a valid domain name.", raw)
			return
		}

		typ := r.FormValue("type")

		if domainLowercased == "" || typ == "" {
			payloadDetails := fmt.Sprintf("Missing or corrupted data. (Processed Domain: %q, Type: %q)", domainLowercased, typ)
			attrs := []any{slog.String("domain", domainLowercased), slog.String("type", typ)}
			if displayDomain != domainLowercased {
				attrs = append(attrs, slog.String("domain_idn", displayDomain))
			}
			log.Warn("Failed quick unblock/reblock via WebUI: missing domain or type", attrs...)
			respondBlocksResult(log, w, r, TheBlocksPage, false, http.StatusBadRequest, "Failed to process unblock request. "+payloadDetails, raw)
			return
		}

		var successMessage string
		switch action {
		case "reblock", "unblock":
			msg, toggleErr := quickToggleExactRule(ui.ruleStore, typ, domainLowercased, displayDomain, action == "unblock", log, "whitelist")
			if toggleErr != nil {
				log.Warn("Failed quick unblock/reblock via WebUI (whitelist)",
					slog.String("action", action), wincoe.SafeErr(toggleErr),
					slog.String("domainLowercased", domainLowercased), slog.String("displayDomain", displayDomain), slog.String("DNSType", typ))
				respondBlocksResult(log, w, r, TheBlocksPage, false, http.StatusNotFound, toggleErr.Error(), raw)
				return
			}
			successMessage = msg
			log.Info("Quick "+action+" via WebUI (whitelist)",
				slog.String("domainLowercased", domainLowercased), slog.String("displayDomain", displayDomain), slog.String("DNSType", typ))
			ui.OnInvalidatePattern(domainLowercased)

		case "reblock_qb", "unblock_qb", "disable_qb_local_rule":
			msg, status, qbErr := ui.processQueryBlocklistQuickAction(action, domainLowercased, displayDomain, r.FormValue("id"))
			if qbErr != nil {
				respondBlocksResult(log, w, r, TheBlocksPage, false, status, qbErr.Error(), raw)
				return
			}
			successMessage = msg

		default:
			log.Warn("Failed quick unblock/reblock via WebUI: invalid action specified", slog.String("action", action))
			respondBlocksResult(log, w, r, TheBlocksPage, false, http.StatusBadRequest, "Invalid action specified", raw)
			return
		} //switch

		// Both the whitelist rule store and the query-blocklist rule store
		// may have just been mutated above (never both in the same
		// request, since action selects exactly one branch), so persist
		// whichever one actually changed.
		var saveErr error
		switch action {
		case "reblock_qb", "unblock_qb", "disable_qb_local_rule":
			saveErr = ui.OnSaveQueryBlocklist()
			if saveErr != nil {
				saveErr = ui.logPersistFailure("query blocklist", saveErr)
			}
		default:
			saveErr = /*uses lock*/ ui.OnSaveWhitelist()
			if saveErr != nil {
				saveErr = ui.logPersistFailure("whitelist", saveErr)
			}
		}
		if saveErr != nil {
			respondBlocksResult(log, w, r, TheBlocksPage, false, http.StatusInternalServerError, saveErr.Error(), "")
			return
		}
		respondBlocksResult(log, w, r, TheBlocksPage, true, http.StatusOK, successMessage, "")
		return
	} // end "POST"
	ui.rejectUnsupportedMethod(w, r, allowedMethods)
} // end blocksHandler

// sanitizeBlocksQuickActionDomain normalizes and validates the "domain" form
// field submitted by the /blocks and /allows pages' quick-action forms
// (Unblock/Reblock, Block, etc.). It first converts any Unicode (IDN)
// domain (e.g. "café.com") to punycode/ASCII, exactly as a browser would
// before ever sending the query on the wire, so the character-set/validity
// checks below don't reject it as "containing illegal characters". Returns
// the ASCII/punycode form (used for every store lookup/mutation) and its
// Unicode display form (used only in human-facing messages).
func sanitizeBlocksQuickActionDomain(raw string) (domainLowercased, displayDomain string, err error) {
	encodedRaw, _, encErr := punycodeEncodePattern(NormalizeDomain(raw))
	if encErr != nil {
		return "", "", fmt.Errorf("invalid domain format: %w", encErr)
	}

	sanitized, modified := sanitizeDomainInput(encodedRaw)
	if modified || !isValidDNSName(sanitized) { // XXX: doesn't expect a pattern here, but an actual valid DNS query domain (and without ending in a dot)
		return "", "", fmt.Errorf("invalid domain format %q", raw)
	}

	domainLowercased = strings.ToLower(sanitized) //XXX: must keep it lowercased for matchPattern() later on.
	displayDomain, _ = punycodeDecodePatternForDisplay(domainLowercased)
	return domainLowercased, displayDomain, nil
}

// processQueryBlocklistQuickAction implements the shared query-blocklist
// quick-action logic — reblock_qb / unblock_qb / disable_qb_local_rule /
// block_qb_local — used by blocksHandler (TheBlocksPage), allowsHandler
// (TheAllowsPage), and queryBlocklistHandler's external hosts-file search
// (unblock_qb/reblock_qb only, for a host surfaced by
// AdminUI.buildExternalHostMatches) for their per-row quick controls.
// Callers must already hold
// ui.tableMutationMu and must have already confirmed
// ui.queryBlocklistStore/ui.OnSaveQueryBlocklist are wired (see either
// handler's guard at the top of its POST branch). ruleID is only used by
// "disable_qb_local_rule" (the "id" form field); it may be empty for the
// other three actions.
//
// On success this has already invalidated whatever cache pattern(s) the
// change affects; callers are only responsible for persisting via
// ui.OnSaveQueryBlocklist and writing the HTTP response.
func (ui *AdminUI) processQueryBlocklistQuickAction(action, domainLowercased, displayDomain, ruleID string) (successMessage string, status int, err error) {
	log := ui.getLogger()

	switch action {
	case "reblock_qb", "unblock_qb":
		// Query-blocklist "except" layer: an "except" rule only ever
		// cancels an EXTERNAL-source block (see checkQueryBlocklist's doc
		// comment); it never overrides a local "block" pattern.
		msg, toggleErr := quickToggleExactRule(ui.queryBlocklistStore, queryBlockCategoryExcept, domainLowercased, displayDomain, action == "unblock_qb", log, "query blocklist: external-source except")
		if toggleErr != nil {
			log.Warn("Failed quick unblock/reblock via WebUI (query-blocklist except)",
				slog.String("action", action), wincoe.SafeErr(toggleErr),
				slog.String("domainLowercased", domainLowercased), slog.String("displayDomain", displayDomain))
			return "", http.StatusNotFound, toggleErr
		}
		log.Info("Quick "+action+" via WebUI (query-blocklist except)",
			slog.String("domainLowercased", domainLowercased), slog.String("displayDomain", displayDomain))
		ui.OnInvalidatePattern(domainLowercased)
		return msg, http.StatusOK, nil

	case "disable_qb_local_rule":
		// Disables the specific local "block" rule (matched earlier, by ID
		// — see the "id" form field) that is currently blocking this
		// domain outright. One-directional: re-enabling it is done from
		// the /query-blocklist page itself.
		if ruleID == "" {
			log.Warn("Failed to disable query-blocklist local rule: missing id", slog.String("domainLowercased", domainLowercased))
			return "", http.StatusBadRequest, errors.New("missing rule id")
		}
		pattern, found, changed := ui.queryBlocklistStore.SetEnabledByID(queryBlockCategoryBlock, ruleID, false, log)
		if !found {
			log.Warn("Failed to disable query-blocklist local rule: not found",
				slog.String("id", ruleID), slog.String("domainLowercased", domainLowercased))
			return "", http.StatusNotFound, errors.New("that query-blocklist rule no longer exists")
		}
		if !changed {
			return fmt.Sprintf("Local query-blocklist rule for %s is already disabled.", displayDomain), http.StatusOK, nil
		}
		log.Info("Quick-disabled query-blocklist local block rule via WebUI",
			slog.String("id", ruleID), slog.String("pattern", pattern), slog.String("domainLowercased", domainLowercased))
		ui.OnInvalidatePattern(pattern)
		return fmt.Sprintf("Disabled the local query-blocklist rule blocking %s.", displayDomain), http.StatusOK, nil

	case "block_qb_local":
		// Quick "Block" action: creates (or re-enables, if a matching
		// disabled rule already exists) an exact-pattern local
		// query-blocklist "block" rule for this domain. Unlike whitelist
		// rules, query-blocklist rules are type-agnostic (see
		// checkQueryBlocklist's doc comment), so this applies to every
		// query type for the domain at once.
		found, changed := ui.queryBlocklistStore.SetEnabled(queryBlockCategoryBlock, domainLowercased, true, log)
		var msg string
		switch {
		case found && changed:
			msg = fmt.Sprintf("Blocked %s: activated an existing paused local query-blocklist rule.", displayDomain)
		case found:
			msg = fmt.Sprintf("%s is already blocked by an existing local query-blocklist rule.", displayDomain)
		default:
			if _, addErr := ui.queryBlocklistStore.AddRule(queryBlockCategoryBlock, domainLowercased, true, log); addErr != nil {
				log.Warn("Failed quick block via WebUI (query-blocklist local block)",
					wincoe.SafeErr(addErr),
					slog.String("domainLowercased", domainLowercased), slog.String("displayDomain", displayDomain))
				return "", http.StatusConflict, addErr
			}
			msg = fmt.Sprintf("Blocked %s: added a new local query-blocklist rule.", displayDomain)
		}
		log.Info("Quick block via WebUI (query-blocklist local block)",
			slog.String("domainLowercased", domainLowercased), slog.String("displayDomain", displayDomain))
		ui.OnInvalidatePattern(domainLowercased)
		return msg, http.StatusOK, nil

	default:
		return "", http.StatusBadRequest, fmt.Errorf("invalid action specified: %q", action)
	}
}

// allowsHandler serves the dedicated TheAllowsPage page ("Recent Allows"), the
// sibling of TheBlocksPage ("Recent Blocks"): a list of recently allowed
// (resolved) queries, populated regardless of whitelist_mode (see
// recentAllowed's doc comment), with a quick way to add a local
// query-blocklist "block" rule for one — the query blocklist is always
// checked before any whitelist decision, so this works identically whether
// the domain was allowed via a matching whitelist rule/host override
// (whitelist_mode=true) or simply because whitelist_mode is off.
func (ui *AdminUI) allowsHandler(w http.ResponseWriter, r *http.Request) {
	const allowedMethods = "GET, HEAD, POST, OPTIONS"
	if writeAllowHeaderResponse(w, r, allowedMethods) {
		return
	}
	log := ui.getLogger()

	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		cfg := ui.getConfig()
		data := map[string]any{
			"Allowed":        ui.getRecentAllowedCopy(),
			"WhitelistMode":  cfg.WhitelistMode,
			"SuccessMessage": r.URL.Query().Get("success"),
			"ErrorMessage":   r.URL.Query().Get("error"),
			"EnteredValue":   r.URL.Query().Get("val"),
			"RenderTime":     fmt.Sprintf("%d", time.Now().UnixNano()),
		}
		ui.renderTemplate(w, r, "allows", data)
		return
	}

	if r.Method == http.MethodPost {
		action := r.FormValue("action")

		switch action {
		case "reblock_qb", "unblock_qb", "disable_qb_local_rule", "block_qb_local":
			if ui.queryBlocklistStore == nil || ui.OnSaveQueryBlocklist == nil {
				log.Error("BUG: query-blocklist /allows POST action reached without queryBlocklistStore/OnSaveQueryBlocklist wired", slog.String("action", action))
				respondBlocksResult(log, w, r, TheAllowsPage, false, http.StatusServiceUnavailable, "query blocklist is not available in this environment", "")
				return
			}
		}

		// --- Handle the Clear action ---
		if action == "clear" {
			cutoffStr := r.FormValue("cutoff")
			cutoffNano, err := strconv.ParseInt(cutoffStr, 10, 64)
			if err != nil {
				log.Warn("Failed to clear allows: invalid cutoff timestamp", slog.String("cutoff", cutoffStr), wincoe.SafeErr(err))
				respondBlocksResult(log, w, r, TheAllowsPage, false, http.StatusBadRequest, "Invalid cutoff timestamp.", "")
				return
			}
			cutoff := time.Unix(0, cutoffNano)

			var cleared int
			if ui.recentAllowed != nil {
				// Preserve rows the operator just blocked (still showing
				// "Unblock (Pause)") — see buildIsLocallyBlockedPredicate's
				// doc comment.
				cleared = ui.recentAllowed.ClearBefore(cutoff, ui.buildIsLocallyBlockedPredicate())
			}
			msg := fmt.Sprintf("Cleared %d recent allow(s) from the list.", cleared)
			log.Info("WebUI: Cleared visible recent allows", slog.Int("cleared", cleared))

			respondBlocksResult(log, w, r, TheAllowsPage, true, http.StatusOK, msg, "")
			return
		}
		// --- END Clear action ---

		// Quick block/unblock mutates the query-blocklist RuleStore and
		// persists it — serialize against a concurrent Reload()/batch-apply,
		// exactly like blocksHandler's identical quick-action path.
		ui.tableMutationMu.Lock()
		defer ui.tableMutationMu.Unlock()

		raw := r.FormValue("domain")
		domainLowercased, displayDomain, sanitizeErr := sanitizeBlocksQuickActionDomain(raw)
		if sanitizeErr != nil {
			log.Warn("Invalid domain input submitted via Quick Block (allows)",
				slog.String("raw", raw), wincoe.SafeErr(sanitizeErr))
			respondBlocksResult(log, w, r, TheAllowsPage, false, http.StatusBadRequest, "Invalid domain format. Please enter a valid domain name.", raw)
			return
		}

		typ := r.FormValue("type")
		if domainLowercased == "" || typ == "" {
			payloadDetails := fmt.Sprintf("Missing or corrupted data. (Processed Domain: %q, Type: %q)", domainLowercased, typ)
			attrs := []any{slog.String("domain", domainLowercased), slog.String("type", typ)}
			if displayDomain != domainLowercased {
				attrs = append(attrs, slog.String("domain_idn", displayDomain))
			}
			log.Warn("Failed quick block via WebUI (allows): missing domain or type", attrs...)
			respondBlocksResult(log, w, r, TheAllowsPage, false, http.StatusBadRequest, "Failed to process request. "+payloadDetails, raw)
			return
		}

		switch action {
		case "reblock_qb", "unblock_qb", "disable_qb_local_rule", "block_qb_local":
			// handled below via the shared query-blocklist quick-action helper
		default:
			log.Warn("Failed quick block via WebUI (allows): invalid action specified", slog.String("action", action))
			respondBlocksResult(log, w, r, TheAllowsPage, false, http.StatusBadRequest, "Invalid action specified", raw)
			return
		}

		successMessage, status, qbErr := ui.processQueryBlocklistQuickAction(action, domainLowercased, displayDomain, r.FormValue("id"))
		if qbErr != nil {
			respondBlocksResult(log, w, r, TheAllowsPage, false, status, qbErr.Error(), raw)
			return
		}

		if err := ui.OnSaveQueryBlocklist(); err != nil {
			respondBlocksResult(log, w, r, TheAllowsPage, false, http.StatusInternalServerError, ui.logPersistFailure("query blocklist", err).Error(), "")
			return
		}
		respondBlocksResult(log, w, r, TheAllowsPage, true, http.StatusOK, successMessage, "")
		return
	}

	ui.rejectUnsupportedMethod(w, r, allowedMethods)
} // end allowsHandler

// logKind identifies which of the three on-disk log files (see
// Config.LogEverythingFile, Config.LogQueriesFile, Config.LogQueriesSimpleFile)
// a /logs* handler wants, so activeLogFilePath and logPathMismatchNotice can
// share one implementation across all three call sites instead of
// duplicating the same three-way switch in each handler.
type logKind int

const (
	logKindEverything logKind = iota
	logKindQueries
	logKindQueriesSimple
)

// configuredLogFilename returns the bare (no directory) filename Config
// currently specifies for kind.
func configuredLogFilename(cfg *Config, kind logKind) string {
	switch kind {
	case logKindEverything:
		return cfg.LogEverythingFile
	case logKindQueries:
		return cfg.LogQueriesFile
	case logKindQueriesSimple:
		return cfg.LogQueriesSimpleFile
	default:
		panic2(fmt.Sprintf("BUG: configuredLogFilename: unhandled logKind %d", kind))
		panic(nil)
	}
}

// activeLogFilename extracts the filename for kind out of the four values
// returned by LoggerManager.ActiveLogPaths.
func activeLogFilename(kind logKind, everythingFile, queriesFile, queriesSimpleFile string) string {
	switch kind {
	case logKindEverything:
		return everythingFile
	case logKindQueries:
		return queriesFile
	case logKindQueriesSimple:
		return queriesSimpleFile
	default:
		panic2(fmt.Sprintf("BUG: activeLogFilename: unhandled logKind %d", kind))
		panic(nil)
	}
}

// activeLogFilePath returns the on-disk path the CURRENTLY ACTIVE logger is
// writing to for the given log kind. It prefers LoggerManager's own record of
// what it actually opened (see LoggerManager.ActiveLogPaths) over the live
// Config's own paths, since the two can diverge after a Reload() whose
// LogMgr.ApplyConfig() call failed partway through: the live Config is
// already swapped to the NEW, possibly-unusable paths at that point (see
// Server.Reload's doc comment), while the logger itself keeps writing to the
// OLD paths that LoggerManager recorded. Falls back to resolving straight
// from the live Config if ui.logMgr is nil (tests constructing AdminUI
// without a full Runtime) or hasn't recorded any active paths yet
// (defensive; should never happen in production once logging has been
// initialized at least once, which OldMain guarantees before AdminUI is
// ever reachable).
func (ui *AdminUI) activeLogFilePath(kind logKind) string {
	cfg := ui.getConfig()
	fallback := resolveLogFilePath(cfg.LogDir, configuredLogFilename(cfg, kind))

	dir, everythingFile, queriesFile, queriesSimpleFile := ui.logMgr.ActiveLogPaths()
	filename := activeLogFilename(kind, everythingFile, queriesFile, queriesSimpleFile)
	if filename == "" {
		// Config-derived filenames are never empty once sanitizeAndValidateConfig
		// has run (cleanLogFileName always falls back to a non-empty default), so
		// an empty filename here unambiguously means ActiveLogPaths has nothing
		// recorded yet, not a legitimately-empty configured value.
		return fallback
	}
	return resolveLogFilePath(dir, filename)
}

// logPathMismatchNotice returns a human-readable notice (ending in a blank
// line, ready to prepend directly to log page content) if the live Config's
// currently-configured path for kind no longer matches activePath — the path
// activeLogFilePath resolved as what the logger is actually writing to.
// Returns "" when they match (the overwhelmingly common case), so callers
// can prepend the result unconditionally without an extra branch.
func (ui *AdminUI) logPathMismatchNotice(kind logKind, activePath string) string {
	cfg := ui.getConfig()
	configuredPath := resolveLogFilePath(cfg.LogDir, configuredLogFilename(cfg, kind))

	if normalizeConfigFilePathForComparison(configuredPath) == normalizeConfigFilePathForComparison(activePath) {
		return ""
	}
	return fmt.Sprintf(
		"WARNING: the configured log path is %q, but a previous configuration reload failed to switch "+
			"logging over to it, so the server is still actively writing to %q (shown below). "+
			"Check the system log for the reload failure, fix it, then reload again.\n\n",
		configuredPath, activePath,
	)
}

// logRingBuffer is a small fixed-capacity ring buffer of the most recent
// matching log lines seen so far, shared across every file renderLogPage
// scans (the live log plus, optionally, its rotated backups) so a single
// "keep only the last maxLines matches" cap applies across all of them
// combined, not per-file.
type logRingBuffer struct {
	ring     []string
	maxLines int
	count    int
}

func newLogRingBuffer(maxLines int) *logRingBuffer {
	return &logRingBuffer{ring: make([]string, maxLines), maxLines: maxLines}
}

func (b *logRingBuffer) add(line string) {
	b.ring[b.count%b.maxLines] = line
	b.count++
}

// orderedNewestFirst extracts the buffer's currently retained lines in
// chronological order (oldest first) then reverses them so the result is
// newest-first, matching renderLogPage's original single-file extraction
// logic.
func (b *logRingBuffer) orderedNewestFirst() []string {
	var filtered []string
	start := 0
	limit := b.count
	if b.count > b.maxLines {
		start = b.count % b.maxLines
		limit = b.maxLines
	}
	for i := 0; i < limit; i++ {
		filtered = append(filtered, b.ring[(start+i)%b.maxLines])
	}
	for i, j := 0, len(filtered)-1; i < j; i, j = i+1, j-1 {
		filtered[i], filtered[j] = filtered[j], filtered[i]
	}
	return filtered
}

// scanLogFileInto opens path (a rotated backup or the live log file) and
// streams its lines into buf, applying the same 20MB-lookback truncation
// for oversized files that renderLogPage has always used. Lines are matched
// against searchLower (already-lowercased filter text; empty means "match
// everything") before being added to buf.
//
// A missing/unreadable path is silently skipped rather than treated as an
// error: for a rotated backup that simply doesn't exist (fewer rotations
// have happened than the requested lookback), that's the expected, normal
// case.
func scanLogFileInto(log *slog.Logger, path, searchLower string, buf *logRingBuffer) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			log.Error("failed to close log file", wincoe.SafeErr(closeErr), slog.String("filename", path))
		}
	}()

	var didSeek bool
	if stat, statErr := file.Stat(); statErr == nil {
		const maxReadBytes = 20 * 1024 * 1024 // 20MB Lookback Limit
		if stat.Size() > maxReadBytes {
			startOffset := stat.Size() - maxReadBytes
			if _, err2 := file.Seek(startOffset, io.SeekStart); err2 == nil {
				didSeek = true
			} else {
				log.Warn("failed to seek ahead in log", slog.String("log_file", path), slog.Int64("seek_to_offset", startOffset))
				if _, err3 := file.Seek(0, io.SeekStart); err3 != nil {
					log.Warn("failed to seek back to beginning in log", slog.String("log_file", path))
				}
			}
		}
	}

	scanner := bufio.NewScanner(file)
	const maxCapacity = 1024 * 1024 // 1 MB
	lineBuf := make([]byte, 2*1024) // 2 KB initial size
	scanner.Buffer(lineBuf, maxCapacity)

	if didSeek {
		if !scanner.Scan() {
			if parseErr := scanner.Err(); parseErr != nil {
				log.Warn("failed to read the first line after seeking in the log", slog.String("log_file", path), wincoe.SafeErr(parseErr))
			}
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if searchLower == "" || strings.Contains(strings.ToLower(line), searchLower) {
			buf.add(line)
		}
	}

	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			log.Error("A log line exceeded the bytes-per-line limit", slog.Int("line_limit_bytes", maxCapacity), slog.String("filename", path))
		} else {
			log.Warn("error scanning log file", slog.String("filename", path), wincoe.SafeErr(err))
		}
	}
}

// listLogRotationFiles returns full paths for up to maxRotations of the
// MOST RECENT rotated backups of basePath (basePath+".1", basePath+".2",
// ...), using the same ".N" suffix convention as getNextLogBackupName /
// rotateYouHoldLock (higher N = more recently rotated). The result is
// ordered oldest-to-newest (lowest included N first), so callers can feed
// it directly into a ring buffer alongside the live file, in the same
// oldest-to-newest order the live file's own lines are already scanned in.
// Returns nil if maxRotations <= 0 or no rotated backups exist yet.
func listLogRotationFiles(basePath string, maxRotations int) []string {
	if maxRotations <= 0 {
		return nil
	}
	// Find the highest existing rotation number by probing sequentially,
	// mirroring getNextLogBackupName's own sequential probe but stopping at
	// the first gap instead of the first free slot.
	const maxProbe = 100000 // safety valve; mirrors maxNumberOfRotations elsewhere
	highest := 0
	for i := 1; i <= maxProbe; i++ {
		if _, err := os.Stat(fmt.Sprintf("%s.%d", basePath, i)); err != nil {
			break
		}
		highest = i
	}
	if highest == 0 {
		return nil
	}
	start := highest - maxRotations + 1
	if start < 1 {
		start = 1
	}
	files := make([]string, 0, highest-start+1)
	for i := start; i <= highest; i++ {
		files = append(files, fmt.Sprintf("%s.%d", basePath, i))
	}
	return files
}

// defaultLogMaxRotations / maxLogMaxRotations bound the "how many rotated
// log files to also search" WebUI setting on the /logs* pages (see
// parseLogRotationParams). The upper bound keeps a single page render from
// ever having to open an unbounded number of files.
const (
	defaultLogMaxRotations = 5
	maxLogMaxRotations     = 50
)

// parseLogRotationParams extracts and validates the "rotated"/"maxrot"
// query parameters shared by all three /logs* handlers (see
// renderLogPage's includeRotated/maxRotations parameters).
func parseLogRotationParams(r *http.Request) (includeRotated bool, maxRotations int) {
	includeRotated = r.URL.Query().Get("rotated") == "1"
	maxRotations = defaultLogMaxRotations
	if raw := r.URL.Query().Get("maxrot"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			maxRotations = n
		}
	}
	if maxRotations > maxLogMaxRotations {
		maxRotations = maxLogMaxRotations
	}
	if maxRotations < 1 {
		maxRotations = 1
	}
	return includeRotated, maxRotations
}

// renderLogPage streams filePath (and, if includeRotated is true, up to
// maxRotations of its most recent rotated backups — see
// listLogRotationFiles) into a single "last cfg.UILogMaxLines matches,
// newest first" view, optionally filtered by filter (a case-insensitive
// substring match). Every included file is scanned in oldest-to-newest
// order (oldest rotation first, live file last) into one shared
// logRingBuffer so the retained-matches cap applies across all of them
// combined.
func (ui *AdminUI) renderLogPage(w http.ResponseWriter, r *http.Request, pageName, title, filePath, filter, notice string, includeRotated bool, maxRotations int) {
	cfg := ui.getConfig()
	log := ui.getLogger()
	if pageName == "" {
		panic2("BUG: called with empty pageName arg in renderLogPage!")
	}

	searchLower := strings.ToLower(filter)
	buf := newLogRingBuffer(cfg.UILogMaxLines)

	if includeRotated {
		for _, rotFile := range listLogRotationFiles(filePath, maxRotations) {
			scanLogFileInto(log, rotFile, searchLower, buf)
		}
	}
	scanLogFileInto(log, filePath, searchLower, buf)

	var content string
	if buf.count == 0 {
		content = "No log entries found."
	} else {
		filtered := buf.orderedNewestFirst()
		content = strings.Join(filtered, "\n")
		if buf.count > buf.maxLines {
			content = fmt.Sprintf("... showing only the last %d out of %d matches to reduce RAM usage ...\n\n", buf.maxLines, buf.count) + content
		}
	}

	renderData := map[string]any{
		"Title":          title,
		"Filter":         filter,
		"Content":        notice + content,
		"IncludeRotated": includeRotated,
		"MaxRotations":   maxRotations,
	}

	ui.renderTemplate(w, r, pageName, renderData)
}

func (ui *AdminUI) logsQueriesHandler(w http.ResponseWriter, r *http.Request) {
	const allowedMethods = "GET, HEAD, OPTIONS"
	if writeAllowHeaderResponse(w, r, allowedMethods) {
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		ui.rejectUnsupportedMethod(w, r, allowedMethods)
		return
	}

	filter := r.URL.Query().Get("q")
	//no:// If they used the old 'domain' param, support it as a fallback
	// if filter == "" {
	//     filter = r.URL.Query().Get("domain")
	// }
	includeRotated, maxRotations := parseLogRotationParams(r)

	activePath := ui.activeLogFilePath(logKindQueries)
	ui.renderLogPage(w, r, "logs_queries", "Query Logs", activePath, filter, ui.logPathMismatchNotice(logKindQueries, activePath), includeRotated, maxRotations)
}

// logsQueriesSimpleHandler serves the plain-text, single-line-per-query
// log (see Config.LogQueriesSimpleFile), reusing the same generic
// renderLogPage/"logs" template as /logs and /logs_queries.
func (ui *AdminUI) logsQueriesSimpleHandler(w http.ResponseWriter, r *http.Request) {
	const allowedMethods = "GET, HEAD, OPTIONS"
	if writeAllowHeaderResponse(w, r, allowedMethods) {
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		ui.rejectUnsupportedMethod(w, r, allowedMethods)
		return
	}

	filter := r.URL.Query().Get("q")
	includeRotated, maxRotations := parseLogRotationParams(r)
	activePath := ui.activeLogFilePath(logKindQueriesSimple)
	ui.renderLogPage(w, r, "logs_queries_simple", "Simple Query Logs", activePath, filter, ui.logPathMismatchNotice(logKindQueriesSimple, activePath), includeRotated, maxRotations)
}

func (ui *AdminUI) logsHandler(w http.ResponseWriter, r *http.Request) {
	const allowedMethods = "GET, HEAD, OPTIONS"
	if writeAllowHeaderResponse(w, r, allowedMethods) {
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		ui.rejectUnsupportedMethod(w, r, allowedMethods)
		return
	}

	filter := r.URL.Query().Get("q")
	includeRotated, maxRotations := parseLogRotationParams(r)
	activePath := ui.activeLogFilePath(logKindEverything)
	ui.renderLogPage(w, r, "logs", "System & Error Logs", activePath, filter, ui.logPathMismatchNotice(logKindEverything, activePath), includeRotated, maxRotations)
}

func (s *Server) shutdown(exitCode int) {
	s.shutdownOnce.Do(func() { //guarantees that the code inside the function runs exactly once.
		log := s.getLogger()
		log.Info("Shutting down...")
		// 1. Cancel the context immediately so all other listeners stop
		s.cancel() //Calling cancel() multiple times is perfectly safe and is actually the expected behavior in Go. In case anything else just called cancel() itself (should be currently happening)
		log.Debug("Context cancelled... this triggers DoH and webUI shutdowns in their own goroutines!")

		s.flushDNSCache()
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

		// --- AUTO RESTART TRIGGER ---
		if s.autoRestart.Load() {
			cfg := s.getConfig()
			spawnRestartProcess(log, cfg.HideConsole, cfg.LogDir, cfg.LogEverythingFile)
		}
		// ---------------------------

		finalShutdownSequence(log, exitCode, s.exitFn, s.rt.FlushLogsForShutdown)
		panic2("BUG: shoulda been unreachable after finalShutdownSequence, which means it didn't os.Exit!")
	})
	panic2("BUG: shoulda been unreachable after s.shutdownOnce.Do")
}

func finalShutdownSequence(logger *slog.Logger, exitCode int, exitFn func(int), flushLogs func()) {
	UnstickStdinRead(logger)
	// Check if the OS is forcefully terminating us
	if skipInteractivePause.Load() {
		logger.Debug("Skipping 'Press any key' pause because either the OS or we are forcefully terminating the session (ie. it's a headless auto-restart).")
	} else if wincoe.IsStdinConsoleInteractive() {
		logger.Debug("Will wait for keypress after flushing logs...")
	} else {
		logger.Debug("Won't wait for keypress due to not an interactive/terminal.")
	}

	logger.Info("exitting with exit code", slog.Int("exitCode", exitCode))

	// Flush any asynchronous log writers (see asyncLogWriter) now, after the
	// final log line above but before exitFn actually terminates the
	// process, so buffered-but-not-yet-written log lines (including that
	// final line) aren't silently lost. flushLogs may be nil during the
	// very earliest bootstrap failure paths, before any log file writer
	// exists yet. This call is itself bounded (see
	// asyncLogWriterCloseDrainTimeout) and can never hang shutdown even if
	// the underlying disk is currently stuck.
	if flushLogs != nil {
		flushLogs()
	}

	// --- NEW: Signal the child process that logs are flushed ---
	if hEvent := windows.Handle(atomic.LoadUintptr(&flushSyncEvent)); hEvent != 0 {
		if err := windows.SetEvent(hEvent); err != nil {
			// //okFIXME: how do we log this?! since logs are closed and os.Stderr may not be available at all!
			// //localLogger.Warn("failed to set sync event", wincoe.SafeErr(err))
			// if wincoe.HasConsole() { //this is too dumb of a check
			// 	fmt.Fprintf(os.Stderr, "failed to set flush-sync event, windows.SetEvent err: %v", err)
			// }

			// os.Stderr is always safe to write to in Go on Windows.
			// If there is no console, the OS handles/discards it gracefully without panicking.
			// but well, i lose the log
			fmt.Fprintf(os.Stderr, "failed to set flush-sync event, windows.SetEvent err: %v\n", err)
		}

		// CRITICAL FIX: Defer the close. This keeps the event object alive in
		// the OS kernel (and permanently Signaled) while we sit at the
		// "Press any key" prompt, allowing a slow-starting child to find it.
		defer wincoe.CloseHandleLogged(&hEvent, "finalShutdownSequence:SetEvent hEvent flushSyncEvent")
		atomic.StoreUintptr(&flushSyncEvent, 0)
	}
	// ---

	if !skipInteractivePause.Load() {
		// Normal exit (like Ctrl+C or clean UI shutdown) - pause as usual
		wincoe.WaitAnyKeyIfInteractive() //does that IsStdinConsoleInteractive inside, and only waits if true
		// if !wincoe.WaitAnyKeyIfInteractive() {
		// 	// // Since logger's async writers are closed/flushed, use stderr directly
		// 	// fmt.Fprintln(os.Stderr, "Didn't wait for keypress due to not an interactive/terminal.")
		// 	// // logger.Debug("Didn't wait for keypress due to not an interactive/terminal.")
		// }
	}

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

func (s *Server) watchKeys(reloadFn func() error, exitFn func(code int)) {
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
		log2 := s.getLogger()

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
		fmt.Print(".") //noTODO: delete this? then the next 6 \n Print(s) as well; we use this to cause scroll to get back to bottom!

		// Ctrl+X (0x18)
		if buf[0] == 0x18 {
			fmt.Print("\n")
			log2.Info("Ctrl+X detected → clean exit")
			if err2 := term.Restore(fd, oldState); err2 != nil {
				log2.Warn("failed to restore terminal state", wincoe.SafeErr(err2))
			}
			exitFn(0)
		}

		// Ctrl+R (0x12)
		if buf[0] == 0x12 {
			fmt.Print("\n")
			log2.Info("Ctrl+R detected → reloading config")
			//_ = term.Restore(fd, oldState)
			// NO restore needed here because we want to stay in Raw mode
			// to catch the next keypress after the reload.
			if reloadErr := reloadFn(); reloadErr != nil {
				log2.Warn("Ctrl+R reload did not apply", wincoe.SafeErr(reloadErr))
			}
		}

		// Ctrl+C (0x03) or else can't break the program except with Ctrl+Break !
		if buf[0] == 0x03 {
			fmt.Print("\n")
			log2.Info("Ctrl+C detected → breaking gracefully")
			if err2 := term.Restore(fd, oldState); err2 != nil {
				log2.Warn("failed to restore terminal state", wincoe.SafeErr(err2))
			}
			exitFn(130)
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
				exitFn(0)
			case 'r', 'R':
				fmt.Print("\n")
				log2.Info("Alt+R detected → reloading config")
				//_ = term.Restore(fd, oldState)
				if reloadErr := reloadFn(); reloadErr != nil {
					log2.Warn("Alt+R reload did not apply", wincoe.SafeErr(reloadErr))
				}
			case 'v', 'V':
				fmt.Print("\n")
				log2.Info("Alt+V detected → dumping", slog.String("version", GetVersion()))

				// fmt.Printf("\n========================================\n")
				// fmt.Printf("VERSION: %s\n", GetVersion())
				// fmt.Printf("========================================\n\n")

				cfg := s.getConfig()
				t := reflect.TypeOf(*cfg)
				v := reflect.ValueOf(*cfg)

				for i := 0; i < t.NumField(); i++ {
					field := t.Field(i)
					jsonTag := field.Tag.Get("json")
					if jsonTag == "" || jsonTag == "-" {
						continue
					}

					jsonKey := strings.Split(jsonTag, ",")[0]
					desc := field.Tag.Get("desc")
					val := v.Field(i).Interface()

					// Mask the password hash in the console dump
					if jsonKey == getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIPasswordHash)) {
						val = "********"
					}

					//fmt.Printf("--- %s ---\nValue: %v\nDescription: %s\n\n", jsonKey, val, desc)
					// Log each config option cleanly as a structured debug/info attribute
					log2.Info("--- ",
						slog.String("key", jsonKey),
						slog.Any("value", val),
						slog.String("description", desc),
					)
				}
			} //switch
		} //alt+

		// Re-ensure raw mode if anything temporarily reset it
		_, err = term.MakeRaw(fd)
		if err != nil {
			fmt.Print("\n")
			log2.Error("Failed to make the terminal raw", wincoe.SafeErr(err))
			return
		}
	}
}

var configKeyNameForHideConsole string = getJSONTagByOffset(unsafe.Offsetof(Config{}.HideConsole))

func promptAndHashPassword(logger *slog.Logger, cost int) (string, error) {
	if !wincoe.HasConsole() {
		return "", errors.New("cannot prompt for a password interactively: no console is attached to this process " +
			"(" + configKeyNameForHideConsole + " is enabled, or this is a -H=windowsgui build); set webui_password_hash in config.json " +
			"beforehand, e.g. by running --hash-password once from a build/run that still has a console")
	}
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

// verifiedAuthCache remembers, for a short TTL, that a specific Authorization
// header value has already been successfully verified against the CURRENT
// WebUI password hash — so authMiddleware can skip the deliberately expensive
// bcrypt.CompareHashAndPassword call for repeat requests carrying that exact
// same header.
//
// Why this is safe: bcrypt's cost is what makes brute-forcing a DIFFERENT
// (wrong) password guess expensive; browsers, however, resend the SAME,
// already-correct Authorization header on every request for the lifetime of
// a session once entered once — paying full bcrypt cost on every one of
// those adds nothing security-wise, and gives an attacker flooding the
// endpoint with one already-known-wrong header a free way to multiply a
// single guess's cost. Caching "this exact header + this exact password hash
// already matched" does not shortcut verifying a NEW guess (a different
// guess produces a different cache key and still pays full bcrypt cost); it
// only shortcuts re-verifying a guess already known-good.
//
// The cache key embeds the live password hash (see computeAuthCacheKey), so
// rotating the WebUI password instantly invalidates every previously cached
// success — no explicit cache-clear call is needed anywhere else.
type verifiedAuthCache struct {
	mu      sync.Mutex
	entries map[string]time.Time // cache key -> expiry
}

// verifiedAuthCacheTTL bounds how long a verified Authorization header is
// trusted without re-checking bcrypt.
const verifiedAuthCacheTTL = 60 * time.Second

// verifiedAuthCacheMaxEntries bounds worst-case memory growth: once
// exceeded, remember() opportunistically purges expired entries first.
const verifiedAuthCacheMaxEntries = 1000

func newVerifiedAuthCache() *verifiedAuthCache {
	return &verifiedAuthCache{entries: make(map[string]time.Time)}
}

// check reports whether key is present and not yet expired, lazily removing
// it if it has expired.
func (c *verifiedAuthCache) check(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.entries[key]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(c.entries, key)
		return false
	}
	return true
}

// remember marks key as verified until ttl from now.
func (c *verifiedAuthCache) remember(key string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= verifiedAuthCacheMaxEntries {
		now := time.Now()
		for k, exp := range c.entries {
			if now.After(exp) {
				delete(c.entries, k)
			}
		}
	}
	c.entries[key] = time.Now().Add(ttl)
}

// computeAuthCacheKey derives a fast, fixed-size cache key from the raw
// Authorization header value and the CURRENTLY-active password hash. Binding
// the key to the live password hash means a password rotation automatically
// and instantly invalidates every cache entry computed against the old hash.
func computeAuthCacheKey(authHeader, currentPasswordHash string) string {
	sum := sha256.Sum256([]byte(authHeader + "\x00" + currentPasswordHash))
	return hex.EncodeToString(sum[:])
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
		clientIP := getCleanIP(r.RemoteAddr, func(splitErr error) {
			log.Warn("WebUI auth: could not split RemoteAddr into host:port",
				slog.String("remoteAddr", r.RemoteAddr),
				wincoe.SafeErr(splitErr))
		})

		// clientIP, _, splitErr := net.SplitHostPort(r.RemoteAddr)
		// if splitErr != nil {
		// 	// r.RemoteAddr should always be host:port for TCP, but be defensive.
		// 	clientIP = r.RemoteAddr
		// 	log.Warn("WebUI auth: could not split RemoteAddr into host:port",
		// 		slog.String("remoteAddr", r.RemoteAddr),
		// 		wincoe.SafeErr(splitErr))
		// }

		// ── Rate-limit gate ──
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
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", ui.currentAuthRealm()))
			http.Error(w, "401 Unauthorized - WebUI Access Restricted", http.StatusUnauthorized)
			return
		}

		// Fast path: skip the expensive bcrypt comparison entirely if this
		// exact Authorization header already verified successfully against
		// the current password hash within the last verifiedAuthCacheTTL —
		// see verifiedAuthCache's doc comment for why this is safe.
		authCacheKey := computeAuthCacheKey(authHeader, cfg.WebUIPasswordHash)
		if ui.verifiedAuthCache.check(authCacheKey) {
			if ui.proceedAfterAuthSuccess(w, r, clientIP) {
				next.ServeHTTP(w, r)
			}
			return
		}

		// ── Credential check ─
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
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", ui.currentAuthRealm()))
			http.Error(w, "401 Unauthorized - WebUI Access Restricted", http.StatusUnauthorized)
			return
		}

		// ── Success ─
		// Remember this exact header as verified so the next request bearing
		// it can skip bcrypt entirely (see verifiedAuthCache's doc comment).
		ui.verifiedAuthCache.remember(authCacheKey, verifiedAuthCacheTTL)
		// proceedAfterAuthSuccess clears any prior failure streak and enforces
		// the configured session-expiry policy (see its doc comment).
		if ui.proceedAfterAuthSuccess(w, r, clientIP) {
			// Password is correct, let the request pass through to the target handler
			next.ServeHTTP(w, r)
		}
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

// webUIRateLimitConfigFrom extracts the WebUI-specific rate-limit settings
// from Config. Kept separate from rateLimitConfigFrom (DNS query path) since
// the two protect entirely different resources with very different traffic
// volumes/defaults, and must be independently tunable.
func webUIRateLimitConfigFrom(cfg Config) RateLimitConfig {
	return RateLimitConfig{
		GlobalQPS:   cfg.WebUIRateQPS,
		GlobalBurst: cfg.WebUIBurstQPS,
		ClientQPS:   cfg.WebUIClientRateQPS,
		ClientBurst: cfg.WebUIClientBurstQPS,
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

func newClientRateLimiter(cfg RateLimitConfig, logger *slog.Logger) *ClientRateLimiter {
	//_ = ctx //doneTODO: because Context is no longer needed since we dropped the background janitor, remove it as arg?!
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
	// clientIP, _, err := net.SplitHostPort(clientAddr)
	// if err != nil {
	// 	// Fallback safety: if string parsing fails, default back to the raw string
	// 	rl.logger.Warn("couldn't split clientAddr into host:port for per-client rate limiter key, using as-is",
	// 		slog.String("clientAddr", clientAddr),
	// 		wincoe.SafeErr(err),
	// 	)
	// 	clientIP = clientAddr
	// }
	// // 2. If it's any loopback address (127.x.x.x or ::1), collapse it to "localhost" to avoid one .exe which could be using many IPs in range of 127.0.0.0/8 as the request sender.
	// // 2. Collapse loopback addresses to prevent bypassing limits
	// if parsed := net.ParseIP(clientIP); parsed != nil && parsed.IsLoopback() {
	// 	clientIP = "localhost"
	// }
	clientIP := getCleanIP(clientAddr, func(splitErr error) {
		rl.logger.Warn("ClientRateLimiter.Allow couldn't split clientAddr into host:port for per-client rate limiter key, using as-is",
			slog.String("clientAddr", clientAddr),
			wincoe.SafeErr(splitErr),
		)
	})

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
	// lastDeleteExpiredNs throttles manual DeleteExpired() sweeps (see Set) to
	// at most once per deleteExpiredThrottle window, regardless of how many
	// concurrent goroutines call Set while the cache is at capacity. go-cache's
	// DeleteExpired() takes a single global lock and performs a full O(N) scan
	// of every key; calling it unconditionally on every Set() once maxEntries
	// is reached turns sustained high-QPS traffic at/above capacity into a
	// full-map-lock storm on the DNS hot path.
	lastDeleteExpiredNs atomic.Int64
	liveLogger          *atomic.Pointer[slog.Logger] // <-- Uses the hot-swappable atomic pointer
}

// pointer to live logger or default bug logger if uninited
func (s *goCacheStore) getLogger() *slog.Logger {
	return wincoe.GetLoggerOrFallback(s.liveLogger, "goCacheStore.liveLogger")
}

func newGoCacheStore(janitorInterval time.Duration, maxEntries int, liveLogger *atomic.Pointer[slog.Logger]) goCacheStore {
	return goCacheStore{
		c:          cache.New(janitorInterval, janitorInterval),
		maxEntries: maxEntries,
		liveLogger: liveLogger,
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

// deleteExpiredThrottle bounds how often Set() is allowed to trigger a manual,
// full O(N) go-cache DeleteExpired() sweep once the cache is at capacity. The
// background janitor (started via cache.New in newGoCacheStore) already runs
// periodically at CacheJanitorIntervalMinutes, but that interval defaults to
// 60 minutes; this throttle lets a full cache still self-heal quickly between
// janitor sweeps without letting every single over-capacity Set() call pay for
// its own O(N) full-map scan under sustained high QPS.
const deleteExpiredThrottle = 1 * time.Second

func (s *goCacheStore) Set(key string, e CacheEntry, d time.Duration) {
	if d <= 0 {
		// go-cache's underlying Set(k, x, d) treats d == 0 as "use this
		// cache's configured default expiration" — which newGoCacheStore
		// wires to CacheJanitorIntervalMinutes (tens of minutes by default)
		// — rather than "expires immediately"; a negative d is nonsensical
		// as a TTL to begin with. Config fields such as CacheNegativeTTLSec
		// are explicitly validated/tested to allow exactly 0 to mean "do not
		// cache this" (see sanitizeAndValidateConfig's sub-zero clamp
		// tests), so silently forwarding a zero/negative duration here would
		// instead cache the entry for up to CacheJanitorIntervalMinutes,
		// directly contradicting that documented behavior. Skip the insert
		// entirely instead.
		log := s.getLogger()
		log.Debug("BUG: callers of goCacheStore.Set shouldn't call it with duration of 0 or less: skipping cache insert for non-positive or 0 TTL",
			slog.String("key", key), slog.Duration("requested_ttl", d))
		return
	}
	if s.maxEntries > 0 && s.c.ItemCount() >= s.maxEntries {
		log := s.getLogger()
		now := time.Now().UnixNano()
		last := s.lastDeleteExpiredNs.Load()
		if now-last >= deleteExpiredThrottle.Nanoseconds() && s.lastDeleteExpiredNs.CompareAndSwap(last, now) {
			// Only the single goroutine that wins this CAS performs the
			// expensive full-map sweep for this throttle window; every other
			// concurrent caller just falls through to the capacity re-check
			// below instead of piling on redundant O(N) scans of its own.
			s.c.DeleteExpired()
			//doneTODO: log this
			log.Debug("Cache capacity reached; performed manual DeleteExpired sweep")
		}
		if s.c.ItemCount() >= s.maxEntries {
			// Still full after the sweep (every entry currently has a live,
			// unexpired TTL): rather than permanently refusing this and every
			// future insert once the cache saturates, evict whichever single
			// entry is closest to expiring anyway — a cheap approximation of
			// LRU that doesn't require a separate tracking structure — to
			// make room for this new, presumably still-useful entry.
			if !s.evictSoonestToExpire() {
				log.Warn("Cache is full and no evictable entry was found; dropping new entry", slog.String("key", key))
				return // Cache is full, safely drop the new entry to prevent memory leaks
			}
			log.Debug("Cache still full after sweep; evicted the soonest-to-expire entry to make room", slog.String("key", key))
		}
	}
	s.c.Set(key, e, d)
}

// evictSoonestToExpire deletes whichever cached item has the smallest
// (soonest) expiration timestamp, freeing one slot. Items with no expiration
// (Expiration == 0, "never expires") are only chosen as a last resort, if no
// expiring item exists at all. Returns false if the cache is completely
// empty and nothing could be evicted.
func (s *goCacheStore) evictSoonestToExpire() bool {
	items := s.c.Items()

	var oldestKey string
	var oldestExp int64
	haveCandidate := false

	for k, item := range items {
		if item.Expiration == 0 {
			if !haveCandidate {
				oldestKey = k
				haveCandidate = true
			}
			continue
		}
		if !haveCandidate || oldestExp == 0 || item.Expiration < oldestExp {
			oldestKey = k
			oldestExp = item.Expiration
			haveCandidate = true
		}
	}

	if !haveCandidate {
		return false
	}
	s.c.Delete(oldestKey)
	return true
}

func (s *goCacheStore) Delete(key string)            { s.c.Delete(key) }
func (s *goCacheStore) Flush()                       { s.c.Flush() }
func (s *goCacheStore) Items() map[string]cache.Item { return s.c.Items() }
func (s *goCacheStore) ItemCount() int               { return s.c.ItemCount() }

func (ui *AdminUI) getLogger() *slog.Logger {
	return wincoe.GetLoggerOrFallback(ui.liveLogger, "AdminUI.liveLogger")
}

// pointer to live Server.Config via AdminUI
func (ui *AdminUI) getConfig() *Config {
	c := ui.getLiveConfigs().Resolved
	if c == nil {
		panic2("BUG: AdminUI.getLiveConfigs().Resolved not initialized before use")
	}
	return c
}

func (ui *AdminUI) getLiveConfigs() *LiveConfigs {
	both := ui.liveConfigs.Load()
	if both == nil {
		panic2("BUG: AdminUI.liveConfigs not initialized before use")
		panic(nil)
	}
	return both
}

func (ui *AdminUI) getRawConfig() *Config {
	c := ui.getLiveConfigs().Raw
	if c != nil {
		return c
	}
	panic2("BUG: AdminUI.getLiveConfigs().Raw isn't inited, should point to the Server's raw config")
	panic2("BUG: AdminUI.liveRawConfig isn't inited, should point to the Server.liveRawConfig")
	panic(nil)
}

func NewAdminUI(
	// logger *slog.Logger,
	// cfg Config,
	// liveConfig *atomic.Pointer[Config],
	// liveRawConfig *atomic.Pointer[Config],
	liveConfigs *atomic.Pointer[LiveConfigs],
	liveLogger *atomic.Pointer[slog.Logger],
	logMgr *LoggerManager,
	rs *RuleStore,
	hs *HostStore,
	bl *BlacklistStore,
	tableMutationMu *sync.Mutex,
	lt *LoginTracker,
	rb *RecentBlocksTracker,
	blockedQueries *expvar.Int,
	//upstreamIPs []string,
	tpls *template.Template,
) *AdminUI {
	return &AdminUI{
		liveConfigs:       liveConfigs,
		liveLogger:        liveLogger,
		logMgr:            logMgr,
		ruleStore:         rs,
		hostStore:         hs,
		blacklist:         bl,
		tableMutationMu:   tableMutationMu,
		loginTracker:      lt,
		recentBlocks:      rb,
		blockedQueries:    blockedQueries,
		verifiedAuthCache: newVerifiedAuthCache(),
		csrfSecret:        newCSRFSecret(),
		sessionAuthSecret: newSessionAuthSecret(),
		uiTemplates:       tpls,
	}
}

// func (ui *AdminUI) getResponseBlacklist() []string {
// 	return ui.blacklist.List()
// }

// IPChecker defines the interface for checking if an IP is blacklisted, allowing easy mocking in tests.
type IPChecker interface {
	Contains(ip net.IP) bool
}

type UpstreamManager struct {
	// liveConfig *atomic.Pointer[Config]
	liveLogger  *atomic.Pointer[slog.Logger]
	liveConfigs *atomic.Pointer[LiveConfigs] //only need the Resolved, not the Raw here tho!
	serverCtx   context.Context              // server lifetime ctx for Upstream.BackgroundCtx

	dohTransportsPtrs []*http.Transport //protected by dohMu, used only to clean up during reinit via initDoHClient
	//upstreamsPtr      atomic.Pointer[[]Upstream] // Combines clients, URLs, and SNIs safely
	activeSet atomic.Pointer[UpstreamSet] // ← the atomic pair
	buildMu   sync.Mutex                  // prevents concurrent builds only
	// dohMu     sync.Mutex                  // Only used for initialization/reloads

	//UM calls this when a fatal exception or manual admin shutdown occurs
	OnShutdown func(exitCode int)

	// flushLogs, if non-nil, flushes buffered async log writers. Passed down
	// to FailoverSelector (via buildSet) and used directly by ForwardToDoH's
	// own per-upstream goroutines, since none of these hot, per-query
	// goroutines may be tracked in Server.shutdownWG the way Server.GoSafe's
	// goroutines are (some are designed to intentionally outlive the call
	// that spawned them). See recoverAndFlushLogs.
	flushLogs func()
}

func NewUpstreamManager(serverCtx context.Context, liveConfigs *atomic.Pointer[LiveConfigs], liveLogger *atomic.Pointer[slog.Logger], shutdownFunc func(exitCode int), flushLogs func()) *UpstreamManager {
	if serverCtx == nil {
		panic2("BUG: NewUpstreamManager: nil serverCtx")
	}
	if liveConfigs == nil {
		panic2("BUG: NewUpstreamManager: nil liveConfig pointer")
	}
	if liveLogger == nil {
		panic2("BUG: NewUpstreamManager: nil liveLogger pointer")
	}
	um := &UpstreamManager{
		serverCtx:   serverCtx,
		liveConfigs: liveConfigs,
		liveLogger:  liveLogger,
		//Pass the server's shutdown method directly
		OnShutdown: shutdownFunc,
		flushLogs:  flushLogs,
	}
	//NewUpstreamManager no longer constructs a FailoverSelector upfront — it's created fresh inside buildSet:
	//um.failoverSelect = NewFailoverSelector(liveLogger)
	return um
}

func (um *UpstreamManager) getLogger() *slog.Logger {
	return wincoe.GetLoggerOrFallback(um.liveLogger, "UpstreamManager.liveLogger")
}

func (um *UpstreamManager) getLiveConfigs() *LiveConfigs {
	both := um.liveConfigs.Load()
	if both == nil {
		panic2("BUG: UpstreamManager.liveConfigs not initialized before use")
		panic(nil)
	}
	return both
}

func (um *UpstreamManager) getConfig() *Config {
	c := um.getLiveConfigs().Resolved
	if c == nil {
		panic2("BUG: UpstreamManager.liveConfig not initialized before use")
		panic(nil)
	}
	return c
}

// parseAndValidateUpstreams validates upstream_urls (each entry must parse, use the https
// scheme, and have an IP-literal host — never a hostname, since this proxy performs no DNS
// resolution of its own to look one up) and derives the three runtime-only fields stored
// alongside them: one *url.URL (with a guaranteed non-empty port, defaulting to 443), one
// IP-literal host string, and one SNI hostname per upstream_urls entry, in the same order.
//
// upstreamSNIHostnames must already be padded out to at least the same length as
// upstreamURLs — sanitizeAndValidateConfig's SNI-padding block guarantees this for any
// Config that went through it — otherwise this returns an error rather than panicking with
// an index-out-of-range.
//
// Shared by two callers:
//   - sanitizeAndValidateConfig, so UpstreamURLsParsed/UpstreamIPs/UpstreamSNIs are already
//     correct on resolvedCfg the instant it becomes the live Config (via Server.applyConfig),
//     closing a race window where concurrent readers (e.g. the /stats WebUI handler) could
//     otherwise observe those fields nil/stale between applyConfig and UpstreamManager
//     getting around to recomputing them. It also means a bad upstream_urls entry is now
//     caught at config-validation time — including the WebUI /config apply dry-run — instead
//     of only surfacing later inside UpstreamManager, which previously reacted to it by
//     shutting down the entire process via UpstreamManager.OnShutdown.
//   - UpstreamManager.updateInnerState, as defense-in-depth: several tests in this package
//     deliberately construct a bare Config{} that bypasses sanitizeAndValidateConfig
//     entirely, specifically to exercise UpstreamManager's own independent validation and
//     shutdown behavior, so that path must keep re-validating on its own rather than trusting
//     that every live Config was necessarily built via the normal pipeline.
func parseAndValidateUpstreams(upstreamURLs, upstreamSNIHostnames []string) (parsedURLs []*url.URL, ips, snis []string, err error) {
	if len(upstreamURLs) == 0 {
		return nil, nil, nil, errors.New("upstream_urls list is empty")
	}

	for i, rawURL := range upstreamURLs {
		u, parseErr := url.Parse(rawURL)
		if parseErr != nil {
			return nil, nil, nil, fmt.Errorf("invalid upstream URL (must be https): %s, err: %w", rawURL, parseErr)
		}
		if u.Scheme != "https" {
			return nil, nil, nil, fmt.Errorf("invalid upstream URL (must be https): %s", rawURL)
		}
		port := u.Port()
		if port == "" {
			port = "443" // since we're allowing only https scheme, this should always be 443
			// This is how you add the port back into the URL object
			u.Host = net.JoinHostPort(u.Hostname(), port)
		}
		if u.Port() == "" {
			panic2("BUG: dev fail: port is empty")
		}
		parsedURLs = append(parsedURLs, u)

		ip := u.Hostname()
		if net.ParseIP(ip) == nil {
			return nil, nil, nil, fmt.Errorf("upstream host must be IP literal (no resolution): %s", ip)
		}
		ips = append(ips, ip)

		if i >= len(upstreamSNIHostnames) {
			// sanitizeAndValidateConfig is responsible for padding UpstreamSNIHostnames
			// out to match UpstreamURLs before this ever runs; a caller that bypasses it
			// would otherwise panic here with an index-out-of-range instead of getting a
			// clean, recoverable error that flows through the normal shutdown path below.
			return nil, nil, nil, fmt.Errorf("upstream_sni_hostnames has %d entries but upstream_urls has %d (index %d has no matching SNI entry); they must be padded to equal length before use", len(upstreamSNIHostnames), len(upstreamURLs), i)
		}
		snis = append(snis, upstreamSNIHostnames[i])
	}
	return parsedURLs, ips, snis, nil
}

// due to presumed config changes ie. UpstreamManager.liveConfig, update the 'cached' inner state of the upstreamIPs, upstreamSNIs and upstreamURLs
func (um *UpstreamManager) updateInnerState() error {
	// XXX: um.getConfig() returns the LIVE, atomically-shared *Config that
	// concurrent DNS queries (ForwardToDoH) and the WebUI /stats handler are
	// actively reading right now via their own getConfig() calls. Mutating its
	// fields in place (as this function used to do) is a full-blown data race:
	// a concurrent reader could observe UpstreamURLsParsed as nil (right after
	// the reset below) or as a half-appended slice mid-loop, leading to an
	// index-out-of-bounds panic or silently corrupted upstream state.
	//
	// The fix: work on our own deep-copied clone, and only publish it via a
	// single atomic Store once it is fully built and valid. Readers therefore
	// always see either the complete old Config or the complete new one, never
	// a struct caught mid-mutation. Any error return below leaves the live
	// config completely untouched.
	//
	// NOTE: sanitizeAndValidateConfig now runs this exact same derivation (via
	// parseAndValidateUpstreams) and publishes the result as part of resolvedCfg
	// before Server.applyConfig ever makes a new Config live — see that call
	// site's doc comment for why. So by the time Reload() gets here via
	// UpstreamManager.ReInitDoHClients(), liveCfg's UpstreamURLsParsed/IPs/SNIs
	// are normally already correct, and this just redundantly recomputes the
	// identical result. This call stays in place regardless, as defense-in-depth:
	// see parseAndValidateUpstreams's doc comment for why.
	// Snapshot the whole (Resolved, Raw) pair via a SINGLE atomic Load so the
	// Raw pointer published below is guaranteed to come from the exact same
	// generation as the Resolved config newCfg is cloned from. Two
	// independent Load() calls (one here, one just before the final Store()
	// below) could otherwise observe two different generations if a
	// concurrent Server.applyConfig() call landed in between them,
	// publishing a mismatched (stale Resolved paired with fresh Raw, or vice
	// versa) pair.
	both := um.getLiveConfigs()
	liveCfg := both.Resolved
	if liveCfg == nil {
		panic2("BUG: UpstreamManager.liveConfigs.Resolved not initialized before use")
	}
	newCfg := liveCfg.Clone()

	parsedURLs, ips, snis, err := parseAndValidateUpstreams(newCfg.UpstreamURLs, newCfg.UpstreamSNIHostnames)
	if err != nil {
		return err
	}
	// if newCfg.UpstreamURLsParsed != parsedURLs {

	// }
	newCfg.UpstreamURLsParsed = parsedURLs
	newCfg.UpstreamIPs = ips
	newCfg.UpstreamSNIs = snis

	// Publish the fully-built, validated clone atomically.
	//um.liveConfig.Store(&newCfg)
	// if newCfg != *liveCfg {
	// 	panic2("BUG: should've been already set properly")
	// }
	//FIXME: maybe don't set it here, but fail if it's not the same! since at load time this should've been properly filled already!
	um.liveConfigs.Store(&LiveConfigs{
		Resolved: &newCfg,
		Raw:      both.Raw,
	})
	return nil
}

// computeForwardOverallTimeout bounds the total wall-clock time a single
// ForwardToDoH call may take, across every configured upstream and every
// retry attempt, regardless of DNS query selection mode (fastest/failover/
// strict). Without this ceiling, doSingleDoHRequest's retry loop budgets a
// fresh UpstreamClientTimeoutSec for EACH attempt, so strict mode's
// wg.Wait() (which waits for every upstream's goroutine, not just the first
// to answer) could hold the caller's DNS concurrency semaphore slot for up
// to UpstreamClientTimeoutSec * (1 + UpstreamRetriesPerQuery) seconds under
// a genuinely slow or partially-failing upstream — long enough, under
// sustained query volume, to exhaust the semaphore pool and stall every new
// connection. This computes that same worst-case per-upstream budget and
// applies it once, up front: within the 60s ceiling below, no upstream is
// cut off before its own documented retry budget elapses; a configuration
// whose computed retry budget would exceed that ceiling is itself clamped
// to it as a hard defense-in-depth cap, which takes precedence over the
// per-upstream budget in that case.
//
// Every quantity below is an operator-controlled int field with no
// upper-bound validation (only "> 0" is enforced elsewhere), reachable via a
// hand-edited config.json even though the WebUI's own Number handling can't
// represent such extreme values safely (see app.js's Number.isSafeInteger
// check on the config-editing path). A large enough value could overflow
// time.Duration's int64 nanosecond range in a naive multiplication, wrapping
// the total to a small or negative number and silently defeating the entire
// point of this function. Every seconds/milliseconds-denominated quantity is
// therefore bound-checked against the ceiling, expressed in the same unit,
// before it's ever multiplied by time.Second/time.Millisecond, so an
// overflow-prone input saturates at the ceiling instead of wrapping.
func computeForwardOverallTimeout(cfg *Config) time.Duration {
	const (
		ceiling    = 60 * time.Second
		ceilingSec = int64(ceiling / time.Second)
		ceilingMs  = int64(ceiling / time.Millisecond)
	)

	clientTimeoutSec := int64(cfg.UpstreamClientTimeoutSec)
	attempts := int64(1 + cfg.UpstreamRetriesPerQuery)
	if clientTimeoutSec <= 0 || attempts <= 0 || clientTimeoutSec > ceilingSec || attempts > ceilingSec {
		return ceiling
	}
	perAttemptTotalSec := clientTimeoutSec * attempts
	if perAttemptTotalSec > ceilingSec {
		return ceiling
	}

	retries := int64(cfg.UpstreamRetriesPerQuery)
	backoffMs := int64(cfg.UpstreamRetryBackoffMs)
	if retries < 0 || backoffMs < 0 || retries > ceilingMs || backoffMs > ceilingMs {
		return ceiling
	}
	totalBackoffMs := retries * backoffMs
	if totalBackoffMs > ceilingMs {
		return ceiling
	}

	total := time.Duration(perAttemptTotalSec)*time.Second +
		time.Duration(totalBackoffMs)*time.Millisecond +
		time.Second // scheduling slack
	if total > ceiling {
		return ceiling
	}
	return total
}

// ForwardToDoH uses the preinitialized dohClient and supports one retry on transient network errors.
func (um *UpstreamManager) ForwardToDoH(ctx context.Context, req *dns.Msg) (*dns.Msg, UpstreamState) {
	cfg := um.getConfig()
	log := um.getLogger()

	// Bound the entire forwarding attempt (covering every upstream and every
	// retry) so strict mode's wg.Wait() below can never hold the caller's
	// DNS concurrency semaphore slot longer than a single upstream's own
	// documented worst-case retry budget. See computeForwardOverallTimeout's
	// doc comment and todonow.txt "Strict Mode Semaphore Exhaustion
	// (Deadlock)".
	overallCtx, cancelOverall := context.WithTimeout(ctx, computeForwardOverallTimeout(cfg))
	defer cancelOverall()
	ctx = overallCtx

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
		msg         *dns.Msg
		resolvedURL string
		err         error
		idx         int // Useful for tracking which upstream won or failed
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
				defer recoverAndFlushLogs(um.flushLogs)
				defer wg.Done()
				msg, resolvedURL, err := target.doSingleDoHRequest(ctx, reqBytes)
				results[idx] = result{msg: msg, resolvedURL: resolvedURL, err: err, idx: idx}
			}(i, upstream)
		}

		wg.Wait()

		var reference *dns.Msg
		var refIdx int

		// Compare responses
		for i, res := range results {
			if res.err != nil || res.msg == nil {
				log.Error("upstream failed or returned nil",
					slog.String("url", res.resolvedURL),
					wincoe.SafeErr(res.err),
				)
				upstreamState1.FailedUpstreams = append(upstreamState1.FailedUpstreams, res.resolvedURL)
				return nil, upstreamState1 // Refuse to resolve if any upstream completely fails
			}

			// A NOERROR response with zero answer records (NODATA) can never be
			// cross-verified: every upstream trivially "agrees" on emptiness, so
			// reaching consensus here proves nothing about the real answer. Strict
			// mode's whole purpose is refusing to trust an answer it can't verify,
			// so treat this the same as an outright failure rather than as valid
			// unanimous consensus. NXDOMAIN (and other non-success rcodes) are
			// unaffected and still participate in normal consensus checking below.
			// by Claude Sonnet 5 Extra Thinking
			if res.msg.Rcode == dns.RcodeSuccess && len(res.msg.Answer) == 0 {
				log.Warn("strict mode: treating NOERROR/no-answer (NODATA) response as an unverifiable failure",
					slog.String("url", res.resolvedURL))
				upstreamState1.FailedUpstreams = append(upstreamState1.FailedUpstreams, res.resolvedURL)
				return nil, upstreamState1
			}

			if reference == nil {
				reference = res.msg
				refIdx = i
				upstreamState1.UpstreamUsed = res.resolvedURL
			} else if !compareDNSResponses(reference, res.msg) {
				// Mismatch means failure to agree
				upstreamState1.FailedUpstreams = append(upstreamState1.FailedUpstreams, res.resolvedURL)

				// Extract IPs for the log message
				refIPs := extractIPs(reference)
				curIPs := extractIPs(res.msg)

				domain := strings.ToLower(strings.TrimSuffix(req.Question[0].Name, "."))
				displayDomain, wasIDN := punycodeDecodePatternForDisplay(domain)

				attrs := []any{
					slog.String("query", req.Question[0].Name),
					slog.String("upstream_DoH_url1", results[refIdx].resolvedURL),
					SafeStringSlice("ips_returned1", refIPs),
					slog.String("upstream_DoH_url2", res.resolvedURL),
					SafeStringSlice("ips_returned2", curIPs),
					slog.String("reference", reference.String()),
					slog.String("current", res.msg.String()),
				}
				if wasIDN {
					attrs = append(attrs, slog.String("query_idn", displayDomain))
				}

				log.Warn("upstream DNS response mismatch! dropping query to protect client", attrs...)
				return nil, upstreamState1 // Drop the query because of answer discrepancy
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
				defer recoverAndFlushLogs(um.flushLogs)
				msg, resolvedURL, err := target.doSingleDoHRequest(ctx, reqBytes)
				resChan <- result{msg: msg, resolvedURL: resolvedURL, err: err, idx: idx}
			}(i, upstream)
		}

		var lastErr error
		for range len(upstreams) {
			res := <-resChan
			// If we got a valid DNS response (even an NXDOMAIN), return it immediately
			if res.err == nil && res.msg != nil {
				upstreamState1.UpstreamUsed = res.resolvedURL
				return res.msg, upstreamState1
			}
			upstreamState1.FailedUpstreams = append(upstreamState1.FailedUpstreams, res.resolvedURL)
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

// UpstreamSet is an immutable snapshot of clients + their failover selector.
// It is replaced atomically on reload, so ForwardToDoH always sees a
// consistent pair — never new clients with stale failover or vice versa.
type UpstreamSet struct {
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
func (um *UpstreamManager) GetOrBuildSet() *UpstreamSet {
	set := um.activeSet.Load()
	if set == nil {
		set = um.buildSet(false)
	}
	return set
}

// can panic/shutdown
func (um *UpstreamManager) buildSet(rebuild bool) *UpstreamSet {
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
	// XXX: must re-fetch AFTER updateInnerState() succeeds, not before: since
	// updateInnerState() now publishes a brand-new cloned *Config instead of
	// mutating the old one in place (see its doc comment for why), a cfg
	// fetched prior to the call would be a stale snapshot whose
	// UpstreamURLsParsed/UpstreamIPs/UpstreamSNIs fields are still nil/outdated.
	cfg := um.getConfig()
	log.Debug("Upstreams (re)validated",
		SafeStringSlice("upstreamURLs", cfg.UpstreamURLs),
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
	// Loop-invariant (same cfg for every upstream), so compute it once rather than per-iteration.
	upstreamReadTimeout := computeUpstreamReadTimeoutDuration(cfg)
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
					Timeout: secondsToDuration(cfg.UpstreamDialTimeoutSec),
					// Encourages OS-level keep-alives
					KeepAlive: secondsToDuration(cfg.UpstreamTCPKeepAliveSec), //doneTODO: const or configurable?
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

				// Read/write deadlines are intentionally independent — see rwTimeoutConn's and
				// computeUpstreamReadTimeoutDuration's doc comments for why.
				return &rwTimeoutConn{
					Conn:         conn,
					readTimeout:  upstreamReadTimeout,
					writeTimeout: secondsToDuration(cfg.UpstreamClientTimeoutSec),
				}, nil
			},
			TLSClientConfig: &tls.Config{
				ServerName:         sniHost,
				InsecureSkipVerify: false,
			},
			// Explicit bound on the TLS handshake phase. This used to be an incidental side
			// effect of rwTimeoutConn sharing one timeout for both read and write; now that the
			// read side is intentionally generous (see computeUpstreamReadTimeoutDuration), this
			// keeps handshake time bounded on its own instead of inheriting that laxity.
			TLSHandshakeTimeout: secondsToDuration(cfg.UpstreamClientTimeoutSec),
			Proxy:               nil,  // avoid proxy interference
			ForceAttemptHTTP2:   true, // allow http2 negotiation via ALPN (needed for 9.9.9.9 due to it saying this "This server implements RFC 8484 - DNS Queries over HTTP, and requires HTTP/2 in accordance with section 5.2 of the RFC."
			IdleConnTimeout:     secondsToDuration(cfg.UpstreamIdleConnTimeoutSec),
			MaxIdleConns:        cfg.UpstreamMaxIdleConns,
			MaxIdleConnsPerHost: cfg.UpstreamMaxIdleConnsPerHost,
		}
		// --- NEW: Proactive HTTP/2 Health Checks ---
		// This extracts the hidden HTTP/2 transport and configures PING frames.
		t2, err := http2.ConfigureTransports(t)
		if err == nil {
			// If the connection is idle (no reads) for 5 seconds, send an HTTP/2 PING.
			t2.ReadIdleTimeout = secondsToDuration(cfg.UpstreamH2ReadIdleTimeoutSec) //doneTODO: shall we make this configurable in config.json or base it on something that already exists and makes sense to be based on? and/or on the below t2.PingTimeout for any clamps?
			// If the upstream doesn't ACK the PING within 2 seconds, destroy the zombie connection.
			t2.PingTimeout = secondsToDuration(cfg.UpstreamH2PingTimeoutSec) //doneTODO: shall we make this configurable in config.json or base it on something that already exists and makes sense to be based on? and/or on the above t2.ReadIdleTimeout for any clamps? Also how does this fare with the dialer's KeepAlive of 15 sec from above? do we need to change things or their timeout values to make these work well together?
		}

		um.dohTransportsPtrs = append(um.dohTransportsPtrs, t)
		if um.dohTransportsPtrs[i] != t {
			panic2("BUG: dev fail: dohTransportsPtrs[i] != t")
		}

		// Bundle everything this specific upstream needs to execute queries completely independently
		newUpstreams = append(newUpstreams, Upstream{
			Client: &http.Client{
				Timeout:   secondsToDuration(cfg.UpstreamClientTimeoutSec),
				Transport: t,
			},
			URL:                           u,
			SNI:                           sniHost,
			liveLogger:                    um.liveLogger,
			Retries:                       cfg.UpstreamRetriesPerQuery,
			RetryBackoffDuration:          millisToDuration(cfg.UpstreamRetryBackoffMs /*clamped later on, at use-site*/),
			UpstreamClientTimeoutDuration: secondsToDuration(cfg.UpstreamClientTimeoutSec /*used as is, good or bad, tho clamped in loadMainConfig()*/),
			BackgroundCtx:                 um.serverCtx,
			CertLogTimeoutSec:             cfg.CertLogTimeoutSec,
		})
	}

	newSet := &UpstreamSet{
		upstreams: newUpstreams,
		failover:  NewFailoverSelector(um.liveLogger, um.flushLogs), // fresh: activeIndex=0, allFailed=false
	}
	// 6. ATOMIC STORE
	um.activeSet.Store(newSet)
	log.Debug("DoH clients initialized", slog.Int("count", len(newUpstreams)))
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

// computeUpstreamReadTimeoutDuration returns the raw-socket read deadline for rwTimeoutConn.
//
// This is deliberately NOT tied to UpstreamClientTimeoutSec (the per-request budget). HTTP/2
// connections are pooled and sit idle between DNS queries by design — that's the whole point of
// upstream_max_idle_conns / upstream_idle_conn_timeout_sec. A read deadline as short as the
// per-request budget fires on every idle gap longer than that, tearing the connection down and
// forcing a brand-new TCP+TLS+HTTP/2 handshake on the very next query, silently defeating
// pooling. Dead/zombie connections are instead primarily detected by the HTTP/2 transport's own
// ReadIdleTimeout+PingTimeout health check (configured via http2.ConfigureTransports below),
// which pings after upstream_h2_read_idle_timeout_sec of silence and evicts the connection if no
// PONG arrives within upstream_h2_ping_timeout_sec. That ping/pong traffic still flows through
// this same wrapped Read(), so summing all three durations guarantees this raw deadline only
// ever fires as a last-resort backstop — strictly after every h2-native mechanism has already
// had its chance — rather than being the primary detector. A ceiling keeps that backstop
// bounded even if an operator configures unusually large idle/ping values. The summation itself
// is also overflow-safe against extreme hand-edited values (see the per-term clamp below).
func computeUpstreamReadTimeoutDuration(cfg *Config) time.Duration {
	const absoluteCeiling = 10 * time.Minute

	// Each term is clamped (in seconds, before any multiplication) to a
	// bound far above absoluteCeiling but far below any risk of overflow
	// once summed and multiplied by time.Second — see secondsToDuration's
	// doc comment for the identical class of concern. Summing three values
	// each capped at perTermCapSec can never come close to overflowing an
	// int64 seconds count, and multiplying that safely-small sum by
	// time.Second can never overflow time.Duration's own int64 nanosecond
	// range either.
	const perTermCapSec = int64(24 * time.Hour / time.Second) // 86400s

	clampSec := func(v int) int64 {
		if v <= 0 {
			return 0
		}
		if int64(v) > perTermCapSec {
			return perTermCapSec
		}
		return int64(v)
	}

	sumSec := clampSec(cfg.UpstreamIdleConnTimeoutSec) + clampSec(cfg.UpstreamH2ReadIdleTimeoutSec) + clampSec(cfg.UpstreamH2PingTimeoutSec)
	sum := time.Duration(sumSec) * time.Second
	if sum > absoluteCeiling {
		return absoluteCeiling
	}
	return sum
}

// rwTimeoutConn wraps a net.Conn to enforce independent timeouts on Read and Write.
//
// The write side stays tight, tied to UpstreamClientTimeoutSec (the per-request budget): a
// healthy connection should always be able to accept a small HTTP/2 frame quickly, so a stuck
// Write() indicates a genuinely wedged socket (e.g. a zero TCP window against a peer that's
// gone silent) and should fail fast.
//
// The read side is deliberately much more generous — see computeUpstreamReadTimeoutDuration for
// why tying it to the per-request budget would sabotage HTTP/2 connection pooling.
type rwTimeoutConn struct {
	net.Conn
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func (c *rwTimeoutConn) Read(b []byte) (int, error) {
	if c.readTimeout > 0 {
		if err := c.SetReadDeadline(time.Now().Add(c.readTimeout)); err != nil {
			return 0, fmt.Errorf("failed to set read deadline (%d) on upstream conn: %w", c.readTimeout, err)
		}
	}
	n, err := c.Conn.Read(b)
	if err != nil {
		return n, fmt.Errorf("failed to read from net connection: %w", err)
	}
	return n, nil
}

func (c *rwTimeoutConn) Write(b []byte) (int, error) {
	if c.writeTimeout > 0 {
		if err := c.SetWriteDeadline(time.Now().Add(c.writeTimeout)); err != nil {
			// Return 0 bytes written and wrap the error so the caller knows exactly what failed
			return 0, fmt.Errorf("failed to set write deadline (%d) on upstream conn, err: %w", c.writeTimeout, err)
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
	return c // Go automatically promotes the concrete pointer to the DNSCache interface
}

func (s *Server) swapDNSCache(janitorIntervalMinutes, maxEntries int) {
	if s.rt == nil {
		panic2("BUG: uninited Server.Runtime")
	}
	if s.rt.LogMgr == nil {
		panic2("BUG: uninited Server.Runtime.LogMgr")
	}
	var logPtr *atomic.Pointer[slog.Logger] = s.rt.LogMgr.Ptr()
	if logPtr == nil {
		panic2("BUG: should never return nil for s.rt.LogMgr.Ptr()")
	}
	newCache := newGoCacheStore(time.Duration(janitorIntervalMinutes)*time.Minute, maxEntries, logPtr)
	s.liveDNSCache.Store(&newCache)
}
func (s *Server) flushDNSCache() {
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
	// ── Semaphore init
	// Must happen before the accept goroutine starts so every Accept() can
	// immediately check capacity.  loadConfig has already validated the
	// value, but defend against a zero here just in case.
	sem := make(chan struct{}, maxConns)
	s.dnsTCPSem.Store(&sem)
}

func (s *Server) acquireDNSTCPSlot() (release func(), ok bool) {
	// ── Concurrent-connection gate ─
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
		// 2. Grab a buffer pointer from the pool
		bufPtr, ok := udpPool.Get().(*[]byte)
		if !ok {
			panic2("BUG: not of *[]byte type")
		}
		if bufPtr == nil {
			panic2("BUG: somehow stored a nil in cache")
		}
		buf := *bufPtr

		//start := time.Now()
		n, clientAddr, err2 := udpLn.ReadFromUDP(buf) //this is blocking here until there's enough/any? data or something
		// if elapsed := time.Since(start); elapsed > 10*time.Millisecond {
		// 	wincoe.GetBugLogger().Warn("slow ReadFromUDP in runDNSUDPLoop",
		// 		slog.Duration("elapsed", elapsed),
		// 	)
		// }
		log3 := s.getLogger()
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

		start := time.Now()
		log3.Debug("client connected(early logging)", //doneitasyncloggingnowFIXME: this can stall for over 1 minute during AnythingLLM installation which causes 11sec avg. response time for C: disk and 100% active time for minutes!
			slog.String("proto", "UDP"),
			SafeAddr("clientAddr", clientAddr),
		)
		if elapsed := time.Since(start); elapsed > 10*time.Millisecond {
			wincoe.GetBugLogger().Warn("slow log.Debug() in runDNSUDPLoop",
				slog.Duration("elapsed", elapsed),
			)
		}

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
		//ok ^ moved!

		// start = time.Now()
		// pid, exe, err2 := wincoe.PidAndExeForUDP(clientAddr)
		// if elapsed := time.Since(start); elapsed > 10*time.Millisecond {
		// 	wincoe.GetBugLogger().Warn("slow wincoe.PidAndExeForUDP() in runDNSUDPLoop",
		// 		slog.Duration("elapsed", elapsed),
		// 	)
		// }

		// --- 1. ACQUIRE SEMAPHORE FIRST ---
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
		// ---

		// --- 2. THEN START METADATA LOOKUP ---
		// NOTE: deliberately rooted in s.ctx, not the per-listener instance ctx — an in-flight
		// query's upstream forwarding should only be cancelled by full process shutdown, not
		// by this specific listener instance being torn down during a hot rebind.
		//udpPacketCtx := s.makeClientInfoContext(s.ctx, "UDP", clientAddr, pid, exe, err2)
		udpPacketCtx := s.startMetadataLookup(s.ctx, "UDP", clientAddr) //non-blocking!

		// --- 3. PROCEED TO HANDLER ---
		// TRACK INDIVIDUAL REQUESTS:

		// s.shutdownWG.Add(1)
		// go func(pCtx context.Context, data []byte, bufferPtr *[]byte, addr *net.UDPAddr, ln *net.UDPConn, rel func()) {
		// 	defer s.shutdownWG.Done()
		// 	defer udpPool.Put(bufferPtr) // 4. Recycle buffer when the handler finishes
		// 	defer rel()                  // Release the slot when the goroutine exits
		// 	s.handleUDP(pCtx, data, addr, ln)
		// }(udpPacketCtx, buf[:n], bufPtr, clientAddr, udpLn, release)
		pCtx := udpPacketCtx
		var data []byte = buf[:n]
		var bufferPtr *[]byte = bufPtr
		var addr *net.UDPAddr = clientAddr
		var ln *net.UDPConn = udpLn
		rel := release
		s.GoSafe(func() {
			defer udpPool.Put(bufferPtr) // 4. Recycle buffer when the handler finishes
			defer rel()                  // Release the slot when the goroutine exits
			s.handleUDP(pCtx, data, addr, ln)
		})
	} //infinite 'for'
}

// dnsTCPKeepAlivePeriod is the OS-level TCP keep-alive probe interval applied
// to every accepted plain-DNS-over-TCP client connection (see runDNSTCPLoop).
// This lets the OS network stack detect and reap dead/idle/misbehaving client
// connections instead of them lingering silently until our own read/write
// deadlines (ClientTCPTimeoutSec, applied per I/O operation, not to a fully
// idle connection) eventually catch them.
const dnsTCPKeepAlivePeriod = 30 * time.Second

func (s *Server) runDNSTCPLoop(ctx context.Context, tcpLn *net.TCPListener) {
	log2 := s.getLogger()
	log2.Info("TCP DNS listening", slog.String("address", tcpLn.Addr().String()))

	for {
		conn, err := tcpLn.Accept()
		log3 := s.getLogger()
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

		// Enable OS-level TCP keep-alive probes so idle, broken, or
		// misbehaving client connections are detected and reaped by the OS
		// network stack, rather than lingering silently in memory.
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			if err2 := tcpConn.SetKeepAlive(true); err2 != nil {
				log3.Debug("failed to enable TCP keep-alive on accepted DNS TCP connection", wincoe.SafeErr(err2))
			} else if err3 := tcpConn.SetKeepAlivePeriod(dnsTCPKeepAlivePeriod); err3 != nil {
				log3.Debug("failed to set TCP keep-alive period on accepted DNS TCP connection", wincoe.SafeErr(err3))
			}
		}

		// ── Concurrent-connection gate ─
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
			//okfixed//itisnecessarysonothingtodoFIXME: this slows down things here until it's ready to tcpLn.Accept() (above) again!
			// 2. Call your new TCP PID/Exe helper

			//pid, exe, pidErr := wincoe.PidAndExeForTCP(clientAddr)
			//tcpPacketCtx = s.makeClientInfoContext(tcpPacketCtx, "TCP", clientAddr, pid, exe, pidErr)
			tcpPacketCtx = s.startMetadataLookup(tcpPacketCtx, "TCP", clientAddr)
		}
		// accepted a connection; handle in new goroutine

		// TRACK INDIVIDUAL CONNECTIONS:
		//XXX: tcpPacketCtx is passed as arg(instead of as above commented out code) because: "Because that goroutine might not start instantly, the loop might move on to the next connection before the first goroutine actually reads the value of tcpPacketCtx." - Gemini 3 Thinking
		//Passing arguments vs. creating a local variable are two ways to achieve the exact same safety result
		// 1. Freeze/copy the interface headers synchronously in the current loop iteration
		c := conn
		pCtx := tcpPacketCtx
		rel := release
		// 2. Hand them off to GoSafe
		s.GoSafe(func() {
			defer rel()     // always release the slot
			defer c.Close() //nolint:errcheck // best-effort close, nothing to do on error

			s.handleTCP(pCtx, c)
		})
		// s.shutdownWG.Add(1)
		// go func(c net.Conn, pCtx context.Context, rel func()) {
		// 	defer s.shutdownWG.Done() // This fires when handleTCP returns

		// 	defer rel() // always release the slot

		// 	defer c.Close() //nolint:errcheck // best-effort close, nothing to do on error

		// 	s.handleTCP(pCtx, c)
		// }(conn, tcpPacketCtx, release)
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
	s.GoSafe(func() {
		defer inst.wg.Done()
		<-instCtx.Done()
		udpConn.Close() //nolint:errcheck // best-effort close, nothing to do on error

		// This wakes up Accept() with an error safely
		tcpLn.Close() //nolint:errcheck // best-effort close, nothing to do on error
	})

	inst.wg.Add(1)
	s.GoSafe(func() {
		defer inst.wg.Done()
		s.runDNSUDPLoop(instCtx, udpConn)
	})

	inst.wg.Add(1)
	s.GoSafe(func() {
		defer inst.wg.Done()
		s.runDNSTCPLoop(instCtx, tcpLn)
	})

	return inst, nil
}

// non-blocking!
func (s *Server) rebindDNSListener(params dnsListenerParams) {
	old := s.dnsListener.Load()
	if old != nil && old.params == params {
		s.getLogger().Debug("DNS rebind/relisten not done, params are same")
		return
	}

	// If binding to the exact same address (e.g. only non-address params changed),
	// we MUST close the old listener first to avoid "address already in use" errors.
	sameAddr := old != nil && old.params.Addr == params.Addr
	if sameAddr {
		old.cancel()
		old.wg.Wait()
	}

	newInst, err := s.startDNSListenerInstance(params)
	if err != nil {
		s.logFatal(fmt.Sprintf("DNS listener (re)bind to %+v failed", params), err)
		panic2("BUG: unreachable")
	}
	s.dnsListener.Store(newInst)

	// If the address changed, we kept the old listener alive during the new bind
	// to ensure zero downtime. Close it now that the new one is active.
	if old != nil && !sameAddr {
		old.cancel()
		old.wg.Wait()
	}
}

// liveLoggerWriter bridges the traditional log.Logger API used by
// http.Server.ErrorLog to the application's hot-swappable slog logger.
//
// The writer resolves the logger on every Write rather than capturing one at
// HTTP-server construction time. This is important because LoggerManager
// replaces the logger and closes the old log writers during config reload.
type liveLoggerWriter struct {
	liveLogger *atomic.Pointer[slog.Logger]
}

func (w *liveLoggerWriter) Write(p []byte) (int, error) {
	if w == nil || w.liveLogger == nil {
		return 0, errors.New("liveLoggerWriter: logger is not initialized")
	}

	logger := w.liveLogger.Load()
	if logger == nil {
		return 0, errors.New("liveLoggerWriter: active logger is nil")
	}

	message := strings.TrimRight(string(p), "\r\n")
	if message == "" {
		return len(p), nil
	}

	logger.Error(message) //you choose the severity for all records emitted through that legacy log.Logger adapter.
	return len(p), nil
}

func newLiveLoggerErrorLog(liveLogger *atomic.Pointer[slog.Logger]) *stdlog.Logger {
	if liveLogger == nil {
		panic2("BUG: newLiveLoggerErrorLog called with nil live logger pointer")
	}

	return stdlog.New(&liveLoggerWriter{liveLogger: liveLogger}, "", 0)
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
		Handler:  mux,
		ErrorLog: newLiveLoggerErrorLog(s.rt.LogMgr.Ptr()), // tell it to use our logger for things like "2026/08/12 13:41:41 http: TLS handshake error from 127.0.0.1:53871: remote error: tls: bad certificate"
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
	// Listen for the global shutdown signal to gracefully close the DoH server
	s.GoSafe(func() {
		defer inst.wg.Done()
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
	})

	inst.wg.Add(1)
	s.GoSafe(func() {
		defer inst.wg.Done()
		// Graceful close on shutdown
		defer listener.Close() //nolint:errcheck // best-effort close, nothing to do on error
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.getLogger().Error("doh_serve_failed", wincoe.SafeErr(err), slog.String("addr", addr))
			s.errChan <- fmt.Errorf("DoH server failed on %q: %w", addr, err)
		}
	})

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

	sameAddr := old != nil && old.params.Addr == params.Addr
	if sameAddr {
		old.cancel()
		old.wg.Wait()
	}

	newInst, err := s.startDoHListenerInstance(params)
	if err != nil {
		s.logFatal(fmt.Sprintf("DoH listener (re)bind to %+v failed", params), err)
		panic2("BUG: unreachable")
	}
	s.dohListener.Store(newInst)

	if old != nil && !sameAddr {
		old.cancel()
		old.wg.Wait()
	}
}

func (s *Server) initAdminUI() {
	ui := NewAdminUI(
		&s.liveConfigs,
		//&s.liveRawConfig,
		s.rt.LogMgr.Ptr(),
		s.rt.LogMgr,
		s.ruleStore,
		s.hostStore,
		s.blacklist,
		&s.tableMutationMu,
		newLoginTracker(),
		s.recentBlocks,
		s.blockedQueries,
		uiTemplates0,
	)
	// WebUI-request rate limiting, independent of the DNS-query rate limiter
	// (s.rateLimiter) and of loginTracker (which only throttles failed logins).
	ui.rateLimiter = newClientRateLimiter( /*s.ctx, */ webUIRateLimitConfigFrom(*s.getConfig()), s.getLogger())

	// Query-blocklist WebUI wiring: reuses the shared *RuleStore machinery
	// (implemented in this same file) and the same externalBlocklist
	// snapshot the DNS hot path reads via s.checkQueryBlocklist.
	ui.queryBlocklistStore = s.queryBlocklistStore
	ui.externalBlocklist = &s.externalBlocklist
	// Powers the /blocks page's "Recent Allows" view shown in allow-mode
	// (WhitelistMode=false) — see Server.recentAllowed's doc comment.
	ui.recentAllowed = s.recentAllowed

	// Wire up the side-effects
	ui.OnSaveWhitelist = s.saveQueryWhitelist
	ui.OnSaveBlacklist = s.saveResponseBlacklist
	ui.OnSaveHosts = s.saveLocalHosts
	ui.OnSaveQueryBlocklist = s.saveQueryBlocklist
	ui.OnInvalidatePattern = s.invalidateCacheForPattern
	ui.OnInvalidatePatterns = s.invalidateCacheForPatterns
	ui.OnInvalidateBlacklist = s.invalidateCacheForBlacklistedIPs
	ui.OnApplyConfig = func(cfg *Config) error {
		// Runtime.FileWriter is process-lifetime: Reload() never replaces the
		// instance, it only mutates ExtraSafety/retry params in place via
		// ApplyFileWriterParams. saveConfig therefore always sees the live
		// FileWriter (with whatever params were last applied). If a future
		// change ever constructs a new FileWriter on Reload, this closure and
		// every other s.rt.FileWriter use site must be re-audited together.
		if err := saveConfig(s.rt.FileWriter, s.getLogger(), cfg); err != nil {
			//if err:=s.saveConfig() can't do this because it's not assigned yet, the s.Reload() below will "assign" it.
			return fmt.Errorf("config write due to [Apply] button, failed: %w", err)
		}
		if err := s.Reload(); err != nil {
			return fmt.Errorf("config was saved to disk but the reload did not apply it (fix any reported error and try Apply again, or wait for the in-progress reload to finish): %w", err)
		}
		return nil
	}
	// OnReloadConfig / OnClearCache power the /control page's "Reload
	// Config" and "Clear DNS Cache" buttons — see their doc comments on
	// AdminUI for what each does.
	ui.OnReloadConfig = s.Reload
	ui.OnClearCache = s.flushDNSCache
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
	s.dohCertMu.RLock()
	loaded := isCertLoaded(&s.dohCert)
	s.dohCertMu.RUnlock()
	if loaded {
		return // normal fast path
	}

	log := s.getLogger()
	log.Warn("BUG: TLS cert not loaded before listener start (generateCertIfNeeded was never called or ran out of order); attempting emergency generation now")
	s.generateCertIfNeeded()

	s.dohCertMu.RLock()
	loaded = isCertLoaded(&s.dohCert)
	s.dohCertMu.RUnlock()
	if !loaded {
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
	s.dohCertMu.RLock()
	defer s.dohCertMu.RUnlock()
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
		Handler:  s.adminUI.SetupRoutes(boundAddr, params.UseTLS),
		ErrorLog: newLiveLoggerErrorLog(s.rt.LogMgr.Ptr()),
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
	s.GoSafe(func() {
		defer inst.wg.Done()
		<-instCtx.Done()
		log := s.getLogger()
		cfg := s.getConfig()
		log.Debug("Shutting down Web UI listener instance...", slog.String("addr", addr))
		shutdownCtx, cancelDown := context.WithTimeout(context.Background(), time.Duration(cfg.ServerGracefulShutdownSec)*time.Second)
		defer cancelDown()
		if err2 := srv.Shutdown(shutdownCtx); /*this call returns*/ err2 != nil && !errors.Is(err2, context.Canceled) {
			log.Warn("webUI server shutdown error", wincoe.SafeErr(err2))
		}
	})

	inst.wg.Add(1)
	s.GoSafe(func() {
		defer inst.wg.Done()
		// Graceful close
		defer finalListener.Close() //nolint:errcheck // best-effort close, nothing to do on error
		if err2 := srv.Serve(finalListener); err2 != nil && !errors.Is(err2, http.ErrServerClosed) {
			log := s.getLogger()
			log.Error("ui_serve_failed", wincoe.SafeErr(err2), slog.String("addr", addr))
			s.errChan <- fmt.Errorf("webUI server failed on %q: %w", addr, err2)
		}
	})

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

	// ONLY log interactive controls if there is an actual console to type them into
	if wincoe.HasConsole() {
		log.Info("Interactive controls available: Ctrl+X to clean exit, Ctrl+R to reload config, Ctrl+C to break gracefully")
	}

	return inst, nil
}

func (s *Server) rebindWebUIListener(params uiListenerParams) {
	old := s.uiListener.Load()
	if old != nil && old.params == params {
		s.getLogger().Debug("webUI rebind/relisten not done, params are same")
		return
	}

	sameAddr := old != nil && old.params.Addr == params.Addr
	if sameAddr {
		old.cancel()
		old.wg.Wait()
	}

	newInst, err := s.startWebUIListenerInstance(params)
	if err != nil {
		s.logFatal(fmt.Sprintf("WebUI listener (re)bind to %+v failed", params), err)
		panic2("BUG: unreachable")
	}
	s.uiListener.Store(newInst)

	if old != nil && !sameAddr {
		old.cancel()
		old.wg.Wait()
	}
}

type dnsListenerParams struct {
	Addr          string
	UDPBufferSize int
}

func dnsListenerParamsFrom(cfg *Config) dnsListenerParams {
	return dnsListenerParams{
		Addr:          cfg.ListenDNS,
		UDPBufferSize: cfg.DNSUDPBufferSize,
	}
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
	start := time.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	lockHeld := time.Since(start)
	if lockHeld > time.Second {
		fmt.Fprintf(os.Stderr,
			"rotatingLogWriter.Write() lock waited %v\n",
			lockHeld)
	}

	if w.file == nil {
		return 0, errors.New("rotatingLogWriter, log file is not open")
	}
	w.rotateIfNeededYouHoldLock()

	if w.file == nil {
		// rotateIfNeededYouHoldLock's rotation attempt (and its reopenOriginal
		// fallback) both failed catastrophically; there is nothing left to write
		// to. Continuing without logs is worse than aborting: operators would
		// silently lose the audit trail. panic2 logs via GetBugLogger (and
		// stderr via the surrounding recover paths) before terminating.
		panic2(fmt.Sprintf("rotatingLogWriter: log file %q is not open after failed rotation — refusing to continue without logging", w.path))
		panic(nil)
	}

	start = time.Now()
	n, err = w.file.Write(p)
	writeTime := time.Since(start)
	w.size += int64(n)

	if writeTime > DISK_STALL_DETECT_AFTER_THIS_MANY_SECONDS*time.Second {
		fmt.Fprintf(os.Stderr,
			"rotatingLogWriter file.Write took %v for a log msg that's somewhere above\n", //can't say for which log msg or contents of it!
			writeTime) // don't include 'p' or string(p) here because you're not allow to reuse it after the .Write(p) !

		if err == nil { // if it didn't err for the above w.file.Write(p), then we attempt to write/add this, as it's guaranteed to be sequential due to caller's lock!
			// Format your second message safely
			warningMsg := fmt.Sprintf("rotatingLogWriter file.Write took %v for the exactly-above log msg\n", writeTime) // can't reuse 'p' here!

			// Write it directly to the file while we still hold the lock
			n2, err2 := w.file.WriteString(warningMsg) //w.file.Write([]byte(warningMsg))

			w.size += int64(n2) // Track the second write so rotation stays accurate

			if err2 != nil {
				// handle error if needed
				fmt.Fprintf(os.Stderr, "rotatingLogWriter file.Write failed to write the above 'took' msg into file, err:%v", err2)
			}
		} else {
			fmt.Fprintf(os.Stderr, "rotatingLogWriter file.Write skipped writing the above 'took' msg into file also, because the prev. attempt (that 'took' that much time) failed with err:%v", err)
		}
	}

	if err == nil {
		return n, nil
	} else {
		return n, fmt.Errorf("rotatingLogWriter, failed to write to the rotating logger file: %w", err)
	}
}

const DISK_STALL_DETECT_AFTER_THIS_MANY_SECONDS = 1

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
	// 2. Determine the dynamic backup name (.1, .2, etc.)
	backupPath, err := getNextLogBackupName(w.path)
	if err != nil {
		w.logger.Error("Log rotation failed: could not get the next logfile name",
			wincoe.SafeErr(err),
			slog.String("current_log", w.path),
			slog.String("gotten_new_log_filename", backupPath),
		)
		return
	}

	// 1. Close the current file so Windows doesn't block the rename
	if err2 := w.file.Close(); err2 != nil {
		w.logger.Error("Log rotation failed: could not close current log file", slog.String("path", w.path), wincoe.SafeErr(err2))
		w.file = nil // clear stale handle so reopenOriginal() starts from a known state
		w.reopenOriginal()
		return
	}
	// Clear the now-closed handle immediately. From this point on, every error
	// path calls reopenOriginal(); if that also fails, w.file stays nil and
	// Write() returns the informative "log file is not open" sentinel rather
	// than a cryptic OS error from writing to a dead file descriptor.
	w.file = nil

	// 3. Rename the file
	if err3 := os.Rename(w.path, backupPath); err3 != nil {
		w.logger.Error("Log rotation failed: rename error", slog.String("path", w.path), slog.String("backup", backupPath), wincoe.SafeErr(err3))
		w.reopenOriginal()
		return
	}

	// 4. Attempt to create the fresh log file
	newFile, err4 := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err4 != nil {
		w.logger.Warn("Log rotation failed to create new file; rolling back to previous log", slog.String("path", w.path), wincoe.SafeErr(err4))

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
// to write to, even if rotation or rollback fails. It also re-derives w.size
// from the actual file on disk: a create-new-file failure followed by a failed
// rollback-rename leaves a brand-new, empty file at w.path while w.size would
// otherwise still reflect the old, pre-rotation size, which would make every
// subsequent Write() believe the fresh file is still oversized and endlessly
// reattempt rotation.
func (w *rotatingLogWriter) reopenOriginal() {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		w.logger.Error("CRITICAL: Failed to reopen original log file after rotation failure", slog.String("path", w.path), wincoe.SafeErr(err))
		return
	}
	w.file = f
	if stat, statErr := f.Stat(); statErr == nil {
		w.size = stat.Size()
	} else {
		w.size = 0
		w.logger.Warn("Failed to stat reopened log file after rotation failure; size tracking may be stale until next successful rotation", slog.String("path", w.path), wincoe.SafeErr(statErr))
	}
}

type ConfigFieldView struct {
	Key       string
	Value     string
	ValueJSON string
	Type      string
	Desc      string
	//Options    string // Comma-separated list for dropdowns
	IsPassword        bool   // Flag to trigger password masking and confirmation
	ModifiedAtDisplay string // Human-readable last-WebUI-modification timestamp (see Config.FieldModifiedAt)
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
		var valueJSON string
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

				encoded, err := json.Marshal(sl)
				if err != nil {
					panic2(fmt.Sprintf("BUG: failed to JSON-encode config []string field %q: %v", tagKey, err))
				}
				valueJSON = string(encoded)

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
			// log.Error("BUG: Config UI generator skipped unsupported field type",
			// 	"field", tagKey,
			// 	"kind", kind.String()) // XXX: this works but we try to avoid this!
			log.Error("BUG: Config UI generator skipped unsupported field type",
				slog.String("field", tagKey),
				slog.String("kind", kind.String()),
			)
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
			Key:       tagKey,
			Value:     strVal,
			ValueJSON: valueJSON,
			Type:      typ,
			Desc:      field.Tag.Get("desc"),
			//Options: options,
			IsPassword:        isPwd,
			ModifiedAtDisplay: formatModifiedAt(cfg.FieldModifiedAt[tagKey]),
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
	const allowedMethods = "GET, HEAD, POST, OPTIONS"
	if writeAllowHeaderResponse(w, r, allowedMethods) {
		return
	}
	log := ui.getLogger()

	if r.Method == http.MethodGet || r.Method == http.MethodHead {
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

			"ConfigVersion":   configVersion,
			"ConfigFileName":  configFileName,
			"ConfigBackupExt": wincoe.BackupFileExtension,

			//Dynamically inject the UpstreamURLs JSON tag
			"UpstreamURLsKey": getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamURLs)),
			// Injected so app.js never hard-codes json tag strings.
			// If a Config field is renamed, only the struct tag changes; JS follows automatically.
			"KeyUpstreamSelectionMode": getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamSelectionMode)),
			"KeyConsoleLogLevel":       getJSONTagByOffset(unsafe.Offsetof(Config{}.ConsoleLogLevel)),
			"KeyBlockMode":             getJSONTagByOffset(unsafe.Offsetof(Config{}.BlockMode)),
			"KeyWebUIPasswordHash":     getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIPasswordHash)),
			"KeyWebUIAuthSessionMode":  getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIAuthSessionMode)),
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
			"OptsWebUIAuthSessionMode": strings.Join([]string{
				webUIAuthSessionModeLegacy,
				webUIAuthSessionModeSessionCookie,
				webUIAuthSessionModeTimeBucket,
			}, ","),
		}
		ui.renderTemplate(w, r, "config", data)
		return
	} // end GET/HEAD

	if r.Method == http.MethodPost {
		action := r.FormValue("action")
		if action == "apply" {
			// Serialize the entire check-version -> read -> merge -> validate ->
			// write -> reload sequence against other concurrent WebUI config
			// applies (e.g. two browser tabs, or a background timer). Without
			// this, the mtime-based optimistic-concurrency check below can be
			// defeated by two requests each passing their own check before
			// either one writes, letting one tab's change silently overwrite
			// the other's despite the version check.
			ui.configApplyMu.Lock()
			defer ui.configApplyMu.Unlock()

			// Computed once up front and reused everywhere a "default value"
			// fallback is needed in this handler (the password-hashing
			// interceptor below, and the sanitizeAndValidateConfig call further
			// down), so a staged-but-invalid bcrypt cost is hashed against the
			// exact same fallback that sanitizeAndValidateConfig will later
			// persist for it — otherwise the two could disagree (see
			// clampBcryptCostField) and the saved config.json would describe a
			// different bcrypt cost than the one actually baked into the hash
			// just created.
			defCfg := defaultConfig()

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
			// If it looks like a real, valid bcrypt hash, keep it as-is.
			// Otherwise, treat it as a new plaintext password and hash it.
			// Hash plaintext password before applying, same as before.
			if plainPwd, ok := changes[tagWebUIPwd].(string); ok {
				// Bcrypt hashes start with $2a$ or $2b$. If it doesn't, assume it's plaintext and hash it.
				//doneTODO: find out why this isn't needed here: && plainPwd != placeHolderPassword  so it's due to displayed vs edited being different areas even tho they seem to be in the same place in the UI.
				if plainPwd != "" && !isValidBcryptHash(plainPwd) { //strings.HasPrefix(plainPwd, "$2") {
					// Fetch current configured cost
					cost := ui.getConfig().WebUIPasswordBcryptCost
					// Prefer a cost staged in this SAME apply batch (e.g. the operator
					// raised webui_password_bcrypt_cost and set a new password in one
					// Apply), so the freshly-hashed password isn't silently generated
					// at the stale, pre-edit cost.
					tagBcryptCost := getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIPasswordBcryptCost))
					if stagedCost, hasStaged := changes[tagBcryptCost]; hasStaged {
						if stagedCostFloat, ok := stagedCost.(float64); ok { // encoding/json always decodes JSON numbers into interface{} as float64; there is no int64 alternative to have chosen here.
							stagedCostInt := int(stagedCostFloat)
							// Fall back to the compiled-in default cost (not the
							// currently-configured one) when the staged value is
							// out of bcrypt's valid range: sanitizeAndValidateConfig's
							// clampBcryptCostField (invoked further below on this
							// same request) clamps an out-of-range persisted value
							// to defCfg.WebUIPasswordBcryptCost too, so matching that
							// fallback here keeps the hash we're about to create and
							// the bcrypt cost we're about to persist in agreement.
							cost = getValidBcryptCost(stagedCostInt, defCfg.WebUIPasswordBcryptCost)
							if cost != stagedCostInt {
								log.Info(fmt.Sprintf("Using different %q than the staged/specified", tagBcryptCost), slog.Int("specified", stagedCostInt), slog.Int("actual_used", cost))
							}
						} else {
							log.Error(fmt.Sprintf("Failed to get staged bcrypt cost %q it's not float64", tagBcryptCost))
						}
					} else {
						// Normal/expected case: most password changes don't also
						// stage a new bcrypt cost in the same batch, so falling
						// back to the currently configured cost is routine, not
						// an error — logging it at Error level would spam
						// error-level logs (and any alerting built on them) for
						// every single ordinary password change via the WebUI.
						log.Debug(fmt.Sprintf("Using already configured %q", tagBcryptCost), slog.Int("current_cost", cost))
					}
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
				//if here, then it's isValidBcryptHash() so no need to touch it.
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

			// Record the exact instant each user-submitted field was applied,
			// for the WebUI's "Last Modified" config column (see
			// Config.FieldModifiedAt's doc comment). Only fields actually
			// present in this request's staged `changes` are touched — not
			// every key in `raw` (which also carries every OTHER field's
			// already-on-disk value, re-applied verbatim by
			// applyConfigChangesToStruct just above, and must not have its
			// timestamp bumped merely for being re-saved unchanged).
			if rawCfg.FieldModifiedAt == nil {
				rawCfg.FieldModifiedAt = make(map[string]time.Time, len(changes))
			}
			fieldModifiedNow := time.Now()
			for changedKey := range changes {
				rawCfg.FieldModifiedAt[changedKey] = fieldModifiedNow
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
			// defCfg was already computed once at the top of this "apply" branch
			// and reused by the password-hashing interceptor above; see its doc
			// comment for why reusing the same value here matters.
			_, errValid := sanitizeAndValidateConfig(log, resolved, &rawCfg, &defCfg, true)
			if errValid != nil {
				http.Error(w, "Validation failed: "+errValid.Error(), http.StatusBadRequest)
				return
			}

			// Commit to disk and trigger hot-reload
			if ui.OnApplyConfig != nil {
				err7 := ui.OnApplyConfig(&rawCfg)
				log = ui.getLogger() // <--- FIX: Refresh the logger pointer after the reload finishes!
				if err7 != nil {
					log.Error("Failed to apply config (that is: save&reload)", wincoe.SafeErr(err7))
					status := http.StatusInternalServerError
					if errors.Is(err7, errReloadAlreadyInProgress) {
						// The config WAS saved to disk successfully; a concurrent
						// reload (e.g. Ctrl+R, or a second WebUI Apply) just happened
						// to already be running and this one was skipped rather than
						// queued. 409 signals "retry shortly" rather than "broken".
						status = http.StatusConflict
					}
					http.Error(w, "Failed to save/reload config: "+err7.Error(), status)
					return
				}
			}

			log.Info("Config updated&saved via WebUI successfully")
			http.Redirect(w, r, "/config", http.StatusSeeOther)
			return
		}
		http.Error(w, fmt.Sprintf("unknown or missing action %q", action), http.StatusBadRequest)
		return
	}

	ui.rejectUnsupportedMethod(w, r, allowedMethods)
}

// shutdownHandler lets an authenticated operator gracefully stop the
// process from the WebUI. This is the only way to do so for a headless run
// (see Config.HideConsole), where Ctrl+X/Ctrl+C/Ctrl+Break are physically
// unreachable since there is no console to receive them.
func (ui *AdminUI) shutdownHandler(w http.ResponseWriter, r *http.Request) {
	const allowedMethods = "POST, OPTIONS"
	if writeAllowHeaderResponse(w, r, allowedMethods) {
		return
	}
	log := ui.getLogger()

	if r.Method != http.MethodPost {
		ui.rejectUnsupportedMethod(w, r, allowedMethods)
		return
	}

	if r.FormValue("confirm") != "yes" {
		log.Warn("WebUI shutdown request rejected: missing confirmation field", slog.String("client", r.RemoteAddr))
		http.Error(w, "missing confirmation", http.StatusBadRequest)
		return
	}

	if ui.OnShutdown == nil {
		log.Error("BUG: WebUI shutdown requested but no shutdown handler is wired (likely in a test environment)")
		http.Error(w, "shutdown is not available in this environment", http.StatusServiceUnavailable)
		return
	}

	log.Warn("Graceful shutdown requested via WebUI", slog.String("client", r.RemoteAddr))

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := io.WriteString(w, "Shutting down now. This connection and the WebUI will become unavailable shortly.\n"); err != nil {
		log.Debug("client disconnected before shutdown acknowledgement write completed", wincoe.SafeErr(err))
	}

	// Delay slightly and run off this request-handling goroutine so the
	// response above has a real chance to reach the client before the
	// WebUI listener (and then the whole process) tears down; OnShutdown
	// never returns normally (it ends in os.Exit), so it must not run
	// synchronously here.
	//
	// Intentionally a bare `go`, not GoSafe: GoSafe tracks goroutines in
	// Server.shutdownWG, which s.shutdown() itself waits on -- tracking the
	// very goroutine that *initiates* shutdown would deadlock.
	go func() {
		time.Sleep(500 * time.Millisecond)
		ui.OnShutdown(0)
	}()
}

func isValidBcryptHash(s string) bool {
	// A standard bcrypt string is always exactly 60 characters long
	if len(s) != 60 {
		return false
	}
	// Must start with valid bcrypt prefix: $2a$, $2b$, or $2y$ followed by cost + $
	// Example: $2a$10$ or $2b$12$
	if !strings.HasPrefix(s, "$2a$") && !strings.HasPrefix(s, "$2b$") && !strings.HasPrefix(s, "$2y$") {
		return false
	}
	// Verify the third '$' separator is at index 6 (e.g., "$2b$10$")
	if s[6] != '$' {
		return false
	}
	// The checks above only confirm the string LOOKS like a bcrypt hash by
	// length and prefix; they don't confirm it actually IS one. A dummy
	// 60-character string engineered to match that superficial shape would
	// otherwise be blindly accepted and persisted as the WebUI password hash
	// — since it's a dummy string the real plaintext is unknown, permanently
	// locking out every administrator. bcrypt.Cost parses the full hash
	// structure (cost field, base64-alphabet salt+hash) and errors on
	// anything malformed, so use it as the authoritative structural check.
	if _, err := bcrypt.Cost([]byte(s)); err != nil {
		return false
	}
	return true
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

	// Global bridge so our Win32 callback can reach your Server instance
	globalConsoleEventTrigger func(eventName string, exitCode int)

	// NEW: Flag to bypass the "Press any key" pause during forced teardowns
	skipInteractivePause atomic.Bool

	// consoleCtrlHandlerFired guards against consoleCtrlHandler re-entering its
	// shutdown-trigger logic. Windows can invoke a registered console control handler
	// on a brand-new OS thread for every signal it delivers, so an impatient second
	// Ctrl+C while the first shutdown is still in flight (e.g. waiting out
	// server_graceful_shutdown_sec) can genuinely re-enter this function
	// concurrently on a different thread, not just re-run sequentially after the
	// first call returns. s.shutdown's own shutdownOnce already prevents the
	// shutdown SEQUENCE from running twice, but this flag stops the second signal
	// from redundantly re-logging and re-entering globalConsoleEventTrigger at all,
	// rather than relying on sync.Once's blocking behavior (which would otherwise
	// leave that second thread parked indefinitely until the first shutdown's
	// terminal os.Exit tears down the whole process anyway).
	consoleCtrlHandlerFired atomic.Bool
)

// consoleCtrlHandler must be a top-level function with no free variables for windows.NewCallback().
// Only the FIRST console control event this process ever receives triggers the shutdown
// sequence; every subsequent invocation (including a concurrent one on another OS
// thread) is acknowledged and ignored — see consoleCtrlHandlerFired's doc comment.
func consoleCtrlHandler(ctrlType uint32) uintptr {
	var exitCode int = 0 // Default to 0 for window-closed,logoff,shutdown

	var eventName string
	switch ctrlType {
	case wincoe.CTRL_C_EVENT:
		eventName = "CTRL_C_EVENT (Ctrl+C)" //it's the sigChan one that triggers tho (this one does only while in shutdown())
		exitCode = 130
	case wincoe.CTRL_BREAK_EVENT:
		eventName = "CTRL_BREAK_EVENT (Ctrl+Break)"
		exitCode = 130
	case wincoe.CTRL_CLOSE_EVENT:
		skipInteractivePause.Store(true) // <-- Bypass pause! Console is closing.
		eventName = "CTRL_CLOSE_EVENT (Console Window Closed)"
	case wincoe.CTRL_LOGOFF_EVENT:
		skipInteractivePause.Store(true) // <-- Bypass pause! User is logging out.
		eventName = "CTRL_LOGOFF_EVENT (User Logoff)"
	case wincoe.CTRL_SHUTDOWN_EVENT:
		skipInteractivePause.Store(true) // <-- Bypass pause! OS is shutting down.
		eventName = "CTRL_SHUTDOWN_EVENT (System Shutdown)"
	default:
		// Return 0 (FALSE) for unhandled events so Windows continues standard routing
		return 0
	}

	if !consoleCtrlHandlerFired.CompareAndSwap(false, true) {
		// A shutdown is already in flight (this is a repeat/concurrent signal);
		// acknowledge it to Windows and do nothing further.
		return 1
	}

	if globalConsoleEventTrigger != nil {
		// This will block, eventually calling os.Exit() from inside your shutdown sequence.
		// This is required. If we returned 1 immediately, the OS would kill the process mid-cleanup.
		globalConsoleEventTrigger(eventName, exitCode)
	}

	return 1 // TRUE (Though os.Exit will usually fire before we ever reach this line)
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

// float64ToWholeInt64 converts a JSON-decoded float64 into an int64,
// requiring it to represent an exact whole number. encoding/json always
// decodes JSON numbers into interface{} as float64 (see the identical
// observation elsewhere in this file, near the WebUI bcrypt-cost staging
// logic), so a staged config field's numeric value arrives this way
// regardless of whether the browser-side JS validation (which does check
// Number.isSafeInteger) was ever exercised at all — a direct authenticated
// POST to /config bypasses it entirely. Silently truncating a fractional
// value (e.g. 12.9 -> 12, via a bare int64(n) conversion) would let such a
// request corrupt an integer config field without any error ever surfacing.
func float64ToWholeInt64(n float64) (int64, error) {
	if n != math.Trunc(n) {
		return 0, fmt.Errorf("value %v is not a whole number", n)
	}
	if n < math.MinInt64 || n > math.MaxInt64 {
		return 0, fmt.Errorf("value %v is out of range for a 64-bit integer", n)
	}
	return int64(n), nil
}

// float64ToWholeUint64 mirrors float64ToWholeInt64 for unsigned fields.
func float64ToWholeUint64(n float64) (uint64, error) {
	if n != math.Trunc(n) {
		return 0, fmt.Errorf("value %v is not a whole number", n)
	}
	if n < 0 || n > math.MaxUint64 {
		return 0, fmt.Errorf("value %v is out of range for an unsigned 64-bit integer", n)
	}
	return uint64(n), nil
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
			var whole int64
			switch n := rawVal.(type) {
			case float64:
				w, err := float64ToWholeInt64(n)
				if err != nil {
					return fmt.Errorf("field %q: %w", jsonKey, err)
				}
				whole = w
			case int:
				whole = int64(n)
			case int64:
				whole = n
			default:
				return fmt.Errorf("field %q: expected int, got %T", jsonKey, rawVal)
			}
			if fv.OverflowInt(whole) {
				return fmt.Errorf("field %q: value %d overflows field type %s", jsonKey, whole, fv.Kind())
			}
			fv.SetInt(whole)

		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			var whole uint64
			switch n := rawVal.(type) {
			case float64:
				w, err := float64ToWholeUint64(n)
				if err != nil {
					return fmt.Errorf("field %q: %w", jsonKey, err)
				}
				whole = w
			case uint64:
				whole = n
			default:
				return fmt.Errorf("field %q: expected uint, got %T", jsonKey, rawVal)
			}
			if fv.OverflowUint(whole) {
				return fmt.Errorf("field %q: value %d overflows field type %s", jsonKey, whole, fv.Kind())
			}
			fv.SetUint(whole)

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

// doubleWithoutOverflow returns v*2, saturating at math.MaxInt/math.MinInt
// instead of silently wrapping when v is large enough that v*2 would
// overflow the platform int. Used by the "idle timeout must be at least 2x
// the corresponding read timeout" clamp checks in sanitizeAndValidateConfig:
// an int overflow there would make the "<" comparison spuriously false for
// an enormous, hand-edited-config.json-supplied read-timeout value (the
// WebUI's own Number handling can't even represent such a value safely —
// see app.js's Number.isSafeInteger check on the config-editing path),
// letting an invalid idle/read timeout pair silently pass validation.
func doubleWithoutOverflow(v int) int {
	if v > math.MaxInt/2 {
		return math.MaxInt
	}
	if v < math.MinInt/2 {
		return math.MinInt
	}
	return v * 2
}

// secondsToDuration converts a configured count of seconds into a
// time.Duration, saturating at time.Duration's own maximum representable
// value instead of silently overflowing/wrapping when secs is large enough
// that secs*time.Second would exceed the int64 nanosecond range — see
// doubleWithoutOverflow's doc comment for the identical class of concern:
// every one of these seconds-denominated fields is an operator-controlled
// int with no enforced upper bound, reachable via a hand-edited
// config.json even though the WebUI's own Number handling can't represent
// such extreme values safely. A non-positive secs returns 0.
func secondsToDuration(secs int) time.Duration {
	if secs <= 0 {
		return 0
	}
	const maxSafeSec = int64(math.MaxInt64) / int64(time.Second)
	if int64(secs) > maxSafeSec {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(secs) * time.Second
}

// millisToDuration mirrors secondsToDuration for millisecond-denominated
// config fields (e.g. UpstreamRetryBackoffMs).
func millisToDuration(ms int) time.Duration {
	if ms <= 0 {
		return 0
	}
	const maxSafeMs = int64(math.MaxInt64) / int64(time.Millisecond)
	if int64(ms) > maxSafeMs {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(ms) * time.Millisecond
}

// clampIntField is the shared implementation behind sanitizeAndValidateConfig's many
// "clamp this int field to a safe value and flag the config for saving" blocks. invalid
// reports whether the field's current value is out of bounds; when it is, both resolved
// and raw are set to fallback (so the correction is persisted to disk on the next save)
// and a standardized warning is logged. msgSuffix is appended verbatim to the log message
// to preserve each call site's specific human-readable explanation (pass "" for none).
// extra lets a handful of call sites attach additional structured log fields (e.g. a
// cross-reference to the field that produced the fallback value). Returns true if a clamp
// was applied, so callers can fold the result straight into shouldSaveConfig.
func clampIntField(log *slog.Logger, tag string, resolved, raw *int, invalid func(int) bool, fallback int, msgSuffix string, extra ...any) bool {
	was := *resolved
	if !invalid(was) {
		return false
	}
	*resolved = fallback
	*raw = fallback
	args := append([]any{slog.Int("was", was), slog.Int("clamp", fallback)}, extra...)
	log.Warn(tag+" clamped"+msgSuffix, args...)
	return true
}

// // clampUint32Field mirrors clampIntField for the two uint32 TTL fields
// // (BlockedResponseTTLSec, LocalHostsOverrideTTLSec).
// func clampUint32Field(log *slog.Logger, tag string, resolved, raw *uint32, invalid func(uint32) bool, fallback uint32, msgSuffix string) bool {
// 	was := *resolved
// 	if !invalid(was) {
// 		return false
// 	}
// 	*resolved = fallback
// 	*raw = fallback
// 	log.Warn(tag+" clamped"+msgSuffix, slog.Uint64("was", uint64(was)), slog.Uint64("clamp", uint64(fallback)))
// 	return true
// }

// sanitizeAndValidateConfig handles validation, clamping, and cleaning of configuration fields.

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
	if clampBcryptCostField(log, tagWebUIPasswordBcryptCost, &resolvedCfg.WebUIPasswordBcryptCost, &rawCfg.WebUIPasswordBcryptCost, defaultCfg.WebUIPasswordBcryptCost) {
		shouldSaveConfig = true
	}

	// WebUI Basic-Auth session-expiry policy (webui_auth_session_mode /
	// webui_auth_session_timeout_minutes) — see Config.WebUIAuthSessionMode's
	// doc comment for what each mode does.
	origWebUIAuthSessionMode := resolvedCfg.WebUIAuthSessionMode
	resolvedCfg.WebUIAuthSessionMode = strings.ToLower(strings.TrimSpace(origWebUIAuthSessionMode))
	switch resolvedCfg.WebUIAuthSessionMode {
	case webUIAuthSessionModeLegacy, webUIAuthSessionModeSessionCookie, webUIAuthSessionModeTimeBucket:
		// valid
	default:
		msg := fmt.Sprintf("Unknown webui_auth_session_mode %q in config file %q, must be one of these: %q, %q, %q",
			resolvedCfg.WebUIAuthSessionMode,
			configFileName,
			webUIAuthSessionModeLegacy,
			webUIAuthSessionModeSessionCookie,
			webUIAuthSessionModeTimeBucket,
		)
		log.Error(msg, slog.String("webui_auth_session_mode", resolvedCfg.WebUIAuthSessionMode))
		return shouldSaveConfig, fmt.Errorf("%s", msg)
	}
	if origWebUIAuthSessionMode != resolvedCfg.WebUIAuthSessionMode {
		shouldSaveConfig = true
	}
	rawCfg.WebUIAuthSessionMode = resolvedCfg.WebUIAuthSessionMode

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIAuthSessionTimeoutMinutes)),
		&resolvedCfg.WebUIAuthSessionTimeoutMinutes, &rawCfg.WebUIAuthSessionTimeoutMinutes,
		func(v int) bool { return v <= 0 }, defaultCfg.WebUIAuthSessionTimeoutMinutes, "") {
		shouldSaveConfig = true
	}

	// =========================================================================
	// Group 1: WebUI Server Timeouts & Rate Limits
	// =========================================================================
	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIReadHeaderTimeoutSec)),
		&resolvedCfg.WebUIReadHeaderTimeoutSec, &rawCfg.WebUIReadHeaderTimeoutSec,
		func(v int) bool { return v <= 0 }, defaultCfg.WebUIReadHeaderTimeoutSec, "") {
		shouldSaveConfig = true
	}

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIReadTimeoutSec)),
		&resolvedCfg.WebUIReadTimeoutSec, &rawCfg.WebUIReadTimeoutSec,
		func(v int) bool { return v <= 0 }, defaultCfg.WebUIReadTimeoutSec, "") {
		shouldSaveConfig = true
	}

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIWriteTimeoutSec)),
		&resolvedCfg.WebUIWriteTimeoutSec, &rawCfg.WebUIWriteTimeoutSec,
		func(v int) bool { return v <= 0 }, defaultCfg.WebUIWriteTimeoutSec, "") {
		shouldSaveConfig = true
	}

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIIdleTimeoutSec)),
		&resolvedCfg.WebUIIdleTimeoutSec, &rawCfg.WebUIIdleTimeoutSec,
		func(v int) bool { return v < doubleWithoutOverflow(resolvedCfg.WebUIReadTimeoutSec) }, doubleWithoutOverflow(resolvedCfg.WebUIReadTimeoutSec),
		"(to double the read timeout) to prevent aggressive keep-alive disconnects") {
		shouldSaveConfig = true
	}

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIMaxLoginFailures)),
		&resolvedCfg.WebUIMaxLoginFailures, &rawCfg.WebUIMaxLoginFailures,
		func(v int) bool { return v <= 0 }, defaultCfg.WebUIMaxLoginFailures, "") {
		shouldSaveConfig = true
	}

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUILoginLockoutSec)),
		&resolvedCfg.WebUILoginLockoutSec, &rawCfg.WebUILoginLockoutSec,
		func(v int) bool { return v <= 0 }, defaultCfg.WebUILoginLockoutSec, "") {
		shouldSaveConfig = true
	}

	// =========================================================================
	// Group 2: Local DoH Server Timeouts
	// =========================================================================
	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.LocalDoHReadHeaderTimeoutSec)),
		&resolvedCfg.LocalDoHReadHeaderTimeoutSec, &rawCfg.LocalDoHReadHeaderTimeoutSec,
		func(v int) bool { return v <= 0 }, defaultCfg.LocalDoHReadHeaderTimeoutSec, "") {
		shouldSaveConfig = true
	}

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.LocalDoHReadTimeoutSec)),
		&resolvedCfg.LocalDoHReadTimeoutSec, &rawCfg.LocalDoHReadTimeoutSec,
		func(v int) bool { return v <= 0 }, defaultCfg.LocalDoHReadTimeoutSec, "") {
		shouldSaveConfig = true
	}

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.LocalDoHWriteTimeoutSec)),
		&resolvedCfg.LocalDoHWriteTimeoutSec, &rawCfg.LocalDoHWriteTimeoutSec,
		func(v int) bool { return v <= 0 }, defaultCfg.LocalDoHWriteTimeoutSec, "") {
		shouldSaveConfig = true
	}

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.LocalDoHIdleTimeoutSec)),
		&resolvedCfg.LocalDoHIdleTimeoutSec, &rawCfg.LocalDoHIdleTimeoutSec,
		func(v int) bool { return v < doubleWithoutOverflow(resolvedCfg.LocalDoHReadTimeoutSec) }, doubleWithoutOverflow(resolvedCfg.LocalDoHReadTimeoutSec),
		"(to double the read timeout) to prevent premature keep-alive drops") {
		shouldSaveConfig = true
	}

	// =========================================================================
	// Group 3: Upstream Client & Connection Pools
	// =========================================================================
	tagUpstreamDialTimeoutSec := getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamDialTimeoutSec))
	if clampIntField(log, tagUpstreamDialTimeoutSec, &resolvedCfg.UpstreamDialTimeoutSec, &rawCfg.UpstreamDialTimeoutSec,
		func(v int) bool { return v <= 0 }, defaultCfg.UpstreamDialTimeoutSec, "") {
		shouldSaveConfig = true
	}

	tagUpstreamClientTimeoutSec := getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamClientTimeoutSec))
	if clampIntField(log, tagUpstreamClientTimeoutSec, &resolvedCfg.UpstreamClientTimeoutSec, &rawCfg.UpstreamClientTimeoutSec,
		func(v int) bool { return v <= 0 }, defaultCfg.UpstreamClientTimeoutSec,
		" (prevents infinite hanging client connections)") {
		shouldSaveConfig = true
	}
	if clampIntField(log, tagUpstreamClientTimeoutSec, &resolvedCfg.UpstreamClientTimeoutSec, &rawCfg.UpstreamClientTimeoutSec,
		func(v int) bool { return v < resolvedCfg.UpstreamDialTimeoutSec }, resolvedCfg.UpstreamDialTimeoutSec,
		" (cannot be less than dial timeout "+tagUpstreamDialTimeoutSec+")") {
		shouldSaveConfig = true
	}

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamTCPKeepAliveSec)),
		&resolvedCfg.UpstreamTCPKeepAliveSec, &rawCfg.UpstreamTCPKeepAliveSec,
		func(v int) bool { return v <= 0 }, defaultCfg.UpstreamTCPKeepAliveSec, " (must be > 0)") {
		shouldSaveConfig = true
	}

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamIdleConnTimeoutSec)),
		&resolvedCfg.UpstreamIdleConnTimeoutSec, &rawCfg.UpstreamIdleConnTimeoutSec,
		func(v int) bool { return v <= 0 }, defaultCfg.UpstreamIdleConnTimeoutSec,
		" (connections stay open indefinitely or drop unpredictably)") {
		shouldSaveConfig = true
	}

	tagH2ReadIdle := getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamH2ReadIdleTimeoutSec))
	if clampIntField(log, tagH2ReadIdle, &resolvedCfg.UpstreamH2ReadIdleTimeoutSec, &rawCfg.UpstreamH2ReadIdleTimeoutSec,
		func(v int) bool { return v <= 0 }, defaultCfg.UpstreamH2ReadIdleTimeoutSec, "") {
		shouldSaveConfig = true
	}
	if clampIntField(log, tagH2ReadIdle, &resolvedCfg.UpstreamH2ReadIdleTimeoutSec, &rawCfg.UpstreamH2ReadIdleTimeoutSec,
		func(v int) bool { return v >= resolvedCfg.UpstreamIdleConnTimeoutSec }, max(resolvedCfg.UpstreamIdleConnTimeoutSec/2, 1),
		" (must trigger before the connection is closed by "+getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamIdleConnTimeoutSec))+")") {
		shouldSaveConfig = true
	}

	tagH2PingTimeout := getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamH2PingTimeoutSec))
	if clampIntField(log, tagH2PingTimeout, &resolvedCfg.UpstreamH2PingTimeoutSec, &rawCfg.UpstreamH2PingTimeoutSec,
		func(v int) bool { return v <= 0 }, defaultCfg.UpstreamH2PingTimeoutSec, "") {
		shouldSaveConfig = true
	}
	if clampIntField(log, tagH2PingTimeout, &resolvedCfg.UpstreamH2PingTimeoutSec, &rawCfg.UpstreamH2PingTimeoutSec,
		func(v int) bool { return v >= resolvedCfg.UpstreamH2ReadIdleTimeoutSec }, max(resolvedCfg.UpstreamH2ReadIdleTimeoutSec-1, 1),
		" (cannot be >= to the H2 read idle timeout)") {
		shouldSaveConfig = true
	}

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.ServerGracefulShutdownSec)),
		&resolvedCfg.ServerGracefulShutdownSec, &rawCfg.ServerGracefulShutdownSec,
		func(v int) bool { return v <= 0 }, defaultCfg.ServerGracefulShutdownSec, "") {
		shouldSaveConfig = true
	}

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.CertLogTimeoutSec)),
		&resolvedCfg.CertLogTimeoutSec, &rawCfg.CertLogTimeoutSec,
		func(v int) bool { return v <= 0 }, defaultCfg.CertLogTimeoutSec, "") {
		shouldSaveConfig = true
	}

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamRetryBackoffMs)),
		&resolvedCfg.UpstreamRetryBackoffMs, &rawCfg.UpstreamRetryBackoffMs,
		func(v int) bool { return v <= 0 }, defaultCfg.UpstreamRetryBackoffMs, "") {
		shouldSaveConfig = true
	}

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamRetriesPerQuery)),
		&resolvedCfg.UpstreamRetriesPerQuery, &rawCfg.UpstreamRetriesPerQuery,
		func(v int) bool { return v < 0 }, defaultCfg.UpstreamRetriesPerQuery, " (cannot be negative)") {
		shouldSaveConfig = true
	}

	tagUpstreamMaxIdleConns := getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamMaxIdleConns))
	if clampIntField(log, tagUpstreamMaxIdleConns, &resolvedCfg.UpstreamMaxIdleConns, &rawCfg.UpstreamMaxIdleConns,
		func(v int) bool { return v <= 0 }, defaultCfg.UpstreamMaxIdleConns, " (disables global keep-alive reuse)") {
		shouldSaveConfig = true
	}

	tagUpstreamMaxIdleConnsPerHost := getJSONTagByOffset(unsafe.Offsetof(Config{}.UpstreamMaxIdleConnsPerHost))
	if clampIntField(log, tagUpstreamMaxIdleConnsPerHost, &resolvedCfg.UpstreamMaxIdleConnsPerHost, &rawCfg.UpstreamMaxIdleConnsPerHost,
		func(v int) bool { return v <= 0 }, defaultCfg.UpstreamMaxIdleConnsPerHost,
		" (Go default of 2 severely throttles throughput)") {
		shouldSaveConfig = true
	}
	if clampIntField(log, tagUpstreamMaxIdleConnsPerHost, &resolvedCfg.UpstreamMaxIdleConnsPerHost, &rawCfg.UpstreamMaxIdleConnsPerHost,
		func(v int) bool { return v > resolvedCfg.UpstreamMaxIdleConns }, resolvedCfg.UpstreamMaxIdleConns,
		" (cannot exceed "+tagUpstreamMaxIdleConns+")", slog.Int(tagUpstreamMaxIdleConns, resolvedCfg.UpstreamMaxIdleConns)) {
		shouldSaveConfig = true
	}

	// =========================================================================
	// Group 4: Local Client & Server Buffer Safeguards
	// =========================================================================
	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.MaxConcurrentDNSTCPConns)),
		&resolvedCfg.MaxConcurrentDNSTCPConns, &rawCfg.MaxConcurrentDNSTCPConns,
		func(v int) bool { return v <= 0 }, defaultCfg.MaxConcurrentDNSTCPConns, "") {
		shouldSaveConfig = true
	}

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.MaxConcurrentDNSUDPQueries)),
		&resolvedCfg.MaxConcurrentDNSUDPQueries, &rawCfg.MaxConcurrentDNSUDPQueries,
		func(v int) bool { return v <= 0 }, defaultCfg.MaxConcurrentDNSUDPQueries, "") {
		shouldSaveConfig = true
	}

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.ClientTCPTimeoutSec)),
		&resolvedCfg.ClientTCPTimeoutSec, &rawCfg.ClientTCPTimeoutSec,
		func(v int) bool { return v <= 0 }, defaultCfg.ClientTCPTimeoutSec, "") {
		shouldSaveConfig = true
	}

	// NOTE: 0 is intentionally valid here ("disable these warnings entirely",
	// per the field's desc tag); only negative values are clamped.
	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.ClientMetadataLookupSlowWarnThresholdMs)),
		&resolvedCfg.ClientMetadataLookupSlowWarnThresholdMs, &rawCfg.ClientMetadataLookupSlowWarnThresholdMs,
		func(v int) bool { return v < 0 }, defaultCfg.ClientMetadataLookupSlowWarnThresholdMs,
		" (must be >= 0; 0 disables slow client-metadata-lookup warnings)") {
		shouldSaveConfig = true
	}

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.DoHMaxRequestBodyBytes)),
		&resolvedCfg.DoHMaxRequestBodyBytes, &rawCfg.DoHMaxRequestBodyBytes,
		func(v int) bool { return v <= 0 }, defaultCfg.DoHMaxRequestBodyBytes, "") {
		shouldSaveConfig = true
	}

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.DNSUDPBufferSize)),
		&resolvedCfg.DNSUDPBufferSize, &rawCfg.DNSUDPBufferSize,
		func(v int) bool { return v < 512 || v > 65535 }, defaultCfg.DNSUDPBufferSize,
		" (must be within standard Ethernet bounds 512-65535)") {
		shouldSaveConfig = true
	}

	// =========================================================================
	// Group 5: Core Engine Limits & Cache Operations
	// =========================================================================
	tagGlobalRateQPS := getJSONTagByOffset(unsafe.Offsetof(Config{}.GlobalRateQPS))
	if clampIntField(log, tagGlobalRateQPS, &resolvedCfg.GlobalRateQPS, &rawCfg.GlobalRateQPS,
		func(v int) bool { return v <= 0 }, defaultCfg.GlobalRateQPS, " (must be greater than 0)") {
		shouldSaveConfig = true
	}

	tagGlobalBurstQPS := getJSONTagByOffset(unsafe.Offsetof(Config{}.GlobalBurstQPS))
	if clampIntField(log, tagGlobalBurstQPS, &resolvedCfg.GlobalBurstQPS, &rawCfg.GlobalBurstQPS,
		func(v int) bool { return v <= 0 }, defaultCfg.GlobalBurstQPS, " (must be greater than 0)") {
		shouldSaveConfig = true
	}
	if clampIntField(log, tagGlobalBurstQPS, &resolvedCfg.GlobalBurstQPS, &rawCfg.GlobalBurstQPS,
		func(v int) bool { return v < resolvedCfg.GlobalRateQPS }, resolvedCfg.GlobalRateQPS,
		" (cannot be less than "+tagGlobalRateQPS+")") {
		shouldSaveConfig = true
	}

	tagClientRateQPS := getJSONTagByOffset(unsafe.Offsetof(Config{}.ClientRateQPS))
	if clampIntField(log, tagClientRateQPS, &resolvedCfg.ClientRateQPS, &rawCfg.ClientRateQPS,
		func(v int) bool { return v <= 0 }, defaultCfg.ClientRateQPS, " (must be greater than 0)") {
		shouldSaveConfig = true
	}

	tagClientBurstQPS := getJSONTagByOffset(unsafe.Offsetof(Config{}.ClientBurstQPS))
	if clampIntField(log, tagClientBurstQPS, &resolvedCfg.ClientBurstQPS, &rawCfg.ClientBurstQPS,
		func(v int) bool { return v <= 0 }, defaultCfg.ClientBurstQPS, " (must be greater than 0)") {
		shouldSaveConfig = true
	}
	if clampIntField(log, tagClientBurstQPS, &resolvedCfg.ClientBurstQPS, &rawCfg.ClientBurstQPS,
		func(v int) bool { return v < resolvedCfg.ClientRateQPS }, resolvedCfg.ClientRateQPS,
		" (cannot be less than "+tagClientRateQPS+")") {
		shouldSaveConfig = true
	}

	tagWebUIRateQPS := getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIRateQPS))
	if clampIntField(log, tagWebUIRateQPS, &resolvedCfg.WebUIRateQPS, &rawCfg.WebUIRateQPS,
		func(v int) bool { return v <= 0 }, defaultCfg.WebUIRateQPS, " (must be greater than 0)") {
		shouldSaveConfig = true
	}

	tagWebUIBurstQPS := getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIBurstQPS))
	if clampIntField(log, tagWebUIBurstQPS, &resolvedCfg.WebUIBurstQPS, &rawCfg.WebUIBurstQPS,
		func(v int) bool { return v <= 0 }, defaultCfg.WebUIBurstQPS, " (must be greater than 0)") {
		shouldSaveConfig = true
	}
	if clampIntField(log, tagWebUIBurstQPS, &resolvedCfg.WebUIBurstQPS, &rawCfg.WebUIBurstQPS,
		func(v int) bool { return v < resolvedCfg.WebUIRateQPS }, resolvedCfg.WebUIRateQPS,
		" (cannot be less than "+tagWebUIRateQPS+")") {
		shouldSaveConfig = true
	}

	tagWebUIClientRateQPS := getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIClientRateQPS))
	if clampIntField(log, tagWebUIClientRateQPS, &resolvedCfg.WebUIClientRateQPS, &rawCfg.WebUIClientRateQPS,
		func(v int) bool { return v <= 0 }, defaultCfg.WebUIClientRateQPS, " (must be greater than 0)") {
		shouldSaveConfig = true
	}

	tagWebUIClientBurstQPS := getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIClientBurstQPS))
	if clampIntField(log, tagWebUIClientBurstQPS, &resolvedCfg.WebUIClientBurstQPS, &rawCfg.WebUIClientBurstQPS,
		func(v int) bool { return v <= 0 }, defaultCfg.WebUIClientBurstQPS, " (must be greater than 0)") {
		shouldSaveConfig = true
	}
	if clampIntField(log, tagWebUIClientBurstQPS, &resolvedCfg.WebUIClientBurstQPS, &rawCfg.WebUIClientBurstQPS,
		func(v int) bool { return v < resolvedCfg.WebUIClientRateQPS }, resolvedCfg.WebUIClientRateQPS,
		" (cannot be less than "+tagWebUIClientRateQPS+")") {
		shouldSaveConfig = true
	}

	// NOTE: CacheMinTTL=0 is intentionally valid ("no minimum", per the
	// field's `desc` tag); do not restore this clamp.
	// if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.CacheMinTTL)),
	// 	&resolvedCfg.CacheMinTTL, &rawCfg.CacheMinTTL,
	// 	func(v int) bool { return v < cacheMinTTLClamp }, cacheMinTTLClamp, " to safe minimum") {
	// 	shouldSaveConfig = true
	// }

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.CacheMaxEntries)),
		&resolvedCfg.CacheMaxEntries, &rawCfg.CacheMaxEntries,
		func(v int) bool { return v <= 0 }, defaultCfg.CacheMaxEntries, "") {
		shouldSaveConfig = true
	}

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.CacheJanitorIntervalMinutes)),
		&resolvedCfg.CacheJanitorIntervalMinutes, &rawCfg.CacheJanitorIntervalMinutes,
		func(v int) bool { return v <= 0 }, defaultCfg.CacheJanitorIntervalMinutes, " to safe minimum interval") {
		shouldSaveConfig = true
	}

	// NOTE: CacheNegativeTTLSec=0 is intentionally valid ("don't cache", per
	// the field's `desc` tag); do not restore this clamp.
	// if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.CacheNegativeTTLSec)),
	// 	&resolvedCfg.CacheNegativeTTLSec, &rawCfg.CacheNegativeTTLSec,
	// 	func(v int) bool { return v < 0 }, defaultCfg.CacheNegativeTTLSec, "") {
	// 	shouldSaveConfig = true
	// }

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.FileWriterMaxRetries)),
		&resolvedCfg.FileWriterMaxRetries, &rawCfg.FileWriterMaxRetries,
		func(v int) bool { return v < 0 }, defaultCfg.FileWriterMaxRetries, "") {
		shouldSaveConfig = true
	}

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.FileWriterRetryBackoffMs)),
		&resolvedCfg.FileWriterRetryBackoffMs, &rawCfg.FileWriterRetryBackoffMs,
		func(v int) bool { return v <= 0 }, defaultCfg.FileWriterRetryBackoffMs, "") {
		shouldSaveConfig = true
	}

	// NOTE: BlockedResponseTTLSec=0 is intentionally valid (embeds TTL=0 in
	// the blocked-response record, telling clients not to cache it at all —
	// see the field's `desc` tag); do not restore this clamp.
	// if clampUint32Field(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.BlockedResponseTTLSec)),
	// 	&resolvedCfg.BlockedResponseTTLSec, &rawCfg.BlockedResponseTTLSec,
	// 	func(v uint32) bool { return v <= 0 }, defaultCfg.BlockedResponseTTLSec, "") {
	// 	shouldSaveConfig = true
	// }

	// NOTE: LocalHostsOverrideTTLSec=0 is intentionally valid (skips both the
	// internal cache insert and signals clients not to cache — see the
	// field's `desc` tag and handleDNSQuery's "if cfg.LocalHostsOverrideTTLSec
	// > 0" guard); do not restore this clamp.
	// if clampUint32Field(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.LocalHostsOverrideTTLSec)),
	// 	&resolvedCfg.LocalHostsOverrideTTLSec, &rawCfg.LocalHostsOverrideTTLSec,
	// 	func(v uint32) bool { return v == 0 }, defaultCfg.LocalHostsOverrideTTLSec, "") {
	// 	shouldSaveConfig = true
	// }

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.MaxRecentBlocks)),
		&resolvedCfg.MaxRecentBlocks, &rawCfg.MaxRecentBlocks,
		func(v int) bool { return v <= 0 }, defaultCfg.MaxRecentBlocks, "") {
		shouldSaveConfig = true
	}

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.UILogMaxLines)),
		&resolvedCfg.UILogMaxLines, &rawCfg.UILogMaxLines,
		func(v int) bool { return v <= 0 }, defaultCfg.UILogMaxLines, "") {
		shouldSaveConfig = true
	}
	// renderLogPage allocates a ring buffer sized exactly to this field
	// (`ring := make([]string, maxLines)`) on every /logs* request; without an
	// upper bound, a hand-edited (or fat-fingered) config.json value near the
	// platform int's range would attempt a multi-gigabyte-or-larger allocation
	// per request despite the field's own description calling it a RAM-usage
	// cap. uiLogMaxLinesHardCap is generous enough for any realistic use while
	// keeping the worst-case allocation bounded and sane.
	const uiLogMaxLinesHardCap = 1_000_000
	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.UILogMaxLines)),
		&resolvedCfg.UILogMaxLines, &rawCfg.UILogMaxLines,
		func(v int) bool { return v > uiLogMaxLinesHardCap }, uiLogMaxLinesHardCap,
		fmt.Sprintf(" (capped at %d to bound the WebUI log-viewer's per-request memory allocation)", uiLogMaxLinesHardCap)) {
		shouldSaveConfig = true
	}

	if clampIntField(log, getJSONTagByOffset(unsafe.Offsetof(Config{}.LogMaxSizeMB)),
		&resolvedCfg.LogMaxSizeMB, &rawCfg.LogMaxSizeMB,
		func(v int) bool { return v <= 0 }, defaultCfg.LogMaxSizeMB, "") {
		shouldSaveConfig = true
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
		//noTODO: should we save this back into config after ParseIP ? and set shouldSaveConfig = true
		//doneTODO: do I have to set the parseds to rawCfg too?! unclear; doesn't seem like I should since they aren't saved due to json:"-" tag,

		// Validate and parse BlockIP (IPv4)
		ipV4Raw := net.ParseIP(resolvedCfg.BlockIP)
		ip4 := ipV4Raw.To4()
		if ip4 != nil {
			resolvedCfg.BlockIPv4Parsed = ip4
			// Independent copy — resolvedCfg and rawCfg must never share a backing array here.
			rawCfg.BlockIPv4Parsed = append(net.IP(nil), ip4...) // assignment is not needed/used but I do it to keep it consistent anyway
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
			// Independent copy — resolvedCfg and rawCfg must never share a backing array here.
			rawCfg.BlockIPv6Parsed = append(net.IP(nil), ipV6Raw...) // assignment is not needed/used but I do it to keep it consistent anyway
		} else {
			tag := getJSONTagByOffset(unsafe.Offsetof(Config{}.BlockIPv6))
			msg := fmt.Sprintf("Invalid IPv6 address %q for %q in config file %q", resolvedCfg.BlockIPv6, tag, configFileName)
			log.Error(msg, slog.String(tag, resolvedCfg.BlockIPv6))
			return shouldSaveConfig, fmt.Errorf("%s", msg)
		}
	} //end tiny scope

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
	} else if parsedUIHost := net.ParseIP(uiHost); parsedUIHost == nil {
		return shouldSaveConfig, fmt.Errorf("%q host %q must be an IP literal with no surrounding spaces (not a hostname(because we can't look it up without DNS)) for TLS cert generation", tagListenUI, uiHost)
	} else if parsedUIHost.IsUnspecified() {
		// hostValidationMiddleware/originValidationMiddleware compare the
		// request's Host/Origin header against the address the WebUI listener
		// actually bound to (see startWebUIListenerInstance's boundAddr, taken
		// from baseListener.Addr().String()). For a wildcard bind, that string
		// is literally "0.0.0.0:port" or "[::]:port" — a value no real client
		// can ever send as its own Host/Origin, since a client always connects
		// to one specific interface IP. Every request would then be rejected
		// with 403, making the WebUI completely unreachable despite having
		// "successfully" started. Reject the wildcard bind outright here
		// instead of weakening Host/Origin validation to accommodate it: the
		// operator must bind to a specific interface IP (use 127.0.0.1 for
		// loopback-only, or the machine's actual LAN IP to expose it).
		return shouldSaveConfig, fmt.Errorf("%q host %q must be a specific interface IP, not the unspecified/wildcard address; binding to it would make the WebUI unreachable (every request would fail Host/Origin validation) — use 127.0.0.1 or a specific interface IP instead", tagListenUI, uiHost)
	}

	origLevel := resolvedCfg.ConsoleLogLevel
	resolvedCfg.ConsoleLogLevel = strings.ToLower(strings.TrimSpace(resolvedCfg.ConsoleLogLevel))
	//doneTODO: ^ if changed, then shouldSaveConfig = true
	if origLevel != resolvedCfg.ConsoleLogLevel {
		shouldSaveConfig = true
	}
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

	origBlockMode := resolvedCfg.BlockMode
	resolvedCfg.BlockMode = strings.ToLower(origBlockMode) //XXX: lowercasing this for future comparisons to be easier!
	//doneTODO: ^ if changed compared to original!, then shouldSaveConfig = true
	switch resolvedCfg.BlockMode {
	case blockModeNXDOMAIN:
		// already canonical

	case blockModeIPBlock:
		// already canonical

	case "block_ip", "ipblock", "blockip": //aka aliases
		resolvedCfg.BlockMode = blockModeIPBlock
		shouldSaveConfig = true //known redundant

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
	} //switch
	if resolvedCfg.BlockMode != origBlockMode {
		shouldSaveConfig = true
	}
	rawCfg.BlockMode = resolvedCfg.BlockMode
	//apparentlynotTODO: see if I've to shouldSaveConfig for anything else here, above maybe?

	// Validate UpstreamSelectionMode. Unknown values (e.g. from a hand-edited config) are
	// reset to the safe default so the server starts rather than refusing to boot.
	origUpstreamSelectionMode := resolvedCfg.UpstreamSelectionMode
	resolvedCfg.UpstreamSelectionMode = strings.ToLower(strings.TrimSpace(origUpstreamSelectionMode))
	//doneTODO: ^ if changed, then shouldSaveConfig = true
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
	if origUpstreamSelectionMode != resolvedCfg.UpstreamSelectionMode {
		shouldSaveConfig = true
	}
	rawCfg.UpstreamSelectionMode = resolvedCfg.UpstreamSelectionMode

	if len(resolvedCfg.UpstreamSNIHostnames) > len(resolvedCfg.UpstreamURLs) {
		const msg = "there are more SNIs vs URLs for upstream, only the opposite is allowed ( >= URLs than SNIs which then inherit the SNI from URLs)"
		log.Warn(msg)
		return shouldSaveConfig, fmt.Errorf("%s", msg)
	}
	// Ensure SNIHostnames has the same length as UpstreamURLs, falling back to the URL's hostname

	for i, rawURL := range resolvedCfg.UpstreamURLs {
		host, err := hostFromURL(rawURL)
		if err != nil {
			log.Warn("invalid upstream URL", slog.String("url", rawURL), slog.Int("at_index", i), wincoe.SafeErr(err))
			return shouldSaveConfig, fmt.Errorf("invalid upstream URL \"%s\" at index %d, err: %w", rawURL, i, err)
		}

		if i >= len(resolvedCfg.UpstreamSNIHostnames) {
			// Slice is too short, append it
			resolvedCfg.UpstreamSNIHostnames = append(resolvedCfg.UpstreamSNIHostnames, host)
			rawCfg.UpstreamSNIHostnames = append(rawCfg.UpstreamSNIHostnames, host)
			shouldSaveConfig = true
		} else if resolvedCfg.UpstreamSNIHostnames[i] == "" {
			// Exists but is empty, overwrite it
			resolvedCfg.UpstreamSNIHostnames[i] = host
			rawCfg.UpstreamSNIHostnames[i] = host
			shouldSaveConfig = true
		}
	}
	log.Debug("Using upstream SNI hostnames:",
		SafeStringSlice("SNI_hostnames", resolvedCfg.UpstreamSNIHostnames),
	)

	// Derive and validate the runtime-only upstream fields (UpstreamURLsParsed, UpstreamIPs,
	// UpstreamSNIs) here, as part of validation, instead of leaving that solely to
	// UpstreamManager.updateInnerState() later in the config lifecycle — see
	// parseAndValidateUpstreams's doc comment for the race this closes and the bad-config
	// crash it prevents.
	parsedUpstreamURLs, upstreamIPs, upstreamSNIs, upstreamErr := parseAndValidateUpstreams(resolvedCfg.UpstreamURLs, resolvedCfg.UpstreamSNIHostnames)
	if upstreamErr != nil {
		return shouldSaveConfig, upstreamErr
	}
	resolvedCfg.UpstreamURLsParsed = parsedUpstreamURLs
	resolvedCfg.UpstreamIPs = upstreamIPs
	resolvedCfg.UpstreamSNIs = upstreamSNIs
	// Mirror onto rawCfg too, for consistency with resolvedCfg (same defensive pattern as
	// BlockIPv4Parsed/BlockIPv6Parsed above): these fields are transient/derived (json:"-")
	// and never persisted, but keeping them populated identically on both structs avoids
	// them silently diverging.
	rawCfg.UpstreamURLsParsed = cloneURLSlice(parsedUpstreamURLs)
	rawCfg.UpstreamIPs = make([]string, len(upstreamIPs))
	copy(rawCfg.UpstreamIPs, upstreamIPs)
	rawCfg.UpstreamSNIs = make([]string, len(upstreamSNIs))
	copy(rawCfg.UpstreamSNIs, upstreamSNIs)

	// Every file this process itself creates/writes (log files, the
	// whitelist/hosts/response-blacklist JSON files, and the TLS cert/key
	// pair) must be a bare filename living directly next to config.json —
	// see cleanBareFileName's doc comment for why.
	checkAndCleanBareFilename := func(resolvedTarget, rawTarget *string, configKey, fallback string) error {
		if cleaned, changed := cleanBareFileName(log, *resolvedTarget, configKey, fallback); changed {
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
			shouldSaveConfig = true
		}
		return nil
	}
	if err := checkAndCleanBareFilename(&resolvedCfg.LogQueriesFile, &rawCfg.LogQueriesFile, getJSONTagByOffset(unsafe.Offsetof(Config{}.LogQueriesFile)), defaultCfg.LogQueriesFile); err != nil {
		return shouldSaveConfig, err
	}
	if err := checkAndCleanBareFilename(&resolvedCfg.LogQueriesSimpleFile, &rawCfg.LogQueriesSimpleFile, getJSONTagByOffset(unsafe.Offsetof(Config{}.LogQueriesSimpleFile)), defaultCfg.LogQueriesSimpleFile); err != nil {
		return shouldSaveConfig, err
	}
	if err := checkAndCleanBareFilename(&resolvedCfg.LogEverythingFile, &rawCfg.LogEverythingFile, getJSONTagByOffset(unsafe.Offsetof(Config{}.LogEverythingFile)), defaultCfg.LogEverythingFile); err != nil {
		return shouldSaveConfig, err
	}

	if err := checkAndCleanBareFilename(&resolvedCfg.BlacklistFile, &rawCfg.BlacklistFile, getJSONTagByOffset(unsafe.Offsetof(Config{}.BlacklistFile)), defaultCfg.BlacklistFile); err != nil {
		return shouldSaveConfig, err
	}
	if err := checkAndCleanBareFilename(&resolvedCfg.WhitelistFile, &rawCfg.WhitelistFile, getJSONTagByOffset(unsafe.Offsetof(Config{}.WhitelistFile)), defaultCfg.WhitelistFile); err != nil {
		return shouldSaveConfig, err
	}
	if err := checkAndCleanBareFilename(&resolvedCfg.HostsFile, &rawCfg.HostsFile, getJSONTagByOffset(unsafe.Offsetof(Config{}.HostsFile)), defaultCfg.HostsFile); err != nil {
		return shouldSaveConfig, err
	}
	if err := checkAndCleanBareFilename(&resolvedCfg.QueryBlocklistFile, &rawCfg.QueryBlocklistFile, getJSONTagByOffset(unsafe.Offsetof(Config{}.QueryBlocklistFile)), defaultCfg.QueryBlocklistFile); err != nil {
		return shouldSaveConfig, err
	}
	//Note: QueryBlocklistExternalHostsFile is deliberately not run through checkAndCleanBareFilename — its desc tag explicitly documents that it may contain a directory component, since dnsbollocks only ever reads it (never SafeWriteFiles to it), so the "prevent arbitrary file overwrite when elevated" threat model doesn't apply.

	if err := checkAndCleanBareFilename(&resolvedCfg.TLSCertFile, &rawCfg.TLSCertFile, getJSONTagByOffset(unsafe.Offsetof(Config{}.TLSCertFile)), defaultCfg.TLSCertFile); err != nil {
		return shouldSaveConfig, err
	}
	if err := checkAndCleanBareFilename(&resolvedCfg.TLSKeyFile, &rawCfg.TLSKeyFile, getJSONTagByOffset(unsafe.Offsetof(Config{}.TLSKeyFile)), defaultCfg.TLSKeyFile); err != nil {
		return shouldSaveConfig, err
	}

	// Log files (LogQueriesFile/LogQueriesSimpleFile/LogEverythingFile) are
	// resolved relative to Config.LogDir (see resolveLogFilePath), while
	// every other file below is resolved relative to config.json's own
	// directory (always "." — see configFileName's declaration). These are
	// NOT necessarily the same directory once log_dir is customized, so the
	// log entries must be run through resolveLogFilePath here too; comparing
	// bare filenames directly would falsely flag two same-named files living
	// in different directories as colliding on disk.
	// Files persisted via wincoe's win11SafeFileWriter (config.json, and the
	// whitelist/blacklist/hosts files saved via Server.save*) each
	// transactionally create two derived sidecar paths of their own on every
	// write — see win11SafeFileWriter.SafeWriteFile and
	// wincoe.BackupFileExtension/PowerlossFileExtension — so a configured
	// path that happens to literally equal one of THOSE derived paths would
	// collide with it even though the two primary paths look distinct from
	// each other. Build the base set of primaries first, then derive and add
	// their sidecar paths before the single distinctness check below, so a
	// collision against a derived path is caught exactly like any other.
	safeWriterProtectedPrimaries := map[string]string{
		"(fixed) main config file":                                       configFileName,
		getJSONTagByOffset(unsafe.Offsetof(Config{}.WhitelistFile)):      resolvedCfg.WhitelistFile,
		getJSONTagByOffset(unsafe.Offsetof(Config{}.BlacklistFile)):      resolvedCfg.BlacklistFile,
		getJSONTagByOffset(unsafe.Offsetof(Config{}.HostsFile)):          resolvedCfg.HostsFile,
		getJSONTagByOffset(unsafe.Offsetof(Config{}.QueryBlocklistFile)): resolvedCfg.QueryBlocklistFile,
	}

	distinctPaths := map[string]string{
		getJSONTagByOffset(unsafe.Offsetof(Config{}.LogQueriesFile)):       resolveLogFilePath(resolvedCfg.LogDir, resolvedCfg.LogQueriesFile),
		getJSONTagByOffset(unsafe.Offsetof(Config{}.LogQueriesSimpleFile)): resolveLogFilePath(resolvedCfg.LogDir, resolvedCfg.LogQueriesSimpleFile),
		getJSONTagByOffset(unsafe.Offsetof(Config{}.LogEverythingFile)):    resolveLogFilePath(resolvedCfg.LogDir, resolvedCfg.LogEverythingFile),
		getJSONTagByOffset(unsafe.Offsetof(Config{}.TLSCertFile)):          resolvedCfg.TLSCertFile,
		getJSONTagByOffset(unsafe.Offsetof(Config{}.TLSKeyFile)):           resolvedCfg.TLSKeyFile,
	}
	for key, primary := range safeWriterProtectedPrimaries {
		distinctPaths[key] = primary
		distinctPaths["(derived backup of) "+key] = primary + wincoe.BackupFileExtension
		distinctPaths["(derived staging of) "+key] = primary + wincoe.PowerlossFileExtension
	}

	// The external hosts-file source is never written by dnsbollocks (see its
	// desc tag), so it needs no derived .bak/.powergotlost entries of its own —
	// but it must still not silently collide with a file dnsbollocks DOES
	// write, which would otherwise let this supposedly "read-only" source get
	// clobbered by an unrelated save.
	if extPath := strings.TrimSpace(resolvedCfg.QueryBlocklistExternalHostsFile); extPath != "" {
		distinctPaths[getJSONTagByOffset(unsafe.Offsetof(Config{}.QueryBlocklistExternalHostsFile))] = extPath
	}

	if err := validateDistinctConfigFilePaths(distinctPaths); err != nil {
		return shouldSaveConfig, err
	}

	if isWebUI && resolvedCfg.WebUIPasswordHash == "" {
		//only for webUI case, non-webUI will ask for pwd to be set on startup, after this!
		tagWebUIPwd := getJSONTagByOffset(unsafe.Offsetof(Config{}.WebUIPasswordHash))
		return shouldSaveConfig, errors.New(tagWebUIPwd + " cannot be empty at this point")
	}

	return shouldSaveConfig, nil
}

// cleanBareFileName ensures a config file-path field contains only a bare
// filename with no directory component, rejecting Windows reserved device
// names (CON, NUL, COM1, etc., including with a trailing extension like
// "con.log" — see wincoe.IsWindowsReservedFileName). Every file dnsbollocks
// itself creates or writes — the three log files, the whitelist/hosts/
// response-blacklist JSON files, and the TLS cert/key pair — is restricted
// to a bare filename living directly next to config.json, never a path with
// directory components, so a hand-edited or WebUI-supplied value can never
// point outside that directory (e.g. overwriting an unrelated file
// elsewhere on disk if this process is ever run elevated).
func cleanBareFileName(log *slog.Logger, original, configKey, fallback string) (string, bool) {
	if fallback == "" {
		msg := fmt.Sprintf("BUG: dev fail: passed empty filename to clean for config key %q and the fallback was also empty!", configKey)
		log.Error(msg, slog.String("config_key", configKey))
		panic(msg)
	}
	if original == "" {
		return filepath.Base(filepath.Clean(fallback)), true
	}

	// Force extraction of JUST the filename.
	// e.g., "C:\Windows\System32\evil.log" -> "evil.log"
	// e.g., "../../../evil.log" -> "evil.log"
	baseName := filepath.Base(filepath.Clean(original))

	// If they passed something bizarre like "/" or ".", revert to fallback
	if baseName == "." || baseName == string(filepath.Separator) {
		baseName = filepath.Base(filepath.Clean(fallback))
	}

	// Standard Windows reserved name check (matches by device-name stem, so
	// "CON.log"/"com1.txt" etc. are caught too — see wincoe.IsWindowsReservedFileName).
	if wincoe.IsWindowsReservedFileName(baseName) {
		log.Warn("Config filename is a reserved Windows device name; using fallback",
			slog.String("config_key", configKey),
			slog.String("reserved", baseName),
			slog.String("fallback", fallback))
		return filepath.Base(filepath.Clean(fallback)), true
	}

	if baseName != original {
		log.Warn("Directory paths are not allowed in this file setting to prevent arbitrary file writes outside the config directory. Stripped path.",
			slog.String("config_key", configKey),
			slog.String("original", original),
			slog.String("forced_to", baseName))
		return baseName, true
	}

	return original, false
}

// validateDistinctConfigFilePaths ensures that none of the given
// (config-json-key -> path) entries resolve to the same file on disk.
// Comparison is case-insensitive and via the cleaned path, because Windows
// filesystems (NTFS/FAT) are case-insensitive — "Query_Whitelist.json" and
// "query_whitelist.json" name the identical file even though they differ as
// strings. Two config keys accidentally pointing at the same path would
// silently corrupt each other at runtime: e.g. two independent
// rotatingLogWriters both believing they exclusively own the same inode for
// rotation purposes, or a log rotation renaming a file out from under a
// concurrent SafeWriteFile targeting what is "coincidentally" the same file
// via a differently-cased setting.
//
// Callers are responsible for passing already fully-resolved paths (i.e.
// joined with whatever base directory each field is actually relative to —
// see the call site in sanitizeAndValidateConfig for why log-file fields
// must be pre-joined with Config.LogDir via resolveLogFilePath before being
// passed in here); this function only compares the strings it's given and
// has no notion of which config field implies which base directory.
// normalizeConfigFilePathForComparison resolves p to an absolute, cleaned,
// lowercased form so that two differently-spelled paths pointing at the same
// file (e.g. a relative path and its equivalent absolute path) are still
// recognized as colliding by validateDistinctConfigFilePaths. This does NOT
// resolve symlinks/junctions/hardlinks — an NTFS reparse point could still
// alias two "distinct"-looking paths onto the same underlying file — but
// every caller here only ever deals with plain files this process itself
// creates directly beneath the working/config directory, so that residual
// gap is accepted rather than paying for an os.Stat+SameFile round trip
// against files that, at validation time, may not exist on disk at all yet.
func normalizeConfigFilePathForComparison(p string) string {
	cleaned := filepath.Clean(p)
	if abs, err := filepath.Abs(cleaned); err == nil {
		cleaned = abs
	}
	return strings.ToLower(cleaned)
}

func validateDistinctConfigFilePaths(paths map[string]string) error {
	seen := make(map[string]string, len(paths))
	keys := make([]string, 0, len(paths))
	for k := range paths {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic error message regardless of map iteration order
	for _, key := range keys {
		norm := normalizeConfigFilePathForComparison(paths[key])
		if otherKey, dup := seen[norm]; dup {
			return fmt.Errorf("config keys %q and %q both resolve to the same file %q; every file-path setting must point at a distinct file", otherKey, key, paths[key])
		}
		seen[norm] = key
	}
	return nil
}

// NormalizeDomain returns a clean, lowercased domain pattern suitable for rules/hosts.
// Handles trailing dot and whitespace. IDN (unicode) domains are NOT punycode-encoded
// here — callers that accept operator-facing patterns must additionally call
// punycodeEncodePattern afterwards; see its doc comment for why this is a separate step.
func NormalizeDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	return s
}

// isASCII reports whether s contains only ASCII (byte < 0x80) characters.
// Used to fast-path skip punycode/IDNA processing for patterns/labels that
// are already plain ASCII — the overwhelming majority of rules/hosts.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// labelSegment is one piece of a wildcard-token-aware split of a rule/host
// pattern label — either a literal content run (ASCII or Unicode text) or a
// single wildcard-syntax token character (one of *, ?, !, {, }). See
// splitLabelAtWildcardTokens.
type labelSegment struct {
	text       string
	isWildcard bool
}

// splitLabelAtWildcardTokens splits a single dot-separated label of a
// rule/host pattern into an ordered sequence of labelSegments: runs of
// literal text (which may freely mix ASCII and Unicode characters)
// alternating with single-character wildcard-syntax tokens (*, ?, !, {, }).
// Concatenating every segment's text back together, in order, exactly
// reconstructs the original label — this is what lets
// punycodeEncodePattern (and punycodeDecodePatternForDisplay, in reverse)
// punycode-convert only the literal-text runs while leaving match-syntax
// tokens like the "*" in "café*" untouched.
func splitLabelAtWildcardTokens(label string) []labelSegment {
	const wildcardTokenChars = "*?!{}"

	var segments []labelSegment
	var run strings.Builder
	for _, r := range label {
		if strings.ContainsRune(wildcardTokenChars, r) {
			if run.Len() > 0 {
				segments = append(segments, labelSegment{text: run.String()})
				run.Reset()
			}
			segments = append(segments, labelSegment{text: string(r), isWildcard: true})
			continue
		}
		run.WriteRune(r)
	}
	if run.Len() > 0 {
		segments = append(segments, labelSegment{text: run.String()})
	}
	return segments
}

// punycodeEncodePattern converts every Unicode (non-ASCII) label of a
// lowercased, dot-separated rule/host pattern into its ASCII "A-label" form
// (RFC 3492 Punycode, "xn--"-prefixed) using the same UTS46 processing a
// browser or OS stub resolver applies before a query ever reaches the wire.
// This is what lets an operator type/see a domain like "café.com" while the
// pattern that's actually stored — and matched against real, always-ASCII,
// incoming DNS queries — is "xn--caf-dma.com". matchPattern itself is never
// touched: it only ever sees ASCII, exactly as before.
//
// Wildcard-token characters (*, ?, !, {, }) are pattern-matching syntax, not
// real domain content. A label made up solely of such tokens (e.g. the "*"
// in "*.café.com") is passed through untouched. A label that MIXES wildcard
// tokens with non-ASCII characters (e.g. "café*" or "café{**}") is handled
// by splitting the label at each wildcard-token character (see
// splitLabelAtWildcardTokens) into alternating content-runs and standalone
// tokens: only the content-runs are punycode-encoded, and the wildcard
// tokens are reinserted verbatim at their original position. This keeps
// "café*.com" and "test*.com" behaving consistently — both are accepted —
// rather than only the pure-ASCII form working. Note this means IDNA's
// position-sensitive validation (e.g. the ACE-prefix hyphen rule) is applied
// per content-run rather than across the label as a single unit; since a
// wildcard pattern was never a literal domain name to begin with, this is an
// accepted trade-off.
//
// Returns the (possibly rewritten) pattern, whether anything was actually
// IDN-encoded, and a non-nil error if a label couldn't be safely converted.
func punycodeEncodePattern(pattern string) (encoded string, wasIDN bool, err error) {
	if pattern == "" || isASCII(pattern) {
		return pattern, false, nil // fast path: nothing to encode
	}

	labels := strings.Split(pattern, ".")
	for i, label := range labels {
		if isASCII(label) {
			continue // nothing to do for this label
		}

		segments := splitLabelAtWildcardTokens(label)
		var rebuilt strings.Builder
		for _, seg := range segments {
			if seg.isWildcard || isASCII(seg.text) {
				rebuilt.WriteString(seg.text)
				continue
			}
			ascii, encErr := idna.Lookup.ToASCII(seg.text)
			if encErr != nil {
				return pattern, false, fmt.Errorf("failed to convert unicode segment %q (within label %q) to punycode: %w", seg.text, label, encErr)
			}
			rebuilt.WriteString(ascii)
		}

		finalLabel := rebuilt.String()
		if len(finalLabel) > 63 {
			// RFC 1035 §3.1 hard-caps every DNS label at 63 octets. A label that
			// blows past this once expanded to punycode can never match any real
			// wire-format DNS query, so reject it now rather than silently saving
			// an unusable rule.
			return pattern, false, fmt.Errorf(
				"unicode label %q expands to punycode label %q (%d chars), exceeding the DNS 63-character label limit",
				label, finalLabel, len(finalLabel))
		}
		labels[i] = finalLabel
		wasIDN = true
	}
	if !wasIDN {
		return pattern, false, nil
	}
	return strings.Join(labels, "."), true, nil
}

// encodePatternOrErr is a thin wrapper around punycodeEncodePattern that
// packages a conversion failure into a single, already-wrapped error
// suitable for returning straight to an HTTP handler.
func encodePatternOrErr(pattern string) (string, error) {
	encoded, _, err := punycodeEncodePattern(pattern)
	if err != nil {
		return "", fmt.Errorf("invalid pattern %q: %w", pattern, err)
	}
	return encoded, nil
}

// punycodeDecodePatternForDisplay converts every ASCII "xn--" punycode
// label in pattern back to its human-readable Unicode form, for display in
// the WebUI and in logs. Labels that aren't punycode-prefixed (plain ASCII,
// wildcard tokens, etc.) are returned unchanged. This is the inverse of
// punycodeEncodePattern and never mutates the underlying stored pattern —
// only display surfaces ever see the Unicode form; matching and persistence
// always use the punycode/ASCII pattern.
//
// A malformed/corrupted "xn--" label is treated as non-fatal: it's left
// exactly as stored rather than failing the whole page render or log line.
func punycodeDecodePatternForDisplay(pattern string) (display string, wasIDN bool) {
	if !strings.Contains(pattern, "xn--") {
		return pattern, false // fast path: definitely nothing to decode
	}

	labels := strings.Split(pattern, ".")
	for i, label := range labels {
		if !strings.Contains(label, "xn--") {
			continue
		}

		// The "xn--" run may not start at the beginning of the label if a
		// wildcard token precedes it (e.g. "*xn--caf-dma", from encoding
		// "*café" — see punycodeEncodePattern/splitLabelAtWildcardTokens),
		// so split at wildcard-token boundaries the same way encoding did,
		// and only attempt to decode the content-run segment(s).
		segments := splitLabelAtWildcardTokens(label)
		var rebuilt strings.Builder
		labelChanged := false
		for _, seg := range segments {
			if seg.isWildcard || !strings.HasPrefix(seg.text, "xn--") {
				rebuilt.WriteString(seg.text)
				continue
			}
			uni, decErr := idna.Punycode.ToUnicode(seg.text)
			if decErr != nil || uni == "" {
				rebuilt.WriteString(seg.text) // leave malformed/unconvertible run exactly as stored
				continue
			}
			rebuilt.WriteString(uni)
			labelChanged = true
		}
		if labelChanged {
			labels[i] = rebuilt.String()
			wasIDN = true
		}
	}
	if !wasIDN {
		return pattern, false
	}
	return strings.Join(labels, "."), true
}

const (
	blockModeNXDOMAIN = "nxdomain"
	blockModeIPBlock  = "ip_block"
	blockModeDrop     = "drop" // actually doesn't drop it but replies with 503 Service Unavailable
)

// upstreamSelectionMode* are the only valid values for Config.UpstreamSelectionMode.
// They are used in Go logic, in the sanitizeAndValidateConfig validator, and injected
// into the HTML template so app.js never hard-codes these strings.
const (
	upstreamSelectionModeFailover = "failover"
	upstreamSelectionModeFastest  = "fastest"
	upstreamSelectionModeStrict   = "strict"
)

// webUIAuthSessionMode* are the only valid values for Config.WebUIAuthSessionMode.
// See that field's doc comment for what each mode does.
const (
	webUIAuthSessionModeLegacy        = "legacy"
	webUIAuthSessionModeSessionCookie = "session_cookie"
	webUIAuthSessionModeTimeBucket    = "time_bucket"
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
			if wincoe.IsWindowsReservedFileName(filename) {
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

		// Write the _modified_at_ entry if this field has a recorded
		// last-WebUI-modification timestamp (see Config.FieldModifiedAt's
		// doc comment and extractFieldModifiedAtTimestamps, which reads
		// this same entry back on the next load).
		if modAt, ok := cfg.FieldModifiedAt[jsonKey]; ok && !modAt.IsZero() {
			modKeyBytes, err := json.Marshal(fieldModifiedAtKeyPrefix + jsonKey)
			if err != nil {
				return nil, fmt.Errorf("marshalConfigWithDescriptions: marshal modified-at key for %q: %w", jsonKey, err)
			}
			modValBytes, err := json.Marshal(modAt.Format(time.RFC3339Nano))
			if err != nil {
				return nil, fmt.Errorf("marshalConfigWithDescriptions: marshal modified-at value for %q: %w", jsonKey, err)
			}
			buf.WriteString("  ")
			buf.Write(modKeyBytes)
			buf.WriteString(": ")
			buf.Write(modValBytes)
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

// fieldModifiedAtKeyPrefix is prepended to a Config JSON key to form the
// on-disk top-level key that stores that field's last-WebUI-modification
// timestamp (see Config.FieldModifiedAt's doc comment), mirroring the
// existing "_description_<key>" convention marshalConfigWithDescriptions/
// stripConfigDescriptionKeys already use for embedded field descriptions.
const fieldModifiedAtKeyPrefix = "_modified_at_"

// extractFieldModifiedAtTimestamps scans the top-level keys of raw config
// JSON bytes (BEFORE stripConfigDescriptionKeys removes underscore-prefixed
// keys — callers must pass the original, unstripped bytes) for
// "_modified_at_<key>" entries and returns a map from the underlying
// Config JSON key to its recorded timestamp.
//
// A malformed individual entry (not a JSON string, or not a valid
// RFC3339Nano timestamp) is logged and simply omitted from the result
// rather than aborting the whole config load — mirroring how a single
// malformed whitelist/hosts/blacklist entry is skipped rather than failing
// the entire file elsewhere in this codebase.
func extractFieldModifiedAtTimestamps(log *slog.Logger, data []byte) (map[string]time.Time, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("extractFieldModifiedAtTimestamps: unmarshal: %w", err)
	}

	out := make(map[string]time.Time, len(raw))
	for k, v := range raw {
		key, isModAtKey := strings.CutPrefix(k, fieldModifiedAtKeyPrefix)
		if !isModAtKey || key == "" {
			continue
		}
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			log.Warn("Ignoring malformed field-modified-at entry in config file (value is not a JSON string)",
				slog.String("key", k), wincoe.SafeErr(err))
			continue
		}
		parsed, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			log.Warn("Ignoring malformed field-modified-at entry in config file (not a valid RFC3339 timestamp)",
				slog.String("key", k), slog.String("value", s), wincoe.SafeErr(err))
			continue
		}
		out[key] = parsed
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

// AsyncLogWriter wraps an io.Writer (in practice, always a *rotatingLogWriter
// pointed at dnsbollocks.log or queries.log) so that a slow or contended disk
// can never stall the goroutine that produced the log line.
//
// Why this exists: every slog handler that logs to a file ends up calling
// Write() synchronously on whatever goroutine emitted the line — including
// the DNS UDP/TCP hot paths (runDNSUDPLoop, runDNSTCPLoop, handleDNSQuery),
// which log on essentially every query. A single rotatingLogWriter.Write()
// call has been observed to block for well over a minute under heavy,
// unrelated disk contention (e.g. Defender scanning during a large install
// on the same physical disk), which would otherwise freeze DNS resolution
// itself for that duration — a logging concern taking down the actual
// service.
//
// AsyncLogWriter decouples "record the log line" from "persist the log
// line": Write() copies the bytes (mandatory — slog recycles its formatting
// buffer via sync.Pool the instant Write returns, so retaining a reference
// to the original slice would race with, and could silently corrupt,
// already-queued lines) and hands the copy to a single dedicated background
// goroutine over a bounded channel, then returns immediately. That goroutine
// is the only thing that ever touches the underlying writer, so per-file
// write ordering is preserved exactly as if the writes were synchronous.
//
// Back-pressure policy: if the queue is full — meaning the drain goroutine
// is currently stuck inside a slow underlying Write() — new lines are
// DROPPED rather than blocking the caller or growing memory without bound.
// This is the same tradeoff every async logger makes (zap's buffered
// WriteSyncer, journald's async mode, etc.): under sustained backpressure,
// losing some log lines is preferable to losing DNS service entirely. A
// dropped-line counter is kept and a rate-limited notice is printed directly
// to os.Stderr (bypassing the queue and the slog pipeline entirely, exactly
// like rotatingLogWriter.Write's own existing slow-write diagnostic above)
// so a stuck disk is never silently invisible to the operator.
//
// Known limitation: if the underlying disk never recovers, the drain
// goroutine can remain permanently blocked inside its current Write() call
// forever (Go has no cancellation for a plain blocking file write); Close()
// only bounds how long *callers* wait for it, not the goroutine's own
// lifetime. This is an inherent limitation of blocking file I/O in Go, not
// something this type can fully close off.
type AsyncLogWriter struct {
	underlying io.Writer
	queue      chan []byte
	done       chan struct{} // closed once the drain goroutine has exited

	mu sync.RWMutex // guards closed; see Write/Close for why this can never panic on a closed channel

	// underlyingCloseErr is written by drainLoop before it closes done.
	// A receive from done establishes the happens-before relationship needed
	// for Close to read this field safely without another mutex.
	underlyingCloseErr error

	closed    bool
	closeOnce sync.Once

	dropped        atomic.Int64
	lastDropWarnNs atomic.Int64

	name string // human-readable identity for diagnostics (e.g. the log file path)
}

// asyncLogWriterQueueCapacity bounds worst-case memory usage for a single
// asyncLogWriter: capacity * (typical JSON log line size, a few hundred
// bytes) is a few MB at most, while comfortably absorbing bursts during
// transient disk contention — the exact scenario that motivated this type —
// without dropping lines under normal, brief hiccups.
const asyncLogWriterQueueCapacity = 4096

// asyncLogWriterDropWarnThrottle bounds how often the "we are dropping log
// lines" diagnostic itself is emitted, so a sustained backlog can't turn
// into its own flood of stderr spam.
const asyncLogWriterDropWarnThrottle = 5 * time.Second

// asyncLogWriterCloseDrainTimeout bounds how long Close() waits for the
// drain goroutine to flush whatever is still queued. Bounded so a
// currently-stalled disk can never hang process shutdown/reload
// indefinitely — see the type-level doc comment on why blocking is exactly
// what this type exists to avoid.
const asyncLogWriterCloseDrainTimeout = 5 * time.Second

// newAsyncLogWriter starts the background drain goroutine and returns the
// facade callers should pass to slog.NewJSONHandler (etc.) instead of
// underlying directly. name is used only for diagnostic messages.
func newAsyncLogWriter(underlying io.Writer, name string) *AsyncLogWriter {
	if underlying == nil {
		panic2("BUG: newAsyncLogWriter called with nil underlying io.Writer")
	}
	w := &AsyncLogWriter{
		underlying: underlying,
		queue:      make(chan []byte, asyncLogWriterQueueCapacity),
		done:       make(chan struct{}),
		name:       name,
	}
	go w.drainLoop()
	return w
}

// Write implements io.Writer. It never blocks on the underlying sink.
//
// Per io.Writer's contract this reports success (len(p), nil) once the
// bytes have been safely queued (or intentionally dropped), since queuing —
// not the eventual disk write — is this method's actual job. A dropped line
// is not surfaced as an error return either: slog's Logger.log() discards
// Handle()'s error return entirely, so returning one here would be silently
// swallowed anyway; the stderr fallback in recordDrop is the only path that
// reliably reaches an operator.
func (w *AsyncLogWriter) Write(p []byte) (int, error) {
	n := len(p)

	// RLock (not a full mutex) so the common, uncontended case costs only a
	// couple of atomic ops — negligible next to the multi-second-to-minute
	// disk stalls this type exists to route around. Close() takes the write
	// lock before closing w.queue, so a Write() can never be mid-select-send
	// on a channel that Close() simultaneously closes out from under it
	// (which would otherwise panic).
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		w.recordDrop(true) // "was closed"
		return n, nil
	}

	// Defensive copy: the caller (slog's internal handler) recycles its
	// formatting buffer via sync.Pool the instant Write returns, so we must
	// not retain a reference to p itself once we hand it off. Only copy
	// once we know we're actually enqueuing — no point paying the
	// allocation cost for a line we're about to drop anyway.
	cp := make([]byte, n)
	copy(cp, p)

	select {
	case w.queue <- cp:
	default:
		w.recordDrop(false) // "queue full"
	}
	return n, nil
}

func (w *AsyncLogWriter) recordDrop(wasClosed bool) {
	total := w.dropped.Add(1)
	var what, extra string
	if wasClosed {
		what = "was closed"
		extra = ""
	} else {
		//only rate limit the "queue full" ones!
		what = "queue full"
		extra = " (underlying sink is not keeping up, e.g. due to slow/contended disk)"

		now := time.Now().UnixNano()
		last := w.lastDropWarnNs.Load()
		if now-last < asyncLogWriterDropWarnThrottle.Nanoseconds() {
			return
		}
		if !w.lastDropWarnNs.CompareAndSwap(last, now) {
			return // another goroutine already won the throttle window
		}
	} // end of queue-full
	fmt.Fprintf(os.Stderr,
		"[asyncLogWriter %q] WARNING: log %q; %d line(s) dropped so far"+extra+"\n",
		w.name, what, total)
}

// DroppedCount returns the total number of log lines dropped so far due to
// sustained back-pressure. Exposed for diagnostics/tests.
func (w *AsyncLogWriter) DroppedCount() int64 {
	return w.dropped.Load()
}

// drainLoop is the single goroutine ever allowed to touch w.underlying, so
// per-file write ordering is preserved exactly as if writes were
// synchronous, with no additional locking required here.
func (w *AsyncLogWriter) drainLoop() {
	defer func() {
		// drainLoop owns the underlying writer for its entire lifetime.
		// Closing it here preserves that single-owner invariant even when
		// Close times out while an underlying Write remains blocked.
		if closer, ok := w.underlying.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				w.underlyingCloseErr = fmt.Errorf(
					"asyncLogWriter %q: close underlying writer: %w",
					w.name,
					err,
				)
			}
		}
		close(w.done)
	}()

	for p := range w.queue {
		// 1. Safely extract an independent string copy of the log context BEFORE writing
		// because it's a copy, it avoids holding onto 'p' after the write finishes.
		//Converting a byte slice to a string in Go (string(p)) explicitly allocates new memory and copies the underlying bytes.
		var logSnippet string = string(p)

		// 2. Time the actual synchronous write operation
		start := time.Now()
		n, err := w.underlying.Write(p)
		// At this point, 'p' is done with, and we only look at our safe 'logSnippet' copy if needed
		elapsed := time.Since(start)
		// 3. If it stalls, dump the independent snippet to stderr
		if elapsed > DISK_STALL_DETECT_AFTER_THIS_MANY_SECONDS*time.Second {
			//only log this on stderr, but there's another part that logs in-file, see: rotatingLogWriter.Write()
			fmt.Fprintf(os.Stderr, "[asyncLogWriter %q] === DISK STALL DETECTED ===\n"+
				"[asyncLogWriter %q] Duration: %s\n"+
				"[asyncLogWriter %q] Attempted to write: %s\n"+
				"[asyncLogWriter %q] Bytes written: %d | Err: %v\n"+
				"[asyncLogWriter %q] ===========================\n",
				w.name,
				w.name, elapsed,
				w.name, logSnippet,
				w.name, n, err,
				w.name,
			)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "[asyncLogWriter %q] underlying write failed: %v\n", w.name, err)
		}
	}
}

// Close stops accepting new writes and waits up to
// asyncLogWriterCloseDrainTimeout for drainLoop to flush the queue and close
// the underlying writer.
//
// If the timeout expires, Close returns without touching the underlying
// writer. drainLoop retains ownership and will close it if the blocked write
// eventually completes. This intentionally prefers a temporarily leaked file
// handle over racing Close against an in-progress Write.
//
// Close is idempotent. Subsequent callers wait on the same done channel and
// observe the same underlying close result once draining completes.
func (w *AsyncLogWriter) Close() error {
	w.closeOnce.Do(func() {
		w.mu.Lock()
		w.closed = true
		close(w.queue)
		w.mu.Unlock()
	})

	timer := time.NewTimer(asyncLogWriterCloseDrainTimeout)
	defer timer.Stop()

	select {
	case <-w.done:
		if dropped := w.dropped.Load(); dropped > 0 {
			fmt.Fprintf(
				os.Stderr,
				"[asyncLogWriter %q] total dropped log lines this session: %d\n",
				w.name,
				dropped,
			)
		}
		return w.underlyingCloseErr

	case <-timer.C:
		fmt.Fprintf(
			os.Stderr,
			"[asyncLogWriter %q] WARNING: drain goroutine did not finish within %s during Close(); "+
				"the underlying writer remains owned by the drain goroutine and will be closed if it recovers\n",
			w.name,
			asyncLogWriterCloseDrainTimeout,
		)

		if dropped := w.dropped.Load(); dropped > 0 {
			fmt.Fprintf(
				os.Stderr,
				"[asyncLogWriter %q] total dropped log lines so far: %d\n",
				w.name,
				dropped,
			)
		}

		// Preserve existing bounded-close behavior. Returning an error here
		// could cause reload/shutdown callers to treat a logging stall as a
		// failure of the primary operation even though ownership remains safe.
		return nil
	}
}

var _ io.Writer = (*AsyncLogWriter)(nil)
var _ io.Closer = (*AsyncLogWriter)(nil)

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

	// simpleQueriesWriter holds the current plain-text (non-JSON) per-query
	// log writer (see Config.LogQueriesSimpleFile), so Server.logQuery can
	// always write to the latest writer after a config reload. This log is
	// deliberately NOT a slog handler — just a raw io.Writer — so its format
	// stays a simple, single-line-per-query string rather than JSON.
	simpleQueriesWriter atomic.Pointer[AsyncLogWriter]

	// activePaths records the on-disk log directory/filenames that the
	// CURRENTLY ACTIVE logger (lm.ptr) is actually writing to, as of the
	// last SUCCESSFUL ApplyConfig call. This can diverge from the live
	// Config's own LogDir/LogEverythingFile/LogQueriesFile/
	// LogQueriesSimpleFile fields when a Reload()'s ApplyConfig call fails
	// partway through (e.g. the new log directory is inaccessible): the live
	// Config is already swapped to the NEW, possibly-unusable paths at that
	// point (see Server.Reload), while the logger itself keeps writing to
	// the OLD paths recorded here until a later ApplyConfig call succeeds.
	// AdminUI's /logs* handlers read this (via ActiveLogPaths) instead of
	// the live Config so the log viewer always shows where the logger is
	// ACTUALLY writing, not merely where the config says it should be.
	activePaths atomic.Pointer[activeLogPaths]
}

// activeLogPaths is the immutable snapshot stored in LoggerManager.activePaths.
// See that field's doc comment.
type activeLogPaths struct {
	dir               string
	everythingFile    string
	queriesFile       string
	queriesSimpleFile string
}

// NewLoggerManager creates a manager seeded with the given bootstrap logger.
// No file handles are registered; call Reinit once real log files are open.
func NewLoggerManager(bootstrap *slog.Logger) *LoggerManager {
	lm := &LoggerManager{}
	lm.ptr.Store(bootstrap)
	return lm
}

// get returns the current logger, falling back to slog.Default() if uninitialised
// (should never happen in production but guards tests that build Server partially).
func (lm *LoggerManager) get() *slog.Logger {
	return wincoe.GetLoggerOrFallback(&lm.ptr, "LoggerManager.ptr")
}

// Ptr returns a pointer to the inner atomic so child structs (AdminUI,
// UpstreamManager, wincoe.FileWriter …) can receive a stable reference
// that always reflects the latest logger after a Reinit.
func (lm *LoggerManager) Ptr() *atomic.Pointer[slog.Logger] {
	return &lm.ptr
}

// SimpleQueriesWriterPtr returns a pointer to the atomic holding the current
// plain-text simple-queries log writer (see Config.LogQueriesSimpleFile),
// mirroring Ptr()'s pattern for the main logger so callers always observe
// the latest writer after a config reload.
func (lm *LoggerManager) SimpleQueriesWriterPtr() *atomic.Pointer[AsyncLogWriter] {
	return &lm.simpleQueriesWriter
}

// ActiveLogPaths returns the log directory and the three log filenames the
// currently active logger was actually opened with — i.e. the state
// recorded by the most recent SUCCESSFUL ApplyConfig call. All four return
// values are "" if ApplyConfig has never succeeded yet, which should not
// happen once startup has completed (OldMain aborts the process if the very
// first ApplyConfig call fails). Safe to call on a nil *LoggerManager
// (returns all-empty), so callers that may hold an unwired LoggerManager
// (e.g. tests constructing AdminUI directly) don't need their own nil check.
func (lm *LoggerManager) ActiveLogPaths() (dir, everythingFile, queriesFile, queriesSimpleFile string) {
	if lm == nil {
		return "", "", "", ""
	}
	p := lm.activePaths.Load()
	if p == nil {
		return "", "", "", ""
	}
	return p.dir, p.everythingFile, p.queriesFile, p.queriesSimpleFile
}

// set atomically swaps the logger without touching file handles.
// Use Reinit when the swap accompanies new file handles.
func (lm *LoggerManager) set(l *slog.Logger) {
	lm.ptr.Store(l)
}

// joinErrorsWithPrefix combines zero or more failures into a single wrapped
// error prefixed with a caller-supplied description, or nil if errs is
// empty. Returning errors.Join's result directly would trip wrapcheck
// ("error returned from external package is unwrapped"), so it's always
// routed through fmt.Errorf here; errors.Is/As still traverse into each
// individual error afterward, since errors.Join's result implements
// Unwrap() []error and fmt.Errorf's %w wrapping doesn't hide that from the
// traversal. Originally written for combining multiple Close() failures
// (hence callers passing a "failed to close ..." prefix), but the logic
// itself is generic and is also used for combining independent persistence
// failures (see applyTablesHandler's flushDirty).
func joinErrorsWithPrefix(prefix string, errs []error) error {
	if joined := errors.Join(errs...); joined != nil {
		return fmt.Errorf("%s, joinedErrs: %w", prefix, joined)
	}
	return nil
}

// Reinit atomically swaps the logger, registers new closers (typically
// *rotatingLogWriter instances), and closes the previously registered ones.
// It is safe to call on config reload.
// Also swaps the plain-text simple-queries log writer (see Config.LogQueriesSimpleFile) using the same publish-before-close ordering, for the same reason.
//
// Before closing any of the previously registered closers, this also
// publishes l to wincoe's package-level logger fallbacks (wincoe.Logger,
// and wincoe.bugLogger via wincoe.SetBugLogger) — not just lm.ptr. Those are
// read independently of lm.ptr by wincoe.* helpers (PidAndExeForUDP,
// panic2, etc.); if they were only updated by the caller sometime *after*
// Reinit returned, any such helper running concurrently in that window
// would still read the OLD logger and write into an already-closed
// asyncLogWriter — silently dropping the line and printing a "was closed"
// warning — instead of the new one. Publishing all three "current logger"
// sources here, before any old writer is closed, closes that window.
func (lm *LoggerManager) Reinit(l *slog.Logger, simpleQueriesWriter *AsyncLogWriter, newClosers ...io.Closer) error {
	lm.mu.Lock()
	old := lm.closers
	lm.closers = newClosers
	lm.mu.Unlock()

	lm.set(l) // readers see the new logger from this point
	lm.simpleQueriesWriter.Store(simpleQueriesWriter)
	wincoe.SetBugLogger(l)
	wincoe.SetLogger(l)

	var errs []error
	for _, c := range old {
		if err := c.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return joinErrorsWithPrefix("LoggerManager.Reinit(..) failed to close one or more previous log writers", errs)
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
	return joinErrorsWithPrefix("LoggerManager.Close() failed to close one or more log writers", errs)
}

// ApplyConfig initializes the multi-handler logger (file writers, console level,
// query-only filter) from a validated Config, atomically swaps the active logger,
// and closes any previously registered file handles via Reinit.
// It also synchronises the package-level bugLogger and wincoe.Logger fallbacks.
func (lm *LoggerManager) ApplyConfig(cfg *Config) error {
	log := lm.get()
	consoleLevel := parseConsoleLogLevel(cfg.ConsoleLogLevel)
	// Collected for Reinit() registration below, and for immediate cleanup
	// if a later openLog() call fails after an earlier one already
	// succeeded (see closeOpenedOnFailure).
	var asyncWriters []*AsyncLogWriter

	// closeOpenedOnFailure releases every writer opened so far in this call.
	// Without this, a later openLog() failing (e.g. the queries log file,
	// after the full log file already opened successfully) would silently
	// leak the earlier writer's open file handle and background drain
	// goroutine forever, since it would never be registered with
	// lm.closers and thus never closed by anyone.
	closeOpenedOnFailure := func() {
		for _, w := range asyncWriters {
			if err := w.Close(); err != nil {
				log.Warn("error closing log writer while unwinding a failed ApplyConfig", wincoe.SafeErr(err))
			}
		}
	}

	// All three log files below share the same configured directory (see
	// Config.LogDir's desc tag); create it once up front rather than
	// redundantly re-creating it on every openLog call.
	logDir := resolveLogDir(cfg.LogDir)
	if err := os.MkdirAll(logDir, 0755); err != nil { //If path is already a directory, MkdirAll does nothing and returns nil.
		return fmt.Errorf("failed to create log directory %q: %w", logDir, err)
	}

	// Simple rotation on each log line write (respects your LogMaxSizeMB).
	// Every log line — including ones on the DNS UDP/TCP hot paths — passes
	// through here, so the raw rotatingLogWriter (which can itself block
	// for a long time under disk contention) is wrapped in asyncLogWriter
	// before being handed to slog; see asyncLogWriter's doc comment for why.
	openLog := func(filename string) (*AsyncLogWriter, error) {
		if filename == "" {
			return nil, errors.New("empty logging filename")
		}

		// Resolve via the single shared helper (see resolveLogFilePath's
		// doc comment) so this can never again silently diverge from where
		// AdminUI's log viewer or the early bootstrap logger look for the
		// same file.
		path := resolveLogFilePath(cfg.LogDir, filename)

		writer, err := newRotatingLogWriter(path, cfg.LogMaxSizeMB, log)
		if err != nil {
			return nil, fmt.Errorf("cannot open log file %q: %w", path, err)
		}
		// We can safely trigger a manual size check/rotation on boot here just in case!
		// The next Write() will rotate it automatically anyway if it's over the limit.
		// This runs synchronously, once, before the writer is wrapped and its
		// background drain goroutine starts, so blocking briefly here (unlike
		// per-query log writes further below) is fine.
		writer.RotateIfNeeded()
		async := newAsyncLogWriter(writer, path)
		asyncWriters = append(asyncWriters, async)
		return async, nil
	}

	fullWriter, err := openLog(cfg.LogEverythingFile)
	if err != nil {
		closeOpenedOnFailure()
		return err
	}
	queriesWriter, err := openLog(cfg.LogQueriesFile)
	if err != nil {
		closeOpenedOnFailure()
		return err
	}
	simpleQueriesWriter, err := openLog(cfg.LogQueriesSimpleFile)
	if err != nil {
		closeOpenedOnFailure()
		return err
	}

	fullHandler := slog.NewJSONHandler(fullWriter, &slog.HandlerOptions{
		Level:       slog.LevelDebug, // full log gets EVERYTHING
		ReplaceAttr: stripColorTags,  // Strips tags safely for files
	})
	queryH := queryFilterHandler{
		Handler: slog.NewJSONHandler(queriesWriter, &slog.HandlerOptions{
			ReplaceAttr: stripColorTags, // Strips tags safely for files
		}),
	}

	// Skip building the colored console handler entirely when no console is
	// attached (a -H=windowsgui build, or after hide_console detached it):
	// every DNS query logs at least one line, so constructing and then
	// discarding a colored console string per query would be pure wasted
	// CPU on the hot path with nothing able to display it.
	handlers := []slog.Handler{fullHandler, queryH}
	if wincoe.HasConsole() {
		handlers = append(handlers, NewColoredConsoleHandler(consoleLevel, log)) // now uses the real config level
	} else {
		log.Debug("No console attached; skipping the colored console log handler")
	}

	// Bind the PID globally across all handlers managed by this logger
	//(Note regarding key order: Because Go's native slog.JSONHandler hardcodes its internal attribute serialization sequence to time $\rightarrow$ level $\rightarrow$ source $\rightarrow$ msg, any attributes added via .With() will serialize at the end of the JSON object. This is standard behavior and fully compatible with all log parsers.)
	improvedLogger := slog.New(multiHandler{
		handlers: handlers,
	}).With(slog.Int("pid", os.Getpid()))

	// Reinit closes old async log writers (if any) and registers these new ones.
	closers := make([]io.Closer, len(asyncWriters))
	for i, w := range asyncWriters {
		closers[i] = w
	}
	// Reinit publishes improvedLogger to wincoe's package-level fallbacks too
	// (before closing anything old) — see Reinit's doc comment.
	if reinitErr := lm.Reinit(improvedLogger, simpleQueriesWriter, closers...); reinitErr != nil {
		// The new logger is already stored by Reinit; use it for the warning.
		improvedLogger.Warn("error closing old log files during logger reinit", wincoe.SafeErr(reinitErr))
	}

	// Record exactly which on-disk paths this now-active logger was opened
	// against. Reaching this point means every openLog() call above already
	// succeeded, so this is the single point where "the config we just
	// applied" and "what the logger is now actually writing to" are
	// guaranteed to agree — see activePaths's doc comment for why that
	// guarantee matters (AdminUI's /logs* handlers rely on it after a LATER
	// Reload() whose ApplyConfig call fails before ever reaching here).
	lm.activePaths.Store(&activeLogPaths{
		dir:               cfg.LogDir,
		everythingFile:    cfg.LogEverythingFile,
		queriesFile:       cfg.LogQueriesFile,
		queriesSimpleFile: cfg.LogQueriesSimpleFile,
	})

	improvedLogger.Info("Logging (re)initialized",
		slog.String("full_log", cfg.LogEverythingFile),
		slog.String("queries_log", cfg.LogQueriesFile),
		slog.String("queries_simple_log", cfg.LogQueriesSimpleFile),
		slog.String("console_level", cfg.ConsoleLogLevel),
	)
	return nil
}

// Runtime encapsulates long-lived infrastructure dependencies (logger, file
// writer) that persist across configuration reloads and server lifecycles.
// OldMain creates and owns a Runtime; NewServer receives it as a dependency
// rather than constructing these services itself.
type Runtime struct {
	LogMgr     *LoggerManager
	FileWriter wincoe.FileWriter
}

// ApplyFileWriterParams pushes ExtraSafety and retry settings from cfg onto
// the process-lifetime FileWriter. Call after every successful config load
// (initial boot and Reload) so writes always use the live values.
func (r *Runtime) ApplyFileWriterParams(cfg *Config) {
	if r == nil || r.FileWriter == nil || cfg == nil {
		panic2("BUG: ApplyFileWriterParams called with nil Runtime, FileWriter, or Config")
	}
	r.FileWriter.SetExtraSafety(cfg.ExtraSafety)
	r.FileWriter.SetRetryParams(cfg.FileWriterMaxRetries, cfg.FileWriterRetryBackoffMs)
}

// Logger is same as rt.LogMgr.Get()
func (r *Runtime) Logger() *slog.Logger {
	if r.LogMgr == nil {
		panic2("BUG: uninited Runtime.LogMgr!")
	}
	return r.LogMgr.get()
}

// SimpleQueriesWriter returns the current plain-text (non-JSON)
// simple-queries log writer (see Config.LogQueriesSimpleFile), or nil if
// logging hasn't been fully initialized yet. Callers must treat a nil
// return as "nothing to write to yet" rather than panicking — this is
// reached from the DNS hot path (Server.logQuery).
func (r *Runtime) SimpleQueriesWriter() *AsyncLogWriter {
	if r == nil || r.LogMgr == nil {
		return nil
	}
	return r.LogMgr.SimpleQueriesWriterPtr().Load()
}

// FlushLogsForShutdown drains and closes every currently-registered
// asynchronous log writer (see asyncLogWriter) via LogMgr.Close(), bounded
// by asyncLogWriterCloseDrainTimeout so it can never itself hang process
// shutdown even if the underlying disk is currently stuck. Safe to call
// more than once, and safe to call even if ApplyConfig was never reached
// yet (nothing registered to close in that case).
//
// Any failure is reported directly to os.Stderr rather than through
// r.Logger(): by the time this runs we are already tearing down the very
// log writers that logger depends on, so routing the error back through
// them would be unreliable.
func (r *Runtime) FlushLogsForShutdown() {
	if r == nil || r.LogMgr == nil {
		return
	}
	if err := r.LogMgr.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: error flushing/closing log writers during shutdown: %v\n", err)
	}
}

// newDefaultFileWriter creates a FileWriter seeded with defaultConfig's safety
// and retry settings. Used when no caller-supplied FileWriter is available.
func newDefaultFileWriter(lp *atomic.Pointer[slog.Logger]) wincoe.FileWriter {
	def := defaultConfig()
	return wincoe.NewWin11SafeFileWriter(
		def.ExtraSafety,
		def.FileWriterMaxRetries,
		def.FileWriterRetryBackoffMs,
		lp,
	)
}

// saveConfig marshals rawCfg and writes it to configFileName via fw.
// If fw is nil a temporary FileWriter is created with default settings.
func saveConfig(fw wincoe.FileWriter, log *slog.Logger, rawCfg *Config) error {
	if rawCfg == nil {
		panic2("BUG: saveConfig called with nil rawCfg")
	}
	if fw == nil {
		var lp atomic.Pointer[slog.Logger]
		lp.Store(log)
		fw = newDefaultFileWriter(&lp)
	}
	data, err := marshalConfigWithDescriptions(rawCfg)
	if err != nil {
		return fmt.Errorf("config marshal failed: %w", err)
	}
	if err := fw.SafeWriteFile(configFileName, data, 0600); err != nil {
		return fmt.Errorf("config write failed: %w", err)
	}
	log.Info("Saved config file", slog.String("config_file", configFileName))
	return nil
}

// saveConfig is the Server method wrapper around the free function.
func (s *Server) saveConfig() error {
	rawCfg := s.getRawConfig()
	if rawCfg == nil {
		// Defensive: should never happen in normal operation.
		panic2("BUG: saveConfig called before liveRawConfig was initialised")
	}
	return saveConfig(s.rt.FileWriter, s.getLogger(), rawCfg)
}

const (
	// Ordinary admin forms contain only a small number of short fields.
	maxWebUIFormBodyBytes int64 = 256 << 10 // 256 KiB

	// Batch table application can legitimately contain many staged entries,
	// but must remain bounded to prevent authenticated memory exhaustion.
	maxWebUIBatchBodyBytes int64 = 4 << 20 // 4 MiB

	maxBatchTableChanges    = 10_000
	maxBatchFieldsPerChange = 16
	maxBatchFieldNameBytes  = 64
	maxBatchFieldValueBytes = 64 << 10
)

func (ui *AdminUI) applyTablesHandler(w http.ResponseWriter, r *http.Request) {
	const allowedMethods = "POST, OPTIONS"
	if writeAllowHeaderResponse(w, r, allowedMethods) {
		return
	}
	log := ui.getLogger()

	if r.Method != http.MethodPost {
		ui.rejectUnsupportedMethod(w, r, allowedMethods)
		return
	}

	// payload := r.FormValue("payload")
	if err := r.ParseForm(); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			// if errors.AsType[*http.MaxBytesError] {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}

		log.Warn("Failed to parse batch-apply form", wincoe.SafeErr(err))
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}

	payload := r.PostForm.Get("payload") // Using PostForm prevents URL query parameters from masquerading as body fields.
	if payload == "" {
		http.Error(w, "empty payload", http.StatusBadRequest)
		return
	}

	type tableChange struct {
		URL      string            `json:"url"`
		Fields   map[string]string `json:"fields"`
		ClientID string            `json:"client_id"`
	}

	type tableVersions struct {
		Rules          string `json:"rules"`
		Hosts          string `json:"hosts"`
		Blacklist      string `json:"blacklist"`
		QueryBlocklist string `json:"query_blocklist"`
	}

	type applyTablesRequest struct {
		Versions tableVersions `json:"versions"`
		Changes  []tableChange `json:"changes"`
	}

	var request applyTablesRequest
	decoder := json.NewDecoder(strings.NewReader(payload))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&request); err != nil {
		log.Warn("Invalid JSON in batch apply", wincoe.SafeErr(err))
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	changes := request.Changes

	if decoder.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "invalid trailing JSON data", http.StatusBadRequest)
		return
	}

	if len(changes) == 0 {
		http.Error(w, "batch must contain at least one change", http.StatusBadRequest)
		return
	}
	if len(changes) > maxBatchTableChanges {
		http.Error(
			w,
			fmt.Sprintf("batch exceeds maximum of %d changes", maxBatchTableChanges),
			http.StatusRequestEntityTooLarge,
		)
		return
	}

	for i, change := range changes {
		if len(change.Fields) == 0 {
			http.Error(
				w,
				fmt.Sprintf("batch change %d contains no fields", i),
				http.StatusBadRequest,
			)
			return
		}
		if len(change.Fields) > maxBatchFieldsPerChange {
			http.Error(
				w,
				fmt.Sprintf(
					"batch change %d exceeds maximum of %d fields",
					i,
					maxBatchFieldsPerChange,
				),
				http.StatusBadRequest,
			)
			return
		}

		for name, value := range change.Fields {
			if name == "" || len(name) > maxBatchFieldNameBytes {
				http.Error(
					w,
					fmt.Sprintf("batch change %d contains an invalid field name", i),
					http.StatusBadRequest,
				)
				return
			}
			if len(value) > maxBatchFieldValueBytes {
				http.Error(
					w,
					fmt.Sprintf(
						"batch change %d field %q exceeds maximum size",
						i,
						name,
					),
					http.StatusRequestEntityTooLarge,
				)
				return
			}
		}
	}

	touchesRules := false
	touchesHosts := false
	touchesBlacklist := false
	touchesQueryBlocklist := false

	for _, change := range changes {
		switch change.URL {
		case "/rules":
			touchesRules = true
		case "/hosts":
			touchesHosts = true
		case "/response-blacklist":
			touchesBlacklist = true
		case "/query-blocklist":
			touchesQueryBlocklist = true
		default:
			http.Error(w, "unknown target URL in batch", http.StatusBadRequest)
			return
		}
	}

	// Hold the shared table-mutation lock from version check through
	// mutation, persistence, and invalidation so reload/load paths cannot
	// interleave and create a stale-write race.
	ui.tableMutationMu.Lock()
	defer ui.tableMutationMu.Unlock()

	// Reused below both for the version checks and for currentVersions();
	// stable for the whole handler since it runs entirely under
	// tableMutationMu, which also serializes against Reload() ever swapping
	// in a Config with different file paths mid-request.
	cfg := ui.getConfig()

	requireVersion := func(name, raw string) (string, error) {
		if raw == "" {
			return "", fmt.Errorf("missing %s version", name)
		}
		return raw, nil
	}

	if touchesRules {
		v, err := requireVersion("rules", request.Versions.Rules)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if current := tableVersionToken(ui.ruleStore.Generation(), cfg.WhitelistFile); v != current {
			http.Error(w, "rules changed (in memory or on disk) since this page was loaded; reload before applying", http.StatusConflict)
			return
		}
	}

	if touchesHosts {
		v, err := requireVersion("hosts", request.Versions.Hosts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if current := tableVersionToken(ui.hostStore.Generation(), cfg.HostsFile); v != current {
			http.Error(w, "hosts changed (in memory or on disk) since this page was loaded; reload before applying", http.StatusConflict)
			return
		}
	}

	if touchesBlacklist {
		v, err := requireVersion("blacklist", request.Versions.Blacklist)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if current := tableVersionToken(ui.blacklist.Generation(), cfg.BlacklistFile); v != current {
			http.Error(w, "response blacklist changed (in memory or on disk) since this page was loaded; reload before applying", http.StatusConflict)
			return
		}
	}

	if touchesQueryBlocklist {
		if ui.queryBlocklistStore == nil || ui.OnSaveQueryBlocklist == nil {
			log.Error("BUG: query-blocklist batch-apply reached without queryBlocklistStore/OnSaveQueryBlocklist wired")
			http.Error(w, "query blocklist is not available in this environment", http.StatusServiceUnavailable)
			return
		}
		v, err := requireVersion("query_blocklist", request.Versions.QueryBlocklist)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if current := ui.queryBlocklistVersionToken(); v != current {
			http.Error(w, "query blocklist changed (in memory or on disk) since this page was loaded; reload before applying", http.StatusConflict)
			return
		}
	}

	// Track which files got dirtied so we only incur disk I/O once per file
	saveRules := false
	saveHosts := false
	saveBlacklist := false
	saveQueryBlocklist := false

	// flushDirty persists every store that was actually mutated so far,
	// attempting ALL of them independently rather than stopping at the first
	// failure (whitelist/hosts/blacklist live in separate files, so a
	// transient failure writing one must not also skip the other two), and
	// returns a combined error if any failed. Each individual failure is
	// logged (via logPersistFailure) but does not crash the process: the
	// in-memory stores were already mutated successfully, so DNS resolution
	// continues correctly with the new state; only the on-disk copy(ies) may
	// be stale until the next successful save.
	flushDirty := func() error {
		var errs []error
		if saveRules {
			if err := ui.OnSaveWhitelist(); err != nil {
				errs = append(errs, ui.logPersistFailure("whitelist", err))
			}
		}
		if saveHosts {
			if err := ui.OnSaveHosts(); err != nil {
				errs = append(errs, ui.logPersistFailure("hosts", err))
			}
		}
		if saveBlacklist {
			if err := ui.OnSaveBlacklist(); err != nil {
				errs = append(errs, ui.logPersistFailure("response blacklist", err))
			}
		}
		if saveQueryBlocklist {
			if err := ui.OnSaveQueryBlocklist(); err != nil {
				errs = append(errs, ui.logPersistFailure("query blocklist", err))
			}
		}
		return joinErrorsWithPrefix("batch apply: one or more staged-table stores failed to persist to disk", errs)
	}

	// Every change in the batch is an independent rule/host/blacklist entry,
	// so one failing entry must not silently discard the outcome of the
	// others. Process the full batch, collect every failure, and persist
	// whatever succeeded exactly once at the end — this replaces the
	// previous "abort at first failure" behavior, which still persisted
	// every change applied so far (flushDirty() ran on that path too) while
	// telling the client the whole batch failed, leaving the client's
	// staged-changes list out of sync with what was actually written to
	// disk. See todonow.txt "Partial Batch Commits in WebUI".
	type batchFailure struct {
		index    int
		clientID string
		url      string
		status   int
		err      error
	}
	var failures []batchFailure
	appliedCount := 0
	var appliedClientIDs []string

	// Cache invalidation is coalesced across the whole batch instead of
	// happening once per changed entry (which used to mean N full O(cache
	// size) table scans for an N-entry batch — see todonow.txt "O(N)
	// Synchronous Cache Eviction"). Rule/host changes accumulate their
	// touched patterns here instead of invalidating immediately; a single
	// aggregated pass runs once after the whole batch (and its disk
	// persistence) completes. Blacklist changes are cheaper to coalesce:
	// invalidateCacheForBlacklistedIPs() already re-snapshots the live
	// blacklist and re-scans the cache in one pass regardless of how many
	// blacklist edits preceded it, so it only needs to run once total too.
	touchedPatterns := make(map[string]struct{})
	var blacklistTouched bool
	collectPattern := func(p string) { touchedPatterns[p] = struct{}{} }
	markBlacklistTouched := func() { blacklistTouched = true }

	for i, change := range changes {
		var status int
		var err error

		switch change.URL {
		case "/rules":
			status, err = ui.processRuleChange(change.Fields, collectPattern)
			if err == nil {
				saveRules = true
			}
		case "/hosts":
			status, err = ui.processHostChange(change.Fields, collectPattern)
			if err == nil {
				saveHosts = true
			}
		case "/response-blacklist":
			status, err = ui.processBlacklistChange(change.Fields, markBlacklistTouched)
			if err == nil {
				saveBlacklist = true
			}
		case "/query-blocklist":
			status, err = ui.processQueryBlockChange(change.Fields, collectPattern)
			if err == nil {
				saveQueryBlocklist = true
			}
		default:
			status, err = http.StatusBadRequest, errors.New("unknown target URL in batch")
		}

		if err != nil {
			log.Warn("Batch apply failed for a record", slog.Int("index", i), slog.String("url", change.URL), wincoe.SafeErr(err))
			// failures = append(failures, batchFailure{index: i, url: change.URL, err: fmt.Errorf("status %d: %w", status, err)})
			failures = append(failures, batchFailure{
				index:    i,
				clientID: change.ClientID,
				url:      change.URL,
				status:   status,
				err:      err,
			})
			continue
		}
		appliedCount++
		if change.ClientID != "" {
			appliedClientIDs = append(appliedClientIDs, change.ClientID)
		}
	} // for

	writeJSON := func(status int, value any) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(value); err != nil {
			log.Debug("Failed to write batch response", wincoe.SafeErr(err))
		}
	}

	// currentVersions() snapshots the CURRENT (post-mutation, whether that
	// mutation fully succeeded, partially succeeded, or succeeded in-memory
	// but failed to persist) generation numbers, so the client can adopt them
	// and safely reload afterward without a stale-version mismatch discarding
	// still-valid staged changes it never got to apply.
	currentVersions := func() applyTablesResponseVersions {
		return applyTablesResponseVersions{
			Rules:          tableVersionToken(ui.ruleStore.Generation(), cfg.WhitelistFile),
			Hosts:          tableVersionToken(ui.hostStore.Generation(), cfg.HostsFile),
			Blacklist:      tableVersionToken(ui.blacklist.Generation(), cfg.BlacklistFile),
			QueryBlocklist: ui.queryBlocklistVersionToken(),
		}
	}

	// buildResponseFailures converts the accumulated per-item failures into
	// their JSON-response shape. Shared by the persistence-failure (500) and
	// partial-validation-failure (422) responses below, since either can
	// leave a non-empty failures slice the client needs to see.
	buildResponseFailures := func() []batchFailureResponse {
		responseFailures := make([]batchFailureResponse, 0, len(failures))
		for _, failure := range failures {
			responseFailures = append(responseFailures, batchFailureResponse{
				Index:    failure.index,
				ClientID: failure.clientID,
				URL:      failure.url,
				Status:   failure.status,
				Error:    failure.err.Error(),
			})
		}
		return responseFailures
	}

	flushErr := flushDirty()

	// The stores were already mutated in memory. Keep dependent caches
	// consistent with that live state even if persistence to disk fails.
	if len(touchedPatterns) > 0 && ui.OnInvalidatePatterns != nil {
		ui.OnInvalidatePatterns(touchedPatterns)
	}
	if blacklistTouched && ui.OnInvalidateBlacklist != nil {
		ui.OnInvalidateBlacklist()
	}

	if flushErr != nil {
		writeJSON(http.StatusInternalServerError, applyTablesResponse{
			OK:                false,
			Applied:           appliedClientIDs,
			Failed:            buildResponseFailures(),
			PersistenceFailed: true,
			Error:             flushErr.Error(),
			Versions:          currentVersions(),
		})
		return
	}

	if len(failures) > 0 {
		log.Warn(
			"Batch apply completed with partial failures",
			slog.Int("failed", len(failures)),
			slog.Int("applied", appliedCount),
			slog.Int("total", len(changes)),
		)

		writeJSON(http.StatusUnprocessableEntity, applyTablesResponse{
			OK:       false,
			Applied:  appliedClientIDs,
			Failed:   buildResponseFailures(),
			Versions: currentVersions(),
		})
		return
	}

	log.Info("Successfully batch-applied staged table changes", slog.Int("changes", len(changes)))
	writeJSON(http.StatusOK, applyTablesResponse{
		OK:       true,
		Applied:  appliedClientIDs,
		Versions: currentVersions(),
	})
}

func (ui *AdminUI) processRuleChange(fields map[string]string, invalidate func(pattern string)) (int, error) {
	log := ui.getLogger()

	// Handle delete requests
	if fields["delete"] == "1" {
		id := fields["id"]
		typ := fields["type"]
		if id == "" || typ == "" {
			log.Warn("Failed to delete rule: id and type required", slog.String("id", id), slog.String("type", typ))
			return http.StatusBadRequest, errors.New("id and type required for delete")
		}
		if err := validateDNSType(typ); err != nil {
			log.Warn("Failed to delete rule: invalid DNS type", slog.String("type", typ), wincoe.SafeErr(err))
			return http.StatusBadRequest, err
		}
		// id is a UUID used only as a map key; sanitize it against injection just in case.
		if _, modified := sanitizeDomainInput(id); modified {
			log.Warn("Failed to delete rule: id contains illegal characters", slog.String("id", id))
			return http.StatusBadRequest, errors.New("id contains illegal characters")
		}
		pattern, err := ui.ruleStore.DeleteRule(typ, id, log)
		if err != nil {
			log.Warn("Failed to delete rule: rule not found", slog.String("id", id), slog.String("type", typ))
			return http.StatusNotFound, err
		}

		invalidate(pattern)
		displayPattern, wasIDN := punycodeDecodePatternForDisplay(pattern)
		attrs := []any{slog.String("id", id), slog.String("type", typ), slog.String("pattern", pattern)}
		if wasIDN {
			attrs = append(attrs, slog.String("pattern_idn", displayPattern))
		}
		log.Info("Successfully deleted rule via WebUI/Batch", attrs...)
		return http.StatusOK, nil
	} //end delete

	// isEdit is explicit (mirrors processHostChange's fields["edit"] flag),
	// rather than being inferred from whether "id" happens to be non-empty,
	// so a client bug that omits the edit flag can't silently fall through
	// to the Add branch (or vice versa).
	isEdit := fields["edit"] == "1"
	patternNormalized := NormalizeDomain(fields["pattern"]) //XXX: must be lowercased for matchPattern later on.
	typ := fields["type"]
	id := fields["id"]
	enabledStr := fields["enabled"]
	enabledBool := enabledStr == "on" || enabledStr == "true" || enabledStr == "1"

	if patternNormalized == "" || typ == "" {
		log.Warn("Failed to add/edit rule: Pattern and type required", slog.String("patternLowercased", patternNormalized), slog.String("type", typ))
		return http.StatusBadRequest, errors.New("pattern and type required")
	}

	// Convert any Unicode (IDN) labels the operator typed/edited (e.g.
	// "café.com") into punycode/ASCII before validation and storage; real
	// DNS queries always arrive already punycode-encoded, so patterns must
	// be stored the same way to ever match. displayPattern is kept only for
	// a more readable conflict/error message further below.
	displayPattern := patternNormalized
	encodedPattern, encErr := encodePatternOrErr(patternNormalized)
	if encErr != nil {
		log.Warn("Failed to add/edit rule: invalid unicode pattern", slog.String("pattern_idn", displayPattern), wincoe.SafeErr(encErr))
		return http.StatusBadRequest, encErr
	}
	patternNormalized = encodedPattern

	if err := validateDNSType(typ); err != nil {
		log.Warn("Failed to add/edit rule: invalid DNS type", slog.String("type", typ), wincoe.SafeErr(err))
		return http.StatusBadRequest, err
	}
	if err := validateRulePattern(patternNormalized); err != nil {
		log.Warn("Failed to add/edit rule: invalid pattern", slog.String("pattern", patternNormalized), slog.String("pattern_idn", displayPattern), wincoe.SafeErr(err))
		return http.StatusBadRequest, errors.New("Invalid pattern: " + err.Error())
	}

	if isEdit {
		// --- EDIT MODE ---
		if id == "" {
			log.Warn("Failed to edit rule: edit flag set but id is empty")
			return http.StatusBadRequest, errors.New("id required for edit")
		}
		// id is a UUID used only as a map key; sanitize it against injection just in case.
		if _, modified := sanitizeDomainInput(id); modified {
			log.Warn("Failed to add/edit rule: id contains illegal characters", slog.String("id", id))
			return http.StatusBadRequest, errors.New("id contains illegal characters")
		}
		_, oldPattern, err := ui.ruleStore.UpdateRule(id, typ, patternNormalized, enabledBool, log)
		if err != nil {
			displayOldPattern, oldWasIDN := punycodeDecodePatternForDisplay(oldPattern)
			attrs := []any{
				wincoe.SafeErr(err),
				slog.String("id", id),
				slog.String("type", typ),
				slog.String("old_pattern", oldPattern),
				slog.String("new_pattern", patternNormalized),
			}
			if displayPattern != patternNormalized {
				attrs = append(attrs, slog.String("new_pattern_idn", displayPattern))
			}
			if oldWasIDN {
				attrs = append(attrs, slog.String("old_pattern_idn", displayOldPattern))
			}
			log.Warn("Failed to edit rule", attrs...)

			if displayPattern != patternNormalized {
				return http.StatusConflict, fmt.Errorf("%w (as entered: %q)", err, displayPattern)
			}
			return http.StatusConflict, err
		}

		invalidate(oldPattern)
		if oldPattern != patternNormalized {
			invalidate(patternNormalized)
		}
		log.Info("Rule edited via WebUI/Batch",
			slog.String("id", id),
			slog.String("type", typ),
			slog.String("new_pattern", patternNormalized),
			slog.String("new_displayPattern", displayPattern),
			slog.Bool("enabled", enabledBool),
			slog.String("old_pattern", oldPattern))
	} else {
		// --- ADD MODE ---
		if id != "" {
			log.Warn("Failed to add rule: id was unexpectedly present without the edit flag", slog.String("id", id))
			return http.StatusBadRequest, errors.New("id must not be set when adding a new rule")
		}
		newID, err := ui.ruleStore.AddRule(typ, patternNormalized, enabledBool, log)
		if err != nil {
			log.Warn("Failed to add rule",
				wincoe.SafeErr(err),
				slog.String("newID", newID),
				slog.String("type", typ),
				slog.String("patternLowercased", patternNormalized),
				slog.String("pattern_idn", displayPattern),
			)
			if displayPattern != patternNormalized {
				return http.StatusConflict, fmt.Errorf("%w (as entered: %q)", err, displayPattern)
			}
			return http.StatusConflict, err
		}

		invalidate(patternNormalized)
		log.Info("Rule added via WebUI/Batch",
			slog.String("patternLowercased", patternNormalized),
			slog.String("pattern_idn", displayPattern),
			slog.String("type", typ),
			slog.String("newID", newID),
			slog.Bool("enabled", enabledBool))
	}
	return http.StatusOK, nil
}

func (ui *AdminUI) processHostChange(fields map[string]string, invalidate func(pattern string)) (int, error) {
	log := ui.getLogger()
	// --- DELETE ---
	if fields["delete"] == "1" {
		patternLowercased := strings.ToLower(strings.TrimSpace(fields["pattern"]))
		if patternLowercased == "" {
			log.Warn("Failed to delete local host: pattern required")
			return http.StatusBadRequest, errors.New("pattern required for delete")
		}
		// Encode defensively in case a Unicode pattern is submitted directly
		// (e.g. an old cached page, or a hand-crafted API request); the
		// hidden form field the WebUI itself submits is already ASCII.
		if encoded, encErr := encodePatternOrErr(patternLowercased); encErr != nil {
			log.Warn("Failed to delete local host: invalid unicode pattern", slog.String("pattern", patternLowercased), wincoe.SafeErr(encErr))
			return http.StatusBadRequest, encErr
		} else {
			patternLowercased = encoded
		}
		if err := validateRulePattern(patternLowercased); err != nil {
			log.Warn("Failed to delete local host: invalid pattern", slog.String("pattern", patternLowercased), wincoe.SafeErr(err))
			return http.StatusBadRequest, errors.New("Invalid pattern: " + err.Error())
		}
		if ui.hostStore.DeleteHost(patternLowercased) {
			invalidate(patternLowercased)
			displayPattern, wasIDN := punycodeDecodePatternForDisplay(patternLowercased)
			attrs := []any{slog.String("pattern", patternLowercased)}
			if wasIDN {
				attrs = append(attrs, slog.String("pattern_idn", displayPattern))
			}
			log.Info("Successfully deleted local host override via WebUI/Batch", attrs...)
			return http.StatusOK, nil
		}
		log.Warn("Failed to delete local host: host not found", slog.String("pattern", patternLowercased))
		return http.StatusNotFound, errors.New("host not found")
	} //end "delete"

	// --- ADD / EDIT ---
	patternLowercased := strings.ToLower(strings.TrimSpace(fields["pattern"]))
	oldPatternLowercased := strings.ToLower(strings.TrimSpace(fields["old_pattern"]))
	isEdit := fields["edit"] == "1"
	enabledStr := fields["enabled"]
	enabledBool := enabledStr == "on" || enabledStr == "true" || enabledStr == "1"

	if patternLowercased == "" {
		log.Warn("Failed to add/edit local host: hostname required")
		return http.StatusBadRequest, errors.New("hostname/pattern required")
	}
	// Mirrors processRuleChange's "id required for edit" guard and
	// processBlacklistChange's "old_cidr ... required" guard: an edit
	// request must always identify which existing entry it's editing.
	// Without this, EditHost("", patternLowercased, netIPs) below would
	// silently behave like an Add (deleteHostEntry("") is a no-op) instead
	// of being rejected as a malformed request.
	if isEdit && oldPatternLowercased == "" {
		log.Warn("Failed to edit local host: edit flag set but old_pattern is empty")
		return http.StatusBadRequest, errors.New("old_pattern required for edit")
	}

	// Convert any Unicode (IDN) labels (e.g. "café.com") into punycode/ASCII
	// before validation and storage; real DNS queries always arrive already
	// punycode-encoded, so patterns must be stored the same way to ever
	// match. displayPattern is kept only for a more readable conflict/error
	// message further below.
	displayPattern := patternLowercased
	if encoded, encErr := encodePatternOrErr(patternLowercased); encErr != nil {
		log.Warn("Failed to add/edit local host: invalid unicode pattern", slog.String("pattern", displayPattern), wincoe.SafeErr(encErr))
		return http.StatusBadRequest, encErr
	} else {
		patternLowercased = encoded
	}

	if isEdit && oldPatternLowercased != "" {
		if encodedOld, encErr := encodePatternOrErr(oldPatternLowercased); encErr != nil {
			log.Warn("Failed to edit local host: invalid unicode old_pattern", slog.String("old_pattern", oldPatternLowercased), wincoe.SafeErr(encErr))
			return http.StatusBadRequest, encErr
		} else {
			oldPatternLowercased = encodedOld
		}
	}

	//okTODO: are we accepting a pattern like /rules does here? or is it just a hostname? it's pattern!
	if err := validateRulePattern(patternLowercased); err != nil {
		attrs := []any{slog.String("pattern", patternLowercased), wincoe.SafeErr(err)}
		if displayPattern != patternLowercased {
			attrs = append(attrs, slog.String("pattern_idn", displayPattern))
		}
		log.Warn("Failed to add/edit local host: invalid pattern", attrs...)
		return http.StatusBadRequest, errors.New("Invalid pattern: " + err.Error())
	}
	// old_pattern (edit path) needs the same check.
	if isEdit && oldPatternLowercased != "" {
		if err := validateRulePattern(oldPatternLowercased); err != nil {
			displayOldPattern, wasIDN := punycodeDecodePatternForDisplay(oldPatternLowercased)
			attrs := []any{slog.String("old_pattern", oldPatternLowercased), wincoe.SafeErr(err)}
			if wasIDN {
				attrs = append(attrs, slog.String("old_pattern_idn", displayOldPattern))
			}
			log.Warn("Failed to edit local host: invalid old_pattern", attrs...)
			return http.StatusBadRequest, errors.New("Invalid old_pattern: " + err.Error())
		}
	}

	ipsRaw := strings.Split(fields["ips"], ",")
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
			return http.StatusBadRequest, errors.New("invalid IP address: " + ipStr)
		}
	}
	if len(netIPs) == 0 {
		log.Warn("Failed to add/edit local host: no valid IP required", slog.String("pattern", patternLowercased))
		return http.StatusBadRequest, errors.New("at least one valid IP required")
	}

	var err error
	if isEdit {
		// NOW CATCHING THE ERROR:
		err = ui.hostStore.EditHostWithEnabled(oldPatternLowercased, patternLowercased, netIPs, enabledBool)
	} else {
		//it's Add (Delete was handled above)
		err = ui.hostStore.AddHostWithEnabled(patternLowercased, netIPs, enabledBool)
	}

	if err != nil {
		log.Warn("Failed to add/edit local host:", wincoe.SafeErr(err),
			slog.String("pattern", patternLowercased),
			slog.String("pattern_idn", displayPattern),
			slog.Any("IPs", netIPs),
		)
		if displayPattern != patternLowercased {
			return http.StatusConflict, fmt.Errorf("local host with this pattern already exists (as entered: %q): %w", displayPattern, err)
		}
		return http.StatusConflict, fmt.Errorf("local host with this pattern already exists: %w", err)
	}

	// --- NEW: Cache Invalidation ---
	// If this was an edit, purge the old pattern's cached entries, if different than new pattern
	if isEdit && oldPatternLowercased != "" && oldPatternLowercased != patternLowercased {
		invalidate(oldPatternLowercased)
	}
	// Always purge the new pattern so the local override takes immediate effect
	// (e.g., clearing out previous NXDOMAINs or external IPs)
	invalidate(patternLowercased) //doneFIXME: pattern here could be same as oldPattern, avoid purging twice?
	log.Info("Successfully added/edited local host override via WebUI/Batch",
		slog.String("pattern", patternLowercased),
		slog.String("pattern_idn", displayPattern),
		slog.Int("ip_count", len(netIPs)),
		slog.Bool("enabled", enabledBool))
	return http.StatusOK, nil
}

func (ui *AdminUI) processBlacklistChange(fields map[string]string, invalidateBlacklist func()) (int, error) {
	log := ui.getLogger()
	action := fields["action"]
	enabledStr := fields["enabled"]
	enabledBool := enabledStr == "on" || enabledStr == "true" || enabledStr == "1"

	switch action { //doneFIXME: could use tagged switch on action QF1003 default
	case "delete":
		cidrStr := strings.TrimSpace(fields["cidr"])
		// 1. Remove the CIDR from the rules list (Source of Truth)
		// Using the clean delete helper method with natural defer unlock

		if ui.tryDeleteBlacklistIP(cidrStr) { //it got deleted
			// 2. Global flush of the cache so it re-reads the updated rules list
			invalidateBlacklist()
			log.Info("Successfully deleted IP/CIDR from response blacklist via WebUI/Batch", slog.String("cidr", cidrStr))
			return http.StatusOK, nil
		}
		log.Warn("Failed to delete IP/CIDR from blacklist: not found", slog.String("cidr", cidrStr))
		return http.StatusNotFound, errors.New("IP/CIDR not found")
	case "add":
		cidrStr := strings.TrimSpace(fields["cidr"])
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
				if ui.blacklist.TryAddWithEnabled(n, enabledBool) {
					// Instantly evict cached entries that contain the newly blacklisted IP
					invalidateBlacklist()
					log.Info("Successfully added IP/CIDR to response blacklist via WebUI/Batch", slog.String("cidr", n.String()), slog.Bool("enabled", enabledBool))
					return http.StatusOK, nil
				}
				log.Warn("Failed to add IP/CIDR to blacklist: already exists", slog.String("cidr", n.String()))
				return http.StatusConflict, errors.New("IP/CIDR already exists")
			}
			log.Warn("Failed to add IP/CIDR to blacklist: invalid format", slog.String("input", cidrStr))
			return http.StatusBadRequest, errors.New("invalid IP or CIDR format")
		}
		log.Warn("Failed to add IP/CIDR to blacklist: empty input")
		return http.StatusBadRequest, errors.New("empty input")
	case "edit":
		oldCIDR := strings.TrimSpace(fields["old_cidr"])
		newCIDRStr := strings.TrimSpace(fields["cidr"])
		if oldCIDR == "" || newCIDRStr == "" {
			log.Warn("Failed to edit blacklist entry: old_cidr and cidr required",
				slog.String("old_cidr", oldCIDR), slog.String("cidr", newCIDRStr))
			return http.StatusBadRequest, errors.New("old_cidr and cidr required")
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
					return http.StatusBadRequest, errors.New("invalid IP or CIDR format")
				}
			}
		}
		if n == nil {
			log.Warn("Failed to edit blacklist entry: invalid IP/CIDR format", slog.String("input", newCIDRStr))
			return http.StatusBadRequest, errors.New("invalid IP or CIDR format")
		}
		// 1. Attempt to update the rule list (Source of Truth) first

		if err := ui.blacklist.TryEditWithEnabled(oldCIDR, n, enabledBool); err != nil {
			log.Warn("Failed to edit blacklist entry", wincoe.SafeErr(err),
				slog.String("old_cidr", oldCIDR), slog.String("new_cidr", n.String()))

			return http.StatusConflict, err
		}
		invalidateBlacklist()
		log.Info("Successfully edited response blacklist entry via WebUI/Batch", slog.String("old_cidr", oldCIDR), slog.String("new_cidr", n.String()), slog.Bool("enabled", enabledBool))
		return http.StatusOK, nil
	default:
		log.Warn("Response blacklist handler received unknown action", slog.String("action", action))
	} //switch
	return http.StatusBadRequest, fmt.Errorf("unknown action: %q", action)
}

// getCleanIP reliably extracts and normalizes the client IP, stripping ephemeral ports
// and collapsing all loopback variants to prevent rate-limit bypasses.
func getCleanIP(remoteAddr string, runFnOnError func(err error)) string {
	ipStr := remoteAddr

	// 1. Attempt to strip the port if present.
	// We ignore the error because a missing port (e.g., bare "localhost" or "192.168.1.1")
	// is perfectly valid depending on where the address originated.
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		ipStr = host
	} else if strings.HasPrefix(ipStr, "[") && strings.HasSuffix(ipStr, "]") {
		// Bracketed IPv6 literal with no port (e.g. "[fe80::1]"): SplitHostPort
		// requires a port and fails on this form, and net.ParseIP does not
		// understand the surrounding brackets either. Strip them manually so
		// this still resolves to a real IP below (and loopback variants still
		// collapse to "localhost"), instead of silently falling through to the
		// raw bracketed string and fracturing rate-limiter IP tracking.
		ipStr = ipStr[1 : len(ipStr)-1]
	}

	// 2. Fast-path for "localhost" (either passed bare or extracted from "localhost:port")
	if strings.EqualFold(ipStr, "localhost") {
		return "localhost"
	}

	// 3. Parse as a strict IP literal
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		// Only warn if it's neither "localhost" nor a valid IP literal (e.g., unexpected garbage)
		runFnOnError(fmt.Errorf("getCleanIP received unparseable IP or it's a hostname %q (original: %q), using it as is then", ipStr, remoteAddr))
		return ipStr // Fallback to what we have
	}

	// 4. Collapse all loopback variants (127.x.x.x, ::1) to "localhost"
	if parsed.IsLoopback() {
		return "localhost"
	}

	// 5. Return the normalized IP string (standardizes IPv6 formatting)
	return parsed.String()
}

// GoSafe executes fn in a new goroutine, tracks it in the shutdown WaitGroup,
// and ensures async logs are flushed if the goroutine accidentally panics.
func (s *Server) GoSafe(fn func()) {
	s.shutdownWG.Add(1)
	go func() {
		defer s.shutdownWG.Done()

		// The panic catcher for this specific goroutine
		defer func() {
			if r := recover(); r != nil {
				// We have access to 's.rt' here to flush the logs
				s.rt.FlushLogsForShutdown()
				panic(r)
			}
		}()

		// Run the actual workload
		fn()
	}()
}

// recoverAndFlushLogs is a lightweight, untracked counterpart to Server.GoSafe
// for goroutines that must NOT be tracked in Server.shutdownWG: specifically
// FailoverSelector.Exchange's per-upstream probe/query goroutine and
// UpstreamManager.ForwardToDoH's own per-upstream goroutines (fastest-mode
// races and strict-mode fan-out). These are extremely hot, per-DNS-query-path
// goroutines, and at least the fastest-mode/healing-probe ones are designed
// to intentionally keep running after the call that spawned them already
// returned — tracking them in shutdownWG the way GoSafe does would make a
// graceful shutdown's Wait() block on work that can only finish after Wait()
// itself would need to return, i.e. a guaranteed deadlock, mirroring exactly
// the reasoning already recorded in todo.txt for why Server.watchKeys is a
// bare `go` statement instead of GoSafe.
//
// What this DOES still provide is GoSafe's other guarantee: since Go gives
// no way to stop an unrecovered panic in one goroutine from crashing the
// entire process, at least make sure any buffered-but-not-yet-written log
// lines (see asyncLogWriter) are flushed before that crash happens, instead
// of silently losing the very lines that would explain why it crashed. It
// recovers the panic, flushes logs via flushLogs, then re-panics
// immediately — the process still terminates exactly as it did before this
// helper existed.
//
// flushLogs may be nil (e.g. tests constructing a FailoverSelector or
// UpstreamManager directly without a full Runtime); a nil flush function is
// simply skipped, matching this codebase's other nil-safety conventions.
//
// Call this as the very FIRST deferred statement in the goroutine (so it's
// registered before any other defers and thus runs LAST during a panic
// unwind), so it catches a panic from anywhere else in that goroutine,
// including from its own other deferred cleanup.
func recoverAndFlushLogs(flushLogs func()) {
	if r := recover(); r != nil {
		if flushLogs != nil {
			flushLogs()
		}
		panic(r)
	}
}

// getValidBcryptCost enforces the boundaries for bcrypt cost in a DRY manner.
func getValidBcryptCost(cost, fallback int) int {
	if cost < bcrypt.MinCost { //4
		return max(bcrypt.MinCost, fallback) // bcrypt.MinCost //
	}
	if cost > bcrypt.MaxCost { //31
		return bcrypt.MaxCost
	}
	return cost
}

// clampBcryptCostField wraps the bounding math for sanitizeAndValidateConfig.
func clampBcryptCostField(log *slog.Logger, tag string, resolved, raw *int, defaultCost int) bool {
	was := *resolved
	valid := getValidBcryptCost(was, defaultCost)
	if was != valid {
		*resolved = valid
		*raw = valid
		log.Warn(tag+" clamped to valid bounds", slog.Int("was", was), slog.Int("clamp", valid))
		return true
	}
	return false
}

var initialCWD string

func init() {
	var err error
	initialCWD, err = os.Getwd()
	if err != nil {
		// Fallback to current directory if os.Getwd() fails for any reason
		initialCWD = "."
	}
}

func spawnRestartProcess(log *slog.Logger, hideConsole bool, logDirToUseDuringStartupOfNewProcess, logFileToUseDuringStartupOfNewProcess string) {
	rawExe, err := os.Executable()
	if err != nil {
		if log != nil {
			log.Error("Auto-restart failed: could not get executable path", wincoe.SafeErr(err))
		}
		return
	}
	// 2. Resolve absolute path safely with explicit error fallback
	exe, err := filepath.Abs(rawExe)
	if err != nil {
		if log != nil {
			log.Warn("Auto-restart warning: could not determine absolute path, falling back to raw path",
				slog.String("raw_exe", rawExe),
				wincoe.SafeErr(err),
			)
		}
		exe = rawExe
	}
	// Sanitize path for defensive filesystem handling
	exe = filepath.Clean(exe)

	// Determine if the OLD process will pause for a keypress
	willPause := wincoe.HasConsole()

	// Forward original arguments so any flags passed via CLI are preserved
	// #nosec G702 G204 -- Self-restart: exe is derived from os.Executable() and args are original CLI arguments
	cmd := exec.Command(exe, os.Args[1:]...)
	//If you don't explicitly assign anything to cmd.Stdout, cmd.Stderr, and cmd.Stdin in the parent, Go defaults to connecting them to the null device (NUL).
	//remember any possible file redirects
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Preserve the exact working directory the user had when they
	// originally launched the app (e.g., project root), rather than .\bin\
	cmd.Dir = initialCWD

	// Inject clone flag to handle file-lock grace period on boot, and pass
	// the log directory/file to use during the new process's own bootstrap
	// phase (see peekBootstrapLogSettings's doc comment for why passing the
	// directory explicitly, not just the filename, matters here).
	env := os.Environ()
	env = append(env,
		"DNSBOLLOCKS_IS_RESTARTING=1",
		"DNSBOLLOCKS_BOOTSTRAP_LOG_DIR="+logDirToUseDuringStartupOfNewProcess,
		"DNSBOLLOCKS_BOOTSTRAP_LOG_FILE="+logFileToUseDuringStartupOfNewProcess,
	)

	// --- NEW: Deterministic Sync Event ---
	syncEventName := fmt.Sprintf("Local\\DNSBollocks_FlushSync_%d", os.Getpid())
	if eventNamePtr, err := windows.UTF16PtrFromString(syncEventName); err == nil {
		// CreateEvent(security, manualReset, initialState, name)
		if hEvent, err := windows.CreateEvent(nil, uint32(1), uint32(0), eventNamePtr); err == nil {
			atomic.StoreUintptr(&flushSyncEvent, uintptr(hEvent))
		}
	}
	// -------------------------------------

	// // Only pass the Parent PID to block the child if the parent is actually going to exit instantly
	// if willPause {
	// 	// Only pass the Sync Event to block the child if the parent is actually going to pause
	// 	env = append(env,
	// 		//"DNSBOLLOCKS_NO_WAIT=1",
	// 		"DNSBOLLOCKS_SYNC_EVENT="+syncEventName,
	// 	)
	// } else {
	// 	//TODO: we can/should pass the old pid unconditionally because then we can check if it's gone if sync event is not existing!
	// 	env = append(env, fmt.Sprintf("DNSBOLLOCKS_PARENT_PID=%d", os.Getpid()))
	// }

	// Unconditionally pass both the Sync Event and the Parent PID.
	// This enables the child's dual-fallback synchronization strategy regardless
	// of whether this parent process plans to pause or exit instantly.
	env = append(env,
		"DNSBOLLOCKS_SYNC_EVENT="+syncEventName,
		fmt.Sprintf("DNSBOLLOCKS_PARENT_PID=%d", os.Getpid()),
	)
	cmd.Env = env
	// cmd.Env = append(os.Environ(),
	// 	"DNSBOLLOCKS_IS_RESTARTING=1",
	// 	"DNSBOLLOCKS_BOOTSTRAP_LOG_FILE="+logFileToUseDuringStartupOfNewProcess,
	// 	fmt.Sprintf("DNSBOLLOCKS_PARENT_PID=%d", os.Getpid()),
	// )

	// 6. Set process creation flags based on hide_console setting
	var flags uint32
	if hideConsole {
		flags = windows.DETACHED_PROCESS
	} else {
		flags = windows.CREATE_NEW_CONSOLE
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: flags,
	}

	if log != nil {
		log.Info("Spawning new process for auto-restart...",
			slog.String("exe", exe),
			slog.String("cwd", initialCWD),
			slog.String("log_dir", logDirToUseDuringStartupOfNewProcess),
			slog.String("log_file", logFileToUseDuringStartupOfNewProcess),
			slog.Bool(configKeyNameForHideConsole, hideConsole),
			slog.Bool("parent_will_pause", willPause),
		)
	}

	// 7. Spawn child process
	if err := cmd.Start(); err != nil {
		if log != nil {
			log.Error("Auto-restart failed: could not start new process", wincoe.SafeErr(err))
		}
		return
	}

	if !willPause {
		skipInteractivePause.Store(true) // Bypass "Press any key to exit..." so this old process dies instantly
	}

	// 8. Safely release process handle and handle potential release errors
	if cmd.Process != nil {
		if log != nil {
			log.Debug("New process spawned successfully", slog.Int("new_pid", cmd.Process.Pid))
		}
		// Detach so the child doesn't become a zombie
		if err := cmd.Process.Release(); err != nil && log != nil {
			log.Warn("Failed to release handle for spawned process",
				slog.Int("pid", cmd.Process.Pid),
				wincoe.SafeErr(err),
			)
		}
	}
} //spawn

func (s *Server) issueAutoRestart() {
	s.autoRestart.Store(true)
	// Asynchronously trigger shutdown to let the current HTTP request (if triggered via WebUI) finish returning.
	go func() {
		time.Sleep(500 * time.Millisecond)
		s.shutdown(0) // Clean exit
	}()
}

// EnsureConsoleHandles checks if a console window is present but standard handles
// are invalid (e.g., when spawned from a DETACHED_PROCESS with CREATE_NEW_CONSOLE).
// If so, it re-binds os.Stdout, os.Stderr, and os.Stdin to CONOUT$ and CONIN$.
// It returns a joined error if any of the recovery steps fail. Use errors.Is() to check.
func EnsureConsoleHandles() error {
	// If no console window is allocated to this process, there's nothing to attach to
	// "[RESOLVED FIXME 4]: GetConsoleWindow is bound with CheckNone; it naturally returns 0 and does not panic." - Gemini 3.1 Pro Extended Thinking (refused to "fix" it, like that)
	if wincoe.GetConsoleWindow() == 0 { //FIXME: this can fail at least in theory, ie. panic2() and use os.Stderr to print the fail!
		return fmt.Errorf("no console allocated, no handles to ensure")
	}

	var errs []error

	/*
		Behavior Matrix:

		Launch / Execution State,GetFileType,GetConsoleMode,Action Taken,Result
		Normal Terminal (cmd / PowerShell),FILE_TYPE_CHAR,Succeeds,Stream kept intact,Logs display in terminal window
		File Redirection (> log.txt),FILE_TYPE_DISK,Fails (File),Stream kept intact,Logs continue writing to log.txt across restarts
		Pipe Redirection (| tee),FILE_TYPE_PIPE,Fails (Pipe),Stream kept intact,Pipe stays open across restarts
		Unattached / WebUI spawned,FILE_TYPE_CHAR or UNKNOWN,Fails (NUL),Repaired via CONOUT$ / CONIN$,Logs print cleanly to the new console window
	*/

	// 1. Repair STDOUT
	hOut, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	// var outMode uint32
	// Check if the handle is 0, invalid, OR not attached to a console buffer
	if err != nil || !isStreamValidOrRedirected(hOut) { // || hOut == 0 || hOut == windows.InvalidHandle || windows.GetConsoleMode(hOut, &outMode) != nil {
		if fOut, openErr := os.OpenFile("CONOUT$", os.O_RDWR, 0); openErr != nil {
			errs = append(errs, fmt.Errorf("open CONOUT$ for stdout failed: %w", openErr))
		} else {
			if setErr := windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, windows.Handle(fOut.Fd())); setErr != nil {
				errs = append(errs, fmt.Errorf("SetStdHandle for stdout failed: %w", setErr))
			}
			os.Stdout = fOut
		}
	}

	// 2. Repair STDERR
	hErr, err := windows.GetStdHandle(windows.STD_ERROR_HANDLE)
	// var errMode uint32
	if err != nil || !isStreamValidOrRedirected(hErr) { //|| hErr == 0 || hErr == windows.InvalidHandle || windows.GetConsoleMode(hErr, &errMode) != nil {
		if fErr, openErr := os.OpenFile("CONOUT$", os.O_RDWR, 0); openErr != nil {
			errs = append(errs, fmt.Errorf("open CONOUT$ for stderr failed: %w", openErr))
		} else {
			if setErr := windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(fErr.Fd())); setErr != nil {
				errs = append(errs, fmt.Errorf("SetStdHandle for stderr failed: %w", setErr))
			}
			os.Stderr = fErr
		}
	}

	// 3. Repair STDIN
	hIn, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE)
	// var inMode uint32
	if err != nil || !isStreamValidOrRedirected(hIn) { // || hIn == 0 || hIn == windows.InvalidHandle || windows.GetConsoleMode(hIn, &inMode) != nil {
		if fIn, openErr := os.OpenFile("CONIN$", os.O_RDWR, 0); openErr != nil {
			errs = append(errs, fmt.Errorf("open CONIN$ for stdin failed: %w", openErr))
		} else {
			if setErr := windows.SetStdHandle(windows.STD_INPUT_HANDLE, windows.Handle(fIn.Fd())); setErr != nil {
				errs = append(errs, fmt.Errorf("SetStdHandle for stdin failed: %w", setErr))
			}
			os.Stdin = fIn
		}
	}

	if len(errs) > 0 {
		// Wrapping errors.Join satisfies wrapcheck without needing a //nolint comment
		return fmt.Errorf("failed to ensure console handles: %w", errors.Join(errs...))
	}

	return nil
}

// isStreamValidOrRedirected checks if a standard handle is attached to a real console
// OR has been intentionally redirected by the user to a file or pipe.
func isStreamValidOrRedirected(h windows.Handle) bool {
	if h == 0 || h == windows.InvalidHandle {
		return false
	}

	fileType, err := windows.GetFileType(h)
	if err != nil {
		return false
	}

	// 1. User redirected to a file on disk (>) or a pipe (|) -> KEEP IT
	if fileType == windows.FILE_TYPE_DISK || fileType == windows.FILE_TYPE_PIPE {
		return true
	}

	// 2. Character device (CONOUT$, CONIN$, NUL)
	if fileType == windows.FILE_TYPE_CHAR {
		var mode uint32
		// If GetConsoleMode succeeds, it's a real interactive console window
		if err := windows.GetConsoleMode(h, &mode); err == nil {
			return true
		}
	}

	// 3. Otherwise, it's NUL or an orphaned handle -> REPAIR IT
	return false
}

// flushSyncEvent holds a windows.Handle used to signal a spawned child
// process that this parent process has finished flushing its logs.
var flushSyncEvent uintptr

func (ui *AdminUI) csrfTokenHandler(w http.ResponseWriter, r *http.Request) {
	const allowedMethods = "GET, HEAD, OPTIONS"
	if writeAllowHeaderResponse(w, r, allowedMethods) {
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		ui.rejectUnsupportedMethod(w, r, allowedMethods)
		return
	}

	// csrfMiddleware (which wraps this handler via innerMux, ahead of it in
	// the SetupRoutes chain) already resolved-or-minted the token for this
	// exact request and stashed it in context. Reuse that instead of calling
	// getOrCreateCSRFToken() a second time here, which could otherwise emit
	// two conflicting Set-Cookie headers (and two different random tokens)
	// for the same cookie name whenever no valid cookie existed yet.
	token, ok := r.Context().Value(csrfTokenKey{}).(string)
	if !ok || token == "" {
		ui.getLogger().Error("BUG: csrfTokenHandler reached without a token in context; csrfMiddleware should always set one")
		token = ui.getOrCreateCSRFToken(w, r)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	if err := json.NewEncoder(w).Encode(map[string]string{
		"csrf_token": token,
	}); err != nil {
		ui.getLogger().Debug("Failed to write CSRF token response", wincoe.SafeErr(err))
	}
}

func (ui *AdminUI) csrfCookieName(r *http.Request) string {
	// The __Host- cookie name prefix (RFC 6265bis) forces the browser to
	// require Secure, Path=/, and no Domain attribute, and — crucially —
	// makes the cookie strictly host-locked: no other origin, including a
	// same-registrable-domain subdomain (e.g. via a subdomain XSS bug),
	// can ever set or override it. This only works when actually served
	// over HTTPS (the prefix requires Secure, which the browser also then
	// requires to accept the Set-Cookie at all), so fall back to an
	// unprefixed name on the plain-HTTP path.

	// Keep the cookie name decision in one place so middleware and any future
	// token-refresh endpoint use the exact same rule.
	if r.TLS != nil {
		return "__Host-csrf_token"
	}
	return "csrf_token"
}

func (ui *AdminUI) getOrCreateCSRFToken(w http.ResponseWriter, r *http.Request) string {
	// 1. Get or generate the CSRF cookie. A cookie is only trusted as
	// "the" token if it carries a valid HMAC signature under this
	// process's in-memory csrfSecret — see verifyCSRFToken's doc comment
	// for why blindly trusting an existing cookie value is a token
	// fixation vulnerability.

	cookieName := ui.csrfCookieName(r)

	// A cookie is only trusted if it verifies under the in-memory secret.
	cookie, err := r.Cookie(cookieName)
	if err == nil && cookie.Value != "" && verifyCSRFToken(cookie.Value, ui.csrfSecret) {
		return cookie.Value
	}

	token := newCSRFToken(ui.csrfSecret)

	http.SetCookie(w,
		//nolint:gosec // HttpOnly and SameSite are set; Secure is conditional on HTTPS support.
		&http.Cookie{
			Name:     cookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   r.TLS != nil,
		},
	)

	return token
}

type batchFailureResponse struct {
	Index    int    `json:"index"`
	ClientID string `json:"client_id,omitempty"`
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Error    string `json:"error"`
}

// applyTablesResponseVersions mirrors tableVersions on the client: the
// post-mutation optimistic-concurrency version token for each store (see
// tableVersionToken), which the client treats as an entirely opaque string
// — no numeric/string coercion needed on either side of the round trip.
type applyTablesResponseVersions struct {
	Rules          string `json:"rules"`
	Hosts          string `json:"hosts"`
	Blacklist      string `json:"blacklist"`
	QueryBlocklist string `json:"query_blocklist"`
}

type applyTablesResponse struct {
	OK                bool                        `json:"ok"`
	Applied           []string                    `json:"applied_client_ids,omitempty"`
	Failed            []batchFailureResponse      `json:"failed,omitempty"`
	Versions          applyTablesResponseVersions `json:"versions"`
	PersistenceFailed bool                        `json:"persistence_failed,omitempty"`
	Error             string                      `json:"error,omitempty"`
}

// queryBlockCategoryBlock/queryBlockCategoryExcept are used as the map keys
// in Server.queryBlocklistStore (a *RuleStore reused verbatim; see that
// field's doc comment) in place of DNS record types, since query-blocklist
// patterns apply regardless of query type.
const (
	queryBlockCategoryBlock  = "block"
	queryBlockCategoryExcept = "except"
)

// queryBlockCategories lists the two valid categories in a stable, UI-friendly order.
var queryBlockCategories = []string{queryBlockCategoryBlock, queryBlockCategoryExcept}

func validQueryBlockCategory(c string) bool {
	return c == queryBlockCategoryBlock || c == queryBlockCategoryExcept
}

// Action strings used for logQuery/UpstreamState.Strategy when a query is
// blocked by this feature; see QueryActionANSI in platform_windows.go for
// their console colors.
const (
	queryBlockedLocalSTR    = "blocked_query_blocklist_local"
	queryBlockedExternalSTR = "blocked_query_blocklist_external"
)

// ExternalHostsBlocklistSource is the read-only, exact-hostname block-set
// loaded from Config.QueryBlocklistExternalHostsFile (see
// Server.loadExternalQueryBlocklist). dnsbollocks never writes to the
// underlying file; this struct is an immutable snapshot swapped wholesale
// via Server.externalBlocklist on every (re)load, so the file itself can be
// replaced/upgraded independently (e.g. a newer StevenBlack Hosts release)
// without any dnsbollocks-side migration or stale-entry carryover.
//
// A nil *ExternalHostsBlocklistSource (the zero atomic.Pointer default,
// before the very first load) is treated identically to "not configured":
// Contains is safe to call on it and always returns false.
type ExternalHostsBlocklistSource struct {
	hosts map[string]struct{}

	// Path is the cleaned path this source was loaded from ("" if
	// query_blocklist_external_hosts_file is unset/disabled).
	Path string
	// LoadedAt is when this snapshot was successfully built. Zero if the
	// load failed (see LoadError) or nothing is configured.
	LoadedAt time.Time
	// FileModTime is the on-disk hosts file's own last-modified timestamp,
	// as reported by the filesystem — distinct from LoadedAt (which is when
	// dnsbollocks itself last read the file into memory). This lets an
	// operator see when the underlying file (e.g. a StevenBlack Hosts
	// download) was actually last updated/downloaded, independent of how
	// recently dnsbollocks happened to reload it. Zero if the stat failed
	// or nothing is configured.
	FileModTime time.Time
	// HostCount is len(hosts), exposed for the WebUI without leaking the map itself.
	HostCount int
	// MalformedLines counts lines skipped for not matching the expected
	// "<ip> <host> [alias...]" hosts-file syntax.
	MalformedLines int
	// NonStandardIPWarnings counts lines whose mapping IP was neither
	// 0.0.0.0 nor ::. Those lines are deliberately ignored for blocking
	// (their hostnames are never added to the block set) so ordinary
	// hosts-file loopback/broadcast entries (127.0.0.1 localhost, ::1
	// localhost, 255.255.255.255 broadcasthost, …) never false-positive.
	// They are still counted and logged as a warning because a non-
	// unspecified IP is unusual for a pure blocklist-style hosts file and
	// may indicate the file isn't what the operator thinks it is.
	NonStandardIPWarnings int
	// LoadError is the last load attempt's error, if any. Non-empty means
	// this layer is effectively disabled (hosts is empty or stale from a
	// previous successful load) until the underlying issue is fixed and the
	// config is reloaded.
	LoadError string
}

// Contains reports whether domain (already normalized: lowercased, no
// trailing dot, punycode-encoded — exactly what checkQueryBlocklist's caller
// already has) is present in the external blocklist source.
func (src *ExternalHostsBlocklistSource) Contains(domain string) bool {
	if src == nil || len(src.hosts) == 0 {
		return false
	}
	_, ok := src.hosts[domain]
	return ok
}

// externalHostsSearchDefaultMaxResults / externalHostsSearchHardCapMaxResults
// bound the "extmax" query parameter accepted by the /query-blocklist page's
// external hosts-file search box (see parseExternalHostsSearchParams),
// mirroring parseLogRotationParams's identical default-then-hard-cap pattern
// for the /logs* pages' "maxrot" parameter.
const (
	externalHostsSearchDefaultMaxResults = 100
	externalHostsSearchHardCapMaxResults = 2000
)

// SearchHosts returns up to maxResults hostnames from src whose stored
// ASCII/punycode form OR human-readable Unicode display form contains query
// as a case-insensitive substring, along with the FULL match count (which
// may exceed len(matches) when capped by maxResults, letting callers report
// "showing X of Y matches"). An empty (after trimming) query intentionally
// matches nothing and returns (nil, 0): the external source can hold
// hundreds of thousands of entries (e.g. StevenBlack Hosts), so scanning and
// sorting the entire set on every /query-blocklist page view — even when the
// operator hasn't typed anything to search for — would be wasted work on a
// page that's otherwise a cheap, mostly-static read.
//
// Matches are returned in a stable, sorted (ascending) order so repeated
// identical searches always return the same page of results; Go map
// iteration order is otherwise randomized on every call.
//
// Safe to call on a nil src or one with no hosts loaded (returns nil, 0).
func (src *ExternalHostsBlocklistSource) SearchHosts(query string, maxResults int) (matches []string, total int) {
	if src == nil || len(src.hosts) == 0 {
		return nil, 0
	}
	queryLower := strings.ToLower(strings.TrimSpace(query))
	if queryLower == "" {
		return nil, 0
	}
	if maxResults <= 0 {
		maxResults = externalHostsSearchDefaultMaxResults
	}

	var all []string
	for host := range src.hosts {
		display, _ := punycodeDecodePatternForDisplay(host)
		if strings.Contains(strings.ToLower(host), queryLower) || strings.Contains(strings.ToLower(display), queryLower) {
			all = append(all, host)
		}
	}
	sort.Strings(all)

	total = len(all)
	if total > maxResults {
		all = all[:maxResults]
	}
	return all, total
}

// loadExternalQueryBlocklist (re)loads the read-only external hosts-file
// configured via Config.QueryBlocklistExternalHostsFile into
// s.externalBlocklist, replacing any previously loaded snapshot wholesale.
//
// This never fails fatally: an unreadable, missing, or malformed file logs
// clearly (at Error/Warn level, and via the stored LoadError, surfaced on
// the /query-blocklist WebUI page) and simply leaves this layer disabled
// (Contains always returns false) rather than taking down DNS resolution
// entirely over an external file dnsbollocks doesn't own — mirrors the
// "graceful degradation over a hard fatal exit" reasoning AdminUI.
// logPersistFailure documents elsewhere in this codebase. Individual
// malformed lines are skipped with a warning rather than aborting the whole
// file, since a single bad line in a large community-maintained blocklist
// (StevenBlack Hosts etc.) is common and should never make the rest of a
// multi-hundred-thousand-line file useless.
//
// Callers must hold s.tableMutationMu for the duration of this call, purely
// for consistency with the other loadDependentStores members — this
// particular source is never mutated by any WebUI handler, so there's no
// actual write-race to close here, but keeping every dependent-store load
// under the same lock avoids having to reason about a partial exception.
func (s *Server) loadExternalQueryBlocklist() {
	cfg := s.getConfig()
	log := s.getLogger()
	defer s.flushDNSCache() // see invalidateCacheForBlacklistedIPs's doc comment for why a full flush is simplest/safest here

	rawPath := strings.TrimSpace(cfg.QueryBlocklistExternalHostsFile)
	if rawPath == "" {
		s.externalBlocklist.Store(&ExternalHostsBlocklistSource{})
		return
	}
	path := filepath.Clean(rawPath)

	f, err := os.Open(path)
	if err != nil {
		log.Error("Failed to open external query-blocklist hosts file; this block-source layer is disabled until fixed",
			slog.String("path", path), wincoe.SafeErr(err))
		s.externalBlocklist.Store(&ExternalHostsBlocklistSource{Path: path, LoadError: err.Error()})
		return
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			log.Debug("failed to close external query-blocklist hosts file", wincoe.SafeErr(closeErr))
		}
	}()

	// Capture the file's own last-modified timestamp (distinct from
	// LoadedAt below) so the WebUI can show when the underlying file was
	// actually last updated/downloaded, not merely when dnsbollocks last
	// read it. A stat failure here is non-fatal: we already have the file
	// open and readable, so just proceed without that timestamp.
	var fileModTime time.Time
	if fi, statErr := f.Stat(); statErr == nil {
		fileModTime = fi.ModTime()
	} else {
		log.Warn("Failed to stat external query-blocklist hosts file for its modification time",
			slog.String("path", path), wincoe.SafeErr(statErr))
	}

	hosts := make(map[string]struct{})
	var malformed, nonStandardIP int
	scanner := bufio.NewScanner(f)
	const maxCapacity = 1024 * 1024 // 1MB; generous for even very long hosts-file lines.
	lineBuf := make([]byte, 4*1024)
	scanner.Buffer(lineBuf, maxCapacity)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx] // '#' starts a comment through end-of-line, even mid-line.
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			malformed++
			log.Warn("Malformed line in external query-blocklist hosts file; expected '<ip> <host> [alias...]', skipping",
				slog.String("path", path), slog.Int("line", lineNum), slog.String("content", line))
			continue
		}

		ip := net.ParseIP(fields[0])
		if ip == nil {
			malformed++
			log.Warn("Malformed line in external query-blocklist hosts file (first field is not a valid IP address), skipping",
				slog.String("path", path), slog.Int("line", lineNum), slog.String("content", line))
			continue
		}
		// Only the unspecified address (0.0.0.0 / ::) is the conventional
		// blocklist signal in hosts-style blocklists (StevenBlack Hosts etc.).
		// Any other mapping IP is treated as a real hosts override, not a
		// block: we count/log it and skip the line entirely so entries like
		// "127.0.0.1 localhost", "::1 localhost", "255.255.255.255 broadcasthost"
		// never false-positive-block. Intentional local IP answers belong in
		// hosts_file / HostStore, not this read-only block layer.
		if !ip.IsUnspecified() {
			nonStandardIP++
			log.Warn("Non-standard mapping IP in external query-blocklist hosts file (expected 0.0.0.0 or ::); "+
				"line ignored for blocking — only unspecified-IP(ie. 0.0.0.0 or ::) lines contribute hostnames to the block set",
				slog.String("path", path), slog.Int("line", lineNum), slog.String("ip", fields[0]))
			continue
		}

		for _, host := range fields[1:] {
			normalized := NormalizeDomain(host)
			if normalized == "" {
				continue
			}
			encoded, _, encErr := punycodeEncodePattern(normalized)
			if encErr != nil {
				malformed++
				log.Warn("Skipping unencodable hostname in external query-blocklist hosts file",
					slog.String("path", path), slog.Int("line", lineNum), slog.String("host", normalized), wincoe.SafeErr(encErr))
				continue
			}
			hosts[encoded] = struct{}{}
		}
	}

	if scanErr := scanner.Err(); scanErr != nil {
		log.Error("Error while scanning external query-blocklist hosts file; results are incomplete/stale until the next successful reload",
			slog.String("path", path), wincoe.SafeErr(scanErr))
		s.externalBlocklist.Store(&ExternalHostsBlocklistSource{Path: path, LoadError: scanErr.Error()})
		return
	}

	s.externalBlocklist.Store(&ExternalHostsBlocklistSource{
		hosts:                 hosts,
		Path:                  path,
		LoadedAt:              time.Now(),
		FileModTime:           fileModTime,
		HostCount:             len(hosts),
		MalformedLines:        malformed,
		NonStandardIPWarnings: nonStandardIP,
	})

	log.Info("Loaded external query-blocklist hosts file",
		slog.String("path", path), slog.Int("host_count", len(hosts)),
		slog.Int("malformed_lines", malformed), slog.Int("non_standard_ip_lines", nonStandardIP))
}

// checkQueryBlocklist evaluates the two-layer query blocklist (see
// Config.QueryBlocklistFile and Config.QueryBlocklistExternalHostsFile) for
// domain (already normalized: lowercased, no trailing dot, punycode-encoded
// — exactly what handleDNSQuery already has at its call site) and reports
// whether it is blocked.
//
// Layer precedence:
//  1. A local "block" pattern in the mutable override file always blocks,
//     regardless of the external source or the "except" rules below.
//  2. Otherwise, an exact-hostname match in the read-only external hosts
//     file blocks UNLESS a local "except" pattern also matches domain, in
//     which case the external-source block is cancelled.
//
// An "except" match ONLY cancels an external-source block; it has no effect
// on a local "block" match (layer 1), and — critically — it never makes the
// query "allowed" on its own: the ordinary whitelist/default-policy
// decision made afterward in handleDNSQuery still applies in full.
//
// Safe to call with a nil s.queryBlocklistStore and/or a never-loaded
// s.externalBlocklist (both simply behave as "nothing configured, never
// blocks"), so test-constructed *Server values that bypass NewServer don't
// need to wire these up.
func (s *Server) checkQueryBlocklist(domain string) (reason, matchedID string, blocked bool) {
	if s.queryBlocklistStore != nil {
		if id, ok := s.queryBlocklistStore.MatchForType(queryBlockCategoryBlock, domain); ok {
			return queryBlockedLocalSTR, id, true
		}
	}
	if s.externalBlocklist.Load().Contains(domain) {
		if s.queryBlocklistStore != nil {
			if _, ok := s.queryBlocklistStore.MatchForType(queryBlockCategoryExcept, domain); ok {
				return "", "", false
			}
		}
		return queryBlockedExternalSTR, "", true
	}
	return "", "", false
}

// loadQueryBlocklist loads the dnsbollocks-owned, mutable query-blocklist
// override file (see Config.QueryBlocklistFile) into s.queryBlocklistStore.
// Shares its on-disk shape, normalization, and validation rules with the
// whitelist (see loadRuleStoreFile's doc comment in platform_windows.go);
// "block"/"except" are used as the map keys here instead of DNS record types.
//
// Callers must hold s.tableMutationMu for the duration of this call — see
// loadDependentStores's doc comment for why.
func (s *Server) loadQueryBlocklist() error {
	return s.loadRuleStoreFile(s.queryBlocklistStore, s.getConfig().QueryBlocklistFile, "query blocklist")
}

func (s *Server) saveQueryBlocklist() error {
	return s.saveRuleStoreFile(s.queryBlocklistStore, s.getConfig().QueryBlocklistFile, "query blocklist")
}

// ═══════════════════════════════════════════════════════════════════════
// WebUI
// ═══════════════════════════════════════════════════════════════════════

// QueryBlockRuleView is the /query-blocklist page's per-row template view.
type QueryBlockRuleView struct {
	Category          string
	ID                string
	Pattern           string
	Enabled           bool
	ModifiedAtDisplay string
}

// ExternalBlocklistView is the /query-blocklist page's read-only summary of
// the external hosts-file source (see ExternalHostsBlocklistSource).
type ExternalBlocklistView struct {
	Configured            bool
	Path                  string
	LoadedAt              string
	FileModTimeDisplay    string
	HostCount             int
	MalformedLines        int
	NonStandardIPWarnings int
	LoadError             string
}

func (ui *AdminUI) getExternalBlocklistView() ExternalBlocklistView {
	if ui.externalBlocklist == nil {
		return ExternalBlocklistView{}
	}
	src := ui.externalBlocklist.Load()
	if src == nil || src.Path == "" {
		return ExternalBlocklistView{}
	}
	loadedAt := ""
	if !src.LoadedAt.IsZero() {
		loadedAt = formatModifiedAt(src.LoadedAt)
	}
	fileModTimeDisplay := ""
	if !src.FileModTime.IsZero() {
		fileModTimeDisplay = formatModifiedAt(src.FileModTime)
	}
	return ExternalBlocklistView{
		Configured:            true,
		Path:                  src.Path,
		LoadedAt:              loadedAt,
		FileModTimeDisplay:    fileModTimeDisplay,
		HostCount:             src.HostCount,
		MalformedLines:        src.MalformedLines,
		NonStandardIPWarnings: src.NonStandardIPWarnings,
		LoadError:             src.LoadError,
	}
}

// ExternalHostBlockMatchView is the /query-blocklist page's per-row view for
// a search match against the external, read-only hosts-file source (see
// ExternalHostsBlocklistSource.SearchHosts).
type ExternalHostBlockMatchView struct {
	// Host is the ASCII/punycode form, submitted back as the "domain" field
	// for the except/un-except quick-action buttons.
	Host string
	// HostDisplay is the human-readable Unicode form (same as Host when not an IDN).
	HostDisplay string
	// Excepted reports whether an enabled, exact-pattern local "except" rule
	// currently exempts this host from the external-source block — mirrors
	// populateQueryBlocklistRowState's identical exact-pattern requirement
	// (see RuleStore.HasExactEnabledPattern's doc comment) so the toggle
	// button this drives never claims to control a rule it can't actually find.
	Excepted bool
	// LocallyBlocked reports whether an enabled local "block" pattern
	// (exact OR wildcard — mirroring checkQueryBlocklist's real precedence,
	// unlike Excepted's exact-only requirement) ALSO matches this host, in
	// which case it stays blocked regardless of Excepted: a local "block"
	// always wins over any "except" (see checkQueryBlocklist's doc comment).
	LocallyBlocked bool
}

// buildExternalHostMatches searches the currently-loaded external hosts-file
// source (see ExternalHostsBlocklistSource.SearchHosts) for query and
// resolves each match's current except/local-block state for display.
// Returns (nil, 0) if the external-hosts feature isn't wired up
// (ui.externalBlocklist == nil) or query is empty — see SearchHosts's doc
// comment for why an empty query intentionally matches nothing.
func (ui *AdminUI) buildExternalHostMatches(query string, maxResults int) (matches []ExternalHostBlockMatchView, total int) {
	if ui.externalBlocklist == nil {
		return nil, 0
	}
	hosts, total := ui.externalBlocklist.Load().SearchHosts(query, maxResults)
	if len(hosts) == 0 {
		return nil, total
	}
	matches = make([]ExternalHostBlockMatchView, len(hosts))
	for i, host := range hosts {
		display, _ := punycodeDecodePatternForDisplay(host)
		var excepted, locallyBlocked bool
		if ui.queryBlocklistStore != nil {
			excepted = ui.queryBlocklistStore.HasExactEnabledPattern(queryBlockCategoryExcept, host)
			_, locallyBlocked = ui.queryBlocklistStore.MatchForType(queryBlockCategoryBlock, host)
		}
		matches[i] = ExternalHostBlockMatchView{
			Host:           host,
			HostDisplay:    display,
			Excepted:       excepted,
			LocallyBlocked: locallyBlocked,
		}
	}
	return matches, total
}

// parseExternalHostsSearchParams extracts and validates the "extq"/"extmax"
// query parameters for the /query-blocklist page's external hosts-file
// search box, mirroring parseLogRotationParams's identical pattern for the
// /logs* pages' "rotated"/"maxrot" parameters.
func parseExternalHostsSearchParams(r *http.Request) (query string, maxResults int) {
	query = r.URL.Query().Get("extq")
	maxResults = externalHostsSearchDefaultMaxResults
	if raw := r.URL.Query().Get("extmax"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			maxResults = n
		}
	}
	if maxResults > externalHostsSearchHardCapMaxResults {
		maxResults = externalHostsSearchHardCapMaxResults
	}
	if maxResults < 1 {
		maxResults = 1
	}
	return query, maxResults
}

func (ui *AdminUI) queryBlocklistHandler(w http.ResponseWriter, r *http.Request) {
	const allowedMethods = "GET, HEAD, POST, OPTIONS"
	if writeAllowHeaderResponse(w, r, allowedMethods) {
		return
	}

	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		var snapshot map[string][]RuleEntry
		if ui.queryBlocklistStore != nil {
			snapshot = ui.queryBlocklistStore.Snapshot()
		}
		views := make([]QueryBlockRuleView, 0, len(snapshot[queryBlockCategoryBlock])+len(snapshot[queryBlockCategoryExcept]))
		for _, category := range queryBlockCategories {
			for _, rule := range snapshot[category] {
				displayPattern, _ := punycodeDecodePatternForDisplay(rule.Pattern)
				views = append(views, QueryBlockRuleView{
					Category:          category,
					ID:                rule.ID,
					Pattern:           displayPattern,
					Enabled:           rule.Enabled,
					ModifiedAtDisplay: formatModifiedAt(rule.ModifiedAt),
				})
			}
		}

		extQuery, extMaxResults := parseExternalHostsSearchParams(r)
		externalMatches, externalTotal := ui.buildExternalHostMatches(extQuery, extMaxResults)

		data := map[string]any{
			"QueryBlockRules":       views,
			"External":              ui.getExternalBlocklistView(),
			"ExternalSearchQuery":   extQuery,
			"ExternalSearchMax":     extMaxResults,
			"ExternalSearchHardCap": externalHostsSearchHardCapMaxResults,
			"ExternalSearchTotal":   externalTotal,
			"ExternalMatches":       externalMatches,
			"SuccessMessage":        r.URL.Query().Get("success"),
			"ErrorMessage":          r.URL.Query().Get("error"),
		}
		ui.renderTemplate(w, r, "query-blocklist", data)
		return
	}

	if r.Method == http.MethodPost {
		log := ui.getLogger()
		if ui.queryBlocklistStore == nil || ui.OnSaveQueryBlocklist == nil {
			log.Error("BUG: query-blocklist WebUI POST reached without queryBlocklistStore/OnSaveQueryBlocklist wired")
			http.Error(w, "query blocklist is not available in this environment", http.StatusServiceUnavailable)
			return
		}

		// Serialize against a concurrent config Reload's loadQueryBlocklist()
		// (or a concurrent WebUI mutation), exactly like rulesHandler.
		ui.tableMutationMu.Lock()
		defer ui.tableMutationMu.Unlock()

		// Quick except/un-except toggle for a host surfaced by the external
		// hosts-file search box (see buildExternalHostMatches): reuses the
		// exact same except-layer toggle the /blocks and /allows pages'
		// quick actions already use (see processQueryBlocklistQuickAction),
		// and the same generic AJAX form wiring (see js-block-action-form
		// in app.js and respondBlocksResult's doc comment).
		if action := r.FormValue("action"); action == "unblock_qb" || action == "reblock_qb" {
			raw := r.FormValue("domain")
			domainLowercased, displayDomain, sanitizeErr := sanitizeBlocksQuickActionDomain(raw)
			if sanitizeErr != nil {
				log.Warn("Invalid domain input submitted via external-hosts except toggle",
					slog.String("raw", raw), wincoe.SafeErr(sanitizeErr))
				respondBlocksResult(log, w, r, "/query-blocklist", false, http.StatusBadRequest, "Invalid domain format.", raw)
				return
			}
			successMessage, status, qbErr := ui.processQueryBlocklistQuickAction(action, domainLowercased, displayDomain, "")
			if qbErr != nil {
				respondBlocksResult(log, w, r, "/query-blocklist", false, status, qbErr.Error(), raw)
				return
			}
			if err := ui.OnSaveQueryBlocklist(); err != nil {
				respondBlocksResult(log, w, r, "/query-blocklist", false, http.StatusInternalServerError, ui.logPersistFailure("query blocklist", err).Error(), "")
				return
			}
			respondBlocksResult(log, w, r, "/query-blocklist", true, http.StatusOK, successMessage, "")
			return
		}

		fields := map[string]string{
			"delete":   r.FormValue("delete"),
			"toggle":   r.FormValue("toggle"),
			"edit":     r.FormValue("edit"),
			"id":       r.FormValue("id"),
			"category": r.FormValue("category"),
			"pattern":  r.FormValue("pattern"),
			"enabled":  r.FormValue("enabled"),
		}

		status, err := ui.processQueryBlockChange(fields, ui.OnInvalidatePattern)
		if err != nil {
			http.Error(w, err.Error(), status)
			return
		}

		if err := ui.OnSaveQueryBlocklist(); err != nil {
			redirectWithPersistFailure(w, r, "/query-blocklist", ui.logPersistFailure("query blocklist", err))
			return
		}
		http.Redirect(w, r, "/query-blocklist", http.StatusSeeOther)
		return
	}

	ui.rejectUnsupportedMethod(w, r, allowedMethods)
}

func (ui *AdminUI) processQueryBlockChange(fields map[string]string, invalidate func(pattern string)) (int, error) {
	log := ui.getLogger()

	category := fields["category"]

	if fields["delete"] == "1" {
		id := fields["id"]
		if id == "" || category == "" {
			log.Warn("Failed to delete query-blocklist rule: id and category required", slog.String("id", id), slog.String("category", category))
			return http.StatusBadRequest, errors.New("id and category required for delete")
		}
		if !validQueryBlockCategory(category) {
			log.Warn("Failed to delete query-blocklist rule: unknown category", slog.String("category", category))
			return http.StatusBadRequest, fmt.Errorf("unknown category %q", category)
		}
		if _, modified := sanitizeDomainInput(id); modified {
			log.Warn("Failed to delete query-blocklist rule: id contains illegal characters", slog.String("id", id))
			return http.StatusBadRequest, errors.New("id contains illegal characters")
		}
		pattern, err := ui.queryBlocklistStore.DeleteRule(category, id, log)
		if err != nil {
			log.Warn("Failed to delete query-blocklist rule: not found", slog.String("id", id), slog.String("category", category))
			return http.StatusNotFound, err
		}
		invalidate(pattern)
		log.Info("Deleted query-blocklist rule via WebUI/Batch",
			slog.String("id", id), slog.String("category", category), slog.String("pattern", pattern))
		return http.StatusOK, nil
	}

	if fields["toggle"] == "1" {
		id := fields["id"]
		if id == "" || category == "" {
			log.Warn("Failed to toggle query-blocklist rule: id and category required", slog.String("id", id), slog.String("category", category))
			return http.StatusBadRequest, errors.New("id and category required for toggle")
		}
		if !validQueryBlockCategory(category) {
			log.Warn("Failed to toggle query-blocklist rule: unknown category", slog.String("category", category))
			return http.StatusBadRequest, fmt.Errorf("unknown category %q", category)
		}

		var curEnabled bool
		found := false
		for _, rule := range ui.queryBlocklistStore.Snapshot()[category] {
			if rule.ID == id {
				curEnabled, found = rule.Enabled, true
				break
			}
		}
		if !found {
			log.Warn("Failed to toggle query-blocklist rule: not found", slog.String("id", id), slog.String("category", category))
			return http.StatusNotFound, errors.New("query-blocklist rule not found")
		}
		pattern, stillFound, changed := ui.queryBlocklistStore.SetEnabledByID(category, id, !curEnabled, log)
		if !stillFound {
			// Rare TOCTOU: deleted between the Snapshot() lookup above and here.
			log.Warn("Failed to toggle query-blocklist rule: disappeared mid-request", slog.String("id", id), slog.String("category", category))
			return http.StatusNotFound, errors.New("query-blocklist rule not found")
		}
		if changed {
			invalidate(pattern)
			log.Info("Toggled query-blocklist rule via WebUI",
				slog.String("id", id), slog.String("category", category), slog.Bool("enabled", !curEnabled))
		}
		return http.StatusOK, nil
	}

	// --- ADD / EDIT ---
	// isEdit is explicit (mirrors processRuleChange/processHostChange's edit
	// flag), rather than being inferred from whether "id" happens to be
	// non-empty, so a client bug that omits the edit flag can't silently
	// fall through to the wrong branch.
	isEdit := fields["edit"] == "1"
	patternNormalized := NormalizeDomain(fields["pattern"])
	id := fields["id"]
	enabledStr := fields["enabled"]
	enabledBool := enabledStr == "on" || enabledStr == "true" || enabledStr == "1"

	if !validQueryBlockCategory(category) {
		log.Warn("Failed to add/edit query-blocklist rule: unknown category", slog.String("category", category))
		return http.StatusBadRequest, fmt.Errorf("unknown category %q", category)
	}
	if patternNormalized == "" {
		log.Warn("Failed to add/edit query-blocklist rule: pattern required")
		return http.StatusBadRequest, errors.New("pattern required")
	}

	// Convert any Unicode (IDN) pattern (e.g. "café.com") into punycode/ASCII
	// before validation and storage; real DNS queries always arrive already
	// punycode-encoded, so patterns must be stored the same way to ever
	// match. displayPattern is kept only for a more readable conflict/error
	// message further below.
	displayPattern := patternNormalized
	encodedPattern, encErr := encodePatternOrErr(patternNormalized)
	if encErr != nil {
		log.Warn("Failed to add/edit query-blocklist rule: invalid unicode pattern", slog.String("pattern", displayPattern), wincoe.SafeErr(encErr))
		return http.StatusBadRequest, encErr
	}
	patternNormalized = encodedPattern

	if err := validateRulePattern(patternNormalized); err != nil {
		log.Warn("Failed to add/edit query-blocklist rule: invalid pattern", slog.String("pattern", patternNormalized), slog.String("pattern_idn", displayPattern), wincoe.SafeErr(err))
		return http.StatusBadRequest, fmt.Errorf("invalid pattern: %w", err)
	}

	if isEdit {
		if id == "" {
			log.Warn("Failed to edit query-blocklist rule: edit flag set but id is empty")
			return http.StatusBadRequest, errors.New("id required for edit")
		}
		if _, modified := sanitizeDomainInput(id); modified {
			log.Warn("Failed to edit query-blocklist rule: id contains illegal characters", slog.String("id", id))
			return http.StatusBadRequest, errors.New("id contains illegal characters")
		}
		_, oldPattern, err := ui.queryBlocklistStore.UpdateRule(id, category, patternNormalized, enabledBool, log)
		if err != nil {
			log.Warn("Failed to edit query-blocklist rule", wincoe.SafeErr(err),
				slog.String("id", id), slog.String("category", category),
				slog.String("old_pattern", oldPattern), slog.String("new_pattern", patternNormalized))
			if displayPattern != patternNormalized {
				return http.StatusConflict, fmt.Errorf("%w (as entered: %q)", err, displayPattern)
			}
			return http.StatusConflict, err
		}
		invalidate(oldPattern)
		if oldPattern != patternNormalized {
			invalidate(patternNormalized)
		}
		log.Info("Edited query-blocklist rule via WebUI/Batch",
			slog.String("id", id), slog.String("category", category),
			slog.String("new_pattern", patternNormalized), slog.String("new_pattern_idn", displayPattern),
			slog.String("old_pattern", oldPattern), slog.Bool("enabled", enabledBool))
		return http.StatusOK, nil
	}

	// --- ADD ---
	if id != "" {
		log.Warn("Failed to add query-blocklist rule: id was unexpectedly present without the edit flag", slog.String("id", id))
		return http.StatusBadRequest, errors.New("id must not be set when adding a new rule")
	}
	newID, err := ui.queryBlocklistStore.AddRule(category, patternNormalized, enabledBool, log)
	if err != nil {
		log.Warn("Failed to add query-blocklist rule", wincoe.SafeErr(err),
			slog.String("category", category), slog.String("pattern", patternNormalized), slog.String("pattern_idn", displayPattern))
		if displayPattern != patternNormalized {
			return http.StatusConflict, fmt.Errorf("%w (as entered: %q)", err, displayPattern)
		}
		return http.StatusConflict, err
	}
	invalidate(patternNormalized)
	log.Info("Added query-blocklist rule via WebUI/Batch",
		slog.String("category", category), slog.String("pattern", patternNormalized),
		slog.String("pattern_idn", displayPattern), slog.String("id", newID), slog.Bool("enabled", enabledBool))
	return http.StatusOK, nil
}

// respondFromCache serves a cached DNS response for an identical prior
// query, restoring the current query's ID and echoing its exact casing
// (see adjustResponseCaseToQuery's doc comment), and logs a cache-hit.
// Shared by every "serve this from the DNS cache" path in handleDNSQuery.
func (s *Server) respondFromCache(ctx context.Context, entry CacheEntry, reqMsg *dns.Msg, clientAddr, domain, qtype, matchedID string) *dns.Msg {
	resp := entry.Msg.Copy()
	resp.Id = reqMsg.Id
	// Echo the current query's casing onto the Question section and any Answer/Ns
	// owner names that directly answer it, since a cache entry may have been
	// populated by a differently-cased query for the same name.
	adjustResponseCaseToQuery(resp, reqMsg)
	ips := extractIPs(resp)
	s.logQuery(ctx, clientAddr, domain, qtype, cacheHit, matchedID, ips, resp, entry.State)
	return resp
}

// shouldSkipAAAARecentBlockEntry reports whether a blocked AAAA query for
// domain is expected, harmless noise that shouldn't clutter the WebUI's
// /blocks page: specifically, when cfg.AllowHTTPSIfAAllowed is enabled and an
// enabled A-type whitelist rule already allows the same domain. This mirrors
// the exact same "A rule implies allowed" convenience handleDNSQuery already
// applies to HTTPS queries (see Config.AllowHTTPSIfAAllowed's desc tag),
// extended here purely for display purposes: browsers/OS resolvers routinely
// query AAAA right alongside A, and once the A half of that pair is
// whitelisted, the AAAA half being blocked (because whitelist_mode still
// requires its own explicit AAAA rule, or the domain genuinely has no IPv6
// records) is not actionable information for the operator. This does NOT
// change actual DNS resolution/blocking behavior at all — the AAAA query is
// still blocked exactly as before — it only controls whether this specific
// block gets recorded in recentBlocks.
func (s *Server) shouldSkipAAAARecentBlockEntry(cfg *Config, qtype, domain string) bool {
	if qtype != "AAAA" || !cfg.AllowHTTPSIfAAllowed {
		return false
	}
	_, allowed := s.ruleStore.MatchForType("A", domain)
	return allowed
}

// blockAndCacheQuery records stats, generates a block response for reqMsg,
// logs it under the given action/matchedID/strategy, and — if
// cfg.BlockedResponseTTLSec > 0 — caches it under key so a repeat of the
// identical query is served from cache rather than regenerated. Shared by
// every "this query is blocked before ever reaching the upstream" path in
// handleDNSQuery (query blocklist, lack of an enabled whitelist rule) so
// they stay in sync.
//
// recordRecentBlock controls whether this block is also added to
// s.recentBlocks (surfaced on the WebUI's /blocks page); callers pass false
// for cases that should still count in stats/logs but shouldn't show up
// there as actionable noise — see shouldSkipAAAARecentBlockEntry's doc
// comment for the motivating case.
func (s *Server) blockAndCacheQuery(ctx context.Context, cfg *Config, cachee DNSCache, reqMsg *dns.Msg, clientAddr, domain, qtype, key, action, matchedID, strategy string, recordRecentBlock bool) *dns.Msg {
	s.blockedQueries.Add(1)
	if recordRecentBlock {
		s.recentBlocks.Record(domain, qtype, cfg.MaxRecentBlocks)
	}
	blocked := s.blockResponse(reqMsg)
	blockedState := UpstreamState{Strategy: strategy}
	s.logQuery(ctx, clientAddr, domain, qtype, action, matchedID, nil, blocked, blockedState)
	if cfg.BlockedResponseTTLSec > 0 {
		cachee.Set(key, CacheEntry{
			Msg:   blocked.Copy(),
			State: blockedState,
		}, time.Duration(cfg.BlockedResponseTTLSec)*time.Second)
	}
	return blocked
}

// quickToggleExactRule implements the shared "find-or-create an exact-pattern
// rule and flip it to the desired enabled state" logic used by the /blocks
// page's quick unblock/reblock controls — both for the whitelist layer
// (store=ui.ruleStore, typ=DNS record type) and for the query-blocklist
// "except" layer (store=ui.queryBlocklistStore, typ=queryBlockCategoryExcept).
// Both layers use the exact same convention: quick-unblock either flips an
// existing disabled rule back on, or creates a brand-new enabled rule if none
// existed yet; quick-reblock only ever disables an existing rule (never
// creates one, since "no rule" already means "not excepted/not whitelisted").
//
// wantEnabled=true is "unblock" (may create); wantEnabled=false is "reblock"
// (never creates — findOnlyOnReblock below governs that).
//
// Returns a human-readable outcome message and an error only for a genuine
// AddRule failure (which, given the enabled-lookup happened just before, and
// this all runs under tableMutationMu, should never actually happen — see the
// call site's existing panic2 for the identical invariant on the whitelist
// path already in place before this helper existed).
func quickToggleExactRule(store *RuleStore, typ, pattern, displayPattern string, wantEnabled bool, log *slog.Logger, thingLabel string) (message string, err error) {
	if wantEnabled {
		found, changed := store.SetEnabled(typ, pattern, true, log)
		switch {
		case found && changed:
			return fmt.Sprintf("Successfully unblocked (%s): activated existing paused rule for %s (%s).", thingLabel, displayPattern, typ), nil
		case found:
			return fmt.Sprintf("Rule for %s (%s) is already active (%s).", displayPattern, typ, thingLabel), nil
		}
		newID, addErr := store.AddRule(typ, pattern, true, log)
		if addErr != nil {
			return "", fmt.Errorf("quickToggleExactRule: AddRule unexpectedly failed for a pattern just confirmed absent (type=%q pattern=%q thing=%q): %w", typ, pattern, thingLabel, addErr)
		}
		_ = newID
		return fmt.Sprintf("Successfully unblocked (%s): added new active rule for %s (%s).", thingLabel, displayPattern, typ), nil
	}

	// reblock: never creates.
	found, changed := store.SetEnabled(typ, pattern, false, log)
	switch {
	case found && changed:
		return fmt.Sprintf("Successfully re-blocked (%s): paused rule for %s (%s).", thingLabel, displayPattern, typ), nil
	case found:
		return fmt.Sprintf("Rule for %s (%s) is already paused (%s).", displayPattern, typ, thingLabel), nil
	default:
		return "", fmt.Errorf("no active rule exists for %s (%s, %s) to re-block/pause", displayPattern, typ, thingLabel)
	}
}
