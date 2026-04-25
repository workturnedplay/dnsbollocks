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

package dnsbollocks

//import "dnsbollocks/internal/dnsbollocks"

import (
	"bytes"
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
	"sync/atomic"

	"fmt"
	"html/template"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"

	//"html"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"github.com/workturnedplay/wincoe"
	"golang.org/x/sys/windows"
	"golang.org/x/term"
	"golang.org/x/time/rate"
)

// Config holds the JSON configuration.
type Config struct {
	ListenDNS               string `json:"listen_dns"`                 // e.g., "127.0.0.1:53"
	ListenDoH               string `json:"listen_doh"`                 // e.g., "127.0.0.1:443"
	UIPort                  int    `json:"ui_port"`                    // 8080
	UpstreamURL             string `json:"upstream_url"`               // "https://9.9.9.9/dns-query"
	UpstreamRetriesPerQuery int    `json:"upstream_retries_per_query"` // e.g., 1 retry (and 1 first try implied, thus 2 total tries!) ie. how many retries are attempted per DNS query to upstream DoH if it fails!
	SNIHostname             string `json:"sni_hostname"`               // Optional ""
	BlockMode               string `json:"block_mode"`                 // "nxdomain", "drop", "ip_block"
	BlockIP                 string `json:"block_ip"`                   // "0.0.0.0"
	RateQPS                 int    `json:"rate_qps"`                   // 100
	CacheMinTTL             int    `json:"cache_min_ttl"`              // 300s
	CacheMaxEntries         int    `json:"cache_max_entries"`          // 10000
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
}

type LocalHostRule struct {
	Pattern string
	IPs     []net.IP
}

var (
	localHosts   []LocalHostRule
	localHostsMu sync.RWMutex
)

// Near the other globals (after Config definition)
var (
	responseBlacklist   []*net.IPNet // parsed and ready-to-use form
	responseBlacklistMu sync.RWMutex
)

// RuleEntry represents a whitelist rule.
type RuleEntry struct {
	ID      string `json:"id"`
	Pattern string `json:"pattern"`
	Enabled bool   `json:"enabled"`
}

// BlacklistFileFormat represents the strict on-disk structure of response_blacklist.json
type BlacklistFileFormat struct {
	ResponseBlacklist []string `json:"response_blacklist"`
}

// Call once during startup (inside loadConfig or after it)
func loadResponseBlacklist() error {
	blacklistFileName := config.BlacklistFile
	if blacklistFileName == "" {
		panic("dev. didn't set the default blacklist filename!")
	}
	blacklistFileName = filepath.Clean(config.BlacklistFile)

	var shouldSave bool = false
	var raw []string
	data, err := os.ReadFile(blacklistFileName)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("read blacklist %q: %w", blacklistFileName, err)
		} else {
			mainLogger.Warn("Blacklist file not found → using built-in defaults\n", slog.String("file", blacklistFileName))
			raw = DefaultResponseBlacklist() // see below
			shouldSave = true
		}
	} else {
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
		s := n.String()
		if _, exists := seen[s]; !exists {
			seen[s] = struct{}{}
			deduped = append(deduped, n)
		} else {
			fmt.Printf("blacklisted %q is duplicate, removing it", s)
			if !shouldSave {
				shouldSave = true
			}
		}
	}
	dups := len(parsed) - len(deduped)
	if dups > 0 {
		fmt.Printf("Removed %d duplicate CIDRs from blacklist file %q\n", len(parsed)-len(deduped), blacklistFileName)
		parsed = deduped
	}

	responseBlacklistMu.Lock()
	responseBlacklist = parsed
	responseBlacklistMu.Unlock()

	fmt.Printf("Loaded %d CIDR entries (%d were dups) from %q\n", len(responseBlacklist), dups, blacklistFileName)
	if shouldSave {
		if err := saveResponseBlacklist(); err != nil {
			return fmt.Errorf("failed to save blacklist file %q, err: %w", blacklistFileName, err)
		} else {
			fmt.Printf("Saved blacklist file %q\n", blacklistFileName)
		}
	}
	return nil
}

func saveResponseBlacklist() error {
	cidrs := GetResponseBlacklist()
	jsonFileContents := BlacklistFileFormat{
		ResponseBlacklist: cidrs,
	}
	data, err := json.MarshalIndent(jsonFileContents, "", "  ")
	if err != nil {
		return fmt.Errorf("blacklist marshal failed: %w", err)
	}

	blacklistFileName := config.BlacklistFile
	if blacklistFileName == "" {
		panic("bad coding: dev. didn't set the default blacklist filename!")
	}
	if err := os.WriteFile(blacklistFileName, data, 0600); err != nil {
		return fmt.Errorf("cannot save/write blacklist file %q: %w", blacklistFileName, err)
	} else {
		fmt.Printf("Saved blacklist file %q\n", blacklistFileName)
	}
	return nil
}

func loadLocalHosts() error {
	path := config.HostsFile
	if path == "" {
		panic("dev: didn't set the default hosts filename!")
	}
	//fmt.Printf("Path before:%s", path) // hmm why is it "." with quotes!
	path = filepath.Clean(path)

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		fmt.Printf("Hosts file %q not found → starting with empty local hosts\n", path)
		localHostsMu.Lock()
		localHosts = nil
		localHostsMu.Unlock()
		return saveLocalHosts() // creates empty default file
	}
	if err != nil {
		return fmt.Errorf("cannot read hosts file %q: %w", path, err)
	}

	var raw map[string][]string
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&raw); err != nil {
		return fmt.Errorf("failed to parse hosts file %q: %w", path, err)
	}

	var parsed []LocalHostRule
	for pat, ips := range raw {
		pat = strings.ToLower(pat) // normalize for matchPattern
		var netIPs []net.IP
		for _, ipStr := range ips {
			if ip := net.ParseIP(ipStr); ip != nil {
				netIPs = append(netIPs, ip)
			} else {
				mainLogger.Warn("Invalid IP in hosts file, skipping", slog.String("ip", ipStr), slog.String("pattern", pat))
			}
		}
		if len(netIPs) > 0 {
			parsed = append(parsed, LocalHostRule{Pattern: pat, IPs: netIPs})
		}
	}

	localHostsMu.Lock()
	localHosts = parsed
	localHostsMu.Unlock()

	fmt.Printf("Loaded %d host rules from %q\n", len(localHosts), path)
	return nil
}

func saveLocalHosts() error {
	localHostsMu.RLock()
	raw := make(map[string][]string)
	for _, rule := range localHosts {
		var ips []string
		for _, ip := range rule.IPs {
			ips = append(ips, ip.String())
		}
		raw[rule.Pattern] = ips
	}
	localHostsMu.RUnlock()

	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("hosts file marshal failed: %w", err)
	}
	if err := os.WriteFile(config.HostsFile, data, 0600); err != nil {
		return fmt.Errorf("cannot save/write hosts file %q: %w", config.HostsFile, err)
	}
	return nil
}

// func saveAndSetResponseBlacklist(cidrs []string) error {
// 	data, err := json.MarshalIndent(cidrs, "", "  ")
// 	if err != nil {
// 		return err
// 	}
// 	fname := config.BlacklistFile
// 	if fname == "" {
// 		panic("dev. didn't set the default blacklist filename!")
// 	}
// 	if err := os.WriteFile(fname, data, 0600); err != nil {
// 		return fmt.Errorf("cannot write blacklist file %q: %w", fname, err)
// 	}

// 	parsed := make([]*net.IPNet, 0, len(cidrs))
// 	for _, c := range cidrs {
// 		_, n, err := net.ParseCIDR(c)
// 		if err != nil {
// 			return err // should not happen if we just saved it
// 		}
// 		parsed = append(parsed, n)
// 	}

// 	responseBlacklistMu.Lock()
// 	responseBlacklist = parsed
// 	responseBlacklistMu.Unlock()
// 	return nil
// }

// Helper – returns current list (snapshot copy)
func GetResponseBlacklist() []string {
	responseBlacklistMu.RLock()
	defer responseBlacklistMu.RUnlock()

	out := make([]string, 0, len(responseBlacklist))
	for _, n := range responseBlacklist {
		out = append(out, n.String())
	}
	return out
}

// Helper – used in filterResponse / processRR
func IsBlockedIP(ip net.IP) bool {
	responseBlacklistMu.RLock()
	defer responseBlacklistMu.RUnlock()

	for _, n := range responseBlacklist {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func DefaultResponseBlacklist() []string {
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

func saveQueryWhitelist() error {
	ruleMutex.RLock()
	defer ruleMutex.RUnlock()

	data, err := json.MarshalIndent(whitelist, "", "  ")
	if err != nil {
		return fmt.Errorf("whitelist marshal failed: %w", err)
	}
	if err := os.WriteFile(config.WhitelistFile, data, 0600); err != nil {
		return fmt.Errorf("cannot save/write whitelist file %q: %w", config.WhitelistFile, err)
	}
	return nil
}

// Loads whitelist rules from dedicated file
func loadQueryWhitelist() error {
	path := config.WhitelistFile
	if path == "" {
		panic("dev. didn't set the default blacklist filename!")
	}
	path = filepath.Clean(config.WhitelistFile)

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		fmt.Printf("Whitelist file %q not found → starting with empty whitelist\n", path)
		func() {
			ruleMutex.Lock()
			defer ruleMutex.Unlock()
			whitelist = make(map[string][]RuleEntry)
		}() // lock released here
		return saveQueryWhitelist() // create "empty" file; uses lock
	}
	if err != nil {
		return fmt.Errorf("cannot read whitelist file %q: %w", path, err)
	}

	var rulesByType map[string][]RuleEntry
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&rulesByType); err != nil {
		return fmt.Errorf("failed to parse whitelist file '%q' (maybe it contains unsupported or typo-ed fields?), err: %w", path, err)
	}
	var changed uint = 0

	func() {
		ruleMutex.Lock()
		defer ruleMutex.Unlock()

		whitelist = make(map[string][]RuleEntry, len(rulesByType))
		for typ, rules := range rulesByType {
			var cleaned []RuleEntry
			for i := range rules {
				r := &rules[i]
				// XXX: it may not have an ID set at this point
				if r.ID == "" {
					nid := newUniqueID(rulesByType)
					fmt.Println("Making new ID for rule that had none: ", nid)
					r.ID = nid
					changed++
				}
				new2 := strings.ToLower(strings.TrimSuffix(r.Pattern, "."))
				if new2 != r.Pattern {
					r.Pattern = new2
					changed++
				}
				cleaned = append(cleaned, *r)
			}
			// // deduplicate by ID, unclear why'd I ever need this before?!
			// seen := make(map[string]struct{})
			// deduped := cleaned[:0]
			// for _, r := range cleaned {
			// 	if _, ok := seen[r.ID]; !ok {
			// 		seen[r.ID] = struct{}{}
			// 		deduped = append(deduped, r)
			// 	}
			// }
			whitelist[typ] = cleaned
		}

		if countRules(rulesByType) != countRules(whitelist) {
			panic("bad coding: lost some rules, shouldn't happen unless we dedupped- but we didn't")
		}

		fmt.Printf("Loaded %d types / %d rules from %q", len(whitelist), countRules(whitelist), path)
	}() // lock released here
	if changed > 0 {
		fmt.Printf(" and had to change/normalize %d of them. Thus, saving file: %q\n", changed, path)
		return saveQueryWhitelist() //uses lock!
	} else {
		fmt.Println()
		return nil // no error
	}
}

// DefaultConfig Every call produces a new map and slice backing array.
// must be func. or else(if configDefaults would be a 'var') the 'make' call/ref. will be shared and the []string{} too.
func DefaultConfig() Config {
	return Config{
		ListenDNS:               "127.0.0.1:53",
		ListenDoH:               "127.0.0.1:443",
		UIPort:                  8080,
		UpstreamURL:             "https://9.9.9.9/dns-query",
		UpstreamRetriesPerQuery: 1,               // 1 initial try(not counted) + 1 retry(counted here)
		SNIHostname:             "dns.quad9.net", // if empty it uses the 9.9.9.9 from url which also works!
		BlockMode:               "nxdomain",
		BlockIP:                 "0.0.0.0",
		RateQPS:                 100,
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
	}
}

// mainLogger is the single source of truth. Every log event goes through ONE call here.
// The multiHandler then fans it out to:
//   - dnsbollocks.log (JSON, everything)
//   - queries.log (JSON, only category=query)
//   - console (colored text, >= ConsoleLogLevel)
//
// var mainLogger *slog.Logger
// mainLogger starts as a bootstrap colored console logger (Info level).
// It is replaced after loadConfig() with the full multi-handler (files + config level).
// This guarantees the very first line of OldMain already uses mainLogger.
var mainLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
	Level: slog.LevelDebug, //TODO: allow env. var. to dictate the level? but nothing right now uses this yet because initBootstrapLogging gets hit early!
})) // temporary placeholder — will be overwritten in initBootstrapLogging

// initBootstrapLogging sets up a colored console-only logger for the earliest messages.
// Called as the FIRST thing in OldMain, before anything else.
func initBootstrapLogging() {
	// Use the exact same colored handler you already have (it gracefully falls back if no console)
	bootstrapLevel := slog.LevelDebug // hard-coded for bootstrap — only ~8 lines anyway
	mainLogger = slog.New(newColoredConsoleHandler(bootstrapLevel))

	// This line is now the very first log in the entire program
	mainLogger.Info("DNSbollocks starting... bootstrap-logging inited.")
}

// -----------------------------------------------------------------------------
// Colored console handler (Windows-only, uses your exact color request)
// -----------------------------------------------------------------------------

// LevelToAttr maps slog levels to Win32 console attributes exactly as you asked.
var LevelToAttr = map[slog.Level]uint16{
	slog.LevelDebug: wincoe.FOREGROUND_GRAY,   // dark grey
	slog.LevelInfo:  wincoe.FOREGROUND_NORMAL, // normal / light grey (we actually restore original, but fallback)
	slog.LevelWarn:  wincoe.FOREGROUND_BRIGHT_MAGENTA,
	slog.LevelError: wincoe.FOREGROUND_RED,
}

// ColoredConsoleHandler sets color before the inner TextHandler writes, then restores.
// If there is no console (service, piped, etc.) it silently falls back to plain text.
type ColoredConsoleHandler struct {
	Inner    slog.Handler
	HStdout  windows.Handle
	OrigAttr uint16
	UseColor bool
	Mu       sync.Mutex
}

func newColoredConsoleHandler(level slog.Level) slog.Handler {
	inner := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
		// ReplaceAttr can be extended later for timestamps, etc.
	})
	//hStdout := windows.Handle(wincoe.STD_OUTPUT_HANDLE) // BAD, won't work.
	hStdout, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE) //this will.
	if hStdout == windows.InvalidHandle || err != nil {
		// No console → plain text fallback
		//FIXME: figure out if this would recuse infinitely:
		mainLogger.Warn("failed to select console, falling back to plain text", slog.Any("err", err))
		//goto normalPlainTextHandler
		return inner //slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}

	origAttr, err := wincoe.GetConsoleScreenBufferAttributes(hStdout) // your new helper
	if err != nil {
		// fallback
		//FIXME: figure out if this would recuse infinitely:
		mainLogger.Warn("failed to select colored console, falling back to plain text", slog.Any("err", err))
		return inner //slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}

	return &ColoredConsoleHandler{
		Inner:    inner,
		HStdout:  hStdout,
		OrigAttr: origAttr,
		UseColor: true,
	}

	// normalPlainTextHandler:
	//
	//	return slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
}

func (h *ColoredConsoleHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.Inner.Enabled(ctx, level)
}

// // what Grok 4.20 Expert says is the fixed one(he's not right):
// func (h *ColoredConsoleHandler) Handle(ctx context.Context, r slog.Record) error {
// 	if !h.UseColor {
// 		return h.Inner.Handle(ctx, r)
// 	}

// 	h.Mu.Lock()
// 	defer h.Mu.Unlock() // ← full critical section; unlock happens even on panic

// 	// ──────────────────────────────────────────────────────────────
// 	// 1. Decide color exactly once while holding the lock
// 	// ──────────────────────────────────────────────────────────────
// 	var color uint16
// 	var isQuery bool
// 	var action string

// 	r.Attrs(func(a slog.Attr) bool {
// 		switch a.Key {
// 		case "category":
// 			if a.Value.String() == "query" {
// 				isQuery = true
// 			}
// 		case "action":
// 			action = a.Value.String()
// 		}
// 		return true
// 	})

// 	if isQuery && action != "" {
// 		if c, ok := QueryActionColors[action]; ok {
// 			color = c
// 		} else {
// 			color = LevelToAttr[r.Level]
// 		}
// 	} else {
// 		color = LevelToAttr[r.Level]
// 	}
// 	if color == 0 {
// 		color = h.OrigAttr // never leave console in undefined state
// 	}

// 	// ──────────────────────────────────────────────────────────────
// 	// 3. Restore on every exit path (including panic)
// 	// ──────────────────────────────────────────────────────────────
// 	defer func() {
// 		if resetErr := wincoe.SetConsoleTextAttribute(h.HStdout, h.OrigAttr); resetErr != nil {
// 			// We are already inside a locked section and returning an error;
// 			// we do not want to swallow the original error, so we only log.
// 			// Never panic here — that would mask the real problem.
// 			//FIXME: figure out if this would recuse infinitely:
// 			mainLogger.Warn("SetConsoleTextAttribute restore failed",
// 				slog.Uint64("original_attr", uint64(h.OrigAttr)),
// 				slog.Any("err", resetErr))
// 		}
// 	}()

// 	// ──────────────────────────────────────────────────────────────
// 	// 2. Apply color — never ignore errors
// 	// ──────────────────────────────────────────────────────────────
// 	if err := wincoe.SetConsoleTextAttribute(h.HStdout, color); err != nil {
// 		// restore immediately on failure, then propagate
// 		//_ = wincoe.SetConsoleTextAttribute(h.hStdout, h.origAttr) // best-effort
// 		return fmt.Errorf("SetConsoleTextAttribute (set color %d): %w", color, err)
// 	}

// 	// ──────────────────────────────────────────────────────────────
// 	// 4. Delegate to the real handler while color is active
// 	// ──────────────────────────────────────────────────────────────
// 	return h.Inner.Handle(ctx, r)
// }

// XXX: original code: Grok 4.20 thinks this causes the crash(he's not right, the cause is this https://github.com/golang/go/issues/77975#issuecomment-4021553575 and fix appears to be commit 6ab37c1ca59664375786fb2f3c122eb3db98e433 (addon) also seen in https://go-review.googlesource.com/c/go/+/753040 well this commit first https://github.com/golang/go/commit/1a44be4cecdc742ac6cce9825f9ffc19857c99f3 )! due to console corruptions when the set color fails and i don't restore it AND i continue printing text.
func (h *ColoredConsoleHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.UseColor {
		// ────────────────────────────────
		//  Decide which color to use
		// ────────────────────────────────

		var color uint16
		var isQuery bool
		var action string

		// Scan attributes once — look for category and action
		r.Attrs(func(a slog.Attr) bool {
			switch a.Key {
			case "category":
				if a.Value.String() == "query" {
					isQuery = true
				}
			case "action":
				action = a.Value.String()
			}
			return true // keep scanning
		})

		if isQuery && action != "" {
			// Query line → try to use action-based color
			if c, ok := QueryActionColors[action]; ok {
				color = c
			} else {
				// unknown action → fall back to level-based color
				color = LevelToAttr[r.Level]
				// if color == 0 {
				// 	color = h.origAttr
				// }
			}
		} else {
			// Normal (non-query) log line → classic level-based coloring
			color = LevelToAttr[r.Level]
			// if color == 0 {
			// 	color = h.origAttr
			// }
		}
		// color := levelToAttr[r.Level]
		if color == 0 {
			color = h.OrigAttr // safety
		}
		// ────────────────────────────────
		//  Apply the chosen color
		// ────────────────────────────────
		//This version prevents two goroutines from changing color at the same time, which is exactly what causes the second line to lose its color when queries arrive almost simultaneously.
		h.Mu.Lock()
		defer h.Mu.Unlock()
		err := wincoe.SetConsoleTextAttribute(h.HStdout, color)
		if err == nil {
			// 	return fmt.Errorf("SetConsoleTextAttribute failed: %w", err)
			// }
			// Important: restore color AFTER writing — even on error paths
			defer func() {
				_ = wincoe.SetConsoleTextAttribute(h.HStdout, h.OrigAttr) //nolint:errcheck // because nothing to do with the error.
			}()
		} // ignore if couldn't set the text attribute/color!
	}

	writeErr := h.Inner.Handle(ctx, r)

	if writeErr != nil {
		return fmt.Errorf("inner handler failed: %w", writeErr)
	}
	return nil
}

// // isQueryLine checks whether this record is one of our DNS query logs
// func isQueryLine(r slog.Record) bool {
// 	isQuery := false
// 	r.Attrs(func(a slog.Attr) bool {
// 		if a.Key == "category" && a.Value.String() == "query" {
// 			isQuery = true
// 			return false // early exit
// 		}
// 		return true
// 	})
// 	return isQuery
// }

// // getActionFromRecord extracts the "action" value if present
// func getActionFromRecord(r slog.Record) string {
// 	var action string
// 	r.Attrs(func(a slog.Attr) bool {
// 		if a.Key == "action" {
// 			action = a.Value.String()
// 			return false // early exit
// 		}
// 		return true
// 	})
// 	return action
// }

func (h *ColoredConsoleHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ColoredConsoleHandler{
		Inner:    h.Inner.WithAttrs(attrs),
		HStdout:  h.HStdout,
		OrigAttr: h.OrigAttr,
		UseColor: h.UseColor,
	}
}

func (h *ColoredConsoleHandler) WithGroup(name string) slog.Handler {
	return &ColoredConsoleHandler{
		Inner:    h.Inner.WithGroup(name),
		HStdout:  h.HStdout,
		OrigAttr: h.OrigAttr,
		UseColor: h.UseColor,
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
var dohCert tls.Certificate // Loaded once for DoH listener
var (
	config      Config
	upstreamIP  string
	upstreamURL *url.URL
	// queryLogger    *slog.Logger
	// errorLogger    *slog.Logger
	cacheStore     *cache.Cache
	globalLimiter  *rate.Limiter
	clientLimiters sync.Map               // map[string]*rate.Limiter
	whitelist      map[string][]RuleEntry // type -> rules
	ruleMutex      sync.RWMutex
	recentBlocks   = make([]BlockedQuery, 0, 50) // For UI
	blockMutex     sync.Mutex
	stats          = expvar.NewInt("blocks") // Simple stats

	backgroundCtx, cancel = context.WithCancel(context.Background())
	shutdownWG            sync.WaitGroup
)

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

type BlockedQuery struct {
	Domain string    `json:"domain"`
	Type   string    `json:"type"`
	Time   time.Time `json:"time"`
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

func IsValidDNSName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	return dnsNameRE.MatchString(s)
}

// SanitizeDomainInput removes any characters not explicitly allowed.
// Safe for logs and DNS-related handling.
func SanitizeDomainInput(input string) (sanitized string, modified bool) {
	const allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-{}*!"

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

const noScriptWarningHTML = `
<noscript>
  <div style="
    padding: 10px;
    margin-bottom: 12px;
    border: 1px solid #cc0000;
    background: #ffeeee;
    color: #660000;
    font-weight: bold;
  ">
    JavaScript is disabled.
    <br>
    which means that input validation and character filtering will be enforced only after submission. (ie. is the hostname within allowable chars or byte limits?)
  </div>
</noscript>
`

// var uiTemplates = template.Must(template.New("").Parse(
// 	`<!DOCTYPE html><html><head><title>DNSbollocks UI</title><meta charset="utf-8"><base href="/">
//     <style>
// body { font-family: 'Segoe UI', sans-serif; background: #121212; color: #e0e0e0; padding: 40px; }
//         .container { max-width: 1000px; margin: auto; }
//         h2 { color: #0078d4; border-bottom: 2px solid #333; padding-bottom: 10px; }
//         table { width: 100%; border-collapse: collapse; background: #1e1e1e; border-radius: 8px; overflow: hidden; }
//         th, td { padding: 15px; text-align: left; border-bottom: 1px solid #333; }
//         th { background: #252525; color: #888; font-size: 0.8em; text-transform: uppercase; }
//         .btn { padding: 6px 12px; cursor: pointer; border: none; border-radius: 4px; font-weight: bold; }
//         .btn-edit { background: #0078d4; color: white; }
//         .btn-del { background: #d83b01; color: white; margin-left: 5px; }
//         .btn-cancel { background: #444; color: white; }\n        .actions { white-space: nowrap; }
//         .hidden { display: none; }
//         input[type="text"] { background: #2d2d2d; color: white; border: 1px solid #444; padding: 6px; width: 70%; }

//         thead th {
//             position: sticky;
//             top: 0;
//             background: #1e1e1e;
//             z-index: 2;
//         }

// .actions {
//     white-space: nowrap;
// }
// .actions form {
//     display: inline;
//     margin: 0;
// }
// .actions button {
//     display: inline-block;
//     vertical-align: middle;
// }

// /* --- UI stability fixes --- */
// table {
//   border-collapse: collapse;
// }
// thead th {
//   position: sticky;
//   top: 0;
//   background: #222;
//   z-index: 3;
// }
// .actions {
//   white-space: nowrap;
// }
// .actions form {
//   display: inline;
//   margin: 0;
// }
// .actions button {
//   display: inline-block;
//   vertical-align: middle;
// }
// /* Prevent edit row from changing height */
// tr td {
//   vertical-align: middle;
// }

// </style></head><body>` +
// 		noScriptWarningHTML + `
//     <div class="container">
//     <h1>DNSbollocks</h1>
//     <a href="/rules">Whitelist Rules</a> | <a href="/hosts">Local Hosts</a> | <a href="/blocks">Recent Blocks</a> | <a href="/logs">Logs</a> | <a href="/">Stats</a> | <a href="/debug/vars">Debug Vars</a>
//     {{.Body}}
//     </div>
//     <script>
//     document.addEventListener('DOMContentLoaded', function() {
//         document.querySelectorAll('button[data-edit-id]').forEach(btn => {
//             btn.addEventListener('click', function(e) {
//                 e.preventDefault();
//                 const row = this.closest('tr');
//                 const typ = this.dataset.editType;
//                 const id = this.dataset.editId;
//                 const oldPattern = this.dataset.editPattern;
//                 const enabled = this.dataset.editEnabled === 'true';
//                 row.style.display = 'none';
//                 const formHtml = ` + "`" + `
//                 <tr>
//                     <td>
//                         <select name="type" id="editType_${id}">
//                             ` + strings.Join(func() []string {
// 		var opts []string
// 		for _, t := range dnsTypes {
// 			//dnsTypes is from our Go code not user input, can use %s here. Also puting user input here would be bad for this templating too!
// 			opts = append(opts, fmt.Sprintf("<option value=\"%s\">%s</option>", t, t))
// 		}
// 		return opts
// 	}(), "") + `
//                         </select>
//                     </td>
//                     <td>${id}</td>
//                     <td><input type="text" id="editPattern_${id}" value="${oldPattern}" style="width:100%"></td>
//                     <td><label><input type="checkbox" id="editEnabled_${id}" ${enabled ? 'checked' : ''}></label></td>
//                     <td>
//                         <form method="post" action="/rules" id="editForm_${id}">
//                             <input type="hidden" name="id" value="${id}">
//                             <button type="submit">Save</button>
//                             <button type="button" onclick="cancelEdit('${id}')">Cancel</button>
//                         </form>
//                     </td>
//                 </tr>
//                 ` + "`" + `;
//                 row.insertAdjacentHTML('afterend', formHtml);
// 				const select = document.getElementById('editType_' + id);
// 				if (select) {
// 					select.value = typ;
// 					// Guard: detect impossible / stale / corrupted types
// 					if (![...select.options].some(o => o.value === typ)) {
// 						console.warn(
// 							'Unknown DNS type for rule',
// 							{ id, typ, known: [...select.options].map(o => o.value) }
// 						);
// 						select.selectedIndex = 0;
// 					}
// 				}
//                 const form = document.getElementById('editForm_' + id);
//                 form.addEventListener('submit', function(e) {
//                     e.preventDefault();
//                     const newPattern = document.getElementById('editPattern_' + id).value.trim();
//                     const enabledChecked = document.getElementById('editEnabled_' + id).checked;
//                     const newType = document.getElementById('editType_' + id).value;
//                     if (newPattern === '') {
//                         alert('Pattern cannot be empty');
//                         return;
//                     }
//                     const formData = new FormData();
//                     formData.append('id', id);
//                     formData.append('pattern', newPattern);
//                     formData.append('type', newType);
//                     formData.append('enabled', enabledChecked ? 'true' : 'false');
//                     fetch('/rules', {method: 'POST', body: formData})
//                         .then(() => location.reload())
//                         .catch(err => console.error('Save failed:', err));
//                 });
//             });
//         });
//         window.cancelEdit = function(id) {
//             const formElem = document.querySelector('#editForm_' + id);
//             if (!formElem) return;
//             const tr = formElem.closest('tr');
//             if (tr) tr.remove();
//             const originalBtn = document.querySelector('button[data-edit-id="' + id + '"]');
//             if (originalBtn) {
//                 const originalRow = originalBtn.closest('tr');
//                 if (originalRow) originalRow.style.display = '';
//             }
//         };
//     });
//     </script>

// <script>
// // Preserve scroll position across form submits / reloads
// (function() {
//   const key = "scrollY";
//   window.addEventListener("beforeunload", function () {
//     try { sessionStorage.setItem(key, window.scrollY); } catch(e) {}
//   });
//   window.addEventListener("load", function () {
//     try {
//       const y = sessionStorage.getItem(key);
//       if (y !== null) window.scrollTo(0, parseInt(y, 10));
//     } catch(e) {}
//   });
// })();
// </script>

// </body></html>`,
// ))

// body { font-family: 'Segoe UI', sans-serif; background: #121212; color: #e0e0e0; padding: 40px; }
//
//	.container { max-width: 1000px; margin: auto; }
//	h2 { color: #0078d4; border-bottom: 2px solid #333; padding-bottom: 10px; }
//	table { width: 100%; border-collapse: collapse; background: #1e1e1e; border-radius: 8px; overflow: hidden; }
//	th, td { padding: 15px; text-align: left; border-bottom: 1px solid #333; }
//	th { background: #252525; color: #888; font-size: 0.8em; text-transform: uppercase; }
//	.btn { padding: 6px 12px; cursor: pointer; border: none; border-radius: 4px; font-weight: bold; }
//	.btn-edit { background: #0078d4; color: white; }
//	.btn-del { background: #d83b01; color: white; margin-left: 5px; }
//	.btn-cancel { background: #444; color: white; }
//	.actions { white-space: nowrap; }
//	.hidden { display: none; }
//	input[type="text"] { background: #2d2d2d; color: white; border: 1px solid #444; padding: 6px; width: 70%; }
//	thead th { position: sticky; top: 0; background: #1e1e1e; z-index: 2; }
//	.actions form { display: inline; margin: 0; }
//	.actions button { display: inline-block; vertical-align: middle; }
//	tr td { vertical-align: middle; }

// <style>
// 		body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #121212; color: #e0e0e0; padding: 40px; line-height: 1.6; }
//         .container { max-width: 1100px; margin: auto; }
//         h1 { color: #0078d4; margin-bottom: 20px; }
//         h2 { color: #0078d4; border-bottom: 2px solid #333; padding-bottom: 10px; margin-top: 40px; }

//         /* GLOBAL FORM STYLES (The Dark Mode Fix) */
//         input[type="text"], select, button {
//             background: #2d2d2d;
//             color: #ffffff;
//             border: 1px solid #444;
//             padding: 8px 12px;
//             border-radius: 4px;
//             outline: none;
//             font-size: 0.9em;
//         }
//         input[type="text"]:focus, select:focus { border-color: #0078d4; }
//         button { cursor: pointer; font-weight: 600; transition: background 0.2s; }
//         button:hover { background: #3d3d3d; }

//         /* Tables */
//         table { width: 100%; border-collapse: collapse; background: #1e1e1e; border-radius: 8px; margin-top: 20px; }
//         th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #333; }
//         th { background: #252525; color: #888; font-size: 0.8em; text-transform: uppercase; letter-spacing: 1px; }

//         /* Specialized Buttons */
//         .btn-edit { background: #0078d4; color: white; border: none; }
//         .btn-edit:hover { background: #005a9e; }
//         .btn-del { background: #d83b01; color: white; border: none; }
//         .btn-del:hover { background: #a82a01; }
//         .btn-cancel { background: #444; color: white; border: none; }

//	nav { margin-bottom: 30px; padding: 10px 0; border-bottom: 1px solid #333; }
//	nav a { color: #0078d4; text-decoration: none; margin-right: 15px; font-weight: bold; }
//	nav a:hover { text-decoration: underline; }
//	.tag-enabled { color: #4ec9b0; font-weight: bold; }
//	.tag-disabled { color: #f44747; font-weight: bold; }
//	pre { background: #1e1e1e; padding: 15px; border-radius: 4px; border: 1px solid #333; }
//
// </style>
var uiTemplates = template.Must(template.New("").Parse(
	`<!DOCTYPE html><html><head><title>DNSbollocks UI</title><meta charset="utf-8"><base href="/">
<style>
    /* 1. LAYOUT & TEXT */
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #121212; color: #e0e0e0; padding: 40px; line-height: 1.6; }
    .container { max-width: 1100px; margin: auto; }
    h1 { color: #0078d4; margin-bottom: 20px; }
    h2 { color: #0078d4; border-bottom: 2px solid #333; padding-bottom: 10px; margin-top: 40px; }
    
    nav { margin-bottom: 30px; padding: 10px 0; border-bottom: 1px solid #333; }
    nav a { color: #0078d4; text-decoration: none; margin-right: 15px; font-weight: bold; }
    nav a:hover { text-decoration: underline; }

    /* 2. GLOBAL FORM STYLES (The "Dark Fix" Merge) */
    input[type="text"], select, button { 
        background-color: #2d2d2d !important; /* Forced Dark */
        color: #ffffff !important;           /* Forced White Text */
        border: 1px solid #444 !important; 
        padding: 8px 12px; 
        border-radius: 4px; 
        outline: none;
        font-size: 0.9em;
        vertical-align: middle;
        box-sizing: border-box;
    }

    /* Specialized Select/Dropdown logic */
    select {
        appearance: none; 
        -webkit-appearance: none;
        background-image: url('data:image/svg+xml;charset=US-ASCII,<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>') !important;
        background-repeat: no-repeat !important;
        background-position: right 10px center !important;
        background-size: 14px !important;
        padding-right: 35px !important;
    }

    /* Ensure dropdown options are also dark */
    select option { background: #2d2d2d; color: white; }

    input[type="text"]:focus, select:focus { border-color: #0078d4 !important; }
    
    button { cursor: pointer; font-weight: 600; transition: background 0.2s; }
    button:hover { background: #3d3d3d !important; }

    /* 3. TABLES (Anti-Jump Fixes) */
    table { width: 100%; table-layout: fixed; border-collapse: collapse; background: #1e1e1e; border-radius: 8px; margin-top: 20px; overflow: hidden;}
    tr { height: 64px; } /* Locks row height to prevent vertical jumping */
    th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #333; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    th { background: #252525; color: #888; font-size: 0.8em; text-transform: uppercase; letter-spacing: 1px; }
    
    /* 4. BUTTON VARIANTS */
    .btn-edit { background-color: #0078d4 !important; color: white !important; border: none !important; }
    .btn-edit:hover { background-color: #005a9e !important; }
    .btn-del { background-color: #d83b01 !important; color: white !important; border: none !important; }
    .btn-del:hover { background-color: #a82a01 !important; }
    
    /* New Save/Cancel Buttons */
    .btn-save { background-color: #28a745 !important; color: white !important; border: none !important; }
    .btn-save:hover { background-color: #218838 !important; }
    .btn-cancel { background-color: #dc3545 !important; color: white !important; border: none !important; }
    .btn-cancel:hover { background-color: #c82333 !important; }

    /* 5. UTILITIES */
    .actions { white-space: nowrap; font-size: 0; } /* Font size 0 prevents gap artifacts between inline-block elements */
    .actions button { font-size: 0.9rem; }
    .tag-enabled { color: #4ec9b0; font-weight: bold; }
    .tag-disabled { color: #f44747; font-weight: bold; }
    pre { background: #1e1e1e; padding: 15px; border-radius: 4px; border: 1px solid #333; white-space: pre-wrap; word-break: break-all; }
</style></head><body>` +
		noScriptWarningHTML + `
    <div class="container">
    <h1>DNSbollocks</h1>
	<nav>
    <a href="/rules">Whitelist Rules</a> | <a href="/hosts">Hosts</a> | 
	<a href="/blocks">Recent Blocks</a> | <a href="/logs">Logs</a> | 
	<a href="/">Stats</a> | <a href="/debug/vars">Debug Vars</a>
    </nav>
    <hr>
    
    {{/* This acts as a router inside the template */}}
    {{if eq .Page "rules"}}
        {{template "rules" .}}
	{{else if eq .Page "hosts"}}
        {{template "hosts" .}}
    {{else if eq .Page "blocks"}}
        {{template "blocks" .}}
	{{else if eq .Page "logs"}}
        {{template "logs" .}}
    {{else}}
        {{/* Fallback for Stats / Legacy*/}}
        {{.RawBody}} 
    {{end}}

    </div>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        document.querySelectorAll('button[data-edit-id]').forEach(btn => {
            btn.addEventListener('click', function(e) {
                e.preventDefault();
                const row = this.closest('tr');
                const typ = this.dataset.editType;
                const id = this.dataset.editId;
                const oldPattern = this.dataset.editPattern;
                const enabled = this.dataset.editEnabled === 'true';
                row.style.display = 'none';
                const formHtml = ` + "`" + `
                <tr>
                    <td>
                        <select name="type" id="editType_${id}" style="width: 100%;">
                            ` + strings.Join(func() []string {
		var opts []string
		for _, t := range dnsTypes {
			opts = append(opts, fmt.Sprintf("<option value=\"%s\">%s</option>", t, t))
		}
		return opts
	}(), "") + `
                        </select>
                    </td>
                    <td title="${id}">${id}</td>
                    <td><input type="text" id="editPattern_${id}" value="${oldPattern}" style="width: 100%;"></td>
                    <td><label><input type="checkbox" id="editEnabled_${id}" ${enabled ? 'checked' : ''} style="vertical-align: middle;"></label></td>
                    <td class="actions">
                        <form method="post" action="/rules" id="editForm_${id}" style="display:inline; margin:0;">
                            <input type="hidden" name="id" value="${id}">
                            <button type="submit" class="btn-save">Save</button>
                            <button type="button" class="btn-cancel" onclick="cancelEdit('${id}')">Cancel</button>
                        </form>
                    </td>
                </tr>
                ` + "`" + `;
                row.insertAdjacentHTML('afterend', formHtml);
				const select = document.getElementById('editType_' + id);
				if (select) { select.value = typ; }
                const form = document.getElementById('editForm_' + id);
                form.addEventListener('submit', function(e) {
                    e.preventDefault();
                    const newPattern = document.getElementById('editPattern_' + id).value.trim();
                    const enabledChecked = document.getElementById('editEnabled_' + id).checked;
                    const newType = document.getElementById('editType_' + id).value;
                    if (newPattern === '') { alert('Pattern cannot be empty'); return; }
                    const formData = new FormData();
                    formData.append('id', id);
                    formData.append('pattern', newPattern);
                    formData.append('type', newType);
                    formData.append('enabled', enabledChecked ? 'true' : 'false');
                    fetch('/rules', {method: 'POST', body: formData})
                        .then(() => location.reload())
                        .catch(err => console.error('Save failed:', err));
                });
            });
        });
        window.cancelEdit = function(id) {
            const formElem = document.querySelector('#editForm_' + id);
            if (!formElem) return;
            const tr = formElem.closest('tr');
            if (tr) tr.remove();
            const originalBtn = document.querySelector('button[data-edit-id="' + id + '"]');
            if (originalBtn) {
                const originalRow = originalBtn.closest('tr');
                if (originalRow) originalRow.style.display = '';
            }
        };
    });
    </script>
</body></html>

{{/* --- SUB-TEMPLATE FOR RULES --- */}}
{{define "rules"}}
<h2>Add New Rule</h2>
<form method="post" action="/rules">
    <select name="type">
    {{range .DNSTypes}}
        <option value="{{.}}">{{.}}</option>
    {{end}}
    </select>
    <input type="text" name="pattern" placeholder="pattern" required> 
    <label style="margin: 0 10px;"><input type="checkbox" name="enabled" checked> Enabled</label> 
    <button type="submit" class="btn-edit">Add Rule</button>
</form>

<h2>Whitelist Rules</h2>
<table>
    <colgroup>
        <col style="width: 14%;">
        <col style="width: 30%;">
        <col style="width: 26%;">
        <col style="width: 12%;">
        <col style="width: 18%;">
    </colgroup>
    <tr><th>Type</th><th>ID</th><th>Pattern</th><th>Enabled</th><th>Actions</th></tr>
{{range $typ, $ruleList := .Rules}}
    {{range $ruleList}}
    <tr>
        <td>{{$typ}}</td>
        <td title="{{.ID}}">{{.ID}}</td>
        <td title="{{.Pattern}}">{{.Pattern}}</td>
		<td>{{if .Enabled}}<span class="tag-enabled">Active</span>{{else}}<span class="tag-disabled">Paused</span>{{end}}</td>
        <td class="actions">
            <button class="btn-edit" data-edit-id="{{.ID}}" data-edit-type="{{$typ}}" data-edit-pattern="{{.Pattern}}" data-edit-enabled="{{.Enabled}}">Edit</button>
            <form method="post" action="/rules" style="display:inline;margin-left:6px" onsubmit="return confirm('Delete rule?')">
                <input type="hidden" name="delete" value="1">
                <input type="hidden" name="id" value="{{.ID}}">
                <input type="hidden" name="type" value="{{$typ}}">
                <button type="submit" class="btn-del">Delete</button>
            </form>
        </td>
    </tr>
    {{end}}
{{end}}
</table>
{{end}}

{{/* --- SUB-TEMPLATE FOR BLOCKS --- */}}
{{define "blocks"}}
<h2>Recent Blocks (Quick Unblock)</h2><ul>
{{range .Blocks}}
    <li>{{.Domain}} ({{.Type}}) 
        <form method="post" action="/blocks" style="display:inline;">
            <input type="hidden" name="domain" value="{{.Domain}}">
            <input type="hidden" name="type" value="A">
            <button type="submit">Unblock A</button>
        </form> 
        <button onclick="location.href='/blocks?type=AAAA&domain={{.Domain}}'">Unblock AAAA</button>
    </li>
{{end}}
</ul>
{{end}}

{{define "hosts"}}
    <div style="padding: 10px; margin-bottom: 15px; border-left: 4px solid #0078d4; background: #1e1e1e;">
        <strong>Note:</strong> A pattern/host must match the whitelist rules first for these local host overrides to take any effect.
    </div>

    <h2>Add New Local Host</h2>
    <form method="post" action="/hosts">
        <input type="text" name="pattern" placeholder="pattern (e.g. router.local)" required> 
        <input type="text" name="ips" placeholder="IPs (comma separated, e.g. 192.168.1.1)" style="width: 280px;" required> 
        <button type="submit">Add Host</button>
    </form>

    <h2>Local Hosts</h2>
    <table>
        <colgroup>
            <col style="width: 35%;">
            <col style="width: 45%;">
            <col style="width: 20%;">
        </colgroup>
        <tr><th>Pattern</th><th>IPs</th><th>Actions</th></tr>
        {{range .Hosts}}
        <tr id="hostRow_{{.Index}}">
            <td title="{{.Pattern}}">{{.Pattern}}</td>
            <td title="{{.IPsDisplay}}">{{.IPsDisplay}}</td>
            <td class="actions">
                <button class="btn-edit" onclick="editHost(this, {{.Index}}, '{{.Pattern}}', '{{.IPsDisplay}}')">Edit</button>
                <form method="post" action="/hosts" style="display:inline;margin-left:6px" onsubmit="return confirm('Delete local host override?')">
                    <input type="hidden" name="delete" value="1">
                    <input type="hidden" name="pattern" value="{{.Pattern}}">
                    <button class="btn-del" type="submit">Delete</button>
                </form>
            </td>
        </tr>
        {{else}}
        <tr><td colspan="3">No local hosts defined.</td></tr>
        {{end}}
    </table>

    <script>
    function editHost(btn, index, pat, ips) {
        const row = document.getElementById('hostRow_' + index);
        row.style.display = 'none';
        const formHtml = ` + "`" + `
        <tr id="editHostRow_${index}">
            <td>
                <input type="hidden" name="old_pattern" value="${pat}" form="editHostForm_${index}">
                <input type="text" name="pattern" value="${pat}" form="editHostForm_${index}" style="width:100%" required>
            </td>
            <td><input type="text" name="ips" value="${ips}" form="editHostForm_${index}" style="width:100%" required></td>
            <td class="actions">
                <form method="post" action="/hosts" id="editHostForm_${index}" style="display:inline; margin:0;">
                    <input type="hidden" name="edit" value="1">
                    <button type="submit" class="btn-save">Save</button>
                    <button type="button" class="btn-cancel" onclick="cancelHostEdit(${index})">Cancel</button>
                </form>
            </td>
        </tr>
        ` + "`" + `;
        row.insertAdjacentHTML('afterend', formHtml);
    }
    function cancelHostEdit(index) {
        const editRow = document.getElementById('editHostRow_' + index);
        if (editRow) editRow.remove();
        const row = document.getElementById('hostRow_' + index);
        if (row) row.style.display = '';
    }
    </script>
{{end}}

{{define "logs"}}
    <h2>{{.Title}}</h2>
    
    <form method="get" style="margin-bottom: 20px;">
        <input type="text" name="q" value="{{.Filter}}" placeholder="Search logs..." style="width: 300px;">
        <button type="submit">Filter</button>
		<button type="button" class="btn-cancel" onclick="this.form.q.value=''; this.form.submit();">Clear</button>
    </form>

    <div style="background: #1e1e1e; padding: 15px; border-radius: 4px; border: 1px solid #333;">
        <pre style="max-height: 600px; overflow: auto; margin: 0; white-space: pre-wrap; word-break: break-all; font-family: 'Consolas', monospace; font-size: 0.9em; color: #dcdcdc;">{{if .Content}}{{.Content}}{{else}}No log entries found.{{end}}</pre>
    </div>
{{end}}
`))

const configFileName = "config.json"

func logFatal(msg string, err error) {
	mainLogger.Error(msg, slog.Any("err", err))
	os.Exit(1) // replaced log.Fatal
}

func logFatal2(msg string) {
	mainLogger.Error(msg)
	os.Exit(1) // replaced log.Fatal
}

// 2. New error channel for service failures
// We use a buffer of (e.g.) 10 so multiple services failing at once won't block
var errChan chan error = make(chan error, 10)

func OldMain() {
	// wincoe.InstallCrashSink()
	// if true {
	// 	panic("deliberate panic")
	// }
	// TEMPORARY: race detector smoke test — remove before release
	if false {
		var raceTest int
		done := make(chan struct{})
		go func() {
			raceTest = 1 // concurrent write
			close(done)
		}()
		raceTest = 2 // concurrent write
		<-done
		_ = raceTest
	}

	initBootstrapLogging() // ← FIRST LINE — colored console, mainLogger now exists
	// go func() {
	// 	ticker := time.NewTicker(5 * time.Second)
	// 	defer ticker.Stop()
	// 	for range ticker.C {
	// 		mainLogger.Debug("MARK")
	// 	}
	// }()
	// go func() {
	// 	for {
	// 		wincoe.Churn2()
	// 		// No sleep here, or a very small one
	// 		time.Sleep(20 * time.Millisecond)
	// 	}
	// }()

	//flag.Parse() // For future flags

	// if len(os.Args) > 1 {
	// 	configPath = os.Args[1]
	// }

	// Signals setup FIRST: Catch interrupts from init onward
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	mainLogger.Debug("Signal channel ready - Ctrl+C to shutdown gracefully")

	//errChan := make(chan error, 10)
	//mainLogger.Debug("Error channel ready")

	if err := loadConfig(); err != nil {
		logFatal("Config load failed:", err)
		// mainLogger.Error("Config load failed", slog.Any("err", err))
		// os.Exit(1) // replaced log.Fatal
	}
	mainLogger.Info("Config loaded", slog.String("file", configFileName))

	if !config.AllowRunAsAdmin && isAdmin {
		logFatal2("Exiting: Elevated privileges detected. Rerun without admin or change the config setting.")
		//os.Exit(1)
	}
	//mainLogger.Debug("Non-elevated mode confirmed") // no good, as we can be admin here!

	// Now we have the real config → switch to full logging
	initFullLogging() // ← this replaces the logger with files + correct console level

	cacheStore = cache.New(time.Hour, time.Hour) // Janitor every hour
	mainLogger.Debug("Cache initialized")
	globalLimiter = rate.NewLimiter(rate.Limit(config.RateQPS), config.RateQPS)
	mainLogger.Debug("Rate limiter initialized")

	if err := validateUpstream(); err != nil {
		logFatal("Upstream validation failed:", err)
	}
	fmt.Printf("Upstream validated: %q (IP: %q)\n", config.UpstreamURL, upstreamIP)

	generateCertIfNeeded() // For DoH
	//mainLogger.Debug("Cert checked/generated if needed")

	initDoHClient()
	// Sequential launches for ordered logging
	fmt.Println("Launching listeners sequentially...")
	startDNSListener(config.ListenDNS) // Blocks until complete/fail
	startDoHListener(config.ListenDoH) // Blocks until complete/fail
	go startWebUI(config.UIPort)       // Concurrent server (blocks forever, but post-serial)

	go watchKeys(
		func() { // Ctrl+R aka reloadFn
			mainLogger.Debug("Reload triggered...")
			cacheStore.Flush()
			mainLogger.Debug("Cache flushed/deleted.")

			if err := loadQueryWhitelist(); err != nil {
				logFatal("Whitelist reload failed:", err)
			} else {
				mainLogger.Debug("Whitelist reloaded")
			}
			if err := loadResponseBlacklist(); err != nil {
				logFatal("Blacklist reload failed:", err)
			} else {
				mainLogger.Debug("Blacklist reloaded")
			}
			// Inside watchKeys, in the Ctrl+R lambda block:
			if err := loadLocalHosts(); err != nil {
				logFatal("Hosts reload failed:", err)
			} else {
				mainLogger.Debug("Local hosts reloaded")
			}
			_ = initDoHClient()
			log.Printf("Reloading of %q wasn't done, you should restart for changes there. This reload was meant to work only for reloading whitelist and blacklist changes!", configFileName)
		},
		func() { // alt+x Ctrl+X etc. aka cleanExitFn
			fmt.Println("Shutdown signal received, clean exit.")
			//doneFIXME: at least UDP DNS listener isn't shutdown while waiting for keypress to exit (after the shutdown(0) below) !!
			//cancel()    //doneFIXME: this triggers the below shutdown(4) !
			shutdown(0) // clean exit
		},
	)

	//<-sigChan // Wait here - UI goroutine handles serving
	// 4. The Seamless Wait
	select {
	case sig := <-sigChan:
		// Case A: User pressed Ctrl+C
		mainLogger.Info("shutdown initiated by signal", slog.Any("signal", sig))
		// Proceed to graceful cleanup
		//cancel()      // Cancel context for graceful close
		shutdown(130) // Ctrl+C / SIGTERM → non-clean exit => exit code 130 (128+2 like in linux)

	case err := <-errChan:
		// Case B: A background goroutine (TCP/DoH) died
		mainLogger.Error("CRITICAL: background service failure", slog.Any("err", err))
		// You can choose to exit(1) here because a vital organ failed
		//cancel()    // Cancel context for graceful close
		shutdown(3) // some error happened

	case <-backgroundCtx.Done():
		// Case C: Context was cancelled elsewhere
		mainLogger.Info("context cancelled, shutting down")
		//cancel()    // Cancel context for graceful close, this was already done since we hit this.
		shutdown(4) // some error happened
	}

	//fmt.Println("Shutdown signal received, SIGINT exit.")
	mainLogger.Error("unreachable")
	//cancel()     // Cancel context for graceful close
	shutdown(44) // impossible to reach this, unless code was added later and shutdown/exit was forgotten above.
}

var shutdownOnce sync.Once

func loadConfig() error {
	const cfgFname = configFileName
	fmt.Printf("Loading config file %q\n", cfgFname)
	var shouldSaveConfig = false
	// ---> FIX: Pre-populate the global config with defaults BEFORE reading/decoding
	// this way missing keys from config.json file will be set to default value!
	// 1. ALWAYS start by filling the global config with defaults.
	// This is critical because Decode only overwrites what is in the file.
	defaultConfig := DefaultConfig()
	config = defaultConfig // deep copy, presumably! FIXME?

	data, err := os.ReadFile(cfgFname)
	if err != nil {
		if isAdmin {
			return fmt.Errorf("config file %q not found; refusing to create a new config file with defaults due to running as Admin!"+
				" because you're likely just in the wrong dir like %%WINDIR%%\\System32\\", cfgFname)
		} else {
			// not admin, auto create config file with defaults
			//FIXME: make sure it's not found not just don't have read permission (but could have write!)
			fmt.Printf("Config file %q not found or unreadable; using defaults and creating new file.\n", cfgFname)
		}
		// Defaults
		// REMOVED: config = DefaultConfig() because it is already set above
		//config = DefaultConfig()

		shouldSaveConfig = true
	} else {
		// 2. First, check for unknown fields and decode into 'config'
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields() // This is why we use NewDecoder
		//var theReadConfig Config = DefaultConfig()

		//FIXME: any reload into existing config would race with other readers of config.* values, in theory, as this isn't mutex protected. But we don't reload config anyway, only the whitelist/blacklist which are mutexed.

		// dec.Decode will now overwrite ONLY the fields present in the JSON.
		// Missing fields will retain the values from DefaultConfig().
		if err = dec.Decode(&config); err != nil {
			//if err = dec.Decode(&theReadConfig); err != nil {
			mainLogger.Error("Config file has typos or unknown fields", slog.String("file", cfgFname), slog.Any("err", err))
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
		// 	tag := t.Field(i).Tag.Get("json")
		// 	if tag == "" || tag == "-" {
		// 		continue
		// 	}

		// 	if _, ok := presentKeys[tag]; !ok {
		// 		missing = append(missing, tag)
		// 	}
		// }

		// Use TypeFor[T] (Go 1.22+) and VisibleFields (Go 1.17+)
		missing := []string{}
		t := reflect.TypeFor[Config]()

		for _, field := range reflect.VisibleFields(t) {
			tag := field.Tag.Get("json")
			if tag == "" || tag == "-" {
				continue
			}

			if _, ok := presentKeys[tag]; !ok {
				missing = append(missing, tag)
			}
		}

		if len(missing) > 0 {
			mainLogger.Warn("Config file has missing keys; using defaults", slog.String("config_file", cfgFname), slog.Any("missing", missing))
			shouldSaveConfig = true
		}
		// if theReadConfig != config {
		// 	mainLogger.Warn("Config file had 1 or more missing fields, using defaults for those and triggering a save next.", slog.String("file", cfgFname))
		// 	config = theReadConfig
		// 	shouldSaveConfig = true
		// }
	}
	// Validate loaded config
	if config.CacheMinTTL < 60 {
		config.CacheMinTTL = 60 // Min reasonable
		fmt.Println("Warning: cache_min_ttl clamped to 60s")
	}

	var upstreamHost string
	if config.SNIHostname == "" {
		upstreamHost, err = hostFromURL(config.UpstreamURL)
		if err != nil {
			// handle parse error (return SERVFAIL or log)
			fmt.Println("invalid upstream URL:", err)
			return fmt.Errorf("invalid upstream URL: %w", err)
		}
	} else {
		upstreamHost = config.SNIHostname
	}

	config.SNIHostname = upstreamHost
	fmt.Println("Using upstream SNI hostname:", config.SNIHostname)

	// Helper closure to apply the cleaning and track if a save is needed
	checkAndClean := func(target *string, desc, fallback string) {
		if cleaned, changed := cleanFileName(*target, desc, fallback); changed {
			*target = cleaned
			if !shouldSaveConfig {
				shouldSaveConfig = true
			}
		}
	}

	checkAndClean(&config.BlacklistFile, "blacklist_file", defaultConfig.BlacklistFile)
	checkAndClean(&config.WhitelistFile, "whitelist_file", defaultConfig.WhitelistFile)
	checkAndClean(&config.LogQueriesFile, "log_queries", defaultConfig.LogQueriesFile)
	checkAndClean(&config.LogErrorsFile, "log_errors", defaultConfig.LogErrorsFile)
	checkAndClean(&config.HostsFile, "hosts_file", defaultConfig.HostsFile)
	// if didClean := cleanFileName(&config.BlacklistFile, "blacklist_file", defaultConfig.BlacklistFile); didClean && !shouldSaveConfig {
	// 	shouldSaveConfig = true
	// }
	// if didClean := cleanFileName(&config.WhitelistFile, "whitelist_file", defaultConfig.WhitelistFile); didClean && !shouldSaveConfig {
	// 	shouldSaveConfig = true
	// }
	// if didClean := cleanFileName(&config.LogQueriesFile, "log_queries", defaultConfig.LogQueriesFile); didClean && !shouldSaveConfig {
	// 	shouldSaveConfig = true
	// }
	// if didClean := cleanFileName(&config.LogErrorsFile, "log_errors", defaultConfig.LogErrorsFile); didClean && !shouldSaveConfig {
	// 	shouldSaveConfig = true
	// }
	// if didClean := cleanFileName(&config.HostsFile, "hosts_file", defaultConfig.HostsFile); didClean && !shouldSaveConfig {
	// 	shouldSaveConfig = true
	// }

	// After decoding config
	err = loadQueryWhitelist()
	if err != nil {
		return err
	}
	err = loadResponseBlacklist()
	if err != nil {
		return err
	}
	if err = loadLocalHosts(); err != nil {
		return err
	}

	if shouldSaveConfig {
		if err = saveConfig(); err != nil {
			return fmt.Errorf("config save failed: %w", err)
		}
	}
	return nil
}

// // don't pass empty or it will panic
// func cleanFileName(what *string, description string, fallback string) (didClean bool) {
// 	if what == nil {
// 		panic("dev fail: nil config filename passed to cleanFileName")
// 	}

// 	didClean = false
// 	if *what == "" {
// 		//woulda been cleaned into "." aka a dot!
// 		//panic("dev fail: passed empty filename to clean for " + description)
// 		if fallback == "" {
// 			panic("dev fail: passed empty filename to clean for '" + description + "' and the passed(to func cleanFileName()) fallback '" + fallback + "' was empty!")
// 		}
// 		mainLogger.Warn("Bad filename in config, used fallback", slog.String("bad_filename", *what), slog.String("fallback_filename", fallback), slog.String("for_config_key", description))
// 		*what = fallback
// 		didClean = true //FIXME: acts like a write the change to config, but we should really do all this outside of this function! some DRY attempt while half-asleep this was!
// 	}

// 	var cleanedFile string = filepath.Clean(*what)
// 	//from doc: If the result of this process is an empty string, Clean returns the string ".".

// 	if cleanedFile != *what {
// 		mainLogger.Debug("Cleaned filename from config file, before vs after: %q vs %q\n", slog.String("filename_description", description), slog.String("filename_before", *what), slog.String("filename_after", cleanedFile))
// 		didClean = true
// 		*what = cleanedFile
// 	}
// 	return
// }

// cleanFileName returns the cleaned filename and a boolean indicating if the original was modified.
func cleanFileName(original, description, fallback string) (string, bool) {
	if original == "" {
		if fallback == "" {
			panic(fmt.Sprintf("dev fail: passed empty filename to clean for %q and the fallback was also empty!", description))
		}
		mainLogger.Warn("Bad filename in config, used fallback",
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
		mainLogger.Debug("Cleaned filename from config file",
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
	// 	host = h
	// }
	return host, nil
}

func saveConfig() error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("config marshal failed: %w", err)
	}
	if err := os.WriteFile(configFileName, data, 0600); err != nil {
		return fmt.Errorf("config write failed: %w", err)
	}
	mainLogger.Info("Saved config file", slog.String("config_file", configFileName))
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

// initLogging creates the single mainLogger with three destinations.
// Called once after config is loaded (files and console level are known).
func initFullLogging() { //qpath, epath string) {
	consoleLevel := parseConsoleLogLevel(config.ConsoleLogLevel)
	// Simple rotation on open (respects your LogMaxSizeMB)
	openLog := func(path string) io.Writer {
		if path == "" {
			panic("empty logging filename: '" + path + "'")
		}
		path = filepath.Clean(path)
		rotateIfNeeded(path, config.LogMaxSizeMB)
		// if fi, err := os.Stat(path); err == nil && fi.Size() > int64(config.LogMaxSizeMB)*1024*1024 {
		// 	os.Rename(path, path+".1") // one backup is enough for now
		// }
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			// We are still in bootstrap phase → use the bootstrap logger so the error is colored
			mainLogger.Error("cannot open log file", slog.String("file", path), slog.Any("err", err))
			os.Exit(1)
			//panic(fmt.Errorf("cannot open log %q: %w", path, err))
		}
		return f
	}
	// if qpath == "" || epath == "" {
	// 	panic("one of these is empty: '" + qpath + "','" + epath + "'")
	// }
	// qpath = filepath.Clean(qpath)
	// epath = filepath.Clean(epath)
	// Rotation stub: Rename if > max size
	// rotateIfNeeded(qpath, config.LogMaxSizeMB)
	// rotateIfNeeded(epath, config.LogMaxSizeMB)

	// qfile, err := os.OpenFile(qpath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	// if err != nil {
	// 	logFatal("Query log open failed:", err)
	// }
	// opts := &slog.HandlerOptions{AddSource: false}
	// qh := slog.NewJSONHandler(qfile, opts)
	// queryLogger = slog.New(qh)

	// efile, err := os.OpenFile(epath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	// if err != nil {
	// 	logFatal("Error log open failed:", err)
	// }
	// eh := slog.NewJSONHandler(efile, opts)
	// errorLogger = slog.New(eh)

	fullHandler := slog.NewJSONHandler(openLog(config.LogErrorsFile), &slog.HandlerOptions{
		Level: slog.LevelDebug, // full log gets EVERYTHING
	})

	consoleH := newColoredConsoleHandler(consoleLevel) // now uses the real config level

	queryH := queryFilterHandler{
		Handler: slog.NewJSONHandler(openLog(config.LogQueriesFile), nil),
	}

	// root := multiHandler{
	// 	handlers: []slog.Handler{fullHandler, consoleH, queryH},
	// }

	// mainLogger = slog.New(root)
	// mainLogger.Info("Logging fully initialized")
	mainLogger = slog.New(multiHandler{ // <-- this REPLACES the global
		handlers: []slog.Handler{fullHandler, consoleH, queryH},
	})

	mainLogger.Info("Logging initialized",
		slog.String("full_log", config.LogErrorsFile),
		slog.String("queries_log", config.LogQueriesFile),
		slog.String("console_level", config.ConsoleLogLevel),
	)
}

func rotateIfNeeded(path string, maxMB int) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > int64(maxMB*1024*1024) {
		old := path + ".old"
		if err := os.Rename(path, old); err != nil {
			fmt.Fprintf(os.Stderr, "Log rotation failed for %q: %v\n", path, err)
		} else {
			fmt.Printf("Rotated log %q to %q (size exceeded %dMB)\n", path, old, maxMB)
		}
	}
}

func validateUpstream() error {
	var err error
	upstreamURL, err = url.Parse(config.UpstreamURL)
	if err != nil || upstreamURL.Scheme != "https" {
		return errors.New("invalid upstream URL, must be similar to this: https://IP/dns-query However, while /dns-query is the \"well-known\" default DoH Path (or Template) used by many providers (like Google and Cloudflare), the RFC 8484 standard allows server operators to configure any path they choose to handle incoming DNS queries.")
	}
	upstreamIP = upstreamURL.Hostname() // Host for IP
	if ip := net.ParseIP(upstreamIP); ip == nil {
		return errors.New("upstream host must be IP literal (no resolution)")
	}
	return nil
}

func countRules(wl map[string][]RuleEntry) int {
	total := 0
	for _, rs := range wl {
		total += len(rs)
	}
	return total
}

func newUniqueID(alreadyHave map[string][]RuleEntry) string {
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
			mainLogger.Warn("attempted to make newUniqueID() which existed", slog.String("id", id), slog.Int("try", try))
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

type state struct {
	p int
	n int
}

// slower but correct
func matchPattern2(pattern, name string) bool {
	if !isLowerASCII(pattern) {
		panic("pattern not lowercase")
	}
	if !isLowerASCII(name) {
		panic("name not lowercase")
	}

	pLen := len(pattern)
	nLen := len(name)

	states := []state{{0, 0}}
	seen := make(map[state]struct{}, 32)

	for len(states) > 0 {
		s := states[len(states)-1]
		states = states[:len(states)-1]

		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}

		p := s.p
		n := s.n

		if p == pLen {
			if n == nLen {
				return true
			}
			continue
		}

		// {**}
		if p+4 <= pLen && pattern[p:p+4] == "{**}" {
			if n < nLen {
				states = append(states, state{p, n + 1})
				states = append(states, state{p + 4, n + 1})
			}
			continue
		}

		// {*}
		if p+3 <= pLen && pattern[p:p+3] == "{*}" {
			if n < nLen && name[n] != '.' {
				states = append(states, state{p, n + 1})
				states = append(states, state{p + 3, n + 1})
			}
			continue
		}

		// **
		if p+2 <= pLen && pattern[p:p+2] == "**" {
			if n < nLen {
				states = append(states, state{p, n + 1})
			}
			states = append(states, state{p + 2, n})
			continue
		}

		switch pattern[p] {

		case '*':
			if n < nLen && name[n] != '.' {
				states = append(states, state{p, n + 1})
			}
			states = append(states, state{p + 1, n})

		case '?':
			if n < nLen && name[n] != '.' {
				states = append(states, state{p + 1, n + 1})
			}

		case '!':
			if n < nLen {
				states = append(states, state{p + 1, n + 1})
			}

		default:
			if n < nLen && pattern[p] == name[n] {
				states = append(states, state{p + 1, n + 1})
			}
		}
	}

	return false
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
	// 	if idx > 0 && idx+2 < len(pattern) &&
	// 		pattern[idx-1] == '{' && pattern[idx+2] == '}' {
	// 		// {**}
	// 		// Handle {**} wildcard (cross-label, requiring at least one label when used with dot)
	// 		//The no allocs variant:
	// 		prefix := pattern[:idx-1]
	// 		suffix := pattern[idx+3:]

	// 		if prefix != "" && !strings.HasPrefix(name, prefix) {
	// 			return false
	// 		}
	// 		if suffix != "" && !strings.HasSuffix(name, suffix) {
	// 			return false
	// 		}

	// 		if prefix == "" && strings.HasPrefix(suffix, ".") {
	// 			return len(name) > len(suffix)
	// 		}
	// 		if suffix == "" && strings.HasSuffix(prefix, ".") {
	// 			return len(name) > len(prefix)
	// 		}

	// 		return true
	// 	} else {
	// 		// **
	// 		// Handle plain ** wildcard (cross-label, may match zero chars). This mirrors legacy behavior.
	// 		//The no allocs variant:
	// 		prefix := pattern[:idx]
	// 		suffix := pattern[idx+2:]

	// 		if prefix != "" && !strings.HasPrefix(name, prefix) {
	// 			return false
	// 		}
	// 		if suffix != "" && !strings.HasSuffix(name, suffix) {
	// 			return false
	// 		}
	// 		return true
	// 	}
	// }

	// Fallback to recursive matching for other tokens ({*}, *, ?, !, literal text)
	return recursiveMatch(pattern, name)
}

func recursiveMatchOld(pattern, name string) bool {

	if strings.HasPrefix(pattern, "{**}") {
		pattern = pattern[4:]
		// must consume at least 1 char including dot
		if len(name) < 1 {
			return false
		}
		for i := 1; i <= len(name); i++ {
			if recursiveMatch(pattern, name[i:]) {
				return true
			}
		}
		return false
	}
	// if strings.HasPrefix(pattern, "{**}") {
	// 	pattern = pattern[4:]
	// 	if len(name) < 1 {
	// 		return false
	// 	}

	// 	// Find the next literal in pattern after {**}
	// 	nextLiteral := 0
	// 	for nextLiteral < len(pattern) && strings.ContainsAny(string(pattern[nextLiteral]), "*?{}!") {
	// 		nextLiteral++
	// 	}
	// 	// If no next literal, consume everything
	// 	if nextLiteral == len(pattern) {
	// 		return true
	// 	}

	// 	// Otherwise, try consuming 1..len(name) chars until the next literal matches
	// 	for i := 1; i <= len(name); i++ {
	// 		if recursiveMatch(pattern, name[i:]) {
	// 			return true
	// 		}
	// 	}
	// 	return false
	// }

	if strings.HasPrefix(pattern, "**") {
		pattern = pattern[2:]
		// can consume zero or more chars including dot
		for i := 0; i <= len(name); i++ {
			if recursiveMatch(pattern, name[i:]) {
				return true
			}
		}
		return false
	}

	for pattern != "" { //len(pattern) > 0 {
		// Handle multi-char token {*}
		if strings.HasPrefix(pattern, "{*}") {
			// consume the token
			pattern = pattern[3:]
			// Match one or more chars (but not dot): we must ensure we don't consume dots.
			// find max2 run of non-dot chars at start of name
			max2 := 0
			for j := 0; j < len(name) && name[j] != '.'; j++ {
				max2 = j + 1
			}
			// must match at least one char
			if max2 < 1 {
				return false
			}
			for i := 1; i <= max2; i++ {
				if recursiveMatch(pattern, name[i:]) {
					return true
				}
			}
			return false
		}

		switch pattern[0] {
		case '*':
			// Match zero or more chars, but stop at dot
			for i := 0; i <= len(name); i++ {
				if i < len(name) && name[i] == '.' {
					if recursiveMatch(pattern[1:], name[i:]) {
						return true
					}
					break
				}
				if recursiveMatch(pattern[1:], name[i:]) {
					return true
				}
			}
			return false

		case '?':
			// Match 1 char, NOT dot
			if len(name) == 0 || name[0] == '.' {
				return false
			}
			pattern = pattern[1:]
			name = name[1:]

		case '!':
			// Match 1 char, ANY (including dot)
			if len(name) == 0 {
				return false
			}
			pattern = pattern[1:]
			name = name[1:]

		default:
			// Literal char match
			if len(name) == 0 || pattern[0] != name[0] {
				return false
			}
			pattern = pattern[1:]
			name = name[1:]
		}
	}
	return len(name) == 0
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

func generateCertIfNeeded() {
	mainLogger.Debug("check if cert is valid or needs regen")
	certFile := "cert.pem"
	keyFile := "key.pem"
	needsRegen := false

	var err error
	// Extract the host/IP from the config to put it in the cert
	host, _, err := net.SplitHostPort(config.ListenDoH)
	if err != nil {
		host = config.ListenDoH // Fallback if no port present
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
		mainLogger.Warn("Cert file doesn't exist", slog.String("file", certFile), slog.Any("err", err)) // no \n
		needsRegen = true
	} else {
		// Parse the PEM
		block, _ := pem.Decode(certBytes)
		if block == nil {
			mainLogger.Warn("Cert file had empty decoded block.", slog.String("file", certFile)) // no \n
			needsRegen = true
		} else {
			cert, err2 := x509.ParseCertificate(block.Bytes)
			if err2 != nil {
				mainLogger.Warn("Cert file failed parsing", slog.String("file", certFile), slog.Any("err", err2)) // no \n
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
					mainLogger.Warn("Cert identity mismatch", slog.String("want", host)) // no \n
					needsRegen = true
				}
			}
		}
	}

	// 3. Regen if necessary
	if needsRegen {
		mainLogger.Warn("Due to above, regenerating self-signed cert(files: %s and %s) for DoH at %s...\n", slog.String("public_key_aka_cert_file", certFile), slog.String("private_key_file", keyFile),
			slog.String("sni_hostname", host))
		if err = generateCert(certFile, keyFile, host); err != nil {
			//done: need to unify logging errors in log and on console somehow, this printf and errorLogger thing is a mess.
			//fmt.Printf("Cert generation failed, err: '%v'", err)
			logFatal("cert generation failed", err) //slog.Any("err", err))
			//os.Exit(1)
		}
		mainLogger.Info("Cert generated: make sure you trust it in clients eg. in Firefox load the IP as url and add a cert exception", slog.Any("IP", currentIP))
	} else {
		mainLogger.Info("Existing cert is valid for host. Skipping generation.", slog.String("sni_hostname", host))
	}

	// Load cert/key into global for reuse
	mainLogger.Info("Loading cert/key for DoH...")

	dohCert, err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		// errorLogger.Error("cert_load_failed", slog.Any("err", err))
		// os.Exit(1)
		logFatal("cert_load_failed", err)
	}
	mainLogger.Info("Success - loaded into tls.Certificate")
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
func startDNSListener(addr string) {
	//	listenerErrs.Add(1)
	//	defer listenerErrs.Done()
	mainLogger.Info("Starting DNS listener", slog.String("addr", addr))

	// UDP
	mainLogger.Info("Attempting UDP bind for DNS listener...")

	// Assuming addr is a string like "127.0.0.1:53"
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		mainLogger.Error("invalid UDP address", slog.String("addr", addr), slog.Any("err", err))
		os.Exit(1) //FIXME: see the below comment
	}
	udpLn, err := net.ListenUDP("udp", udpAddr)

	if err != nil {
		mainLogger.Error("UDP bind/listen failed", slog.String("addr", addr), slog.Any("err", err))
		shutdown(1)
		//os.Exit(1) //FIXME: need to use winbollocks' dual deferrers as the traps for clean exit and thus have only 1-2 os.Exit in whole program!
	} else {
		shutdownWG.Add(1) // +1 for the Main UDP Loop

		go func() { //we won't be blocking here.
			defer shutdownWG.Done()
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
			shutdownWG.Add(1) // +1 for the UDP Shutdown Watcher
			go func() {
				defer shutdownWG.Done()
				<-backgroundCtx.Done()
				// We call Close here to unblock the Read/Accept loop immediately.
				// If this runs, the 'defer' above will just return an error later.
				closer()
			}()
			mainLogger.Info("UDP DNS listening success", slog.String("addr", addr))

			//buf := make([]byte, 512+512)
			// FIX: Use a 4096-byte buffer to safely accommodate modern EDNS0 UDP packets
			buf := make([]byte, 4096)

			//TheFor:
			for {
				n, clientAddr, err2 := udpLn.ReadFromUDP(buf)
				if err2 != nil {
					select {
					case <-backgroundCtx.Done():
						// to see this you've to wait like 1 sec in shutdown() or that "press a key" msg does it.
						mainLogger.Debug("UDP DNS listener is quitting due to shutdown...")

						return // Quit on shutdown
					default:
						//runtime.Gosched()  // Yield to scheduler on error (deep yield, 0% CPU during)
						mainLogger.Warn("UDP DNS listener udp_read_error", slog.Any("err", err2))
						//time.Sleep(100 * time.Millisecond)
						//break TheFor
						continue // Real network error, keep trying
					} //select
				} //if err2

				//fmt.Printf("UDP dns client connected(early printf logging), addr=%v\n", clientAddr)
				mainLogger.Debug("client connected(early logging)",
					slog.String("proto", "UDP"),
					slog.Any("clientAddr", clientAddr),
					//slog.Any("pid", pid),
					//slog.String("exe", exe),
					//slog.String("service", serviceInfo),
					//slog.Any("err", err),
				)

				if n > len(buf) {
					panic(fmt.Sprintf("n>len(buf) aka %d>%d", n, len(buf)))
				}

				//FIXME: this below(until the goroutine) slows down things here before going to the next ReadFromUDP aka client (above) again! could move these into the below goroutine but then XXX: it's gonna be too late to get the pid of the exe that just did this connection because it's gone from the list of UDP conns!

				// Create a distinct copy for the background worker
				wireCopy := make([]byte, n)
				copy(wireCopy, buf[:n])

				pid, exe, err2 := wincoe.PidAndExeForUDP(clientAddr)
				// wincoe.Smashy()
				// pid := uint32(1)
				// exe := "foo"
				// err = nil

				udpPacketCtx := makeClientInfoContext(backgroundCtx /* this is your global shutdown ctx*/, "UDP", clientAddr, pid, exe, err2)
				//go handleUDP(udpPacketCtx, wireCopy, clientAddr, udpLn)
				// TRACK INDIVIDUAL REQUESTS:
				shutdownWG.Add(1)
				go func(pCtx context.Context, data []byte, addr *net.UDPAddr, ln *net.UDPConn) {
					defer shutdownWG.Done()
					handleUDP(pCtx, data, addr, ln)
				}(udpPacketCtx, wireCopy, clientAddr, udpLn)
			} //infinite 'for'
		}()
	} // else

	// TCP
	mainLogger.Info("Attempting TCP bind for DNS listener...")

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr) // parses, no DNS for literal IPs, FIXME: this shouldn't attempt to DNS resolve the hostname!
	if err != nil {
		// errStr := fmt.Sprintf("TCP bind failed(the address should be an IP) on %q: %v", addr, err)
		// fmt.Fprintln(os.Stderr, "Failed\n"+errStr)
		//errorLogger.Error(errStr)
		mainLogger.Error("invalid TCP address", slog.String("addr", addr), slog.Any("err", err))
		os.Exit(1)
	}
	tcpLn, err := net.ListenTCP("tcp", tcpAddr) // returns *net.TCPListener

	if err != nil {
		//errStr := fmt.Sprintf("TCP bind failed on %q: %v", addr, err)
		//fmt.Fprintln(os.Stderr, "Failed\n"+errStr)
		//errorLogger.Error(errStr)
		mainLogger.Error("TCP bind/listen failed", slog.String("addr", addr), slog.Any("err", err))
		os.Exit(1)
	} else {
		// caller provides ctx context.Context and tcpLn *net.TCPListener
		shutdownWG.Add(1) // +1 for the Main TCP Loop
		go func() {
			defer shutdownWG.Done()

			closer := func() {
				err := tcpLn.Close()
				_ = err
			} // just in case we exit via non-shutdown(x)
			defer closer()
			// In a separate goroutine watch for shutdown and close the listener
			shutdownWG.Add(1) // +1 for the TCP Shutdown Watcher
			go func() {
				defer shutdownWG.Done()
				<-backgroundCtx.Done()
				closer() // This wakes up Accept() with an error safely
			}()
			fmt.Println("Success")
			fmt.Printf("TCP DNS listening on %q\n", addr)

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
				// 	mainLogger.Warn("can't set TCP deadline", slog.Any("err", err))
				// 	panic("wtw")
				// }

				conn, err := tcpLn.Accept()
				if err != nil {
					// if context canceled, exit cleanly
					select {
					case <-backgroundCtx.Done():
						mainLogger.Debug("TCP DNS listener is quitting due to shutdown...")
						return
					default:
						// // handle timeout-like errors (due to SetDeadline)
						// // 1. Declare a variable for the interface you're looking for
						// var netErr net.Error
						// // 2. Use errors.As to check if 'err' (or anything it wraps) is a net.Error
						// if errors.As(err, &netErr) && netErr.Timeout() {
						// 	// reset backoff and continue
						// 	backoff = 0
						// 	continue
						// }

						// non-temporary error: log, backoff a bit to avoid hot loop, continue
						//fmt.Println("tcp accept error:", err)
						mainLogger.Warn("tcp_accept_error", slog.Any("err", err))

						// if backoff == 0 {
						// 	backoff = 50 * time.Millisecond
						// } else if backoff < 1*time.Second {
						// 	backoff *= 2
						// }
						// mainLogger.Debug("DNS TCP accept sleeping", slog.Any("milliseconds", backoff))
						// time.Sleep(backoff)
						continue
					} // select
				} // if err

				tcpPacketCtx := backgroundCtx /* this is your global shutdown ctx*/
				// 1. Get the remote address as a *net.TCPAddr
				clientAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
				mainLogger.Debug("client connected(early logging)",
					slog.String("proto", "TCP"),
					slog.Any("clientAddr", clientAddr))
				if !ok {
					mainLogger.Warn("could not cast remote addr to TCPAddr", slog.Any("addr", conn.RemoteAddr()))
					//FIXME: when can this happen?!
				} else {
					//FIXME: this slows down things here until it's ready to tcpLn.Accept() (above) again!
					// 2. Call your new TCP PID/Exe helper
					pid, exe, err := wincoe.PidAndExeForTCP(clientAddr)
					// wincoe.Smashy()
					// pid := uint32(2)
					// exe := "foo2"
					// err = nil
					tcpPacketCtx = makeClientInfoContext(tcpPacketCtx, "TCP", clientAddr, pid, exe, err)
				}

				// accepted a connection; handle in new goroutine
				// go func(c net.Conn) {
				// 	defer func() { _ = c.Close() }()
				// 	handleTCP(tcpPacketCtx, c)
				// }(conn)

				//XXX: tcpPacketCtx is passed as arg(instead of as above commented out code) because: "Because that goroutine might not start instantly, the loop might move on to the next connection before the first goroutine actually reads the value of tcpPacketCtx." - Gemini 3 Thinking
				// TRACK INDIVIDUAL CONNECTIONS:
				shutdownWG.Add(1)
				go func(c net.Conn, pCtx context.Context) {
					defer shutdownWG.Done() // This fires when handleTCP returns
					defer c.Close()
					handleTCP(pCtx, c)
				}(conn, tcpPacketCtx)
			}
		}()

	}
	if udpLn == nil && tcpLn == nil {
		mainLogger.Warn("No DNS listeners(neither TCP nor UDP!")
	}
}

func makeClientInfoContext(ctx context.Context, protocol string, clientAddr net.Addr, pid uint32, exe string, err error) context.Context {
	var services []string
	var serviceInfo string
	if err != nil {
		mainLogger.Warn("couldn't get pid and exe name",
			slog.String("proto", protocol),
			slog.Any("clientAddr", clientAddr),
			slog.Any("err", err))
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
			serviceInfo = fmt.Sprintf("err:%v", err)
		} else {
			if len(services) > 0 {
				serviceInfo = fmt.Sprintf("%d service(s): %v", len(services), services)
			} else {
				serviceInfo = "no services"
			}
		}
	}

	mainLogger.Debug("client connected",
		slog.String("proto", protocol),
		slog.Any("clientAddr", clientAddr),
		slog.Any("pid", pid),
		slog.String("exe", exe),
		slog.String("service", serviceInfo),
		slog.Any("err", err),
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

func handleUDP(ctx context.Context, wire []byte, clientAddr *net.UDPAddr, ln *net.UDPConn) {
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		// Edge: Invalid packet (common in floods)
		mainLogger.Warn("invalid DNS UDP packet (couldn't Unpack) thus dropped/ignored", slog.Any("err", err))
		return
	}
	resp := handleDNSQuery(ctx, msg, clientAddr.String())
	if resp == nil {
		return // Drop
	}
	pack, err := resp.Pack()
	if err != nil {
		mainLogger.Warn("failed to pack DNS UDP packet response thus not sent", slog.Any("err", err))
		return
	}
	wroteN, err := ln.WriteToUDP(pack, clientAddr)
	if err != nil {
		mainLogger.Warn("failed to write to UDP the DNS packet response", slog.Any("err", err), slog.Int("wrote_bytes", wroteN), slog.Int("shoulda_written", len(pack)))
		return
	}
}

func handleTCP(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	const timeoutSeconds = 5 //XXX: that is per operation: read 2 bytes, read the body, write the response; so each 3 operations get this timeout!
	const timeoutDuration time.Duration = timeoutSeconds * time.Second
	const maxDNSTCPPacketSize = 65535

	// --- 1. READ THE LENGTH HEADER ---
	// We give the client 5 seconds to send just these 2 bytes.
	_ = conn.SetReadDeadline(time.Now().Add(timeoutDuration))

	const TWO = 2
	buf := make([]byte, TWO)
	if n, err := io.ReadFull(conn, buf); err != nil {
		mainLogger.Warn("couldn't read 2 bytes from TCP DNS connection, thus dropped/ignored", slog.Any("err", err), slog.Int("read_bytes", n),
			slog.Int("wanted_to_read_bytes", TWO), slog.Any("timeout", timeoutDuration))
		return
	}
	length := int(binary.BigEndian.Uint16(buf))
	if length > maxDNSTCPPacketSize || length == 0 { // Edge: Oversize packet
		mainLogger.Warn("invalid packet length in TCP DNS connection, thus dropped/ignored", slog.Int("actual_bytes", length), slog.Any("max", maxDNSTCPPacketSize),
			slog.Any("min", 1))
		return
	}

	// --- 2. READ THE BODY ---
	// We REFRESH the deadline. The client gets a fresh 5 seconds
	// to finish sending the actual DNS message.
	_ = conn.SetReadDeadline(time.Now().Add(timeoutDuration))
	wire := make([]byte, length)
	if n, err := io.ReadFull(conn, wire); err != nil {
		mainLogger.Warn("couldn't read some bytes from TCP DNS connection, thus dropped/ignored", slog.Any("err", err), slog.Int("read_bytes", n), slog.Int("wanted_to_read_bytes", length),
			slog.Any("timeout", timeoutDuration))
		return
	}

	// --- 3. PROCESS ---
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		mainLogger.Warn("invalid DNS TCP packet (couldn't Unpack) thus dropped/ignored", slog.Any("err", err))
		return
	}

	resp := handleDNSQuery(ctx, msg, conn.RemoteAddr().String())
	// --- 4. WRITE THE RESPONSE ---
	if resp != nil {
		pack, err := resp.Pack() // Ignore err
		if err != nil {
			mainLogger.Warn("failed to pack DNS TCP packet response thus not sent", slog.Any("err", err))
			return
		}
		// Prepare the output (length + payload)
		out := new(bytes.Buffer)
		err = binary.Write(out, binary.BigEndian, uint16(len(pack))) // Single err return
		if err != nil {
			mainLogger.Warn("failed to write-to-the-buffer the pack len (2 bytes) of the TCP DNS packet response", slog.Any("err", err))
			return
		}
		out.Write(pack)
		// Set a WRITE deadline. This prevents a "slow receiver" from
		// hanging your goroutine forever while you try to push data.
		_ = conn.SetWriteDeadline(time.Now().Add(timeoutDuration))
		wroteN, err := conn.Write(out.Bytes())
		if err != nil {
			mainLogger.Warn("failed to write to TCP the DNS packet response body", slog.Any("err", err), slog.Int("wrote_bytes", wroteN),
				slog.Int("shoulda_written", len(pack)), slog.Any("timeout", timeoutDuration))
			return
		}
	}
	mainLogger.Warn("No TCP DNS response to write, filtered out maybe? Shouldn't happen tho. FIXME")
}

// non-blocking!
func startDoHListener(addr string) {
	fmt.Printf("Starting DoH listener on %q...\n", addr)

	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", dohHandler)

	fmt.Print("  Attempting TLS bind...")
	listener, err := tls.Listen("tcp", addr, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{dohCert}, // Use loaded cert
	})
	if err != nil {
		// errStr := fmt.Sprintf("DoH listener failed on %q: %v", addr, err)
		// fmt.Fprintln(os.Stderr, "Failed\n"+errStr)
		// errorLogger.Error(errStr)
		mainLogger.Error("DoH listener failed to bind/listen", slog.String("addr", addr), slog.Any("err", err))
		os.Exit(1) // Fail-fast serial
	}
	fmt.Println("Success")
	fmt.Printf("DoH listening on %q\n", addr)

	dohSrv := &http.Server{Handler: mux,
		ReadTimeout:  30 * time.Second, // Workaround for CPU/timer bug
		WriteTimeout: 30 * time.Second, // Optional, for responses
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
	shutdownWG.Add(1)
	// Listen for the global shutdown signal to gracefully close the DoH server
	go func() {
		defer shutdownWG.Done() // Signal this watcher is finished
		<-backgroundCtx.Done()
		mainLogger.Debug("Shutting down DoH server...")
		// Give it a max of 3 seconds to finish existing requests before force closing
		shutdownCtx, cancelDown := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancelDown()
		_ = dohSrv.Shutdown(shutdownCtx)
	}()

	shutdownWG.Add(1)
	go func() {
		defer shutdownWG.Done() // Signal the server is officially stopped

		defer listener.Close() // Graceful close on shutdown
		//doneFIXME: how do we know if this failed to maybe restart it or exit the whole program or whatever!?
		if err := dohSrv.Serve(listener); err != nil && err != http.ErrServerClosed {
			mainLogger.Error("doh_serve_failed", slog.Any("err", err))
			errChan <- fmt.Errorf("DoH server failed: %w", err)
		}
	}()
	fmt.Println("DoH server loop launched in goroutine - func returning")
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

func dohHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context() // Get the request context

	var err error
	// 1. Identify the client immediately, before replying.
	//Since you are performing the PID lookup inside the handler (before sending the response), the TCP connection is guaranteed to be in the ESTABLISHED state.
	// Firefox is sitting there waiting for its DNS-over-HTTPS answer, so it's the perfect time to "catch" it in the Windows TCP table.
	remoteTCP, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err == nil {
		mainLogger.Debug("client connected(early logging)",
			slog.String("proto", "DoH"),
			slog.Any("clientAddr", remoteTCP))
		// Use our TCP PID helper
		pid, exe, pErr := wincoe.PidAndExeForTCP(remoteTCP)
		// wincoe.Smashy()
		// pid := uint32(3)
		// exe := "foo3"
		// var pErr error = nil
		ctx = makeClientInfoContext(ctx, "DoH", remoteTCP, pid, exe, pErr)
	} else {
		mainLogger.Warn("DoH: could not resolve remote addr", slog.String("addr", r.RemoteAddr))
		//FIXME: this is a bigger problem than a WARN, if it happens! but an ERROR here would make it mix with the red colored blocked requests, thus harder to be seen!
		//TODO: see if we can trigger this! and/or think of what happens if it happens!
	}

	if r.Method != "POST" && r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body []byte

	if r.Method == "POST" {
		// FIX: Limit incoming DoH payload to 64KB to prevent memory exhaustion attacks
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
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
		http.Error(w, fmt.Sprintf("Failed to unpack DNS query, err:%v", err2), http.StatusInternalServerError)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	resp := handleDNSQuery(ctx, msg, r.RemoteAddr) // Field, not method
	if resp == nil {
		mainLogger.Warn("empty DNS response, replying to client with service unavailable", slog.String("client", r.RemoteAddr))
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	pack, err := resp.Pack()
	if err != nil {
		mainLogger.Warn("doh_pack_response_to_client_failed", slog.Any("err", err), slog.String("client", r.RemoteAddr))
		// Return a 500 error to the DoH client
		http.Error(w, "Failed to pack DNS response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Content-Length", fmt.Sprint(len(pack)))
	w.WriteHeader(http.StatusOK)
	wroteN, err := w.Write(pack)
	if err != nil {
		mainLogger.Warn("failed to write the DoH reply to client (the DNS packet response body)", slog.Any("err", err), slog.Int("wrote_bytes", wroteN), slog.Int("shoulda_written", len(pack)))
		return
	}
}

func handleDNSQuery(ctx context.Context, msg *dns.Msg, clientAddr string) *dns.Msg {
	if len(msg.Question) != 1 {
		return formerrResponse(msg)
	}
	q := msg.Question[0]
	domain := strings.ToLower(strings.TrimSuffix(q.Name, ".")) //XXX: must lowecase it for matchPattern below! at least.
	if domain == "" {                                          // Edge: Empty domain
		return formerrResponse(msg)
	}
	qtype := dns.TypeToString[q.Qtype] // Map lookup

	// Rate limit
	gl := globalLimiter.Allow()
	clIface, _ := clientLimiters.LoadOrStore(clientAddr, rate.NewLimiter(10, 100)) // Per-client 10qps/100 burst, FIXME: is this in config.json ? or should it be!
	cl := clIface.(*rate.Limiter)
	if !gl || !cl.Allow() {
		mainLogger.Warn("rate_limit_exceeded", slog.String("client", clientAddr))
		return servfailResponse(msg)
	}

	// Whitelist
	ruleMutex.RLock()
	rules := whitelist[qtype]
	matchedID := "" // must be empty, used in 2 logical places, one's here.
	matched := false
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
	if config.AllowHTTPSIfAAllowed && !matched && qtype == "HTTPS" {
		for _, rule := range whitelist["A"] {
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

	ruleMutex.RUnlock()
	if !matched {
		stats.Add(1)
		func() {
			blockMutex.Lock()
			defer blockMutex.Unlock() // Executes even if the code below panics
			recentBlocks = append(recentBlocks, BlockedQuery{Domain: domain, Type: qtype, Time: time.Now()})
			if len(recentBlocks) > 50 {
				recentBlocks = recentBlocks[1:]
			}
			//blockMutex.Unlock()
		}() // Notice the parens here to call it immediately
		blocked := blockResponse(msg)
		logQuery(ctx, clientAddr, domain, qtype, "blocked", "", nil, blocked)
		return blocked
	}

	// Cache (edge: Negative responses cached short)
	key := domain + ":" + qtype

	//fmt.Printf("checking '%s' key in cache\n", key)
	if cachedIf, ok := cacheStore.Get(key); ok {
		cached := cachedIf.(*dns.Msg)
		// Return a copy of cached response with the current query ID to avoid
		// clients rejecting replies because of mismatched transaction IDs.
		resp := cached.Copy()
		resp.Id = msg.Id
		//fmt.Printf("found '%s' key in cache as: '%s' aka %+v aka %#v\n", key, resp.String(), resp, resp)
		ips := extractIPs(resp)
		logQuery(ctx, clientAddr, domain, qtype, "cache_hit", matchedID, ips, resp)
		return resp
	}

	// --- START Local Hosts Override ---
	var hasLocalHost bool
	var matchedIPs []net.IP
	func() {
		localHostsMu.RLock()
		defer localHostsMu.RUnlock() // maybe it panics so unlock it even then!
		for _, rule := range localHosts {
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

		const timeUntilLocalHostsExpireInSeconds = 300
		for _, ip := range matchedIPs {
			isIPv4 := ip.To4() != nil

			if qtype == "A" && isIPv4 {
				rr := new(dns.A)
				rr.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: timeUntilLocalHostsExpireInSeconds}
				rr.A = ip
				resp.Answer = append(resp.Answer, rr)
			} else if qtype == "AAAA" && !isIPv4 {
				rr := new(dns.AAAA)
				rr.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: timeUntilLocalHostsExpireInSeconds}
				rr.AAAA = ip
				resp.Answer = append(resp.Answer, rr)
			}
		}

		// Cache this override so subsequent queries bypass the pattern loop
		cacheStore.Set(key, resp.Copy(), timeUntilLocalHostsExpireInSeconds*time.Second) //TODO: configurable cache time and dns record aka ttl time? (see above)

		logQuery(ctx, clientAddr, domain, qtype, "local_host_override", "", extractIPs(resp), resp)
		return resp
	}
	// --- END Local Hosts Override ---

	// Forward to upstream DNS
	// 1. Save the original client ID
	oldID := msg.Id
	msg.Id = getSecureID() // 2. Generate a random ID for the upstream query (helps prevent cache poisoning)
	// 3. DO THE ACTUAL UPSTREAM QUERY
	resp := forwardToDoH(msg)
	// 4. Restore the original ID so the client's DNS resolver accepts the answer
	if resp != nil {
		resp.Id = oldID
	}
	//Gemini 3 Thinking: "The ID Matching is a "defense in depth" move. By using a random ID for the journey to Quad9 and back, you decouple your internal network's IDs from the public internet,
	// making it much harder for someone to inject fake DNS responses into your proxy."
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		ips := []string{} //{"NXDOMAIN"}
		if resp != nil {
			ips = append(ips, fmt.Sprintf("dns.Rcode:%d", resp.Rcode))
		}
		negResp := servfailResponse(msg)
		logQuery(ctx, clientAddr, domain, qtype, "forwarded_but_FAILED_so_NXDOMAIN", matchedID, ips, negResp)
		// Cache negatives short
		//cacheStore.Set(key, negResp, 2*time.Second) // time to cache negatives TODO: make this user setable in config.json
		// FIX: Store a copy of the negative response as well
		cacheStore.Set(key, negResp.Copy(), 2*time.Second) // time to cache negatives TODO: make this user setable in config.json
		return negResp
	}

	ips := extractIPs(resp) //before 'resp' gets mutated, and its IPs deleted.
	// Filter
	filtered := filterResponse(resp) //, responseBlacklist)
	if filtered == nil {
		logQuery(ctx, clientAddr, domain, qtype,
			"blockedByUpstream_ORIGINAL", //FIXME: this here is a guess because the upstream answer was filtered out likely due to having an IP like 0.0.0.0 returned, but could also be any of the blocked IPs specified in the config like 127.0.0.1/8 or 192.168.0.0/16 therefore this could mean the upstream tried to return a local or LAN IP but we stripped it out and we should notify accordingly! not just say that upstream blocked the hostname request which it only does if IP was 0.0.0.0 and nothing else.
			matchedID, ips, resp)         //FIXME: 'resp' here isn't the original, we should make a copy of it like we did above for its 'ips' and use that here.
		blocked := blockResponse(msg)
		ips = extractIPs(blocked)
		logQuery(ctx, clientAddr, domain, qtype,
			"blockedByUpstream_RETURNEDMODIFIED", //FIXME: this here is a guess because the upstream answer was filtered out likely due to having an IP like 0.0.0.0 returned, but could also be any of the blocked IPs specified in the config like 127.0.0.1/8 or 192.168.0.0/16 therefore this could mean the upstream tried to return a local or LAN IP but we stripped it out and we should notify accordingly! not just say that upstream blocked the hostname request which it only does if IP was 0.0.0.0 and nothing else.
			matchedID, ips, blocked)
		return blocked
	}

	// Cache with clamped TTL
	ttl := computeTTL(filtered)
	expiry := time.Duration(ttl) * time.Second
	if expiry < time.Duration(config.CacheMinTTL)*time.Second {
		expiry = time.Duration(config.CacheMinTTL) * time.Second
	}

	//cacheStore.Set(key, filtered, expiry)
	// FIX: Store a copy in the cache, not the pointer you are about to return
	cacheStore.Set(key, filtered.Copy(), expiry)

	ips = extractIPs(filtered)
	logQuery(ctx, clientAddr, domain, qtype, "forwarded", matchedID, ips, filtered)

	return filtered
}

func computeTTL(msg *dns.Msg) int {
	minTTL := 3600 // Default 1h
	for _, rr := range msg.Answer {
		if int(rr.Header().Ttl) < minTTL {
			minTTL = int(rr.Header().Ttl)
		}
	}
	if minTTL == 0 { // Edge: Zero TTL
		minTTL = 60
	}
	return minTTL
}

var (
	//dohClient    *http.Client
	dohTransport *http.Transport //protected by dohMu, used only to clean up during reinit via initDoHClient
	//dohMu        sync.RWMutex
	//atomicDohClient atomic.Pointer[http.Client]
	dohClientPtr atomic.Pointer[http.Client]
	dohMu        sync.Mutex // Only used for initialization/reloads
)

// call once at startup or when upstream config changes
func initDoHClient() *http.Client { //upstreamIP, sni string) {
	//What this function does is purely preparatory. You are assembling a plan for future connections, not executing one.
	//Here’s why nothing goes on the network yet:
	//The http.Transport you create is just configuration.
	//DialContext is a callback, not an action. Go stores that function and promises to call it later only when a request actually needs a connection.
	//CloseIdleConnections() is the only thing here that might touch sockets — and even then, only previously established idle ones. If this is the first init, or if no DoH requests were ever made, there’s nothing to close and nothing goes out.
	//http.Client and http.Transport are blueprints, not engines.
	mainLogger.Debug("starting initDoHClient()")
	// 3. LOCK (Slow path, ensures only one goroutine builds the client)
	dohMu.Lock()
	defer dohMu.Unlock()
	mainLogger.Debug("past lock in initDoHClient()")
	// 4. DOUBLE CHECK
	// While we were waiting for the lock, someone else might
	// have finished the initialization. Check again.
	if current := dohClientPtr.Load(); current != nil {
		return current
	}
	// 5. DO THE ACTUAL WORK
	// Build your transport, tls config, etc.

	if dohTransport != nil {
		dohTransport.CloseIdleConnections()
	}
	// --- PRE-COMPUTE DIAL ADDRESS ONCE ---
	const ImpliedPort string = "443"
	port := upstreamURL.Port()
	if port == "" {
		// Log this only once when the client initializes, not on every connection!
		mainLogger.Warn("Using implied port for DoH upstream",
			slog.String("implied_port", ImpliedPort),
			slog.Any("upstreamURL", upstreamURL))
		port = ImpliedPort
	}

	// Create the final "IP:Port" string once
	dialAddr := net.JoinHostPort(upstreamIP, port)
	// --------------------------------------
	t := &http.Transport{
		// Dial raw TCP to the chosen IP so we don't perform DNS resolution here.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 3 * time.Second} //TODO: make this configurable in config.json or const!
			// Use the pre-computed dialAddr captured via closure!
			mainLogger.Debug("(re)connected to upstream DoH", slog.Any("dialAddr", dialAddr))
			return d.DialContext(ctx, network, dialAddr)
			//return d.DialContext(ctx, network, net.JoinHostPort(upstreamIP, port)) //doneFIXME: port 443 is hardcoded instead of used from config.json !
		},
		TLSClientConfig: &tls.Config{
			ServerName:         config.SNIHostname,
			InsecureSkipVerify: false,
		},
		Proxy:               nil,              // avoid proxy interference
		ForceAttemptHTTP2:   true,             // allow http2 negotiation via ALPN (needed for 9.9.9.9 due to it saying this "This server implements RFC 8484 - DNS Queries over HTTP, and requires HTTP/2 in accordance with section 5.2 of the RFC."
		IdleConnTimeout:     90 * time.Second, //TODO: make these configurable in config.json
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
	}

	dohTransport = t
	newDoHClient := &http.Client{
		Timeout:   5 * time.Second, // overall per-request timeout
		Transport: dohTransport,
	}
	// 6. ATOMIC STORE
	dohClientPtr.Store(newDoHClient)
	mainLogger.Info("DoH client initialized/reloaded")
	mainLogger.Debug("ending initDoHClient()")
	return newDoHClient
}

// forwardToDoH uses the preinitialized dohClient and supports one retry on transient network errors.
func forwardToDoH(req *dns.Msg) *dns.Msg {
	reqBytes, err := req.Pack()
	if err != nil {
		mainLogger.Error("doh_prepost_pack_failed", slog.Any("err", err))
		//fmt.Println("Failed to pack query for upstreaming it to DNS server:", err)
		return nil
	}

	// create request with supplied context so caller controls deadline/cancel
	makeReq := func() (*http.Request, error) {
		r, err2 := http.NewRequestWithContext(backgroundCtx, "POST", upstreamURL.String(), bytes.NewReader(reqBytes))
		if err2 != nil {
			mainLogger.Error("doh_newrequest_failed", slog.Any("err", err2))
			//fmt.Println("Failed to create upstream request:", err)
			return nil, err2
		}
		r.Header.Set("Content-Type", "application/dns-message")
		if config.SNIHostname != "" {
			r.Host = config.SNIHostname
			//fmt.Println("Using http header hostname:", r.Host)
		}
		return r, nil
	}
	//fmt.Println("Using servername: !", config.SNIHostname,"! and upstreamIP: !",upstreamIP,"!")
	var resp *http.Response
	//var attempt int
	//for attempt = 0; attempt < 2; attempt++ {
	retries := config.UpstreamRetriesPerQuery
	if retries < 1 {
		retries = 0 // Sanity check: must attempt at least once(see the 'for' below)
	}
	maxTries := 1 + retries
	for attempt := range maxTries { //doneTODO: make this setable or const: number of tries to forward the DNS query to upstream if it failed.
		// 1. ATOMIC LOAD (Fast path, no locking)
		dohClient := dohClientPtr.Load()
		//Since forwardToDoH gets its own local copy of the pointer from .Load(), even if a Ctrl+R swap happens in the middle of a request, that specific request finishes
		// using the "old" client safely. The old client is then garbage collected naturally when the function returns.

		if dohClient == nil {
			// defensive: initialize if not yet done (use current config)
			dohClient = initDoHClient() // Inside this, you already have a Lock()
		}
		if dohClient == nil {
			panic("dohClient still nil after init! shouldn't happen")
		}

		req2, err2 := makeReq()
		if err2 != nil {
			mainLogger.Error("doh_newrequest_failed", slog.Any("err", err2))
			//fmt.Println("Failed to create upstream request:", err)
			return nil
		}

		resp, err2 = dohClient.Do(req2) // this is concurrency safe
		if err2 == nil {
			//success!
			break
		}

		// decide if error is transient/retryable
		// common retryable errors: temporary network errors, EOF, connection reset
		var netErr net.Error
		isRetryable := errors.Is(err2, io.EOF) ||
			errors.Is(err2, io.ErrUnexpectedEOF) ||
			errors.Is(err2, syscall.ECONNRESET) || // Since you are on Windows, syscall.ECONNRESET is actually mapped to the Windows-specific WSAECONNRESET code internally by the Go net package, so errors.Is will work correctly across platforms if you ever decide to compile this for Linux/macOS too.
			errors.Is(err2, syscall.ECONNREFUSED) ||
			(errors.As(err2, &netErr) && netErr.Timeout()) //netErr.Timeout(): This is the "official" way to check for timeouts now. It covers both the network dial timing out and your http.Client.Timeout.
		if isRetryable {
			// // Don't retry if the app is shutting down
			// if backgroundCtx.Err() != nil {
			// 	return nil
			// }
			// retry once
			mainLogger.Error("doh_post_transient_error for this query", slog.Any("err", err2), slog.Int("attempt", attempt),
				slog.Int("current_try", attempt), slog.Int("max_tries", maxTries), slog.Any("query", req2),
				slog.Bool("will_retry", attempt < maxTries))
			// small backoff: sleep a bit but respect context
			select {
			case <-time.After(100 * time.Millisecond): //TODO: make the backoff time configurable ? or at least const!
			case <-backgroundCtx.Done():
				fmt.Println("doh sensed quit during retry backoff...")
				return nil
			}
			continue
		}

		// non-retryable error
		mainLogger.Error("Failed to query upstream DNS server", slog.Any("err", err2))
		//fmt.Println("Failed to query upstream DNS server:", err)
		return nil
	}

	if resp == nil {
		// last attempt produced no response (shouldn't happen), treat as failure
		mainLogger.Error("doh_no_response")
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		mainLogger.Error("doh_readbody_failed", slog.Any("err", err))
		return nil
	}

	// debug/log non-200 or unexpected content-type
	if resp.StatusCode != 200 {
		mainLogger.Error("doh_upstream_status", slog.Any("status", resp.Status))
		//fmt.Println("Upstream HTTP status:", resp.Status)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "application/dns-message" {
		mainLogger.Error("doh_upstream_content_type isn't the expected application/dns-message", slog.Any("content_type", ct))
		//fmt.Println("Upstream Content-Type:", ct)
	}
	if len(body) < 12 {
		mainLogger.Error("doh_upstream_body_too_short", slog.Any("len", len(body)))
		//fmt.Println("Upstream body too short:", len(body))
	}
	upMsg := new(dns.Msg)
	if err := upMsg.Unpack(body); err != nil {
		n := len(body)
		mainLogger.Error("doh_unpack_failed", slog.Any("err", err),
			slog.String("body_hex", fmt.Sprintf("Upstream body (hex, first %d): %x\n", n, body[:n])),
			slog.String("body_text", fmt.Sprintf("Upstream body (text, first %d): %q\n", n, body[:n])),
		)
		return nil
	}
	return upMsg

}

// Globals for static data
var (
	// This runs once at startup
	edeText = getBlockedString()
	edeCode = dns.ExtendedErrorCodeBlocked
)

func getBlockedString() string {
	exePath, err := os.Executable()
	if err != nil {
		exePath = "DNSbollocks"
	}
	// Get startup time. "15:04:05" is the Go magic layout for HH:MM:SS
	// You can also use time.DateOnly (2006-01-02) if you prefer
	startTime := time.Now().Format("2006-01-02 15:04:05-0700") // don't need more precision here!

	return fmt.Sprintf("Blocked by %q [which was started on %q]", exePath, startTime)
}

func blockResponse(msg *dns.Msg) *dns.Msg {
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
	if config.BlockAAAAasEmptyNoError && len(msg.Question) > 0 && msg.Question[0].Qtype == dns.TypeAAAA && config.BlockMode == "nxdomain" {
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
	switch config.BlockMode {
	case "nxdomain":
		msg.SetRcode(msg, dns.RcodeNameError)
	case "ip_block", "block_ip":
		ttl := uint32(300)
		blockIP := net.ParseIP(config.BlockIP)
		if blockIP == nil {
			blockIP = net.IPv4(0, 0, 0, 0) // Default, TODO: const or global this!
		}
		if blockIP.To4() != nil { // A record
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
			rr.A = blockIP
			msg.Answer = []dns.RR{rr}
		} else { // AAAA stub
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

	opt.SetDo() // Set the "DNSSEC OK" bit; some browsers require this to process OPT records
	// You can reuse a global EDE struct here IF it is never modified
	opt.Option = []dns.EDNS0{ede}

	msg.Extra = append(msg.Extra, opt)

	return msg

}

// mutates the passed arg
func filterResponse(msg *dns.Msg /*, blacklists []string)*/) *dns.Msg {
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
	// 	_, ipnet, err := net.ParseCIDR(cidr)
	// 	if err == nil {
	// 		nets = append(nets, ipnet)
	// 	} else {
	// 		//hard fail here (it should've alredy failed at startup or at some other future stage when updating the reponse blacklist)
	// 		errorLogger.Error("invalid_cidr", slog.String("cidr", cidr), "context", "in blacklist reponse") // 'go vet' caught it (indirectly via 'go test')
	// 		panic("unreachable2, or the logger is broken")
	// 	}
	// }

	var goodAnswer, goodExtra []dns.RR
	for _, rr := range msg.Answer {
		if keep, modifiedRR := processRR(rr); keep {
			goodAnswer = append(goodAnswer, modifiedRR)
			//fmt.Println("Good inAnswer:",rr)
		} else {
			mainLogger.Warn("Dropped inAnswer from upstream due to containing blocked ip", slog.Any("query_type", qtype), slog.Any("rr", rr))
		}
	}
	for _, rr := range msg.Extra {
		if keep, modifiedRR := processRR(rr); keep {
			goodExtra = append(goodExtra, modifiedRR)
			//fmt.Println("Good inExtra:",rr)
		} else {
			mainLogger.Warn("Dropped inExtra from upstream due to containing blocked ip:", slog.Any("query_type", qtype), slog.Any("rr", rr))
		}
	}

	msg.Answer = goodAnswer
	msg.Extra = goodExtra

	//if len(msg.Answer) == 0 { // this dropped HTTPS replies and they were thus not seen at all, so seen as blockedbyUpstream
	if len(msg.Answer) == 0 && len(msg.Ns) == 0 && len(msg.Extra) == 0 {
		mainLogger.Warn("response_filtered_all", slog.Any("query_type", qtype), slog.String("domain", q.Name))
		return nil
	}
	return msg
}

// filters out unwanteds like the IPs that are returned or ip hints in HTTPS dns types.
// mutates the passed arg!
func processRR(rr dns.RR /*, nets []*net.IPNet*/) (bool, dns.RR) {
	switch r := rr.(type) {
	case *dns.A:
		if IsBlockedIP(r.A) {
			return false, nil
		}
		return true, r

	case *dns.AAAA:
		if IsBlockedIP(r.AAAA) {
			return false, nil
		}
		return true, r

	// Look for HTTPS records (Type 65)
	case *dns.HTTPS:
		//TODO: make this configurable in config.json so only if 'true' do this:
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
				//} else {
				//	fmt.Println("Dropping IP hint from the reply:", param);
				//fmt.Println("NOT Dropping IP hint from the reply:", param);
				//newParams = append(newParams, param)
			} else {
				mainLogger.Warn("Dropping IP hint from the HTTPS reply", slog.Any("param", param))
			}
		}
		r.Value = newParams
		return true, r

	case *dns.RRSIG:
		// Always drop signatures because we are modifying the RRsets they sign.
		// A missing signature is better than a broken one.
		return false, nil

	default:
		// Keep other types (MX, TXT, CNAME, etc.)
		return true, rr
	}
}

// func ipInNets(ip net.IP, nets []*net.IPNet) bool {
// 	for _, n := range nets {
// 		if n.Contains(ip) {
// 			return true
// 		}
// 	}
// 	return false
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

// NEW: action-specific colors (only used for category=query lines)
var QueryActionColors = map[string]uint16{
	"forwarded":                          wincoe.FOREGROUND_BRIGHT_GREEN,
	"cache_hit":                          wincoe.FOREGROUND_BRIGHT_YELLOW,
	"blocked":                            wincoe.FOREGROUND_BRIGHT_RED,
	"rate_limit_exceeded":                wincoe.FOREGROUND_RED,
	"blockedByUpstream_ORIGINAL":         wincoe.FOREGROUND_BRIGHT_RED,
	"blockedByUpstream_RETURNEDMODIFIED": wincoe.FOREGROUND_BRIGHT_RED,
	"forwarded_but_FAILED_so_NXDOMAIN":   wincoe.FOREGROUND_BRIGHT_RED,
	"local_host_override":                wincoe.FOREGROUND_BRIGHT_CYAN,
	// you can add more action → color mappings here
	// unknown actions → fall back to level-based color
}

// func logQuery(client, domain, typ, action, ruleID string, ips []string) {
// 	attrs := []any{
// 		slog.String("client", client),
// 		slog.String("domain", domain),
// 		slog.String("type", typ),
// 		slog.String("action", action),
// 		slog.String("ts", time.Now().Format(time.RFC3339)),
// 	}
// 	if ruleID != "" {
// 		attrs = append(attrs, slog.String("rule_id", ruleID))
// 	}
// 	if len(ips) > 0 {
// 		attrs = append(attrs, slog.String("ips", strings.Join(ips, ",")))
// 	}
// 	queryLogger.Log(ctx, slog.LevelInfo, "query", attrs...)
// }

const TIMESTAMPS_FORMAT string = "2006-01-02 15:04:05.000000000-07:00 MST" // old: /*time.RFC3339*/

func logQuery(ctx context.Context, client, domain, typ, action, ruleID string, ips []string, blocked *dns.Msg) {
	if ctx == nil {
		mainLogger.Error("bad coding: logQuery called with nil context", // should never happen
			slog.String("client", client),
			slog.String("domain", domain))
		return
	}

	var ts string = time.Now().Format(TIMESTAMPS_FORMAT)

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
	// 	// Epic Coding Fail tracker - this should never happen in production
	// 	// attrs = append(attrs, slog.String("metadata_error", "context_missing_client_info"))
	// 	// This is the "Epic Coding Fail" tracker.
	// 	// We add a field to the query log so you can find these easily.
	// 	attrs = append(attrs, slog.String("metadata_error", "context_missing_client_info"))

	// 	// Also, log a separate Error to your main system log/stderr
	// 	// so you get alerted that a handler is broken.
	// 	mainLogger.Warn("coding_fail: logQuery called without metadata in context",
	// 		slog.String("client", client),
	// 		slog.String("domain", domain))
	// } else {
	// --- NEW: Pull the PID/Exe info from the context backpack ---
	if info, ok := ctx.Value(clientInfoKey).(clientMetadata); ok {
		elapsed := time.Since(info.startTime)
		attrs = append(attrs,
			slog.Uint64("pid", uint64(info.pid)),
			slog.String("exe", info.exe),
			slog.String("proto", info.protocol),
			slog.Any("clientAddr", info.clientAddr),
		)
		//To avoid cluttering the console, at least.
		num_services := len(info.services)
		if num_services != 0 {
			attrs = append(attrs,
				slog.Any("services", info.services),
				slog.Int("num_services", num_services),
			)
		}
		if info.err != nil {
			attrs = append(attrs,
				slog.Any("err", info.err),
			)
		}
		attrs = append(attrs,
			slog.String("elapsed", elapsed.String()),
			//slog.Int64("elapsed_ms", elapsed.Milliseconds()),
			slog.Int64("elapsed_ns", elapsed.Nanoseconds()),
			slog.String("client_connected_at_ts", info.startTime.Format(TIMESTAMPS_FORMAT)),
			slog.String("log_ts", ts),
		)
	} else {
		// This is the "Epic Coding Fail" tracker.
		// We add a field to the query log so you can find these easily.
		attrs = append(attrs, slog.String("metadata_error", "context_missing_client_info"))

		// Also, log a separate Error to your main system log/stderr
		// so you get alerted that a handler is broken.
		mainLogger.Warn("coding_fail: logQuery called without metadata in context",
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
		attrs = append(attrs, slog.Any("blocked_dnsMsg", blocked))
	}
	mainLogger.Log(ctx, slog.LevelInfo, "logged_query", attrs...)
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

const hostForUIListener string = "127.0.0.1" //TODO: add this to config, but should start with 127. for security reasons.

func startWebUI(port int) {
	hostOrIp := hostForUIListener
	fmt.Printf("Starting web UI on %s:%d...\n", hostOrIp, port) //FIXME: hardcoded IP

	mux := http.NewServeMux()
	mux.HandleFunc("/", statsHandler)
	mux.HandleFunc("/rules", rulesHandler)
	mux.HandleFunc("/hosts", hostsHandler)
	mux.HandleFunc("/blocks", blocksHandler)
	mux.HandleFunc("/logs", logsHandler)
	mux.HandleFunc("/logs_queries", logsQueriesHandler)
	mux.Handle("/debug/vars", expvar.Handler()) // Stats endpoint

	//FIXME: need the IP to be settable for UI as well, not just the port, else cannot run multiple UIs on diff. localhost IPs w/ same port.
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", hostOrIp, port))
	if err != nil {
		//errStr := fmt.Sprintf("UI listener failed on :%d: %v", port, err)
		//fmt.Fprintln(os.Stderr, "  Attempting UI bind...Failed\n"+errStr)
		//errorLogger.Error(errStr)
		mainLogger.Error("UI listener failed to bind/listen", slog.String("hostOrIp", hostOrIp), slog.Int("port", port), slog.Any("err", err))
		os.Exit(1) // Fail-fast serial
	}
	fmt.Println("  Attempting UI bind...Success")
	fmt.Printf("Web UI listening on %s:%d (stats at /debug/vars)\n", hostOrIp, port) //FIXME: hardcoded IP

	uiSrv := &http.Server{Handler: mux}
	// Listen for the global shutdown signal to gracefully close the Web UI
	shutdownWG.Add(1)
	go func() {
		defer shutdownWG.Done()

		<-backgroundCtx.Done()
		mainLogger.Debug("Shutting down Web UI server...")
		shutdownCtx, cancelDown := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancelDown()
		_ = uiSrv.Shutdown(shutdownCtx)
	}()
	shutdownWG.Add(1)
	go func() {
		defer shutdownWG.Done()

		defer listener.Close() // Graceful close
		if err := uiSrv.Serve(listener); err != nil && err != http.ErrServerClosed {
			//errorLogger.Error("ui_serve_failed", slog.Any("err", err))
			logFatal("ui_serve_failed", err)
			//os.Exit(1) // Fail-fast serial
		}
	}()
	fmt.Println("UI server loop launched")
	fmt.Println("Use Ctrl+X to clean exit, but Ctrl+C works too. Ctrl+R to reload config without exiting.")
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var body strings.Builder
	body.WriteString("<h2>Statistics</h2>")
	fmt.Fprintf(&body, "<p>Blocks: %q</p><p>Cache size: %d</p><p>Upstream IP: %q</p>", stats.String(), cacheStore.ItemCount(), upstreamIP)
	//uiTemplates.Execute(w, struct{ Body template.HTML }{Body: template.HTML(body)}) // Raw HTML, no escape
	data := map[string]any{
		"Page":    "stats",
		"RawBody": template.HTML(body.String()), // Tells template "I'm not ready to be a sub-template yet"
	}
	uiTemplates.Execute(w, data)
}

func snapshotWhitelist() map[string][]RuleEntry {
	ruleMutex.RLock()
	defer ruleMutex.RUnlock()

	copyMap := make(map[string][]RuleEntry)
	for key, entries := range whitelist {
		// Copy the slice to prevent modification of the underlying array
		newSlice := make([]RuleEntry, len(entries))
		copy(newSlice, entries)
		copyMap[key] = newSlice
	}
	return copyMap
}

func rulesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		// ruleMutex.RLock()
		// defer ruleMutex.RUnlock()

		data := map[string]any{
			"Page":     "rules",
			"DNSTypes": dnsTypes,
			"Rules":    snapshotWhitelist(), // Safe, independent copy
		}

		// var body strings.Builder

		// // Add form
		// body.WriteString("<h2>Add New Rule</h2>")
		// body.WriteString("<form method=\"post\" action=\"/rules\">")
		// body.WriteString("<select name=\"type\">")
		// for _, t := range dnsTypes {
		// 	fmt.Fprintf(&body, "<option value=%q>%s</option>", t, t)
		// }
		// body.WriteString("</select> ")
		// body.WriteString("<input type=\"text\" name=\"pattern\" placeholder=\"pattern\" required> ")
		// body.WriteString("<label><input type=\"checkbox\" name=\"enabled\" checked> Enabled</label> ")
		// body.WriteString("<button type=\"submit\">Add Rule</button>")
		// body.WriteString("</form>")

		// // Table
		// body.WriteString("<h2>Whitelist Rules</h2>")
		// body.WriteString("<table><tr><th>Type</th><th>ID</th><th>Pattern</th><th>Enabled</th><th>Actions</th></tr>")

		// for typ, rules := range whitelist {
		// 	for _, rule := range rules {
		// 		enabled := "Yes"
		// 		if !rule.Enabled {
		// 			enabled = "No"
		// 		}
		// 		escapedPattern := html.EscapeString(rule.Pattern)
		// 		body.WriteString(fmt.Sprintf(`
		// <tr>
		//     <td>%q</td>
		//     <td>%q</td>
		//     <td>%q</td>
		//     <td>%q</td>
		//     <td class="actions">
		//         <button class="btn btn-edit" data-edit-id=%q data-edit-type=%q data-edit-pattern=%q data-edit-enabled="%t">Edit</button>
		//         <form method="post" action="/rules" style="display:inline;margin-left:6px" onsubmit="return confirm('Delete rule?')">
		//             <input type="hidden" name="delete" value="1">
		//             <input type="hidden" name="id" value=%q>
		//             <input type="hidden" name="type" value=%q>
		//             <button type="submit">Delete</button>
		//         </form>
		//     </td>
		// </tr>`, typ, rule.ID, escapedPattern, enabled, rule.ID, typ, escapedPattern, rule.Enabled, rule.ID, typ))
		// 	}
		// }
		// body.WriteString("</table>")
		// Pass the raw data. The template handles the HTML.
		//uiTemplates.Execute(w, struct{ Body template.HTML }{Body: template.HTML(body.String())})

		// NO LOCK NEEDED HERE during Execute
		if err := uiTemplates.Execute(w, data); err != nil {
			mainLogger.Error("template_execute_failed", slog.Any("err", err))
		}

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
			var deleted bool = false

			//TODO: make proper delete rule function, heh.
			func() {
				ruleMutex.Lock()
				defer ruleMutex.Unlock()

				if rules, ok := whitelist[typ]; ok {
					for i, rule := range rules {
						if rule.ID == id {
							// Copy the tail over the deleted element
							copy(rules[i:], rules[i+1:])
							// Explicitly zero the last element to prevent string memory leaks
							rules[len(rules)-1] = RuleEntry{}
							// Shrink the slice (wouldn't have zeroed last without the above explicit!)
							whitelist[typ] = rules[:len(rules)-1]
							deleted = true
							break
						}
					}
				}

				// if rules, ok := whitelist[typ]; ok && len(rules) > 0 {
				// 	for i := range rules {
				// 		if rules[i].ID == id {
				// 			// Move the last element into the hole, even if it is itself
				// 			rules[i] = rules[len(rules)-1]
				// 			// Shrink slice (zero the old last element for GC friendliness)
				// 			whitelist[typ] = rules[:len(rules)-1]
				// 			deleted = true
				// 			break
				// 		}
				// 	}
				// }

				// if rules, ok := whitelist[typ]; ok {
				// 	// all operations on 'rules' are known to be on a non-nil slice
				// 	for i, rule := range rules {
				// 		if rule.ID == id {
				// 			whitelist[typ] = append(rules[:i], rules[i+1:]...)
				// 			fmt.Printf("Rule deleted: %q id:%q (type: %q)\n", rule.Pattern, id, typ)
				// 			deleted = true
				// 			break
				// 		}
				// 	}
				// }

				// rules := whitelist[typ]
				// for _, rr := range rules {
				// 	if rr.ID == id {
				// 		//config.Whitelist[typ] = append(rules[:i], rules[i+1:]...)
				// 		wr := whitelist[typ]
				// 		for j, wrr := range wr {
				// 			if wrr.ID == id {
				// 				whitelist[typ] = append(wr[:j], wr[j+1:]...)
				// 				fmt.Printf("Rule deleted: %q id:%q (type: %q)\n", wr[j].Pattern, id, typ)
				// 				deleted = true
				// 				break
				// 			}
				// 		}

				// 	}
				// }
			}() // lock released here
			if deleted {
				if err := /*uses lock*/ saveQueryWhitelist(); err != nil {
					logFatal("failed to save whitelist after rule deletion from webUI", err)
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

		func() {
			ruleMutex.Lock()
			defer ruleMutex.Unlock()

			if id != "" {
				// ruleMutex.Lock()
				// defer ruleMutex.Unlock()
				// Edit: Find and update (search all types)
				found := false
			outerfor:
				for oldTyp, rules := range whitelist {
					for i, rule := range rules {
						if rule.ID == id {
							// Remove from old type
							//config.Whitelist[oldTyp] = append(rules[:i], rules[i+1:]...)
							whitelist[oldTyp] = append(rules[:i], rules[i+1:]...)
							found = true
							break outerfor
						}
					}
					if found {
						panic("shouldn't be hit, else the break label is wrong!?")
						//break
					}
				}
				if !found {
					http.Error(w, "Rule not found", http.StatusNotFound)
					return
				}

				// Add to new type
				newRule := RuleEntry{ID: id, Pattern: patternLowercased, Enabled: enabledBool}
				// if _, ok := whitelist[typ]; !ok {
				// 	//config.Whitelist[typ] = []Rule{}
				// 	whitelist[typ] = []Rule{}
				// }
				//config.Whitelist[typ] = append(config.Whitelist[typ], newRule)
				whitelist[typ] = append(whitelist[typ] /*ok if nil*/, newRule)

				fmt.Printf("Rule edited: %q → %q (ID: %q, Enabled: %t)\n", id, patternLowercased, id, enabledBool)
			} else {
				// Add new: Prevent duplicate (same type + pattern, case-insensitive)
				//lowerPattern := strings.ToLower(pattern)
				for _, rule := range whitelist[typ] {
					//if strings.ToLower(rule.Pattern) == lowerPattern {
					if rule.Pattern /*already lowercase!*/ == patternLowercased {
						http.Error(w, "Rule with this pattern '"+patternLowercased+"' already exists for type "+typ, http.StatusConflict)
						return
					}
				}

				newID := newUniqueID(whitelist)
				newRule := RuleEntry{ID: newID, Pattern: patternLowercased, Enabled: enabledBool}
				// if _, ok := whitelist[typ]; !ok { //does the key for 'typ' not exist? make it
				// 	whitelist[typ] = []Rule{}
				// }
				// // if whitelist[typ] == nil { // does the key for 'typ' not exist? OR it exists but has nil value
				// // 	whitelist[typ] = []Rule{}
				// // }
				//config.Whitelist[typ] = append(config.Whitelist[typ], newRule)
				whitelist[typ] = append(whitelist[typ] /*ok if nil*/, newRule)

				fmt.Printf("Rule added: %q (type: %q, ID: %q, Enabled: %t)\n", patternLowercased, typ, newID, enabledBool)
			}
		}() // lock released here

		if err := /*uses lock!*/ saveQueryWhitelist(); err != nil {
			logFatal("failed to save whitelist after rule add/edit from webUI", err)
		}
		http.Redirect(w, r, "/rules", http.StatusSeeOther)
	}
}

type HostView struct {
	Index      int
	Pattern    string
	IPsDisplay string // Pre-joined "1.1.1.1, 2.2.2.2"
}

func hostsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		// localHostsMu.RLock()
		// defer localHostsMu.RUnlock()

		// var body strings.Builder

		// // Disclaimer per request
		// body.WriteString(`<div style="padding: 10px; margin-bottom: 15px; border-left: 4px solid #0078d4; background: #1e1e1e;">`)
		// body.WriteString(`<strong>Note:</strong> A pattern/host must match the whitelist rules first for these local host overrides to take any effect.`)
		// body.WriteString(`</div>`)

		// // Add form
		// body.WriteString("<h2>Add New Local Host</h2>")
		// body.WriteString(`<form method="post" action="/hosts">`)
		// body.WriteString(`<input type="text" name="pattern" placeholder="pattern (e.g. router.local)" required> `)
		// body.WriteString(`<input type="text" name="ips" placeholder="IPs (comma separated, e.g. 192.168.1.1)" style="width: 280px;" required> `)
		// body.WriteString(`<button type="submit">Add Host</button>`)
		// body.WriteString(`</form>`)

		// // Table
		// body.WriteString("<h2>Local Hosts</h2>")
		// body.WriteString("<table><tr><th>Pattern</th><th>IPs</th><th>Actions</th></tr>")

		// for i, rule := range localHosts {
		// 	escapedPattern := html.EscapeString(rule.Pattern)
		// 	var ipsStr []string
		// 	for _, ip := range rule.IPs {
		// 		ipsStr = append(ipsStr, ip.String())
		// 	}
		// 	joinedIPs := html.EscapeString(strings.Join(ipsStr, ", "))

		// 	//body.WriteString(fmt.Sprintf(`
		// 	fmt.Fprintf(&body, `
		// 	<tr id="hostRow_%d">
		// 		<td>%s</td>
		// 		<td>%s</td>
		// 		<td class="actions">
		// 			<button class="btn btn-edit" onclick="editHost(this, %d, '%s', '%s')">Edit</button>
		// 			<form method="post" action="/hosts" style="display:inline;margin-left:6px" onsubmit="return confirm('Delete local host override?')">
		// 				<input type="hidden" name="delete" value="1">
		// 				<input type="hidden" name="pattern" value="%s">
		// 				<button class="btn btn-del" type="submit">Delete</button>
		// 			</form>
		// 		</td>
		// 	</tr>`, i, escapedPattern, joinedIPs, i, escapedPattern, joinedIPs, escapedPattern)
		// 	//)
		// }
		// body.WriteString("</table>")

		// // Isolated script for Local Hosts inline editing
		// body.WriteString(`
		// <script>
		// function editHost(btn, index, pat, ips) {
		// 	const row = document.getElementById('hostRow_' + index);
		// 	row.style.display = 'none';
		// 	const formHtml = ` + "`" + `
		// 	<tr id="editHostRow_${index}">
		// 		<td>
		// 			<input type="hidden" name="old_pattern" value="${pat}" form="editHostForm_${index}">
		// 			<input type="text" name="pattern" value="${pat}" form="editHostForm_${index}" style="width:100%" required>
		// 		</td>
		// 		<td><input type="text" name="ips" value="${ips}" form="editHostForm_${index}" style="width:100%" required></td>
		// 		<td>
		// 			<form method="post" action="/hosts" id="editHostForm_${index}" style="display:inline;">
		// 				<input type="hidden" name="edit" value="1">
		// 				<button type="submit" class="btn btn-edit">Save</button>
		// 				<button type="button" class="btn btn-cancel" onclick="cancelHostEdit(${index})">Cancel</button>
		// 			</form>
		// 		</td>
		// 	</tr>
		// 	` + "`" + `;
		// 	row.insertAdjacentHTML('afterend', formHtml);
		// }
		// function cancelHostEdit(index) {
		// 	const editRow = document.getElementById('editHostRow_' + index);
		// 	if (editRow) editRow.remove();
		// 	const row = document.getElementById('hostRow_' + index);
		// 	if (row) row.style.display = '';
		// }
		// </script>
		// `)
		//uiTemplates.Execute(w, struct{ Body template.HTML }{Body: template.HTML(body.String())})

		// 1. Snapshot the data under lock
		localHostsMu.RLock()
		viewData := make([]HostView, len(localHosts))
		for i, h := range localHosts {
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
		localHostsMu.RUnlock() // Lock released!

		// 2. Render the page
		data := map[string]any{
			"Page":  "hosts",
			"Hosts": viewData,
		}

		if err := uiTemplates.Execute(w, data); err != nil {
			mainLogger.Error("template_error", slog.Any("err", err))
		}

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

			deleted := false
			func() {
				localHostsMu.Lock()
				defer localHostsMu.Unlock()
				for i, rule := range localHosts {
					if rule.Pattern == pattern {
						localHosts = append(localHosts[:i], localHosts[i+1:]...)
						deleted = true
						break
					}
				}
			}()

			if deleted {
				if err := saveLocalHosts(); err != nil {
					logFatal("failed to save local hosts after deletion", err)
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
			http.Error(w, "pattern required", http.StatusBadRequest)
			return
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
			localHostsMu.Lock()
			defer localHostsMu.Unlock()

			if isEdit {
				// Remove the old rule if editing
				for i, rule := range localHosts {
					if rule.Pattern == oldPattern {
						localHosts = append(localHosts[:i], localHosts[i+1:]...)
						break
					}
				}
				// Remove the target pattern if we renamed to an existing one (overwrite logic)
				for i, rule := range localHosts {
					if rule.Pattern == pattern {
						localHosts = append(localHosts[:i], localHosts[i+1:]...)
						break
					}
				}
			} else {
				// Prevent duplicates on explicit 'Add'
				for _, rule := range localHosts {
					if rule.Pattern == pattern {
						conflictErr = true
						return
					}
				}
			}

			if !conflictErr {
				localHosts = append(localHosts, LocalHostRule{Pattern: pattern, IPs: netIPs})
			}
		}()

		if conflictErr {
			http.Error(w, "Local host with this pattern already exists", http.StatusConflict)
			return
		}

		if err := saveLocalHosts(); err != nil {
			logFatal("failed to save local hosts after add/edit", err)
		}

		http.Redirect(w, r, "/hosts", http.StatusSeeOther)
	}
}

func blocksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// var body strings.Builder
		// body.WriteString("<h2>Recent Blocks (Quick Unblock)</h2><ul>")
		// func() {
		// 	blockMutex.Lock()
		// 	defer blockMutex.Unlock()
		// 	for _, b := range recentBlocks {
		// 		body.WriteString(fmt.Sprintf("<li>%q (%q) <form method=post action=/blocks><input type=hidden name=domain value=%q><input type=hidden name=type value=A><button>Unblock A</button></form> <button onclick=\"location.href='/blocks?type=AAAA&domain=%s'\">Unblock AAAA</button></li>",
		// 			b.Domain, b.Type, b.Domain, b.Domain))
		// 	}
		// }()
		// body.WriteString("</ul>")
		// uiTemplates.Execute(w, struct{ Body template.HTML }{Body: template.HTML(body.String())})
		blockMutex.Lock()
		// Make a copy so we don't hold the lock while template renders
		blocksCopy := make([]BlockedQuery, len(recentBlocks))
		copy(blocksCopy, recentBlocks)
		blockMutex.Unlock()

		data := map[string]any{
			"Page":   "blocks",
			"Blocks": blocksCopy,
		}

		if err := uiTemplates.Execute(w, data); err != nil {
			mainLogger.Error("template_execute_failed", slog.Any("err", err))
		}
		return
	}
	if r.Method == "POST" {
		//domain := r.FormValue("domain")
		raw := r.FormValue("domain")

		sanitized, modified := SanitizeDomainInput(raw)

		if modified || !IsValidDNSName(sanitized) { //TODO: check if this is valid upon querying too!
			//TODO:
			// re-render form with:
			// - error message
			// - escaped original raw input
			lastEditedPatternEscaped := template.HTMLEscapeString(raw)
			fmt.Printf("Invalid domain, raw: %q\n sanitized: %q\n modified: %t\n escaped: %q", raw, sanitized, modified, lastEditedPatternEscaped)
			return
		}
		domainLowercased := strings.ToLower(sanitized) //XXX: must keep it lowercased for matchPattern() later on.

		// accept sanitized
		typ := r.FormValue("type")
		if domainLowercased != "" && typ != "" {
			func() { // anonymous function just for scoping defer
				ruleMutex.Lock()
				defer ruleMutex.Unlock()
				// Add rule for typ
				newRule := RuleEntry{ID: newUniqueID(whitelist), // this can panic
					Pattern: domainLowercased, Enabled: true}
				// if _, ok := whitelist[typ]; !ok { //does the key for 'typ' not exist? make it
				// 	whitelist[typ] = []Rule{}
				// }
				whitelist[typ] = append(whitelist[typ] /*ok if nil*/, newRule)
			}() // lock released here
			if err := /*uses lock*/ saveQueryWhitelist(); err != nil {
				//mainLogger.Error("save_whitelist_failed_after_quick_unblock", slog.Any("err", err))
				logFatal("failed to save whitelist after rule that was blocked was deleted from the blocks handler in webUI", err)
			}
			mainLogger.Info("Quick unblock added", slog.String("domainLowercased", domainLowercased), slog.String("DNSType", typ))
		}
		http.Redirect(w, r, "/blocks", http.StatusSeeOther)
	}
}

// Helper to keep things clean
func renderLogPage(w http.ResponseWriter, r *http.Request, title, filePath, filter string) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		// If file doesn't exist yet, don't crash, just show empty
		data = []byte("")
	}

	lines := strings.Split(string(data), "\n")
	var filtered []string

	searchLower := strings.ToLower(filter)
	for _, line := range lines {
		if line == "" {
			continue
		}
		if filter == "" || strings.Contains(strings.ToLower(line), searchLower) {
			filtered = append(filtered, line)
		}
	}

	// We reverse them so the newest logs are at the top
	for i, j := 0, len(filtered)-1; i < j; i, j = i+1, j-1 {
		filtered[i], filtered[j] = filtered[j], filtered[i]
	}

	renderData := map[string]any{
		"Page":    "logs",
		"Path":    r.URL.Path, // Pass current path (e.g., "/logs" or "/queries")
		"Title":   title,
		"Filter":  filter,
		"Content": strings.Join(filtered, "\n"),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	uiTemplates.Execute(w, renderData)
}

func logsQueriesHandler(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("q")
	//no:// If they used the old 'domain' param, support it as a fallback
	// if filter == "" {
	// 	filter = r.URL.Query().Get("domain")
	// }

	renderLogPage(w, r, "Query Logs", config.LogQueriesFile, filter)
}

func logsHandler(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("q")
	renderLogPage(w, r, "System & Error Logs", config.LogErrorsFile, filter)
}

// func logsQueriesHandler(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "text/html; charset=utf-8")
// 	domainFilter := r.URL.Query().Get("domain")
// 	// Basic file read/filter stub
// 	data, err := os.ReadFile(config.LogQueriesFile)
// 	if err != nil {
// 		http.Error(w, "Log read failed", http.StatusInternalServerError)
// 		return
// 	}
// 	lines := strings.Split(string(data), "\n")
// 	var filtered []string
// 	for _, line := range lines {
// 		if strings.Contains(line, domainFilter) || domainFilter == "" {
// 			filtered = append(filtered, line)
// 		}
// 	}
// 	body := fmt.Sprintf("<h2>Logs (filtered by %q)</h2><pre style=\"max-height:400px;overflow:auto;\">%q</pre>", domainFilter, strings.Join(filtered, "\n"))

// 	uiTemplates.Execute(w, struct{ Body template.HTML }{Body: template.HTML(body)}) // Raw HTML, no escape
// }

// func logsHandler(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "text/html; charset=utf-8")
// 	domainFilter := r.URL.Query().Get("domain") //FIXME: filter by what? should be any string since this is the full log, not just queries in it.
// 	// Basic file read/filter stub
// 	data, err := os.ReadFile(config.LogErrorsFile)
// 	if err != nil {
// 		http.Error(w, "Log read failed", http.StatusInternalServerError)
// 		return
// 	}
// 	lines := strings.Split(string(data), "\n")
// 	var filtered []string
// 	for _, line := range lines {
// 		if strings.Contains(line, domainFilter) || domainFilter == "" {
// 			filtered = append(filtered, line)
// 		}
// 	}
// 	body := fmt.Sprintf("<h2>Logs (filtered by %q)</h2><pre style=\"max-height:400px;overflow:auto;\">%q</pre>", domainFilter, strings.Join(filtered, "\n"))

// 	uiTemplates.Execute(w, struct{ Body template.HTML }{Body: template.HTML(body)}) // Raw HTML, no escape
// }

func shutdown(exitCode int) {
	shutdownOnce.Do(func() { //guarantees that the code inside the function runs exactly once.
		mainLogger.Info("Shutting down...")
		// 1. Cancel the context immediately so all other listeners stop
		cancel() //Calling cancel() multiple times is perfectly safe and is actually the expected behavior in Go. In case anything else just called cancel() itself (should be currently happening)
		mainLogger.Debug("Context cancelled... this triggers DoH and webUI shutdowns in their own goroutines!")

		cacheStore.Flush()
		mainLogger.Debug("Cache flushed")
		//doneTODO: webUI shutdown (done via cancel() above)
		//mainLogger.Debug("webUI shutdown(fake)")
		//sleep 1 sec to allow "quitting on shutdown" message to show.
		// Wait 1 sec to allow graceful HTTP shutdowns and the "quitting" messages to show
		//time.Sleep(1000 * time.Millisecond)
		// ADD: Wait for all registered goroutines to signal they've exited
		mainLogger.Debug("Waiting for goroutines to finish...")
		shutdownWG.Wait()
		mainLogger.Debug("All goroutines exited.")
		//mainLogger.Debug("waited 1 sec for port cleanup")

		if !wincoe.WaitAnyKeyIfInteractive() {
			mainLogger.Debug("Didn't wait for keypress due to not an interactive/terminal.")
		}
		//bufio.NewReader(os.Stdin).ReadBytes('\n') //done: make it for any key not just Enter!
		mainLogger.Info("exitting with exit code", slog.Int("exitCode", exitCode))
		os.Exit(exitCode)
	})
}

func watchKeys(reloadFn func(), cleanExitFn func()) {
	fd := int(os.Stdin.Fd())

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return
	}
	defer term.Restore(fd, oldState)

	buf := make([]byte, 3)

	for {
		fmt.Print(".")
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			continue
		}

		// Ctrl+X (0x18)
		if buf[0] == 0x18 {
			fmt.Println("\nCtrl+X detected → clean exit")
			_ = term.Restore(fd, oldState)
			cleanExitFn()
		}

		// Ctrl+R (0x12)
		if buf[0] == 0x12 {
			fmt.Println("\nCtrl+R detected → reloading config")
			//_ = term.Restore(fd, oldState)
			// NO restore needed here because we want to stay in Raw mode
			// to catch the next keypress after the reload.
			reloadFn()
		}

		// Ctrl+C (0x03) or else can't break the program except with Ctrl+Break !
		if buf[0] == 0x03 {
			fmt.Println("\nCtrl+C detected → breaking gracefully")
			_ = term.Restore(fd, oldState)
			cleanExitFn()
		}

		// Alt+X / Alt+R → ESC + key
		if buf[0] == 0x1b && n >= 2 {
			switch buf[1] {
			case 'x', 'X':
				fmt.Println("\nAlt+X detected → clean exit")
				_ = term.Restore(fd, oldState)
				cleanExitFn()
			case 'r', 'R':
				fmt.Println("\nAlt+R detected → reloading config")
				//_ = term.Restore(fd, oldState)
				reloadFn()
			}
		}

		_, err = term.MakeRaw(fd)
		if err != nil {
			fmt.Println("\nFailed to makeraw the terminal...")
			return
		}
	}
}
