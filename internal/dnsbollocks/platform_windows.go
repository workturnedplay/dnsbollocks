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
	"flag"
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
	"regexp"

	"html"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"golang.org/x/sys/windows"
	"golang.org/x/term"
	"golang.org/x/time/rate"
)

// Config holds the JSON configuration.
type Config struct {
	ListenDNS         string            `json:"listen_dns"`         // e.g., "127.0.0.1:53"
	ListenDoH         string            `json:"listen_doh"`         // e.g., "127.0.0.1:443"
	UIPort            int               `json:"ui_port"`            // 8080
	UpstreamURL       string            `json:"upstream_url"`       // "https://9.9.9.9/dns-query"
	SNIHostname       string            `json:"sni_hostname"`       // Optional ""
	BlockMode         string            `json:"block_mode"`         // "nxdomain", "drop", "ip_block"
	BlockIP           string            `json:"block_ip"`           // "0.0.0.0"
	RateQPS           int               `json:"rate_qps"`           // 100
	CacheMinTTL       int               `json:"cache_min_ttl"`      // 300s
	CacheMaxEntries   int               `json:"cache_max_entries"`  // 10000
	Whitelist         map[string][]Rule `json:"whitelist"`          // Per-type rules
	ResponseBlacklist []string          `json:"response_blacklist"` // CIDR e.g., "127.0.0.1/8"
	WhitelistFile     string            `json:"whitelist_file"`     // "query_whitelist.json"
	BlacklistFile     string            `json:"blacklist_file"`     // "response_blacklist.json"
	LogQueries        string            `json:"log_queries"`        // "queries.log"
	LogErrors         string            `json:"log_errors"`         // "errors.log"
	LogMaxSizeMB      int               `json:"log_max_size_mb"`    // 1 for rotation
	AllowRunAsAdmin   bool              `json:"allow_run_as_admin"` // if running the exe as Admin in windows is allowed or if false just exits.
	// Special-case: For AAAA queries, return NOERROR with an empty answer instead of NXDOMAIN.
	// Windows treats NXDOMAIN for AAAA as authoritative non-existence which prevents IPv4 fallback.
	BlockAAAAasEmptyNoError bool `json:"block_aaaa_as_empty_noerror"` // default true
}

// Rule represents a whitelist rule.
type Rule struct {
	ID      string `json:"id"`
	Pattern string `json:"pattern"`
	Enabled bool   `json:"enabled"`
}

// Globals.
var dohCert tls.Certificate // Loaded once for DoH listener
var (
	config         Config
	upstreamIP     string
	upstreamURL    *url.URL
	queryLogger    *slog.Logger
	errorLogger    *slog.Logger
	cacheStore     *cache.Cache
	globalLimiter  *rate.Limiter
	clientLimiters sync.Map          // map[string]*rate.Limiter
	whitelist      map[string][]Rule // type -> rules
	ruleMutex      sync.RWMutex
	recentBlocks   = make([]BlockedQuery, 0, 50) // For UI
	blockMutex     sync.Mutex
	stats          = expvar.NewInt("blocks") // Simple stats

	ctx, cancel = context.WithCancel(context.Background())
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
    which means that input validation and character filtering will be enforced only after submission. (ie. is the hostname withing allowable chars or byte limits?)
  </div>
</noscript>
`

var uiTemplates = template.Must(template.New("").Parse(
	`<!DOCTYPE html><html><head><title>DNSbollocks UI</title><meta charset="utf-8"><base href="/">
    <style>
body { font-family: 'Segoe UI', sans-serif; background: #121212; color: #e0e0e0; padding: 40px; }
        .container { max-width: 1000px; margin: auto; }
        h2 { color: #0078d4; border-bottom: 2px solid #333; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; background: #1e1e1e; border-radius: 8px; overflow: hidden; }
        th, td { padding: 15px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #252525; color: #888; font-size: 0.8em; text-transform: uppercase; }
        .btn { padding: 6px 12px; cursor: pointer; border: none; border-radius: 4px; font-weight: bold; }
        .btn-edit { background: #0078d4; color: white; }
        .btn-del { background: #d83b01; color: white; margin-left: 5px; }
        .btn-cancel { background: #444; color: white; }\n        .actions { white-space: nowrap; }
        .hidden { display: none; }
        input[type="text"] { background: #2d2d2d; color: white; border: 1px solid #444; padding: 6px; width: 70%; }

        thead th {
            position: sticky;
            top: 0;
            background: #1e1e1e;
            z-index: 2;
        }

.actions {
    white-space: nowrap;
}
.actions form {
    display: inline;
    margin: 0;
}
.actions button {
    display: inline-block;
    vertical-align: middle;
}

/* --- UI stability fixes --- */
table {
  border-collapse: collapse;
}
thead th {
  position: sticky;
  top: 0;
  background: #222;
  z-index: 3;
}
.actions {
  white-space: nowrap;
}
.actions form {
  display: inline;
  margin: 0;
}
.actions button {
  display: inline-block;
  vertical-align: middle;
}
/* Prevent edit row from changing height */
tr td {
  vertical-align: middle;
}

</style></head><body>` +
		noScriptWarningHTML + `
    <div class="container">
    <h1>DNSbollocks</h1>
    <a href="/rules">Whitelist Rules</a> | <a href="/blocks">Recent Blocks</a> | <a href="/logs">Logs</a> | <a href="/">Stats</a> | <a href="/debug/vars">Debug Vars</a>
    {{.Body}}
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
                        <select name="type" id="editType_${id}">
                            ` + strings.Join(func() []string {
		var opts []string
		for _, t := range dnsTypes {
			//dnsTypes is from our Go code not user input, can use %s here. Also puting user input here would be bad for this templating too!
			opts = append(opts, fmt.Sprintf("<option value=\"%s\">%s</option>", t, t))
		}
		return opts
	}(), "") + `
                        </select>
                    </td>
                    <td>${id}</td>
                    <td><input type="text" id="editPattern_${id}" value="${oldPattern}" style="width:100%"></td>
                    <td><label><input type="checkbox" id="editEnabled_${id}" ${enabled ? 'checked' : ''}></label></td>
                    <td>
                        <form method="post" action="/rules" id="editForm_${id}">
                            <input type="hidden" name="id" value="${id}">
                            <button type="submit">Save</button>
                            <button type="button" onclick="cancelEdit('${id}')">Cancel</button>
                        </form>
                    </td>
                </tr>
                ` + "`" + `;
                row.insertAdjacentHTML('afterend', formHtml);
				const select = document.getElementById('editType_' + id);
				if (select) {
					select.value = typ;
					// Guard: detect impossible / stale / corrupted types
					if (![...select.options].some(o => o.value === typ)) {
						console.warn(
							'Unknown DNS type for rule',
							{ id, typ, known: [...select.options].map(o => o.value) }
						);
						select.selectedIndex = 0;
					}
				}
                const form = document.getElementById('editForm_' + id);
                form.addEventListener('submit', function(e) {
                    e.preventDefault();
                    const newPattern = document.getElementById('editPattern_' + id).value.trim();
                    const enabledChecked = document.getElementById('editEnabled_' + id).checked;
                    const newType = document.getElementById('editType_' + id).value;
                    if (newPattern === '') {
                        alert('Pattern cannot be empty');
                        return;
                    }
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

<script>
// Preserve scroll position across form submits / reloads
(function() {
  const key = "scrollY";
  window.addEventListener("beforeunload", function () {
    try { sessionStorage.setItem(key, window.scrollY); } catch(e) {}
  });
  window.addEventListener("load", function () {
    try {
      const y = sessionStorage.getItem(key);
      if (y !== null) window.scrollTo(0, parseInt(y, 10));
    } catch(e) {}
  });
})();
</script>

</body></html>`,
))

func OldMain() {
	fmt.Println("DNSbollocks starting...")
	flag.Parse() // For future flags
	configPath := "config.json"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	// Signals setup FIRST: Catch interrupts from init onward
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Signal channel ready - Ctrl+C to shutdown gracefully")

	if err := loadConfig(configPath); err != nil {
		log.Fatal("Config load failed:", err)
	}
	fmt.Printf("Config loaded from %q\n", configPath)

	if !config.AllowRunAsAdmin && isAdmin() {
		log.Println("Exiting: Elevated privileges detected. Rerun without admin or change the config setting.")
		os.Exit(1)
	}
	fmt.Println("Non-elevated mode confirmed")

	initLogging(config.LogQueries, config.LogErrors)
	fmt.Println("Logging initialized")

	cacheStore = cache.New(time.Hour, time.Hour) // Janitor every hour
	fmt.Println("Cache initialized")
	globalLimiter = rate.NewLimiter(rate.Limit(config.RateQPS), config.RateQPS)
	fmt.Println("Rate limiter initialized")
	loadWhitelist()
	fmt.Println("Whitelist loaded")

	if err := validateUpstream(); err != nil {
		log.Fatal("Upstream validation failed:", err)
	}
	fmt.Printf("Upstream validated: %q (IP: %q)\n", config.UpstreamURL, upstreamIP)

	generateCertIfNeeded() // For DoH
	fmt.Println("Cert checked/generated if needed")

	initDoHClient()
	// Sequential launches for ordered logging
	fmt.Println("Launching listeners sequentially...")
	startDNSListener(config.ListenDNS) // Blocks until complete/fail
	startDoHListener(config.ListenDoH) // Blocks until complete/fail
	go startWebUI(config.UIPort)       // Concurrent server (blocks forever, but post-serial)

	go watchKeys(
		func() { // Ctrl+R
			if err := loadConfig(configPath); err != nil {
				log.Println("Config reload failed:", err)
			} else {
				log.Println("Config reloaded successfully but beware that it's meant to work only for reloading whitelist changes!")
			}
			loadWhitelist()
			fmt.Println("Whitelist reloaded")
		},
		func() { // alt+x etc.
			fmt.Println("Shutdown signal received, clean exit.")
			cancel()
			shutdown(0) // clean exit
		},
	)

	<-sigChan // Wait here - UI goroutine handles serving
	fmt.Println("Shutdown signal received, SIGINT exit.")
	cancel()      // Cancel context for graceful close
	shutdown(130) // Ctrl+C / SIGTERM → non-clean exit => exit code 130 (128+2 like in linux)
}

func loadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {

		if isAdmin() {

			return fmt.Errorf("Config file %q not found; refusing to create a new config file with defaults due to running as Admin!\n", path)
		} else {
			// not admin, auto create config file with defaults
			//FIXME: make sure it's not found not just don't have read permission (but could have write!)
			fmt.Printf("Config file %q not found or unreadable; using defaults and creating new file.\n", path)
		}
		// Defaults
		config = Config{
			ListenDNS:       "127.0.0.1:53",
			ListenDoH:       "127.0.0.1:443",
			UIPort:          8080,
			UpstreamURL:     "https://9.9.9.9/dns-query",
			SNIHostname:     "dns.quad9.net", // if empty it uses the 9.9.9.9 from url which also works!
			BlockMode:       "nxdomain",
			BlockIP:         "0.0.0.0",
			RateQPS:         100,
			CacheMinTTL:     300,
			CacheMaxEntries: 10000,
			Whitelist:       make(map[string][]Rule),
			ResponseBlacklist: []string{
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
			},

			//FIXME: these two aren't used:
			WhitelistFile: "query_whitelist.json",
			BlacklistFile: "response_blacklist.json",

			LogQueries:              "queries.log",
			LogErrors:               "errors.log",
			LogMaxSizeMB:            4095, // Rotation threshold
			AllowRunAsAdmin:         false,
			BlockAAAAasEmptyNoError: true,
		}

		if err := saveConfig(path); err != nil {
			return fmt.Errorf("default config save failed: %w", err)
		}
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&config); err != nil {
		return fmt.Errorf("Config contains unsupported or typo-ed fields: %w", err)
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

	// fail-fast if the response blacklist has malformed CIDR addresses
	for _, cidr := range config.ResponseBlacklist {
		_, _, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid_cidr %q in response blacklist which is in the config file %q", cidr, path)
		}
	}

	return nil
}

// helper to return host (IP or hostname) from an URL
func hostFromURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	host := u.Host
	// Strip any port if present (e.g. "example.com:443" -> "example.com")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host, nil
}

func saveConfig(path string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("config marshal failed: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("config write failed: %w", err)
	}
	return nil
}

func isAdmin() bool {
	// Windows: Use latest x/sys API for elevation check.
	token := windows.GetCurrentProcessToken()
	elevated := token.IsElevated() // Single bool return
	return elevated
}

func initLogging(qpath, epath string) {
	// Rotation stub: Rename if > max size
	rotateIfNeeded(qpath, config.LogMaxSizeMB)
	rotateIfNeeded(epath, config.LogMaxSizeMB)

	qfile, err := os.OpenFile(qpath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		log.Fatal("Query log open failed:", err)
	}
	opts := &slog.HandlerOptions{AddSource: false}
	qh := slog.NewJSONHandler(qfile, opts)
	queryLogger = slog.New(qh)

	efile, err := os.OpenFile(epath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		log.Fatal("Error log open failed:", err)
	}
	eh := slog.NewJSONHandler(efile, opts)
	errorLogger = slog.New(eh)
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

func loadWhitelist() {
	fmt.Println("loadWhitelist() entered - starting")
	// Gen IDs pre-lock to avoid nesting
	for _, rules := range config.Whitelist {
		for i := range rules {
			if rules[i].ID == "" {
				nid := newUniqueID() // Gen outside lock
				fmt.Println("Made new ID for a rule that missed one: ", nid)
				rules[i].ID = nid
			}
		}
	}
	ruleMutex.Lock()
	defer ruleMutex.Unlock()
	whitelist = make(map[string][]Rule)
	loadErr := false
	fmt.Printf("Whitelist config has %d types\n", len(config.Whitelist))
	for typ, rules := range config.Whitelist {
		fmt.Printf("Processing type %q with %d rules...\n", typ, len(rules))
		var processed []Rule
		for i := range rules {
			fmt.Printf("  Rule %d: Pattern %q, ID %q\n", i, rules[i].Pattern, rules[i].ID)
			r := &rules[i]
			fmt.Print("    Using simple wildcard-style pattern...")
			r.Pattern = strings.ToLower(strings.TrimSuffix(r.Pattern, "."))
			fmt.Println("OK")
			processed = append(processed, *r)
		}
		// Dedup by ID within type (keep first occurrence)
		seen := make(map[string]struct{})
		deduped := processed[:0]
		for _, r := range processed {
			if _, ok := seen[r.ID]; !ok {
				seen[r.ID] = struct{}{}
				deduped = append(deduped, r)
			}
		}
		processed = deduped
		whitelist[typ] = processed
		fmt.Printf("Type %q processed: %d valid rules\n", typ, len(processed))
	}
	if loadErr {
		fmt.Println("Warning: Some whitelist rules skipped due to errors")
	}
	if err := saveConfig("config.json"); err != nil {
		errMsg := fmt.Sprintf("save config after whitelist load: %v", err)
		fmt.Fprintln(os.Stderr, errMsg)
		errorLogger.Error("save_config_failed", slog.Any("err", err))
	}
	fmt.Printf("loadWhitelist() complete: %d types, %d total rules\n", len(whitelist), countRules(whitelist))
}

func countRules(wl map[string][]Rule) int {
	total := 0
	for _, rs := range wl {
		total += len(rs)
	}
	return total
}

func newUniqueID() string {
	//fmt.Println("starts newUniqueID()")
	existing := make(map[string]struct{})
	//fmt.Println("in newUniqueID() before RLock")
	ruleMutex.RLock()
	//fmt.Println("in newUniqueID() after RLock")
	for _, rs := range whitelist {
		for _, r := range rs {
			existing[r.ID] = struct{}{}
		}
	}
	//fmt.Println("in newUniqueID() before RUnlock")
	ruleMutex.RUnlock()
	//fmt.Println("in newUniqueID() after RUnlock")

	for i := 0; i < 10; i++ {
		id := uuid.New().String()
		if _, ok := existing[id]; !ok {
			//fmt.Println("exits newUniqueID() ret:", id)
			return id
		}
	}
	panic("UUID collision limit reached—check RNG or storage")
}

func matchPattern(pattern, name string) bool {
	pattern = strings.ToLower(pattern)
	name = strings.ToLower(name)

	// Handle {**} wildcard (cross-label, requiring at least one label when used with dot)
	if strings.Contains(pattern, "{**}") {
		parts := strings.SplitN(pattern, "{**}", 2)
		prefix := parts[0]
		suffix := ""
		if len(parts) == 2 {
			suffix = parts[1]
		}
		if prefix != "" && !strings.HasPrefix(name, prefix) {
			return false
		}
		if suffix != "" && !strings.HasSuffix(name, suffix) {
			return false
		}
		// If pattern is of form "{**}.suffix", require at least one label before suffix
		if prefix == "" && strings.HasPrefix(suffix, ".") {
			return len(name) > len(suffix)
		}
		if suffix == "" && strings.HasSuffix(prefix, ".") {
			return len(name) > len(prefix)
		}
		return true
	}

	// Handle plain ** wildcard (cross-label, may match zero chars). This mirrors legacy behavior.
	if strings.Contains(pattern, "**") {
		parts := strings.SplitN(pattern, "**", 2)
		prefix := parts[0]
		suffix := ""
		if len(parts) == 2 {
			suffix = parts[1]
		}
		if prefix != "" && !strings.HasPrefix(name, prefix) {
			return false
		}
		if suffix != "" && !strings.HasSuffix(name, suffix) {
			return false
		}
		return true
	}

	// Fallback to recursive matching for other tokens ({*}, *, ?, !, literal text)
	return recursiveMatch(pattern, name)
}

func recursiveMatch(pattern, name string) bool {
	for len(pattern) > 0 {
		// Handle multi-char token {*}
		if strings.HasPrefix(pattern, "{*}") {
			// consume the token
			pattern = pattern[3:]
			// Match one or more chars (but not dot): we must ensure we don't consume dots.
			// find max run of non-dot chars at start of name
			max := 0
			for j := 0; j < len(name) && name[j] != '.'; j++ {
				max = j + 1
			}
			// must match at least one char
			if max < 1 {
				return false
			}
			for i := 1; i <= max; i++ {
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
func generateCertIfNeeded() {
	certFile := "cert.pem"
	keyFile := "key.pem"
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		fmt.Println("Generating self-signed cert for DoH...")
		if err := generateCert(certFile, keyFile); err != nil {
			errorLogger.Error("cert generation failed", slog.Any("err", err))
			os.Exit(1)
		}
		fmt.Println("Cert generated: Trust in clients (e.g., Firefox exception for 127.0.0.1)")
	} else {
		fmt.Println("Cert exists: Skipping generation")
	}

	// Load cert/key into global for reuse
	fmt.Print("Loading cert/key for DoH...")
	var err error
	dohCert, err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		errorLogger.Error("cert_load_failed", slog.Any("err", err))
		os.Exit(1)
	}
	fmt.Println("Success - loaded into tls.Certificate")
}

func generateCert(certFile, keyFile string) error {
	// From crypto/tls/generate_cert.go; edge: Ensure unique serial, valid for 10y
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("key gen failed: %w", err)
	}
	serial := big.NewInt(0)
	serial.SetString(uuid.New().String(), 16) // Unique serial
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"DNSbollocks ie. Local DNS Proxy"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour * 10),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, //FIXME: it's hardcoded
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("cert create failed: %w", err)
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("cert write failed: %w", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("pem encode cert failed: %w", err)
	}

	keyOut, err := os.Create(keyFile)
	if err != nil {
		return fmt.Errorf("key write failed: %w", err)
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return fmt.Errorf("pem encode key failed: %w", err)
	}
	return nil
}

// Listeners...

func startDNSListener(addr string) {
	//	listenerErrs.Add(1)
	//	defer listenerErrs.Done()
	fmt.Printf("Starting DNS listener on %q...\n", addr)

	// UDP
	fmt.Print("  Attempting UDP bind...")
	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}) //FIXME: hardcoded ip and port

	if err != nil {
		errStr := fmt.Sprintf("UDP bind failed on %q: %v", addr, err)
		fmt.Fprintln(os.Stderr, "Failed\n"+errStr)
		errorLogger.Error(errStr)

		os.Exit(1)
	} else {
		fmt.Println("Success")
		fmt.Printf("UDP DNS listening on %q\n", addr)

		buf := make([]byte, 512+512)
		go func() {
			defer udpLn.Close()

			//TheFor:
			for {

				select {
				case <-ctx.Done():
					// to see this you've to wait like 1 sec in shutdown() or that "press a key" msg does it.
					fmt.Println("quitting on shutdown...")

					return // Quit on shutdown
				default:
					n, clientAddr, err := udpLn.ReadFromUDP(buf)
					if err != nil {

						//runtime.Gosched()  // Yield to scheduler on error (deep yield, 0% CPU during)
						fmt.Println("udp error...", err)
						errorLogger.Warn("udp_read_error", slog.Any("err", err))
						//time.Sleep(100 * time.Millisecond)
						//break TheFor
						continue
					}
					pid, exe, err := PidAndExeForUDP(clientAddr) //TODO: do this for TCP below too!
					if err != nil {
						fmt.Printf("clientAddr=%q couldn't get pid and exe name:%q\n", clientAddr, err)
					} else {
						adminNeeded := ""
						if exe == "" {
							adminNeeded = " (you need to run as Admin to see this particular exe path because it's a program that your user didn't start, tho it's safe to assume that it is dnscache aka \"DNS Client\" service)"
							// tested ^ to be true at the moment, shows svchost.exe but it's dnscache service wrapped in svchost!
						}
						fmt.Printf("clientAddr=%q pid=%d exe=%q%s\n", clientAddr, pid, exe, adminNeeded)
					}

					go handleUDP(buf[:n], clientAddr, udpLn)
				}
			}
		}()
	} // else

	// TCP
	fmt.Print("  Attempting TCP bind...")

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr) // parses, no DNS for literal IPs
	if err != nil {
		errStr := fmt.Sprintf("TCP bind failed(the address should be an IP) on %q: %v", addr, err)
		fmt.Fprintln(os.Stderr, "Failed\n"+errStr)
		errorLogger.Error(errStr)
		os.Exit(1)
	}
	tcpLn, err := net.ListenTCP("tcp", tcpAddr) // returns *net.TCPListener

	if err != nil {
		errStr := fmt.Sprintf("TCP bind failed on %q: %v", addr, err)
		fmt.Fprintln(os.Stderr, "Failed\n"+errStr)
		errorLogger.Error(errStr)

		os.Exit(1)
	} else {
		fmt.Println("Success")
		fmt.Printf("TCP DNS listening on %q\n", addr)
		// caller provides ctx context.Context and tcpLn *net.TCPListener
		go func() {
			defer tcpLn.Close()

			// small buffer for accept errors backoff
			var backoff time.Duration

			for {
				// allow Accept to be interruptible by context by using a deadline
				tcpLn.SetDeadline(time.Now().Add(500 * time.Millisecond))

				conn, err := tcpLn.Accept()
				if err != nil {
					// if context canceled, exit cleanly
					select {
					case <-ctx.Done():
						fmt.Println("quitting on shutdown...")
						return
					default:
					}

					// handle timeout-like errors (due to SetDeadline)
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						// reset backoff and continue
						backoff = 0
						continue
					}

					// non-temporary error: log, backoff a bit to avoid hot loop, continue
					fmt.Println("tcp accept error:", err)
					errorLogger.Warn("tcp_accept_error", slog.Any("err", err))

					if backoff == 0 {
						backoff = 50 * time.Millisecond
					} else if backoff < 1*time.Second {
						backoff *= 2
					}
					time.Sleep(backoff)
					continue
				}

				// accepted a connection; handle in new goroutine
				go func(c net.Conn) {
					defer c.Close()
					handleTCP(c)
				}(conn)
			}
		}()

	}
	if udpLn == nil && tcpLn == nil {
		fmt.Println("Warning: No DNS listeners!")
	}
}

func handleUDP(wire []byte, clientAddr *net.UDPAddr, ln *net.UDPConn) {
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		// Edge: Invalid packet—drop silently (common in floods)
		return
	}
	resp := handleDNSQuery(msg, clientAddr.String())
	if resp == nil {
		return // Drop
	}
	pack, _ := resp.Pack()                 // Ignore err for brevity (rare)
	_, _ = ln.WriteToUDP(pack, clientAddr) // Ignore write err
}

func handleTCP(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	length := int(binary.BigEndian.Uint16(buf))
	if length > 65535 { // Edge: Oversize packet
		return
	}
	wire := make([]byte, length)
	if _, err := io.ReadFull(conn, wire); err != nil {
		return
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		return
	}
	resp := handleDNSQuery(msg, conn.RemoteAddr().String())
	if resp != nil {
		pack, _ := resp.Pack() // Ignore err
		out := new(bytes.Buffer)
		err := binary.Write(out, binary.BigEndian, uint16(len(pack))) // Single err return
		if err != nil {
			return
		}
		out.Write(pack)
		_, _ = conn.Write(out.Bytes()) // Ignore write err
	}
}

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
		errStr := fmt.Sprintf("DoH listener failed on %q: %v", addr, err)
		fmt.Fprintln(os.Stderr, "Failed\n"+errStr)
		errorLogger.Error(errStr)
		os.Exit(1) // Fail-fast serial
	}
	fmt.Println("Success")
	fmt.Printf("DoH listening on %q\n", addr)

	dohSrv := &http.Server{Handler: mux,
		ReadTimeout:  30 * time.Second, // Workaround for CPU/timer bug
		WriteTimeout: 30 * time.Second, // Optional, for responses
	}
	go func() {
		defer listener.Close() // Graceful close on shutdown
		if err := dohSrv.Serve(listener); err != nil && err != http.ErrServerClosed {
			errorLogger.Error("doh_serve_failed", slog.Any("err", err))
		}
	}()
	fmt.Println("DoH server loop launched in goroutine - func returning")
}

func dohHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" && r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body []byte
	var err error
	if r.Method == "POST" {
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
	if err := msg.Unpack(body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	resp := handleDNSQuery(msg, r.RemoteAddr) // Field, not method
	if resp == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	pack, _ := resp.Pack() // Ignore err
	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(pack)
}

func handleDNSQuery(msg *dns.Msg, clientAddr string) *dns.Msg {
	if len(msg.Question) != 1 {
		return formerrResponse(msg)
	}
	q := msg.Question[0]
	domain := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	if domain == "" { // Edge: Empty domain
		return formerrResponse(msg)
	}
	qtype := dns.TypeToString[q.Qtype] // Map lookup

	// Rate limit
	gl := globalLimiter.Allow()
	clIface, _ := clientLimiters.LoadOrStore(clientAddr, rate.NewLimiter(10, 100)) // Per-client 10qps/100 burst
	cl := clIface.(*rate.Limiter)
	if !gl || !cl.Allow() {
		errorLogger.Warn("rate_limit_exceeded", slog.String("client", clientAddr))
		return servfailResponse(msg)
	}

	// Whitelist
	ruleMutex.RLock()
	rules := whitelist[qtype]
	matchedID := ""
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
	ruleMutex.RUnlock()
	if !matched {
		stats.Add(1)
		blockMutex.Lock()
		recentBlocks = append(recentBlocks, BlockedQuery{Domain: domain, Type: qtype, Time: time.Now()})
		if len(recentBlocks) > 50 {
			recentBlocks = recentBlocks[1:]
		}
		blockMutex.Unlock()
		logQuery(clientAddr, domain, qtype, "blocked", "", nil)
		return blockResponse(msg)
	}

	// Cache (edge: Negative responses cached short)
	key := domain + ":" + qtype

	if cachedIf, ok := cacheStore.Get(key); ok {
		cached := cachedIf.(*dns.Msg)
		// Return a copy of cached response with the current query ID to avoid
		// clients rejecting replies because of mismatched transaction IDs.
		resp := cached.Copy()
		resp.Id = msg.Id
		logQuery(clientAddr, domain, qtype, "cache_hit", matchedID, nil)
		return resp
	}

	// Forward
	resp := forwardToDoH(msg)
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		negResp := servfailResponse(msg)
		// Cache negatives short
		cacheStore.Set(key, negResp, 10*time.Second)
		return negResp
	}

	// Filter
	filtered := filterResponse(resp, config.ResponseBlacklist)
	if filtered == nil {
		logQuery(clientAddr, domain, qtype,
			"blockedByUpstream", //FIXME: this here is a guess because the upstream answer was filtered out likely due to having an IP like 0.0.0.0 returned, but could also be any of the blocked IPs specified in the config like 127.0.0.1/8 or 192.168.0.0/16 therefore this could mean the upstream tried to return a local or LAN IP but we stripped it out and we should notify accordingly! not just say that upstream blocked the hostname request which it only does if IP was 0.0.0.0 and nothing else.
			"", nil)
		return blockResponse(msg)
	}

	// Cache with clamped TTL
	ttl := computeTTL(filtered)
	expiry := time.Duration(ttl) * time.Second
	if expiry < time.Duration(config.CacheMinTTL)*time.Second {
		expiry = time.Duration(config.CacheMinTTL) * time.Second
	}
	cacheStore.Set(key, filtered, expiry)

	ips := extractIPs(filtered)
	logQuery(clientAddr, domain, qtype, "forwarded", matchedID, ips)

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
	dohClient    *http.Client
	dohTransport *http.Transport
	dohMu        sync.Mutex
)

// call once at startup or when upstream config changes
func initDoHClient() { //upstreamIP, sni string) {
	//What this function does is purely preparatory. You are assembling a plan for future connections, not executing one.
	//Here’s why nothing goes on the network yet:
	//The http.Transport you create is just configuration.
	//DialContext is a callback, not an action. Go stores that function and promises to call it later only when a request actually needs a connection.
	//CloseIdleConnections() is the only thing here that might touch sockets — and even then, only previously established idle ones. If this is the first init, or if no DoH requests were ever made, there’s nothing to close and nothing goes out.
	//http.Client and http.Transport are blueprints, not engines.
	fmt.Println("starting initDoHClient()")
	dohMu.Lock()
	defer dohMu.Unlock()
	fmt.Println("past lock in initDoHClient()")

	if dohTransport != nil {
		dohTransport.CloseIdleConnections()
	}

	t := &http.Transport{
		// Dial raw TCP to the chosen IP so we don't perform DNS resolution here.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, network, net.JoinHostPort(upstreamIP, "443"))
		},
		TLSClientConfig: &tls.Config{
			ServerName:         config.SNIHostname,
			InsecureSkipVerify: false,
		},
		Proxy:               nil,  // avoid proxy interference
		ForceAttemptHTTP2:   true, // allow http2 negotiation via ALPN (needed for 9.9.9.9 due to it saying this "This server implements RFC 8484 - DNS Queries over HTTP, and requires HTTP/2 in accordance with section 5.2 of the RFC."
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
	}

	dohTransport = t
	dohClient = &http.Client{
		Timeout:   5 * time.Second, // overall per-request timeout
		Transport: dohTransport,
	}
	fmt.Println("ending initDoHClient()")
}

// forwardToDoH uses the preinitialized dohClient and supports one retry on transient network errors.
func forwardToDoH(req *dns.Msg) *dns.Msg {
	reqBytes, err := req.Pack()
	if err != nil {
		errorLogger.Error("doh_prepost_pack_failed", slog.Any("err", err))
		fmt.Println("Failed to pack query for upstreaming it to DNS server:", err)
		return nil
	}

	// create request with supplied context so caller controls deadline/cancel
	makeReq := func() (*http.Request, error) {
		r, err := http.NewRequestWithContext(ctx, "POST", upstreamURL.String(), bytes.NewReader(reqBytes))
		if err != nil {
			errorLogger.Error("doh_newrequest_failed", slog.Any("err", err))
			fmt.Println("Failed to create upstream request:", err)
			return nil, err
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
	var attempt int
	for attempt = 0; attempt < 2; attempt++ {
		if dohClient == nil {
			// defensive: initialize if not yet done (use current config)
			initDoHClient()
		}

		req2, err := makeReq()
		if err != nil {
			errorLogger.Error("doh_newrequest_failed", slog.Any("err", err))
			fmt.Println("Failed to create upstream request:", err)
			return nil
		}

		resp, err = dohClient.Do(req2)
		if err == nil {
			//success!
			break
		}

		// decide if error is transient/retryable
		// common retryable errors: temporary network errors, EOF, connection reset
		var netErr net.Error
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) ||
			errors.As(err, &netErr) && netErr.Temporary() {
			// retry once
			errorLogger.Error("doh_post_transient_error", slog.Any("err", err), slog.Int("attempt", attempt))
			fmt.Println("doh_post_transient_error(retrying next tho!):", err)
			// small backoff: sleep a bit but respect context
			select {
			case <-time.After(100 * time.Millisecond):
			case <-ctx.Done():
				fmt.Println("doh sensed quit...")
				return nil
			}
			continue
		}

		// non-retryable error
		errorLogger.Error("doh_post_failed", slog.Any("err", err))
		fmt.Println("Failed to query upstream DNS server:", err)
		return nil
	}

	if resp == nil {
		// last attempt produced no response (shouldn't happen), treat as failure
		errorLogger.Error("doh_no_response")
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		errorLogger.Error("doh_readbody_failed", slog.Any("err", err))
		return nil
	}

	// debug/log non-200 or unexpected content-type
	if resp.StatusCode != 200 {
		errorLogger.Error("doh_upstream_status", slog.Any("status", resp.Status))
		fmt.Println("Upstream HTTP status:", resp.Status)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "application/dns-message" {
		errorLogger.Error("doh_upstream_content_type", slog.Any("content_type", ct))
		fmt.Println("Upstream Content-Type:", ct)
	}
	if len(body) < 12 {
		errorLogger.Error("doh_upstream_body_too_short", slog.Any("len", len(body)))
		fmt.Println("Upstream body too short:", len(body))
	}
	upMsg := new(dns.Msg)
	if err := upMsg.Unpack(body); err != nil {
		errorLogger.Error("doh_unpack_failed", slog.Any("err", err))
		// log first bytes for debugging (already discussed)
		// print first 200 bytes as hex and text (safe slice)
		n := 200
		if len(body) < n {
			n = len(body)
		}
		fmt.Printf("Upstream body (hex, first %d): %x\n", n, body[:n])
		fmt.Printf("Upstream body (text, first %d): %q\n", n, body[:n])
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
	startTime := time.Now().Format("2006-01-02 15:04:05")

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

func filterResponse(msg *dns.Msg, blacklists []string) *dns.Msg {
	if msg == nil {
		errorLogger.Error("msg was nil, unexpected bad programming/code ;p")
		//return nil //un
		panic("unreachable1, or the logger is broken")
	}

	nets := make([]*net.IPNet, 0, len(blacklists))
	for _, cidr := range blacklists {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, ipnet)
		} else {
			//hard fail here (it should've alredy failed at startup or at some other future stage when updating the reponse blacklist)
			errorLogger.Error("invalid_cidr", slog.String("cidr", cidr), "context", "in blacklist reponse") // 'go vet' caught it (indirectly via 'go test')
			panic("unreachable2, or the logger is broken")
		}
	}
	var goodAnswer, goodExtra []dns.RR
	for _, rr := range msg.Answer {
		if keep, modifiedRR := processRR(rr, nets); keep {
			goodAnswer = append(goodAnswer, modifiedRR)
			//fmt.Println("Good inAnswer:",rr)
		} else {
			fmt.Println("Dropped inAnswer from upstream due to containing blocked ip:", rr)
		}
	}
	for _, rr := range msg.Extra {
		if keep, modifiedRR := processRR(rr, nets); keep {
			goodExtra = append(goodExtra, modifiedRR)
			//fmt.Println("Good inExtra:",rr)
		} else {
			fmt.Println("Dropped inExtra from upstream due to containing blocked ip:", rr)
		}
	}

	msg.Answer = goodAnswer
	msg.Extra = goodExtra

	//if len(msg.Answer) == 0 { // this dropped HTTPS replies and they were thus not seen at all, so seen as blockedbyUpstream
	if len(msg.Answer) == 0 && len(msg.Ns) == 0 && len(msg.Extra) == 0 {
		//logQuery(clientAddr, msg.Question[0].Name, qtype, "blockedbyUpstream", "", nil)
		//errorLogger.Warn("response_filtered_all", slog.String("domain", msg.Question[0].Name))
		if len(msg.Question) > 0 {
			errorLogger.Warn("response_filtered_all", slog.String("domain", msg.Question[0].Name))
		} else {
			errorLogger.Warn("response_filtered_all", slog.String("domain", "unknown"))
		}
		return nil
		//	} else {
		//		fmt.Println("Non0 answer:", msg.Answer)
	}
	return msg
}

// filters out unwanteds like the IPs that are returned or ip hints in HTTPS dns types.
func processRR(rr dns.RR, nets []*net.IPNet) (bool, dns.RR) {
	switch r := rr.(type) {
	case *dns.A:
		if ipInNets(r.A, nets) {
			return false, nil
		}
		return true, r

	case *dns.AAAA:
		if ipInNets(r.AAAA, nets) {
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

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

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

func logQuery(client, domain, typ, action, ruleID string, ips []string) {
	attrs := []any{
		slog.String("client", client),
		slog.String("domain", domain),
		slog.String("type", typ),
		slog.String("action", action),
		slog.String("ts", time.Now().Format(time.RFC3339)),
	}
	if ruleID != "" {
		attrs = append(attrs, slog.String("rule_id", ruleID))
	}
	if len(ips) > 0 {
		attrs = append(attrs, slog.String("ips", strings.Join(ips, ",")))
	}
	queryLogger.Log(ctx, slog.LevelInfo, "query", attrs...)
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

func startWebUI(port int) {
	fmt.Printf("Starting web UI on 127.0.0.1:%d...\n", port) //FIXME: hardcoded IP

	mux := http.NewServeMux()
	mux.HandleFunc("/", statsHandler)
	mux.HandleFunc("/rules", rulesHandler)
	mux.HandleFunc("/blocks", blocksHandler)
	mux.HandleFunc("/logs", logsHandler)
	mux.Handle("/debug/vars", expvar.Handler()) // Stats endpoint

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		errStr := fmt.Sprintf("UI listener failed on :%d: %v", port, err)
		fmt.Fprintln(os.Stderr, "  Attempting UI bind...Failed\n"+errStr)
		errorLogger.Error(errStr)
		os.Exit(1) // Fail-fast serial
	}
	fmt.Println("  Attempting UI bind...Success")
	fmt.Printf("Web UI listening on 127.0.0.1:%d (stats at /debug/vars)\n", port) //FIXME: hardcoded IP

	uiSrv := &http.Server{Handler: mux}
	go func() {
		defer listener.Close() // Graceful close
		if err := uiSrv.Serve(listener); err != nil && err != http.ErrServerClosed {
			errorLogger.Error("ui_serve_failed", slog.Any("err", err))
		}
	}()
	fmt.Println("UI server loop launched - func returning")
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := fmt.Sprintf("<p>Blocks: %q</p><p>Cache size: %d</p><p>Upstream IP: %q</p>", stats.String(), cacheStore.ItemCount(), upstreamIP)
	//uiTemplates.Execute(w, struct{ Body string }{Body: body})
	uiTemplates.Execute(w, struct{ Body template.HTML }{Body: template.HTML(body)}) // Raw HTML, no escape
}

func rulesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		ruleMutex.RLock()
		defer ruleMutex.RUnlock()

		var body strings.Builder

		// Table
		body.WriteString("<h2>Whitelist Rules</h2>")
		body.WriteString("<table><tr><th>Type</th><th>ID</th><th>Pattern</th><th>Enabled</th><th>Actions</th></tr>")

		for typ, rules := range whitelist {
			for _, rule := range rules {
				enabled := "Yes"
				if !rule.Enabled {
					enabled = "No"
				}
				escapedPattern := html.EscapeString(rule.Pattern)
				body.WriteString(fmt.Sprintf(`
        <tr>
            <td>%q</td>
            <td>%q</td>
            <td>%q</td>
            <td>%q</td>
            <td class="actions">
                <button class="btn btn-edit" data-edit-id=%q data-edit-type=%q data-edit-pattern=%q data-edit-enabled="%t">Edit</button>
                <form method="post" action="/rules" style="display:inline;margin-left:6px" onsubmit="return confirm('Delete rule?')">
                    <input type="hidden" name="delete" value="1">
                    <input type="hidden" name="id" value=%q>
                    <input type="hidden" name="type" value=%q>
                    <button type="submit">Delete</button>
                </form>
            </td>
        </tr>`, typ, rule.ID, escapedPattern, enabled, rule.ID, typ, escapedPattern, rule.Enabled, rule.ID, typ))
			}
		}
		body.WriteString("</table>")

		// Add form
		body.WriteString("<h2>Add New Rule</h2>")
		body.WriteString("<form method=\"post\" action=\"/rules\">")
		body.WriteString("<select name=\"type\">")
		for _, t := range dnsTypes {
			fmt.Fprintf(&body, "<option value=%q>%s</option>", t, t)
		}
		body.WriteString("</select> ")
		body.WriteString("<input type=\"text\" name=\"pattern\" placeholder=\"pattern\" required> ")
		body.WriteString("<label><input type=\"checkbox\" name=\"enabled\" checked> Enabled</label> ")
		body.WriteString("<button type=\"submit\">Add Rule</button>")
		body.WriteString("</form>")

		uiTemplates.Execute(w, struct{ Body template.HTML }{Body: template.HTML(body.String())})
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
			ruleMutex.Lock()
			defer ruleMutex.Unlock()
			rules := config.Whitelist[typ]
			for i, rr := range rules {
				if rr.ID == id {
					config.Whitelist[typ] = append(rules[:i], rules[i+1:]...)
					wr := whitelist[typ]
					for j, wrr := range wr {
						if wrr.ID == id {
							whitelist[typ] = append(wr[:j], wr[j+1:]...)
							fmt.Printf("Rule deleted: %q id:%q (type: %q)\n", wr[j].Pattern, id, typ)
							break
						}
					}

					saveConfig("config.json")
					http.Redirect(w, r, "/rules", http.StatusSeeOther)
					return
				}
			}
			http.Error(w, "rule not found", http.StatusNotFound)
			return
		}

		pattern := strings.TrimSpace(r.FormValue("pattern"))
		typ := r.FormValue("type")
		id := r.FormValue("id")
		enabledStr := r.FormValue("enabled")
		enabledBool := enabledStr == "on" || enabledStr == "true" || enabledStr == "1"

		if pattern == "" || typ == "" {
			http.Error(w, "Pattern and type required", http.StatusBadRequest)
			return
		}

		if id != "" {
			ruleMutex.Lock()
			defer ruleMutex.Unlock()
			// Edit: Find and update (search all types)
			found := false
		outerfor:
			for oldTyp, rules := range config.Whitelist {
				for i, rule := range rules {
					if rule.ID == id {
						// Remove from old type
						config.Whitelist[oldTyp] = append(rules[:i], rules[i+1:]...)
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
			newRule := Rule{ID: id, Pattern: pattern, Enabled: enabledBool}
			if _, ok := config.Whitelist[typ]; !ok {
				config.Whitelist[typ] = []Rule{}
				whitelist[typ] = []Rule{}
			}
			config.Whitelist[typ] = append(config.Whitelist[typ], newRule)
			whitelist[typ] = append(whitelist[typ], newRule)

			fmt.Printf("Rule edited: %q → %q (ID: %q, Enabled: %t)\n", id, pattern, id, enabledBool)
		} else {
			newID := newUniqueID()
			ruleMutex.Lock()
			defer ruleMutex.Unlock()
			// Add new: Prevent duplicate (same type + pattern, case-insensitive)
			lowerPattern := strings.ToLower(pattern)
			for _, rule := range config.Whitelist[typ] {
				if strings.ToLower(rule.Pattern) == lowerPattern {
					http.Error(w, "Rule with this pattern already exists for type "+typ, http.StatusConflict)
					return
				}
			}

			newRule := Rule{ID: newID, Pattern: pattern, Enabled: enabledBool}
			if _, ok := config.Whitelist[typ]; !ok {
				config.Whitelist[typ] = []Rule{}
				whitelist[typ] = []Rule{}
			}
			config.Whitelist[typ] = append(config.Whitelist[typ], newRule)
			whitelist[typ] = append(whitelist[typ], newRule)

			fmt.Printf("Rule added: %q (type: %q, ID: %q, Enabled: %t)\n", pattern, typ, newID, enabledBool)
		}

		saveConfig("config.json")
		http.Redirect(w, r, "/rules", http.StatusSeeOther)
	}
}

func blocksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		blockMutex.Lock()
		var body strings.Builder
		body.WriteString("<h2>Recent Blocks (Quick Unblock)</h2><ul>")
		for _, b := range recentBlocks {
			body.WriteString(fmt.Sprintf("<li>%q (%q) <form method=post action=/blocks><input type=hidden name=domain value=%q><input type=hidden name=type value=A><button>Unblock A</button></form> <button onclick=\"location.href='/blocks?type=AAAA&domain=%s'\">Unblock AAAA</button></li>",
				b.Domain, b.Type, b.Domain, b.Domain))
		}
		body.WriteString("</ul>")
		blockMutex.Unlock()
		//uiTemplates.Execute(w, struct{ Body string }{Body: body.String()})
		uiTemplates.Execute(w, struct{ Body template.HTML }{Body: template.HTML(body.String())})
		return
	}
	if r.Method == "POST" {
		//domain := r.FormValue("domain")
		raw := r.FormValue("domain")

		sanitized, modified := SanitizeDomainInput(raw)

		if modified || !IsValidDNSName(sanitized) {
			//TODO:
			// re-render form with:
			// - error message
			// - escaped original raw input
			lastEditedPatternEscaped := template.HTMLEscapeString(raw)
			fmt.Printf("Invalid domain, raw: %q\n sanitized: %q\n modified: %t\n escaped: %q", raw, sanitized, modified, lastEditedPatternEscaped)
			return
		}
		domain := sanitized

		// accept sanitized
		typ := r.FormValue("type")
		if domain != "" && typ != "" {
			// Add rule for typ
			newRule := Rule{ID: newUniqueID(), Pattern: domain, Enabled: true}
			ruleMutex.Lock()
			config.Whitelist[typ] = append(config.Whitelist[typ], newRule)
			whitelist[typ] = append(whitelist[typ], newRule)
			ruleMutex.Unlock()
			saveConfig("config.json")
			fmt.Printf("Quick unblock added for %q (%q)\n", domain, typ)
		}
		http.Redirect(w, r, "/blocks", http.StatusSeeOther)
	}
}

func logsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	domainFilter := r.URL.Query().Get("domain")
	// Basic file read/filter stub
	data, err := os.ReadFile(config.LogQueries)
	if err != nil {
		http.Error(w, "Log read failed", http.StatusInternalServerError)
		return
	}
	lines := strings.Split(string(data), "\n")
	var filtered []string
	for _, line := range lines {
		if strings.Contains(line, domainFilter) || domainFilter == "" {
			filtered = append(filtered, line)
		}
	}
	body := fmt.Sprintf("<h2>Logs (filtered by %q)</h2><pre style=\"max-height:400px;overflow:auto;\">%q</pre>", domainFilter, strings.Join(filtered, "\n"))

	uiTemplates.Execute(w, struct{ Body template.HTML }{Body: template.HTML(body)}) // Raw HTML, no escape
}

func shutdown(exitCode int) {
	fmt.Println("Shutting down...")

	cacheStore.Flush()
	fmt.Println("Cache flushed")
	//TODO: webUI shutdown
	fmt.Println("webUI shutdown")
	// Close log files (reopen on next run)
	//sleep 1 sec to allow "quitting on shutdown" message to show.
	time.Sleep(1000 * time.Millisecond)
	waitAnyKeyIfInteractive()
	//fmt.Print("Press Enter to exit...")
	//bufio.NewReader(os.Stdin).ReadBytes('\n') //FIXME: make it for any key not just Enter!
	fmt.Println("exitting with exit code", exitCode)
	os.Exit(exitCode)
}

func waitAnyKeyIfInteractive() {
	fd := int(os.Stdin.Fd())

	// Skip waiting if stdin isn't a terminal
	if !term.IsTerminal(fd) {
		// don't wait if eg. echo foo | program.exe
		return
	}

	fmt.Print("Press any key to exit...")

	// oldState, err := term.MakeRaw(fd)
	// if err != nil {
	// 	fmt.Print("couldn't make the terminal raw, bailing!")
	// 	return // or log, or fail loudly — your call
	// }
	// defer term.Restore(fd, oldState)

	var hadKey bool
	WithConsoleEventRaw(func() {
		hadKey = ClearStdin() // OS-specific
	})

	if hadKey {
		fmt.Print("(clrbuf)...")
	}

	done := make(chan struct{}, 1)

	go func() {
		WithConsoleEventRaw(func() {
			ReadKeySequence() // OS-specific
			//})
			//WithConsoleEventRaw(func() {

			if ClearStdin() { // OS-specific
				fmt.Print("(clrbuf2).")
			}

		})
		done <- struct{}{}
	}()

	select {
	case <-done:
		//case <-ctx.Done():  // this bypasses the key wait!
	}
	fmt.Println()
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
