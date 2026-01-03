// Package main implements a local DNS proxy with whitelisting, DoH forwarding, caching, and web UI.
// It listens on 127.0.0.1:53 (UDP/TCP) for plain DNS and 127.0.0.1:443 (HTTPS) for DoH.
// Blocks by default; allows via config whitelist (per-type, with regex/wildcards).
// Caches responses (including negatives), rate-limits queries (global/per-client), filters response IPs, logs to JSON files with rotation.
// Web UI at 127.0.0.1:8080 for config edits, logs, and stats (/debug/vars).
// Assumes no admin elevation; exits if detected on Windows.
// Generates self-signed cert for DoH if missing (trust manually in clients like Firefox).
// Handles edge cases: Port conflicts (degraded mode), invalid configs (defaults), concurrent races (mutexes), shutdown (graceful close).
// Vendored for offline build; verbose for defensive programming.

package main

import (
	//"runtime"
	"bufio"
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
	//	"net/http/pprof" // For /debug/vars
	"net/url"
	"os"
	"os/signal"
	//	"path/filepath"
	"html"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"golang.org/x/sys/windows"
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
	CacheMinTTL       int               `json:"cache_min_ttl,s"`    // 300s
	CacheMaxEntries   int               `json:"cache_max_entries"`  // 10000
	Whitelist         map[string][]Rule `json:"whitelist"`          // Per-type rules
	ResponseBlacklist []string          `json:"response_blacklist"` // CIDR e.g., "127.0.0.1/8"
	WhitelistFile     string            `json:"whitelist_file"`     // "query_whitelist.json"
	BlacklistFile     string            `json:"blacklist_file"`     // "response_blacklist.json"
	LogQueries        string            `json:"log_queries"`        // "queries.log"
	LogErrors         string            `json:"log_errors"`         // "errors.log"
	LogMaxSizeMB      int               `json:"log_max_size_mb"`    // 1 for rotation
	AllowRunAsAdmin   bool              `json:"allow_run_as_admin"` // if running the exe as Admin in windows is allowed or if false just exits.
}

// Rule represents a whitelist rule.
type Rule struct {
	ID      string `json:"id"`
	Pattern string `json:"pattern"`
	IsRegex bool   `json:"is_regex"`
	Enabled bool   `json:"enabled"`
}

// Globals.
var dohCert tls.Certificate // Loaded once for DoH listener
var (
	//dohSrv, uiSrv *http.Server
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
	//listenerErrs    sync.WaitGroup
	//listenerErrCh   = make(chan error, 3) // Collect bind errs
	ctx, cancel = context.WithCancel(context.Background())
)

var dnsTypes = []string{
	"A",
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

// Templates for UI (embedded).
//var uiTemplates = template.Must(template.New("").Parse(`
//<!DOCTYPE html><html><head><title>DNS Proxy UI</title></head><body>
//<h1>DNS Proxy Control</h1>
//<a href="/rules">Whitelist Rules</a> | <a href="/blocks">Recent Blocks</a> | <a href="/logs">Logs</a> | <a href="/">Stats</a> | <a href="/debug/vars">Debug Vars</a>
//{{.Body}}
//</body></html>
//`))

//var uiTemplates = template.Must(template.New("").Parse(`
//<!DOCTYPE html><html><head><title>DNS Proxy UI</title><base href="/"></head><body>
//<h1>DNS Proxy Control</h1>
//<a href="/rules">Whitelist Rules</a> | <a href="/blocks">Recent Blocks</a> | <a href="/logs">Logs</a> | <a href="/">Stats</a> | <a href="/debug/vars">Debug Vars</a>
//{{.Body}}
//</body></html>
//`))

//var uiTemplates = template.Must(template.New("").Parse(`
//<!DOCTYPE html><html><head><title>DNS Proxy UI</title><meta charset="utf-8"><base href="/"></head><body>
//<h1>DNS Proxy Control</h1>
//<a href="/rules">Whitelist Rules</a> | <a href="/blocks">Recent Blocks</a> | <a href="/logs">Logs</a> | <a href="/">Stats</a> | <a href="/debug/vars">Debug Vars</a>
//{{.Body}}
//</body></html>
//`))
/*var uiTemplates = template.Must(template.New("").Parse(`
<!DOCTYPE html><html><head><title>DNS Proxy UI</title><meta charset="utf-8"><base href="/"></head><body>
<h1>DNS Proxy Control</h1>
<a href="/rules">Whitelist Rules</a> | <a href="/blocks">Recent Blocks</a> | <a href="/logs">Logs</a> | <a href="/">Stats</a> | <a href="/debug/vars">Debug Vars</a>
{{.Body}}
<script>
// Inline JS for in-place rule editing (vanilla, no deps)
document.addEventListener('DOMContentLoaded', function() {
    const editButtons = document.querySelectorAll('button[onclick*="editRule"]');
    editButtons.forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            const row = this.closest('tr');
            const cells = row.cells;
            const typ = cells[0].textContent;
            const id = cells[1].textContent;
            const oldPattern = cells[2].textContent;
            const enabled = cells[3].textContent === 'Yes';

            // Hide row, show form
            row.style.display = 'none';
            const formHtml = `+"`"+`
                <tr>
                    <td>${typ}</td>
                    <td>${id}</td>
                    <td><input type="text" id="editPattern_$$ {id}" value=" $${oldPattern}" style="width:100%"></td>
                    <td><label><input type="checkbox" id="editEnabled_${id}" ${enabled ? 'checked' : ''}> Enabled</label></td>
                    <td>
                        <form method="post" action="/rules" id="editForm_${id}">
                            <input type="hidden" name="id" value="${id}">
                            <input type="hidden" name="type" value="${typ}">
                            <button type="submit">Save</button>
                            <button type="button" onclick="cancelEdit('$$ {id}', ' $${oldPattern}', ${enabled})">Cancel</button>
                        </form>
                    </td>
                </tr>
            `+"`"+`;
            row.insertAdjacentHTML('afterend', formHtml);
            const form = document.getElementById(`+"`"+`editForm_${id}`+"`"+`);
            form.addEventListener('submit', function(e) {
                e.preventDefault();
                const newPattern = document.getElementById(`+"`"+`editPattern_${id}`+"`"+`).value;
                const enabledChecked = document.getElementById(`+"`"+`editEnabled_${id}`+"`"+`).checked;
                const formData = new FormData(form);
                formData.append('pattern', newPattern);
                formData.append('enabled', enabledChecked ? 'true' : 'false');
                fetch('/rules', {method: 'POST', body: formData}).then(() => location.reload());
            });
        });
    });
    window.cancelEdit = function(id, oldPattern, enabled) {
        const formRow = document.querySelector(`+"`"+`#editForm_${id}`+"`"+`).closest('tr');
        formRow.remove();
        const originalRow = formRow.previousElementSibling;
        originalRow.style.display = '';
    };
});
</script>
</body></html>
`)) */

//// In rulesHandler GET, before body.WriteString table
//var typeOptions strings.Builder=crap()
//func crap() strings.Builder {
//var typeOptions strings.Builder
//for _, t := range typeStrings {
//    selected := ""
//    if t == typ {
//        selected = " selected"
//    }
//    typeOptions.WriteString(fmt.Sprintf("<option value=\"%s\"%s>%s</option>", t, selected, t))
//}
//return typeOptions
//}
//
//var uiTemplates = template.Must(template.New("").Parse(
//    `<!DOCTYPE html><html><head><title>DNS Proxy UI</title><meta charset="utf-8"><base href="/"></head><body>
//    <h1>DNS Proxy Control</h1>
//    <a href="/rules">Whitelist Rules</a> | <a href="/blocks">Recent Blocks</a> | <a href="/logs">Logs</a> | <a href="/">Stats</a> | <a href="/debug/vars">Debug Vars</a>
//    {{.Body}}
//    <script>
//    // Inline JS for in-place rule editing (vanilla, no deps)
//    document.addEventListener('DOMContentLoaded', function() {
//        document.querySelectorAll('button[data-edit-id]').forEach(btn => {
//            btn.addEventListener('click', function(e) {
//                e.preventDefault();
//                const row = this.closest('tr');
//                const typ = this.dataset.editType;
//                const id = this.dataset.editId;
//                const oldPattern = this.dataset.editPattern;
//                const enabled = this.dataset.editEnabled === 'true';
//                row.style.display = 'none';
//                const formHtml = ` + "`" + `                <tr>
//                    <td>
//										<select name="type" id="editType_${id}">
//    ` + typeOptions.String() + `
//</select>
//                    </td>
//                    <td>${id}</td>
//                    <td><input type="text" id="editPattern_${id}" value="${oldPattern}" style="width:100%"></td>
//                    <td><label><input type="checkbox" id="editEnabled_${id}" ${enabled ? 'checked' : ''}> Enabled</label></td>
//                    <td>
//                        <form method="post" action="/rules" id="editForm_${id}">
//                            <input type="hidden" name="id" value="${id}">
//                            <button type="submit">Save</button>
//                            <button type="button" onclick="cancelEdit('${id}', '${oldPattern}', ${enabled})">Cancel</button>
//                        </form>
//                    </td>
//                </tr>
//            ` + "`" + `;
//                row.insertAdjacentHTML('afterend', formHtml);
//                const form = document.getElementById('editForm_' + id);
//                form.addEventListener('submit', function(e) {
//                    e.preventDefault();
//                    const newPattern = document.getElementById('editPattern_' + id).value;
//                    const enabledChecked = document.getElementById('editEnabled_' + id).checked;
//                    const newType = document.getElementById('editType_' + id).value;
//                    const formData = new FormData(form);
//                    formData.append('pattern', newPattern);
//                    formData.append('enabled', enabledChecked ? 'true' : 'false');
//                    formData.append('type', newType);
//                    fetch('/rules', {method: 'POST', body: formData}).then(() => location.reload()).catch(err => console.error('Save failed:', err));
//                });
//            });
//        });
//        window.cancelEdit = function(id, oldPattern, enabled) {
//            const formRow = document.querySelector('#editForm_' + id).closest('tr');
//            formRow.remove();
//            const originalRow = formRow.previousElementSibling;
//            if (originalRow) originalRow.style.display = '';
//        };
//    });
//    </script>
//    </body></html>`,
//))
//var uiTemplates = template.Must(template.New("ui").Parse(`
//<!DOCTYPE html>
//<html>
//<head>
//    <title>DNS Proxy UI</title>
//    <meta charset="utf-8">
//    <base href="/">
//    <style>
//        table { border-collapse: collapse; width: 100%; }
//        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
//        th { background-color: #f0f0f0; }
//        input[type=text] { width: 100%; box-sizing: border-box; }
//        select { width: 100%; }
//    </style>
//</head>
//<body>
//    <h1>DNS Proxy Control</h1>
//    <nav>
//        <a href="/">Stats</a> |
//        <a href="/rules">Whitelist Rules</a> |
//        <a href="/blocks">Recent Blocks</a> |
//        <a href="/logs">Logs</a> |
//        <a href="/debug/vars">Debug Vars</a>
//    </nav>
//    <hr>
//    {{.Body}}
//    <script>
//    // Inline JS for in-place editing remains here — see full version below
//    </script>
//</body>
//</html>
//`))

var uiTemplates = template.Must(template.New("").Parse(
	`<!DOCTYPE html><html><head><title>DNS Proxy UI</title><meta charset="utf-8"><base href="/"></head><body>
    <h1>DNS Proxy Control</h1>
    <a href="/rules">Whitelist Rules</a> | <a href="/blocks">Recent Blocks</a> | <a href="/logs">Logs</a> | <a href="/">Stats</a> | <a href="/debug/vars">Debug Vars</a>
    {{.Body}}
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
			selected := ""
			//            if t == typ {
			//                selected = " selected"
			//            }
			opts = append(opts, fmt.Sprintf("<option value=\"%s\"%s>%s</option>", t, selected, t))
		}
		return opts
	}(), "") + `
                        </select>
                    </td>
                    <td>${id}</td>
                    <td><input type="text" id="editPattern_${id}" value="${oldPattern}" style="width:100%"></td>
                    <td><label><input type="checkbox" id="editEnabled_${id}" ${enabled ? 'checked' : ''}> Enabled</label></td>
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
            const formRow = document.querySelector('#editForm_' + id).closest('tr');
            formRow.remove();
            const originalRow = formRow.previousElementSibling;
            if (originalRow) originalRow.style.display = '';
        };
    });
    </script>
    </body></html>`,
))

func main() {
	fmt.Println("DNS Proxy starting...")
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
	fmt.Printf("Config loaded from %s\n", configPath)

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
	fmt.Printf("Upstream validated: %s (IP: %s)\n", config.UpstreamURL, upstreamIP)

	generateCertIfNeeded() // For DoH
	fmt.Println("Cert checked/generated if needed")

	// Sequential launches for ordered logging
	fmt.Println("Launching listeners sequentially...")
	startDNSListener(config.ListenDNS) // Blocks until complete/fail
	startDoHListener(config.ListenDoH) // Blocks until complete/fail
	go startWebUI(config.UIPort)       // Concurrent server (blocks forever, but post-serial)

	<-sigChan // Wait here - UI goroutine handles serving
	fmt.Println("Shutdown signal received")
	cancel() // Cancel context for graceful close
	shutdown()
}

func loadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("Config file %s not found; using defaults\n", path)
		// Defaults
		config = Config{
			ListenDNS:         "127.0.0.1:53",
			ListenDoH:         "127.0.0.1:443",
			UIPort:            8080,
			UpstreamURL:       "https://9.9.9.9/dns-query",
			SNIHostname:       "",
			BlockMode:         "nxdomain",
			BlockIP:           "0.0.0.0",
			RateQPS:           100,
			CacheMinTTL:       300,
			CacheMaxEntries:   10000,
			Whitelist:         make(map[string][]Rule),
			ResponseBlacklist: []string{"127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16", "::1/128", "fc00::/7"},
			WhitelistFile:     "query_whitelist.json",
			BlacklistFile:     "response_blacklist.json",
			LogQueries:        "queries.log",
			LogErrors:         "errors.log",
			LogMaxSizeMB:      4095, // Rotation threshold
			AllowRunAsAdmin:   false,
		}

		if err := saveConfig(path); err != nil {
			return fmt.Errorf("default config save failed: %w", err)
		}
		return nil
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("config unmarshal failed: %w", err)
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
			fmt.Fprintf(os.Stderr, "Log rotation failed for %s: %v\n", path, err)
		} else {
			fmt.Printf("Rotated log %s to %s (size exceeded %dMB)\n", path, old, maxMB)
		}
	}
}

func validateUpstream() error {
	var err error
	upstreamURL, err = url.Parse(config.UpstreamURL)
	if err != nil || upstreamURL.Scheme != "https" { //|| upstreamURL.Path != "/dns-query" {
		return errors.New("invalid upstream URL: must be similar to this: https://IP/dns-query")
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
				rules[i].ID = newUniqueID() // Gen outside lock
			}
		}
	}
	ruleMutex.Lock()
	defer ruleMutex.Unlock()
	whitelist = make(map[string][]Rule)
	loadErr := false
	fmt.Printf("Whitelist config has %d types\n", len(config.Whitelist))
	for typ, rules := range config.Whitelist {
		fmt.Printf("Processing type '%s' with %d rules...\n", typ, len(rules))
		var processed []Rule
		for i := range rules {
			fmt.Printf("  Rule %d: Pattern '%s', IsRegex %t, ID '%s'\n", i, rules[i].Pattern, rules[i].IsRegex, rules[i].ID)
			r := &rules[i]
			if !r.IsRegex {
				fmt.Print("    Converting wildcard to regex...")
				regexPat, err := wildcardToRegex(r.Pattern)
				if err != nil {
					errMsg := fmt.Sprintf("invalid wildcard for '%s': %v", r.Pattern, err)
					fmt.Fprintln(os.Stderr, errMsg)
					errorLogger.Error("invalid_wildcard", slog.String("pattern", r.Pattern), slog.Any("err", err))
					loadErr = true
					continue
				}
				r.Pattern = regexPat
				r.IsRegex = true
				fmt.Println("Success")
			} else {
				fmt.Println("    IsRegex true - skipping conversion")
			}
			// Validate regex (no RLock needed - inside write lock)
			fmt.Print("    Compiling regex...")
			if _, err := regexp.Compile(r.Pattern); err != nil {
				errMsg := fmt.Sprintf("invalid regex for '%s': %v", r.Pattern, err)
				fmt.Fprintln(os.Stderr, errMsg)
				errorLogger.Error("invalid_regex", slog.String("pattern", r.Pattern), slog.Any("err", err))
				loadErr = true
				continue
			}
			fmt.Println("Success")
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
		fmt.Printf("Type '%s' processed: %d valid rules\n", typ, len(processed))
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
	fmt.Println("starts newUniqueID()")
	existing := make(map[string]struct{})
	fmt.Println("in newUniqueID() before RLock")
	ruleMutex.RLock()
	fmt.Println("in newUniqueID() after RLock")
	for _, rs := range whitelist {
		for _, r := range rs {
			existing[r.ID] = struct{}{}
		}
	}
	fmt.Println("in newUniqueID() before RUnlock")
	ruleMutex.RUnlock()
	fmt.Println("in newUniqueID() after RUnlock")

	for i := 0; i < 10; i++ {
		id := uuid.New().String()
		if _, ok := existing[id]; !ok {
			fmt.Println("exits newUniqueID() ret:", id)
			return id
		}
	}
	panic("UUID collision limit reached—check RNG or storage")
}

func wildcardToRegex(pat string) (string, error) {
	// Convert: exact -> ^pat$; *.dom -> ^[^.]+\\.dom$; *dom -> .*dom$
	// Edge: Empty pat -> ^$; invalid chars escaped
	if pat == "" {
		return "^$", nil
	}
	pat = strings.ReplaceAll(pat, "\\", "\\\\") // Escape backslashes
	pat = strings.ReplaceAll(pat, ".", "\\.")
	pat = strings.ReplaceAll(pat, "$", "\\$")
	pat = strings.ReplaceAll(pat, "^", "\\^")
	pat = strings.ReplaceAll(pat, "(", "\\(")
	pat = strings.ReplaceAll(pat, ")", "\\)")
	pat = strings.ReplaceAll(pat, "[", "\\[")
	pat = strings.ReplaceAll(pat, "]", "\\]")

	if strings.HasPrefix(pat, "*") && strings.HasSuffix(pat, "*") {
		pat = strings.Trim(pat, "*")
		return "^.*" + pat + ".*$", nil
	}
	if strings.HasPrefix(pat, "*") {
		pat = strings.TrimPrefix(pat, "*")
		return "^.*" + pat + "$", nil
	}
	if strings.HasSuffix(pat, "*") {
		pat = strings.TrimSuffix(pat, "*")
		return "^" + pat + ".*$", nil
	}
	if strings.Contains(pat, "*") {
		// Subdomain wildcard: *.dom -> ^[^.]+\\.dom$
		parts := strings.Split(pat, ".")
		for i, p := range parts {
			if p == "*" {
				parts[i] = "[^.]+"
			}
		}
		return "^" + strings.Join(parts, "\\.") + "$", nil
	}
	return "^" + pat + "$", nil
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
			Organization: []string{"Local DNS Proxy"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour * 10),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
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
	fmt.Printf("Starting DNS listener on %s...\n", addr)

	// UDP
	fmt.Print("  Attempting UDP bind...")
	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53})
	/*	if err != nil {
		errStr := fmt.Sprintf("UDP bind failed on %s: %v", addr, err)
		fmt.Fprintln(os.Stderr, "Failed\n"+errStr)
		errorLogger.Error(errStr)
		listenerErrCh <- errors.New(errStr)
	} else {*/
	if err != nil {
		errStr := fmt.Sprintf("UDP bind failed on %s: %v", addr, err)
		fmt.Fprintln(os.Stderr, "Failed\n"+errStr)
		errorLogger.Error(errStr)
		//		select {  // Non-blocking send
		//		case listenerErrCh <- errors.New(errStr):
		//			default:  // Closed/dropped - log only
		//			errorLogger.Warn("err_channel_closed", slog.String("msg", errStr))
		//		}
		//return
		os.Exit(1)
	} else {
		fmt.Println("Success")
		fmt.Printf("UDP DNS listening on %s\n", addr)

		buf := make([]byte, 512+512)
		go func() {
			defer udpLn.Close()

			//TheFor:
			for {
				//udpLn.SetReadDeadline(time.Now().Add(3 * time.Second))
				//fmt.Println("in for...")
				//time.Sleep(1000 * time.Millisecond)  // Yield
				select {
				case <-ctx.Done():
					fmt.Println("quitting on shutdown...") // to see this you've to wait like 1 sec in shutdown() or that "press a key" msg does it.
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
					pid, exe, err := pidAndExeForUDP(clientAddr)
					if err != nil {
						fmt.Printf("clientAddr=%s couldn't get pid and exe name:%s\n", clientAddr, err)
					} else {
						fmt.Printf("clientAddr=%s pid=%d exe=%s\n", clientAddr, pid, exe)
					}
					//fmt.Println("new go routine for handling...",clientAddr, pidAndExeForUDP(clientAddr))
					//pidAndExeForUDP(&clientAddr)
					go handleUDP(buf[:n], clientAddr, udpLn)
				}
			}
		}()
	} // else

	// TCP
	fmt.Print("  Attempting TCP bind...")
	//tcpLn *net.TCPListener
	//	tcpLn, err := net.ListenTCP("tcp", addr)
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr) // parses, no DNS for literal IPs
	if err != nil {
		errStr := fmt.Sprintf("TCP bind failed(the address should be an IP) on %s: %v", addr, err)
		fmt.Fprintln(os.Stderr, "Failed\n"+errStr)
		errorLogger.Error(errStr)
		os.Exit(1)
	}
	tcpLn, err := net.ListenTCP("tcp", tcpAddr) // returns *net.TCPListener
	//if err != nil { /* handle */ }
	/*	if err != nil {
		errStr := fmt.Sprintf("TCP bind failed on %s: %v", addr, err)
		fmt.Fprintln(os.Stderr, "Failed\n"+errStr)
		errorLogger.Error(errStr)
		listenerErrCh <- errors.New(errStr)
	} else {*/
	if err != nil {
		errStr := fmt.Sprintf("TCP bind failed on %s: %v", addr, err)
		fmt.Fprintln(os.Stderr, "Failed\n"+errStr)
		errorLogger.Error(errStr)
		//		select {  // Non-blocking send
		//		case listenerErrCh <- errors.New(errStr):
		//			default:  // Closed/dropped - log only
		//			errorLogger.Warn("err_channel_closed", slog.String("msg", errStr))
		//		}
		//return
		os.Exit(1)
	} else {
		fmt.Println("Success")
		fmt.Printf("TCP DNS listening on %s\n", addr)
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
		fmt.Println("Warning: No DNS listeners active—degraded mode")
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
	fmt.Printf("Starting DoH listener on %s...\n", addr)

	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", dohHandler)

	fmt.Print("  Attempting TLS bind...")
	listener, err := tls.Listen("tcp", addr, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{dohCert}, // Use loaded cert
	})
	if err != nil {
		errStr := fmt.Sprintf("DoH listener failed on %s: %v", addr, err)
		fmt.Fprintln(os.Stderr, "Failed\n"+errStr)
		errorLogger.Error(errStr)
		os.Exit(1) // Fail-fast serial
	}
	fmt.Println("Success")
	fmt.Printf("DoH listening on %s\n", addr)

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
		re, _ := regexp.Compile(rule.Pattern)
		if re.MatchString(domain) {
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
		// Assume go-cache TTL handles expiry
		logQuery(clientAddr, domain, qtype, "cache_hit", matchedID, nil)
		return cached
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
	///////////////////////////////

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
        return "Blocked by proxy.exe"
    }
	// Get startup time. "15:04:05" is the Go magic layout for HH:MM:SS
    // You can also use time.DateOnly (2006-01-02) if you prefer
    startTime := time.Now().Format("2006-01-02 15:04:05")

    return "Blocked by " + exePath + " [Started: " + startTime + "]"
    //return "Blocked by " + exePath
}

func blockResponse(msg *dns.Msg) *dns.Msg {
	//in Go, implicit 'break' after each 'case'
	switch config.BlockMode {
	case "nxdomain":
		msg.SetRcode(msg, dns.RcodeNameError)
	case "ip_block", "block_ip":
		ttl := uint32(300)
		blockIP := net.ParseIP(config.BlockIP)
		if blockIP == nil {
			blockIP = net.IPv4(0, 0, 0, 0) // Default
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
	
/*	// Get the absolute path to the running .exe
	exePath, err := os.Executable()
	if err != nil {
		exePath = "proxy.exe" // Fallback
	}

	// Create the dynamic string
	edeText := "Blocked by " + exePath

	// Create the EDE option with the dynamic text
	ede := &dns.EDNS0_EDE{
		InfoCode:  dns.ExtendedErrorCodeBlocked,
		ExtraText: edeText,
	}*/
	
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
	nets := make([]*net.IPNet, 0, len(blacklists))
	for _, cidr := range blacklists {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, ipnet)
		} else {
			errorLogger.Warn("invalid_cidr", slog.String("cidr", cidr))
		}
	}
	var goodAnswer, goodExtra []dns.RR
	for _, rr := range msg.Answer {
        if keep, modifiedRR := processRR(rr, nets); keep {
            goodAnswer = append(goodAnswer, modifiedRR)
        }
    }
    for _, rr := range msg.Extra {
        if keep, modifiedRR := processRR(rr, nets); keep {
            goodExtra = append(goodExtra, modifiedRR)
        }
    }

	msg.Answer = goodAnswer
	msg.Extra = goodExtra
	
	if len(msg.Answer) == 0 {
		errorLogger.Warn("response_filtered_all", slog.String("domain", msg.Question[0].Name))
		return nil
	}
	return msg
}

func processRR(rr dns.RR, nets []*net.IPNet) (bool, dns.RR) {
    switch r := rr.(type) {
    case *dns.A:
        if ipInNets(r.A, nets) { return false, nil }
        return true, r

    case *dns.AAAA:
        if ipInNets(r.AAAA, nets) { return false, nil }
        return true, r

    // Look for HTTPS records (Type 65)
    case *dns.HTTPS:
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
	fmt.Printf("Starting web UI on 127.0.0.1:%d...\n", port)

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
	fmt.Printf("Web UI listening on 127.0.0.1:%d (stats at /debug/vars)\n", port)

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
	body := fmt.Sprintf("<p>Blocks: %s</p><p>Cache size: %d</p><p>Upstream IP: %s</p>", stats.String(), cacheStore.ItemCount(), upstreamIP)
	//uiTemplates.Execute(w, struct{ Body string }{Body: body})
	uiTemplates.Execute(w, struct{ Body template.HTML }{Body: template.HTML(body)}) // Raw HTML, no escape
}

/*func rulesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
    ruleMutex.RLock()
    defer ruleMutex.RUnlock()

    var body strings.Builder

    // Table header
    body.WriteString("<h2>Whitelist Rules</h2>")
    body.WriteString("<table><tr><th>Type</th><th>ID</th><th>Pattern</th><th>Enabled</th><th>Actions</th></tr>")

    // Rules rows
    for typ, rules := range whitelist {
        for _, rule := range rules {
            enabled := "Yes"
            if !rule.Enabled {
                enabled = "No"
            }
            body.WriteString(fmt.Sprintf(
                "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>"+
                    "<button data-edit-id=\"%s\" data-edit-type=\"%s\" data-edit-pattern=\"%s\" data-edit-enabled=\"%t\">Edit</button>"+
                    "</td></tr>",
                typ, rule.ID, html.EscapeString(rule.Pattern), enabled,
                rule.ID, typ, html.EscapeString(rule.Pattern), rule.Enabled,
            ))
        }
    }
    body.WriteString("</table>")

    // Add new rule form with full type dropdown
    body.WriteString("<h2>Add New Rule</h2>")
    body.WriteString("<form method=\"post\" action=\"/rules\">")
    body.WriteString("<select name=\"type\">")
    for _, t := range dnsTypes {
        body.WriteString(fmt.Sprintf("<option value=\"%s\">%s</option>", t, t))
    }
    body.WriteString("</select> ")
    body.WriteString("<input type=\"text\" name=\"pattern\" placeholder=\"pattern\" required> ")
    body.WriteString("<label><input type=\"checkbox\" name=\"enabled\" checked> Enabled</label> ")
    body.WriteString("<button type=\"submit\">Add Rule</button>")
    body.WriteString("</form>")

    // Execute template with dynamic body
    uiTemplates.Execute(w, struct{ Body template.HTML }{Body: template.HTML(body.String())})
    return
}
//	if r.Method == "POST" {
//		pattern := r.FormValue("pattern")
//		typ := r.FormValue("type")
//		id := r.FormValue("id") // For edit
//		enabledStr := r.FormValue("enabled")
//		enabledBool := enabledStr == "true"
//		if typ == "" {
//			//FIXME: when this happens, enabled is not true
//			typ = "A"
//		}
//		if pattern != "" && typ != "" {
//			var newID string
//			if id == "" {
//				newID = newUniqueID() // Gen ID pre-lock (no nesting)
//			} else {
//				newID = id // Edit uses existing
//			}
//			ruleMutex.Lock()
//			var newRule Rule
//			if id != "" {
//				// Edit: Find and update
//				for i, r := range config.Whitelist[typ] {
//					if r.ID == id {
//						newRule = Rule{ID: id, Pattern: pattern, IsRegex: false, Enabled: enabledBool}
//						config.Whitelist[typ][i] = newRule
//						whitelist[typ][i] = newRule
//						break
//					}
//				}
//			} else {
//				// Add
//				newRule = Rule{ID: newID, Pattern: pattern, IsRegex: false, Enabled: enabledBool}
//				config.Whitelist[typ] = append(config.Whitelist[typ], newRule)
//				whitelist[typ] = append(whitelist[typ], newRule)
//			}
//			ruleMutex.Unlock()
//			saveConfig("config.json")
//			fmt.Printf("Rule updated/added for %s: %s\n", typ, pattern)
//		}
//		http.Redirect(w, r, "/rules", http.StatusSeeOther)
//	}
	if r.Method == "POST" {
    pattern := r.FormValue("pattern")
    typ := r.FormValue("type")  // From select
    id := r.FormValue("id")
    enabledStr := r.FormValue("enabled")
		enabledBool := enabledStr == "true" || enabledStr == "on"  // Checkbox sends "on" if checked
    if pattern != "" && typ != "" {
        if id != "" {
						ruleMutex.Lock()
						defer ruleMutex.Unlock()
            // Edit: Find in old typ (assume typ param is new type; search all for old)
            //oldTyp := typ  // Default to same if no change
            found := false
            for oldT, rs := range config.Whitelist {
                for i, r := range rs {
                    if r.ID == id {
                        // Remove from old typ
                        config.Whitelist[oldT] = append(rs[:i], rs[i+1:]...)
                        whitelist[oldT] = append(rs[:i], rs[i+1:]...)
                        found = true
                        //oldTyp = oldT
                        break
                    }
                }
                if found {
                    break
                }
            }
            if !found {
                //ruleMutex.Unlock()
                http.Error(w, "Rule not found", http.StatusNotFound)
                return
            }
            // Add/update in new typ
            newRule := Rule{ID: id, Pattern: pattern, IsRegex: false, Enabled: enabledBool}
            if _, ok := config.Whitelist[typ]; !ok {
                config.Whitelist[typ] = []Rule{}
                whitelist[typ] = []Rule{}
            }
            config.Whitelist[typ] = append(config.Whitelist[typ], newRule)
            whitelist[typ] = append(whitelist[typ], newRule)
        } else {
						newID := newUniqueID() //FIXME: ugly
						ruleMutex.Lock()
						defer ruleMutex.Unlock()
//            // Add new
//            newID := newUniqueID()
//            newRule := Rule{ID: newID, Pattern: pattern, IsRegex: false, Enabled: enabledBool}
//            if _, ok := config.Whitelist[typ]; !ok {
//                config.Whitelist[typ] = []Rule{}
//                whitelist[typ] = []Rule{}
//            }
//            config.Whitelist[typ] = append(config.Whitelist[typ], newRule)
//            whitelist[typ] = append(whitelist[typ], newRule)

						// Add
						//ruleMutex.Unlock()
						//ruleMutex.Lock()
						//defer ruleMutex.Unlock()
						newRule := Rule{ID: newID, Pattern: pattern, IsRegex: false, Enabled: enabledBool}
						if _, ok := config.Whitelist[typ]; !ok {
								config.Whitelist[typ] = []Rule{}
								whitelist[typ] = []Rule{}
						}
						config.Whitelist[typ] = append(config.Whitelist[typ], newRule)  // Single append
						whitelist[typ] = append(whitelist[typ], newRule)              // Single append
        }
        saveConfig("config.json")
        fmt.Printf("Rule updated/added for %s: %s (ID: %s, Enabled: %t)\n", typ, pattern, id, enabledBool)
    }
    http.Redirect(w, r, "/rules", http.StatusSeeOther)
}//POST
}*/

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
				body.WriteString(fmt.Sprintf(
					"<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>"+
						"<button data-edit-id=\"%s\" data-edit-type=\"%s\" data-edit-pattern=\"%s\" data-edit-enabled=\"%t\">Edit</button>"+
						"</td></tr>",
					typ, rule.ID, escapedPattern, enabled,
					rule.ID, typ, escapedPattern, rule.Enabled,
				))
			}
		}
		body.WriteString("</table>")

		// Add form
		body.WriteString("<h2>Add New Rule</h2>")
		body.WriteString("<form method=\"post\" action=\"/rules\">")
		body.WriteString("<select name=\"type\">")
		for _, t := range dnsTypes {
			body.WriteString(fmt.Sprintf("<option value=\"%s\">%s</option>", t, t))
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
					break
				}
			}
			if !found {
				http.Error(w, "Rule not found", http.StatusNotFound)
				return
			}

			// Add to new type
			newRule := Rule{ID: id, Pattern: pattern, IsRegex: false, Enabled: enabledBool}
			if _, ok := config.Whitelist[typ]; !ok {
				config.Whitelist[typ] = []Rule{}
				whitelist[typ] = []Rule{}
			}
			config.Whitelist[typ] = append(config.Whitelist[typ], newRule)
			whitelist[typ] = append(whitelist[typ], newRule)

			fmt.Printf("Rule edited: %s → %s (ID: %s, Enabled: %t)\n", id, pattern, id, enabledBool)
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

			newRule := Rule{ID: newID, Pattern: pattern, IsRegex: false, Enabled: enabledBool}
			if _, ok := config.Whitelist[typ]; !ok {
				config.Whitelist[typ] = []Rule{}
				whitelist[typ] = []Rule{}
			}
			config.Whitelist[typ] = append(config.Whitelist[typ], newRule)
			whitelist[typ] = append(whitelist[typ], newRule)

			fmt.Printf("Rule added: %s (type: %s, ID: %s, Enabled: %t)\n", pattern, typ, newID, enabledBool)
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
			body.WriteString(fmt.Sprintf("<li>%s (%s) <form method=post action=/blocks><input type=hidden name=domain value=\"%s\"><input type=hidden name=type value=A><button>Unblock A</button></form> <button onclick=\"location.href='/blocks?type=AAAA&domain=%s'\">Unblock AAAA</button></li>",
				b.Domain, b.Type, b.Domain, b.Domain))
		}
		body.WriteString("</ul>")
		blockMutex.Unlock()
		//uiTemplates.Execute(w, struct{ Body string }{Body: body.String()})
		uiTemplates.Execute(w, struct{ Body template.HTML }{Body: template.HTML(body.String())})
		return
	}
	if r.Method == "POST" {
		domain := r.FormValue("domain")
		typ := r.FormValue("type")
		if domain != "" && typ != "" {
			// Add rule for typ
			newRule := Rule{ID: newUniqueID(), Pattern: domain, IsRegex: false, Enabled: true}
			ruleMutex.Lock()
			config.Whitelist[typ] = append(config.Whitelist[typ], newRule)
			whitelist[typ] = append(whitelist[typ], newRule)
			ruleMutex.Unlock()
			saveConfig("config.json")
			fmt.Printf("Quick unblock added for %s (%s)\n", domain, typ)
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
	body := fmt.Sprintf("<h2>Logs (filtered by '%s')</h2><pre style=\"max-height:400px;overflow:auto;\">%s</pre>", domainFilter, strings.Join(filtered, "\n"))
	//uiTemplates.Execute(w, struct{ Body string }{Body: body})
	uiTemplates.Execute(w, struct{ Body template.HTML }{Body: template.HTML(body)}) // Raw HTML, no escape
}

func shutdown() {
	fmt.Println("Shutting down...")
	//dohSrv.Shutdown(ctx); //done differenly at start place
	//dohCert=nil;
	fmt.Println("DoH down...")
	cacheStore.Flush()
	fmt.Println("Cache flushed")
	//uiSrv.Shutdown(ctx);
	fmt.Println("webUI shutdown")
	// Close log files (reopen on next run)
	//sleep 1 sec to allow "quitting on shutdown" message to show.
	select {
	case <-time.After(1000 * time.Millisecond):
	}
	fmt.Print("Press Enter to exit...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
	os.Exit(0)
}
