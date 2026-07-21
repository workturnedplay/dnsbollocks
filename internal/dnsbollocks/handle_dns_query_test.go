//go:build windows
// +build windows

package dnsbollocks

import (
	"context"
	"expvar"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ── Mock DoHForwarder ─────────────────────────────────────────────────────────

type mockDoHForwarder struct {
	mu    sync.Mutex
	calls int
	fn    func(ctx context.Context, req *dns.Msg) (*dns.Msg, UpstreamState)
}

func (m *mockDoHForwarder) ForwardToDoH(ctx context.Context, req *dns.Msg) (*dns.Msg, UpstreamState) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
	return m.fn(ctx, req)
}

func (m *mockDoHForwarder) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// fixedFwd returns the same response and state on every call.
func fixedFwd(resp *dns.Msg, state UpstreamState) *mockDoHForwarder {
	return &mockDoHForwarder{
		fn: func(_ context.Context, _ *dns.Msg) (*dns.Msg, UpstreamState) {
			return resp, state
		},
	}
}

// nilFwd simulates total upstream failure (all upstreams down).
func nilFwd() *mockDoHForwarder {
	return fixedFwd(nil, UpstreamState{Strategy: "test"})
}

// ── Test Server Factory ───────────────────────────────────────────────────────

// newQueryTestServer builds the minimum viable Server needed by handleDNSQuery.
// No listeners or background goroutines are started; all fields are initialised
// directly so the test controls the full lifecycle.
func newQueryTestServer(t *testing.T, cfg Config, fwd DoHForwarder) *Server {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	s := &Server{
		ruleStore:    newRuleStore(),
		hostStore:    newHostStore(),
		blacklist:    newBlacklistStore(),
		recentBlocks: newRecentBlocksTracker(),
		//dnsCache:     newGoCacheStore(5 * time.Minute),
		stats:        new(expvar.Int), // unregistered; avoids expvar duplicate-key panic
		dohForwarder: fwd,
	}
	s.liveConfigs.Store(&LiveConfigs{
		Resolved: &cfg,
		Raw:      &cfg,
	})
	s.rt = newTestRuntime(log)
	s.swapDNSCache(5, 100)
	// t.Context() is cancelled when the test ends, which cleanly stops the
	// rate limiter's internal janitor goroutine.
	s.rateLimiter = newClientRateLimiter(t.Context(), rateLimitConfigFrom(cfg), log)
	return s
}

// ── DNS Message Helpers ───────────────────────────────────────────────────────

// aQuery produces a TypeA query with a fixed, recognisable ID.
func aQuery(domain string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.Id = 7777
	return m
}

// aaaaQuery produces a TypeAAAA query.
func aaaaQuery(domain string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeAAAA)
	m.Id = 7777
	return m
}

// httpsQueryMsg produces a TypeHTTPS query.
func httpsQueryMsg(domain string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)
	m.Id = 7777
	return m
}

// upstreamAResp builds a typical upstream success response containing A records.
// The query is used to set the reply header so Question is populated (required
// by filterResponse which panics on empty Question).
func upstreamAResp(query *dns.Msg, ips ...string) *dns.Msg {
	r := new(dns.Msg)
	r.SetReply(query)
	r.Rcode = dns.RcodeSuccess
	r.RecursionAvailable = true
	for _, ip := range ips {
		r.Answer = append(r.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   query.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP(ip).To4(),
		})
	}
	return r
}

// // upstreamAAAAResp builds an upstream success response containing AAAA records.
// func upstreamAAAAResp(query *dns.Msg, ips ...string) *dns.Msg {
// 	r := new(dns.Msg)
// 	r.SetReply(query)
// 	r.Rcode = dns.RcodeSuccess
// 	r.RecursionAvailable = true
// 	for _, ip := range ips {
// 		r.Answer = append(r.Answer, &dns.AAAA{
// 			Hdr: dns.RR_Header{
// 				Name:   query.Question[0].Name,
// 				Rrtype: dns.TypeAAAA,
// 				Class:  dns.ClassINET,
// 				Ttl:    300,
// 			},
// 			AAAA: net.ParseIP(ip),
// 		})
// 	}
// 	return r
// }

// upstreamFailResp builds a non-success upstream response (e.g. SERVFAIL).
func upstreamFailResp(query *dns.Msg, rcode int) *dns.Msg {
	r := new(dns.Msg)
	r.SetReply(query)
	r.Rcode = rcode
	return r
}

// addWhitelistRule adds an enabled rule to the server's rule store; fatals on
// duplicate or other error.
func addWhitelistRule(t *testing.T, s *Server, typ, pattern string) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := s.ruleStore.AddRule(typ, pattern, true, log); err != nil {
		t.Fatalf("addWhitelistRule(%q, %q): %v", typ, pattern, err)
	}
}

// testClient is a non-loopback address. The rate limiter normalises 127.x.x.x
// → "localhost", which would collapse all tests sharing a server into one
// per-client bucket. Using a TEST-NET address avoids that.
const testClient = "192.0.2.1:9999"

// altClient is a second address with a different IP used when a test needs two
// independent per-client rate-limit buckets.
const altClient = "192.0.2.2:9999"

// ── Format Error Tests ────────────────────────────────────────────────────────

func TestHandleDNSQuery_FormatErrors(t *testing.T) {
	// A single server is fine here; format errors never reach the forwarder.
	fwd := nilFwd()
	s := newQueryTestServer(t, defaultConfig(), fwd)

	cases := []struct {
		name string
		msg  func() *dns.Msg
	}{
		{
			name: "no questions",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.Id = 1
				return m
			},
		},
		{
			name: "multiple questions",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.Id = 2
				m.Question = []dns.Question{
					{Name: "a.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
					{Name: "b.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				}
				return m
			},
		},
		{
			name: "root dot only → empty domain after TrimSuffix",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.Id = 3
				m.Question = []dns.Question{
					{Name: ".", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				}
				return m
			},
		},
		{
			name: "label starts with hyphen",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.Question = []dns.Question{
					{Name: "-bad.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				}
				return m
			},
		},
		{
			name: "label exceeds 63 characters",
			msg: func() *dns.Msg {
				// Build a 64-char label; isValidDNSName regex only allows ≤63.
				label := ""
				for i := 0; i < 64; i++ {
					label += "a"
				}
				m := new(dns.Msg)
				m.Question = []dns.Question{
					{Name: label + ".com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				}
				return m
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := s.handleDNSQuery(context.Background(), tc.msg(), testClient)
			if resp == nil {
				t.Fatal("want non-nil FORMERR response, got nil")
			}
			if resp.Rcode != dns.RcodeFormatError {
				t.Errorf("rcode: want FORMERR(%d), got %d", dns.RcodeFormatError, resp.Rcode)
			}
		})
	}

	// Format errors must never reach the upstream forwarder.
	if n := fwd.CallCount(); n != 0 {
		t.Errorf("DoH forwarder called %d times for format errors; want 0", n)
	}
}

// ── Rate Limiting Tests ───────────────────────────────────────────────────────

func TestHandleDNSQuery_RateLimit_Global(t *testing.T) {
	cfg := defaultConfig()
	cfg.GlobalRateQPS = 1
	cfg.GlobalBurstQPS = 1
	// Keep per-client limit high so only the global limit triggers.
	cfg.ClientRateQPS = 1000
	cfg.ClientBurstQPS = 1000

	fwd := nilFwd()
	s := newQueryTestServer(t, cfg, fwd)

	// Drain the single global token.
	s.rateLimiter.Allow(altClient)

	// This request must be rejected by the global limiter.
	resp := s.handleDNSQuery(context.Background(), aQuery("example.com"), testClient)

	if resp == nil {
		t.Fatal("want non-nil SERVFAIL, got nil")
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode: want SERVFAIL(%d), got %d", dns.RcodeServerFailure, resp.Rcode)
	}
	// Rate-limited requests still must not reach the forwarder.
	if n := fwd.CallCount(); n != 0 {
		t.Errorf("DoH forwarder called %d times; want 0", n)
	}
}

func TestHandleDNSQuery_RateLimit_PerClient(t *testing.T) {
	cfg := defaultConfig()
	// Global limit is generous; only per-client should trigger.
	cfg.GlobalRateQPS = 1000
	cfg.GlobalBurstQPS = 1000
	cfg.ClientRateQPS = 1
	cfg.ClientBurstQPS = 1

	fwd := nilFwd()
	s := newQueryTestServer(t, cfg, fwd)

	// Drain the per-client token for testClient.
	s.rateLimiter.Allow(testClient)

	// Same IP again; global is fine but per-client bucket is empty.
	resp := s.handleDNSQuery(context.Background(), aQuery("example.com"), testClient)

	if resp == nil {
		t.Fatal("want non-nil SERVFAIL, got nil")
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode: want SERVFAIL(%d), got %d", dns.RcodeServerFailure, resp.Rcode)
	}
	if n := fwd.CallCount(); n != 0 {
		t.Errorf("DoH forwarder called %d times; want 0", n)
	}
}

// ── Whitelist / Block Tests ───────────────────────────────────────────────────

func TestHandleDNSQuery_Blocked_NoMatchingRule(t *testing.T) {
	s := newQueryTestServer(t, defaultConfig(), nilFwd())
	// No rules added; every query should be blocked.
	initialStats := s.stats.Value()

	resp := s.handleDNSQuery(context.Background(), aQuery("blocked.com"), testClient)

	if resp == nil {
		t.Fatal("want non-nil block response, got nil")
	}
	// defaultConfig BlockMode = "nxdomain"
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode: want NXDOMAIN(%d), got %d", dns.RcodeNameError, resp.Rcode)
	}

	// Stats counter must increment on every block.
	if s.stats.Value() != initialStats+1 {
		t.Errorf("stats: want %d, got %d", initialStats+1, s.stats.Value())
	}

	// Domain must appear in the recent-blocks tracker.
	snap := s.recentBlocks.Snapshot(func(_, _ string) bool { return false })
	if len(snap) != 1 {
		t.Fatalf("recentBlocks length: want 1, got %d", len(snap))
	}
	if snap[0].Domain != "blocked.com" || snap[0].Type != "A" {
		t.Errorf("recentBlocks[0]: want {blocked.com A}, got {%s %s}", snap[0].Domain, snap[0].Type)
	}
}

func TestHandleDNSQuery_Blocked_AAAA_ReturnsEmptyNoError(t *testing.T) {
	// When BlockAAAAasEmptyNoError=true and BlockMode=nxdomain, a blocked AAAA
	// query must return RcodeSuccess with zero answer records instead of NXDOMAIN.
	// This prevents AAAA-aware clients from permanently blacklisting a domain.
	cfg := defaultConfig()
	cfg.BlockAAAAasEmptyNoError = true
	cfg.BlockMode = "nxdomain"

	s := newQueryTestServer(t, cfg, nilFwd())
	// Deliberately no AAAA rule added.

	resp := s.handleDNSQuery(context.Background(), aaaaQuery("example.com"), testClient)

	if resp == nil {
		t.Fatal("want non-nil response, got nil")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode: want Success(%d), got %d", dns.RcodeSuccess, resp.Rcode)
	}
	if len(resp.Answer) != 0 {
		t.Errorf("Answer: want 0 records, got %d", len(resp.Answer))
	}
}

func TestHandleDNSQuery_HTTPS_AllowedViaARule(t *testing.T) {
	// With AllowHTTPSIfAAllowed=true, an existing A rule unlocks HTTPS queries
	// for the same domain even when no explicit HTTPS rule is present.
	cfg := defaultConfig()
	cfg.AllowHTTPSIfAAllowed = true

	q := httpsQueryMsg("example.com")
	// Return a trivial success (no answer records) so filterResponse passes.
	noDataResp := new(dns.Msg)
	noDataResp.SetReply(q)
	noDataResp.Rcode = dns.RcodeSuccess

	fwd := fixedFwd(noDataResp, UpstreamState{Strategy: "fastest"})
	s := newQueryTestServer(t, cfg, fwd)
	addWhitelistRule(t, s, "A", "example.com") // A rule, NOT HTTPS

	resp := s.handleDNSQuery(context.Background(), q, testClient)

	if resp == nil {
		t.Fatal("want non-nil response; HTTPS query via A rule should not be blocked")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode: want Success(%d), got %d", dns.RcodeSuccess, resp.Rcode)
	}
	if fwd.CallCount() != 1 {
		t.Errorf("DoH forwarder call count: want 1, got %d", fwd.CallCount())
	}
}

func TestHandleDNSQuery_HTTPS_BlockedWhenFeatureDisabled(t *testing.T) {
	// With AllowHTTPSIfAAllowed=false, an A rule must NOT unlock HTTPS queries.
	cfg := defaultConfig()
	cfg.AllowHTTPSIfAAllowed = false

	fwd := nilFwd()
	s := newQueryTestServer(t, cfg, fwd)
	addWhitelistRule(t, s, "A", "example.com") // A rule only

	resp := s.handleDNSQuery(context.Background(), httpsQueryMsg("example.com"), testClient)

	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode: want NXDOMAIN(%d) when HTTPS feature is off, got %d",
			dns.RcodeNameError, resp.Rcode)
	}
	if fwd.CallCount() != 0 {
		t.Errorf("DoH forwarder must not be called when domain is blocked, got %d calls", fwd.CallCount())
	}
}

func TestHandleDNSQuery_HTTPS_BlockedWithoutAnyRule(t *testing.T) {
	// Even with the feature enabled, absence of both A and HTTPS rules blocks.
	cfg := defaultConfig()
	cfg.AllowHTTPSIfAAllowed = true

	fwd := nilFwd()
	s := newQueryTestServer(t, cfg, fwd)
	// No rules at all.

	resp := s.handleDNSQuery(context.Background(), httpsQueryMsg("example.com"), testClient)

	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode: want NXDOMAIN(%d), got %d", dns.RcodeNameError, resp.Rcode)
	}
	if fwd.CallCount() != 0 {
		t.Errorf("DoH forwarder must not be called, got %d calls", fwd.CallCount())
	}
}

// ── Cache Tests ───────────────────────────────────────────────────────────────

func TestHandleDNSQuery_CacheHit_BypassesForwarder(t *testing.T) {
	fwd := nilFwd() // would panic the test if called
	s := newQueryTestServer(t, defaultConfig(), fwd)
	addWhitelistRule(t, s, "A", "cached.example.com")

	// Pre-populate the cache with the exact key handleDNSQuery would produce.
	key := "cached.example.com:A"
	cachedMsg := upstreamAResp(aQuery("cached.example.com"), "1.2.3.4")
	s.getCache().Set(key, CacheEntry{
		Msg:   cachedMsg,
		State: UpstreamState{Strategy: "fastest", UpstreamUsed: "https://1.1.1.1/dns-query"},
	}, time.Minute)

	q := aQuery("cached.example.com")
	q.Id = 4242

	resp := s.handleDNSQuery(context.Background(), q, testClient)

	if resp == nil {
		t.Fatal("want non-nil cache response, got nil")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode: want Success, got %d", resp.Rcode)
	}
	// Original query ID must be preserved even on a cache hit.
	if resp.Id != 4242 {
		t.Errorf("response ID: want 4242, got %d", resp.Id)
	}
	// Forwarder must not be contacted.
	if n := fwd.CallCount(); n != 0 {
		t.Errorf("DoH forwarder called %d times on cache hit; want 0", n)
	}
	// Verify the cached IP is in the response.
	ips := extractIPs(resp)
	if len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Errorf("cached IPs: want [1.2.3.4], got %v", ips)
	}
}

func TestHandleDNSQuery_CachePopulatedAfterForward(t *testing.T) {
	// After a successful forward, the same query must be served from cache
	// without calling the forwarder a second time.
	q := aQuery("example.com")
	fwd := fixedFwd(upstreamAResp(q, "8.8.8.8"), UpstreamState{Strategy: "fastest"})
	s := newQueryTestServer(t, defaultConfig(), fwd)
	addWhitelistRule(t, s, "A", "example.com")

	// First request: should reach the forwarder.
	s.handleDNSQuery(context.Background(), aQuery("example.com"), testClient)
	if fwd.CallCount() != 1 {
		t.Fatalf("first request: forwarder call count want 1, got %d", fwd.CallCount())
	}

	// Second request: must hit the cache.
	s.handleDNSQuery(context.Background(), aQuery("example.com"), testClient)
	if fwd.CallCount() != 1 {
		t.Errorf("second request: forwarder call count still want 1, got %d (cache miss?)", fwd.CallCount())
	}
}

// ── Local Host Override Tests ─────────────────────────────────────────────────

func TestHandleDNSQuery_LocalHost_A(t *testing.T) {
	fwd := nilFwd()
	s := newQueryTestServer(t, defaultConfig(), fwd)
	addWhitelistRule(t, s, "A", "router.local")
	if err := s.hostStore.AddHost("router.local", []net.IP{net.ParseIP("192.168.1.1")}); err != nil {
		t.Fatalf("AddHost: %v", err)
	}

	resp := s.handleDNSQuery(context.Background(), aQuery("router.local"), testClient)

	if resp == nil {
		t.Fatal("want non-nil response, got nil")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode: want Success, got %d", resp.Rcode)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("Answer: want 1 A record, got %d", len(resp.Answer))
	}
	aRec, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatal("expected *dns.A record in Answer")
	}
	if !aRec.A.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("A record IP: want 192.168.1.1, got %v", aRec.A)
	}
	if n := fwd.CallCount(); n != 0 {
		t.Errorf("DoH forwarder must not be called for local host override, got %d calls", n)
	}
}

func TestHandleDNSQuery_LocalHost_AAAA(t *testing.T) {
	fwd := nilFwd()
	s := newQueryTestServer(t, defaultConfig(), fwd)
	addWhitelistRule(t, s, "AAAA", "ipv6host.local")
	if err := s.hostStore.AddHost("ipv6host.local", []net.IP{net.ParseIP("2001:db8::1")}); err != nil {
		t.Fatalf("AddHost: %v", err)
	}

	resp := s.handleDNSQuery(context.Background(), aaaaQuery("ipv6host.local"), testClient)

	if resp == nil {
		t.Fatal("want non-nil response, got nil")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode: want Success, got %d", resp.Rcode)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("Answer: want 1 AAAA record, got %d", len(resp.Answer))
	}
	aaaaRec, ok := resp.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatal("expected *dns.AAAA record in Answer")
	}
	if !aaaaRec.AAAA.Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("AAAA record IP: want 2001:db8::1, got %v", aaaaRec.AAAA)
	}
	if n := fwd.CallCount(); n != 0 {
		t.Errorf("DoH forwarder must not be called, got %d calls", n)
	}
}

func TestHandleDNSQuery_LocalHost_TypeMismatch_ReturnsEmptySuccess(t *testing.T) {
	// When the host store has only IPv4 IPs but the query is AAAA, the host
	// store still intercepts (preventing a forwarded upstream call), but
	// returns Success with zero answer records — correct NODATA behaviour.
	fwd := nilFwd()
	s := newQueryTestServer(t, defaultConfig(), fwd)
	addWhitelistRule(t, s, "AAAA", "dualstack.local")
	if err := s.hostStore.AddHost("dualstack.local", []net.IP{net.ParseIP("10.0.0.1")}); err != nil {
		t.Fatalf("AddHost: %v", err)
	}

	resp := s.handleDNSQuery(context.Background(), aaaaQuery("dualstack.local"), testClient)

	if resp == nil {
		t.Fatal("want non-nil response, got nil")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode: want Success(%d), got %d", dns.RcodeSuccess, resp.Rcode)
	}
	if len(resp.Answer) != 0 {
		t.Errorf("Answer: want 0 records (type mismatch), got %d", len(resp.Answer))
	}
	if n := fwd.CallCount(); n != 0 {
		t.Errorf("DoH forwarder must not be called when hostStore matches, got %d calls", n)
	}
}

// ── DoH Forwarding Tests ──────────────────────────────────────────────────────

func TestHandleDNSQuery_Forward_Success(t *testing.T) {
	q := aQuery("example.com")
	fwd := fixedFwd(upstreamAResp(q, "8.8.8.8"), UpstreamState{Strategy: "fastest"})
	s := newQueryTestServer(t, defaultConfig(), fwd)
	addWhitelistRule(t, s, "A", "example.com")

	q.Id = 5555
	resp := s.handleDNSQuery(context.Background(), q, testClient)

	if resp == nil {
		t.Fatal("want non-nil response, got nil")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode: want Success, got %d", resp.Rcode)
	}
	if fwd.CallCount() != 1 {
		t.Errorf("forwarder call count: want 1, got %d", fwd.CallCount())
	}
	// Original query ID must be in the response even though the forwarder
	// received a randomised ID (handleDNSQuery scrambles and restores it).
	if resp.Id != 5555 {
		t.Errorf("response ID: want 5555, got %d", resp.Id)
	}
	ips := extractIPs(resp)
	if len(ips) != 1 || ips[0] != "8.8.8.8" {
		t.Errorf("IPs: want [8.8.8.8], got %v", ips)
	}
}

func TestHandleDNSQuery_Forward_NilResponse_ServFail(t *testing.T) {
	// All upstreams unreachable → nil from forwarder → SERVFAIL to client.
	fwd := nilFwd()
	s := newQueryTestServer(t, defaultConfig(), fwd)
	addWhitelistRule(t, s, "A", "example.com")

	resp := s.handleDNSQuery(context.Background(), aQuery("example.com"), testClient)

	if resp == nil {
		t.Fatal("want non-nil SERVFAIL, got nil")
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode: want SERVFAIL(%d), got %d", dns.RcodeServerFailure, resp.Rcode)
	}
}

func TestHandleDNSQuery_Forward_NonSuccessRcode_ServFail(t *testing.T) {
	// Upstream returns SERVFAIL itself → propagated to client as SERVFAIL.
	q := aQuery("example.com")
	fwd := fixedFwd(upstreamFailResp(q, dns.RcodeServerFailure), UpstreamState{})
	s := newQueryTestServer(t, defaultConfig(), fwd)
	addWhitelistRule(t, s, "A", "example.com")

	resp := s.handleDNSQuery(context.Background(), aQuery("example.com"), testClient)

	if resp == nil {
		t.Fatal("want non-nil SERVFAIL, got nil")
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode: want SERVFAIL(%d), got %d", dns.RcodeServerFailure, resp.Rcode)
	}
}

func TestHandleDNSQuery_Forward_NegativeResultCached(t *testing.T) {
	// A SERVFAIL must be cached under CacheNegativeTTLSec so the second
	// identical query does not hit the forwarder again.
	q := aQuery("example.com")
	fwd := nilFwd()
	s := newQueryTestServer(t, defaultConfig(), fwd)
	addWhitelistRule(t, s, "A", "example.com")

	s.handleDNSQuery(context.Background(), aQuery("example.com"), testClient)
	if fwd.CallCount() != 1 {
		t.Fatalf("first request: forwarder call count want 1, got %d", fwd.CallCount())
	}

	_ = q // second query below
	resp := s.handleDNSQuery(context.Background(), aQuery("example.com"), testClient)
	if fwd.CallCount() != 1 {
		t.Errorf("second request: forwarder must not be called again (negative cached), got %d calls", fwd.CallCount())
	}
	// The cached SERVFAIL must still come back as SERVFAIL.
	if resp != nil && resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("cached negative response rcode: want SERVFAIL(%d), got %d",
			dns.RcodeServerFailure, resp.Rcode)
	}
}

func TestHandleDNSQuery_Forward_AllIPsBlacklisted_BlockResponse(t *testing.T) {
	// When every IP in the upstream response is on the blacklist, the
	// response should be treated as a block (NXDOMAIN).
	q := aQuery("example.com")
	// Use RFC 5737 documentation range as the "blacklisted" IP.
	fwd := fixedFwd(upstreamAResp(q, "203.0.113.5"), UpstreamState{Strategy: "fastest"})
	s := newQueryTestServer(t, defaultConfig(), fwd)
	addWhitelistRule(t, s, "A", "example.com")

	_, cidr, _ := net.ParseCIDR("203.0.113.0/24")
	s.blacklist.TryAdd(cidr)

	resp := s.handleDNSQuery(context.Background(), aQuery("example.com"), testClient)

	if resp == nil {
		t.Fatal("want non-nil block response, got nil")
	}
	// BlockMode = "nxdomain" in defaultConfig.
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode: want NXDOMAIN(%d) when all IPs are blacklisted, got %d",
			dns.RcodeNameError, resp.Rcode)
	}
}

func TestHandleDNSQuery_Forward_ZeroIP_BlockedByUpstream(t *testing.T) {
	// Upstreams sometimes return 0.0.0.0 as a block signal. filterResponse
	// treats these as BlockedZeroIP; handleDNSQuery must convert that to a
	// proper block response.
	q := aQuery("example.com")
	fwd := fixedFwd(upstreamAResp(q, "0.0.0.0"), UpstreamState{Strategy: "fastest"})
	s := newQueryTestServer(t, defaultConfig(), fwd)
	addWhitelistRule(t, s, "A", "example.com")

	resp := s.handleDNSQuery(context.Background(), aQuery("example.com"), testClient)

	if resp == nil {
		t.Fatal("want non-nil block response, got nil")
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode: want NXDOMAIN(%d) for zero-IP upstream block, got %d",
			dns.RcodeNameError, resp.Rcode)
	}
}

func TestHandleDNSQuery_Forward_PartialFilter_ReturnsOnlyCleanIPs(t *testing.T) {
	// If an upstream response mixes blacklisted and clean IPs, only the clean
	// IPs should survive in the returned message.
	q := aQuery("example.com")
	fwd := fixedFwd(upstreamAResp(q, "203.0.113.5", "8.8.8.8"), UpstreamState{Strategy: "fastest"})
	s := newQueryTestServer(t, defaultConfig(), fwd)
	addWhitelistRule(t, s, "A", "example.com")

	_, cidr, _ := net.ParseCIDR("203.0.113.0/24")
	s.blacklist.TryAdd(cidr)

	resp := s.handleDNSQuery(context.Background(), aQuery("example.com"), testClient)

	if resp == nil {
		t.Fatal("want non-nil response after partial filter, got nil")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode: want Success, got %d", resp.Rcode)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("Answer: want 1 record (only clean IP), got %d", len(resp.Answer))
	}
	aRec, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatal("expected *dns.A record")
	}
	if !aRec.A.Equal(net.ParseIP("8.8.8.8")) {
		t.Errorf("remaining IP: want 8.8.8.8, got %v", aRec.A)
	}
}

// ── ID Preservation Test ──────────────────────────────────────────────────────

func TestHandleDNSQuery_OriginalQueryIDPreservedInResponse(t *testing.T) {
	// handleDNSQuery randomises the ID before forwarding (to prevent cache
	// poisoning) and must restore the original ID in every response path.
	//
	// This sub-test table covers the three response-generating paths that run
	// after ID randomisation: forward-success, forward-nil (SERVFAIL), and
	// block (NXDOMAIN).

	const originalID uint16 = 0xBEEF

	buildQuery := func(domain string, qtype uint16) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), qtype)
		m.Id = originalID
		return m
	}

	t.Run("forward success", func(t *testing.T) {
		q := buildQuery("example.com", dns.TypeA)
		fwd := fixedFwd(upstreamAResp(q, "8.8.8.8"), UpstreamState{})
		s := newQueryTestServer(t, defaultConfig(), fwd)
		addWhitelistRule(t, s, "A", "example.com")

		resp := s.handleDNSQuery(context.Background(), buildQuery("example.com", dns.TypeA), testClient)
		if resp.Id != originalID {
			t.Errorf("ID: want 0x%04X, got 0x%04X", originalID, resp.Id)
		}
	})

	t.Run("forward nil → SERVFAIL", func(t *testing.T) {
		s := newQueryTestServer(t, defaultConfig(), nilFwd())
		addWhitelistRule(t, s, "A", "example.com")

		resp := s.handleDNSQuery(context.Background(), buildQuery("example.com", dns.TypeA), testClient)
		if resp.Id != originalID {
			t.Errorf("ID: want 0x%04X, got 0x%04X", originalID, resp.Id)
		}
	})

	t.Run("blocked (no rule)", func(t *testing.T) {
		s := newQueryTestServer(t, defaultConfig(), nilFwd())
		// No rules → blocked before forwarding; ID must still be preserved.

		resp := s.handleDNSQuery(context.Background(), buildQuery("blocked.com", dns.TypeA), testClient)
		if resp.Id != originalID {
			t.Errorf("ID: want 0x%04X, got 0x%04X", originalID, resp.Id)
		}
	})
}

// ── Stats and Recent Blocks ───────────────────────────────────────────────────

func TestHandleDNSQuery_StatCounterIncrementsOnEveryBlock(t *testing.T) {
	s := newQueryTestServer(t, defaultConfig(), nilFwd())
	// No rules; every query is blocked.

	for i := range 3 {
		domain := "blocked.com"
		s.handleDNSQuery(context.Background(), aQuery(domain), testClient)
		if s.stats.Value() != int64(i+1) {
			t.Errorf("after %d blocks: stats want %d, got %d", i+1, i+1, s.stats.Value())
		}
	}
}

func TestHandleDNSQuery_RecentBlocks_RecordsUniqueDomainsLRU(t *testing.T) {
	cfg := defaultConfig()
	cfg.MaxRecentBlocks = 2 // small cap to test LRU eviction

	s := newQueryTestServer(t, cfg, nilFwd())

	s.handleDNSQuery(context.Background(), aQuery("first.com"), testClient)
	s.handleDNSQuery(context.Background(), aQuery("second.com"), testClient)
	// third.com should evict first.com.
	s.handleDNSQuery(context.Background(), aQuery("third.com"), testClient)

	snap := s.recentBlocks.Snapshot(func(_, _ string) bool { return false })
	if len(snap) != 2 {
		t.Fatalf("recentBlocks length: want 2 (capped), got %d", len(snap))
	}
	// Most recent should be at index 0.
	if snap[0].Domain != "third.com" {
		t.Errorf("snap[0].Domain: want third.com, got %s", snap[0].Domain)
	}
	if snap[1].Domain != "second.com" {
		t.Errorf("snap[1].Domain: want second.com, got %s", snap[1].Domain)
	}
}

func TestHandleDNSQuery_RecentBlocks_NotRecordedOnAllowedQuery(t *testing.T) {
	// Forwarded (allowed) queries must NOT appear in the recent-blocks list.
	q := aQuery("allowed.com")
	fwd := fixedFwd(upstreamAResp(q, "8.8.8.8"), UpstreamState{})
	s := newQueryTestServer(t, defaultConfig(), fwd)
	addWhitelistRule(t, s, "A", "allowed.com")

	s.handleDNSQuery(context.Background(), aQuery("allowed.com"), testClient)

	snap := s.recentBlocks.Snapshot(func(_, _ string) bool { return false })
	if len(snap) != 0 {
		t.Errorf("recentBlocks: want empty for allowed query, got %d entries", len(snap))
	}
}
