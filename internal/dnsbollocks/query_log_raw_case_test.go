//go:build windows
// +build windows

package dnsbollocks

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func newLogCapturingQueryServer(t *testing.T) (*Server, *bytes.Buffer) {
	t.Helper()
	s := newQueryTestServer(t, defaultConfig(), nilFwd())
	var buf bytes.Buffer
	s.rt = newTestRuntime(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return s, &buf
}

// logRecordsWithMsg returns every captured JSON log record whose msg equals msg.
func logRecordsWithMsg(t *testing.T, buf *bytes.Buffer, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(buf.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("captured log line is not valid JSON: %q: %v", line, err)
		}
		if rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

func recordWithAction(t *testing.T, recs []map[string]any, action string) map[string]any {
	t.Helper()
	for _, rec := range recs {
		if rec["action"] == action {
			return rec
		}
	}
	t.Fatalf("no logged_query record with action %q among %d record(s): %v", action, len(recs), recs)
	return nil
}

func TestQueryLog_KeepsClientCasingForDomainAndReply(t *testing.T) {
	s, buf := newLogCapturingQueryServer(t)

	// No rules -> blocked; the block reply is built from the raw query.
	s.handleDNSQuery(context.Background(), aQuery("ExAmPlE.CoM"), testClient)
	s.shutdownWG.Wait()

	rec := recordWithAction(t, logRecordsWithMsg(t, buf, "logged_query"), blockedSTR)
	if rec["domain"] != "ExAmPlE.CoM" {
		t.Errorf("domain: want %q, got %v", "ExAmPlE.CoM", rec["domain"])
	}
	if _, has := rec["domain_punycode"]; has {
		t.Errorf("a plain ASCII name must not get a domain_punycode field, got %v", rec["domain_punycode"])
	}
	resp, ok := rec["dns_response"].(string)
	if !ok {
		t.Fatalf("expected rec[\"dns_response\"] to be string, got %T (%v)", rec["dns_response"], rec["dns_response"])
	}
	if !strings.Contains(resp, "ExAmPlE.CoM.") {
		t.Errorf("dns_response should carry the client's casing, got: %v", rec["dns_response"])
	}
}

func TestQueryLog_CacheHitLogsTheCurrentQueriesCasing(t *testing.T) {
	s, buf := newLogCapturingQueryServer(t)

	s.handleDNSQuery(context.Background(), aQuery("ExAmPlE.CoM"), testClient)
	s.handleDNSQuery(context.Background(), aQuery("EXAMPLE.com"), testClient) // served from cache
	s.shutdownWG.Wait()

	recs := logRecordsWithMsg(t, buf, "logged_query")
	if got := recordWithAction(t, recs, blockedSTR)["domain"]; got != "ExAmPlE.CoM" {
		t.Errorf("first query domain: want ExAmPlE.CoM, got %v", got)
	}
	if got := recordWithAction(t, recs, cacheHit)["domain"]; got != "EXAMPLE.com" {
		t.Errorf("cache-hit query domain: want EXAMPLE.com, got %v", got)
	}
}

func TestQueryLog_IDNShowsUnicodeAndRawPunycode(t *testing.T) {
	s, buf := newLogCapturingQueryServer(t)

	s.handleDNSQuery(context.Background(), aQuery("XN--CAF-DMA.com"), testClient)
	s.shutdownWG.Wait()

	rec := recordWithAction(t, logRecordsWithMsg(t, buf, "logged_query"), blockedSTR)
	if rec["domain"] != "café.com" {
		t.Errorf("domain: want café.com, got %v", rec["domain"])
	}
	if rec["domain_punycode"] != "XN--CAF-DMA.com" {
		t.Errorf("domain_punycode: want the raw wire name XN--CAF-DMA.com, got %v", rec["domain_punycode"])
	}
}

func TestFilterResponse_LogsQueriedNameVerbatim(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))

	msg := new(dns.Msg)
	msg.SetQuestion("ExAmPlE.CoM.", dns.TypeA)
	msg.Answer = []dns.RR{makeA("ExAmPlE.CoM.", "0.0.0.0", 300)}

	if filtered, reason := filterResponse(log, msg, true, &mockBlacklist{}); filtered != nil || reason != BlockedByUpstream {
		t.Fatalf("want (nil, %q), got (%v, %q)", BlockedByUpstream, filtered, reason)
	}

	recs := logRecordsWithMsg(t, &buf, "response_filtered_all")
	if len(recs) != 1 {
		t.Fatalf("want exactly 1 response_filtered_all record, got %d", len(recs))
	}
	if recs[0]["domain"] != "ExAmPlE.CoM" {
		t.Errorf("domain: want ExAmPlE.CoM, got %v", recs[0]["domain"])
	}
}

func TestQueryLogDomainFields(t *testing.T) {
	tests := []struct {
		name         string
		queried      string
		lowercased   string
		wantLogged   string
		wantPunycode string
		wantIDN      bool
	}{
		{"ascii keeps casing", "ExAmPlE.CoM", "example.com", "ExAmPlE.CoM", "", false},
		{"idn -> unicode + raw punycode", "XN--CAF-DMA.com", "xn--caf-dma.com", "café.com", "XN--CAF-DMA.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logged, puny, isIDN := queryLogDomainFields(tt.queried, tt.lowercased)
			if logged != tt.wantLogged || puny != tt.wantPunycode || isIDN != tt.wantIDN {
				t.Errorf("got (%q, %q, %v), want (%q, %q, %v)", logged, puny, isIDN, tt.wantLogged, tt.wantPunycode, tt.wantIDN)
			}
		})
	}
}

func TestQueriedNameFromContext(t *testing.T) {
	if got := queriedNameFromContext(context.Background(), "fallback.example"); got != "fallback.example" {
		t.Errorf("no value: want fallback, got %q", got)
	}
	ctx := context.WithValue(context.Background(), queriedNameKey{}, "MiXeD.Example")
	if got := queriedNameFromContext(ctx, "fallback.example"); got != "MiXeD.Example" {
		t.Errorf("with value: want MiXeD.Example, got %q", got)
	}
	empty := context.WithValue(context.Background(), queriedNameKey{}, "")
	if got := queriedNameFromContext(empty, "fallback.example"); got != "fallback.example" {
		t.Errorf("empty value: want fallback, got %q", got)
	}
}
