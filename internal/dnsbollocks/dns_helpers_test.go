//go:build windows
// +build windows

package dnsbollocks

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ── builder helpers ───────────────────────────────────────────────────────────

func makeA(name, ip string, ttl uint32) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip).To4(),
	}
}

func makeAAAA(name, ip string, ttl uint32) *dns.AAAA {
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
		AAAA: net.ParseIP(ip),
	}
}

func makeCNAME(name, target string, ttl uint32) *dns.CNAME {
	return &dns.CNAME{
		Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
		Target: target,
	}
}

func makeSOA(name string, headerTTL, minTTL uint32) *dns.SOA {
	return &dns.SOA{
		Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: headerTTL},
		Minttl: minTTL,
	}
}

func makeNS(name, ns string, ttl uint32) *dns.NS {
	return &dns.NS{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl},
		Ns:  ns,
	}
}

func msgWithAnswer(rrs ...dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.Answer = rrs
	return m
}

func msgWithNs(rrs ...dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.Ns = rrs
	return m
}

// ── computeTTL ────────────────────────────────────────────────────────────────

func TestComputeTTL_NoRecords_Returns300s(t *testing.T) {
	m := new(dns.Msg) // no Answer, no Ns
	got := computeTTLForCaching(m)
	if got != 300*time.Second {
		t.Errorf("expected 300s for empty message, got %v", got)
	}
}

func TestComputeTTL_SingleAnswerRecord(t *testing.T) {
	m := msgWithAnswer(makeA("example.com.", "1.2.3.4", 120))
	got := computeTTLForCaching(m)
	if got != 120*time.Second {
		t.Errorf("expected 120s, got %v", got)
	}
}

func TestComputeTTL_MinOfMultipleAnswerRecords(t *testing.T) {
	m := msgWithAnswer(
		makeA("example.com.", "1.2.3.4", 600),
		makeA("example.com.", "5.6.7.8", 200),
		makeA("example.com.", "9.0.1.2", 900),
	)
	got := computeTTLForCaching(m)
	if got != 200*time.Second {
		t.Errorf("expected 200s (min of 600,200,900), got %v", got)
	}
}

func TestComputeTTL_FloorOf10s(t *testing.T) {
	// TTL of 5 is below the 10s floor.
	m := msgWithAnswer(makeA("example.com.", "1.2.3.4", 5))
	got := computeTTLForCaching(m)
	if got != 10*time.Second {
		t.Errorf("expected floor of 10s, got %v", got)
	}
}

func TestComputeTTL_ZeroTTL_ClampsTo10s(t *testing.T) {
	m := msgWithAnswer(makeA("example.com.", "1.2.3.4", 0))
	got := computeTTLForCaching(m)
	if got != 10*time.Second {
		t.Errorf("expected 10s for TTL=0, got %v", got)
	}
}

func TestComputeTTL_NsSection_Participates(t *testing.T) {
	// Answer has TTL 500; Ns record has TTL 100 — Ns should win.
	m := new(dns.Msg)
	m.Answer = []dns.RR{makeA("example.com.", "1.2.3.4", 500)}
	m.Ns = []dns.RR{makeNS("example.com.", "ns1.example.com.", 100)}

	got := computeTTLForCaching(m)
	if got != 100*time.Second {
		t.Errorf("expected 100s (Ns section should participate), got %v", got)
	}
}

func TestComputeTTL_SOA_MinttlBeatsHeaderTTL(t *testing.T) {
	// SOA header TTL = 3600, but Minttl = 60 — Minttl should win.
	m := msgWithNs(makeSOA("example.com.", 3600, 60))
	got := computeTTLForCaching(m)
	if got != 60*time.Second {
		t.Errorf("expected 60s from SOA Minttl, got %v", got)
	}
}

func TestComputeTTL_SOA_HeaderTTLBeatsMinttlWhenSmaller(t *testing.T) {
	// Header TTL = 30, Minttl = 120 — header wins because it's checked first.
	m := msgWithNs(makeSOA("example.com.", 30, 120))
	got := computeTTLForCaching(m)
	if got != 30*time.Second {
		t.Errorf("expected 30s from SOA header TTL, got %v", got)
	}
}

func TestComputeTTL_SOA_MinttlBelowFloor(t *testing.T) {
	m := msgWithNs(makeSOA("example.com.", 3600, 3))
	got := computeTTLForCaching(m)
	if got != 10*time.Second {
		t.Errorf("expected 10s floor even from SOA Minttl=3, got %v", got)
	}
}

func TestComputeTTL_AnswerWinsOverNsWhenLower(t *testing.T) {
	m := new(dns.Msg)
	m.Answer = []dns.RR{makeA("example.com.", "1.2.3.4", 50)}
	m.Ns = []dns.RR{makeNS("example.com.", "ns1.example.com.", 200)}

	got := computeTTLForCaching(m)
	if got != 50*time.Second {
		t.Errorf("expected 50s (Answer lower than Ns), got %v", got)
	}
}

func TestComputeTTL_OnlyNsNoAnswer(t *testing.T) {
	m := msgWithNs(makeNS("example.com.", "ns1.example.com.", 450))
	got := computeTTLForCaching(m)
	if got != 450*time.Second {
		t.Errorf("expected 450s from Ns-only message, got %v", got)
	}
}

// ── compareDNSResponses ───────────────────────────────────────────────────────

func TestCompareDNSResponses_BothNil(t *testing.T) {
	if !compareDNSResponses(nil, nil) {
		t.Error("nil == nil should be true")
	}
}

func TestCompareDNSResponses_OneNil(t *testing.T) {
	m := msgWithAnswer(makeA("example.com.", "1.2.3.4", 300))
	if compareDNSResponses(nil, m) {
		t.Error("nil vs non-nil should be false")
	}
	if compareDNSResponses(m, nil) {
		t.Error("non-nil vs nil should be false")
	}
}

func TestCompareDNSResponses_IdenticalSingleRecord(t *testing.T) {
	a := msgWithAnswer(makeA("example.com.", "1.2.3.4", 300))
	b := msgWithAnswer(makeA("example.com.", "1.2.3.4", 300))
	if !compareDNSResponses(a, b) {
		t.Error("identical messages should compare equal")
	}
}

func TestCompareDNSResponses_DifferentRcode(t *testing.T) {
	a := new(dns.Msg)
	a.Rcode = dns.RcodeSuccess
	b := new(dns.Msg)
	b.Rcode = dns.RcodeNameError
	if compareDNSResponses(a, b) {
		t.Error("different Rcode should be not equal")
	}
}

func TestCompareDNSResponses_DifferentAnswerCount(t *testing.T) {
	a := msgWithAnswer(makeA("example.com.", "1.2.3.4", 300))
	b := msgWithAnswer(
		makeA("example.com.", "1.2.3.4", 300),
		makeA("example.com.", "5.6.7.8", 300),
	)
	if compareDNSResponses(a, b) {
		t.Error("different answer counts should be not equal")
	}
}

func TestCompareDNSResponses_DifferentIP(t *testing.T) {
	a := msgWithAnswer(makeA("example.com.", "1.2.3.4", 300))
	b := msgWithAnswer(makeA("example.com.", "9.9.9.9", 300))
	if compareDNSResponses(a, b) {
		t.Error("different IPs should be not equal")
	}
}

func TestCompareDNSResponses_OrderIndependent(t *testing.T) {
	// Same two records, swapped order — must still compare equal.
	a := msgWithAnswer(
		makeA("example.com.", "1.2.3.4", 300),
		makeA("example.com.", "5.6.7.8", 300),
	)
	b := msgWithAnswer(
		makeA("example.com.", "5.6.7.8", 300),
		makeA("example.com.", "1.2.3.4", 300),
	)
	if !compareDNSResponses(a, b) {
		t.Error("responses with same records in different order should be equal")
	}
}

func TestCompareDNSResponses_TTLDifference_IsIgnored(t *testing.T) {
	// TTLs are zeroed before comparison, so different TTLs must not matter.
	a := msgWithAnswer(makeA("example.com.", "1.2.3.4", 60))
	b := msgWithAnswer(makeA("example.com.", "1.2.3.4", 3600))
	if !compareDNSResponses(a, b) {
		t.Error("TTL difference alone should not make responses unequal")
	}
}

func TestCompareDNSResponses_DifferentRecordType(t *testing.T) {
	// Same name, same "address" bytes but one is A and the other CNAME.
	a := msgWithAnswer(makeA("example.com.", "1.2.3.4", 300))
	b := msgWithAnswer(makeCNAME("example.com.", "other.example.com.", 300))
	if compareDNSResponses(a, b) {
		t.Error("different RR types should be not equal")
	}
}

func TestCompareDNSResponses_BothEmpty(t *testing.T) {
	a := new(dns.Msg)
	b := new(dns.Msg)
	if !compareDNSResponses(a, b) {
		t.Error("two empty messages with same Rcode should be equal")
	}
}

func TestCompareDNSResponses_NsSection_NotConsidered(t *testing.T) {
	// The implementation only looks at Answer; Ns differences must be ignored.
	a := new(dns.Msg)
	a.Answer = []dns.RR{makeA("example.com.", "1.2.3.4", 300)}
	a.Ns = []dns.RR{makeNS("example.com.", "ns1.example.com.", 300)}

	b := new(dns.Msg)
	b.Answer = []dns.RR{makeA("example.com.", "1.2.3.4", 300)}
	// b has no Ns section

	if !compareDNSResponses(a, b) {
		t.Error("Ns section differences should not affect comparison")
	}
}

// ── extractIPs ────────────────────────────────────────────────────────────────

func TestExtractIPs_EmptyMessage(t *testing.T) {
	m := new(dns.Msg)
	ips := extractIPs(m)
	if len(ips) != 0 {
		t.Errorf("expected empty slice, got %v", ips)
	}
}

func TestExtractIPs_SingleA(t *testing.T) {
	m := msgWithAnswer(makeA("example.com.", "1.2.3.4", 300))
	ips := extractIPs(m)
	if len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Errorf("expected [1.2.3.4], got %v", ips)
	}
}

func TestExtractIPs_SingleAAAA(t *testing.T) {
	m := msgWithAnswer(makeAAAA("example.com.", "2001:db8::1", 300))
	ips := extractIPs(m)
	if len(ips) != 1 || ips[0] != "2001:db8::1" {
		t.Errorf("expected [2001:db8::1], got %v", ips)
	}
}

func TestExtractIPs_MixedAandAAAA(t *testing.T) {
	m := msgWithAnswer(
		makeA("example.com.", "1.2.3.4", 300),
		makeAAAA("example.com.", "2001:db8::1", 300),
	)
	ips := extractIPs(m)
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs, got %d: %v", len(ips), ips)
	}
}

func TestExtractIPs_NonIPRecordsAreSkipped(t *testing.T) {
	// CNAME in Answer should be silently skipped.
	m := msgWithAnswer(
		makeCNAME("example.com.", "cdn.example.com.", 300),
		makeA("cdn.example.com.", "1.2.3.4", 300),
	)
	ips := extractIPs(m)
	if len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Errorf("expected only A record IP, got %v", ips)
	}
}

func TestExtractIPs_NsSection_IsIgnored(t *testing.T) {
	// IPs only come from Answer, not Ns or Extra.
	m := new(dns.Msg)
	m.Ns = []dns.RR{makeNS("example.com.", "ns1.example.com.", 300)}
	ips := extractIPs(m)
	if len(ips) != 0 {
		t.Errorf("expected no IPs from Ns-only message, got %v", ips)
	}
}

func TestExtractIPs_MultipleARecords_OrderPreserved(t *testing.T) {
	m := msgWithAnswer(
		makeA("example.com.", "1.1.1.1", 300),
		makeA("example.com.", "2.2.2.2", 300),
		makeA("example.com.", "3.3.3.3", 300),
	)
	ips := extractIPs(m)
	if len(ips) != 3 {
		t.Fatalf("expected 3 IPs, got %d", len(ips))
	}
	expected := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	for i, want := range expected {
		if ips[i] != want {
			t.Errorf("ips[%d]: expected %q, got %q", i, want, ips[i])
		}
	}
}

// ── adjustResponseCaseToQuery ────────────────────────────────────────────────

func TestAdjustResponseCaseToQuery_RewritesQuestionAndAnswerOwnerName(t *testing.T) {
	m := msgWithAnswer(makeA("Example.COM.", "1.2.3.4", 300))
	m.Question = []dns.Question{{Name: "EXAMPLE.COM."}}

	req := &dns.Msg{
		Question: []dns.Question{{Name: "example.com."}},
	}

	adjustResponseCaseToQuery(m, req)

	// Verify Question section was updated
	if len(m.Question) > 0 && m.Question[0].Name != "example.com." {
		t.Errorf("expected Question section rewritten to query casing, got %q", m.Question[0].Name)
	}

	// Verify Answer section was updated
	if m.Answer[0].Header().Name != "example.com." {
		t.Errorf("expected owner name rewritten to query casing, got %q", m.Answer[0].Header().Name)
	}
}

func TestAdjustResponseCaseToQuery_LeavesCNAMETargetUntouched(t *testing.T) {
	m := new(dns.Msg)
	m.Answer = []dns.RR{
		makeCNAME("Example.COM.", "target.example.net.", 300),
		makeA("target.example.net.", "1.2.3.4", 300),
	}
	req := &dns.Msg{
		Question: []dns.Question{{Name: "example.com."}},
	}

	adjustResponseCaseToQuery(m, req)

	if m.Answer[0].Header().Name != "example.com." {
		t.Errorf("expected CNAME owner name rewritten to query casing, got %q", m.Answer[0].Header().Name)
	}
	if m.Answer[1].Header().Name != "target.example.net." {
		t.Errorf("expected CNAME target owner name left untouched, got %q", m.Answer[1].Header().Name)
	}
}

func TestAdjustResponseCaseToQuery_NoMatchLeavesRecordsUntouched(t *testing.T) {
	m := msgWithAnswer(makeA("other.example.", "1.2.3.4", 300))
	req := &dns.Msg{
		Question: []dns.Question{{Name: "example.com."}},
	}

	adjustResponseCaseToQuery(m, req)

	if m.Answer[0].Header().Name != "other.example." {
		t.Errorf("expected unrelated owner name untouched, got %q", m.Answer[0].Header().Name)
	}
}

func TestAdjustResponseCaseToQuery_NilAndEmptyInputsAreSafe(t *testing.T) {
	req := &dns.Msg{
		Question: []dns.Question{{Name: "example.com."}},
	}
	m := msgWithAnswer(makeA("Example.COM.", "1.2.3.4", 300))

	// Should not panic on nil msg
	adjustResponseCaseToQuery(nil, req)

	// Should not panic on nil reqMsg
	adjustResponseCaseToQuery(m, nil)

	// Should not panic on empty Question slice in reqMsg
	adjustResponseCaseToQuery(m, &dns.Msg{})
}
