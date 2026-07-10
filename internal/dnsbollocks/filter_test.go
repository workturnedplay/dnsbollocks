//go:build windows
// +build windows

package dnsbollocks

import (
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// 1. Mock the Blacklist
// We implement the IPChecker interface so we don't need a real BlacklistStore.
type mockBlacklist struct {
	blockedIPs []net.IP
}

func (m *mockBlacklist) Contains(ip net.IP) bool {
	for _, blocked := range m.blockedIPs {
		if blocked.Equal(ip) {
			return true
		}
	}
	return false
}

// Create a dummy logger that discards output so tests stay quiet
var dummyLog = slog.New(slog.NewTextHandler(io.Discard, nil))

// 2. Test processRR
func TestProcessRR(t *testing.T) {
	blacklist := &mockBlacklist{
		blockedIPs: []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("2001:db8::1")},
	}

	tests := []struct {
		name                 string
		rr                   dns.RR
		removeHTTPSIPv4Hints bool
		wantKeep             bool
		wantReason           string
	}{
		{
			name: "Valid A Record",
			rr: &dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("9.9.9.9"),
			},
			wantKeep:   true,
			wantReason: "",
		},
		{
			name: "Zero IP A Record (Blocked)",
			rr: &dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("0.0.0.0"),
			},
			wantKeep:   false,
			wantReason: BlockedZeroIP,
		},
		{
			name: "Blacklisted IPv4 Record",
			rr: &dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.168.1.1"),
			},
			wantKeep:   false,
			wantReason: BlockedBlacklistedIP,
		},
		{
			name: "Blacklisted IPv6 Record",
			rr: &dns.AAAA{
				Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: net.ParseIP("2001:db8::1"),
			},
			wantKeep:   false,
			wantReason: BlockedBlacklistedIP,
		},
		{
			name: "RRSIG Record (Stripped)",
			rr: &dns.RRSIG{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
			},
			wantKeep:   false,
			wantReason: StrippedRRSIG,
		},
		{
			name: "HTTPS Record (Hints Removed)",
			rr: &dns.HTTPS{
				SVCB: dns.SVCB{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
					Value: []dns.SVCBKeyValue{
						&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("1.2.3.4")}},
						&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
					},
				},
			},
			removeHTTPSIPv4Hints: true,
			wantKeep:             true,
			wantReason:           "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keep, modifiedRR, reason := processRR(dummyLog, tc.rr, tc.removeHTTPSIPv4Hints, blacklist)

			if keep != tc.wantKeep {
				t.Errorf("expected keep=%v, got %v", tc.wantKeep, keep)
			}
			if reason != tc.wantReason {
				t.Errorf("expected reason=%q, got %q", tc.wantReason, reason)
			}

			// Specific check for HTTPS hint removal
			if tc.name == "HTTPS Record (Hints Removed)" && keep {
				httpsRR, ok3 := modifiedRR.(*dns.HTTPS)
				if !ok3 {
					t.Errorf("this cast or wtw: modifiedRR.(*dns.HTTPS) , failed!")
				}
				for _, param := range httpsRR.Value {
					if param.Key() == dns.SVCB_IPV4HINT || param.Key() == dns.SVCB_IPV6HINT {
						t.Errorf("expected HTTPS hints to be removed, but found %d", param.Key())
					}
				}
			}
		})
	}
}

// 3. Test filterResponse
func TestFilterResponse(t *testing.T) {
	blacklist := &mockBlacklist{
		blockedIPs: []net.IP{net.ParseIP("10.0.0.1")},
	}

	t.Run("Filters all records completely (Zero IP)", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		msg.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("0.0.0.0"),
			},
		}

		filtered, reason := filterResponse(dummyLog, msg, true, blacklist)

		if filtered != nil {
			t.Errorf("expected filtered message to be nil, got %v", filtered)
		}
		if reason != BlockedByUpstream {
			t.Errorf("expected reason to be %q, got %q", BlockedByUpstream, reason)
		}
	})

	t.Run("Keeps clean records and drops bad ones", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		msg.Answer = []dns.RR{
			// Bad record
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("10.0.0.1"),
			},
			// Good record
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("8.8.8.8"),
			},
		}

		filtered, reason := filterResponse(dummyLog, msg, true, blacklist)

		if filtered == nil {
			t.Fatalf("expected filtered message to NOT be nil")
		}
		if reason != "" {
			t.Errorf("expected no filter reason, got %q", reason)
		}
		if len(filtered.Answer) != 1 {
			t.Fatalf("expected 1 answer left, got %d", len(filtered.Answer))
		}

		// Verify the remaining record is the good one
		ans, ok4 := filtered.Answer[0].(*dns.A)
		if !ok4 {
			t.Errorf("this cast or wtw: filtered.Answer[0].(*dns.A) , failed!")
		}
		if !ans.A.Equal(net.ParseIP("8.8.8.8")) {
			t.Errorf("expected remaining IP to be 8.8.8.8, got %v", ans.A)
		}
	})
}
