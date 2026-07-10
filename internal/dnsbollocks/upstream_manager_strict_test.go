//go:build windows && portmasterFirewalled
// +build windows,portmasterFirewalled

package dnsbollocks

import (
	"context"
	"net/http"
	//"net/http/httptest"
	"testing"
	//"time"

	"github.com/miekg/dns"
)

// TestFWNeededForwardToDoH_Strict_EmptyResponseIsTreatedAsFailure
func TestFWNeededForwardToDoH_Strict_EmptyResponseIsTreatedAsFailure(t *testing.T) {
	// Even a 200 OK with zero answer records should be considered a failure in strict mode
	// because we cannot get consensus on the "real" answer.
	emptyMsg := new(dns.Msg)
	emptyMsg.SetRcode(emptyMsg, dns.RcodeSuccess)
	emptyBytes, _ := emptyMsg.Pack()

	srv1 := mockDoHServer(0, http.StatusOK, emptyBytes)
	defer srv1.Close()
	srv2 := mockDoHServer(0, http.StatusOK, emptyBytes)
	defer srv2.Close()

	cfg := Config{
		UpstreamURLs:          []string{srv1.URL, srv2.URL},
		UpstreamSNIHostnames:  []string{"s1.test", "s2.test"},
		UpstreamSelectionMode: "strict",
	}
	um := setupTestContext(&cfg)
	um.InitDoHClients()

	active := um.activeSet.Load()
	active.upstreams[0].Client.Transport = srv1.Client().Transport
	active.upstreams[1].Client.Transport = srv2.Client().Transport

	req := createDummyDNSMsg("example.com.", "")
	resp, state := um.ForwardToDoH(context.Background(), req)

	if resp != nil {
		t.Error("strict mode must drop empty responses (no consensus)")
	}
	if len(state.FailedUpstreams) == 0 {
		t.Error("expected both upstreams to be marked failed")
	}
}

// TestFWNeededForwardToDoH_Strict_PartialConsensusWithEDNS0
func TestFWNeededForwardToDoH_Strict_PartialConsensusWithEDNS0(t *testing.T) {
	// One server returns a proper answer with EDNS0, the other returns a truncated response.
	// Strict mode should still refuse because the messages are not identical.
	msgA := createDummyDNSMsg("example.com.", "1.2.3.4")
	msgA.SetEdns0(4096, false)
	bytesA, _ := msgA.Pack()

	msgB := createDummyDNSMsg("example.com.", "1.2.3.4")
	// no EDNS0 → different wire format
	bytesB, _ := msgB.Pack()

	srvA := mockDoHServer(0, http.StatusOK, bytesA)
	defer srvA.Close()
	srvB := mockDoHServer(0, http.StatusOK, bytesB)
	defer srvB.Close()

	cfg := Config{
		UpstreamURLs:          []string{srvA.URL, srvB.URL},
		UpstreamSNIHostnames:  []string{"a.test", "b.test"},
		UpstreamSelectionMode: "strict",
	}
	um := setupTestContext(&cfg)
	um.InitDoHClients()

	active := um.activeSet.Load()
	active.upstreams[0].Client.Transport = srvA.Client().Transport
	active.upstreams[1].Client.Transport = srvB.Client().Transport

	req := createDummyDNSMsg("example.com.", "")
	resp, state := um.ForwardToDoH(context.Background(), req)

	if resp != nil {
		t.Error("strict mode must reject responses that differ in EDNS0 presence")
	}
	if len(state.FailedUpstreams) == 0 {
		t.Error("expected at least one upstream to be marked failed")
	}
}
