//go:build windows && portmasterFirewalled
// +build windows,portmasterFirewalled

//XXX: all test that will be run also need to be prefixed with TestFWNeeded

package dnsbollocks

import (
	//"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// mockDoHServer creates an HTTPS server that returns a specific status code and optional delay.
func mockDoHServer(delay time.Duration, statusCode int, responseBody []byte) *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if delay > 0 {
			time.Sleep(delay)
		}
		// Set the content type just like a real DoH server
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(statusCode)
		if responseBody != nil {
			_, _ = w.Write(responseBody)
		}
	})
	return httptest.NewTLSServer(handler)
}

// createDummyDNSMsg creates a basic valid DNS message for testing
func createDummyDNSMsg(domain string, answerIP string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	if answerIP != "" {
		rr, _ := dns.NewRR(fmt.Sprintf("%s A %s", dns.Fqdn(domain), answerIP))
		msg.Answer = append(msg.Answer, rr)
	}
	return msg
}

func TestFWNeededForwardToDoH_Failover(t *testing.T) {
	// 1. Setup Mock Servers
	srvPrimary := mockDoHServer(0, http.StatusInternalServerError, nil)
	defer srvPrimary.Close()

	// Secondary server returns a valid packed DNS message
	successMsg := createDummyDNSMsg("success.test.", "")
	successBytes, _ := successMsg.Pack()
	srvSecondary := mockDoHServer(0, http.StatusOK, successBytes)
	defer srvSecondary.Close()

	// 2. Configure UpstreamManager
	cfg := Config{
		UpstreamURLs:             []string{srvPrimary.URL, srvSecondary.URL},
		SNIHostnames:             []string{"primary.test", "secondary.test"},
		UpstreamClientTimeoutSec: 5,
		UpstreamRetriesPerQuery:  0,          // Set to 0 to speed up the test
		UpstreamSelectionMode:    "failover", // Corrected field name
	}
	um := setupTestContext(&cfg)
	//_ = um.updateInnerState()
	um.InitDoHClients()

	// 3. Bypass TLS Verification for Local Test Certs
	active := um.activeSet.Load()
	active.upstreams[0].Client.Transport = srvPrimary.Client().Transport
	active.upstreams[1].Client.Transport = srvSecondary.Client().Transport

	// 4. Execute Routing Logic
	reqMsg := createDummyDNSMsg("query.test.", "")
	resp, state := um.ForwardToDoH(context.Background(), reqMsg)

	// 5. Assert Expectations
	if resp == nil {
		t.Fatalf("expected failover to succeed, got nil response")
	}

	// Ensure it actually fell back to the secondary server
	if state.UpstreamUsed != srvSecondary.URL {
		t.Errorf("expected failover to use secondary URL %q, got %q", srvSecondary.URL, state.UpstreamUsed)
	}

	// Ensure the primary server was logged as failed
	if len(state.FailedUpstreams) == 0 || state.FailedUpstreams[0] != srvPrimary.URL {
		t.Errorf("expected primary URL %q to be in FailedUpstreams, got %v", srvPrimary.URL, state.FailedUpstreams)
	}
}

func TestFWNeededForwardToDoH_FastestWins(t *testing.T) {
	// 1. Setup Mock Servers
	slowMsg := createDummyDNSMsg("slow.test.", "")
	slowBytes, _ := slowMsg.Pack()
	srvSlow := mockDoHServer(200*time.Millisecond, http.StatusOK, slowBytes)
	defer srvSlow.Close()

	fastMsg := createDummyDNSMsg("fast.test.", "")
	fastBytes, _ := fastMsg.Pack()
	srvFast := mockDoHServer(10*time.Millisecond, http.StatusOK, fastBytes)
	defer srvFast.Close()

	// 2. Configure UpstreamManager
	cfg := Config{
		UpstreamURLs:             []string{srvSlow.URL, srvFast.URL},
		SNIHostnames:             []string{"slow.test", "fast.test"},
		UpstreamClientTimeoutSec: 5,
		UpstreamSelectionMode:    "fastest", // Corrected field name
	}
	um := setupTestContext(&cfg)
	//_ = um.updateInnerState()
	um.InitDoHClients()

	// 3. Bypass TLS
	active := um.activeSet.Load()
	active.upstreams[0].Client.Transport = srvSlow.Client().Transport
	active.upstreams[1].Client.Transport = srvFast.Client().Transport

	// 4. Execute Routing Logic
	reqMsg := createDummyDNSMsg("query.test.", "")

	start := time.Now()
	resp, state := um.ForwardToDoH(context.Background(), reqMsg)
	elapsed := time.Since(start)

	// 5. Assert Expectations
	if resp == nil {
		t.Fatalf("expected request to succeed, got nil response")
	}

	// It should return the response from the fast server
	if resp.Question[0].Name != fastMsg.Question[0].Name {
		t.Errorf("expected fast response for %q, got %q", fastMsg.Question[0].Name, resp.Question[0].Name)
	}
	if state.UpstreamUsed != srvFast.URL {
		t.Errorf("expected used upstream to be %q, got %q", srvFast.URL, state.UpstreamUsed)
	}

	// It should complete well before the slow server finishes
	if elapsed > 150*time.Millisecond {
		t.Errorf("expected fastest routing to finish under 150ms, took %v", elapsed)
	}
}

func TestFWNeededForwardToDoH_Strict_MatchSuccess(t *testing.T) {
	// 1. Setup Mock Servers with identical responses
	msgA := createDummyDNSMsg("consensus.test.", "1.2.3.4")
	bytesA, _ := msgA.Pack()

	srv1 := mockDoHServer(0, http.StatusOK, bytesA)
	defer srv1.Close()
	srv2 := mockDoHServer(0, http.StatusOK, bytesA)
	defer srv2.Close()

	// 2. Configure UpstreamManager
	cfg := Config{
		UpstreamURLs:             []string{srv1.URL, srv2.URL},
		SNIHostnames:             []string{"strict1.test", "strict2.test"},
		UpstreamClientTimeoutSec: 5,
		UpstreamSelectionMode:    "strict",
	}
	um := setupTestContext(&cfg)
	//_ = um.updateInnerState()
	um.InitDoHClients()

	active := um.activeSet.Load()
	active.upstreams[0].Client.Transport = srv1.Client().Transport
	active.upstreams[1].Client.Transport = srv2.Client().Transport

	// 3. Execute
	reqMsg := createDummyDNSMsg("consensus.test.", "")
	resp, state := um.ForwardToDoH(context.Background(), reqMsg)

	// 4. Assert
	if resp == nil {
		t.Fatalf("expected strict mode to succeed on matching answers, got nil")
	}
	if len(state.FailedUpstreams) > 0 {
		t.Errorf("expected zero failed upstreams, got %v", state.FailedUpstreams)
	}
}

func TestFWNeededForwardToDoH_Strict_RefuseOnSingleOutage(t *testing.T) {
	// One healthy server, one dead server
	validMsg := createDummyDNSMsg("partial.test.", "1.2.3.4")
	validBytes, _ := validMsg.Pack()

	srvHealthy := mockDoHServer(0, http.StatusOK, validBytes)
	defer srvHealthy.Close()
	srvBroken := mockDoHServer(0, http.StatusInternalServerError, nil)
	defer srvBroken.Close()

	cfg := Config{
		UpstreamURLs:             []string{srvHealthy.URL, srvBroken.URL},
		SNIHostnames:             []string{"healthy.test", "broken.test"},
		UpstreamClientTimeoutSec: 5,
		UpstreamSelectionMode:    "strict",
	}
	um := setupTestContext(&cfg)
	//_ = um.updateInnerState()
	um.InitDoHClients()

	active := um.activeSet.Load()
	active.upstreams[0].Client.Transport = srvHealthy.Client().Transport
	active.upstreams[1].Client.Transport = srvBroken.Client().Transport

	reqMsg := createDummyDNSMsg("partial.test.", "")
	resp, state := um.ForwardToDoH(context.Background(), reqMsg)

	// Your logic states: "Refuse to resolve if any upstream completely fails"
	if resp != nil {
		t.Errorf("expected strict mode to refuse resolution on partial outage, but got a response")
	}
	if len(state.FailedUpstreams) == 0 {
		t.Errorf("expected broken server to be marked inside FailedUpstreams")
	}
}

func TestFWNeededForwardToDoH_Strict_DropOnMismatch(t *testing.T) {
	// Two healthy servers returning completely different answers
	msgAlpha := createDummyDNSMsg("mismatch.test.", "1.1.1.1")
	bytesAlpha, _ := msgAlpha.Pack()

	msgBeta := createDummyDNSMsg("mismatch.test.", "8.8.8.8")
	bytesBeta, _ := msgBeta.Pack()

	srvAlpha := mockDoHServer(0, http.StatusOK, bytesAlpha)
	defer srvAlpha.Close()
	srvBeta := mockDoHServer(0, http.StatusOK, bytesBeta)
	defer srvBeta.Close()

	cfg := Config{
		UpstreamURLs:             []string{srvAlpha.URL, srvBeta.URL},
		SNIHostnames:             []string{"alpha.test", "beta.test"},
		UpstreamClientTimeoutSec: 5,
		UpstreamSelectionMode:    "strict",
	}
	um := setupTestContext(&cfg)
	//_ = um.updateInnerState()
	um.InitDoHClients()

	active := um.activeSet.Load()
	active.upstreams[0].Client.Transport = srvAlpha.Client().Transport
	active.upstreams[1].Client.Transport = srvBeta.Client().Transport

	reqMsg := createDummyDNSMsg("mismatch.test.", "")
	resp, state := um.ForwardToDoH(context.Background(), reqMsg)

	// Your logic states: "Drop the query because of answer discrepancy"
	if resp != nil {
		t.Errorf("expected strict mode to drop query on conflicting records, but returned a response")
	}
	if len(state.FailedUpstreams) == 0 {
		t.Errorf("expected the mismatching upstream to be tracked as failed")
	}
}
