//go:build windows && portmasterFirewalled
// +build windows,portmasterFirewalled

//XXX: all test that will be run also need to be prefixed with TestFWNeeded

package dnsbollocks

import (
	"context"
	"io"
	"log/slog"
	"net"
	//"os"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestFWNeededHandleUDP_TruncationAndEDNS0(t *testing.T) {
	// 1. Initialize a Server instance with logs discarded to keep test output clean
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	//logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := defaultConfig()
	server := NewServer(logger, &cfg, &cfg)
	//cfg := server.getConfig()
	server.rateLimiter = newClientRateLimiter(server.ctx, rateLimitConfigFrom(cfg /*it's a copy, not pointer to live*/), logger) //rate.Inf, 1, time.Hour)
	//server.dnsCache = newGoCacheStore(time.Duration(cfg.CacheJanitorIntervalMinutes) * time.Minute)
	server.swapDNSCache(cfg.CacheJanitorIntervalMinutes, 100)

	// 2. Inject a local host rule with a large number of IP addresses.
	// This ensures that the generated DNS response will easily exceed 512 bytes.
	var largeIPList []net.IP
	for i := 1; i <= 40; i++ {
		largeIPList = append(largeIPList, net.IPv4(192, 168, 1, byte(i)))
	}

	server.ruleStore.AddRule("A", "large-response.example.com", true, logger)
	server.hostStore.ReplaceAll([]LocalHostRule{
		{
			Pattern: "large-response.example.com",
			IPs:     largeIPList,
		},
	})

	// 3. Set up an ephemeral local UDP socket for the server listener (ln)
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve server UDP addr: %v", err)
	}
	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("failed to listen on server UDP: %v", err)
	}
	defer serverConn.Close()

	// 4. Set up an ephemeral local UDP socket to simulate the client
	clientAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve client UDP addr: %v", err)
	}
	clientConn, err := net.ListenUDP("udp", clientAddr)
	if err != nil {
		t.Fatalf("failed to listen on client UDP: %v", err)
	}
	defer clientConn.Close()

	// Get the actual dynamic client port allocated by the operating system
	realClientAddr := clientConn.LocalAddr().(*net.UDPAddr)

	t.Run("Standard UDP Query (No EDNS0) - Should Truncate at 512 bytes", func(t *testing.T) {
		// Construct a standard DNS query message without any EDNS0 extensions
		query := new(dns.Msg)
		query.SetQuestion("large-response.example.com.", dns.TypeA)
		wire, err := query.Pack()
		if err != nil {
			t.Fatalf("failed to pack query: %v", err)
		}

		// Enforce a read deadline so the test doesn't hang if something fails
		_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))

		// Execute the target handler logic
		server.handleUDP(context.Background(), wire, realClientAddr, serverConn)

		// Read the outbound response packet sent back to the client
		buf := make([]byte, 4096)
		n, err := clientConn.Read(buf)
		if err != nil {
			t.Fatalf("failed to read response from client conn: %v", err)
		}

		resp := new(dns.Msg)
		if err := resp.Unpack(buf[:n]); err != nil {
			t.Fatalf("failed to unpack response: %v", err)
		}
		// t.Logf("DEBUG RESPONSE:\n%s", resp.String())
		// Assertions: The TC (Truncated) bit must be flipped, and size restricted to <= 512 bytes
		if !resp.MsgHdr.Truncated {
			t.Error("expected response to be truncated (TC bit true), but it wasn't")
		}
		if n > 512 {
			t.Errorf("expected response size to be restricted to <= 512 bytes, got %d bytes", n)
		}
	})

	t.Run("EDNS0 UDP Query - Should Honor Advertised Size and Not Truncate", func(t *testing.T) {
		// Construct a query that includes an EDNS0 OPT record advertising a 4096-byte buffer
		query := new(dns.Msg)
		query.SetQuestion("large-response.example.com.", dns.TypeA)
		query.SetEdns0(4096, false)
		wire, err := query.Pack()
		if err != nil {
			t.Fatalf("failed to pack query: %v", err)
		}

		_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))

		// Execute the target handler logic
		server.handleUDP(context.Background(), wire, realClientAddr, serverConn)

		buf := make([]byte, 4096)
		n, err := clientConn.Read(buf)
		if err != nil {
			t.Fatalf("failed to read response from client conn: %v", err)
		}

		resp := new(dns.Msg)
		if err := resp.Unpack(buf[:n]); err != nil {
			t.Fatalf("failed to unpack response: %v", err)
		}
		// t.Logf("DEBUG RESPONSE:\n%s", resp.String())
		// Assertions: The response shouldn't be truncated and must contain all 40 elements
		if resp.MsgHdr.Truncated {
			t.Error("expected response NOT to be truncated, but the TC bit was true")
		}
		if len(resp.Answer) != len(largeIPList) {
			t.Errorf("expected all %d answers to be packed, but only got %d", len(largeIPList), len(resp.Answer))
		}
	})
}
