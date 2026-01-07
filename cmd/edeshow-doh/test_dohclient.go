package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"

	"github.com/miekg/dns"
)

func main() {
	dohURL := "https://127.0.0.1:443/dns-query" // Adjust path if needed
	targetDomain := "blog.cloudflare.com."

	// 1. Create the DNS Query
	m := new(dns.Msg)
	m.SetQuestion(targetDomain, dns.TypeA)
	m.SetEdns0(1232, false)
	blob, _ := m.Pack()

	// 2. Setup HTTP client to skip TLS check for local testing
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	fmt.Printf("Querying DoH at %s...\n", dohURL)

	// 3. Send POST request (standard for DoH)
	resp, err := httpClient.Post(dohURL, "application/dns-message", bytes.NewReader(blob))
	if err != nil {
		fmt.Printf("HTTP Error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Server returned status: %d\n", resp.StatusCode)
		return
	}

	// 4. Parse Response
	responseBody, _ := io.ReadAll(resp.Body)
	res := new(dns.Msg)
	if err := res.Unpack(responseBody); err != nil {
		fmt.Printf("DNS Unpack Error: %v\n", err)
		return
	}

	fmt.Printf("Response Rcode: %s\n", dns.RcodeToString[res.Rcode])

	// 5. Check for EDE
	for _, extra := range res.Extra {
		if opt, ok := extra.(*dns.OPT); ok {
			for _, option := range opt.Option {
				if ede, ok := option.(*dns.EDNS0_EDE); ok {
					fmt.Println("\n--- Extended DNS Error (via DoH) ---")
					fmt.Printf("Code: %d\nText: %s\n", ede.InfoCode, ede.ExtraText)
					return
				}
			}
		}
	}
	fmt.Println("\nNo EDE found in DoH response.")
}
