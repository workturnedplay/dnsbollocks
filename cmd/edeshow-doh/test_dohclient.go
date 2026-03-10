package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/miekg/dns"
	"io"
	"net/http"
	"os"
)

func main() {
	dohURL := "https://127.0.0.1:443/dns-query" // Adjust path if needed
	targetDomain := "blog.cloudflare.com."
	certPath := "..\\..\\cert.pem" // Your self-signed certificate

	// 1. Create the DNS Query
	m := new(dns.Msg)
	m.SetQuestion(targetDomain, dns.TypeA)
	m.SetEdns0(1232, false)
	// Handling m.Pack() error
	blob, err := m.Pack()
	if err != nil {
		fmt.Printf("Error packing DNS message: %v\n", err)
		return
	}

	// 2. Setup TLS using the self-signed cert as the Root CA
	pemCerts, err := os.ReadFile(certPath)

	if err != nil {
		fmt.Printf("Failed to read %s: %v\n", certPath, err)
		return
	}

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(pemCerts); !ok {
		fmt.Println("Failed to parse cert.pem")
		return
	}

	// 2. Setup HTTP client to skip TLS check for local testing
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				InsecureSkipVerify: false, // Verified against your cert.pem
			},
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
	// 4. Parse Response & Handle ReadAll error
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return
	}

	res := new(dns.Msg)
	if err := res.Unpack(responseBody); err != nil {
		fmt.Printf("DNS Unpack Error: %v\n", err)
		return
	}

	fmt.Printf("Response Rcode: %s\n", dns.RcodeToString[res.Rcode])

	// 5. Check for EDE
	foundEDE := false

	for _, extra := range res.Extra {
		if opt, ok := extra.(*dns.OPT); ok {
			for _, option := range opt.Option {
				if ede, ok := option.(*dns.EDNS0_EDE); ok {
					fmt.Println("\n--- Extended DNS Error (via DoH) ---")
					fmt.Printf("Code: %d\nText: %s\n", ede.InfoCode, ede.ExtraText)
					foundEDE = true

				}
			}
		}
	}
	if !foundEDE {

		fmt.Println("\nNo EDE found in DoH response.")
	}
}
