package main

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

func main() {
	proxyserver := "127.0.0.1:53" // Change if your proxy is on a different port
	targetDomain := "blog.cloudflare.com." // Note the trailing dot

	c := new(dns.Client)
	c.Timeout = 2 * time.Second

	m := new(dns.Msg)
	m.SetQuestion(targetDomain, dns.TypeA)
	
	// Add an OPT record to the request to tell the proxy we support EDNS
	m.SetEdns0(1232, false)

	fmt.Printf("Querying %s for %s...\n", proxyserver, targetDomain)
	
	res, _, err := c.Exchange(m, proxyserver)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Response Rcode: %s\n", dns.RcodeToString[res.Rcode])

	// Look for the EDE in the Extra section
	foundEDE := false
	for _, extra := range res.Extra {
		if opt, ok := extra.(*dns.OPT); ok {
			for _, option := range opt.Option {
				if ede, ok := option.(*dns.EDNS0_EDE); ok {
					foundEDE = true
					fmt.Println("\n--- Extended DNS Error Found ---")
					fmt.Printf("Code: %d (%s)\n", ede.InfoCode, edeCodeToString(ede.InfoCode))
					fmt.Printf("Text: %s\n", ede.ExtraText)
					fmt.Println("--------------------------------")
				}
			}
		}
	}

	if !foundEDE {
		fmt.Println("\nNo EDE record found in the response.")
	}
}

func edeCodeToString(code uint16) string {
	switch code {
	case 15: return "Blocked"
	case 16: return "Censored"
	case 17: return "Filtered"
	case 18: return "Prohibited"
	default: return "Other/Unknown"
	}
}