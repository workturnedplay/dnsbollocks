//go:build windows
// +build windows

package main

import (
//	"context"
	"fmt"
//	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func main() {
	fmt.Println("=== DNSbollocks Crash Hammer ===")
	fmt.Println("Sending many concurrent UDP DNS queries to 127.0.0.1:53")
	fmt.Println("This should trigger the GetServiceNamesFromPID race if it's still present.")
	fmt.Println("Press Ctrl+C to stop.")

	//const numGoroutines = 48
  const numGoroutines = 2
	const queriesPerGoroutine = 800
	const targetAddr = "127.0.0.1:53"

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	start := time.Now()

	for g := 0; g < numGoroutines; g++ {
		go func(gid int) {
			defer wg.Done()

			c := new(dns.Client)
			c.Net = "udp"
			c.Timeout = 2 * time.Second

			for i := 0; i < queriesPerGoroutine; i++ {
				// Mix of domains that will hit blocked + forwarded + services lookup
				domain := fmt.Sprintf("hammer%d.example.com.", gid)
				if i%5 == 0 {
					domain = "firefox.settings.services.mozilla.com."
				} else if i%7 == 0 {
					domain = "addons.mozilla.org."
				} else if i%11 == 0 {
					domain = "www.youtube.com."
				}

				m := new(dns.Msg)
				m.SetQuestion(domain, dns.TypeA)
				m.RecursionDesired = true

				_, _, err := c.Exchange(m, targetAddr)
				if err != nil && i%50 == 0 {
					fmt.Printf("goroutine %d query %d error: %v\n", gid, i, err)
				}

				// Small sleep to increase interleaving / GC pressure
				if i%13 == 0 {
					//time.Sleep(10 * time.Microsecond)
          time.Sleep(300 * time.Millisecond)
				}
			}
		}(g)
	}

	wg.Wait()
	fmt.Printf("\nHammer finished in %v\n", time.Since(start))
	fmt.Println("If the old GetServiceNamesFromPID race is still present, the process likely crashed during this run.")
}