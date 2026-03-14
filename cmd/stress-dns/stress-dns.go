// File: stress-dns.go
// Small stress / concurrency test tool for dnsbollocks
// Usage examples:
//   go run stress-dns.go
//   go run stress-dns.go -server=127.0.0.1:53 -count=300 -conc=50
//   go run stress-dns.go -server=127.0.0.1:53 -list=domains.txt -conc=80

package main

import (
  "bufio"
  "context"
  "flag"
  "fmt"
  "log"
  "math/rand"
  "net"
  "os"
  "strings"
  "sync"
  "sync/atomic"
  "time"
)

var (
  flagServer   = flag.String("server", "127.0.0.2:53", "DNS server to query (IP:port)")
  flagCount    = flag.Int("count", 400, "how many queries to send in total")
  flagConc     = flag.Int("conc", 40, "maximum concurrent queries")
  flagListFile = flag.String("list", "", "optional file with one domain per line (overrides -count)")
  flagTimeout  = flag.Duration("timeout", 4*time.Second, "per-query timeout")
  flagTypes    = flag.String("types", "A,AAAA", "comma-separated record types to query")
)

func main() {
  flag.Parse()

  resolver := &net.Resolver{
    PreferGo: true,
    Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
      d := net.Dialer{Timeout: *flagTimeout}
      return d.DialContext(ctx, "udp", *flagServer)
    },
  }

  var domains []string

  if *flagListFile != "" {
    f, err := os.Open(*flagListFile)
    if err != nil {
      log.Fatalf("Cannot open domain list: %v", err)
    }
    defer f.Close()

    sc := bufio.NewScanner(f)
    for sc.Scan() {
      line := strings.TrimSpace(sc.Text())
      if line == "" || strings.HasPrefix(line, "#") {
        continue
      }
      domains = append(domains, line)
    }
    if err := sc.Err(); err != nil {
      log.Fatalf("Error reading domain list: %v", err)
    }
    fmt.Printf("Loaded %d domains from file\n", len(domains))
  } else {
    // fallback: well-known domains
    domains = []string{
      "google.com", "cloudflare.com", "facebook.com", "youtube.com",
      "apple.com", "microsoft.com", "amazon.com", "github.com",
      "reddit.com", "wikipedia.org", "twitter.com", "linkedin.com",
      "stackoverflow.com", "netflix.com", "openai.com", "x.com",
    }
    fmt.Printf("Using built-in %d domains (repeat them many times)\n", len(domains))
  }

  // Prepare the work queue
  totalQueries := *flagCount
  if len(domains) == 0 {
    log.Fatal("No domains to query")
  }

  // If we have a list but count is smaller → limit it
  if totalQueries > len(domains)*10 {
    totalQueries = len(domains) * 10 // reasonable cap
  }

  // We'll cycle through the list many times if needed
  queryList := make([]string, 0, totalQueries)
  for i := 0; i < totalQueries; i++ {
    domain := domains[i%len(domains)]
    queryList = append(queryList, domain)
  }

  // Shuffle to avoid perfect patterns
  rand.Shuffle(len(queryList), func(i, j int) {
    queryList[i], queryList[j] = queryList[j], queryList[i]
  })

  types := strings.Split(*flagTypes, ",")
  for i := range types {
    types[i] = strings.TrimSpace(strings.ToUpper(types[i]))
  }

  fmt.Printf("\nStarting stress test:\n")
  fmt.Printf("  Server   : %s\n", *flagServer)
  fmt.Printf("  Concurrency : %d\n", *flagConc)
  fmt.Printf("  Total queries : %d\n", len(queryList))
  fmt.Printf("  Record types  : %v\n", types)
  fmt.Printf("  Timeout       : %v\n\n", *flagTimeout)

  start := time.Now()

  var wg sync.WaitGroup
  sem := make(chan struct{}, *flagConc)

  var success, failed, timeout, nxdomain atomic.Int32

  ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
  defer cancel()

  for _, domain := range queryList {
    wg.Add(1)
    sem <- struct{}{} // acquire

    go func(domain string) {
      defer wg.Done()
      defer func() { <-sem }()

      //for _, qtype := range types {
        //for _, _ := range types {
        _, err := resolver.LookupHost(ctx, domain)
        // Note: LookupHost always asks for A + AAAA

        // If you want to query specific types only, use LookupIP / LookupTXT / etc.
        // For more precise control consider using miekg/dns directly.

        var outcome string
        if err == nil {
          success.Add(1)
          outcome = "OK"
        } else {
          failed.Add(1)
          if strings.Contains(err.Error(), "no such host") {
            nxdomain.Add(1)
            outcome = "NXDOMAIN"
          } else if ctx.Err() != nil {
            timeout.Add(1)
            outcome = "TIMEOUT"
          } else {
            outcome = "ERROR"
          }
        }

        // Print ~every 50th result or errors/timeouts
        if success.Load()+failed.Load()%50 == 0 || outcome != "OK" {
          fmt.Printf("%6d | %s | %-28s | %s\n",
            success.Load()+failed.Load(),
            time.Since(start).Round(time.Millisecond),
            domain,
            outcome,
          )
        }
      //}
    }(domain)
  }

  wg.Wait()

  duration := time.Since(start)

  fmt.Println("\n──────────────────────────────────────────────")
  fmt.Printf("Finished in %v\n", duration.Round(time.Millisecond))
  fmt.Printf("  Successful : %d\n", success.Load())
  fmt.Printf("  Failed     : %d\n", failed.Load())
  fmt.Printf("    → NXDOMAIN : %d\n", nxdomain.Load())
  fmt.Printf("    → Timeout  : %d\n", timeout.Load())
  fmt.Printf("  QPS        : %.1f\n", float64(success.Load()+failed.Load())/duration.Seconds())
}