package dnsbollocks

import (
	"strings"
	"testing"
)

type benchRule struct {
	pattern string
	qtype   uint16
	enabled bool
}

func makeBenchRules(n int) []benchRule {
	rules := make([]benchRule, n)

	patterns := []string{
		"api*.examPle.com",
		"foo*bar.examPle.com",
		"a?i.examPle.com",
		"sdmntpr*.oaIusercontent.com",
		"{*}.cdn.examPle.com",
		"**.tracking.exAMPle",
		"foo.?ar.cOm",
		"a{*}c.exaMPle.com",
		"a{**}c.examPle.com",
		"*.examplE.com",
	}

	for i := 0; i < n; i++ {
		rules[i] = benchRule{
			//pattern: patterns[i%len(patterns)],
			pattern: strings.ToLower(patterns[i%len(patterns)]), //XXX: ensure all rules are lowercase on load from file
			qtype:   1,                                          // A
			enabled: true,
		}
	}

	return rules
}

func benchLookup(name string, qtype uint16, rules []benchRule) bool {
	for _, r := range rules {
		if !r.enabled {
			continue
		}
		if r.qtype != qtype {
			continue
		}
		if matchPattern(r.pattern, name) {
			return true
		}
	}
	return false
}

func BenchmarkLookup100(b *testing.B) {
	rules := makeBenchRules(100)
	runLookupBenchmark(b, rules)
}

func BenchmarkLookup1000(b *testing.B) {
	rules := makeBenchRules(1000)
	runLookupBenchmark(b, rules)
}

func BenchmarkLookup10000(b *testing.B) {
	rules := makeBenchRules(10000)
	runLookupBenchmark(b, rules)
}

// The global benchResult is important. Without it, the compiler can detect that the lookup result is unused and may partially eliminate the call, especially with inlining.
var benchResult bool

func runLookupBenchmark(b *testing.B, rules []benchRule) {
	b.ReportAllocs()
	var names = []string{
		"zzzzzzzzzzzzzz.invalid", // worst case
		"aPi.example.com",        // early match
		//mixed case:
		"foO123bar.example.com",
		"ai.Example.com",
		"sdmnTpritalynorth.oaiusercontent.com",
		"abc.cDn.example.com",
		"foo.bAr.com",
	}

	// normalize once
	for i := range names {
		names[i] = strings.ToLower(names[i])
	}

	qtype := uint16(1) // A

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		//name := names[i%len(names)]
		name := strings.ToLower(names[i%len(names)]) //XXX: it's assumed that the name to lookup is already lowercased before checking it.
		benchResult = benchLookup(name, qtype, rules)
	}
}
