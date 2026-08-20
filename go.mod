module github.com/workturnedplay/dnsbollocks

go 1.26.2

require (
	github.com/google/uuid v1.6.0
	github.com/miekg/dns v1.1.73
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/workturnedplay/wincoe v0.10.9
	golang.org/x/crypto v0.55.0
	golang.org/x/sys v0.47.0
	golang.org/x/term v0.45.0
	golang.org/x/time v0.15.0
)

require golang.org/x/text v0.41.0 // indirect

require golang.org/x/net v0.58.0 // indirect (for miekg/dns)
