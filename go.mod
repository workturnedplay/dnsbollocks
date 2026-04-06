module github.com/workturnedplay/dnsbollocks

go 1.27

require (
	github.com/google/uuid v1.6.0
	github.com/miekg/dns v1.1.73-0.20260402044838-d1539a788a12
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/workturnedplay/wincoe v0.0.11
	golang.org/x/sys v0.42.0
	golang.org/x/term v0.41.0
	golang.org/x/time v0.15.0
)

require (
	golang.org/x/mod v0.34.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/tools v0.43.0 // indirect
)

require golang.org/x/net v0.52.0 // indirect; indirect (for miekg/dns)
