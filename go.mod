module dns-proxy

go 1.25.0

require (
	github.com/google/uuid v1.6.0
	github.com/miekg/dns v1.1.68
	github.com/patrickmn/go-cache v2.1.0+incompatible
	golang.org/x/sys v0.39.0
	golang.org/x/time v0.14.0
)

require (
	golang.org/x/mod v0.29.0 // indirect
	golang.org/x/sync v0.18.0 // indirect
	golang.org/x/tools v0.38.0 // indirect
)

require golang.org/x/net v0.47.0 // indirect; indirect (for miekg/dns)
