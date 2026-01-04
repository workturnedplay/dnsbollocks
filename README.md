# dnsbollocks

Originally located here: https://github.com/workturnedplay/dnsbollocks  
(unless you got it from a fork)

`dnsbollocks` is AI-assisted Go code that I run on Windows 11 as a local DNS proxy/filter.  
Its core behavior is simple: **block every DNS request by default unless explicitly whitelisted**.

Firefox connects to it via DoH (DNS over HTTPS), treating it like a normal DoH resolver. The browser asks for IPs for hostnames it wants to reach, and this program either allows or blocks those queries.

If a hostname is not whitelisted, the proxy responds with either:
- `NXDOMAIN`, or
- `0.0.0.0`  
  (this works on Windows; on Linux/Android it is usually bad because the kernel routes traffic to localhost)

The whitelist can be edited via:
- a small web UI exposed by the program, or
- directly editing the config file and restarting/reloading

## Protocols and behavior

- Listens for **plain DNS** on UDP port 53
- Listens for **DoH** on TCP port 443
- By default (if not configured in `config.json`), it binds to `127.0.0.1`
- On Windows 11, this does **not** require admin privileges or elevation

For DNS queries of type `HTTPS`, the program strips IP hints from responses.  
At least with Firefox 146.0.1 (at the time of writing), these hints are not used if the corresponding `A` record returns `NXDOMAIN` or `0.0.0.0`, but they are removed anyway.

## State

It works.  
The code is a mess.

## Usage (Firefox / DoH)

In Firefox, open `about:config` and set:

- `network.trr.mode` → `3` (DoH only, no fallback)
- `network.trr.custom_uri` → `https://127.0.0.1/dns-query`
- `network.trr.default_provider_uri` → `https://127.0.0.1/dns-query`
- `network.trr.uri` → `https://127.0.0.1/dns-query`

Setting all three URIs is probably overkill, but works.

Then open https://127.0.0.1 in Firefox and accept the self-signed certificate exception.  
Without this, all DoH queries will fail.

### Why DoH instead of plain DNS in Firefox?

On my system, the Windows `dnscache` (DNS Client) service is completely disabled.  
Without it, Firefox cannot perform DNS lookups via the OS and all queries fail. Other tools (like `aria2c`) can still resolve names if a DNS IP is explicitly configured.

Using DoH over TCP 443 avoids this problem entirely.

## Using it system-wide

If you want non-Firefox applications (or the OS itself) to use it:
- Set `127.0.0.1` as the DNS server in your network adapter settings

This uses plain DNS over UDP port 53.  
DoH support for other apps or OS-level DoH was not explored.

## Firewall notes (Windows)

I use TinyWall as a firewall.

- Allow outbound TCP port 443 for the `dnsbollocks` executable  
  (this allows forwarding queries to the upstream DoH server defined in `config.json`)
- Allow Firefox outbound TCP and UDP port 443

A limitation of TinyWall is that rules are port-based only.  
If a port is allowed, **any IP** is implicitly allowed for that port.

When TinyWall is active, Windows Firewall rules are ignored; only TinyWall rules apply.

## Requirements

You need `go.exe` of Go language to compile this code into a standalone exe.  
No internet required if you have Go already installed.  

## License

Apache License 2.0

Do whatever you want with it.  
No warranty. No liability.

