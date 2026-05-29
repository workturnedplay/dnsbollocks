# dnsbollocks

Originally located here: [https://github.com/workturnedplay/dnsbollocks](https://github.com/workturnedplay/dnsbollocks)

(unless you got it from a fork, try `git remote -v` to check)

`dnsbollocks` is a local DNS proxy/filter written in Go that I used to use and run on Windows 11(before I decided to switch to Linux). The codebase was initially generated with AI assistance(via chat only, no agents) and is no longer under active iteration anymore(because I'm switching to Linux mainly because the requirement for having signed drivers in Win11 if I wanted to make it a firewall or use a modified version of portmaster firewall), testing, and hardening using AI assistance.

Its core behavior is simple: **block every DNS request by default unless explicitly whitelisted**.

Firefox connects to it via DoH (DNS over HTTPS), treating it like a normal DoH resolver. The browser asks for IPs for hostnames it wants to reach, and this program either allows or blocks those queries.

## Key Features

* **Default Deny:** Everything is blocked unless a whitelist pattern matches the domain and DNS query type.
* **Web UI (Port 8080):** Manage whitelist rules, set local host overrides, view recent blocks for quick one-click unblocking, and view system/query logs in real-time.
* **Pattern Matching:** Supports wildcards (`*`, ``, `?`, `!`) for flexible domain whitelisting.
* **Local Hosts Overrides:** Map specific domains to local IPs (similar to a standard `hosts` file) directly from the Web UI.
* **Hot Reloading:** Press `Ctrl+R` in the console window to reload whitelist, blacklist, and host files without dropping active connections.
* **Client Tracking:** Tracks the connecting Windows process PID and Executable name (e.g., `firefox.exe`) in the query logs for easier debugging.
* **HTTPS Auto-Allow:** Configurable option to automatically allow `HTTPS` queries if the corresponding `A` record is whitelisted (`AllowHTTPSIfAAllowed`).
* **Privilege Guard:** By default, it refuses to run with Administrator privileges to limit security risks (can be overridden with `allow_run_as_admin`).

## Protocols and Behavior

* Listens for **plain DNS** on UDP and TCP port 53.
* Listens for **DoH** on TCP port 443 (automatically generates a self-signed certificate if one isn't provided).
* By default (if not configured in `config.json`), it binds to `127.0.0.1`.
* On Windows 11, this does **not** require admin privileges or elevation.

If a hostname is not whitelisted, the proxy responds with either:

* `NXDOMAIN` (Recommended. Note: AAAA records can optionally return a `NOERROR` empty reply so the requester tries an `A` record next, avoiding issues with tools like `ssh.exe` via git for Windows. This is on by default via `block_aaaa_as_empty_noerror`).
* `0.0.0.0` (Works on Windows; on Linux/Android it is usually bad because the kernel routes traffic to localhost).
* An IP of your choosing via the `block_ip` config.
* `drop` aka ignore the query (leads to timeouts).

For DNS queries of type `HTTPS`, the program strips IP hints from responses.

At least with Firefox 146.0.1 (at the time of writing), these hints are not used if the corresponding `A` record returns `NXDOMAIN` or `0.0.0.0`, but they are removed anyway. It also filters out blacklisted response IPs and strips `RRSIG` records.

## Configuration Files

The proxy manages state via several JSON files (which are generated with defaults if missing):

* `config.json`: Core settings (listeners, upstreams, block modes, caching, log paths).
* `query_whitelist.json`: Your allowed domain patterns.
* `response_blacklist.json`: CIDR blocks to strip from upstream responses.
* `hosts2ip.json`: Local DNS overrides.

## State

It works.

The code is a mess.

## Usage (Firefox / DoH)

In Firefox, open `about:config` and set:

* `network.trr.mode` → `3` (DoH only, no fallback)
* `network.trr.custom_uri` → `https://127.0.0.1/dns-query`
* `network.trr.default_provider_uri` → `https://127.0.0.1/dns-query`
* `network.trr.uri` → `https://127.0.0.1/dns-query`

Setting all three URIs is probably overkill, but works.

Then open [https://127.0.0.1](https://127.0.0.1) in Firefox and accept the self-signed certificate exception.

Without this, all DoH queries will fail.

### Why DoH instead of plain DNS in Firefox?

On my system, the Windows `dnscache` (DNS Client) service is completely disabled.

Without it, Firefox cannot perform DNS lookups via the OS and all queries fail. Other tools (like `nslookup.exe`) can still resolve names if a DNS IP is explicitly configured or specified.

Using DoH over TCP 443 avoids this problem entirely.

## Using it system-wide

If you want non-Firefox applications (or the OS itself) to use it:

* Set `127.0.0.1` as the DNS server in your network adapter settings

This uses plain DNS over UDP/TCP port 53.

DoH support for other apps or OS-level DoH was not explored.

## Console Controls

When running in an interactive terminal, the following shortcuts are supported:

* `Ctrl+C` or `Ctrl+X`: Graceful shutdown (flushes cache, closes listeners).
* `Ctrl+R`: Hot-reload rules, blacklists, and hosts files.

## Firewall notes (Windows)

I use TinyWall as a firewall.

* Allow outbound TCP port 443 for the `dnsbollocks` executable (allows forwarding queries to the upstream DoH servers like Quad9 or Cloudflare defined in `config.json`).
* Allow Firefox outbound TCP and UDP port 443.

A limitation of TinyWall is that rules are port-based only.

If a port is allowed, **any IP** is implicitly allowed for that port.

When TinyWall is active, Windows Firewall rules are ignored; only TinyWall rules apply.

## Requirements

You need `go.exe` of Go language to compile this code into a standalone exe.

No internet required if you have Go already installed.

To run `buildwrace.bat` or `go build -race` or `go run -race` you need a `gcc.exe` in `PATH` so use this (or just get it from [https://winlibs.com](https://winlibs.com)):

[https://github.com/brechtsanders/winlibs_mingw/releases/download/15.2.0posix-14.0.0-ucrt-r7/winlibs-x86_64-posix-seh-gcc-15.2.0-mingw-w64ucrt-14.0.0-r7.7z](https://github.com/brechtsanders/winlibs_mingw/releases/download/15.2.0posix-14.0.0-ucrt-r7/winlibs-x86_64-posix-seh-gcc-15.2.0-mingw-w64ucrt-14.0.0-r7.7z)

which has this sha256 from here: [https://github.com/brechtsanders/winlibs_mingw/releases/download/15.2.0posix-14.0.0-ucrt-r7/winlibs-x86_64-posix-seh-gcc-15.2.0-mingw-w64ucrt-14.0.0-r7.7z.sha256](https://github.com/brechtsanders/winlibs_mingw/releases/download/15.2.0posix-14.0.0-ucrt-r7/winlibs-x86_64-posix-seh-gcc-15.2.0-mingw-w64ucrt-14.0.0-r7.7z.sha256)

and has this sha512 `6339f5d849bce4da2d4c7d9c89d8fc921599e68544e190efc4d800e84f64b3d46e850d7b707225e9edaa32ef7a76115bdd31788c6e2b2d92b532b4bb7c18c5d0 *winlibs-x86_64-posix-seh-gcc-15.2.0-mingw-w64ucrt-14.0.0-r7.7z`

put it in `c:\winlibs\` and make sure its in `PATH` like `c:\winlibs\mingw64\bin`

(`mingwvars.bat` doesn't need to be ran at all)

## License

Apache License 2.0

Do whatever you want with it.

No warranty. No liability.

## Third-party code

This repository includes vendored third-party Go modules under the `vendor/` directory so it can be built without internet access.

Those components are licensed under their respective licenses.
Individual license texts and notices are preserved alongside the vendored code.

