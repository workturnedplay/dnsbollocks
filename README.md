# dnsbollocks

Originally located here: https://github.com/workturnedplay/dnsbollocks  
(unless you got it from a fork)  
  
This is AI generated <del>slop</del> Go language code which I run on win11 as a DNS proxy to act as a filter which blocks every DNS request by default unless whitelisted. The browser(Firefox) connects to it via DoH (in my case) as if connecting to a normal DoH DNS server and asks for the IPs for the hostnames it wants to connect to. The program will block these queries either by returning `NXDOMAIN` or an IP like `0.0.0.0`(ok in Windows, bad in Linux/Android as kernel points the packets to localhost) if the hostnames aren't in the whitelist(which you can edit by connecting to its webUI via the browser, or modify the config file and reload the program).  

It listens for plain DNS queries on UDP 53 and for DoH (dns over https) queries on TCP 443. By default, if not configured (in `config.json`) it uses localhost IP 127.0.0.1 to listen on and doesn't require Admin or elevation, on win11 to do this.  
It also strips away the IP hints in the replies for DNS type `HTTPS` queries, even though at least Firefox 146.0.1 (at this time) doesn't use those to connect to if the A type record returned `NXDOMAIN` or `0.0.0.0`.  

# State
It's working but it's a coding mess.

# Usage
Point Firefox to it like `about:config`:  
`network.trr.mode`	`3` (try only DoH, no fallbacks)  
`network.trr.custom_uri`	`https://127.0.0.1/dns-query`  
`network.trr.default_provider_uri`	`https://127.0.0.1/dns-query`  
`network.trr.uri`	`https://127.0.0.1/dns-query`  
(probably overkill to set all 3 of these.)  
Then load https://127.0.0.1 in Firefox and accept the self-signed certificate as an exception, otherwise all queries will fail due to this.  
The reason I use it as DoH(443 TCP) not plain DNS(53 UDP) in Firefox is because I have `dnscache` aka `DNS Client` service in win11 disabled entirely and Firefox can't do any DNS lookups without it(they fail), for some reason, unlike other apps like aria2c which can(if an IP is set in LAN settings for it, like below).  
If you want others (non-Firefox, like the OS itself, or aria2c) to use it, set `127.0.0.1` in LAN device's settings as the DNS (this will do plain DNS via port 53 UDP, didn't look into other settings like DoH, if they exist or even work without the `dnscache` service running)  
  
As a firewall I use TinyWall and set it to allow port TCP outgoing 443 for this exe, that allows it to forward request to the upstream DoH that you set in `config.json`, and set Firefox to allow TCP and UDP port 443 outgoing, which unfortunately means any IP outgoing will be allowed, a limitation of TinyWall (filters by port but ANY ip is allowed if port is allowed/matches). While using TinyWall, any allowing in Windows Firewall will not actually allow anything, TinyWall rules are the only rules in effect. The only downsite is that you can't allow only a specific IP, you implicitly allow all IPs, on the specified port (like 443).  


# License
TODO:
Apache 2, GPL2, MIT

