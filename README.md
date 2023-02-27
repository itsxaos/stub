Stub DNS module for Caddy
=========================

> **Warning**
>
> This is alpha-quality, at best. It is not ready for production use. Use at your own risk!

The easiest way to get a wildcard certificate with Caddy: almost as *magical* as the automatic [HTTP challenge](https://caddyserver.com/docs/automatic-https#http-challenge)!

This module **does not require any DNS API**; it simply serves the DNS itself.
You just need to set up your DNS *once* to delegate all queries for the `_acme-challenge` zone to the IP where Caddy is running.
From then on, Caddy can fulfill all DNS challenges itself by opening a temporary DNS server.

Basically, by redirecting the DNS challenge queries to the host itself, the DNS challenge can be solved just like the [HTTP challenge](https://caddyserver.com/docs/automatic-https#http-challenge).

Pros:
- no DNS API required
- no credentials stored on the device
- no need to connect to another server to complete the challenge
- no propagation delays
- no separate DNS server process to manage

Cons:
- requires one additional DNS record in the requested zone
- UDP port 53 needs to be exposed & externally accessible (or port 53 on another host forwarded to it)
- ACME CA (i.e. Let's Encrypt) needs to connect to your server (like the [HTTP](https://caddyserver.com/docs/automatic-https#http-challenge) & [TLS-ALPN](https://caddyserver.com/docs/automatic-https#tls-alpn-challenge) challenge)
- can't have another public DNS server running on the same IP (see [below](#already-running-a-dns-server))
- can't have multiple Caddies running on different hosts authenticate for the same domain
- relies on deprecated & undocumented Caddy behavior (for now)
- doesn't support [`dns_challenge_override_domain`](https://caddyserver.com/docs/caddyfile/directives/tls#dns_challenge_override_domain) / [`override_domain`](https://caddyserver.com/docs/modules/tls.issuance.acme#challenges/dns/override_domain) (yet)


## Required DNS Record

The DNS needs to be set up to direct all DNS queries for the `_acme-challenge` subdomain of the zone you're trying to authenticate to the server that's running Caddy.
This should be pretty simple, but you still need to be careful and make sure **only** queries for the `_acme-challenge` subdomain get sent to your server.

So, let's say you have this record (could be an `AAAA` record too):
```
example.com.    A    192.0.2.123
```

Simply create a record like:
```
_acme-challenge.example.com.    NS    example.com.
```
And you're done!

Since DNS can be a little confusing, here's a quick recap of what this means.

The first record means "if you want to *connect to* `example.com`, go to `192.0.2.123`".
You need a record like this for clients (i.e. a web browser) to connect to your website, and you've probably set this up already.  
The second record, which you need to add for this module to work, means "if you want to *look up a domain* in `_acme-challenge.example.com.`, then you need to ask the nameserver running at `example.com`".
This will cause the client (e.g. Let's Encrypt or another ACME CA) to look up the first record as well, since it now knows it has to *connect to* `example.com` (though not to make an HTTP request like your browser would) to complete the query, and then it will get the `TXT` record for the challenge directly from your server.



## Configuration

The provider requires only one configuration value: the (local) IP address and port to serve the DNS on.
If the IP is not specified, like in `:53`, DNS will be served on *all* of the addresses assigned to the machine, and this may work for you.
However, many systems already have a DNS server running for local use: for instance, [systemd-resolved](https://wiki.archlinux.org/title/Systemd-resolved) listens on `127.0.0.53` by default.
In this case, it will not be possible to bind to the wildcard address, since it would overlap with systemd-resolved, and the provider will fail with `bind: address already in use`.
To avoid this, specify the (externally accessible) IP address you want to use.

For the port, you'll need to use `53` since that is the DNS port, and that's where Let's Encrypt (or whatever ACME CA you use) will query for the challenge.
Still, this isn't hard-coded to allow for more complicated setups and forwarding.

### Already running a DNS server?

If you're already hosting a DNS server on the machine that's running Caddy, you'll need to do some additional configuration.

The issue essentially boils down to not having enough IP addresses to host DNS on (you can create as many subdomains as you like, but they all have to point to an IP address in the end), and it can be resolved in two ways.

The first and arguably *cleaner* solution is to figure out a way to get your DNS server to forward / recurse queries for the `_acme-challenge` subdomain to some internal address & port and have `stub_dns` listen on that.
Note though that DNS has two kinds of "forwarding": one where the server will tell the client where to go to make their query ("iterative") and one where the server will do it on behalf of the client ("recursive").
Obviously, if you use an internal address that the client (e.g. LE) can't reach itself, you'll need to get your server to do the second kind.
If you manage to get this to work, please let people know how!

The second solution is to just use IPv6 since you probably have tons of IPv6 addresses you can use anyway, and Let's Encrypt has supported it for many years.
This is (arguably, again) less clean than the first because you'll need to set up another `NS` record and also an `AAAA` record to point it to, but it may be easier if you already have a reasonable setup for IPv6 (e.g. firewall rules).

## Caddy module name

```
dns.providers.stub_dns
```

## Config examples

To use this module for the ACME DNS challenge, [configure the ACME issuer in your Caddy JSON](https://caddyserver.com/docs/json/apps/tls/automation/policies/issuer/acme/) like so:

```json
{
	"module": "acme",
	"challenges": {
		"dns": {
			"provider": {
				"name": "stub_dns",
				"address": "IP_AND_PORT_TO_SERVE_DNS_ON"
			}
		}
	}
}
```

or with the Caddyfile:

```
# one site
tls {
	dns stub_dns ...
}
```

Unlike other providers, global configuration with `acme_dns` does *not* work!
