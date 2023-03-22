package stub

import (
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/libdns/libdns"
	"github.com/miekg/dns"
)

// An in-process request to create or delete a DNS record
type request struct {
	append    bool
	zone      string
	records   []dns.RR
	responder chan error
}

func init() {
	caddy.RegisterModule(App{})
	caddy.RegisterModule(Provider{})

	httpcaddyfile.RegisterGlobalOption("dns", parseApp)
}

func record_to_rr(zone string, record libdns.Record) (dns.RR, error) {
	maybe_priority := ""
	if record.Priority != 0 {
		maybe_priority += strconv.FormatInt(int64(record.Priority), 10)
		maybe_priority += " "
	}
	//TODO: consider fixing this with dns.StringToType & dns.TypeToRR
	// Problem is putting the value in, since it will be a different field
	// for every type.
	// Also, will probably require parsing the value anyway (e.g. to net.IP)
	//TODO: does the value need to be escaped?!
	return dns.NewRR(
		dns.Fqdn(record.Name+"."+zone) +
			" " +
			strconv.FormatInt(int64(record.TTL.Seconds()), 10) +
			" IN " +
			record.Type +
			" " +
			maybe_priority +
			record.Value)
}
