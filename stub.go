package stub

import (
	"context"

	"github.com/miekg/dns"
	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// TTL of the challenge TXT record to serve
const challenge_ttl = 600 // (anything is probably fine here)

type StubDNS struct {
	// the address & port on which to serve DNS for the challenge
	Address string `json:"address,omitempty"`

	server *dns.Server // set in Present()
}


func init() {
	caddy.RegisterModule(StubDNS{})
}

// CaddyModule returns the Caddy module information.
func (StubDNS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.stub_dns",
		New: func() caddy.Module {return &StubDNS{}},
	}
}

// Provision sets up the module. Implements caddy.Provisioner.
func (p *StubDNS) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	p.Address = repl.ReplaceAll(p.Address, "")
	return nil
}

// UnmarshalCaddyfile sets up the DNS provider from Caddyfile tokens. Syntax:
//
// stub_dns [address] {
//     address <address>
// }
//
func (s *StubDNS) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			s.Address = d.Val()
		}
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "address":
				if s.Address != "" {
					return d.Err("Address already set")
				}
				if d.NextArg() {
					s.Address = d.Val()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	if s.Address == "" {
		return d.Err("missing Address")
	}
	return nil
}


func (s *StubDNS) Present(ctx context.Context, challenge acme.Challenge) error {
	// get challenge parameters
	fqdn := dns.Fqdn(challenge.DNS01TXTRecordName())
	content := challenge.DNS01KeyAuthorization()
	// spawn the server
	handler := s.make_handler(fqdn, content)
	dns.HandleFunc(".", handler)
	server := &dns.Server{Addr: s.Address, Net: "udp", TsigSecret: nil,}
	go server.ListenAndServe()

	// store the server for shutdown later
	s.server = server
	return nil
}

func (p *StubDNS) CleanUp(ctx context.Context, _ acme.Challenge) error {
	if p.server == nil {
		return nil
	} else {
		return p.server.ShutdownContext(ctx)
	}
}

func (s *StubDNS) make_handler(fqdn string, txt string) dns.HandlerFunc {
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) != 1 {
			m.Rcode = dns.RcodeRefused
			m.Answer = []dns.RR{}
			w.WriteMsg(m)
			return
		}

		q := r.Question[0]
		domain := q.Name

		valid := r.Response == false &&
			(q.Qclass == dns.ClassINET || q.Qclass == dns.ClassANY) &&
			q.Qtype == dns.TypeTXT
		if !valid {
			m.Rcode = dns.RcodeNotImplemented
			m.Answer = []dns.RR{}
		} else if domain != fqdn {
			m.Rcode = dns.RcodeNameError
			m.Answer = []dns.RR{}
		} else {
			m.Authoritative = true
			rr := new(dns.TXT)
			rr.Hdr = dns.RR_Header{
				Name: domain,
				Rrtype: dns.TypeTXT,
				Class: dns.ClassINET,
				Ttl: uint32(challenge_ttl),
			}
			rr.Txt = []string{txt}
			m.Answer = []dns.RR{rr}
		}
		w.WriteMsg(m)
	}

	return handler
}

// Interface guards
var (
	_ acmez.Solver = (*StubDNS)(nil)
	_ caddy.Provisioner = (*StubDNS)(nil)
	_ caddyfile.Unmarshaler = (*StubDNS)(nil)
)
