package stub

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

type StubDNS struct {
	// the address & port on which to serve DNS for the challenge
	Address string `json:"address,omitempty"`

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


// Interface guards
var (
	_ caddy.Provisioner = (*StubDNS)(nil)
	_ caddyfile.Unmarshaler = (*StubDNS)(nil)
)
