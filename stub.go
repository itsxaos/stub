package stub

import (
	"github.com/caddyserver/caddy/v2"
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
