package stub

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"

	"github.com/miekg/dns"
	"go.uber.org/zap"
)

type App struct {
	// the address & port on which to serve DNS for the challenge
	Address string `json:"address,omitempty"`

	// Statically configured set of records to serve
	Records []string `json:"records,omitempty"`

	ctx    *caddy.Context // set in Provision()
	logger *zap.Logger    // set in Provision()

	requests chan request  // set in Provision()
	shutdown chan struct{} // set in Provision()
}

func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns",
		New: func() caddy.Module { return &App{} },
	}
}

// Provision sets up the module. Implements caddy.Provisioner.
func (a *App) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger()
	if a.requests == nil {
		a.requests = make(chan request)
	}
	if a.Records == nil {
		a.Records = []string{}
	}
	if a.shutdown == nil {
		a.shutdown = make(chan struct{})
	}
	if a.Address == "" {
		a.Address = ":53"
	}
	return nil
}

func (a *App) Start() error {
	parsed, err := caddy.ParseNetworkAddress(a.Address)
	if err != nil {
		return err
	}
	parsed.Network = "udp"
	a.logger.Debug("starting app", zap.Stringer("address", parsed))
	srv := Server{
		Address:  parsed,
		logger:   a.logger,
		shutdown: a.shutdown,
		ctx:      a.ctx,
		requests: a.requests,
		Records:  make(map[key][]dns.RR),
	}
	for _, record_string := range a.Records {
		record, err := dns.NewRR(record_string)
		if err != nil {
			return err
		}
		srv.insert_record(record)
	}
	if len(a.Records) > 0 {
		a.logger.Debug("loaded records", zap.Int("count", len(a.Records)))
	} else {
		a.logger.Debug("no records loaded")
	}

	err = srv.start_stop_server()
	if err != nil {
		return err
	}
	go srv.main()

	return nil
}

func (a *App) Stop() error {
	a.logger.Debug("stopping app")
	close(a.shutdown)
	return nil
}

// UnmarshalCaddyfile sets up the DNS provider from Caddyfile tokens. Syntax:
//
//	dns [address] {
//	    bind <address>
//	    [record "<record>"]
//	}
func (a *App) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			a.Address = d.Val()
			_, err := caddy.ParseNetworkAddress(a.Address)
			if err != nil {
				return d.WrapErr(err)
			}
		}
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "bind":
				if a.Address != "" {
					return d.Err("Bind address already set")
				}
				if d.NextArg() {
					a.Address = d.Val()
					_, err := caddy.ParseNetworkAddress(a.Address)
					if err != nil {
						return d.WrapErr(err)
					}
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			case "record":
				if d.NextArg() {
					rr, err := dns.NewRR(d.Val())
					if err != nil {
						return d.WrapErr(err)
					}
					if rr == nil {
						return d.Err("invalid empty record")
					}
					a.Records = append(a.Records, rr.String())
				} else {
					return d.ArgErr()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	if a.Address == "" {
		a.Address = ":53"
	}
	return nil
}

// parseApp configures the "dns" global option from Caddyfile.
// Syntax:
//
//	dns [address] {
//	    bind <address>
//	    [record <record>]
//	}
func parseApp(d *caddyfile.Dispenser, prev interface{}) (interface{}, error) {
	var a App
	var warnings []caddyconfig.Warning
	if prev != nil {
		return nil, fmt.Errorf("multiple DNS servers are not supported!")
	}

	err := a.UnmarshalCaddyfile(d)
	if err != nil {
		return nil, err
	}

	// tell Caddyfile adapter that this is the JSON for an app
	return httpcaddyfile.App{
		Name:  "dns",
		Value: caddyconfig.JSON(a, &warnings),
	}, nil
}

// Interface guards
var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
)
