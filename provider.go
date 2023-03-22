package stub

import (
	"context"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

type Provider struct {
	app_channel chan request
	logger      *zap.Logger // set in Provision()
}

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.internal",
		New: func() caddy.Module { return &Provider{} },
	}
}

// Provision sets up the module. Implements caddy.Provisioner.
func (p *Provider) Provision(ctx caddy.Context) error {
	p.logger = ctx.Logger()
	if !ctx.AppIsConfigured("dns") {
		p.logger.Warn("DNS app not yet configured")
	}
	app, err := ctx.App("dns")
	if err != nil {
		return err
	}
	if app == nil {
		return fmt.Errorf("failed to load DNS app")
	}
	dns_app, ok := app.(*App)
	if !ok {
		return fmt.Errorf("received invalid app")
	}
	p.app_channel = dns_app.requests
	return nil
}

// UnmarshalCaddyfile sets up the DNS provider from Caddyfile tokens. Syntax:
//
//	dns internal
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}

func (p *Provider) convert(zone string, set []libdns.Record) ([]dns.RR, error) {
	converted := []dns.RR{}

	for _, r := range set {
		rr, err := record_to_rr(zone, r)
		if err != nil {
			p.logger.Error(
				"failed to convert",
				zap.Error(err),
				zap.String("zone", zone),
				zap.Object("record", log_libdns_record(&r)),
			)
			return nil, err
		}
		converted = append(converted, rr)
	}
	return converted, nil
}

func (p *Provider) make_request(
	ctx context.Context,
	zone string,
	append bool,
	recs []libdns.Record,
) ([]libdns.Record, error) {
	resp := make(chan error)

	records, err := p.convert(zone, recs)
	if err != nil {
		return nil, err
	}

	req := request{
		append:    append,
		zone:      zone,
		records:   records,
		responder: resp,
	}

	p.app_channel <- req
	p.logger.Debug("sent request", zap.Object("request", req))

	select {
	case err = <-resp:
		if err != nil {
			p.logger.Debug("request failed", zap.Error(err))
			return nil, err
		} else {
			p.logger.Debug("request succeeded")
			return recs, nil
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *Provider) AppendRecords(
	ctx context.Context,
	zone string,
	recs []libdns.Record,
) ([]libdns.Record, error) {
	return p.make_request(ctx, zone, true, recs)
}

func (p *Provider) DeleteRecords(
	ctx context.Context,
	zone string,
	recs []libdns.Record,
) ([]libdns.Record, error) {
	return p.make_request(ctx, zone, false, recs)
}

// Interface guards
var (
	_ caddy.Provisioner     = (*Provider)(nil)
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
