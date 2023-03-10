package stub

import (
	"context"
	"net"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// TTL of the challenge TXT record to serve
const challenge_ttl = 600 // (anything is probably fine here)

type StubDNS struct {
	// the address & port on which to serve DNS for the challenge
	Address string `json:"address,omitempty"`

	server *dns.Server // set in Present()
	logger *zap.Logger // set in Provision()
}

// Wrapper for logging (relevant parts of) dns.Msg
type LoggableDNSMsg struct{ *dns.Msg }

func init() {
	caddy.RegisterModule(StubDNS{})
}

// CaddyModule returns the Caddy module information.
func (StubDNS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.stub_dns",
		New: func() caddy.Module { return &StubDNS{} },
	}
}

// Provision sets up the module. Implements caddy.Provisioner.
func (p *StubDNS) Provision(ctx caddy.Context) error {
	p.logger = ctx.Logger()
	repl := caddy.NewReplacer()
	before := p.Address
	p.Address = repl.ReplaceAll(p.Address, "")
	p.logger.Debug(
		"provisioned",
		zap.String("address", p.Address),
		zap.String("address_before_replace", before),
	)
	return nil
}

// UnmarshalCaddyfile sets up the DNS provider from Caddyfile tokens. Syntax:
//
//	stub_dns [address] {
//	    address <address>
//	}
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

	s.logger.Debug(
		"presenting record",
		zap.String("name", fqdn),
		zap.String("content", content),
		zap.String("address", s.Address),
	)

	// dns.Server.ListenAndServe blocks when it binds successfully,
	// so it has to run in a separate task and can't return errors directly

	if err := try_bind(ctx, s.Address); err != nil {
		s.logger.Error(
			"failed to bind",
			zap.String("address", s.Address),
			zap.Error(err),
		)
		return err
	}

	// spawn the server
	handler := s.make_handler(fqdn, content)
	server := &dns.Server{
		Addr:       s.Address,
		Net:        "udp",
		Handler:    handler,
		TsigSecret: nil,
	}
	go s.serve(server)

	// store the server for shutdown later
	s.server = server
	return nil
}

func (p *StubDNS) CleanUp(ctx context.Context, _ acme.Challenge) error {
	if p.server == nil {
		p.logger.Debug("server never started, nothing to clean up")
		return nil
	} else {
		p.logger.Debug(
			"shutting down DNS server",
			zap.String("address", p.Address),
		)
		return p.server.ShutdownContext(ctx)
	}
}

// quickly check whether it's possible to bind to the address
func try_bind(ctx context.Context, address string) error {
	var lc net.ListenConfig
	conn, err := lc.ListenPacket(ctx, "udp", address)
	if conn != nil {
		return conn.Close()
	}
	return err
}

func (s *StubDNS) serve(server *dns.Server) {
	err := server.ListenAndServe()
	if err != nil {
		s.logger.Error(
			"DNS ListenAndServe returned an error!",
			zap.Error(err),
		)
	} else {
		s.logger.Debug("server terminated successfully")
	}
}

func (s *StubDNS) make_handler(fqdn string, txt string) dns.HandlerFunc {
	logger := s.logger
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)

		logger.Debug(
			"received DNS query",
			zap.Stringer("address", w.RemoteAddr()),
			zap.Object("request", LoggableDNSMsg{r}),
		)

		reject_and_log := func(code int, reason string) {
			m.Rcode = code
			m.Answer = []dns.RR{}
			logger.Debug(
				"rejecting query",
				zap.String("reason", reason),
				zap.Object("response", LoggableDNSMsg{m}),
			)
			w.WriteMsg(m)
		}

		if len(r.Question) != 1 {
			reject_and_log(dns.RcodeRefused, "not exactly 1 question")
			return
		}
		q := r.Question[0]
		domain := q.Name

		switch {
		case r.Response:
			reject_and_log(dns.RcodeRefused, "not a query")
		case !(q.Qclass == dns.ClassINET || q.Qclass == dns.ClassANY):
			reject_and_log(dns.RcodeNotImplemented, "invalid class")
		// queries may be wAcKY casE
		// https://datatracker.ietf.org/doc/html/draft-vixie-dnsext-dns0x20-00
		case !strings.EqualFold(domain, fqdn):
			reject_and_log(dns.RcodeNameError, "wrong domain")
		case q.Qtype != dns.TypeTXT:
			reject_and_log(dns.RcodeRefused, "invalid type")
		default:
			m.Authoritative = true
			rr := new(dns.TXT)
			rr.Hdr = dns.RR_Header{
				Name:   fqdn, // only question section has to match wAcKY casE
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    uint32(challenge_ttl),
			}
			rr.Txt = []string{txt}
			m.Answer = []dns.RR{rr}
			logger.Debug(
				"replying",
				zap.Object("response", LoggableDNSMsg{m}),
			)
			w.WriteMsg(m)
		}
	}

	return handler
}

// MarshalLogObject satisfies the zapcore.ObjectMarshaler interface.
func (m LoggableDNSMsg) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	// adapted version of MsgHdr.String() from github.com/miekg/dns
	enc.AddUint16("id", m.Id)
	enc.AddString("opcode", dns.OpcodeToString[m.Opcode])
	enc.AddString("status", dns.RcodeToString[m.Rcode])

	flag_array := func(arr zapcore.ArrayEncoder) error {
		if m.Response {
			arr.AppendString("qr")
		}
		if m.Authoritative {
			arr.AppendString("aa")
		}
		if m.Truncated {
			arr.AppendString("tc")
		}
		if m.RecursionDesired {
			arr.AppendString("rd")
		}
		if m.RecursionAvailable {
			arr.AppendString("ra")
		}
		if m.Zero {
			arr.AppendString("z")
		}
		if m.AuthenticatedData {
			arr.AppendString("ad")
		}
		if m.CheckingDisabled {
			arr.AppendString("cd")
		}

		return nil
	}
	enc.AddArray("flags", zapcore.ArrayMarshalerFunc(flag_array))

	log_questions(enc, &m.Question)
	log_answers(enc, &m.Answer)
	// not logged:
	// - EDNS0 "OPT pseudosection" from m.IsEdns0()
	// - "authority section" in m.Ns
	// - "additional section" in m.Extra

	return nil
}

func log_answers(enc zapcore.ObjectEncoder, answers *[]dns.RR) {
	if len(*answers) > 0 {
		array := func(arr zapcore.ArrayEncoder) error {
			for _, r := range *answers {
				// since we only serve TXT records
				txt, ok := r.(*dns.TXT)
				if ok {
					object := func(obj zapcore.ObjectEncoder) error {
						obj.AddString("name", txt.Hdr.Name)
						obj.AddString("class", dns.ClassToString[txt.Hdr.Class])
						obj.AddString("type", dns.TypeToString[txt.Hdr.Rrtype])
						obj.AddUint32("TTL", txt.Hdr.Ttl)
						rec := func(arr2 zapcore.ArrayEncoder) error {
							for _, t := range txt.Txt {
								arr2.AppendString(t)
							}
							return nil
						}
						obj.AddArray("content", zapcore.ArrayMarshalerFunc(rec))
						return nil
					}
					arr.AppendObject(zapcore.ObjectMarshalerFunc(object))
				} else {
					// fallback for other record types, serialized dig-style
					arr.AppendString(r.String())
				}
			}
			return nil
		}
		enc.AddArray("answer", zapcore.ArrayMarshalerFunc(array))
	}
}

func log_questions(enc zapcore.ObjectEncoder, questions *[]dns.Question) {
	if len(*questions) > 0 {
		array := func(arr zapcore.ArrayEncoder) error {
			for _, q := range *questions {
				object := func(obj zapcore.ObjectEncoder) error {
					obj.AddString("name", q.Name)
					obj.AddString("class", dns.ClassToString[q.Qclass])
					obj.AddString("type", dns.TypeToString[q.Qtype])
					return nil
				}
				arr.AppendObject(zapcore.ObjectMarshalerFunc(object))
			}
			return nil
		}
		enc.AddArray("question", zapcore.ArrayMarshalerFunc(array))
	}
}

// Interface guards
var (
	_ acmez.Solver          = (*StubDNS)(nil)
	_ caddy.Provisioner     = (*StubDNS)(nil)
	_ caddyfile.Unmarshaler = (*StubDNS)(nil)
)
