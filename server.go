package stub

import (
	"errors"
	"net"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

// A DNS Query coming in from outside
type query struct {
	w dns.ResponseWriter
	r *dns.Msg
}

type key struct {
	Type dns.Type
	Name string
}

type Server struct {
	// the address & port on which to serve DNS for the challenge
	Address caddy.NetworkAddress `json:"address,omitempty"`

	// Statically configured records to serve
	Records map[key][]dns.RR `json:"records,omitempty"`

	logger   *zap.Logger    // set by App.start()
	ctx      *caddy.Context // set by App.start()
	shutdown chan struct{}  // set by App.start()
	requests chan request   // set by App.start()

	dns_server *dns.Server // set by start_stop_server()
	queries    chan query  // set by start_stop_server()

}

func rr_key(record dns.RR) key {
	return key{
		Type: dns.Type(record.Header().Rrtype),
		Name: strings.ToLower(record.Header().Name),
	}
}

func (srv *Server) insert_record(record dns.RR) {
	key := rr_key(record)
	current, exists := srv.Records[key]
	if exists {
		// TODO: de-duplicate?
		srv.Records[key] = append(current, record)
	} else {
		srv.Records[key] = []dns.RR{record}
	}
}

func (srv *Server) delete_record(record dns.RR) {
	key := rr_key(record)
	current, exists := srv.Records[key]
	if exists {
		filtered := []dns.RR{}
		for _, rec := range current {
			if rec != record {
				filtered = append(filtered, rec)
			}
		}
		if len(filtered) == 0 {
			delete(srv.Records, key)
		} else {
			srv.Records[key] = filtered
		}
	} else {
		// doesn't exist, nothing to delete
	}
}

// This is the "main loop" of the DNS server
// To avoid having to synchronize access to the records map, it is owned
// exclusively by this loop, and the methods it calls.
// All DNS queries coming from outside, as well as all requests to create
// or delete DNS records coming from within the process are serialized by
// the select statement.
func (srv *Server) main() {
	srv.logger.Debug(
		"main loop running",
		zap.Int("record_count", len(srv.Records)),
	)
	for {
		select {
		case r := <-srv.requests:
			srv.handle_request(r)
		case q := <-srv.queries:
			srv.handle_query(q)
		case <-srv.shutdown:
			srv.logger.Debug("stopping main loop")
			if srv.dns_server != nil {
				srv.dns_server.Shutdown()
			}
			return
		}
	}
}

func (srv *Server) handle_request(r request) {
	srv.logger.Debug("received", zap.Object("request", r))

	if r.append {
		for _, record := range r.records {
			srv.insert_record(record)
		}
	} else {
		for _, record := range r.records {
			srv.delete_record(record)
		}
	}

	r.responder <- srv.start_stop_server()
}

func (srv *Server) start_stop_server() error {
	if srv.queries == nil {
		srv.queries = make(chan query)
	}
	if len(srv.Records) == 0 {
		if srv.dns_server != nil {
			srv.logger.Debug("no more records to serve, shutting down server")
			err := srv.dns_server.Shutdown()
			srv.dns_server = nil
			return err
		}
		srv.logger.Debug("no records to serve")
		return nil
	} else {
		if srv.dns_server == nil {
			conn, err := srv.bind()
			if err != nil {
				srv.logger.Error(
					"failed to bind",
					zap.Stringer("address", srv.Address),
					zap.Error(err),
				)
				return err
			}

			// spawn the server
			handler := make_proxy(srv.queries)
			server := &dns.Server{
				PacketConn: conn,
				Net:        "udp",
				Handler:    handler,
				TsigSecret: nil,
			}
			srv.logger.Debug(
				"starting server",
				zap.Int("record_count", len(srv.Records)),
			)
			go srv.serve(server)

			// store the server for shutdown later
			srv.dns_server = server
			return nil
		}
		srv.logger.Debug(
			"server already running",
			zap.Int("record_count", len(srv.Records)),
		)
		return nil
	}
}

func (srv *Server) bind() (net.PacketConn, error) {
	conn, err := srv.Address.Listen(srv.ctx, 0, net.ListenConfig{})
	if err != nil {
		return nil, err
	}
	pkt_conn := conn.(net.PacketConn)
	if pkt_conn == nil {
		return nil, errors.New("invalid address")
	}
	srv.logger.Debug("bound to socket", zap.Stringer("address", srv.Address))
	return pkt_conn, nil
}

func (srv *Server) handle_query(q query) {
	// dns.DefaultMsgAcceptFunc already checks that the query is fairly
	// reasonable.

	m := new(dns.Msg)
	m.SetReply(q.r)

	reject_and_log := func(code int, reason string) {
		m.Rcode = code
		m.Answer = []dns.RR{}
		srv.logger.Debug(
			"rejecting query",
			zap.Stringer("address", q.w.RemoteAddr()),
			zap.String("reason", reason),
			zap.Object("response", LoggableDNSMsg{m}),
		)
		q.w.WriteMsg(m)
	}

	qstn := q.r.Question[0]
	if !(qstn.Qclass == dns.ClassINET || qstn.Qclass == dns.ClassANY) {
		// TODO: consider just not worrying about this
		reject_and_log(dns.RcodeNotImplemented, "invalid class")
		return
	}
	// queries may be wAcKY casE
	// https://datatracker.ietf.org/doc/html/draft-vixie-dnsext-dns0x20-00
	key := key{
		Type: dns.Type(qstn.Qtype),
		Name: strings.ToLower(qstn.Name),
	}
	records, exists := srv.Records[key]
	if !exists {
		reject_and_log(dns.RcodeNameError, "no such record")
		return
	}

	m.Authoritative = true
	m.Answer = records

	srv.logger.Debug(
		"answering query",
		zap.Stringer("address", q.w.RemoteAddr()),
		zap.Object("response", LoggableDNSMsg{m}),
	)
	q.w.WriteMsg(m)
}

func (srv *Server) serve(server *dns.Server) {
	err := server.ActivateAndServe()
	if err != nil {
		srv.logger.Error("dns.ActivateAndServe failed", zap.Error(err))
	} else {
		srv.logger.Debug("server terminated successfully")
	}
}

// dns.HandlerFunc that forwards every query into a channel
func make_proxy(sink chan query) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		q := query{w, r}
		sink <- q
	}
}
