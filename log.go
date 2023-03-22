package stub

import (
	"github.com/libdns/libdns"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Wrapper for logging (relevant parts of) dns.Msg
type LoggableDNSMsg struct{ *dns.Msg }

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
				object := func(obj zapcore.ObjectEncoder) error {
					log_RR(obj, r)
					return nil
				}
				arr.AppendObject(zapcore.ObjectMarshalerFunc(object))
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

// Only logs the "content"/values of the RR for common types
func log_RR(enc zapcore.ObjectEncoder, rr dns.RR) {
	hdr := rr.Header()
	enc.AddString("name", hdr.Name)
	enc.AddString("class", dns.ClassToString[hdr.Class])
	enc.AddString("type", dns.TypeToString[hdr.Rrtype])
	enc.AddUint32("TTL", hdr.Ttl)
	switch r := rr.(type) {
	case *dns.A:
		enc.AddString("A", r.A.String())
	case *dns.AAAA:
		enc.AddString("AAAA", r.AAAA.String())
	case *dns.AFSDB:
	// case *dns.AMTRELAY:
	case *dns.ANY: // empty
	case *dns.APL:
	case *dns.AVC:
	case *dns.CAA:
		enc.AddUint8("flag", r.Flag)
		enc.AddString("tag", r.Tag)
		enc.AddString("value", r.Value)
	case *dns.CDNSKEY:
	case *dns.CDS:
	case *dns.CERT:
	case *dns.CNAME:
		enc.AddString("target", r.Target)
	case *dns.CSYNC:
	case *dns.DHCID:
	case *dns.DLV:
	case *dns.DNAME:
		enc.AddString("target", r.Target)
	case *dns.DNSKEY:
	case *dns.DS:
	case *dns.EID:
	case *dns.EUI48:
	case *dns.EUI64:
	case *dns.GID:
	case *dns.GPOS:
	case *dns.HINFO:
	case *dns.HIP:
	case *dns.HTTPS:
	// case *dns.IPSECKEY:
	case *dns.KEY:
	case *dns.KX:
	case *dns.L32:
	case *dns.L64:
	case *dns.LOC:
	case *dns.LP:
	case *dns.MB:
	case *dns.MD:
	case *dns.MF:
	case *dns.MG:
	case *dns.MINFO:
	case *dns.MR:
	case *dns.MX:
		enc.AddString("MX", r.Mx)
		enc.AddUint16("preference", r.Preference)
	case *dns.NAPTR:
	case *dns.NID:
	case *dns.NIMLOC:
	case *dns.NINFO:
	case *dns.NS:
		enc.AddString("NS", r.Ns)
	case *dns.NSAPPTR:
	case *dns.NSEC:
	case *dns.NSEC3:
	case *dns.NSEC3PARAM:
	case *dns.NULL:
	case *dns.OPENPGPKEY:
		enc.AddString("public_key", r.PublicKey)
	case *dns.OPT:
	case *dns.PTR:
		enc.AddString("PTR", r.Ptr)
	case *dns.PX:
	case *dns.RKEY:
	case *dns.RP:
	case *dns.RRSIG:
	case *dns.RT:
	case *dns.SIG:
	case *dns.SMIMEA:
	case *dns.SOA:
		enc.AddString("NS", r.Ns)
		enc.AddString("mbox", r.Mbox)
		enc.AddUint32("serial", r.Serial)
		enc.AddUint32("retry", r.Retry)
		enc.AddUint32("refresh", r.Refresh)
		enc.AddUint32("expire", r.Expire)
		enc.AddUint32("minttl", r.Minttl)
	case *dns.SPF:
		zap.Strings("TXT", r.Txt).AddTo(enc)
	case *dns.SRV:
		enc.AddUint16("priority", r.Priority)
		enc.AddUint16("weight", r.Weight)
		enc.AddUint16("port", r.Port)
		enc.AddString("target", r.Target)
	case *dns.SSHFP:
		enc.AddUint8("algorithm", r.Algorithm)
		enc.AddUint8("type", r.Type)
		enc.AddString("fingerprint", r.FingerPrint)
	case *dns.SVCB:
	case *dns.TA:
	case *dns.TALINK:
	case *dns.TKEY:
	case *dns.TLSA:
	case *dns.TSIG:
	case *dns.TXT:
		zap.Strings("TXT", r.Txt).AddTo(enc)
	case *dns.UID:
	case *dns.UINFO:
	case *dns.URI:
	case *dns.X25:
	case *dns.ZONEMD:
	default:
	}
}

func log_libdns_record(record *libdns.Record) zapcore.ObjectMarshaler {
	f := func(enc zapcore.ObjectEncoder) error {
		enc.AddString("ID", record.ID)
		enc.AddString("type", record.Type)
		enc.AddString("name", record.Name)
		enc.AddString("value", record.Value)
		enc.AddString("TTL", record.TTL.String())
		if record.Priority != 0 {
			enc.AddInt("priority", record.Priority)
		}
		return nil
	}
	return zapcore.ObjectMarshalerFunc(f)
}

