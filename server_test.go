package stub

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/miekg/dns"
)

const dns_address string = "127.0.0.1:53535"

const dns_only string = `{
	admin localhost:2999
	debug
	dns 127.0.0.1:53535 {
		record "sub123.example.com. A 127.0.0.1"
		record "ABC123. AAAA ::"
		record "example.com. CAA 0 issue ca.example.net"
		record "example.com. CNAME test123"
		record "example.com. 3333 IN NS ns1.example.com."
		record "example.com. MX 42 mx.example.com."
		record "_caddy._tcp.example.com. SRV 3 33 2999 test123."
		record "txt123.example.com. TXT Test123"
		record "whitespace. TXT Test 123 ABC	XYZ"
	}
}
`

const dns_only_json string = `{
	"admin": {
		"listen": "localhost:2999"
	},
	"logging": {
		"logs": {
			"default": {
				"level": "DEBUG"
			}
		}
	},
	"apps": {
		"dns": {
			"address": "127.0.0.1:53535",
			"records": [
				"sub123.example.com.\t3600\tIN\tA\t127.0.0.1",
				"ABC123.\t3600\tIN\tAAAA\t::",
				"example.com.\t3600\tIN\tCAA\t0 issue \"ca.example.net\"",
				"example.com.\t3600\tIN\tCNAME\ttest123.",
				"example.com.\t3333\tIN\tNS\tns1.example.com.",
				"example.com.\t3600\tIN\tMX\t42 mx.example.com.",
				"_caddy._tcp.example.com.\t3600\tIN\tSRV\t3 33 2999 test123.",
				"txt123.example.com.\t3600\tIN\tTXT\t\"Test123\"",
				"whitespace.\t3600\tIN\tTXT\t\"Test\" \"123\" \"ABC\" \"XYZ\""
			]
		}
	}
}`


const dns_but_empty string = `{
	admin localhost:2999
	debug
	dns 127.0.0.1:53535
}
`

const dns_but_empty_json string = `{
	"admin": {
		"listen": "localhost:2999"
	},
	"logging": {
		"logs": {
			"default": {
				"level": "debug"
			}
		}
	},
	"apps": {
		"dns": {
			"address": "127.0.0.1:53535"
		}
	}
}`

func TestDNSConfig(t *testing.T) {
	caddytest.AssertAdapt(t, dns_only, "caddyfile", dns_only_json)
}

func check_exists(t *testing.T, record string) {
	rr, err := dns.NewRR(record)
	if err != nil {
		t.Fatal("invalid record; ", record, "\nerror:", err)
	}
	in := query_dns(t, rr.Header().Name, rr.Header().Rrtype)

	if in.MsgHdr.Rcode != dns.RcodeSuccess {
		t.Fatal("DNS error: ", dns.RcodeToString[in.MsgHdr.Rcode])
	}

	expected := rr.String()
	received := in.Answer[0].String()

	if expected != received {
		t.Fatal(
			"record mismatch!",
			"\nexpected: ",
			expected,
			"\nreceived: ",
			received,
		)
	}

	// Gives different results than the string comparison. unclear why
	//if !reflect.DeepEqual(in.Answer[0], rr) {
	//	t.Fatal("answer section mismatch!")
	//}
}

func query_dns(t *testing.T, name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)

	c := new(dns.Client)
	c.DialTimeout = 1 * time.Second
	in, rtt, err := c.Exchange(m, dns_address)
	_ = rtt

	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in.Question, m.Question) {
		t.Fatal("question section mismatch!")
	}
	return in
}


func wAcKY_casE(input string) string {
	INPUT := strings.ToUpper(input)
	InPuT := ""

	for i := range input {
		if rand.Intn(2) == 1 {
			InPuT = InPuT + INPUT[i:i]
		} else {
			InPuT = InPuT + input[i:i]
		}
	}

	return InPuT
}

// https://datatracker.ietf.org/doc/html/draft-vixie-dnsext-dns0x20-00
func qUeRY_dNs(t *testing.T, name string, qtype uint16) *dns.Msg {

	runes := []rune{}
	for _, c := range name {
		if rand.Intn(2) == 1 {
			runes = append(runes, unicode.ToUpper(c))
		} else {
			runes = append(runes, c)
		}
	}
	nAmE := string(runes)
	println("before: ", name, "\nafter: ", nAmE)

	m := new(dns.Msg)
	m.SetQuestion(nAmE, qtype)

	c := new(dns.Client)
	c.DialTimeout = 1 * time.Second
	in, rtt, err := c.Exchange(m, dns_address)
	_ = rtt

	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in.Question, m.Question) {
		t.Fatal(
			"question section mismatch!",
			"\nsent: ",
			m.Question,
			"\nreceived: ",
			in.Question,
		)
	}
	return in
}

func cHEcK_eXiSTs(t *testing.T, record string) {
	rr, err := dns.NewRR(record)
	if err != nil {
		t.Fatal("invalid record; ", record, "\nerror:", err)
	}
	in := qUeRY_dNs(t, rr.Header().Name, rr.Header().Rrtype)

	if in.MsgHdr.Rcode != dns.RcodeSuccess {
		t.Fatal("DNS error: ", dns.RcodeToString[in.MsgHdr.Rcode])
	}

	expected := rr.String()
	received := in.Answer[0].String()

	if expected != received {
		t.Fatal(
			"record mismatch!",
			"\nexpected: ",
			expected,
			"\nreceived: ",
			received,
		)
	}
}

func check_errors(t *testing.T, m *dns.Msg, rcode int) {
	c := new(dns.Client)
	c.DialTimeout = 100 * time.Millisecond
	in, rtt, err := c.Exchange(m, dns_address)
	_ = rtt

	if err != nil {
		t.Fatal(err, "\n", m)
	}
	/*
	if !reflect.DeepEqual(in.Question, m.Question) {
		t.Fatal(
			"question section mismatch!",
			"\nsent: ",
			m.Question,
			"\nreceived: ",
			in.Question,
		)
	}
	*/
	if in.Rcode != rcode {
		t.Fatal(
			"rcode mismatch:",
			"\nexpected: ",
			rcode,
			"\nreceived: ",
			in.Rcode,
			"\nquery:\n",
			m,
		)
	}
}

func check_fails(t *testing.T, m *dns.Msg, error_contains string) {
	c := new(dns.Client)
	c.DialTimeout = 100 * time.Millisecond
	in, rtt, err := c.Exchange(m, dns_address)
	_ = rtt

	if in != nil {
		t.Fatal(
			"query was expected to fail with: \"",
			error_contains,
			"\", but returned response!\n",
			in.String(),
		)
	}
	if err == nil {
		t.Fatal(
			"query was expected to fail with: \"",
			error_contains,
			"\", but did not return an error!",
		)
	}
	if !strings.Contains(err.Error(), error_contains) {
		// TODO: this might be flaky
		t.Fatal(
			"query was expected to fail with: \"",
			error_contains,
			"\", but returned error: ",
			err,
		)
	}
}


func TestServer(t *testing.T) {
	// I guess I have to seed my own RNG like a caveman
	rand.Seed(time.Now().UnixNano())

	caddytest.Default.TestRequestTimeout = 1 * time.Second
	caddytest.Default.LoadRequestTimeout = 1 * time.Second

	tester := caddytest.NewTester(t)
	tester.InitServer(dns_only, "caddyfile")

	records := []string {
		"sub123.example.com. A 127.0.0.1",
		"ABC123 AAAA ::",
		"example.com. CAA 0 issue ca.example.net",
		"example.com CNAME test123",
		"example.com. 3333 IN NS ns1.example.com.",
		"example.com. MX 42 mx.example.com.",
		"_caddy._tcp.example.com. SRV 3 33 2999 test123.",
		"txt123.example.com. TXT Test123",
		"whitespace. TXT Test 123 ABC	XYZ",
	}


	for _, record := range records {
		check_exists(t, record)
		/*	WACKY-CASE QUERIES */
		cHEcK_eXiSTs(t, record)
	}

	empty := new(dns.Msg)
	check_errors(t, empty, dns.RcodeFormatError)

	non_existent := new(dns.Msg)
	non_existent.SetQuestion("does.not.exist.example.com.", dns.TypeA)
	check_errors(t, non_existent, dns.RcodeNameError)

	chaos := new(dns.Msg)
	chaos.SetQuestion("sub123.example.com.", dns.TypeA)
	chaos.Question[0].Qclass = dns.ClassCHAOS
	check_errors(t, chaos, dns.RcodeNotImplemented)


	/* IGNORE NON-QUESTIONS */
	question := new(dns.Msg)
	question.SetQuestion("sub123.example.com.", dns.TypeA)
	not_a_question := new(dns.Msg)
	not_a_question.SetReply(not_a_question)
	answer, _ := dns.NewRR("sub123.example.com. A 127.0.0.1")
	not_a_question.Answer = []dns.RR{answer}
	check_fails(t, not_a_question, "timeout")


	/*	REFUSE MULTI-QUESTIONS */
	multi := new(dns.Msg)
	multi.SetQuestion("example.com.", dns.TypeCNAME)
	q1 := multi.Question[0]
	multi.SetQuestion("sub123.example.com.", dns.TypeA)
	multi.Question = append(multi.Question, q1)
	check_errors(t, multi, dns.RcodeFormatError)

}

// The server only listens for DNS queries if there are records to serve
func TestEmptyServer(t *testing.T) {
	caddytest.Default.TestRequestTimeout = 1 * time.Second
	caddytest.Default.LoadRequestTimeout = 1 * time.Second

	tester := caddytest.NewTester(t)
	tester.InitServer(dns_but_empty, "caddyfile")

	question := new(dns.Msg)
	question.SetQuestion("sub123.example.com.", dns.TypeA)
	check_fails(t, question, "refused")
}
