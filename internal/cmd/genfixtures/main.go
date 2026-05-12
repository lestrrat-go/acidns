// Command genfixtures regenerates the wire/testdata/*.hex roundtrip
// fixtures using the wiretest builders. It is run by hand when a fixture
// needs to be added or refreshed; the produced .hex bytes are committed
// to the repository and consumed by wire/testdata_test.go.
//
// This program lives under cmd/ but is intentionally NOT shipped: it
// is a developer-only fixture generator and its output (one short hex
// string per packet) is what actually exercises the decoder in CI.
package main

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/internal/wiretest"
)

type fixture struct {
	name string
	desc string
	msg  wire.Message
}

func mustEDNSResponse(q wire.Message, opts ...wire.EDNSOption) wire.Message {
	eb := wire.NewEDNSBuilder()
	for _, o := range opts {
		eb = eb.Option(o)
	}
	e, err := eb.Build()
	if err != nil {
		panic(err)
	}
	b := wire.NewMessageBuilder().
		ID(q.ID()).
		Response(true).
		RecursionDesired(q.Flags().RecursionDesired()).
		RecursionAvailable(true).
		EDNS(e)
	if qs := q.Questions(); len(qs) > 0 {
		b = b.Question(qs[0])
	}
	m, err := b.Build()
	if err != nil {
		panic(err)
	}
	return m
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: genfixtures <output-dir>")
		os.Exit(2)
	}
	outDir := os.Args[1]
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		panic(err)
	}

	exampleCom := wire.MustParseName("example.com.")
	wwwExample := wire.MustParseName("www.example.com.")
	mxHost := wire.MustParseName("mx1.example.com.")
	ns1 := wire.MustParseName("ns1.example.com.")
	ns2 := wire.MustParseName("ns2.example.com.")
	revIPv4 := wire.MustParseName("1.0.0.127.in-addr.arpa.")
	sipUDP := wire.MustParseName("_sip._udp.example.com.")
	sipTarget := wire.MustParseName("sipserver.example.com.")
	naptrName := wire.MustParseName("naptr.example.com.")
	tlsaName := wire.MustParseName("_443._tcp.example.com.")
	sshfpName := wire.MustParseName("ssh.example.com.")
	apexEx := wire.MustParseName("example.com.")
	httpsName := wire.MustParseName("svc.example.com.")
	svcbName := wire.MustParseName("_dns.example.com.")
	target := wire.MustParseName("svc.example.net.")

	// EDNS option for the OPT fixture: an Extended DNS Error.
	ede := wire.NewExtendedError(wire.ExtendedErrorOther, "fuzz fixture")

	// SRV target.
	srv, err := rdata.NewSRV(10, 60, 5060, sipTarget)
	if err != nil {
		panic(err)
	}

	// NAPTR.
	naptr, err := rdata.NewNAPTR(100, 10, "u", "E2U+sip",
		"!^.*$!sip:info@example.com!", wire.MustParseName("."))
	if err != nil {
		panic(err)
	}

	// CAA.
	caa, err := rdata.NewCAA(0, "issue", []byte("letsencrypt.org"))
	if err != nil {
		panic(err)
	}

	// TLSA: PKIX-EE / SPKI / SHA-256.
	tlsaSig := make([]byte, 32)
	for i := range tlsaSig {
		tlsaSig[i] = byte(i + 1)
	}
	tlsa := rdata.NewTLSA(rdata.TLSAUsagePKIXEE, rdata.TLSASelectorSPKI,
		rdata.TLSAMatchingSHA256, tlsaSig)

	// SSHFP: ED25519 / SHA-256.
	sshfpFp := make([]byte, 32)
	for i := range sshfpFp {
		sshfpFp[i] = byte(0xa0 + i)
	}
	sshfp := rdata.NewSSHFP(rdata.SSHFPAlgED25519, rdata.SSHFPTypeSHA256, sshfpFp)

	// DNSKEY: zone, ECDSAP256SHA256, dummy 64-byte pubkey.
	dnskeyPub := make([]byte, 64)
	for i := range dnskeyPub {
		dnskeyPub[i] = byte(i + 7)
	}
	dnskey, err := rdata.NewDNSKEY(rdata.DNSKEYFlagZone, 3,
		rdata.AlgECDSAP256SHA256, dnskeyPub)
	if err != nil {
		panic(err)
	}

	// DS: matching SHA-256.
	dsDigest := make([]byte, 32)
	for i := range dsDigest {
		dsDigest[i] = byte(0x10 + i)
	}
	ds, err := rdata.NewDS(12345, rdata.AlgECDSAP256SHA256,
		rdata.DigestSHA256, dsDigest)
	if err != nil {
		panic(err)
	}

	// RRSIG over A, dummy 64-byte signature.
	rrsigSig := make([]byte, 64)
	for i := range rrsigSig {
		rrsigSig[i] = byte(0x40 + i)
	}
	inception := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	expiration := inception.Add(14 * 24 * time.Hour)
	rrsig := rdata.NewRRSIG(rrtype.A, rdata.AlgECDSAP256SHA256,
		2, time.Hour, expiration, inception, 12345, exampleCom, rrsigSig)

	// NSEC: example.com -> www.example.com, types A, AAAA, RRSIG, NSEC.
	nsec := rdata.NewNSEC(wwwExample,
		[]rrtype.Type{rrtype.A, rrtype.AAAA, rrtype.RRSIG, rrtype.NSEC})

	// NSEC3.
	nsec3Salt := []byte{0xaa, 0xbb}
	nsec3Next := make([]byte, 20)
	for i := range nsec3Next {
		nsec3Next[i] = byte(0x80 + i)
	}
	nsec3, err := rdata.NewNSEC3(1, 0, 10, nsec3Salt, nsec3Next,
		[]rrtype.Type{rrtype.A, rrtype.RRSIG})
	if err != nil {
		panic(err)
	}

	// SVCB / HTTPS.
	alpn, err := rdata.NewSvcParamALPN("h2", "h3")
	if err != nil {
		panic(err)
	}
	port := rdata.NewSvcParamPort(443)
	v4Hint, err := rdata.NewSvcParamIPv4Hint(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		panic(err)
	}
	svcb, err := rdata.NewSVCB(1, target, alpn, port, v4Hint)
	if err != nil {
		panic(err)
	}
	https, err := rdata.NewHTTPS(1, target, alpn, port)
	if err != nil {
		panic(err)
	}

	exit := func(err error) {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	mkResp := func(qname wire.Name, qtype rrtype.Type, ans ...wire.Record) wire.Message {
		q, err := wiretest.Query(qname, qtype)
		exit(err)
		r, err := wiretest.Response(q, ans...)
		exit(err)
		return r
	}

	aR, err := wiretest.ARecord(exampleCom, 5*time.Minute, "192.0.2.1")
	exit(err)
	aaaaR, err := wiretest.AAAARecord(exampleCom, 5*time.Minute, "2001:db8::1")
	exit(err)
	mxR, err := wiretest.MXRecord(exampleCom, time.Hour, 10, mxHost)
	exit(err)
	txtR, err := wiretest.TXTRecord(exampleCom, time.Hour, "v=spf1 -all")
	exit(err)
	cnameR, err := wiretest.CNAMERecord(wwwExample, time.Hour, exampleCom)
	exit(err)
	soaR, err := wiretest.SOARecord(exampleCom, time.Hour,
		ns1, wire.MustParseName("hostmaster.example.com."),
		2024010101, 7200*time.Second, 3600*time.Second,
		1209600*time.Second, 3600*time.Second)
	exit(err)
	nsR1, err := wiretest.NSRecord(exampleCom, time.Hour, ns1)
	exit(err)
	nsR2, err := wiretest.NSRecord(exampleCom, time.Hour, ns2)
	exit(err)
	ptrR, err := wiretest.PTRRecord(revIPv4, time.Hour, wwwExample)
	exit(err)
	optQ, err := wiretest.Query(exampleCom, rrtype.A)
	exit(err)

	fixtures := []fixture{
		{
			name: "a", desc: "A query for example.com -> 192.0.2.1",
			msg:  mkResp(exampleCom, rrtype.A, aR),
		},
		{
			name: "aaaa", desc: "AAAA query for example.com -> 2001:db8::1",
			msg:  mkResp(exampleCom, rrtype.AAAA, aaaaR),
		},
		{
			name: "mx", desc: "MX query for example.com -> 10 mx1.example.com",
			msg:  mkResp(exampleCom, rrtype.MX, mxR),
		},
		{
			name: "txt", desc: "TXT query for example.com -> v=spf1 -all",
			msg:  mkResp(exampleCom, rrtype.TXT, txtR),
		},
		{
			name: "cname", desc: "CNAME www.example.com -> example.com",
			msg:  mkResp(wwwExample, rrtype.CNAME, cnameR),
		},
		{
			name: "soa", desc: "SOA for example.com",
			msg:  mkResp(exampleCom, rrtype.SOA, soaR),
		},
		{
			name: "ns", desc: "NS for example.com -> ns1, ns2",
			msg:  mkResp(exampleCom, rrtype.NS, nsR1, nsR2),
		},
		{
			name: "ptr", desc: "PTR 1.0.0.127.in-addr.arpa -> www.example.com",
			msg:  mkResp(revIPv4, rrtype.PTR, ptrR),
		},
		{
			name: "srv", desc: "SRV _sip._udp.example.com -> sipserver",
			msg: mkResp(sipUDP, rrtype.SRV,
				wire.NewRecord(sipUDP, time.Hour, srv)),
		},
		{
			name: "naptr", desc: "NAPTR for naptr.example.com",
			msg: mkResp(naptrName, rrtype.NAPTR,
				wire.NewRecord(naptrName, time.Hour, naptr)),
		},
		{
			name: "caa", desc: "CAA issue letsencrypt.org",
			msg: mkResp(exampleCom, rrtype.CAA,
				wire.NewRecord(exampleCom, time.Hour, caa)),
		},
		{
			name: "tlsa", desc: "TLSA _443._tcp.example.com",
			msg: mkResp(tlsaName, rrtype.TLSA,
				wire.NewRecord(tlsaName, time.Hour, tlsa)),
		},
		{
			name: "sshfp", desc: "SSHFP ssh.example.com (ED25519/SHA-256)",
			msg: mkResp(sshfpName, rrtype.SSHFP,
				wire.NewRecord(sshfpName, time.Hour, sshfp)),
		},
		{
			name: "dnskey", desc: "DNSKEY for example.com (ECDSAP256SHA256)",
			msg: mkResp(apexEx, rrtype.DNSKEY,
				wire.NewRecord(apexEx, time.Hour, dnskey)),
		},
		{
			name: "ds", desc: "DS for example.com (SHA-256)",
			msg: mkResp(apexEx, rrtype.DS,
				wire.NewRecord(apexEx, time.Hour, ds)),
		},
		{
			name: "rrsig", desc: "RRSIG over A for example.com",
			msg: mkResp(apexEx, rrtype.RRSIG,
				wire.NewRecord(apexEx, time.Hour, rrsig)),
		},
		{
			name: "nsec", desc: "NSEC example.com -> www.example.com",
			msg: mkResp(apexEx, rrtype.NSEC,
				wire.NewRecord(apexEx, time.Hour, nsec)),
		},
		{
			name: "nsec3", desc: "NSEC3 for example.com",
			msg: mkResp(apexEx, rrtype.NSEC3,
				wire.NewRecord(apexEx, time.Hour, nsec3)),
		},
		{
			name: "opt", desc: "OPT (EDNS) response with EDE option",
			msg:  mustEDNSResponse(optQ, ede),
		},
		{
			name: "svcb", desc: "SVCB _dns.example.com",
			msg: mkResp(svcbName, rrtype.SVCB,
				wire.NewRecord(svcbName, time.Hour, svcb)),
		},
		{
			name: "https", desc: "HTTPS svc.example.com",
			msg: mkResp(httpsName, rrtype.HTTPS,
				wire.NewRecord(httpsName, time.Hour, https)),
		},
	}

	for _, f := range fixtures {
		buf, err := wire.Pack(f.msg)
		if err != nil {
			panic(fmt.Errorf("marshal %s: %w", f.name, err))
		}
		hexPath := filepath.Join(outDir, f.name+".hex")
		txtPath := filepath.Join(outDir, f.name+".txt")
		if err := os.WriteFile(hexPath, []byte(hex.EncodeToString(buf)+"\n"), 0o644); err != nil {
			panic(err)
		}
		if err := os.WriteFile(txtPath, []byte(f.desc+"\n"), 0o644); err != nil {
			panic(err)
		}
		fmt.Printf("wrote %s (%d bytes)\n", hexPath, len(buf))
	}
}
