// Command lookup demonstrates the acidns client API by performing an A/AAAA
// lookup against the resolver supplied on the command line.
//
// Usage: lookup [-server 1.1.1.1:53] <hostname>
package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
)

func main() {
	server := flag.String("server", "1.1.1.1:53", "DNS server to query")
	rrType := flag.String("type", "", "RR type (A, AAAA, MX, ...) — overrides default LookupHost")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: lookup [-server host:port] [-type RR] <hostname>")
		os.Exit(2)
	}
	host := flag.Arg(0)

	addr, err := netip.ParseAddrPort(*server)
	check(err)

	r, err := dnsclient.New(dnsclient.WithServers(addr))
	check(err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if *rrType == "" {
		addrs, err := dnsclient.LookupHost(ctx, r, host)
		check(err)
		for _, a := range addrs {
			fmt.Println(a)
		}
		return
	}

	t, ok := rrtype.Parse(*rrType)
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown RR type: %s\n", *rrType)
		os.Exit(2)
	}
	name, err := dnsname.Parse(host)
	check(err)

	ans, err := r.Resolve(ctx, name, t)
	check(err)
	fmt.Printf(";; ->>HEADER<<- rcode: %s, answers: %d\n", ans.RCODE(), len(ans.Records()))
	for _, rec := range ans.Records() {
		fmt.Printf("%s\t%d\t%s\t%s\t%s\n",
			rec.Name(), int(rec.TTL().Seconds()),
			rec.Class(), rec.Type(), formatRData(rec.RData()))
	}
}

func formatRData(rd rdata.RData) string {
	// Switching on Type() rather than on Go interface — interfaces with
	// overlapping method sets (e.g. CNAME and SVCB both have Target())
	// would otherwise route to the wrong case.
	switch rd.Type() {
	case rrtype.A:
		return rd.(rdata.A).Addr().String()
	case rrtype.AAAA:
		return rd.(rdata.AAAA).Addr().String()
	case rrtype.CNAME:
		return rd.(rdata.CNAME).Target().String()
	case rrtype.NS:
		return rd.(rdata.NS).NSDName().String()
	case rrtype.PTR:
		return rd.(rdata.PTR).PtrDName().String()
	case rrtype.MX:
		v := rd.(rdata.MX)
		return fmt.Sprintf("%d %s", v.Preference(), v.Exchange())
	case rrtype.TXT:
		return fmt.Sprintf("%q", rd.(rdata.TXT).Strings())
	case rrtype.SOA:
		v := rd.(rdata.SOA)
		return fmt.Sprintf("%s %s %d %d %d %d %d",
			v.MName(), v.RName(), v.Serial(),
			int(v.Refresh().Seconds()), int(v.Retry().Seconds()),
			int(v.Expire().Seconds()), int(v.Minimum().Seconds()))
	case rrtype.SVCB, rrtype.HTTPS:
		return formatSVCB(rd.(rdata.SVCB))
	case rrtype.CAA:
		v := rd.(rdata.CAA)
		return fmt.Sprintf("%d %s %q", v.Flags(), v.Tag(), v.Value())
	case rrtype.DNSKEY:
		v := rd.(rdata.DNSKEY)
		return fmt.Sprintf("%d 3 %d %x...", v.Flags(), v.Algorithm(), truncate(v.PublicKey(), 8))
	case rrtype.DS:
		v := rd.(rdata.DS)
		return fmt.Sprintf("%d %d %d %x", v.KeyTag(), v.Algorithm(), v.DigestType(), v.Digest())
	case rrtype.RRSIG:
		v := rd.(rdata.RRSIG)
		return fmt.Sprintf("%s %d %d %d %d %d %d %s %x...",
			v.TypeCovered(), v.Algorithm(), v.Labels(),
			int(v.OriginalTTL().Seconds()),
			v.SignatureExpiration().Unix(), v.SignatureInception().Unix(),
			v.KeyTag(), v.SignerName(), truncate(v.Signature(), 8))
	default:
		if u, ok := rd.(rdata.Unknown); ok {
			return fmt.Sprintf("(opaque %d bytes)", len(u.Bytes()))
		}
		return fmt.Sprintf("(unhandled type %s)", rd.Type())
	}
}

func formatSVCB(s rdata.SVCB) string {
	out := fmt.Sprintf("%d %s", s.Priority(), s.Target())
	for _, p := range s.Params() {
		out += fmt.Sprintf(" key%d=%x", p.Key(), p.Value())
	}
	return out
}

func truncate(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
