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
	"strings"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
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

	r, err := acidns.NewResolver(acidns.WithServers(addr))
	check(err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if *rrType == "" {
		addrs, err := acidns.LookupHost(ctx, r, host)
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
	name, err := wire.ParseName(host)
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
	// Type switch on the concrete rdata struct: each case binds v to the
	// specific type so we can call its accessors without a separate
	// assertion. rdata structs no longer share method sets across types
	// (CNAME and SVCB both have Target() but different concrete types),
	// so a Go type switch routes each value correctly.
	switch v := rd.(type) {
	case rdata.A:
		return v.Addr().String()
	case rdata.AAAA:
		return v.Addr().String()
	case rdata.CNAME:
		return v.Target().String()
	case rdata.NS:
		return v.NSDName().String()
	case rdata.PTR:
		return v.PtrDName().String()
	case rdata.MX:
		return fmt.Sprintf("%d %s", v.Preference(), v.Exchange())
	case rdata.TXT:
		return fmt.Sprintf("%q", v.Strings())
	case rdata.SOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d",
			v.MName(), v.RName(), v.Serial(),
			int(v.Refresh().Seconds()), int(v.Retry().Seconds()),
			int(v.Expire().Seconds()), int(v.Minimum().Seconds()))
	case rdata.SVCB:
		return formatSVCB(v)
	case rdata.HTTPS:
		return formatSVCB(v)
	case rdata.CAA:
		return fmt.Sprintf("%d %s %q", v.Flags(), v.Tag(), v.Value())
	case rdata.DNSKEY:
		return fmt.Sprintf("%d 3 %d %x...", v.Flags(), v.Algorithm(), truncate(v.PublicKey(), 8))
	case rdata.DS:
		return fmt.Sprintf("%d %d %d %x", v.KeyTag(), v.Algorithm(), v.DigestType(), v.Digest())
	case rdata.RRSIG:
		return fmt.Sprintf("%s %d %d %d %d %d %d %s %x...",
			v.TypeCovered(), v.Algorithm(), v.Labels(),
			int(v.OriginalTTL().Seconds()),
			v.SignatureExpiration().Unix(), v.SignatureInception().Unix(),
			v.KeyTag(), v.SignerName(), truncate(v.Signature(), 8))
	case rdata.Unknown:
		return fmt.Sprintf("(opaque %d bytes)", len(v.Bytes()))
	default:
		return fmt.Sprintf("(unhandled type %s)", rd.Type())
	}
}

// svcbLike covers the methods shared by rdata.SVCB and rdata.HTTPS via
// their embedded body. The type-set constraint pairs with the method set
// promoted from svcbBody on each member.
type svcbLike interface {
	rdata.SVCB | rdata.HTTPS
	Priority() uint16
	Target() wire.Name
	Params() []rdata.SVCBParam
}

func formatSVCB[T svcbLike](s T) string {
	var out strings.Builder
	fmt.Fprintf(&out, "%d %s", s.Priority(), s.Target())
	for _, p := range s.Params() {
		fmt.Fprintf(&out, " key%d=%x", p.Key(), p.Value())
	}
	return out.String()
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
