// Command acidig is a dig-style command-line DNS query tool built on the
// acidns toolkit. It supports plain UDP/TCP, DNS over TLS, and DNS over
// HTTPS, and renders responses in a compact zone-file-like format.
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
	"github.com/lestrrat-go/acidns/doh"
	"github.com/lestrrat-go/acidns/dot"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type opts struct {
	server  string
	port    int
	rrType  string
	useTCP  bool
	useDoT  bool
	dohURL  string
	short   bool
	timeout time.Duration
	tlsName string
	useSys  bool
}

func run(argv []string) error {
	var o opts
	fs := flag.NewFlagSet("acidig", flag.ContinueOnError)
	fs.StringVar(&o.server, "server", "", "explicit DNS server (default: 1.1.1.1, or @server / system resolvers)")
	fs.IntVar(&o.port, "p", 0, "server port (default: 53, 853 for --tls)")
	fs.StringVar(&o.rrType, "t", "", "RR type (default: A)")
	fs.BoolVar(&o.useTCP, "tcp", false, "force TCP")
	fs.BoolVar(&o.useDoT, "tls", false, "use DNS over TLS (port 853 by default)")
	fs.StringVar(&o.dohURL, "https", "", "use DNS over HTTPS at the given URL")
	fs.BoolVar(&o.short, "short", false, "compact output (rdata only)")
	fs.DurationVar(&o.timeout, "timeout", 5*time.Second, "overall timeout")
	fs.StringVar(&o.tlsName, "tls-name", "", "TLS server name (for --tls when server is an IP)")
	fs.BoolVar(&o.useSys, "system", false, "use /etc/resolv.conf for servers and search list")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "usage: acidig [options] [@server] <name> [type]\n\noptions:\n")
		fs.PrintDefaults()
	}

	args := splitAtServerArg(argv, &o.server)
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return fmt.Errorf("no name to query")
	}
	host := rest[0]
	if len(rest) >= 2 && o.rrType == "" {
		o.rrType = rest[1]
	}
	if o.rrType == "" {
		o.rrType = "A"
	}

	rt, ok := rrtype.Parse(o.rrType)
	if !ok {
		return fmt.Errorf("unknown RR type %q", o.rrType)
	}

	r, err := buildResolver(o)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	name, err := wire.ParseName(host)
	if err != nil {
		return fmt.Errorf("parse name: %w", err)
	}

	start := time.Now()
	ans, err := r.Resolve(ctx, name, rt)
	elapsed := time.Since(start)
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	render(os.Stdout, name, rt, ans, elapsed, o)
	return nil
}

// splitAtServerArg extracts a leading @server token from argv, populating
// the supplied server pointer if found, and returns the remaining flags.
func splitAtServerArg(argv []string, server *string) []string {
	out := make([]string, 0, len(argv))
	for _, a := range argv {
		if strings.HasPrefix(a, "@") {
			*server = a[1:]
			continue
		}
		out = append(out, a)
	}
	return out
}

func buildResolver(o opts) (acidns.Resolver, error) {
	switch {
	case o.dohURL != "":
		ex, err := doh.New(o.dohURL)
		if err != nil {
			return nil, err
		}
		return acidns.NewResolver(acidns.WithExchanger(ex))
	case o.useDoT:
		addr, err := serverAddr(o, 853)
		if err != nil {
			return nil, err
		}
		dotOpts := []dot.Option{}
		if o.tlsName != "" {
			dotOpts = append(dotOpts, dot.WithServerName(o.tlsName))
		}
		ex, err := dot.New(addr, dotOpts...)
		if err != nil {
			return nil, err
		}
		return acidns.NewResolver(acidns.WithExchanger(ex))
	case o.useTCP:
		addr, err := serverAddr(o, 53)
		if err != nil {
			return nil, err
		}
		ex, err := acidns.NewTCPExchanger(addr)
		if err != nil {
			return nil, err
		}
		return acidns.NewResolver(acidns.WithExchanger(ex))
	case o.useSys:
		return acidns.NewResolver(acidns.WithSystemResolvers())
	default:
		var ex acidns.Exchanger
		addr, err := serverAddr(o, 53)
		if err != nil {
			return nil, err
		}
		ex, err = acidns.NewUDPExchanger(addr)
		if err != nil {
			return nil, err
		}
		return acidns.NewResolver(acidns.WithExchanger(ex))
	}
}

func serverAddr(o opts, defaultPort int) (netip.AddrPort, error) {
	host := o.server
	if host == "" {
		host = "1.1.1.1"
	}
	port := defaultPort
	if o.port != 0 {
		port = o.port
	}
	if ap, err := netip.ParseAddrPort(host); err == nil {
		return ap, nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("server must be an IP address: %s", host)
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

func render(w *os.File, name wire.Name, rt rrtype.Type, ans *acidns.Answer, elapsed time.Duration, o opts) {
	if o.short {
		for _, rec := range ans.Records() {
			_, _ = fmt.Fprintln(w, formatRData(rec.RData()))
		}
		return
	}
	_, _ = fmt.Fprintf(w, ";; QUESTION SECTION:\n;%s\t\tIN\t%s\n\n", name, rt)
	if rcode := ans.RCODE(); rcode != wire.RCODENoError {
		_, _ = fmt.Fprintf(w, ";; ->>HEADER<<- rcode: %s\n", rcode)
	}

	if records := ans.Raw().Answers(); len(records) > 0 {
		_, _ = fmt.Fprintln(w, ";; ANSWER SECTION:")
		for _, rec := range records {
			_, _ = fmt.Fprintln(w, formatRecord(rec))
		}
		_, _ = fmt.Fprintln(w)
	}
	if records := ans.Raw().Authorities(); len(records) > 0 {
		_, _ = fmt.Fprintln(w, ";; AUTHORITY SECTION:")
		for _, rec := range records {
			_, _ = fmt.Fprintln(w, formatRecord(rec))
		}
		_, _ = fmt.Fprintln(w)
	}
	if records := ans.Raw().Additionals(); len(records) > 0 {
		_, _ = fmt.Fprintln(w, ";; ADDITIONAL SECTION:")
		for _, rec := range records {
			_, _ = fmt.Fprintln(w, formatRecord(rec))
		}
		_, _ = fmt.Fprintln(w)
	}
	_, _ = fmt.Fprintf(w, ";; Query time: %s\n", elapsed.Round(time.Microsecond))
	flags := []string{}
	if ans.Authoritative() {
		flags = append(flags, "AA")
	}
	if ans.Truncated() {
		flags = append(flags, "TC")
	}
	if len(flags) > 0 {
		_, _ = fmt.Fprintf(w, ";; Flags: %s\n", strings.Join(flags, " "))
	}
}

func formatRecord(rec wire.Record) string {
	return fmt.Sprintf("%s\t%d\t%s\t%s\t%s",
		rec.Name(), int(rec.TTL().Seconds()), rec.Class(), rec.Type(), formatRData(rec.RData()))
}

func formatRData(rd rdata.RData) string {
	switch v := rd.(type) {
	case rdata.A:
		return v.Addr().String()
	case rdata.AAAA:
		return v.Addr().String()
	case rdata.CNAME:
		return v.Target().String()
	case rdata.NS:
		return v.Target().String()
	case rdata.PTR:
		return v.Target().String()
	case rdata.MX:
		return fmt.Sprintf("%d %s", v.Preference(), v.Exchange())
	case rdata.TXT:
		var parts []string
		for _, s := range v.Strings() {
			parts = append(parts, fmt.Sprintf("%q", s))
		}
		return strings.Join(parts, " ")
	case rdata.SOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d",
			v.MName(), v.RName(), v.Serial(),
			int(v.Refresh().Seconds()), int(v.Retry().Seconds()),
			int(v.Expire().Seconds()), int(v.Minimum().Seconds()))
	case rdata.SVCB:
		return formatSvcbBody(v.Priority(), v.Target().String(), v.Params())
	case rdata.HTTPS:
		return formatSvcbBody(v.Priority(), v.Target().String(), v.Params())
	case rdata.CAA:
		return fmt.Sprintf("%d %s %q", v.Flags(), v.Tag(), v.Value())
	case rdata.Unknown:
		return fmt.Sprintf("\\# %d (opaque)", len(v.Bytes()))
	default:
		return fmt.Sprintf("(%s)", rd.Type())
	}
}

func formatSvcbBody(priority uint16, target string, params []rdata.SVCBParam) string {
	var out strings.Builder
	fmt.Fprintf(&out, "%d %s", priority, target)
	for _, p := range params {
		fmt.Fprintf(&out, " key%d=%x", p.Key(), p.Value())
	}
	return out.String()
}
