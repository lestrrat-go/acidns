// Command acidns-server runs the acidns DNS server as either authoritative
// (loading zones from master files), recursive (walking from the roots),
// or both modes layered (zones for delegated names; recursion for
// everything else).
package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/lestrrat-go/acidns/recursive"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/zonefile"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type opts struct {
	mode      string
	listen    string
	zoneFiles []string
	roots     []string
}

func run(argv []string) error {
	var o opts
	var zonesFlag, rootsFlag string
	fs := flag.NewFlagSet("acidns-server", flag.ContinueOnError)
	fs.StringVar(&o.mode, "mode", "authoritative",
		"authoritative | recursive | hybrid")
	fs.StringVar(&o.listen, "listen", "127.0.0.1:5353",
		"address:port to bind UDP and TCP listeners on")
	fs.StringVar(&zonesFlag, "zones", "",
		"comma-separated list of master files to load (authoritative/hybrid mode)")
	fs.StringVar(&rootsFlag, "roots", "",
		"comma-separated list of root server addr:port (recursive/hybrid mode)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: acidns-server [options]\n\noptions:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if zonesFlag != "" {
		o.zoneFiles = splitCSV(zonesFlag)
	}
	if rootsFlag != "" {
		o.roots = splitCSV(rootsFlag)
	}

	addr, err := netip.ParseAddrPort(o.listen)
	if err != nil {
		return fmt.Errorf("parse listen address: %w", err)
	}

	handler, err := buildHandler(o)
	if err != nil {
		return err
	}

	udpSrv, err := dnsserver.ListenUDP(addr, handler)
	if err != nil {
		return err
	}
	tcpSrv, err := dnsserver.ListenTCP(addr, handler)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Fprintf(os.Stdout, "acidns-server: %s mode listening on %s (UDP %s, TCP %s)\n",
		o.mode, addr, udpSrv.Addr(), tcpSrv.Addr())

	errCh := make(chan error, 2)
	go func() { errCh <- udpSrv.Serve(ctx) }()
	go func() { errCh <- tcpSrv.Serve(ctx) }()

	<-ctx.Done()
	cancel()
	for i := 0; i < 2; i++ {
		<-errCh
	}
	return nil
}

func buildHandler(o opts) (dnsserver.Handler, error) {
	switch o.mode {
	case "authoritative":
		return buildAuthoritative(o.zoneFiles)
	case "recursive":
		return buildRecursive(o.roots)
	case "hybrid":
		auth, err := buildAuthoritative(o.zoneFiles)
		if err != nil {
			return nil, err
		}
		rec, err := buildRecursive(o.roots)
		if err != nil {
			return nil, err
		}
		return hybrid{auth: auth, rec: rec}, nil
	default:
		return nil, fmt.Errorf("unknown mode %q", o.mode)
	}
}

func buildAuthoritative(files []string) (dnsserver.Handler, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("authoritative mode requires -zones")
	}
	var opts []authoritative.Option
	for _, p := range files {
		f, err := os.Open(p)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", p, err)
		}
		z, err := zonefile.Parse(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		opts = append(opts, authoritative.WithZone(z))
	}
	return authoritative.New(opts...)
}

func buildRecursive(roots []string) (dnsserver.Handler, error) {
	var addrs []netip.AddrPort
	for _, r := range roots {
		ap, err := netip.ParseAddrPort(r)
		if err != nil {
			return nil, fmt.Errorf("parse root %q: %w", r, err)
		}
		addrs = append(addrs, ap)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("recursive mode requires -roots")
	}
	return recursive.New(recursive.WithRoots(addrs...)), nil
}

// hybrid serves authoritative answers for owned zones and falls through to
// the recursive resolver for everything else.
type hybrid struct {
	auth, rec dnsserver.Handler
}

func (h hybrid) ServeDNS(ctx context.Context, w dnsserver.ResponseWriter, q wire.Message) {
	rec := &peekingWriter{ResponseWriter: w}
	h.auth.ServeDNS(ctx, rec, q)
	if rec.captured == nil {
		return
	}
	// If the authoritative side returned REFUSED (out of zone), try
	// the recursive resolver.
	if rec.captured.Flags().RCODE() == wire.RCODERefused {
		h.rec.ServeDNS(ctx, w, q)
		return
	}
	_ = w.WriteMsg(rec.captured)
}

type peekingWriter struct {
	dnsserver.ResponseWriter
	captured wire.Message
}

func (p *peekingWriter) WriteMsg(m wire.Message) error {
	p.captured = m
	return nil
}

func splitCSV(s string) []string {
	out := strings.Split(s, ",")
	for i := range out {
		out[i] = strings.TrimSpace(out[i])
	}
	return out
}
