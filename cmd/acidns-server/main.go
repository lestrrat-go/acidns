// Command acidns-server runs the acidns DNS server as authoritative
// (loading zones from master files), recursive (walking from the roots),
// hybrid (zones for delegated names; recursion for everything else), or
// forward (caching forwarder that relays to a single upstream over UDP
// or DoT).
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

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/forward"
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

	upstream    string
	upstreamTLS string
	tlsName     string
	cacheSize   int
}

func run(argv []string) error {
	var o opts
	var zonesFlag, rootsFlag string
	fs := flag.NewFlagSet("acidns-server", flag.ContinueOnError)
	fs.StringVar(&o.mode, "mode", "authoritative",
		"authoritative | recursive | hybrid | forward")
	fs.StringVar(&o.listen, "listen", "127.0.0.1:5353",
		"address:port to bind UDP and TCP listeners on")
	fs.StringVar(&zonesFlag, "zones", "",
		"comma-separated list of master files to load (authoritative/hybrid mode)")
	fs.StringVar(&rootsFlag, "roots", "",
		"comma-separated list of root server addr:port (recursive/hybrid mode)")
	fs.StringVar(&o.upstream, "upstream", "",
		"forward mode: upstream addr:port over UDP-with-TCP-fallback (e.g. 8.8.8.8:53)")
	fs.StringVar(&o.upstreamTLS, "upstream-tls", "",
		"forward mode: upstream addr:port over DoT (e.g. 8.8.8.8:853)")
	fs.StringVar(&o.tlsName, "tls-name", "",
		"forward mode: SNI / cert-verify name for -upstream-tls (e.g. dns.google)")
	fs.IntVar(&o.cacheSize, "cache-size", 4096,
		"forward mode: number of cached answers retained (0 disables caching)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: acidns-server [options]\n\noptions:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if err := validateFlagsForMode(fs, o.mode); err != nil {
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

	udpSrv, err := acidns.NewUDPServer(addr, handler)
	if err != nil {
		return err
	}
	tcpSrv, err := acidns.NewTCPServer(addr, handler)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	udpCtrl, err := udpSrv.Run(ctx)
	if err != nil {
		return err
	}
	tcpCtrl, err := tcpSrv.Run(ctx)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(os.Stdout, "acidns-server: %s mode listening on %s (UDP %s, TCP %s)\n",
		o.mode, addr, udpCtrl.Addr(), tcpCtrl.Addr())

	<-ctx.Done()
	if err := udpCtrl.Wait(); err != nil {
		return fmt.Errorf("udp server: %w", err)
	}
	if err := tcpCtrl.Wait(); err != nil {
		return fmt.Errorf("tcp server: %w", err)
	}
	return nil
}

func buildHandler(o opts) (acidns.Handler, error) {
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
	case "forward":
		return buildForward(o)
	default:
		return nil, fmt.Errorf("unknown mode %q", o.mode)
	}
}

func buildForward(o opts) (acidns.Handler, error) {
	if o.upstream == "" && o.upstreamTLS == "" {
		return nil, fmt.Errorf("forward mode requires -upstream or -upstream-tls")
	}
	if o.upstream != "" && o.upstreamTLS != "" {
		return nil, fmt.Errorf("forward mode: pass at most one of -upstream / -upstream-tls")
	}
	opts := []forward.Option{forward.WithCacheSize(o.cacheSize)}
	switch {
	case o.upstreamTLS != "":
		ap, err := netip.ParseAddrPort(o.upstreamTLS)
		if err != nil {
			return nil, fmt.Errorf("parse upstream-tls %q: %w", o.upstreamTLS, err)
		}
		opts = append(opts, forward.WithDoTUpstream(ap, o.tlsName))
	default:
		ap, err := netip.ParseAddrPort(o.upstream)
		if err != nil {
			return nil, fmt.Errorf("parse upstream %q: %w", o.upstream, err)
		}
		opts = append(opts, forward.WithUDPUpstream(ap))
	}
	return forward.NewForwarder(opts...)
}

func buildAuthoritative(files []string) (acidns.Handler, error) {
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
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		opts = append(opts, authoritative.WithZone(z))
	}
	return authoritative.New(opts...)
}

func buildRecursive(roots []string) (acidns.Handler, error) {
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
	return recursive.New(recursive.WithRoots(addrs...))
}

// hybrid serves authoritative answers for owned zones and falls through to
// the recursive resolver for everything else.
type hybrid struct {
	auth, rec acidns.Handler
}

func (h hybrid) ServeDNS(ctx context.Context, w acidns.ResponseWriter, q wire.Message) {
	rec := &peekingWriter{ResponseWriter: w}
	h.auth.ServeDNS(ctx, rec, q)
	if !rec.hasCaptured {
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
	acidns.ResponseWriter

	captured    wire.Message
	hasCaptured bool
}

func (p *peekingWriter) WriteMsg(m wire.Message) error {
	p.captured = m
	p.hasCaptured = true
	return nil
}

// modeFlags lists, per server mode, the flag names that are meaningful
// in that mode beyond the universal -mode and -listen. Any flag the user
// explicitly set that does not appear in the active mode's set is
// rejected at parse time so misconfigurations fail loudly at startup
// instead of silently degrading at query time (e.g. -tls-name set with
// -upstream rather than -upstream-tls).
var modeFlags = map[string]map[string]struct{}{
	"authoritative": {"zones": {}},
	"recursive":     {"roots": {}},
	"hybrid":        {"zones": {}, "roots": {}},
	"forward":       {"upstream": {}, "upstream-tls": {}, "tls-name": {}, "cache-size": {}},
}

// universalFlags are valid in every mode.
var universalFlags = map[string]struct{}{
	"mode":   {},
	"listen": {},
}

func validateFlagsForMode(fs *flag.FlagSet, mode string) error {
	allowed, ok := modeFlags[mode]
	if !ok {
		// Unknown mode is reported by buildHandler with a clearer message;
		// don't double up the error here.
		return nil
	}
	var stray []string
	fs.Visit(func(f *flag.Flag) {
		if _, ok := universalFlags[f.Name]; ok {
			return
		}
		if _, ok := allowed[f.Name]; ok {
			return
		}
		stray = append(stray, "-"+f.Name)
	})
	if len(stray) > 0 {
		return fmt.Errorf("flags %s are not valid in -mode=%s",
			strings.Join(stray, ", "), mode)
	}
	if mode == "forward" {
		// -tls-name only makes sense paired with -upstream-tls; it would
		// otherwise be silently dropped on the plaintext path.
		var tlsNameSet, upstreamTLSSet bool
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "tls-name":
				tlsNameSet = true
			case "upstream-tls":
				upstreamTLSSet = true
			}
		})
		if tlsNameSet && !upstreamTLSSet {
			return fmt.Errorf("-tls-name requires -upstream-tls")
		}
	}
	return nil
}

func splitCSV(s string) []string {
	out := strings.Split(s, ",")
	for i := range out {
		out[i] = strings.TrimSpace(out[i])
	}
	return out
}
