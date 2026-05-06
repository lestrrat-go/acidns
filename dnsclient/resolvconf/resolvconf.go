// Package resolvconf parses /etc/resolv.conf-style configuration into a
// strongly-typed Config that the higher-level Resolver can consume.
//
// The grammar implemented is the common Linux/BSD subset documented in
// resolv.conf(5): nameserver, search, domain, options ndots:N, options
// timeout:N, options attempts:N. Unknown options and directives are
// preserved (Verbatim) so a caller may surface them or pass them through.
package resolvconf

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat-go/acidns/dnsname"
)

// DefaultPath is the conventional location of resolv.conf on Unix.
const DefaultPath = "/etc/resolv.conf"

// Config is a parsed resolv.conf snapshot.
type Config struct {
	Nameservers []netip.AddrPort
	Search      []dnsname.Name
	Ndots       int
	Timeout     time.Duration
	Attempts    int
	Verbatim    []string
}

// Default values used when a field is absent or zero.
const (
	defaultNdots    = 1
	defaultTimeout  = 5 * time.Second
	defaultAttempts = 2
)

// ErrNoNameserver indicates a parsed file produced no usable nameserver.
var ErrNoNameserver = errors.New("resolvconf: no nameserver entries")

// Parse reads a Config from r.
func Parse(r io.Reader) (*Config, error) {
	cfg := &Config{Ndots: defaultNdots, Timeout: defaultTimeout, Attempts: defaultAttempts}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		switch fields[0] {
		case "nameserver":
			if len(fields) < 2 {
				continue
			}
			ap, err := parseServer(fields[1])
			if err != nil {
				continue
			}
			cfg.Nameservers = append(cfg.Nameservers, ap)
		case "search":
			cfg.Search = cfg.Search[:0]
			for _, s := range fields[1:] {
				n, err := dnsname.Parse(s)
				if err != nil {
					continue
				}
				cfg.Search = append(cfg.Search, n)
			}
		case "domain":
			if len(fields) >= 2 {
				if n, err := dnsname.Parse(fields[1]); err == nil {
					cfg.Search = []dnsname.Name{n}
				}
			}
		case "options":
			for _, opt := range fields[1:] {
				k, v, ok := strings.Cut(opt, ":")
				switch {
				case k == "ndots" && ok:
					if n, err := strconv.Atoi(v); err == nil {
						cfg.Ndots = n
					}
				case k == "timeout" && ok:
					if n, err := strconv.Atoi(v); err == nil {
						cfg.Timeout = time.Duration(n) * time.Second
					}
				case k == "attempts" && ok:
					if n, err := strconv.Atoi(v); err == nil {
						cfg.Attempts = n
					}
				default:
					cfg.Verbatim = append(cfg.Verbatim, "options "+opt)
				}
			}
		default:
			cfg.Verbatim = append(cfg.Verbatim, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("resolvconf: read: %w", err)
	}
	return cfg, nil
}

// Load reads and parses the resolv.conf at the given path. If path is empty,
// DefaultPath is used.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("resolvconf: open %s: %w", path, err)
	}
	defer f.Close()
	return Parse(f)
}

func parseServer(s string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(addr, 53), nil
}
