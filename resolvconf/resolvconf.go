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

	"github.com/lestrrat-go/acidns/wire"
)

// DefaultPath is the conventional location of resolv.conf on Unix.
const DefaultPath = "/etc/resolv.conf"

// Config is a parsed resolv.conf snapshot.
type Config struct {
	nameservers []netip.AddrPort
	search      []wire.Name
	ndots       int
	timeout     time.Duration
	attempts    int
	verbatim    []string
}

// Nameservers returns the parsed nameserver entries in source order. The
// returned slice is a copy; callers may mutate it without affecting the
// Config.
func (c *Config) Nameservers() []netip.AddrPort { return c.nameservers }

// Search returns the parsed search-list entries. The returned slice is a
// copy; callers may mutate it without affecting the Config.
func (c *Config) Search() []wire.Name { return c.search }

// Ndots returns the ndots option value.
func (c *Config) Ndots() int { return c.ndots }

// Timeout returns the per-attempt timeout option value.
func (c *Config) Timeout() time.Duration { return c.timeout }

// Attempts returns the attempts option value.
func (c *Config) Attempts() int { return c.attempts }

// Verbatim returns directives and options the parser did not consume,
// preserved verbatim so callers may surface them or pass them through. The
// returned slice is a copy; callers may mutate it without affecting the
// Config.
func (c *Config) Verbatim() []string { return c.verbatim }

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
	cfg := &Config{ndots: defaultNdots, timeout: defaultTimeout, attempts: defaultAttempts}
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
			cfg.nameservers = append(cfg.nameservers, ap)
		case "search":
			cfg.search = cfg.search[:0]
			for _, s := range fields[1:] {
				n, err := wire.ParseName(s)
				if err != nil {
					continue
				}
				cfg.search = append(cfg.search, n)
			}
		case "domain":
			if len(fields) >= 2 {
				if n, err := wire.ParseName(fields[1]); err == nil {
					cfg.search = []wire.Name{n}
				}
			}
		case "options":
			for _, opt := range fields[1:] {
				k, v, ok := strings.Cut(opt, ":")
				switch {
				case k == "ndots" && ok:
					if n, err := strconv.Atoi(v); err == nil {
						cfg.ndots = n
					}
				case k == "timeout" && ok:
					if n, err := strconv.Atoi(v); err == nil {
						cfg.timeout = time.Duration(n) * time.Second
					}
				case k == "attempts" && ok:
					if n, err := strconv.Atoi(v); err == nil {
						cfg.attempts = n
					}
				default:
					cfg.verbatim = append(cfg.verbatim, "options "+opt)
				}
			}
		default:
			cfg.verbatim = append(cfg.verbatim, line)
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
	defer func() { _ = f.Close() }()
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

// ConfigBuilder constructs a Config programmatically. Build() always
// returns a nil error; the signature is reserved so future validation
// can be added without breaking callers.
type ConfigBuilder struct {
	cfg Config
}

// NewConfigBuilder returns a ConfigBuilder seeded with the package
// defaults for ndots/timeout/attempts so the produced Config matches
// what Parse would yield from an empty file.
func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{cfg: Config{
		ndots:    defaultNdots,
		timeout:  defaultTimeout,
		attempts: defaultAttempts,
	}}
}

// Nameservers replaces the nameserver list. The slice is aliased,
// not copied — callers who plan to mutate ns afterwards must
// [slices.Clone] before passing.
func (b *ConfigBuilder) Nameservers(ns ...netip.AddrPort) *ConfigBuilder {
	b.cfg.nameservers = ns
	return b
}

// Search replaces the search list. The slice is aliased — see
// [ConfigBuilder.Nameservers] for the alias-vs-clone contract.
func (b *ConfigBuilder) Search(s ...wire.Name) *ConfigBuilder {
	b.cfg.search = s
	return b
}

// Ndots sets the ndots option.
func (b *ConfigBuilder) Ndots(n int) *ConfigBuilder {
	b.cfg.ndots = n
	return b
}

// Timeout sets the per-attempt timeout.
func (b *ConfigBuilder) Timeout(d time.Duration) *ConfigBuilder {
	b.cfg.timeout = d
	return b
}

// Attempts sets the attempts option.
func (b *ConfigBuilder) Attempts(n int) *ConfigBuilder {
	b.cfg.attempts = n
	return b
}

// Verbatim replaces the verbatim list of unrecognised directives.
// The slice is aliased — see [ConfigBuilder.Nameservers].
func (b *ConfigBuilder) Verbatim(v ...string) *ConfigBuilder {
	b.cfg.verbatim = v
	return b
}

// Build returns the assembled Config and resets b to the zero state
// — single-shot semantics. The Config's slice fields ALIAS the
// slices passed to the builder's setters. The error return is
// reserved for future validation; today it is always nil.
func (b *ConfigBuilder) Build() (*Config, error) {
	out := b.cfg
	*b = ConfigBuilder{cfg: Config{
		ndots:    defaultNdots,
		timeout:  defaultTimeout,
		attempts: defaultAttempts,
	}}
	return &out, nil
}
