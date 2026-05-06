// Package dnszone parses RFC 1035 §5 master files into a strongly-typed
// Zone composed of dnsmsg.Records. It supports the common subset used by
// production zone files: $ORIGIN, $TTL, parenthesised line continuation,
// `;` end-of-line comments, quoted strings, the `@` and blank owner-name
// shortcuts, and presentation-format RDATA for A, AAAA, NS, CNAME, PTR,
// MX, TXT, and SOA.
//
// $INCLUDE, escapes inside the SOA rname's @-encoded local part, and the
// generic RFC 3597 \# form are intentionally out of scope for this first
// version; they can be added without changing the surface API.
package dnszone

import (
	"errors"
	"fmt"
	"io"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
)

// ErrParse is returned when a master file fails to parse.
var ErrParse = errors.New("dnszone: parse error")

// Zone is a parsed master file.
type Zone interface {
	Origin() dnsname.Name
	Records() []dnsmsg.Record
	// SOA returns the first SOA record observed and its rdata, if any.
	SOA() (rdata.SOA, dnsmsg.Record, bool)
}

type zone struct {
	origin  dnsname.Name
	records []dnsmsg.Record
}

func (z *zone) Origin() dnsname.Name     { return z.origin }
func (z *zone) Records() []dnsmsg.Record { return z.records }
func (z *zone) SOA() (rdata.SOA, dnsmsg.Record, bool) {
	for _, r := range z.records {
		if r.Type() == rrtype.SOA {
			return r.RData().(rdata.SOA), r, true
		}
	}
	return nil, nil, false
}

// Option configures a parse.
type Option interface{ applyZone(*config) }

type optionFunc func(*config)

func (f optionFunc) applyZone(c *config) { f(c) }

type config struct {
	origin     dnsname.Name
	defaultTTL int64 // seconds, -1 = unset
}

// WithOrigin sets the initial origin used until $ORIGIN appears.
func WithOrigin(n dnsname.Name) Option {
	return optionFunc(func(c *config) { c.origin = n })
}

// WithDefaultTTL sets the initial TTL used until $TTL appears.
func WithDefaultTTL(seconds int) Option {
	return optionFunc(func(c *config) { c.defaultTTL = int64(seconds) })
}

// Parse parses a master file from r.
func Parse(r io.Reader, opts ...Option) (Zone, error) {
	c := config{defaultTTL: -1}
	for _, o := range opts {
		o.applyZone(&c)
	}
	p := newParser(r, c)
	if err := p.run(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParse, err)
	}
	return &zone{origin: p.origin, records: p.records}, nil
}
