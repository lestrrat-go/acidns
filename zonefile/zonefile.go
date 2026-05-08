// Package zonefile parses RFC 1035 §5 master files into a strongly-typed
// Zone composed of wire.Records. It supports the common subset used by
// production zone files: $ORIGIN, $TTL, parenthesised line continuation,
// `;` end-of-line comments, quoted strings, the `@` and blank owner-name
// shortcuts, and presentation-format RDATA for A, AAAA, NS, CNAME, PTR,
// MX, TXT, and SOA.
//
// $INCLUDE, escapes inside the SOA rname's @-encoded local part, and the
// generic RFC 3597 \# form are intentionally out of scope for this first
// version; they can be added without changing the surface API.
package zonefile

import (
	"errors"
	"fmt"
	"io"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
)

// ErrParse is returned when a master file fails to parse.
var ErrParse = errors.New("dnszone: parse error")

// Zone is a parsed master file.
type Zone interface {
	Origin() wire.Name
	Records() []wire.Record
	// SOA returns the first SOA record observed and its rdata, if any.
	SOA() (rdata.SOA, wire.Record, bool)
}

type zone struct {
	origin  wire.Name
	records []wire.Record
}

func (z *zone) Origin() wire.Name      { return z.origin }
func (z *zone) Records() []wire.Record { return z.records }
func (z *zone) SOA() (rdata.SOA, wire.Record, bool) {
	for _, r := range z.records {
		if soa, ok := wire.RDataAs[rdata.SOA](r); ok {
			return soa, r, true
		}
	}
	return rdata.SOA{}, nil, false
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
