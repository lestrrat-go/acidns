// Package amt implements the DNS-based discovery procedure for
// Automatic Multicast Tunneling (AMT) relays per RFC 8777. AMT lets a
// host that has unicast Internet connectivity but no native multicast
// (e.g. behind a NAT or a non-multicast-aware ISP) tunnel into a
// multicast-enabled network through a relay; the relay is found by
// running a DNS SRV lookup.
//
// # Usage
//
// Pass a Resolver and the source-address domain to Discover; it issues
// the SRV lookup at `_amt._udp.<domain>`, ranks the answers per RFC
// 2782 priority/weight, and returns the relay candidates. Higher-level
// callers iterate the result list, attempting each relay in order
// until one accepts the AMT request.
//
// Production callers also typically want the typed AMTRELAY rdata
// payload (rdata.AMTRELAY) advertised by the discovered relays
// themselves; that record is parsed by the wire/rdata package.
package amt

import (
	"context"
	"sort"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// DiscoveryName returns the SRV name a client queries to find AMT relays
// for the supplied domain (RFC 8777 §3).
func DiscoveryName(domain wire.Name) (wire.Name, error) {
	return wire.ParseName("_amt._udp." + domain.String())
}

// Relay is a single AMT relay candidate.
type Relay struct {
	priority uint16
	weight   uint16
	port     uint16
	target   wire.Name
}

// NewRelay constructs a Relay candidate with the given SRV-style fields.
func NewRelay(priority, weight, port uint16, target wire.Name) Relay {
	return Relay{priority: priority, weight: weight, port: port, target: target}
}

// Priority returns the relay's RFC 2782 priority.
func (r Relay) Priority() uint16 { return r.priority }

// Weight returns the relay's RFC 2782 weight.
func (r Relay) Weight() uint16 { return r.weight }

// Port returns the relay's UDP port.
func (r Relay) Port() uint16 { return r.port }

// Target returns the relay's target host name.
func (r Relay) Target() wire.Name { return r.target }

// Discover queries `_amt._udp.<domain>` for SRV records and returns the
// candidate relays sorted by RFC 2782 priority (ascending; weight ties
// preserve server-supplied order).
func Discover(ctx context.Context, r acidns.Resolver, domain wire.Name) ([]Relay, error) {
	name, err := DiscoveryName(domain)
	if err != nil {
		return nil, err
	}
	ans, err := r.Resolve(ctx, name, rrtype.SRV)
	if err != nil {
		return nil, err
	}
	var out []Relay
	for _, rec := range ans.Records() {
		if rec.Type() != rrtype.SRV {
			continue
		}
		s, ok := rec.RData().(rdata.SRV)
		if !ok {
			continue
		}
		out = append(out, NewRelay(s.Priority(), s.Weight(), s.Port(), s.Target()))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].priority < out[j].priority })
	return out, nil
}
