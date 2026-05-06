// Package amt implements the DNS-based discovery procedure for Automatic
// Multicast Tunneling (AMT) relays per RFC 8777. Discovery is a simple SRV
// lookup at `_amt._udp.<domain>`; the helpers here construct the canonical
// query name and rank the results per RFC 2782 priority/weight.
package amt

import (
	"context"
	"sort"

	"github.com/lestrrat-go/acidns/dnsclient"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
)

// DiscoveryName returns the SRV name a client queries to find AMT relays
// for the supplied domain (RFC 8777 §3).
func DiscoveryName(domain dnsname.Name) (dnsname.Name, error) {
	return dnsname.Parse("_amt._udp." + domain.String())
}

// Relay is a single AMT relay candidate.
type Relay struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   dnsname.Name
}

// Discover queries `_amt._udp.<domain>` for SRV records and returns the
// candidate relays sorted by RFC 2782 priority (ascending; weight ties
// preserve server-supplied order).
func Discover(ctx context.Context, r dnsclient.Resolver, domain dnsname.Name) ([]Relay, error) {
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
		out = append(out, Relay{
			Priority: s.Priority(),
			Weight:   s.Weight(),
			Port:     s.Port(),
			Target:   s.Target(),
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out, nil
}
