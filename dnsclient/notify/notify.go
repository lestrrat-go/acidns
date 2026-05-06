// Package notify implements the client side of RFC 1996 DNS NOTIFY.
//
// A primary nameserver sends NOTIFY messages to its secondaries when a
// zone changes; the secondaries respond with a simple ACK and may then
// fetch the new zone via AXFR or IXFR. This package provides Send for
// the primary, and a SOA-bearing variant SendWithSOA that includes the
// new SOA in the answer section as RFC 1996 §3.7 permits.
package notify

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/transport"
	"github.com/lestrrat-go/acidns/dnsclient/transport/udp"
	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
)

// Option configures a Send call.
type Option interface{ applyNotify(*config) }

type optionFunc func(*config)

func (f optionFunc) applyNotify(c *config) { f(c) }

type config struct {
	timeout time.Duration
	soa     rdata.SOA
}

// WithTimeout sets the per-secondary timeout when ctx has no deadline.
func WithTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) { c.timeout = d })
}

// WithSOA includes the new SOA in the answer section (RFC 1996 §3.7).
// Some secondaries skip the follow-up SOA query when the new SOA is
// piggy-backed on the NOTIFY.
func WithSOA(soa rdata.SOA) Option {
	return optionFunc(func(c *config) { c.soa = soa })
}

// Send sends a NOTIFY for zone to one secondary and waits for the ACK.
func Send(ctx context.Context, secondary netip.AddrPort, zone dnsname.Name, opts ...Option) (dnsmsg.Message, error) {
	c := config{timeout: 5 * time.Second}
	for _, o := range opts {
		o.applyNotify(&c)
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	b := dnsmsg.NewBuilder().
		ID(id).
		Opcode(dnsmsg.OpcodeNotify).
		Authoritative(true).
		Question(dnsmsg.NewQuestion(zone, rrtype.SOA))
	if c.soa != nil {
		b = b.Answer(dnsmsg.NewRecord(zone, time.Duration(c.soa.Minimum()), c.soa))
	}
	q, err := b.Build()
	if err != nil {
		return nil, err
	}

	if _, ok := ctx.Deadline(); !ok && c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	ex, err := udp.New(secondary)
	if err != nil {
		return nil, err
	}
	return ex.Exchange(ctx, q)
}

// Broadcast sends NOTIFY in parallel to many secondaries and returns a
// per-secondary result map. Errors do not abort the broadcast.
func Broadcast(ctx context.Context, secondaries []netip.AddrPort, zone dnsname.Name, opts ...Option) map[netip.AddrPort]error {
	results := make(map[netip.AddrPort]error, len(secondaries))
	type r struct {
		addr netip.AddrPort
		err  error
	}
	ch := make(chan r, len(secondaries))
	for _, s := range secondaries {
		go func(addr netip.AddrPort) {
			_, err := Send(ctx, addr, zone, opts...)
			ch <- r{addr: addr, err: err}
		}(s)
	}
	for range secondaries {
		got := <-ch
		results[got.addr] = got.err
	}
	return results
}

// Suppress unused-import warning when building without callers using the
// transport package directly.
var _ transport.Exchanger

func randomID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("notify: random id: %w", err)
	}
	return binary.BigEndian.Uint16(b[:]), nil
}
