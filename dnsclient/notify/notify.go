// Package notify implements the client side of RFC 1996 DNS NOTIFY.
//
// A primary nameserver sends NOTIFY messages to its secondaries when a
// zone changes; the secondaries respond with a simple ACK and may then
// fetch the new zone via AXFR or IXFR.
//
// The caller chooses the transport — typically UDP, but TCP / DoT / DoQ
// are equally valid since NOTIFY is a single-message exchange that fits
// the transport.Exchanger contract.
package notify

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/transport"
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
// Defaults to 5 seconds.
func WithTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) { c.timeout = d })
}

// WithSOA includes the new SOA in the answer section (RFC 1996 §3.7).
// Some secondaries skip the follow-up SOA query when the new SOA is
// piggy-backed on the NOTIFY.
func WithSOA(soa rdata.SOA) Option {
	return optionFunc(func(c *config) { c.soa = soa })
}

// Send transmits a NOTIFY for zone over ex and waits for the ACK.
func Send(ctx context.Context, ex transport.Exchanger, zone dnsname.Name, opts ...Option) (dnsmsg.Message, error) {
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
	return ex.Exchange(ctx, q)
}

// Result captures one secondary's response from Broadcast.
type Result interface {
	Exchanger() transport.Exchanger
	Response() dnsmsg.Message
	Err() error
}

type result struct {
	ex   transport.Exchanger
	resp dnsmsg.Message
	err  error
}

func (r result) Exchanger() transport.Exchanger { return r.ex }
func (r result) Response() dnsmsg.Message       { return r.resp }
func (r result) Err() error                     { return r.err }

// Broadcast sends NOTIFY in parallel to many secondaries and returns one
// Result per exchanger, in the order supplied. Errors on individual
// secondaries do not abort the broadcast.
func Broadcast(ctx context.Context, exs []transport.Exchanger, zone dnsname.Name, opts ...Option) []Result {
	out := make([]Result, len(exs))
	type slot struct {
		idx  int
		resp dnsmsg.Message
		err  error
	}
	ch := make(chan slot, len(exs))
	for i, ex := range exs {
		go func(i int, ex transport.Exchanger) {
			resp, err := Send(ctx, ex, zone, opts...)
			ch <- slot{idx: i, resp: resp, err: err}
		}(i, ex)
	}
	for range exs {
		s := <-ch
		out[s.idx] = result{ex: exs[s.idx], resp: s.resp, err: s.err}
	}
	return out
}

func randomID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("notify: random id: %w", err)
	}
	return binary.BigEndian.Uint16(b[:]), nil
}
