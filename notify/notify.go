// Package notify implements the client side of RFC 1996 DNS NOTIFY.
//
// A primary nameserver sends NOTIFY messages to its secondaries when a
// zone changes; the secondaries respond with a simple ACK and may then
// fetch the new zone via AXFR or IXFR.
//
// The caller chooses the transport — typically UDP, but TCP / DoT / DoQ
// are equally valid since NOTIFY is a single-message exchange that fits
// the acidns.Exchanger contract.
package notify

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/tsig"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/option/v3"
)

// ErrTSIGVerify is returned when the response's TSIG signature fails
// to verify against the key supplied via [WithTSIGKey]. Aliased to
// [tsig.ErrVerify] so callers can match either form via errors.Is.
var ErrTSIGVerify = tsig.ErrVerify

// Send transmits a NOTIFY for zone over ex and waits for the ACK.
func Send(ctx context.Context, ex acidns.Exchanger, zone wire.Name, opts ...Option) (wire.Message, error) {
	c := config{timeout: 5 * time.Second, tsigFudge: 5 * time.Minute, tsigNow: time.Now}
	for _, o := range opts {
		switch o.Ident() {
		case identTimeout{}:
			c.timeout = option.MustGet[time.Duration](o)
		case identSOA{}:
			c.soa = option.MustGet[rdata.SOA](o)
			c.hasSOA = true
		case identTSIGKey{}:
			c.tsigKey = option.MustGet[*tsig.Key](o)
		case identTSIGFudge{}:
			c.tsigFudge = option.MustGet[time.Duration](o)
		case identTSIGClock{}:
			c.tsigNow = option.MustGet[func() time.Time](o)
		}
	}
	id, err := randomID()
	if err != nil {
		return wire.Message{}, err
	}
	b := wire.NewMessageBuilder().
		ID(id).
		Opcode(wire.OpcodeNotify).
		Authoritative(true).
		Question(wire.NewQuestion(zone, rrtype.SOA))
	if c.hasSOA {
		b = b.Answer(wire.NewRecord(zone, c.soa.Minimum(), c.soa))
	}
	q, err := b.Build()
	if err != nil {
		return wire.Message{}, err
	}

	if c.tsigKey != nil {
		signed, requestMAC, err := signMessage(q, *c.tsigKey, c.tsigNow(), c.tsigFudge)
		if err != nil {
			return wire.Message{}, fmt.Errorf("notify: TSIG sign: %w", err)
		}
		q, err = wire.Unmarshal(signed)
		if err != nil {
			return wire.Message{}, fmt.Errorf("notify: re-parse signed query: %w", err)
		}
		if _, ok := ctx.Deadline(); !ok && c.timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, c.timeout)
			defer cancel()
		}
		resp, err := ex.Exchange(ctx, q)
		if err != nil {
			return wire.Message{}, err
		}
		if err := verifyResponseIfTSIG(resp, *c.tsigKey, requestMAC, c.tsigNow(), c.tsigFudge); err != nil {
			return wire.Message{}, err
		}
		return resp, nil
	}

	if _, ok := ctx.Deadline(); !ok && c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	return ex.Exchange(ctx, q)
}

// signMessage marshals m, signs it with key, and returns the signed
// bytes plus the request MAC for response binding.
func signMessage(m wire.Message, key tsig.Key, now time.Time, fudge time.Duration) ([]byte, []byte, error) {
	signed, err := tsig.SignMessage(m, key, now, fudge)
	if err != nil {
		return nil, nil, err
	}
	_, mac, _, err := tsig.VerifyMAC(signed, key, now, fudge)
	if err != nil {
		return nil, nil, fmt.Errorf("extract MAC: %w", err)
	}
	return signed, mac, nil
}

// verifyResponseIfTSIG verifies the response's TSIG MAC against the
// request MAC. If the response carries no TSIG, this is a no-op (some
// secondaries — and most error paths — answer unsigned).
func verifyResponseIfTSIG(resp wire.Message, key tsig.Key, requestMAC []byte, now time.Time, fudge time.Duration) error {
	raw, err := wire.Marshal(resp)
	if err != nil {
		return fmt.Errorf("%w: marshal response: %w", ErrTSIGVerify, err)
	}
	if !hasTSIG(resp) {
		return nil
	}
	if _, _, _, err := tsig.VerifyResponse(raw, key, requestMAC, now, fudge); err != nil {
		return fmt.Errorf("%w: %w", ErrTSIGVerify, err)
	}
	return nil
}

// hasTSIG reports whether m carries a TSIG RR (type 250) in its
// additional section. The wire encoder treats TSIG as an unknown
// RR type since this package never registered a typed rdata for it.
func hasTSIG(m wire.Message) bool {
	for _, r := range m.Additionals() {
		if uint16(r.Type()) == 250 {
			return true
		}
	}
	return false
}

// Result captures one secondary's response from Broadcast.
type Result interface {
	Exchanger() acidns.Exchanger
	Response() wire.Message
	Err() error
}

type result struct {
	ex   acidns.Exchanger
	resp wire.Message
	err  error
}

func (r result) Exchanger() acidns.Exchanger { return r.ex }
func (r result) Response() wire.Message      { return r.resp }
func (r result) Err() error                  { return r.err }

// Broadcast sends NOTIFY in parallel to many secondaries and returns one
// Result per exchanger, in the order supplied. Errors on individual
// secondaries do not abort the broadcast.
func Broadcast(ctx context.Context, exs []acidns.Exchanger, zone wire.Name, opts ...Option) []Result {
	out := make([]Result, len(exs))
	type slot struct {
		idx  int
		resp wire.Message
		err  error
	}
	ch := make(chan slot, len(exs))
	for i, ex := range exs {
		go func(i int, ex acidns.Exchanger) {
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
