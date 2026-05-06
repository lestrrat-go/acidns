// Package ixfr implements the client side of RFC 1995 incremental zone
// transfer.
//
// An IXFR query carries the requester's current SOA in the authority
// section. The server responds with one of three shapes:
//
//   - "Up to date": single SOA whose serial equals the client's serial.
//   - "AXFR fallback": the entire zone, identical wire format to AXFR.
//   - "Incremental": [SOA_new, (SOA_old, removed..., SOA_new, added...)+, SOA_new]
//
// Transfer auto-detects which shape arrived and reports it via Result.Kind.
package ixfr

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
)

// Kind describes the shape of an IXFR response.
type Kind int

const (
	// KindUpToDate indicates the requester's serial matched the server's;
	// no records need applying.
	KindUpToDate Kind = iota
	// KindAXFRFallback indicates the server returned the full zone in
	// AXFR format. Records is the entire zone.
	KindAXFRFallback
	// KindIncremental indicates the server returned a diff. Removed and
	// Added carry the records to apply, in order.
	KindIncremental
)

// Diff is one (delete, add) sub-diff of an incremental response, taking
// the zone from one serial to the next.
type Diff struct {
	FromSerial uint32
	ToSerial   uint32
	Removed    []dnsmsg.Record
	Added      []dnsmsg.Record
}

// Result captures the parsed IXFR outcome.
type Result struct {
	Kind     Kind
	Records  []dnsmsg.Record // full zone in AXFR-fallback mode
	Diffs    []Diff          // incremental mode
	NewSOA   rdata.SOA       // the latest SOA from the server
}

// Option configures a transfer.
type Option interface{ applyIXFR(*config) }

type optionFunc func(*config)

func (f optionFunc) applyIXFR(c *config) { f(c) }

type config struct {
	timeout time.Duration
}

// WithTimeout sets the overall timeout when ctx has no deadline.
func WithTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) { c.timeout = d })
}

// Transfer performs an IXFR request against server.
//
// The clientSOA argument names the client's current view of the zone —
// only the Serial of clientSOA is consulted by the server, but the full
// SOA RR is what the wire requires.
func Transfer(ctx context.Context, server netip.AddrPort, zone dnsname.Name, clientSOA rdata.SOA, opts ...Option) (Result, error) {
	c := config{timeout: 30 * time.Second}
	for _, o := range opts {
		o.applyIXFR(&c)
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", server.String())
	if err != nil {
		return Result{}, fmt.Errorf("ixfr: dial %s: %w", server, err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else if c.timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(c.timeout))
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-stop:
		}
	}()

	id, err := randomID()
	if err != nil {
		return Result{}, err
	}
	authSOA := dnsmsg.NewRecord(zone, time.Second, clientSOA)
	q, err := dnsmsg.NewBuilder().
		ID(id).
		Question(dnsmsg.NewQuestion(zone, rrtype.IXFR)).
		Authority(authSOA).
		Build()
	if err != nil {
		return Result{}, err
	}
	wire, err := dnsmsg.Marshal(q)
	if err != nil {
		return Result{}, err
	}
	if err := writeMessage(conn, wire); err != nil {
		return Result{}, err
	}

	var all []dnsmsg.Record
	for {
		body, err := readMessage(conn)
		if err != nil {
			return Result{}, err
		}
		resp, err := dnsmsg.Unmarshal(body)
		if err != nil {
			return Result{}, fmt.Errorf("ixfr: parse: %w", err)
		}
		if resp.ID() != q.ID() {
			return Result{}, fmt.Errorf("ixfr: id mismatch")
		}
		if rcode := resp.Flags().RCODE(); rcode != dnsmsg.RCODENoError {
			return Result{}, fmt.Errorf("ixfr: %s", rcode)
		}
		all = append(all, resp.Answers()...)
		if isComplete(all) {
			break
		}
	}
	return parseStream(clientSOA.Serial(), all)
}

func isComplete(all []dnsmsg.Record) bool {
	if len(all) < 2 {
		return false
	}
	if all[0].Type() != rrtype.SOA || all[len(all)-1].Type() != rrtype.SOA {
		return false
	}
	// At least the leading + trailing SOA share the same serial → done.
	first := all[0].RData().(rdata.SOA).Serial()
	last := all[len(all)-1].RData().(rdata.SOA).Serial()
	return first == last && len(all) >= 2
}

func parseStream(clientSerial uint32, recs []dnsmsg.Record) (Result, error) {
	if len(recs) == 0 || recs[0].Type() != rrtype.SOA {
		return Result{}, errors.New("ixfr: stream must begin with SOA")
	}
	newSOA := recs[0].RData().(rdata.SOA)

	if len(recs) == 1 {
		return Result{Kind: KindUpToDate, NewSOA: newSOA}, nil
	}

	// "Up to date": single SOA whose serial == client's. RFC 1995 §2.
	if len(recs) == 2 && recs[1].Type() == rrtype.SOA &&
		recs[0].RData().(rdata.SOA).Serial() == recs[1].RData().(rdata.SOA).Serial() &&
		newSOA.Serial() == clientSerial {
		return Result{Kind: KindUpToDate, NewSOA: newSOA}, nil
	}

	// Detect incremental shape: recs[1] is an SOA whose serial is OLDER
	// than recs[0]'s serial.
	if len(recs) >= 3 && recs[1].Type() == rrtype.SOA &&
		serialIsOlder(recs[1].RData().(rdata.SOA).Serial(), newSOA.Serial()) {
		diffs, err := parseDiffs(recs)
		if err != nil {
			return Result{}, err
		}
		return Result{Kind: KindIncremental, Diffs: diffs, NewSOA: newSOA}, nil
	}

	// AXFR fallback: full zone bracketed by SOA.
	body := recs[1 : len(recs)-1]
	out := []dnsmsg.Record{recs[0]}
	out = append(out, body...)
	out = append(out, recs[len(recs)-1])
	return Result{Kind: KindAXFRFallback, Records: out, NewSOA: newSOA}, nil
}

// parseDiffs walks the incremental stream after the leading SOA.
//
// Layout: SOA_new, (SOA_old, [removed RRs...], SOA_new, [added RRs...])+, SOA_new.
func parseDiffs(recs []dnsmsg.Record) ([]Diff, error) {
	if len(recs) < 4 {
		return nil, errors.New("ixfr: incremental stream too short")
	}
	final := recs[len(recs)-1].RData().(rdata.SOA).Serial()
	cursor := 1 // past leading SOA_new
	var diffs []Diff
	for cursor < len(recs)-1 {
		if recs[cursor].Type() != rrtype.SOA {
			return nil, errors.New("ixfr: expected SOA at sub-diff start")
		}
		fromSerial := recs[cursor].RData().(rdata.SOA).Serial()
		cursor++

		var removed []dnsmsg.Record
		for cursor < len(recs) && recs[cursor].Type() != rrtype.SOA {
			removed = append(removed, recs[cursor])
			cursor++
		}
		if cursor >= len(recs) || recs[cursor].Type() != rrtype.SOA {
			return nil, errors.New("ixfr: missing SOA between removed and added")
		}
		toSerial := recs[cursor].RData().(rdata.SOA).Serial()
		cursor++

		var added []dnsmsg.Record
		for cursor < len(recs) && recs[cursor].Type() != rrtype.SOA {
			added = append(added, recs[cursor])
			cursor++
		}
		diffs = append(diffs, Diff{
			FromSerial: fromSerial,
			ToSerial:   toSerial,
			Removed:    removed,
			Added:      added,
		})
	}
	// Sanity: final SOA serial must match the last sub-diff's ToSerial.
	if len(diffs) > 0 && diffs[len(diffs)-1].ToSerial != final {
		return nil, errors.New("ixfr: trailing SOA serial does not match last sub-diff")
	}
	return diffs, nil
}

// serialIsOlder applies RFC 1982 sequence-space arithmetic.
func serialIsOlder(a, b uint32) bool {
	const half uint32 = 1 << 31
	return a != b && (b-a) < half
}

func writeMessage(w io.Writer, body []byte) error {
	if len(body) > 0xffff {
		return fmt.Errorf("ixfr: query too large")
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("ixfr: write length: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("ixfr: write body: %w", err)
	}
	return nil
}

func readMessage(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("ixfr: read length: %w", err)
	}
	n := binary.BigEndian.Uint16(hdr[:])
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("ixfr: read body: %w", err)
	}
	return body, nil
}

func randomID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}
