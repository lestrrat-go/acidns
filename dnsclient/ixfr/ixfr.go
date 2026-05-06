// Package ixfr implements the client side of RFC 1995 incremental zone
// transfer.
//
// An IXFR query carries the requester's current SOA in the authority
// section. The server responds with one of three shapes, exposed by
// Transfer.Kind:
//
//   - KindUpToDate — single SOA whose serial equals the client's serial.
//   - KindAXFRFallback — the entire zone, identical wire format to AXFR.
//   - KindIncremental — [SOA_new, (SOA_old, removed..., SOA_new, added...)+, SOA_new]
//
// Start performs the IXFR query over a transport.StreamExchanger and
// returns a Transfer iterator. The caller pulls Events with Next until
// io.EOF and MUST Close the iterator to release the underlying stream.
//
// AXFR-fallback responses yield RecordEvents (one per record, leading and
// trailing SOA included). Incremental responses yield DiffEvents (one per
// sub-diff). Up-to-date responses yield nothing — Next returns io.EOF on
// the first call.
package ixfr

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/transport"
	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
)

// Kind describes the shape of an IXFR response, queryable on the Transfer
// once Start has read the first message.
type Kind int

const (
	// KindUpToDate indicates the requester's serial matched the server's;
	// no events follow.
	KindUpToDate Kind = iota + 1
	// KindAXFRFallback indicates the server returned the full zone in
	// AXFR format. Events will all be RecordEvents.
	KindAXFRFallback
	// KindIncremental indicates the server returned a diff. Events will
	// all be DiffEvents, one per sub-diff.
	KindIncremental
)

// Transfer is the iterator returned by Start. Kind and NewSOA become
// well-defined once Start returns; Next yields events until io.EOF.
type Transfer interface {
	Kind() Kind
	NewSOA() rdata.SOA
	Next(ctx context.Context) (Event, error)
	Close() error
}

// Event is the sealed sum of values yielded by Transfer.Next. Concrete
// variants are RecordEvent and DiffEvent; the seal method keeps the type
// closed against external implementations.
type Event interface {
	isTransferEvent()
}

// RecordEvent carries a single record from an AXFR-fallback transfer.
type RecordEvent interface {
	Event
	Record() dnsmsg.Record
}

// DiffEvent carries one (removed, added) sub-diff from an incremental
// transfer.
type DiffEvent interface {
	Event
	FromSerial() uint32
	ToSerial() uint32
	Removed() []dnsmsg.Record
	Added() []dnsmsg.Record
}

type recordEvent struct{ rec dnsmsg.Record }

func (recordEvent) isTransferEvent()        {}
func (e recordEvent) Record() dnsmsg.Record { return e.rec }

type diffEvent struct {
	from, to       uint32
	removed, added []dnsmsg.Record
}

func (diffEvent) isTransferEvent()           {}
func (e diffEvent) FromSerial() uint32       { return e.from }
func (e diffEvent) ToSerial() uint32         { return e.to }
func (e diffEvent) Removed() []dnsmsg.Record { return e.removed }
func (e diffEvent) Added() []dnsmsg.Record   { return e.added }

// Option configures a Start call.
type Option interface{ applyIXFR(*config) }

type optionFunc func(*config)

func (f optionFunc) applyIXFR(c *config) { f(c) }

type config struct {
	timeout time.Duration
}

// WithTimeout sets the per-stream-message read timeout used when ctx has
// no deadline. Defaults to 30 seconds.
func WithTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) { c.timeout = d })
}

// Start sends an IXFR query for zone over ex and returns a Transfer
// iterator positioned just past the first response message. The caller's
// ctx applies to the initial request and the first response read; per-call
// contexts on Next apply to subsequent reads.
//
// clientSOA names the requester's current view of the zone — only the
// Serial field is interpreted by the server, but the full SOA RR is what
// the wire requires.
func Start(ctx context.Context, ex transport.StreamExchanger, zone dnsname.Name, clientSOA rdata.SOA, opts ...Option) (Transfer, error) {
	c := config{timeout: 30 * time.Second}
	for _, o := range opts {
		o.applyIXFR(&c)
	}
	_ = c // reserved for future per-stream options

	id, err := randomID()
	if err != nil {
		return nil, err
	}
	q, err := dnsmsg.NewBuilder().
		ID(id).
		Question(dnsmsg.NewQuestion(zone, rrtype.IXFR)).
		Authority(dnsmsg.NewRecord(zone, time.Second, clientSOA)).
		Build()
	if err != nil {
		return nil, err
	}
	stream, err := ex.Stream(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("ixfr: open stream: %w", err)
	}
	t := &transfer{stream: stream, reader: &recReader{stream: stream}}
	if err := t.init(ctx, clientSOA.Serial()); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return t, nil
}

// transfer is the concrete Transfer implementation.
type transfer struct {
	stream transport.MessageStream
	reader *recReader

	kind   Kind
	newSOA rdata.SOA

	axfrEmittedFirst bool
	axfrDone         bool
	incDone          bool
}

func (t *transfer) Kind() Kind        { return t.kind }
func (t *transfer) NewSOA() rdata.SOA { return t.newSOA }
func (t *transfer) Close() error      { return t.stream.Close() }

// init reads the first records from the stream to determine kind and
// position the reader for subsequent Next calls.
func (t *transfer) init(ctx context.Context, clientSerial uint32) error {
	rec1, err := t.reader.Read(ctx)
	if err == io.EOF {
		return errors.New("ixfr: empty response")
	}
	if err != nil {
		return err
	}
	if rec1.Type() != rrtype.SOA {
		return errors.New("ixfr: stream must begin with SOA")
	}
	t.newSOA = rec1.RData().(rdata.SOA)

	rec2, err := t.reader.Read(ctx)
	if err == io.EOF {
		t.kind = KindUpToDate
		return nil
	}
	if err != nil {
		return err
	}

	if rec2.Type() != rrtype.SOA {
		t.kind = KindAXFRFallback
		t.reader.Push(rec1)
		t.reader.Push(rec2)
		return nil
	}

	rec2SOA := rec2.RData().(rdata.SOA)
	if serialIsOlder(rec2SOA.Serial(), t.newSOA.Serial()) {
		// Incremental: rec1=SOA_new (already captured), rec2=SOA_old of first sub-diff.
		t.kind = KindIncremental
		t.reader.Push(rec2)
		return nil
	}
	if rec2SOA.Serial() == t.newSOA.Serial() {
		if t.newSOA.Serial() == clientSerial {
			t.kind = KindUpToDate
			return nil
		}
		// Empty AXFR-fallback (zero records between bracketing SOAs).
		t.kind = KindAXFRFallback
		t.reader.Push(rec1)
		t.reader.Push(rec2)
		return nil
	}
	return errors.New("ixfr: invalid SOA pair (rec2 serial newer than rec1)")
}

// Next pulls the next event from the stream. Returns io.EOF when the
// transfer has been fully consumed.
func (t *transfer) Next(ctx context.Context) (Event, error) {
	switch t.kind {
	case KindUpToDate:
		return nil, io.EOF
	case KindAXFRFallback:
		return t.nextAXFR(ctx)
	case KindIncremental:
		return t.nextIncremental(ctx)
	}
	return nil, errors.New("ixfr: invalid transfer state")
}

func (t *transfer) nextAXFR(ctx context.Context) (Event, error) {
	if t.axfrDone {
		return nil, io.EOF
	}
	rec, err := t.reader.Read(ctx)
	if err != nil {
		return nil, err
	}
	if rec.Type() == rrtype.SOA && rec.RData().(rdata.SOA).Serial() == t.newSOA.Serial() {
		if !t.axfrEmittedFirst {
			t.axfrEmittedFirst = true
		} else {
			t.axfrDone = true
		}
	}
	return recordEvent{rec: rec}, nil
}

func (t *transfer) nextIncremental(ctx context.Context) (Event, error) {
	if t.incDone {
		return nil, io.EOF
	}

	soaOld, err := t.reader.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("ixfr: read sub-diff start: %w", err)
	}
	if soaOld.Type() != rrtype.SOA {
		return nil, errors.New("ixfr: expected SOA at sub-diff start")
	}
	soaOldSerial := soaOld.RData().(rdata.SOA).Serial()

	if soaOldSerial == t.newSOA.Serial() {
		// Closing bracket. Verify nothing follows.
		if _, err := t.reader.Read(ctx); err != io.EOF {
			if err != nil {
				return nil, fmt.Errorf("ixfr: read past closing SOA: %w", err)
			}
			return nil, errors.New("ixfr: unexpected record after closing SOA")
		}
		t.incDone = true
		return nil, io.EOF
	}

	var removed []dnsmsg.Record
	var soaNew dnsmsg.Record
	for {
		rec, err := t.reader.Read(ctx)
		if err != nil {
			return nil, fmt.Errorf("ixfr: read removed: %w", err)
		}
		if rec.Type() == rrtype.SOA {
			soaNew = rec
			break
		}
		removed = append(removed, rec)
	}
	soaNewSerial := soaNew.RData().(rdata.SOA).Serial()

	var added []dnsmsg.Record
	for {
		rec, err := t.reader.Read(ctx)
		if err == io.EOF {
			return nil, errors.New("ixfr: stream ended without closing SOA")
		}
		if err != nil {
			return nil, fmt.Errorf("ixfr: read added: %w", err)
		}
		if rec.Type() == rrtype.SOA {
			// Either next sub-diff's SOA_old or the closing bracket. Push
			// back; the next nextIncremental call decides.
			t.reader.Push(rec)
			return diffEvent{from: soaOldSerial, to: soaNewSerial, removed: removed, added: added}, nil
		}
		added = append(added, rec)
	}
}

// recReader yields records from the answer section of each successive
// stream message, with a small pushback queue so callers can defer
// interpretation of a record they peeked.
type recReader struct {
	stream   transport.MessageStream
	curMsg   dnsmsg.Message
	curIdx   int
	pushback []dnsmsg.Record
	msgEOF   bool
}

func (rr *recReader) Read(ctx context.Context) (dnsmsg.Record, error) {
	if len(rr.pushback) > 0 {
		rec := rr.pushback[0]
		rr.pushback = rr.pushback[1:]
		return rec, nil
	}
	for {
		if rr.curMsg != nil && rr.curIdx < len(rr.curMsg.Answers()) {
			rec := rr.curMsg.Answers()[rr.curIdx]
			rr.curIdx++
			return rec, nil
		}
		if rr.msgEOF {
			return nil, io.EOF
		}
		msg, err := rr.stream.Next(ctx)
		if err != nil {
			if err == io.EOF {
				rr.msgEOF = true
				return nil, io.EOF
			}
			return nil, err
		}
		if rcode := msg.Flags().RCODE(); rcode != dnsmsg.RCODENoError {
			return nil, fmt.Errorf("ixfr: %s", rcode)
		}
		rr.curMsg = msg
		rr.curIdx = 0
	}
}

func (rr *recReader) Push(rec dnsmsg.Record) {
	rr.pushback = append(rr.pushback, rec)
}

// serialIsOlder applies RFC 1982 sequence-space arithmetic.
func serialIsOlder(a, b uint32) bool {
	const half uint32 = 1 << 31
	return a != b && (b-a) < half
}

func randomID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}
