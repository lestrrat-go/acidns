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
// Start performs the IXFR query over a acidns.StreamExchanger and
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

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
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
	Record() wire.Record
}

// DiffEvent carries one (removed, added) sub-diff from an incremental
// transfer.
type DiffEvent interface {
	Event
	FromSerial() uint32
	ToSerial() uint32
	Removed() []wire.Record
	Added() []wire.Record
}

type recordEvent struct{ rec wire.Record }

func (recordEvent) isTransferEvent()      {}
func (e recordEvent) Record() wire.Record { return e.rec }

type diffEvent struct {
	from, to       uint32
	removed, added []wire.Record
}

func (diffEvent) isTransferEvent()         {}
func (e diffEvent) FromSerial() uint32     { return e.from }
func (e diffEvent) ToSerial() uint32       { return e.to }
func (e diffEvent) Removed() []wire.Record { return e.removed }
func (e diffEvent) Added() []wire.Record   { return e.added }

// Start sends an IXFR query for zone over ex and returns a Transfer
// iterator positioned just past the first response message. The caller's
// ctx applies to the initial request and the first response read; per-call
// contexts on Next apply to subsequent reads.
//
// clientSOA names the requester's current view of the zone — only the
// Serial field is interpreted by the server, but the full SOA RR is what
// the wire requires.
func Start(ctx context.Context, ex acidns.StreamExchanger, zone wire.Name, clientSOA rdata.SOA, opts ...Option) (Transfer, error) {
	c := config{timeout: 30 * time.Second}
	for _, o := range opts {
		o.applyIXFR(&c)
	}
	_ = c // reserved for future per-stream options

	id, err := randomID()
	if err != nil {
		return nil, err
	}
	q, err := wire.NewBuilder().
		ID(id).
		Question(wire.NewQuestion(zone, rrtype.IXFR)).
		Authority(wire.NewRecord(zone, time.Second, clientSOA)).
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
	stream acidns.MessageStream
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
	soa1, ok := wire.RDataAs[rdata.SOA](rec1)
	if !ok {
		return errors.New("ixfr: stream must begin with SOA")
	}
	t.newSOA = soa1

	rec2, err := t.reader.Read(ctx)
	if err == io.EOF {
		t.kind = KindUpToDate
		return nil
	}
	if err != nil {
		return err
	}

	rec2SOA, ok := wire.RDataAs[rdata.SOA](rec2)
	if !ok {
		t.kind = KindAXFRFallback
		t.reader.Push(rec1)
		t.reader.Push(rec2)
		return nil
	}
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
	if soa, ok := wire.RDataAs[rdata.SOA](rec); ok && soa.Serial() == t.newSOA.Serial() {
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
	soaOldRD, ok := wire.RDataAs[rdata.SOA](soaOld)
	if !ok {
		return nil, errors.New("ixfr: expected SOA at sub-diff start")
	}
	soaOldSerial := soaOldRD.Serial()

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

	var removed []wire.Record
	var soaNew wire.Record
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
	soaNewRD, ok := wire.RDataAs[rdata.SOA](soaNew)
	if !ok {
		return nil, errors.New("ixfr: expected SOA at sub-diff end")
	}
	soaNewSerial := soaNewRD.Serial()

	var added []wire.Record
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
	stream   acidns.MessageStream
	curMsg   wire.Message
	curIdx   int
	pushback []wire.Record
	msgEOF   bool
}

func (rr *recReader) Read(ctx context.Context) (wire.Record, error) {
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
		if rcode := msg.Flags().RCODE(); rcode != wire.RCODENoError {
			return nil, fmt.Errorf("ixfr: %s", rcode)
		}
		rr.curMsg = msg
		rr.curIdx = 0
	}
}

func (rr *recReader) Push(rec wire.Record) {
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
