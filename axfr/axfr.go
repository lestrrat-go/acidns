// Package axfr implements RFC 5936 zone transfer over a stream transport.
//
// Start sends the AXFR query and returns a Transfer iterator. The caller
// pulls RecordEvents with Next until io.EOF — the leading and trailing
// SOA are emitted along with the body — and MUST Close the iterator to
// release the underlying stream.
//
// Streaming protocol details (single-message vs. chunked, compression
// pointer continuity) are handled by the underlying transport.
package axfr

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

// Transfer is the iterator returned by Start.
type Transfer interface {
	NewSOA() rdata.SOA
	Next(ctx context.Context) (RecordEvent, error)
	Close() error
}

// RecordEvent carries a single record from the transfer.
type RecordEvent interface {
	isAXFREvent()
	Record() wire.Record
}

type recordEvent struct{ rec wire.Record }

func (recordEvent) isAXFREvent()          {}
func (e recordEvent) Record() wire.Record { return e.rec }

// ErrEmptyResponse is returned when the server's first response
// contains no records.
var ErrEmptyResponse = errors.New("axfr: empty response")

// ErrMissingLeadingSOA is returned when the first record of the
// transfer is not the apex SOA — RFC 5936 §2.2 requires it.
var ErrMissingLeadingSOA = errors.New("axfr: stream must begin with SOA")

// ErrRCODE is returned when the server answered with a non-NOERROR
// RCODE. The wrapped error carries the specific RCODE value
// rendered as text; use errors.Is(err, ErrRCODE) to branch on the
// generic case and unwrap to inspect the value.
var ErrRCODE = errors.New("axfr: server returned error rcode")

// Start sends an AXFR query for zone over ex and returns a Transfer
// iterator positioned just past the leading SOA.
func Start(ctx context.Context, ex acidns.StreamExchanger, zone wire.Name, opts ...Option) (Transfer, error) {
	c := config{timeout: 30 * time.Second}
	for _, o := range opts {
		o.applyAXFR(&c)
	}
	_ = c // reserved

	id, err := randomID()
	if err != nil {
		return nil, err
	}
	q, err := wire.NewBuilder().
		ID(id).
		Question(wire.NewQuestion(zone, rrtype.AXFR)).
		Build()
	if err != nil {
		return nil, err
	}
	stream, err := ex.Stream(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("axfr: open stream: %w", err)
	}
	t := &transfer{stream: stream, reader: &recReader{stream: stream}}
	if err := t.init(ctx); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return t, nil
}

type transfer struct {
	stream acidns.MessageStream
	reader *recReader

	newSOA          rdata.SOA
	emittedFirstSOA bool
	done            bool
}

func (t *transfer) NewSOA() rdata.SOA { return t.newSOA }
func (t *transfer) Close() error      { return t.stream.Close() }

func (t *transfer) init(ctx context.Context) error {
	rec, err := t.reader.Read(ctx)
	if err == io.EOF {
		return ErrEmptyResponse
	}
	if err != nil {
		return err
	}
	soa, ok := wire.RDataAs[rdata.SOA](rec)
	if !ok {
		return ErrMissingLeadingSOA
	}
	t.newSOA = soa
	t.reader.Push(rec)
	return nil
}

func (t *transfer) Next(ctx context.Context) (RecordEvent, error) {
	if t.done {
		return nil, io.EOF
	}
	rec, err := t.reader.Read(ctx)
	if err != nil {
		return nil, err
	}
	if soa, ok := wire.RDataAs[rdata.SOA](rec); ok && soa.Serial() == t.newSOA.Serial() {
		if !t.emittedFirstSOA {
			t.emittedFirstSOA = true
		} else {
			t.done = true
		}
	}
	return recordEvent{rec: rec}, nil
}

// recReader pulls records from successive stream messages with a small
// pushback queue.
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
			return nil, fmt.Errorf("%w: %s", ErrRCODE, rcode)
		}
		rr.curMsg = msg
		rr.curIdx = 0
	}
}

func (rr *recReader) Push(rec wire.Record) {
	rr.pushback = append(rr.pushback, rec)
}

func randomID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("axfr: random id: %w", err)
	}
	return binary.BigEndian.Uint16(b[:]), nil
}
