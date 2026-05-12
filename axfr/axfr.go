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
	"github.com/lestrrat-go/acidns/tsig"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/option/v3"
)

// Transfer is the iterator returned by Start.
type Transfer interface {
	NewSOA() rdata.SOA
	Next(ctx context.Context) (RecordEvent, error)
	Close() error
}

// RecordEvent carries a single record from the transfer.
type RecordEvent struct {
	rec wire.Record
}

// Record returns the wire record carried by this event.
func (e RecordEvent) Record() wire.Record { return e.rec }

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

// ErrTSIGVerify is returned when a stream envelope's TSIG signature
// fails to verify against the key supplied via [WithTSIGKey]. Aliased
// to [tsig.ErrVerify] so callers can match either form via errors.Is.
var ErrTSIGVerify = tsig.ErrVerify

// ErrEnvelopeMismatch is returned when a continuation envelope's
// transaction ID or echoed question does not match the original AXFR
// request. RFC 5936 §3.4: every response message in the AXFR response
// stream MUST have the same ID as the request, and (when present) the
// question MUST match the original. Without this check, a hostile
// upstream — or one multiplexing concurrent transfers on the same
// connection — could splice records from another zone into the stream.
var ErrEnvelopeMismatch = errors.New("axfr: response envelope id or question does not match request")

// Start sends an AXFR query for zone over ex and returns a Transfer
// iterator positioned just past the leading SOA.
func Start(ctx context.Context, ex acidns.StreamExchanger, zone wire.Name, opts ...Option) (Transfer, error) {
	c := config{timeout: 30 * time.Second, tsigFudge: 5 * time.Minute, tsigNow: time.Now}
	for _, o := range opts {
		switch o.Ident() {
		case identTimeout{}:
			c.timeout = option.MustGet[time.Duration](o)
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
		return nil, err
	}
	q, err := wire.NewMessageBuilder().
		ID(id).
		Question(wire.NewQuestion(zone, rrtype.AXFR)).
		Build()
	if err != nil {
		return nil, err
	}
	if c.tsigKey != nil {
		signed, err := tsig.SignMessage(q, *c.tsigKey, c.tsigNow(), c.tsigFudge)
		if err != nil {
			return nil, fmt.Errorf("axfr: TSIG sign: %w", err)
		}
		// Capture the request MAC so we can chain MAC verification on
		// the response envelopes per RFC 8945 §5.3.1.
		_, mac, _, err := tsig.VerifyMAC(signed, *c.tsigKey, c.tsigNow(), c.tsigFudge)
		if err != nil {
			return nil, fmt.Errorf("axfr: TSIG extract MAC: %w", err)
		}
		q, err = wire.Unpack(signed)
		if err != nil {
			return nil, fmt.Errorf("axfr: re-parse signed query: %w", err)
		}
		stream, err := ex.Stream(ctx, q)
		if err != nil {
			return nil, fmt.Errorf("axfr: open stream: %w", err)
		}
		reader := &recReader{
			stream:   stream,
			verifier: newTSIGVerifier(*c.tsigKey, mac, c.tsigNow, c.tsigFudge),
			wantID:   q.ID(),
			wantQ:    q.Questions()[0],
		}
		t := &transfer{stream: stream, reader: reader}
		if err := t.init(ctx); err != nil {
			_ = stream.Close()
			return nil, err
		}
		return t, nil
	}

	stream, err := ex.Stream(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("axfr: open stream: %w", err)
	}
	t := &transfer{stream: stream, reader: &recReader{
		stream: stream,
		wantID: q.ID(),
		wantQ:  q.Questions()[0],
	}}
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
		return RecordEvent{}, io.EOF
	}
	rec, err := t.reader.Read(ctx)
	if err != nil {
		return RecordEvent{}, err
	}
	if soa, ok := wire.RDataAs[rdata.SOA](rec); ok && soa.Serial() == t.newSOA.Serial() {
		if !t.emittedFirstSOA {
			t.emittedFirstSOA = true
		} else {
			t.done = true
		}
	}
	return RecordEvent{rec: rec}, nil
}

// recReader pulls records from successive stream messages with a small
// pushback queue.
type recReader struct {
	stream   acidns.MessageStream
	curMsg   wire.Message
	curIdx   int
	pushback []wire.Record
	msgEOF   bool
	verifier *tsigVerifier
	// wantID and wantQ identify the originating AXFR request; every
	// continuation envelope must echo them so a hostile or
	// connection-pooling upstream cannot splice records from another
	// in-flight transfer into our stream.
	wantID uint16
	wantQ  wire.Question
}

func (rr *recReader) Read(ctx context.Context) (wire.Record, error) {
	if len(rr.pushback) > 0 {
		rec := rr.pushback[0]
		rr.pushback = rr.pushback[1:]
		return rec, nil
	}
	for {
		if rr.curIdx < len(rr.curMsg.Answers()) {
			rec := rr.curMsg.Answers()[rr.curIdx]
			rr.curIdx++
			return rec, nil
		}
		if rr.msgEOF {
			return wire.Record{}, io.EOF
		}
		msg, err := rr.stream.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				rr.msgEOF = true
				return wire.Record{}, io.EOF
			}
			return wire.Record{}, err
		}
		if msg.ID() != rr.wantID {
			return wire.Record{}, fmt.Errorf("%w: id %d != %d", ErrEnvelopeMismatch, msg.ID(), rr.wantID)
		}
		// RFC 5936 §3.4 allows continuation envelopes to either echo the
		// question or omit it. When present, it must match the original
		// (same name, type, class) — otherwise records from a different
		// transfer have been spliced in.
		if qs := msg.Questions(); len(qs) > 0 {
			if qs[0].Type() != rr.wantQ.Type() || qs[0].Class() != rr.wantQ.Class() || !qs[0].Name().Equal(rr.wantQ.Name()) {
				return wire.Record{}, fmt.Errorf("%w: question mismatch", ErrEnvelopeMismatch)
			}
		}
		if rcode := msg.Flags().RCODE(); rcode != wire.RCODENoError {
			return wire.Record{}, fmt.Errorf("%w: %s", ErrRCODE, rcode)
		}
		if rr.verifier != nil {
			if err := rr.verifier.verify(msg); err != nil {
				return wire.Record{}, err
			}
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
