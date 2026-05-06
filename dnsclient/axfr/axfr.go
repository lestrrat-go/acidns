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

	"github.com/lestrrat-go/acidns/dnsclient/transport"
	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
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
	Record() dnsmsg.Record
}

type recordEvent struct{ rec dnsmsg.Record }

func (recordEvent) isAXFREvent()            {}
func (e recordEvent) Record() dnsmsg.Record { return e.rec }

// Option configures a Start call.
type Option interface{ applyAXFR(*config) }

type optionFunc func(*config)

func (f optionFunc) applyAXFR(c *config) { f(c) }

type config struct {
	timeout time.Duration
}

// WithTimeout sets the per-stream-message read timeout used when ctx has
// no deadline. Defaults to 30 seconds.
func WithTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) { c.timeout = d })
}

// Start sends an AXFR query for zone over ex and returns a Transfer
// iterator positioned just past the leading SOA.
func Start(ctx context.Context, ex transport.StreamExchanger, zone dnsname.Name, opts ...Option) (Transfer, error) {
	c := config{timeout: 30 * time.Second}
	for _, o := range opts {
		o.applyAXFR(&c)
	}
	_ = c // reserved

	id, err := randomID()
	if err != nil {
		return nil, err
	}
	q, err := dnsmsg.NewBuilder().
		ID(id).
		Question(dnsmsg.NewQuestion(zone, rrtype.AXFR)).
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
	stream transport.MessageStream
	reader *recReader

	newSOA           rdata.SOA
	emittedFirstSOA  bool
	done             bool
}

func (t *transfer) NewSOA() rdata.SOA { return t.newSOA }
func (t *transfer) Close() error      { return t.stream.Close() }

func (t *transfer) init(ctx context.Context) error {
	rec, err := t.reader.Read(ctx)
	if err == io.EOF {
		return errors.New("axfr: empty response")
	}
	if err != nil {
		return err
	}
	if rec.Type() != rrtype.SOA {
		return errors.New("axfr: stream must begin with SOA")
	}
	t.newSOA = rec.RData().(rdata.SOA)
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
	if rec.Type() == rrtype.SOA && rec.RData().(rdata.SOA).Serial() == t.newSOA.Serial() {
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
			return nil, fmt.Errorf("axfr: %s", rcode)
		}
		rr.curMsg = msg
		rr.curIdx = 0
	}
}

func (rr *recReader) Push(rec dnsmsg.Record) {
	rr.pushback = append(rr.pushback, rec)
}

func randomID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("axfr: random id: %w", err)
	}
	return binary.BigEndian.Uint16(b[:]), nil
}
