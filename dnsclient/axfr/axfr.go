// Package axfr implements RFC 5936 zone transfer over TCP from the
// client side.
//
// The transfer terminates on the second occurrence of the zone's SOA RR,
// supporting both single-message and streamed responses. Out-of-scope for
// this version: IXFR (RFC 1995), TSIG-authenticated transfers, and EDNS0
// chained transfers.
package axfr

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
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
)

// ErrNoSOA is returned when the server's response stream contains no SOA
// record, which is malformed per RFC 5936 §2.2.
var ErrNoSOA = errors.New("axfr: response missing SOA")

// Option configures a transfer.
type Option interface{ applyAXFR(*config) }

type optionFunc func(*config)

func (f optionFunc) applyAXFR(c *config) { f(c) }

type config struct {
	timeout time.Duration
}

// WithTimeout sets the overall timeout when the caller's context has no
// deadline. Defaults to 30 seconds (zone transfers are bigger than ordinary
// queries).
func WithTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) { c.timeout = d })
}

// Transfer performs a single AXFR against server for zone and returns every
// record in the zone, in the order the server emitted them. The leading
// SOA appears first and the trailing SOA appears last.
func Transfer(ctx context.Context, server netip.AddrPort, zone dnsname.Name, opts ...Option) ([]dnsmsg.Record, error) {
	c := config{timeout: 30 * time.Second}
	for _, o := range opts {
		o.applyAXFR(&c)
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", server.String())
	if err != nil {
		return nil, fmt.Errorf("axfr: dial %s: %w", server, err)
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
		return nil, err
	}
	q, err := dnsmsg.NewBuilder().
		ID(id).
		Question(dnsmsg.NewQuestion(zone, rrtype.AXFR)).
		Build()
	if err != nil {
		return nil, err
	}
	wire, err := dnsmsg.Marshal(q)
	if err != nil {
		return nil, err
	}
	if err := writeMessage(conn, wire); err != nil {
		return nil, err
	}

	var records []dnsmsg.Record
	soas := 0
	for soas < 2 {
		body, err := readMessage(conn)
		if err != nil {
			return nil, err
		}
		resp, err := dnsmsg.Unmarshal(body)
		if err != nil {
			return nil, fmt.Errorf("axfr: parse: %w", err)
		}
		if resp.ID() != q.ID() {
			return nil, fmt.Errorf("axfr: id mismatch")
		}
		if resp.Flags().RCODE() != dnsmsg.RCODENoError {
			return nil, fmt.Errorf("axfr: %s", resp.Flags().RCODE())
		}
		for _, rec := range resp.Answers() {
			records = append(records, rec)
			if rec.Type() == rrtype.SOA {
				soas++
				if soas == 2 {
					return records, nil
				}
			}
		}
	}
	if soas == 0 {
		return nil, ErrNoSOA
	}
	return records, nil
}

func writeMessage(w io.Writer, body []byte) error {
	if len(body) > 0xffff {
		return fmt.Errorf("axfr: query too large")
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("axfr: write length: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("axfr: write body: %w", err)
	}
	return nil
}

func readMessage(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("axfr: read length: %w", err)
	}
	n := binary.BigEndian.Uint16(hdr[:])
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("axfr: read body: %w", err)
	}
	return body, nil
}

func randomID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("axfr: random id: %w", err)
	}
	return binary.BigEndian.Uint16(b[:]), nil
}
