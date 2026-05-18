package rdata

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// SOA is the start-of-authority rdata (RFC 1035 §3.3.13). All time-based
// fields are exposed as time.Duration; on the wire they are 32-bit unsigned
// seconds.
type SOA struct {
	mname, rname                    wirebb.Name
	serial                          uint32
	refresh, retry, expire, minimum time.Duration
}

func (SOA) Type() rrtype.Type        { return rrtype.SOA }
func (SOA) typedRData()              {}
func (s SOA) MName() wirebb.Name     { return s.mname }
func (s SOA) RName() wirebb.Name     { return s.rname }
func (s SOA) Serial() uint32         { return s.serial }
func (s SOA) Refresh() time.Duration { return s.refresh }
func (s SOA) Retry() time.Duration   { return s.retry }
func (s SOA) Expire() time.Duration  { return s.expire }
func (s SOA) Minimum() time.Duration { return s.minimum }

func (s SOA) Pack(p *wirebb.Packer) {
	p.Name(s.mname)
	p.Name(s.rname)
	p.Uint32(s.serial)
	p.Uint32(uint32(s.refresh / time.Second))
	p.Uint32(uint32(s.retry / time.Second))
	p.Uint32(uint32(s.expire / time.Second))
	p.Uint32(uint32(s.minimum / time.Second))
}

// NewSOA returns an SOA rdata. Returns [ErrInvalidRData] when mname
// or rname is the zero name; both are required by RFC 1035 §3.3.13
// and silently emitting "." would corrupt zone state in any consumer.
//
// Also returns [ErrInvalidRData] if any of refresh, retry, expire, or
// minimum is negative or exceeds 2^31-1 seconds (RFC 2308 §8 ceiling).
// Negative durations would otherwise wrap to a huge uint32 on the wire,
// producing nonsensical timer values that confuse downstream resolvers.
func NewSOA(mname, rname wirebb.Name, serial uint32, refresh, retry, expire, minimum time.Duration) (SOA, error) {
	if !mname.IsValid() {
		return SOA{}, fmt.Errorf("%w: SOA mname is invalid", ErrInvalidRData)
	}
	if !rname.IsValid() {
		return SOA{}, fmt.Errorf("%w: SOA rname is invalid", ErrInvalidRData)
	}
	for _, t := range [...]struct {
		name string
		d    time.Duration
	}{
		{"refresh", refresh},
		{"retry", retry},
		{"expire", expire},
		{"minimum", minimum},
	} {
		if t.d < 0 {
			return SOA{}, fmt.Errorf("%w: SOA %s is negative (%s)", ErrInvalidRData, t.name, t.d)
		}
		if t.d/time.Second > maxSOATimerSeconds {
			return SOA{}, fmt.Errorf("%w: SOA %s %s exceeds RFC 2308 §8 ceiling (2^31-1 seconds)", ErrInvalidRData, t.name, t.d)
		}
	}
	return SOA{
		mname: mname, rname: rname, serial: serial,
		refresh: refresh, retry: retry, expire: expire, minimum: minimum,
	}, nil
}

// maxSOATimerSeconds is the RFC 2308 §8 ceiling for SOA timer values
// (signed 32-bit). The wire format is uint32, but values above this
// limit are routinely rejected by RFC 2308 §8 compliant caches.
const maxSOATimerSeconds = 0x7fffffff

func unpackSOA(u *wirebb.Unpacker, rdlen int) (SOA, error) {
	var zero SOA
	end := u.Off() + rdlen
	mname, err := u.NameInRange(end)
	if err != nil {
		return zero, err
	}
	rname, err := u.NameInRange(end)
	if err != nil {
		return zero, err
	}
	serial, err := u.Uint32()
	if err != nil {
		return zero, err
	}
	refresh, err := u.Uint32()
	if err != nil {
		return zero, err
	}
	retry, err := u.Uint32()
	if err != nil {
		return zero, err
	}
	expire, err := u.Uint32()
	if err != nil {
		return zero, err
	}
	minimum, err := u.Uint32()
	if err != nil {
		return zero, err
	}
	return SOA{
		mname:   mname,
		rname:   rname,
		serial:  serial,
		refresh: time.Duration(refresh) * time.Second,
		retry:   time.Duration(retry) * time.Second,
		expire:  time.Duration(expire) * time.Second,
		minimum: time.Duration(minimum) * time.Second,
	}, nil
}
