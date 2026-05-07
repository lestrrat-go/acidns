package rdata

import (
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

// NewSOA returns an SOA rdata.
func NewSOA(mname, rname wirebb.Name, serial uint32, refresh, retry, expire, minimum time.Duration) SOA {
	return SOA{
		mname: mname, rname: rname, serial: serial,
		refresh: refresh, retry: retry, expire: expire, minimum: minimum,
	}
}

func unpackSOA(u *wirebb.Unpacker) (SOA, error) {
	var zero SOA
	mname, err := u.Name()
	if err != nil {
		return zero, err
	}
	rname, err := u.Name()
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
