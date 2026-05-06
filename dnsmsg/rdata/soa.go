package rdata

import (
	"time"

	"github.com/lestrrat-go/acidns/dnsmsg/internal/wire"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
)

// SOA is the start-of-authority rdata (RFC 1035 §3.3.13). All time-based
// fields are exposed as time.Duration; on the wire they are 32-bit unsigned
// seconds.
type SOA interface {
	RData
	MName() dnsname.Name
	RName() dnsname.Name
	Serial() uint32
	Refresh() time.Duration
	Retry() time.Duration
	Expire() time.Duration
	Minimum() time.Duration
}

type soa struct {
	mname, rname                    dnsname.Name
	serial                          uint32
	refresh, retry, expire, minimum time.Duration
}

func (soa) Type() rrtype.Type        { return rrtype.SOA }
func (s soa) MName() dnsname.Name    { return s.mname }
func (s soa) RName() dnsname.Name    { return s.rname }
func (s soa) Serial() uint32         { return s.serial }
func (s soa) Refresh() time.Duration { return s.refresh }
func (s soa) Retry() time.Duration   { return s.retry }
func (s soa) Expire() time.Duration  { return s.expire }
func (s soa) Minimum() time.Duration { return s.minimum }

func (s soa) Pack(p *wire.Packer) {
	p.Name(s.mname)
	p.Name(s.rname)
	p.Uint32(s.serial)
	p.Uint32(uint32(s.refresh / time.Second))
	p.Uint32(uint32(s.retry / time.Second))
	p.Uint32(uint32(s.expire / time.Second))
	p.Uint32(uint32(s.minimum / time.Second))
}

// NewSOA returns an SOA rdata.
func NewSOA(mname, rname dnsname.Name, serial uint32, refresh, retry, expire, minimum time.Duration) SOA {
	return soa{
		mname: mname, rname: rname, serial: serial,
		refresh: refresh, retry: retry, expire: expire, minimum: minimum,
	}
}

func unpackSOA(u *wire.Unpacker) (SOA, error) {
	mname, err := u.Name()
	if err != nil {
		return nil, err
	}
	rname, err := u.Name()
	if err != nil {
		return nil, err
	}
	serial, err := u.Uint32()
	if err != nil {
		return nil, err
	}
	refresh, err := u.Uint32()
	if err != nil {
		return nil, err
	}
	retry, err := u.Uint32()
	if err != nil {
		return nil, err
	}
	expire, err := u.Uint32()
	if err != nil {
		return nil, err
	}
	minimum, err := u.Uint32()
	if err != nil {
		return nil, err
	}
	return soa{
		mname:   mname,
		rname:   rname,
		serial:  serial,
		refresh: time.Duration(refresh) * time.Second,
		retry:   time.Duration(retry) * time.Second,
		expire:  time.Duration(expire) * time.Second,
		minimum: time.Duration(minimum) * time.Second,
	}, nil
}
