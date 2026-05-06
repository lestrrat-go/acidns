package rdata

import (
	"fmt"
	"sort"
	"time"

	"github.com/lestrrat-go/acidns/dnsmsg/internal/wire"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
)

// DNSSECAlgorithm enumerates the values from the IANA DNSSEC Algorithm
// Numbers registry (RFC 8624 §3.1).
type DNSSECAlgorithm uint8

const (
	AlgRSASHA1         DNSSECAlgorithm = 5
	AlgRSASHA256       DNSSECAlgorithm = 8
	AlgRSASHA512       DNSSECAlgorithm = 10
	AlgECDSAP256SHA256 DNSSECAlgorithm = 13
	AlgECDSAP384SHA384 DNSSECAlgorithm = 14
	AlgED25519         DNSSECAlgorithm = 15
	AlgED448           DNSSECAlgorithm = 16
)

// DSDigestType enumerates the digest types of a DS RR (RFC 4509, RFC 6605).
type DSDigestType uint8

const (
	DigestSHA1   DSDigestType = 1
	DigestSHA256 DSDigestType = 2
	DigestSHA384 DSDigestType = 4
)

// DNSKEY is the DNSSEC public key rdata (RFC 4034 §2).
type DNSKEY interface {
	RData
	Flags() uint16
	Protocol() uint8
	Algorithm() DNSSECAlgorithm
	PublicKey() []byte
}

type dnskey struct {
	flags     uint16
	protocol  uint8
	algorithm DNSSECAlgorithm
	pubkey    []byte
}

func (dnskey) Type() rrtype.Type            { return rrtype.DNSKEY }
func (k dnskey) Flags() uint16              { return k.flags }
func (k dnskey) Protocol() uint8            { return k.protocol }
func (k dnskey) Algorithm() DNSSECAlgorithm { return k.algorithm }
func (k dnskey) PublicKey() []byte          { return k.pubkey }
func (k dnskey) Pack(p *wire.Packer) {
	p.Uint16(k.flags)
	p.Uint8(k.protocol)
	p.Uint8(uint8(k.algorithm))
	p.Raw(k.pubkey)
}

// NewDNSKEY returns a DNSKEY rdata.
func NewDNSKEY(flags uint16, protocol uint8, algorithm DNSSECAlgorithm, pubkey []byte) DNSKEY {
	cp := make([]byte, len(pubkey))
	copy(cp, pubkey)
	return dnskey{flags: flags, protocol: protocol, algorithm: algorithm, pubkey: cp}
}

func unpackDNSKEY(u *wire.Unpacker, rdlen int) (DNSKEY, error) {
	end := u.Off() + rdlen
	flags, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	proto, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	alg, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	pk, err := u.Bytes(end - u.Off())
	if err != nil {
		return nil, err
	}
	cp := make([]byte, len(pk))
	copy(cp, pk)
	return dnskey{flags: flags, protocol: proto, algorithm: DNSSECAlgorithm(alg), pubkey: cp}, nil
}

// DS is the delegation signer rdata (RFC 4034 §5).
type DS interface {
	RData
	KeyTag() uint16
	Algorithm() DNSSECAlgorithm
	DigestType() DSDigestType
	Digest() []byte
}

type dsRec struct {
	keyTag    uint16
	algorithm DNSSECAlgorithm
	digestT   DSDigestType
	digest    []byte
}

func (dsRec) Type() rrtype.Type            { return rrtype.DS }
func (d dsRec) KeyTag() uint16             { return d.keyTag }
func (d dsRec) Algorithm() DNSSECAlgorithm { return d.algorithm }
func (d dsRec) DigestType() DSDigestType   { return d.digestT }
func (d dsRec) Digest() []byte             { return d.digest }
func (d dsRec) Pack(p *wire.Packer) {
	p.Uint16(d.keyTag)
	p.Uint8(uint8(d.algorithm))
	p.Uint8(uint8(d.digestT))
	p.Raw(d.digest)
}

// NewDS returns a DS rdata.
func NewDS(keyTag uint16, alg DNSSECAlgorithm, dt DSDigestType, digest []byte) DS {
	cp := make([]byte, len(digest))
	copy(cp, digest)
	return dsRec{keyTag: keyTag, algorithm: alg, digestT: dt, digest: cp}
}

func unpackDS(u *wire.Unpacker, rdlen int) (DS, error) {
	end := u.Off() + rdlen
	tag, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	alg, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	dt, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	dig, err := u.Bytes(end - u.Off())
	if err != nil {
		return nil, err
	}
	cp := make([]byte, len(dig))
	copy(cp, dig)
	return dsRec{keyTag: tag, algorithm: DNSSECAlgorithm(alg), digestT: DSDigestType(dt), digest: cp}, nil
}

// RRSIG is the resource record signature rdata (RFC 4034 §3).
type RRSIG interface {
	RData
	TypeCovered() rrtype.Type
	Algorithm() DNSSECAlgorithm
	Labels() uint8
	OriginalTTL() time.Duration
	SignatureExpiration() time.Time
	SignatureInception() time.Time
	KeyTag() uint16
	SignerName() dnsname.Name
	Signature() []byte
}

type rrsig struct {
	typeCovered rrtype.Type
	algorithm   DNSSECAlgorithm
	labels      uint8
	origTTL     uint32
	sigExp      uint32
	sigInc      uint32
	keyTag      uint16
	signerName  dnsname.Name
	signature   []byte
}

func (rrsig) Type() rrtype.Type                { return rrtype.RRSIG }
func (r rrsig) TypeCovered() rrtype.Type       { return r.typeCovered }
func (r rrsig) Algorithm() DNSSECAlgorithm     { return r.algorithm }
func (r rrsig) Labels() uint8                  { return r.labels }
func (r rrsig) OriginalTTL() time.Duration     { return time.Duration(r.origTTL) * time.Second }
func (r rrsig) SignatureExpiration() time.Time { return time.Unix(int64(r.sigExp), 0).UTC() }
func (r rrsig) SignatureInception() time.Time  { return time.Unix(int64(r.sigInc), 0).UTC() }
func (r rrsig) KeyTag() uint16                 { return r.keyTag }
func (r rrsig) SignerName() dnsname.Name       { return r.signerName }
func (r rrsig) Signature() []byte              { return r.signature }
func (r rrsig) Pack(p *wire.Packer) {
	p.Uint16(uint16(r.typeCovered))
	p.Uint8(uint8(r.algorithm))
	p.Uint8(r.labels)
	p.Uint32(r.origTTL)
	p.Uint32(r.sigExp)
	p.Uint32(r.sigInc)
	p.Uint16(r.keyTag)
	p.NameUncompressed(r.signerName)
	p.Raw(r.signature)
}

// NewRRSIG constructs an RRSIG. expiration/inception are stored as the
// 32-bit absolute seconds-since-epoch values defined by RFC 4034 §3.1.5.
func NewRRSIG(typeCovered rrtype.Type, alg DNSSECAlgorithm, labels uint8,
	origTTL time.Duration, expiration, inception time.Time,
	keyTag uint16, signerName dnsname.Name, signature []byte) RRSIG {
	cp := make([]byte, len(signature))
	copy(cp, signature)
	return rrsig{
		typeCovered: typeCovered,
		algorithm:   alg,
		labels:      labels,
		origTTL:     uint32(origTTL / time.Second),
		sigExp:      uint32(expiration.Unix()),
		sigInc:      uint32(inception.Unix()),
		keyTag:      keyTag,
		signerName:  signerName,
		signature:   cp,
	}
}

func unpackRRSIG(u *wire.Unpacker, rdlen int) (RRSIG, error) {
	end := u.Off() + rdlen
	tc, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	alg, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	labels, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	origTTL, err := u.Uint32()
	if err != nil {
		return nil, err
	}
	sigExp, err := u.Uint32()
	if err != nil {
		return nil, err
	}
	sigInc, err := u.Uint32()
	if err != nil {
		return nil, err
	}
	keyTag, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	signer, err := u.Name()
	if err != nil {
		return nil, err
	}
	sig, err := u.Bytes(end - u.Off())
	if err != nil {
		return nil, err
	}
	cp := make([]byte, len(sig))
	copy(cp, sig)
	return rrsig{
		typeCovered: rrtype.Type(tc),
		algorithm:   DNSSECAlgorithm(alg),
		labels:      labels,
		origTTL:     origTTL,
		sigExp:      sigExp,
		sigInc:      sigInc,
		keyTag:      keyTag,
		signerName:  signer,
		signature:   cp,
	}, nil
}

// NSEC is the next secure rdata (RFC 4034 §4).
type NSEC interface {
	RData
	NextDomainName() dnsname.Name
	Types() []rrtype.Type
}

type nsec struct {
	next  dnsname.Name
	types []rrtype.Type
}

func (nsec) Type() rrtype.Type              { return rrtype.NSEC }
func (n nsec) NextDomainName() dnsname.Name { return n.next }
func (n nsec) Types() []rrtype.Type         { return n.types }
func (n nsec) Pack(p *wire.Packer) {
	p.NameUncompressed(n.next)
	encodeTypeBitmap(p, n.types)
}

// NewNSEC returns an NSEC rdata.
func NewNSEC(next dnsname.Name, types []rrtype.Type) NSEC {
	cp := append([]rrtype.Type(nil), types...)
	return nsec{next: next, types: cp}
}

func unpackNSEC(u *wire.Unpacker, rdlen int) (NSEC, error) {
	end := u.Off() + rdlen
	next, err := u.Name()
	if err != nil {
		return nil, err
	}
	types, err := decodeTypeBitmap(u, end-u.Off())
	if err != nil {
		return nil, err
	}
	return nsec{next: next, types: types}, nil
}

// encodeTypeBitmap implements the type-bitmap encoding of RFC 4034 §4.1.2.
func encodeTypeBitmap(p *wire.Packer, types []rrtype.Type) {
	if len(types) == 0 {
		return
	}
	sorted := append([]rrtype.Type(nil), types...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	// Bucket by window (high byte of type).
	type bucket struct {
		win    uint8
		bitmap []byte
	}
	var buckets []bucket
	for _, t := range sorted {
		win := uint8(t >> 8)
		idx := -1
		for i := range buckets {
			if buckets[i].win == win {
				idx = i
				break
			}
		}
		if idx < 0 {
			buckets = append(buckets, bucket{win: win, bitmap: make([]byte, 32)})
			idx = len(buckets) - 1
		}
		bit := uint8(t & 0xff)
		buckets[idx].bitmap[bit/8] |= 1 << (7 - bit%8)
	}
	for _, b := range buckets {
		// Trim trailing zero bytes; minimum length 1.
		ln := 32
		for ln > 1 && b.bitmap[ln-1] == 0 {
			ln--
		}
		p.Uint8(b.win)
		p.Uint8(uint8(ln))
		p.Raw(b.bitmap[:ln])
	}
}

func decodeTypeBitmap(u *wire.Unpacker, n int) ([]rrtype.Type, error) {
	end := u.Off() + n
	var out []rrtype.Type
	for u.Off() < end {
		win, err := u.Uint8()
		if err != nil {
			return nil, err
		}
		ln, err := u.Uint8()
		if err != nil {
			return nil, err
		}
		if ln == 0 || ln > 32 {
			return nil, fmt.Errorf("%w: NSEC bitmap length %d", ErrInvalidRData, ln)
		}
		bm, err := u.Bytes(int(ln))
		if err != nil {
			return nil, err
		}
		for i := 0; i < int(ln); i++ {
			b := bm[i]
			for bit := 0; bit < 8; bit++ {
				if b&(1<<(7-bit)) != 0 {
					t := uint16(win)<<8 | uint16(i*8+bit)
					out = append(out, rrtype.Type(t))
				}
			}
		}
	}
	return out, nil
}

// NSEC3 is the hashed authenticated denial-of-existence rdata
// (RFC 5155 §3.2). Salt and NextHashedOwner are stored as raw bytes; the
// caller is responsible for any base32hex encoding.
type NSEC3 interface {
	RData
	HashAlgorithm() uint8
	Flags() uint8
	Iterations() uint16
	Salt() []byte
	NextHashedOwner() []byte
	Types() []rrtype.Type
}

type nsec3 struct {
	hashAlg    uint8
	flags      uint8
	iterations uint16
	salt       []byte
	nextOwner  []byte
	types      []rrtype.Type
}

func (nsec3) Type() rrtype.Type         { return rrtype.NSEC3 }
func (n nsec3) HashAlgorithm() uint8    { return n.hashAlg }
func (n nsec3) Flags() uint8            { return n.flags }
func (n nsec3) Iterations() uint16      { return n.iterations }
func (n nsec3) Salt() []byte            { return n.salt }
func (n nsec3) NextHashedOwner() []byte { return n.nextOwner }
func (n nsec3) Types() []rrtype.Type    { return n.types }
func (n nsec3) Pack(p *wire.Packer) {
	p.Uint8(n.hashAlg)
	p.Uint8(n.flags)
	p.Uint16(n.iterations)
	p.Uint8(uint8(len(n.salt)))
	p.Raw(n.salt)
	p.Uint8(uint8(len(n.nextOwner)))
	p.Raw(n.nextOwner)
	encodeTypeBitmap(p, n.types)
}

// NewNSEC3 returns an NSEC3 rdata.
func NewNSEC3(hashAlg, flags uint8, iterations uint16, salt, nextOwner []byte, types []rrtype.Type) NSEC3 {
	saltCp := append([]byte(nil), salt...)
	nextCp := append([]byte(nil), nextOwner...)
	tCp := append([]rrtype.Type(nil), types...)
	return nsec3{
		hashAlg: hashAlg, flags: flags, iterations: iterations,
		salt: saltCp, nextOwner: nextCp, types: tCp,
	}
}

func unpackNSEC3(u *wire.Unpacker, rdlen int) (NSEC3, error) {
	end := u.Off() + rdlen
	alg, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	flags, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	iters, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	saltLen, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	salt, err := u.Bytes(int(saltLen))
	if err != nil {
		return nil, err
	}
	hashLen, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	hash, err := u.Bytes(int(hashLen))
	if err != nil {
		return nil, err
	}
	types, err := decodeTypeBitmap(u, end-u.Off())
	if err != nil {
		return nil, err
	}
	saltCp := make([]byte, len(salt))
	copy(saltCp, salt)
	hashCp := make([]byte, len(hash))
	copy(hashCp, hash)
	return nsec3{
		hashAlg: alg, flags: flags, iterations: iters,
		salt: saltCp, nextOwner: hashCp, types: types,
	}, nil
}
