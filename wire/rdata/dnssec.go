package rdata

import (
	"fmt"
	"slices"
	"time"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// DNSSECAlgorithm enumerates the values from the IANA DNSSEC Algorithm
// Numbers registry (RFC 8624 §3.1).
//
// Algorithms 1, 3, 5, 6, 7 are listed for completeness only. Per RFC 8624
// they are MUST NOT for signing; verification of legacy zones may still
// require recognising them. Library verification primitives only support
// the modern algorithms (RSASHA256, RSASHA512, ECDSAP256, ECDSAP384,
// Ed25519); attempts to verify with a deprecated algorithm return
// ErrUnsupportedAlgorithm.
type DNSSECAlgorithm uint8

const (
	AlgRSAMD5           DNSSECAlgorithm = 1  // RFC 2537 / 3110 — deprecated
	AlgDH               DNSSECAlgorithm = 2  // RFC 2539 — deprecated
	AlgDSA              DNSSECAlgorithm = 3  // RFC 2536 — deprecated
	AlgRSASHA1          DNSSECAlgorithm = 5  // RFC 3110 — discouraged
	AlgDSANSEC3SHA1     DNSSECAlgorithm = 6  // RFC 5155 — deprecated
	AlgRSASHA1NSEC3SHA1 DNSSECAlgorithm = 7  // RFC 5155 — discouraged
	AlgRSASHA256        DNSSECAlgorithm = 8  // RFC 5702
	AlgRSASHA512        DNSSECAlgorithm = 10 // RFC 5702
	AlgECCGOST          DNSSECAlgorithm = 12 // RFC 5933 — deprecated
	AlgECDSAP256SHA256  DNSSECAlgorithm = 13 // RFC 6605
	AlgECDSAP384SHA384  DNSSECAlgorithm = 14 // RFC 6605
	AlgED25519          DNSSECAlgorithm = 15 // RFC 8080
	AlgED448            DNSSECAlgorithm = 16 // RFC 8080
)

// DSDigestType enumerates the digest types of a DS RR (RFC 4509, RFC 6605).
type DSDigestType uint8

const (
	DigestSHA1   DSDigestType = 1
	DigestSHA256 DSDigestType = 2
	DigestSHA384 DSDigestType = 4
)

// DNSKEY flag bit positions (RFC 4034 §2.1.1, post-RFC 3445 simplification
// where the historical KEY flag space was narrowed to DNS zone signing
// usage). Use these masks against the value returned by DNSKEY.Flags.
const (
	// DNSKEYFlagZone marks a key as a zone key (bit 7 in network byte
	// order — the high bit of the second flag byte).
	DNSKEYFlagZone uint16 = 0x0100
	// DNSKEYFlagRevoke marks a key as revoked (RFC 5011 §2.1).
	DNSKEYFlagRevoke uint16 = 0x0080
	// DNSKEYFlagSEP marks a key as a Secure Entry Point (RFC 4034 §2.1.1
	// + RFC 3757). Conventionally set on KSKs.
	DNSKEYFlagSEP uint16 = 0x0001
)

// DNSKEY is the DNSSEC public key rdata (RFC 4034 §2).
type DNSKEY struct {
	flags     uint16
	protocol  uint8
	algorithm DNSSECAlgorithm
	pubkey    []byte
}

func (DNSKEY) Type() rrtype.Type            { return rrtype.DNSKEY }
func (DNSKEY) typedRData()                  {}
func (k DNSKEY) Flags() uint16              { return k.flags }
func (k DNSKEY) Protocol() uint8            { return k.protocol }
func (k DNSKEY) Algorithm() DNSSECAlgorithm { return k.algorithm }
func (k DNSKEY) PublicKey() []byte          { return k.pubkey }
func (k DNSKEY) Pack(p *wirebb.Packer) {
	p.Uint16(k.flags)
	p.Uint8(k.protocol)
	p.Uint8(uint8(k.algorithm))
	p.Raw(k.pubkey)
}

// NewDNSKEY returns a DNSKEY rdata.
func NewDNSKEY(flags uint16, protocol uint8, algorithm DNSSECAlgorithm, pubkey []byte) DNSKEY {
	cp := make([]byte, len(pubkey))
	copy(cp, pubkey)
	return DNSKEY{flags: flags, protocol: protocol, algorithm: algorithm, pubkey: cp}
}

func unpackDNSKEY(u *wirebb.Unpacker, rdlen int) (DNSKEY, error) {
	var zero DNSKEY
	end := u.Off() + rdlen
	flags, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	proto, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	alg, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	pk, err := u.Bytes(end - u.Off())
	if err != nil {
		return zero, err
	}
	cp := make([]byte, len(pk))
	copy(cp, pk)
	return DNSKEY{flags: flags, protocol: proto, algorithm: DNSSECAlgorithm(alg), pubkey: cp}, nil
}

// DS is the delegation signer rdata (RFC 4034 §5).
type DS struct {
	keyTag    uint16
	algorithm DNSSECAlgorithm
	digestT   DSDigestType
	digest    []byte
}

func (DS) Type() rrtype.Type            { return rrtype.DS }
func (DS) typedRData()                  {}
func (d DS) KeyTag() uint16             { return d.keyTag }
func (d DS) Algorithm() DNSSECAlgorithm { return d.algorithm }
func (d DS) DigestType() DSDigestType   { return d.digestT }
func (d DS) Digest() []byte             { return d.digest }
func (d DS) Pack(p *wirebb.Packer) {
	p.Uint16(d.keyTag)
	p.Uint8(uint8(d.algorithm))
	p.Uint8(uint8(d.digestT))
	p.Raw(d.digest)
}

// NewDS returns a DS rdata.
func NewDS(keyTag uint16, alg DNSSECAlgorithm, dt DSDigestType, digest []byte) DS {
	cp := make([]byte, len(digest))
	copy(cp, digest)
	return DS{keyTag: keyTag, algorithm: alg, digestT: dt, digest: cp}
}

func unpackDS(u *wirebb.Unpacker, rdlen int) (DS, error) {
	var zero DS
	end := u.Off() + rdlen
	tag, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	alg, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	dt, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	dig, err := u.Bytes(end - u.Off())
	if err != nil {
		return zero, err
	}
	cp := make([]byte, len(dig))
	copy(cp, dig)
	return DS{keyTag: tag, algorithm: DNSSECAlgorithm(alg), digestT: DSDigestType(dt), digest: cp}, nil
}

// RRSIG is the resource record signature rdata (RFC 4034 §3).
type RRSIG struct {
	typeCovered rrtype.Type
	algorithm   DNSSECAlgorithm
	labels      uint8
	origTTL     uint32
	sigExp      uint32
	sigInc      uint32
	keyTag      uint16
	signerName  wirebb.Name
	signature   []byte
}

func (RRSIG) Type() rrtype.Type                { return rrtype.RRSIG }
func (RRSIG) typedRData()                      {}
func (r RRSIG) TypeCovered() rrtype.Type       { return r.typeCovered }
func (r RRSIG) Algorithm() DNSSECAlgorithm     { return r.algorithm }
func (r RRSIG) Labels() uint8                  { return r.labels }
func (r RRSIG) OriginalTTL() time.Duration     { return time.Duration(r.origTTL) * time.Second }
func (r RRSIG) SignatureExpiration() time.Time { return time.Unix(int64(r.sigExp), 0).UTC() }
func (r RRSIG) SignatureInception() time.Time  { return time.Unix(int64(r.sigInc), 0).UTC() }
func (r RRSIG) KeyTag() uint16                 { return r.keyTag }
func (r RRSIG) SignerName() wirebb.Name        { return r.signerName }
func (r RRSIG) Signature() []byte              { return r.signature }
func (r RRSIG) Pack(p *wirebb.Packer) {
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
	keyTag uint16, signerName wirebb.Name, signature []byte) RRSIG {
	cp := make([]byte, len(signature))
	copy(cp, signature)
	return RRSIG{
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

func unpackRRSIG(u *wirebb.Unpacker, rdlen int) (RRSIG, error) {
	var zero RRSIG
	end := u.Off() + rdlen
	tc, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	alg, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	labels, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	origTTL, err := u.Uint32()
	if err != nil {
		return zero, err
	}
	sigExp, err := u.Uint32()
	if err != nil {
		return zero, err
	}
	sigInc, err := u.Uint32()
	if err != nil {
		return zero, err
	}
	keyTag, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	signer, err := u.Name()
	if err != nil {
		return zero, err
	}
	sig, err := u.Bytes(end - u.Off())
	if err != nil {
		return zero, err
	}
	cp := make([]byte, len(sig))
	copy(cp, sig)
	return RRSIG{
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
type NSEC struct {
	next  wirebb.Name
	types []rrtype.Type
}

func (NSEC) Type() rrtype.Type             { return rrtype.NSEC }
func (NSEC) typedRData()                   {}
func (n NSEC) NextDomainName() wirebb.Name { return n.next }
func (n NSEC) Types() []rrtype.Type        { return n.types }
func (n NSEC) Pack(p *wirebb.Packer) {
	p.NameUncompressed(n.next)
	encodeTypeBitmap(p, n.types)
}

// NewNSEC returns an NSEC rdata.
func NewNSEC(next wirebb.Name, types []rrtype.Type) NSEC {
	cp := append([]rrtype.Type(nil), types...)
	return NSEC{next: next, types: cp}
}

func unpackNSEC(u *wirebb.Unpacker, rdlen int) (NSEC, error) {
	var zero NSEC
	end := u.Off() + rdlen
	next, err := u.Name()
	if err != nil {
		return zero, err
	}
	types, err := decodeTypeBitmap(u, end-u.Off())
	if err != nil {
		return zero, err
	}
	return NSEC{next: next, types: types}, nil
}

// encodeTypeBitmap implements the type-bitmap encoding of RFC 4034 §4.1.2.
func encodeTypeBitmap(p *wirebb.Packer, types []rrtype.Type) {
	if len(types) == 0 {
		return
	}
	sorted := append([]rrtype.Type(nil), types...)
	slices.Sort(sorted)

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

func decodeTypeBitmap(u *wirebb.Unpacker, n int) ([]rrtype.Type, error) {
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
			for bit := range 8 {
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
type NSEC3 struct {
	hashAlg    uint8
	flags      uint8
	iterations uint16
	salt       []byte
	nextOwner  []byte
	types      []rrtype.Type
}

func (NSEC3) Type() rrtype.Type         { return rrtype.NSEC3 }
func (NSEC3) typedRData()               {}
func (n NSEC3) HashAlgorithm() uint8    { return n.hashAlg }
func (n NSEC3) Flags() uint8            { return n.flags }
func (n NSEC3) Iterations() uint16      { return n.iterations }
func (n NSEC3) Salt() []byte            { return n.salt }
func (n NSEC3) NextHashedOwner() []byte { return n.nextOwner }
func (n NSEC3) Types() []rrtype.Type    { return n.types }
func (n NSEC3) Pack(p *wirebb.Packer) {
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
	return NSEC3{
		hashAlg: hashAlg, flags: flags, iterations: iterations,
		salt: saltCp, nextOwner: nextCp, types: tCp,
	}
}

func unpackNSEC3(u *wirebb.Unpacker, rdlen int) (NSEC3, error) {
	var zero NSEC3
	end := u.Off() + rdlen
	alg, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	flags, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	iters, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	saltLen, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	salt, err := u.Bytes(int(saltLen))
	if err != nil {
		return zero, err
	}
	hashLen, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	hash, err := u.Bytes(int(hashLen))
	if err != nil {
		return zero, err
	}
	types, err := decodeTypeBitmap(u, end-u.Off())
	if err != nil {
		return zero, err
	}
	saltCp := make([]byte, len(salt))
	copy(saltCp, salt)
	hashCp := make([]byte, len(hash))
	copy(hashCp, hash)
	return NSEC3{
		hashAlg: alg, flags: flags, iterations: iters,
		salt: saltCp, nextOwner: hashCp, types: types,
	}, nil
}
