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

// NewDNSKEY returns a DNSKEY rdata. The protocol field MUST be 3
// (DNSSEC) per RFC 4034 §2.1.2; other values are rejected because
// they have no defined wire interpretation and would silently
// poison signature-validation downstream.
func NewDNSKEY(flags uint16, protocol uint8, algorithm DNSSECAlgorithm, pubkey []byte) (DNSKEY, error) {
	if protocol != 3 {
		return DNSKEY{}, fmt.Errorf("%w: DNSKEY protocol %d, RFC 4034 §2.1.2 mandates 3", ErrInvalidRData, protocol)
	}
	cp := make([]byte, len(pubkey))
	copy(cp, pubkey)
	return DNSKEY{flags: flags, protocol: protocol, algorithm: algorithm, pubkey: cp}, nil
}
func unpackDNSKEY(u *wirebb.Unpacker, rdlen int) (DNSKEY, error) {
	var zero DNSKEY
	if rdlen < 4 {
		return zero, fmt.Errorf("%w: DNSKEY rdlen %d below minimum 4", ErrInvalidRData, rdlen)
	}
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

// dsDigestLen returns the expected digest length in bytes for the
// digest types this package knows about. Returns 0 for unknown types
// (no validation enforced for digest types this package does not
// implement; the receiver still parses them, it just cannot validate
// the digest length).
func dsDigestLen(dt DSDigestType) int {
	switch dt {
	case DigestSHA1:
		return 20
	case DigestSHA256:
		return 32
	case DigestSHA384:
		return 48
	}
	return 0
}

// NewDS returns a DS rdata. The digest length is validated against
// the digest-type field for known types (SHA-1=20, SHA-256=32,
// SHA-384=48 per RFC 4034 §5.1.4 / RFC 4509 / RFC 6605). Unknown
// digest types pass through unvalidated.
func NewDS(keyTag uint16, alg DNSSECAlgorithm, dt DSDigestType, digest []byte) (DS, error) {
	if want := dsDigestLen(dt); want != 0 && len(digest) != want {
		return DS{}, fmt.Errorf("%w: DS digest type %d expects %d bytes, got %d", ErrInvalidRData, dt, want, len(digest))
	}
	cp := make([]byte, len(digest))
	copy(cp, digest)
	return DS{keyTag: keyTag, algorithm: alg, digestT: dt, digest: cp}, nil
}
func unpackDS(u *wirebb.Unpacker, rdlen int) (DS, error) {
	var zero DS
	if rdlen < 4 {
		return zero, fmt.Errorf("%w: DS rdlen %d below minimum 4", ErrInvalidRData, rdlen)
	}
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

// SignatureExpirationRaw returns the on-the-wire 32-bit
// seconds-since-epoch value of the expiration field. RFC 4034 §3.1.5
// requires interpretation under RFC 1982 serial-number arithmetic
// (mod 2³²) — naive [time.Time] comparison silently mis-classifies
// signatures that legitimately span the 2106-02-07 wrap. Validators
// performing inception/expiration bound checks SHOULD compare against
// these raw values, not the time.Time accessor.
func (r RRSIG) SignatureExpirationRaw() uint32 { return r.sigExp }

// SignatureInceptionRaw returns the on-the-wire 32-bit
// seconds-since-epoch value of the inception field. See
// [RRSIG.SignatureExpirationRaw] for why callers should prefer this
// over the time.Time form.
func (r RRSIG) SignatureInceptionRaw() uint32 { return r.sigInc }
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
	// RRSIG fixed header: 2+1+1+4+4+4+2 = 18 bytes, then signer name
	// (≥ 1 byte for the root label), then signature (≥ 0 bytes per
	// the algorithm). Reject anything that can't even hold the
	// fixed header + a one-byte root signer.
	if rdlen < 19 {
		return zero, fmt.Errorf("%w: RRSIG rdlen %d below minimum 19", ErrInvalidRData, rdlen)
	}
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
	signer, err := u.UncompressedName(end - u.Off())
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
	next, err := u.UncompressedName(end - u.Off())
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
	// RFC 4034 §4.1.2 mandates that bitmap window blocks appear in
	// strictly increasing order of window number with no duplicates.
	// Permitting non-canonical ordering or duplicates lets a hostile
	// authoritative craft an NSEC the resolver accepts but a peer
	// using a strict decoder rejects, opening a small canonicalisation
	// attack surface. Track the last-seen window and reject any block
	// that violates the ordering.
	lastWin := -1
	first := true
	for u.Off() < end {
		win, err := u.Uint8()
		if err != nil {
			return nil, err
		}
		if !first && int(win) <= lastWin {
			return nil, fmt.Errorf("%w: NSEC bitmap windows out of order (saw %d after %d)", ErrInvalidRData, win, lastWin)
		}
		first = false
		lastWin = int(win)
		ln, err := u.Uint8()
		if err != nil {
			return nil, err
		}
		if ln == 0 || ln > 32 {
			return nil, fmt.Errorf("%w: NSEC bitmap length %d", ErrInvalidRData, ln)
		}
		// Bound the bitmap read against the rdata window. u.Bytes only
		// checks the message-wide bound, so a truncated rdata where the
		// declared bitmap length runs past the window's end would
		// silently consume bytes belonging to the next record before
		// the outer rdlen check catches the off!=end mismatch. Reject
		// here so the failure surfaces at the per-record level instead.
		if u.Off()+int(ln) > end {
			return nil, fmt.Errorf("%w: NSEC bitmap length %d exceeds rdata window", ErrInvalidRData, ln)
		}
		bm, err := u.Bytes(int(ln))
		if err != nil {
			return nil, err
		}
		for i := range int(ln) {
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

// NSEC3HashAlgorithm is the IANA NSEC3-Hash-Algorithms registry value
// (RFC 5155 §11.2). SHA-1 is the only registered algorithm.
type NSEC3HashAlgorithm uint8

// NSEC3HashSHA1 is the only NSEC3 hash algorithm registered with IANA
// (RFC 5155 §11.2).
const NSEC3HashSHA1 NSEC3HashAlgorithm = 1

// String returns a short human-readable name for the algorithm.
func (a NSEC3HashAlgorithm) String() string {
	if a == NSEC3HashSHA1 {
		return "SHA1"
	}
	return fmt.Sprintf("NSEC3-Hash-%d", uint8(a))
}

// NSEC3 is the hashed authenticated denial-of-existence rdata
// (RFC 5155 §3.2). Salt and NextHashedOwner are stored as raw bytes; the
// caller is responsible for any base32hex encoding.
type NSEC3 struct {
	hashAlg    NSEC3HashAlgorithm
	flags      uint8
	iterations uint16
	salt       []byte
	nextOwner  []byte
	types      []rrtype.Type
}

func (NSEC3) Type() rrtype.Type                 { return rrtype.NSEC3 }
func (NSEC3) typedRData()                       {}
func (n NSEC3) HashAlgorithm() NSEC3HashAlgorithm { return n.hashAlg }
func (n NSEC3) Flags() uint8            { return n.flags }
func (n NSEC3) Iterations() uint16      { return n.iterations }
func (n NSEC3) Salt() []byte            { return n.salt }
func (n NSEC3) NextHashedOwner() []byte { return n.nextOwner }
func (n NSEC3) Types() []rrtype.Type    { return n.types }
func (n NSEC3) Pack(p *wirebb.Packer) {
	p.Uint8(uint8(n.hashAlg))
	p.Uint8(n.flags)
	p.Uint16(n.iterations)
	p.Uint8(uint8(len(n.salt)))
	p.Raw(n.salt)
	p.Uint8(uint8(len(n.nextOwner)))
	p.Raw(n.nextOwner)
	encodeTypeBitmap(p, n.types)
}

// NewNSEC3 returns an NSEC3 rdata. Returns [ErrInvalidRData] when
// salt or nextOwner exceeds 255 bytes (RFC 5155 §3.1: both lengths
// are wire-encoded as uint8) or when nextOwner is empty (RFC 5155
// §3.1.7: the field carries a binary hash output, 0-byte is
// structurally invalid).
func NewNSEC3(hashAlg NSEC3HashAlgorithm, flags uint8, iterations uint16, salt, nextOwner []byte, types []rrtype.Type) (NSEC3, error) {
	if len(salt) > 255 {
		return NSEC3{}, fmt.Errorf("%w: NSEC3 salt %d bytes exceeds 255-byte limit", ErrInvalidRData, len(salt))
	}
	// A 0-byte next-hashed-owner can't be a real hash; passing it
	// through to a validator's NSEC3-chain compare path would silently
	// match any input. Reject at construction so downstream code can
	// rely on len(nextOwner) > 0.
	if len(nextOwner) == 0 {
		return NSEC3{}, fmt.Errorf("%w: NSEC3 next-hashed-owner is empty", ErrInvalidRData)
	}
	if len(nextOwner) > 255 {
		return NSEC3{}, fmt.Errorf("%w: NSEC3 next-hashed-owner %d bytes exceeds 255-byte limit", ErrInvalidRData, len(nextOwner))
	}
	saltCp := append([]byte(nil), salt...)
	nextCp := append([]byte(nil), nextOwner...)
	tCp := append([]rrtype.Type(nil), types...)
	return NSEC3{
		hashAlg: hashAlg, flags: flags, iterations: iterations,
		salt: saltCp, nextOwner: nextCp, types: tCp,
	}, nil
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
	if u.Off()+int(saltLen) > end {
		return zero, fmt.Errorf("%w: NSEC3 salt length %d exceeds rdata window", ErrInvalidRData, saltLen)
	}
	salt, err := u.Bytes(int(saltLen))
	if err != nil {
		return zero, err
	}
	hashLen, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	// RFC 5155 §3.1.7: the next-hashed-owner field is a binary hash —
	// 0 bytes is structurally invalid. Reject early so the validator
	// never compares against a zero-length "hash".
	if hashLen == 0 {
		return zero, fmt.Errorf("%w: NSEC3 next-hashed-owner length 0", ErrInvalidRData)
	}
	if u.Off()+int(hashLen) > end {
		return zero, fmt.Errorf("%w: NSEC3 hash length %d exceeds rdata window", ErrInvalidRData, hashLen)
	}
	hash, err := u.Bytes(int(hashLen))
	if err != nil {
		return zero, err
	}
	if u.Off() > end {
		return zero, fmt.Errorf("%w: NSEC3 over-read", ErrInvalidRData)
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
		hashAlg: NSEC3HashAlgorithm(alg), flags: flags, iterations: iters,
		salt: saltCp, nextOwner: hashCp, types: types,
	}, nil
}
