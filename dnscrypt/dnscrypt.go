// Package dnscrypt implements the DNSCrypt v2 protocol — an encrypted
// transport for DNS queries between a client and a resolver. The msg
// format is the format documented at https://dnscrypt.info/protocol
// (DNSCrypt is not standardised by any RFC; the protocol is defined by
// its reference implementation).
//
// Two pieces are exposed:
//
//   - Cert: the in-band certificate the resolver advertises via a TXT
//     record at "2.dnscrypt-cert.<provider>", together with helpers to
//     parse and verify it against a known provider Ed25519 public key.
//   - Exchanger: a acidns.Exchanger that encrypts queries and
//     decrypts responses using the certificate's short-term key.
//
// Only ES version 2 (X25519 + XChaCha20-Poly1305) is implemented; the
// older ES version 1 (X25519-XSalsa20-Poly1305) is not.
package dnscrypt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/option/v3"
)

// Certificate magic values.
var (
	certMagic     = [4]byte{'D', 'N', 'S', 'C'}
	resolverMagic = [8]byte{'r', '6', 'f', 'n', 'v', 'W', 'j', '8'}
)

// ESVersion is the cryptographic suite advertised in a DNSCrypt cert.
type ESVersion uint16

const (
	// ESVersion1 selects X25519-XSalsa20-Poly1305 (legacy, not implemented here).
	ESVersion1 ESVersion = 1
	// ESVersion2 selects X25519-XChaCha20-Poly1305 (current default).
	ESVersion2 ESVersion = 2
)

// Errors.
var (
	ErrCertMagicMismatch    = errors.New("dnscrypt: cert magic mismatch")
	ErrCertSignatureInvalid = errors.New("dnscrypt: cert signature invalid")
	ErrCertExpired          = errors.New("dnscrypt: cert outside validity window")
	ErrUnsupportedESVersion = errors.New("dnscrypt: unsupported ES version")
	ErrResponseMagic        = errors.New("dnscrypt: bad resolver magic in response")
	ErrPlainTextTooShort    = errors.New("dnscrypt: response too short")
	ErrCertUnverified       = errors.New("dnscrypt: cert not verified — call Cert.Verify first")
	ErrCertRequired         = errors.New("dnscrypt: NewClient requires WithCertificate")
	// ErrLowOrderPoint indicates the X25519 shared-secret derivation
	// produced an all-zero output, which means the peer supplied a
	// Curve25519 low-order point. Accepting such a key would AEAD
	// with a known-constant secret.
	ErrLowOrderPoint = errors.New("dnscrypt: x25519 low-order point: shared secret is all zero")
)

// Cert is a parsed DNSCrypt certificate (124 bytes on the wire). The
// fields are unexported so a verified cert cannot be mutated after
// it leaves [ParseCert] — a mutation would silently break the
// signature relationship a downstream Encrypt/Decrypt depends on.
// Tests and fake responders that need to construct a cert from
// components use [NewCert]; signing and serialisation use the
// package-level [SignCert] and [EncodeCert].
type Cert struct {
	esVersion     ESVersion
	protocolMinor uint16
	signature     [64]byte
	resolverPK    [32]byte // X25519 short-term public key
	clientMagic   [8]byte
	serial        uint32
	validFrom     time.Time
	validUntil    time.Time
	// verified is set true only by Verify() on a successful signature
	// check (or by SignCert when a fake/test cert is locally signed).
	// NewClient refuses to construct an Exchanger from an unverified cert
	// so a caller cannot accidentally bypass the signature check that
	// is the entire point of DNSCrypt.
	verified bool
}

// NewCert returns an unsigned Cert populated from the supplied
// options. The caller passes the result to [SignCert] (with the
// provider's long-term private key) before serialising or using it.
//
// Required: WithCertResolverPK, WithCertClientMagic,
// WithCertValidFrom, WithCertValidUntil. Defaults: ESVersion2,
// protocol minor 0, serial 0.
//
// Production code does NOT call this — verified certs come from
// [ParseCert] over a wire blob. NewCert is provided for tests, fake
// responders, and offline tooling.
func NewCert(opts ...CertOption) (*Cert, error) {
	c := certConfig{esVersion: ESVersion2}
	for _, o := range opts {
		switch o.Ident() {
		case identCertESVersion{}:
			c.esVersion = option.MustGet[ESVersion](o)
		case identCertProtocolMinor{}:
			c.protocolMinor = option.MustGet[uint16](o)
		case identCertResolverPK{}:
			c.resolverPK = option.MustGet[[32]byte](o)
			c.resolverPKSet = true
		case identCertClientMagic{}:
			c.clientMagic = option.MustGet[[8]byte](o)
			c.clientMagicSet = true
		case identCertSerial{}:
			c.serial = option.MustGet[uint32](o)
		case identCertValidFrom{}:
			c.validFrom = option.MustGet[time.Time](o)
			c.validFromSet = true
		case identCertValidUntil{}:
			c.validUntil = option.MustGet[time.Time](o)
			c.validUntilSet = true
		}
	}
	if !c.resolverPKSet {
		return nil, fmt.Errorf("dnscrypt: NewCert requires WithCertResolverPK")
	}
	if !c.clientMagicSet {
		return nil, fmt.Errorf("dnscrypt: NewCert requires WithCertClientMagic")
	}
	if !c.validFromSet {
		return nil, fmt.Errorf("dnscrypt: NewCert requires WithCertValidFrom")
	}
	if !c.validUntilSet {
		return nil, fmt.Errorf("dnscrypt: NewCert requires WithCertValidUntil")
	}
	if c.validUntil.Before(c.validFrom) {
		return nil, fmt.Errorf("dnscrypt: NewCert validUntil precedes validFrom")
	}
	return &Cert{
		esVersion:     c.esVersion,
		protocolMinor: c.protocolMinor,
		resolverPK:    c.resolverPK,
		clientMagic:   c.clientMagic,
		serial:        c.serial,
		validFrom:     c.validFrom,
		validUntil:    c.validUntil,
	}, nil
}

// ESVersion returns the ES version number from the cert.
func (c *Cert) ESVersion() ESVersion { return c.esVersion }

// ProtocolMinor returns the protocol minor field.
func (c *Cert) ProtocolMinor() uint16 { return c.protocolMinor }

// Signature returns a copy of the 64-byte Ed25519 signature.
func (c *Cert) Signature() [64]byte { return c.signature }

// ResolverPK returns a copy of the resolver's short-term X25519
// public key.
func (c *Cert) ResolverPK() [32]byte { return c.resolverPK }

// ClientMagic returns a copy of the 8-byte client-magic prefix used
// to tag every query encrypted under this cert.
func (c *Cert) ClientMagic() [8]byte { return c.clientMagic }

// Serial returns the cert's serial number.
func (c *Cert) Serial() uint32 { return c.serial }

// ValidFrom returns the start of the cert's validity window (UTC).
func (c *Cert) ValidFrom() time.Time { return c.validFrom }

// ValidUntil returns the end of the cert's validity window (UTC).
func (c *Cert) ValidUntil() time.Time { return c.validUntil }

// ParseCert decodes a 124-byte certificate blob.
func ParseCert(b []byte) (*Cert, error) {
	if len(b) < 124 {
		return nil, fmt.Errorf("dnscrypt: cert too short (%d bytes)", len(b))
	}
	if !bytes.Equal(b[0:4], certMagic[:]) {
		return nil, ErrCertMagicMismatch
	}
	c := &Cert{
		esVersion:     ESVersion(binary.BigEndian.Uint16(b[4:6])),
		protocolMinor: binary.BigEndian.Uint16(b[6:8]),
	}
	copy(c.signature[:], b[8:72])
	copy(c.resolverPK[:], b[72:104])
	copy(c.clientMagic[:], b[104:112])
	c.serial = binary.BigEndian.Uint32(b[112:116])
	c.validFrom = time.Unix(int64(binary.BigEndian.Uint32(b[116:120])), 0).UTC()
	c.validUntil = time.Unix(int64(binary.BigEndian.Uint32(b[120:124])), 0).UTC()
	return c, nil
}

// Verify checks the cert's Ed25519 signature against the provider's
// long-term public key (32 bytes) and confirms the validity window
// covers now. Returns nil on success.
//
// Order matters: cheap structural checks (ES version, validity window)
// run first so a cert with an unsupported version or out-of-window
// timestamp does not consume Ed25519 verification CPU.
func (c *Cert) Verify(providerPK ed25519.PublicKey, now time.Time) error {
	if c.esVersion != ESVersion2 {
		return fmt.Errorf("%w: ES%d", ErrUnsupportedESVersion, c.esVersion)
	}
	if now.Before(c.validFrom) || now.After(c.validUntil) {
		return fmt.Errorf("%w: now=%s window=[%s, %s]", ErrCertExpired, now, c.validFrom, c.validUntil)
	}
	signed := make([]byte, 0, 52)
	signed = append(signed, c.resolverPK[:]...)
	signed = append(signed, c.clientMagic[:]...)
	var nums [12]byte
	binary.BigEndian.PutUint32(nums[0:], c.serial)
	binary.BigEndian.PutUint32(nums[4:], uint32(c.validFrom.Unix()))
	binary.BigEndian.PutUint32(nums[8:], uint32(c.validUntil.Unix()))
	signed = append(signed, nums[:]...)

	if !ed25519.Verify(providerPK, signed, c.signature[:]) {
		return ErrCertSignatureInvalid
	}
	c.verified = true
	return nil
}

// EncodeCert serialises c back to msg form. Useful for tests that
// build a fake responder.
func EncodeCert(c *Cert) []byte {
	out := make([]byte, 124)
	copy(out[0:4], certMagic[:])
	binary.BigEndian.PutUint16(out[4:], uint16(c.esVersion))
	binary.BigEndian.PutUint16(out[6:], c.protocolMinor)
	copy(out[8:72], c.signature[:])
	copy(out[72:104], c.resolverPK[:])
	copy(out[104:112], c.clientMagic[:])
	binary.BigEndian.PutUint32(out[112:], c.serial)
	binary.BigEndian.PutUint32(out[116:], uint32(c.validFrom.Unix()))
	binary.BigEndian.PutUint32(out[120:], uint32(c.validUntil.Unix()))
	return out
}

// SignCert produces the cert's signature given the resolver's long-term
// private key. Used by tests / fake responders to forge a valid cert.
func SignCert(c *Cert, providerSK ed25519.PrivateKey) {
	signed := make([]byte, 0, 52)
	signed = append(signed, c.resolverPK[:]...)
	signed = append(signed, c.clientMagic[:]...)
	var nums [12]byte
	binary.BigEndian.PutUint32(nums[0:], c.serial)
	binary.BigEndian.PutUint32(nums[4:], uint32(c.validFrom.Unix()))
	binary.BigEndian.PutUint32(nums[8:], uint32(c.validUntil.Unix()))
	signed = append(signed, nums[:]...)
	sig := ed25519.Sign(providerSK, signed)
	copy(c.signature[:], sig)
	// Locally-signed cert: the caller knows-good the signature; allow
	// tests / fake responders to use it via [NewClient] without re-verifying.
	c.verified = true
}

// Encrypt produces a DNSCrypt-formatted query packet.
//
// nonce must be 12 random bytes; the framing pads it to 24 bytes for
// XChaCha20-Poly1305 by appending zeros. The caller is responsible for
// generating a fresh nonce per query.
func Encrypt(c *Cert, clientPK [32]byte, clientSK [32]byte, nonce [12]byte, query []byte) ([]byte, error) {
	if c.esVersion != ESVersion2 {
		return nil, fmt.Errorf("%w: ES%d", ErrUnsupportedESVersion, c.esVersion)
	}
	sharedKey, err := sharedKey(c.resolverPK, clientSK)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(sharedKey[:])
	if err != nil {
		return nil, err
	}

	padded := pad(query)
	var fullNonce [24]byte
	copy(fullNonce[:12], nonce[:])

	ct := aead.Seal(nil, fullNonce[:], padded, nil)

	out := make([]byte, 0, 8+32+12+len(ct))
	out = append(out, c.clientMagic[:]...)
	out = append(out, clientPK[:]...)
	out = append(out, nonce[:]...)
	out = append(out, ct...)
	return out, nil
}

// Decrypt validates and decrypts a DNSCrypt response packet against the
// supplied cert and the client nonce that was used for the query.
func Decrypt(c *Cert, clientSK [32]byte, clientNonce [12]byte, packet []byte) ([]byte, error) {
	if c.esVersion != ESVersion2 {
		return nil, fmt.Errorf("%w: ES%d", ErrUnsupportedESVersion, c.esVersion)
	}
	if len(packet) < 8+12+12 {
		return nil, ErrPlainTextTooShort
	}
	if !bytes.Equal(packet[0:8], resolverMagic[:]) {
		return nil, ErrResponseMagic
	}
	// Constant-time on the client-nonce echo so that response forgery
	// attempts cannot use prefix-match timing as an oracle.
	if subtle.ConstantTimeCompare(packet[8:20], clientNonce[:]) != 1 {
		return nil, fmt.Errorf("dnscrypt: client nonce mismatch")
	}
	var fullNonce [24]byte
	copy(fullNonce[:12], packet[8:20])
	copy(fullNonce[12:], packet[20:32])

	sharedKey, err := sharedKey(c.resolverPK, clientSK)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(sharedKey[:])
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, fullNonce[:], packet[32:], nil)
	if err != nil {
		return nil, fmt.Errorf("dnscrypt: decrypt: %w", err)
	}
	return unpad(plain)
}

// sharedKey performs X25519 between resolverPK and clientSK and returns
// the raw 32-byte shared secret used as the symmetric key. (DNSCrypt v2
// uses the raw X25519 output as the XChaCha20-Poly1305 key — no further
// KDF is applied.)
//
// A peer supplying one of the documented Curve25519 low-order points
// produces an all-zero shared secret. Go's curve25519.X25519 already
// returns ErrInvalidScalar for the most common low-order inputs, but
// the family is broader than that single check; we additionally reject
// any all-zero output via constant-time compare to close the gap.
func sharedKey(resolverPK, clientSK [32]byte) ([32]byte, error) {
	out, err := curve25519.X25519(clientSK[:], resolverPK[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("dnscrypt: x25519: %w", err)
	}
	var k [32]byte
	copy(k[:], out)
	var zero [32]byte
	if subtle.ConstantTimeCompare(k[:], zero[:]) == 1 {
		return [32]byte{}, ErrLowOrderPoint
	}
	return k, nil
}

// pad applies the DNSCrypt padding rules: append 0x80, then NUL bytes
// up to a multiple of 64 bytes.
func pad(query []byte) []byte {
	out := append([]byte(nil), query...)
	out = append(out, 0x80)
	for len(out)%64 != 0 {
		out = append(out, 0)
	}
	return out
}

// unpad reverses pad: strip trailing NULs back to the 0x80 sentinel.
func unpad(b []byte) ([]byte, error) {
	for i := len(b) - 1; i >= 0; i-- {
		switch b[i] {
		case 0x00:
			continue
		case 0x80:
			return b[:i], nil
		default:
			return nil, fmt.Errorf("dnscrypt: bad padding")
		}
	}
	return nil, fmt.Errorf("dnscrypt: padding sentinel not found")
}

type Client struct {
	addr      netip.AddrPort
	cert      *Cert
	timeout   time.Duration
	now       func() time.Time
	clockSkew time.Duration
}

// NewClient returns a *Client that sends DNSCrypt-encrypted queries to
// addr. The verified [*Cert] is supplied via [WithCertificate] and
// is required — see that option for the caller's [Cert.Verify]
// obligation. *Client satisfies [acidns.Exchanger].
func NewClient(addr netip.AddrPort, opts ...Option) (*Client, error) {
	c := config{timeout: 5 * time.Second, now: time.Now, clockSkew: 5 * time.Second}
	for _, o := range opts {
		switch o.Ident() {
		case identCertificate{}:
			c.cert = option.MustGet[*Cert](o)
		case identTimeout{}:
			c.timeout = option.MustGet[time.Duration](o)
		case identClockSkew{}:
			c.clockSkew = option.MustGet[time.Duration](o)
		case identClock{}:
			c.now = option.MustGet[func() time.Time](o)
		}
	}
	if c.cert == nil {
		return nil, ErrCertRequired
	}
	if !c.cert.verified {
		return nil, ErrCertUnverified
	}
	if c.cert.esVersion != ESVersion2 {
		return nil, fmt.Errorf("%w: ES%d", ErrUnsupportedESVersion, c.cert.esVersion)
	}
	if c.now == nil {
		c.now = time.Now
	}
	return &Client{addr: addr, cert: c.cert, timeout: c.timeout, now: c.now, clockSkew: c.clockSkew}, nil
}

// Exchange encrypts q, sends it via UDP, and decrypts the response.
//
// The certificate's validity window is re-checked here against the
// caller-supplied clock so a long-lived Exchanger does not silently
// continue using a cert past ValidUntil. A failed re-check surfaces
// [ErrCertExpired]; the caller is expected to fetch a fresh cert and
// rebuild the Exchanger.
func (e *Client) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	now := e.now()
	if !certWithinWindow(now, e.cert, e.clockSkew) {
		return wire.Message{}, fmt.Errorf("%w: now=%s window=[%s, %s] skew=%s",
			ErrCertExpired, now, e.cert.validFrom, e.cert.validUntil, e.clockSkew)
	}

	msg, err := wire.Pack(q)
	if err != nil {
		return wire.Message{}, fmt.Errorf("dnscrypt: marshal: %w", err)
	}

	var clientSK [32]byte
	if _, err := rand.Read(clientSK[:]); err != nil {
		return wire.Message{}, fmt.Errorf("dnscrypt: rand: %w", err)
	}
	// Zero the ephemeral scalar before return so it does not linger in
	// heap memory longer than this Exchange.
	defer func() {
		for i := range clientSK {
			clientSK[i] = 0
		}
	}()
	var clientPK [32]byte
	pk, err := curve25519.X25519(clientSK[:], curve25519.Basepoint)
	if err != nil {
		return wire.Message{}, err
	}
	copy(clientPK[:], pk)

	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return wire.Message{}, fmt.Errorf("dnscrypt: rand: %w", err)
	}

	enc, err := Encrypt(e.cert, clientPK, clientSK, nonce, msg)
	if err != nil {
		return wire.Message{}, err
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", e.addr.String())
	if err != nil {
		return wire.Message{}, fmt.Errorf("dnscrypt: dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else if e.timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(e.timeout))
	}

	if _, err := conn.Write(enc); err != nil {
		return wire.Message{}, fmt.Errorf("dnscrypt: write: %w", err)
	}
	// Sized to accommodate an EDNS-bumped DNS message (up to 65535 wire
	// bytes per the 16-bit RDLENGTH ceiling) plus the DNSCrypt v2 header
	// and AEAD framing. A smaller buffer would silently truncate large
	// DNSSEC responses, leading Decrypt to fail in non-obvious ways.
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return wire.Message{}, fmt.Errorf("dnscrypt: read: %w", err)
	}
	if n == len(buf) {
		// Read filled the buffer exactly: a UDP datagram larger than
		// our cap was silently truncated by the kernel. Refuse rather
		// than feed truncated ciphertext to Decrypt.
		return wire.Message{}, fmt.Errorf("dnscrypt: response exceeded %d byte buffer", len(buf))
	}
	plain, err := Decrypt(e.cert, clientSK, nonce, buf[:n])
	if err != nil {
		return wire.Message{}, err
	}
	resp, err := wire.Unpack(plain)
	if err != nil {
		return wire.Message{}, err
	}
	// AEAD only proves the resolver's short-term key signed *some* DNS
	// message — not necessarily the one we asked. Bind the response to
	// the request the same way every other transport in this repo does
	// (UDP Client, streamframe, DoH, DoQ).
	if resp.ID() != q.ID() {
		return wire.Message{}, fmt.Errorf("dnscrypt: response id %d != request id %d", resp.ID(), q.ID())
	}
	if !wire.QuestionsMatch(q, resp) {
		return wire.Message{}, fmt.Errorf("dnscrypt: response question does not match request")
	}
	return resp, nil
}
