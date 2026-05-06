// Package dnscrypt implements the DNSCrypt v2 protocol — an encrypted
// transport for DNS queries between a client and a resolver. The wire
// format is the format documented at https://dnscrypt.info/protocol
// (DNSCrypt is not standardised by any RFC; the protocol is defined by
// its reference implementation).
//
// Two pieces are exposed:
//
//   - Cert: the in-band certificate the resolver advertises via a TXT
//     record at "2.dnscrypt-cert.<provider>", together with helpers to
//     parse and verify it against a known provider Ed25519 public key.
//   - Exchanger: a transport.Exchanger that encrypts queries and
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
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"

	"github.com/lestrrat-go/acidns/dnsclient/transport"
	"github.com/lestrrat-go/acidns/dnsmsg"
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
)

// Cert is a parsed DNSCrypt certificate (124 bytes on the wire).
type Cert struct {
	ESVersion     ESVersion
	ProtocolMinor uint16
	Signature     [64]byte
	ResolverPK    [32]byte // X25519 short-term public key
	ClientMagic   [8]byte
	Serial        uint32
	ValidFrom     time.Time
	ValidUntil    time.Time
}

// ParseCert decodes a 124-byte certificate blob.
func ParseCert(b []byte) (*Cert, error) {
	if len(b) < 124 {
		return nil, fmt.Errorf("dnscrypt: cert too short (%d bytes)", len(b))
	}
	if !bytes.Equal(b[0:4], certMagic[:]) {
		return nil, ErrCertMagicMismatch
	}
	c := &Cert{
		ESVersion:     ESVersion(binary.BigEndian.Uint16(b[4:6])),
		ProtocolMinor: binary.BigEndian.Uint16(b[6:8]),
	}
	copy(c.Signature[:], b[8:72])
	copy(c.ResolverPK[:], b[72:104])
	copy(c.ClientMagic[:], b[104:112])
	c.Serial = binary.BigEndian.Uint32(b[112:116])
	c.ValidFrom = time.Unix(int64(binary.BigEndian.Uint32(b[116:120])), 0).UTC()
	c.ValidUntil = time.Unix(int64(binary.BigEndian.Uint32(b[120:124])), 0).UTC()
	return c, nil
}

// Verify checks the cert's Ed25519 signature against the provider's
// long-term public key (32 bytes) and confirms the validity window
// covers now. Returns nil on success.
func (c *Cert) Verify(providerPK ed25519.PublicKey, now time.Time) error {
	signed := make([]byte, 0, 52)
	signed = append(signed, c.ResolverPK[:]...)
	signed = append(signed, c.ClientMagic[:]...)
	var nums [12]byte
	binary.BigEndian.PutUint32(nums[0:], c.Serial)
	binary.BigEndian.PutUint32(nums[4:], uint32(c.ValidFrom.Unix()))
	binary.BigEndian.PutUint32(nums[8:], uint32(c.ValidUntil.Unix()))
	signed = append(signed, nums[:]...)

	if !ed25519.Verify(providerPK, signed, c.Signature[:]) {
		return ErrCertSignatureInvalid
	}
	if now.Before(c.ValidFrom) || now.After(c.ValidUntil) {
		return fmt.Errorf("%w: now=%s window=[%s, %s]", ErrCertExpired, now, c.ValidFrom, c.ValidUntil)
	}
	if c.ESVersion != ESVersion2 {
		return fmt.Errorf("%w: ES%d", ErrUnsupportedESVersion, c.ESVersion)
	}
	return nil
}

// EncodeCert serialises c back to wire form. Useful for tests that
// build a fake responder.
func EncodeCert(c *Cert) []byte {
	out := make([]byte, 124)
	copy(out[0:4], certMagic[:])
	binary.BigEndian.PutUint16(out[4:], uint16(c.ESVersion))
	binary.BigEndian.PutUint16(out[6:], c.ProtocolMinor)
	copy(out[8:72], c.Signature[:])
	copy(out[72:104], c.ResolverPK[:])
	copy(out[104:112], c.ClientMagic[:])
	binary.BigEndian.PutUint32(out[112:], c.Serial)
	binary.BigEndian.PutUint32(out[116:], uint32(c.ValidFrom.Unix()))
	binary.BigEndian.PutUint32(out[120:], uint32(c.ValidUntil.Unix()))
	return out
}

// SignCert produces the cert.Signature given the resolver's long-term
// private key. Used by tests / fake responders to forge a valid cert.
func SignCert(c *Cert, providerSK ed25519.PrivateKey) {
	signed := make([]byte, 0, 52)
	signed = append(signed, c.ResolverPK[:]...)
	signed = append(signed, c.ClientMagic[:]...)
	var nums [12]byte
	binary.BigEndian.PutUint32(nums[0:], c.Serial)
	binary.BigEndian.PutUint32(nums[4:], uint32(c.ValidFrom.Unix()))
	binary.BigEndian.PutUint32(nums[8:], uint32(c.ValidUntil.Unix()))
	signed = append(signed, nums[:]...)
	sig := ed25519.Sign(providerSK, signed)
	copy(c.Signature[:], sig)
}

// Encrypt produces a DNSCrypt-formatted query packet.
//
// nonce must be 12 random bytes; the framing pads it to 24 bytes for
// XChaCha20-Poly1305 by appending zeros. The caller is responsible for
// generating a fresh nonce per query.
func Encrypt(c *Cert, clientPK [32]byte, clientSK [32]byte, nonce [12]byte, query []byte) ([]byte, error) {
	if c.ESVersion != ESVersion2 {
		return nil, fmt.Errorf("%w: ES%d", ErrUnsupportedESVersion, c.ESVersion)
	}
	sharedKey, err := sharedKey(c.ResolverPK, clientSK)
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
	out = append(out, c.ClientMagic[:]...)
	out = append(out, clientPK[:]...)
	out = append(out, nonce[:]...)
	out = append(out, ct...)
	return out, nil
}

// Decrypt validates and decrypts a DNSCrypt response packet against the
// supplied cert and the client nonce that was used for the query.
func Decrypt(c *Cert, clientSK [32]byte, clientNonce [12]byte, packet []byte) ([]byte, error) {
	if c.ESVersion != ESVersion2 {
		return nil, fmt.Errorf("%w: ES%d", ErrUnsupportedESVersion, c.ESVersion)
	}
	if len(packet) < 8+12+12 {
		return nil, ErrPlainTextTooShort
	}
	if !bytes.Equal(packet[0:8], resolverMagic[:]) {
		return nil, ErrResponseMagic
	}
	if !bytes.Equal(packet[8:20], clientNonce[:]) {
		return nil, fmt.Errorf("dnscrypt: client nonce mismatch")
	}
	var fullNonce [24]byte
	copy(fullNonce[:12], packet[8:20])
	copy(fullNonce[12:], packet[20:32])

	sharedKey, err := sharedKey(c.ResolverPK, clientSK)
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
func sharedKey(resolverPK, clientSK [32]byte) ([32]byte, error) {
	out, err := curve25519.X25519(clientSK[:], resolverPK[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("dnscrypt: x25519: %w", err)
	}
	var k [32]byte
	copy(k[:], out)
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

// Option configures an Exchanger.
type Option interface{ applyDNSCrypt(*config) }

type optionFunc func(*config)

func (f optionFunc) applyDNSCrypt(c *config) { f(c) }

type config struct {
	timeout time.Duration
}

// WithTimeout sets the per-exchange timeout when ctx has no deadline.
func WithTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) { c.timeout = d })
}

type exchanger struct {
	addr    netip.AddrPort
	cert    *Cert
	timeout time.Duration
}

// New returns a transport.Exchanger that sends DNSCrypt-encrypted
// queries to addr using the verified cert.
func New(addr netip.AddrPort, cert *Cert, opts ...Option) (transport.Exchanger, error) {
	if cert.ESVersion != ESVersion2 {
		return nil, fmt.Errorf("%w: ES%d", ErrUnsupportedESVersion, cert.ESVersion)
	}
	c := config{timeout: 5 * time.Second}
	for _, o := range opts {
		o.applyDNSCrypt(&c)
	}
	return &exchanger{addr: addr, cert: cert, timeout: c.timeout}, nil
}

// Exchange encrypts q, sends it via UDP, and decrypts the response.
func (e *exchanger) Exchange(ctx context.Context, q dnsmsg.Message) (dnsmsg.Message, error) {
	wire, err := dnsmsg.Marshal(q)
	if err != nil {
		return nil, fmt.Errorf("dnscrypt: marshal: %w", err)
	}

	var clientSK [32]byte
	if _, err := rand.Read(clientSK[:]); err != nil {
		return nil, err
	}
	var clientPK [32]byte
	pk, err := curve25519.X25519(clientSK[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(clientPK[:], pk)

	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	enc, err := Encrypt(e.cert, clientPK, clientSK, nonce, wire)
	if err != nil {
		return nil, err
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", e.addr.String())
	if err != nil {
		return nil, fmt.Errorf("dnscrypt: dial: %w", err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else if e.timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(e.timeout))
	}

	if _, err := conn.Write(enc); err != nil {
		return nil, fmt.Errorf("dnscrypt: write: %w", err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("dnscrypt: read: %w", err)
	}
	plain, err := Decrypt(e.cert, clientSK, nonce, buf[:n])
	if err != nil {
		return nil, err
	}
	return dnsmsg.Unmarshal(plain)
}
