package dnscrypt

import (
	"time"

	"github.com/lestrrat-go/option/v3"
)

// Option configures an Exchanger.
type Option interface {
	option.Interface
	dnscryptOption()
}

type dnscryptOption struct{ option.Interface }

func (dnscryptOption) dnscryptOption() {}

type config struct {
	timeout   time.Duration
	now       func() time.Time
	clockSkew time.Duration
}

type identTimeout struct{}
type identClockSkew struct{}
type identClock struct{}

// WithTimeout sets the per-exchange timeout when ctx has no deadline.
func WithTimeout(d time.Duration) Option {
	return dnscryptOption{option.New(identTimeout{}, d)}
}

// WithClockSkew widens the cert validity-window check by ±d on every
// Exchange. Mirrors [WithServerClockSkew] on the server side: small
// drift between the resolver's clock and the cert-signing host
// otherwise turns hourly cert rotation into a hard outage. Defaults
// to 5 seconds; pass 0 to require an exact within-window match.
func WithClockSkew(d time.Duration) Option {
	return dnscryptOption{option.New(identClockSkew{}, d)}
}

// WithClock injects a clock function. Defaults to time.Now. Used for
// the cert validity-window check on every Exchange call; production
// code should leave this unset, tests can pin time to verify boundary
// behaviour without monkey-patching the system clock.
func WithClock(now func() time.Time) Option {
	return dnscryptOption{option.New(identClock{}, now)}
}

// CertOption configures a Cert via NewCert.
type CertOption interface {
	option.Interface
	certOption()
}

type certOption struct{ option.Interface }

func (certOption) certOption() {}

type certConfig struct {
	esVersion      ESVersion
	protocolMinor  uint16
	resolverPK     [32]byte
	resolverPKSet  bool
	clientMagic    [8]byte
	clientMagicSet bool
	serial         uint32
	validFrom      time.Time
	validFromSet   bool
	validUntil     time.Time
	validUntilSet  bool
}

type identCertESVersion struct{}
type identCertProtocolMinor struct{}
type identCertResolverPK struct{}
type identCertClientMagic struct{}
type identCertSerial struct{}
type identCertValidFrom struct{}
type identCertValidUntil struct{}

// WithCertESVersion sets the cert's ES version. Defaults to ESVersion2.
func WithCertESVersion(v ESVersion) CertOption {
	return certOption{option.New(identCertESVersion{}, v)}
}

// WithCertProtocolMinor sets the cert's protocol-minor field.
func WithCertProtocolMinor(v uint16) CertOption {
	return certOption{option.New(identCertProtocolMinor{}, v)}
}

// WithCertResolverPK sets the resolver's short-term X25519 public
// key. Required.
func WithCertResolverPK(pk [32]byte) CertOption {
	return certOption{option.New(identCertResolverPK{}, pk)}
}

// WithCertClientMagic sets the 8-byte client-magic prefix. Required.
func WithCertClientMagic(m [8]byte) CertOption {
	return certOption{option.New(identCertClientMagic{}, m)}
}

// WithCertSerial sets the cert's serial number.
func WithCertSerial(v uint32) CertOption {
	return certOption{option.New(identCertSerial{}, v)}
}

// WithCertValidFrom sets the start of the cert's validity window.
// Required.
func WithCertValidFrom(t time.Time) CertOption {
	return certOption{option.New(identCertValidFrom{}, t.UTC())}
}

// WithCertValidUntil sets the end of the cert's validity window.
// Required.
func WithCertValidUntil(t time.Time) CertOption {
	return certOption{option.New(identCertValidUntil{}, t.UTC())}
}
