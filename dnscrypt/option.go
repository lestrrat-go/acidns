package dnscrypt

import "time"

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

// CertOption configures a Cert via NewCert.
type CertOption interface{ applyCert(*certConfig) }

type certOptionFunc func(*certConfig)

func (f certOptionFunc) applyCert(c *certConfig) { f(c) }

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

// WithCertESVersion sets the cert's ES version. Defaults to ESVersion2.
func WithCertESVersion(v ESVersion) CertOption {
	return certOptionFunc(func(c *certConfig) { c.esVersion = v })
}

// WithCertProtocolMinor sets the cert's protocol-minor field.
func WithCertProtocolMinor(v uint16) CertOption {
	return certOptionFunc(func(c *certConfig) { c.protocolMinor = v })
}

// WithCertResolverPK sets the resolver's short-term X25519 public
// key. Required.
func WithCertResolverPK(pk [32]byte) CertOption {
	return certOptionFunc(func(c *certConfig) { c.resolverPK = pk; c.resolverPKSet = true })
}

// WithCertClientMagic sets the 8-byte client-magic prefix. Required.
func WithCertClientMagic(m [8]byte) CertOption {
	return certOptionFunc(func(c *certConfig) { c.clientMagic = m; c.clientMagicSet = true })
}

// WithCertSerial sets the cert's serial number.
func WithCertSerial(v uint32) CertOption {
	return certOptionFunc(func(c *certConfig) { c.serial = v })
}

// WithCertValidFrom sets the start of the cert's validity window.
// Required.
func WithCertValidFrom(t time.Time) CertOption {
	return certOptionFunc(func(c *certConfig) { c.validFrom = t.UTC(); c.validFromSet = true })
}

// WithCertValidUntil sets the end of the cert's validity window.
// Required.
func WithCertValidUntil(t time.Time) CertOption {
	return certOptionFunc(func(c *certConfig) { c.validUntil = t.UTC(); c.validUntilSet = true })
}
