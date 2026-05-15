package spki

import (
	"crypto/subtle"
	"crypto/tls"
	"slices"
)

// PrepareConfig is the per-call policy a TLS-over-DNS transport
// applies when preparing a *tls.Config for a client handshake.
//
// The fields capture the shape every encrypted-DNS client follows:
// raise MinVersion to TLS 1.3, ensure ServerName is set (or refuse
// when it is not), append the protocol-specific ALPN identifier,
// optionally enforce SPKI pinning on top of PKIX validation. Each
// transport (dot, doq) passes its own sentinel errors via the Err*
// fields so the returned errors remain matchable with errors.Is
// against the transport's package-local vars.
type PrepareConfig struct {
	// Base is the caller-supplied *tls.Config; nil means
	// "construct a fresh tls.Config{MinVersion: TLS 1.3}". A
	// non-nil Base is always cloned — the returned config is
	// independent of the caller's.
	Base *tls.Config

	// ServerName, if non-empty, overrides Base.ServerName.
	ServerName string

	// ALPN, if non-empty, is appended to NextProtos when not
	// already present.
	ALPN string

	// Insecure, when true, propagates InsecureSkipVerify=true onto
	// the returned config and disables the empty-ServerName guard.
	Insecure bool

	// SPKIPins are the SHA-256 SubjectPublicKeyInfo pins
	// (RFC 7858 §4.2). When non-empty, PrepareClient wraps
	// VerifyConnection to enforce that at least one pin matches
	// the leaf certificate. The caller is expected to have
	// validated each pin's length against HashSize.
	SPKIPins [][]byte

	// ErrInsecureConfig is returned when Base.InsecureSkipVerify
	// is set but Insecure is false. The transport supplies its
	// own package-local sentinel (e.g. dot.ErrInsecureTLSConfig)
	// so callers can errors.Is it.
	ErrInsecureConfig error

	// ErrServerNameReq is returned when ServerName resolves empty
	// and Insecure is false. The transport supplies a per-call
	// error (typically fmt.Errorf("%w ...", pkg.ErrServerNameRequired))
	// so its wrapping advice (or extra context) is preserved.
	ErrServerNameReq error

	// ErrNoPeerCert / ErrSPKIMismatch are returned from the wrapped
	// VerifyConnection — the transport's package-local sentinels.
	ErrNoPeerCert   error
	ErrSPKIMismatch error
}

// PrepareClient builds the *tls.Config a client transport uses for
// its handshake. The returned config is freshly allocated; mutations
// on it do not affect cfg.Base.
func PrepareClient(cfg PrepareConfig) (*tls.Config, error) {
	var t *tls.Config
	if cfg.Base != nil {
		if cfg.Base.InsecureSkipVerify && !cfg.Insecure {
			return nil, cfg.ErrInsecureConfig
		}
		t = cfg.Base.Clone()
	} else {
		t = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	if t.MinVersion < tls.VersionTLS13 {
		t.MinVersion = tls.VersionTLS13
	}
	if cfg.ServerName != "" {
		t.ServerName = cfg.ServerName
	}
	if t.ServerName == "" && !cfg.Insecure {
		return nil, cfg.ErrServerNameReq
	}
	if cfg.Insecure {
		t.InsecureSkipVerify = true
	}
	if cfg.ALPN != "" && !slices.Contains(t.NextProtos, cfg.ALPN) {
		t.NextProtos = append(t.NextProtos, cfg.ALPN)
	}
	if len(cfg.SPKIPins) > 0 {
		prev := t.VerifyConnection
		pins := cfg.SPKIPins
		noPeer := cfg.ErrNoPeerCert
		mismatch := cfg.ErrSPKIMismatch
		t.VerifyConnection = func(cs tls.ConnectionState) error {
			if prev != nil {
				if err := prev(cs); err != nil {
					return err
				}
			}
			return verifyPin(cs, pins, noPeer, mismatch)
		}
	}
	return t, nil
}

// verifyPin enforces RFC 7858 §4.2 SPKI pinning: at least one of pins
// must equal the SHA-256 hash of the leaf certificate's SPKI.
// Constant-time comparison is used uniformly with the rest of the
// codebase's crypto pattern even though pins are public material.
func verifyPin(cs tls.ConnectionState, pins [][]byte, errNoPeer, errMismatch error) error {
	if len(cs.PeerCertificates) == 0 {
		return errNoPeer
	}
	got := Hash(cs.PeerCertificates[0])
	for _, pin := range pins {
		if subtle.ConstantTimeCompare(got[:], pin) == 1 {
			return nil
		}
	}
	return errMismatch
}
