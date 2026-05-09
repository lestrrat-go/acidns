package axfr

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns/tsig"
	"github.com/lestrrat-go/acidns/wire"
)

// tsigVerifier verifies TSIG-signed AXFR envelopes per RFC 8945
// §5.3.1/§5.3.2. The first envelope is verified as a response to the
// request and MUST be signed. Subsequent signed envelopes chain MAC
// verification through priorMAC; intermediate unsigned envelopes are
// tolerated per §5.3.2.
//
// Caveat: the MessageStream interface does not expose the original wire
// bytes of each envelope, so verification re-marshals the parsed message
// to recompute the HMAC input. This works only when both peers use a
// byte-deterministic encoder (acidns's own implementation does); a TSIG
// signed by a server whose encoder makes different name-compression
// choices will fail verification here even when the signature is valid
// in the strict sense. Production deployments crossing implementations
// SHOULD perform TSIG verification at the transport layer where the raw
// bytes are available.
type tsigVerifier struct {
	key      tsig.Key
	priorMAC []byte
	now      func() time.Time
	fudge    time.Duration
	first    bool
}

func newTSIGVerifier(key tsig.Key, requestMAC []byte, now func() time.Time, fudge time.Duration) *tsigVerifier {
	return &tsigVerifier{key: key, priorMAC: requestMAC, now: now, fudge: fudge, first: true}
}

func (v *tsigVerifier) verify(m wire.Message) error {
	signed := messageHasTSIG(m)
	if v.first {
		if !signed {
			return fmt.Errorf("%w: first envelope unsigned", ErrTSIGVerify)
		}
		raw, err := wire.Marshal(m)
		if err != nil {
			return fmt.Errorf("%w: re-marshal: %w", ErrTSIGVerify, err)
		}
		_, mac, _, err := tsig.VerifyResponse(raw, v.key, v.priorMAC, v.now(), v.fudge)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrTSIGVerify, err)
		}
		v.priorMAC = mac
		v.first = false
		return nil
	}
	if !signed {
		return nil
	}
	raw, err := wire.Marshal(m)
	if err != nil {
		return fmt.Errorf("%w: re-marshal: %w", ErrTSIGVerify, err)
	}
	_, mac, _, err := tsig.VerifyAXFRChunk(raw, v.key, v.priorMAC, v.now(), v.fudge)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrTSIGVerify, err)
	}
	v.priorMAC = mac
	return nil
}

// messageHasTSIG reports whether m carries a TSIG RR (type 250) in its
// additional section.
func messageHasTSIG(m wire.Message) bool {
	for _, r := range m.Additionals() {
		if uint16(r.Type()) == 250 {
			return true
		}
	}
	return false
}
