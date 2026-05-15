package ixfr

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns/tsig"
	"github.com/lestrrat-go/acidns/wire"
)

// tsigVerifier verifies TSIG-signed IXFR envelopes per RFC 8945
// §5.3.1/§5.3.2. The first envelope is verified as a response to the
// request and MUST be signed. Subsequent signed envelopes chain MAC
// verification through priorMAC; intermediate unsigned envelopes are
// tolerated per §5.3.2.
//
// Caveat: the MessageStream interface does not expose original wire
// bytes; verification re-marshals each message to recompute the HMAC
// input. This requires byte-deterministic encoding on both peers.
type tsigVerifier struct {
	key      tsig.Key
	priorMAC []byte
	now      func() time.Time
	fudge    time.Duration
	first    bool
	// unsignedRun counts envelopes received since the last signed one.
	// RFC 8945 §5.3.2: "the sender MUST sign at least every 100th
	// message"; a verifier MUST therefore reject a stream that exceeds
	// 99 unsigned envelopes between signatures, otherwise an on-path
	// attacker can inject unlimited forged envelopes after the first
	// signed one and have them accepted as zone content.
	unsignedRun int
}

// maxUnsignedIXFREnvelopes is the cap on consecutive unsigned envelopes
// between two signed envelopes per RFC 8945 §5.3.2.
const maxUnsignedIXFREnvelopes = 99

func newTSIGVerifier(key tsig.Key, requestMAC []byte, now func() time.Time, fudge time.Duration) *tsigVerifier {
	return &tsigVerifier{key: key, priorMAC: requestMAC, now: now, fudge: fudge, first: true}
}

func (v *tsigVerifier) verify(m wire.Message) error {
	signed := messageHasTSIG(m)
	if v.first {
		if !signed {
			return fmt.Errorf("%w: first envelope unsigned", ErrTSIGVerify)
		}
		raw, err := wire.Pack(m)
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
		v.unsignedRun++
		if v.unsignedRun > maxUnsignedIXFREnvelopes {
			return fmt.Errorf("%w: %d consecutive unsigned envelopes (RFC 8945 §5.3.2 cap is 99)",
				ErrTSIGVerify, v.unsignedRun)
		}
		return nil
	}
	raw, err := wire.Pack(m)
	if err != nil {
		return fmt.Errorf("%w: re-marshal: %w", ErrTSIGVerify, err)
	}
	_, mac, _, err := tsig.VerifyAXFRChunk(raw, v.key, v.priorMAC, v.now(), v.fudge)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrTSIGVerify, err)
	}
	v.priorMAC = mac
	v.unsignedRun = 0
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
