package rdata_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
	"github.com/stretchr/testify/require"
)

// NewSvcParamALPN must reject empty ALPN ids — the constructor invariant
// the wire decoder also has to enforce.
func TestNewSvcParamALPNRejectsEmpty(t *testing.T) {
	t.Parallel()

	_, err := rdata.NewSvcParamALPN("h2", "")
	require.Error(t, err)
	require.ErrorIs(t, err, rdata.ErrInvalidRData)
}

// A hand-crafted SVCB rdata with an ALPN value that contains a
// zero-length entry must be rejected by Unpack. Before the fix, the
// payload survived decode and surfaced via ALPN() as a nil slice that
// could not be re-encoded with NewSvcParamALPN — round-trip asymmetry.
func TestUnpackSVCBRejectsZeroLengthALPN(t *testing.T) {
	t.Parallel()

	// Build SVCB wire by hand:
	//   priority(2) | target name | key(2) | len(2) | value...
	// Value here is the malformed ALPN bytes:
	//   0x02 'h' '2' 0x00     <- second entry has length zero
	target := wirebb.MustParse("svc.example.com")
	pkr := wirebb.NewPacker(nil)
	pkr.Uint16(1)
	pkr.NameUncompressed(target)
	pkr.Uint16(uint16(rdata.SvcParamALPN))
	alpnValue := []byte{0x02, 'h', '2', 0x00}
	pkr.Uint16(uint16(len(alpnValue)))
	pkr.Raw(alpnValue)
	buf := pkr.Bytes()

	u := wirebb.NewUnpacker(buf)
	_, err := rdata.Unpack(rrtype.SVCB, u, len(buf))
	require.Error(t, err)
	require.ErrorIs(t, err, rdata.ErrInvalidRData)
}

// NewSVCB with raw NewSVCBParam bytes carrying a zero-length ALPN
// entry must also be rejected at construction time so a caller can't
// smuggle wire-invalid bytes past the decoder via the generic param
// constructor.
func TestNewSVCBRejectsZeroLengthALPNParam(t *testing.T) {
	t.Parallel()

	_, err := rdata.NewSVCB(1, wirebb.MustParse("svc.example.com"),
		rdata.NewSVCBParam(rdata.SvcParamALPN, []byte{0x02, 'h', '2', 0x00}),
	)
	require.Error(t, err)
	require.ErrorIs(t, err, rdata.ErrInvalidRData)
}

// A valid SVCB built through the public API must always round-trip
// cleanly through Pack/Unpack — the symmetry the previous decoder
// silently broke when it accepted ALPN payloads NewSvcParamALPN
// would have refused.
func TestSVCBRoundTripALPN(t *testing.T) {
	t.Parallel()

	alpn, err := rdata.NewSvcParamALPN("h2", "h3")
	require.NoError(t, err)

	r, err := rdata.NewSVCB(1, wirebb.MustParse("svc.example.com"), alpn)
	require.NoError(t, err)

	got, ok := packUnpack(t, r).(rdata.SVCB)
	require.True(t, ok)
	require.Equal(t, []string{"h2", "h3"}, got.ALPN())
}
