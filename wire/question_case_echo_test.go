package wire_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

// TestQuestionRawWireCaseEchoes locks in the rawName-based byte-exact
// echo path: a query that arrived on the wire with a mixed-case QNAME
// must round-trip through Unpack → builder.Question → Pack with
// the original case bytes intact. This is required by RFC 4343 (case
// insensitivity in matching, case preservation in echoes) and is what
// makes RFC 5452 §9.3 0x20 verification meaningful for clients.
func TestQuestionRawWireCaseEchoes(t *testing.T) {
	t.Parallel()
	// Hand-crafted: ID=0xbeef, RD=1, QDCOUNT=1, qname = "EXAMPLE.cOm",
	// qtype = A (1), qclass = IN (1).
	q := []byte{
		0xbe, 0xef, 0x01, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'E', 'X', 'A', 'M', 'P', 'L', 'E', 0x03, 'c', 'O', 'm', 0x00,
		0x00, 0x01,
		0x00, 0x01,
	}
	got, err := wire.Unpack(q)
	require.NoError(t, err)

	resp, err := wire.NewMessageBuilder().
		ID(got.ID()).
		Response(true).
		Question(got.Questions()[0]).
		Build()
	require.NoError(t, err)
	rb, err := wire.Pack(resp)
	require.NoError(t, err)

	require.Contains(t, string(rb), "EXAMPLE", "response must echo qname case from the wire")
	require.Contains(t, string(rb), "cOm", "response must echo qname case from the wire")
}
