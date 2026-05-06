package dnsmsg_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalShortHeader(t *testing.T) {
	t.Parallel()
	_, err := dnsmsg.Unmarshal([]byte{0x01})
	require.Error(t, err)
}

func TestUnmarshalEmpty(t *testing.T) {
	t.Parallel()
	_, err := dnsmsg.Unmarshal(nil)
	require.Error(t, err)
}

func TestUnmarshalTruncatedQuestion(t *testing.T) {
	t.Parallel()
	// 12-byte header claims one question but no more bytes.
	hdr := []byte{
		0x00, 0x01, // ID
		0x00, 0x00, // flags
		0x00, 0x01, // qdcount = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	_, err := dnsmsg.Unmarshal(hdr)
	require.Error(t, err)
}

func TestUnmarshalTruncatedAnswer(t *testing.T) {
	t.Parallel()
	hdr := []byte{
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x01, // ancount = 1
		0x00, 0x00, 0x00, 0x00,
	}
	_, err := dnsmsg.Unmarshal(hdr)
	require.Error(t, err)
}

func TestUnmarshalTruncatedAdditional(t *testing.T) {
	t.Parallel()
	hdr := []byte{
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x01, // arcount=1
	}
	_, err := dnsmsg.Unmarshal(hdr)
	require.Error(t, err)
}
