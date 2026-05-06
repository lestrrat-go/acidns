package wire_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/dnsmsg/internal/wire"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/stretchr/testify/require"
)

func TestPackerPrimitives(t *testing.T) {
	t.Parallel()

	p := wire.NewPacker(nil)
	p.Uint8(0x01)
	p.Uint16(0x0203)
	p.Uint32(0x04050607)
	p.Raw([]byte{0xff, 0xfe})
	require.Equal(t, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xff, 0xfe}, p.Bytes())
	require.Equal(t, 9, p.Len())
}

func TestPackerName(t *testing.T) {
	t.Parallel()

	p := wire.NewPacker(nil)
	p.Name(dnsname.MustParse("example.com"))
	p.Name(dnsname.MustParse("www.example.com"))
	got := p.Bytes()

	// First name is uncompressed, second compresses to a pointer at offset 0.
	require.Equal(t,
		[]byte{
			7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
			3, 'w', 'w', 'w', 0xc0, 0,
		}, got)
}

func TestPackerNameNoCompression(t *testing.T) {
	t.Parallel()

	p := wire.NewPacker(nil)
	p.NameUncompressed(dnsname.MustParse("example.com"))
	p.NameUncompressed(dnsname.MustParse("www.example.com"))
	got := p.Bytes()
	require.Equal(t, 13+17, len(got))
	require.Equal(t, byte(7), got[0])
	require.Equal(t, byte(3), got[13])
}

func TestUnpackerPrimitives(t *testing.T) {
	t.Parallel()

	buf := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xff}
	u := wire.NewUnpacker(buf)

	v8, err := u.Uint8()
	require.NoError(t, err)
	require.Equal(t, uint8(1), v8)

	v16, err := u.Uint16()
	require.NoError(t, err)
	require.Equal(t, uint16(0x0203), v16)

	v32, err := u.Uint32()
	require.NoError(t, err)
	require.Equal(t, uint32(0x04050607), v32)

	rest, err := u.Bytes(1)
	require.NoError(t, err)
	require.Equal(t, []byte{0xff}, rest)

	_, err = u.Uint8()
	require.Error(t, err)
}

func TestUnpackerName(t *testing.T) {
	t.Parallel()

	buf := []byte{
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		3, 'w', 'w', 'w', 0xc0, 0,
	}
	u := wire.NewUnpacker(buf)
	n, err := u.Name()
	require.NoError(t, err)
	require.Equal(t, "example.com.", n.String())
	require.Equal(t, 13, u.Off())

	n2, err := u.Name()
	require.NoError(t, err)
	require.Equal(t, "www.example.com.", n2.String())
	require.Equal(t, 19, u.Off())
}

func TestPackerCharString(t *testing.T) {
	t.Parallel()

	p := wire.NewPacker(nil)
	require.NoError(t, p.CharString([]byte("hello")))
	require.Equal(t, []byte{5, 'h', 'e', 'l', 'l', 'o'}, p.Bytes())

	require.Error(t, p.CharString(make([]byte, 256)))
}

func TestUnpackerCharString(t *testing.T) {
	t.Parallel()

	buf := []byte{5, 'h', 'e', 'l', 'l', 'o'}
	u := wire.NewUnpacker(buf)
	got, err := u.CharString()
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), got)
}
