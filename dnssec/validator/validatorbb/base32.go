package validatorbb

import "fmt"

// base32hexAlphabet is the RFC 4648 base32hex alphabet (extended hex,
// uppercase) used by NSEC3 owner-name labels (RFC 5155 §1.3 / §5.3).
const base32hexAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV"

// Base32HexEncode renders raw bytes as the no-padding base32hex form used
// by NSEC3 owner labels (RFC 5155 §1.3). Output is uppercase; callers that
// need lowercase wire form should fold afterwards (acidns names are
// stored lowercase).
func Base32HexEncode(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	out := make([]byte, 0, (len(b)*8+4)/5)
	var buf uint64
	bits := 0
	for _, x := range b {
		buf = (buf << 8) | uint64(x)
		bits += 8
		for bits >= 5 {
			bits -= 5
			idx := (buf >> bits) & 0x1f
			out = append(out, base32hexAlphabet[idx])
		}
	}
	if bits > 0 {
		idx := (buf << (5 - bits)) & 0x1f
		out = append(out, base32hexAlphabet[idx])
	}
	return string(out)
}

// Base32HexDecode parses a base32hex-encoded label produced by NSEC3.
// Returns an error for any non-alphabet character. Both upper-case and
// lower-case input are accepted.
func Base32HexDecode(s string) ([]byte, error) {
	if len(s) == 0 {
		return nil, nil
	}
	out := make([]byte, 0, (len(s)*5+7)/8)
	var buf uint64
	bits := 0
	for i := range len(s) {
		c := s[i]
		var v int
		switch {
		case c >= '0' && c <= '9':
			v = int(c - '0')
		case c >= 'A' && c <= 'V':
			v = int(c-'A') + 10
		case c >= 'a' && c <= 'v':
			v = int(c-'a') + 10
		default:
			return nil, fmt.Errorf("validatorbb: bad base32hex character %q", c)
		}
		buf = (buf << 5) | uint64(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte((buf>>bits)&0xff))
		}
	}
	return out, nil
}
