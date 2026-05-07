package validatorbb

// HexDigit returns the value of an ASCII hex digit (0-9, a-f, A-F) or -1
// if b is not a hex digit. Used by [MustHex] and by trust-anchor digest
// parsing.
func HexDigit(b byte) int {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0')
	case b >= 'a' && b <= 'f':
		return int(b-'a') + 10
	case b >= 'A' && b <= 'F':
		return int(b-'A') + 10
	}
	return -1
}

// MustHex decodes a hex string into bytes, panicking if s contains a
// non-hex character. Length must be even (callers using it for trust
// anchors hard-code well-known digests so a panic on bad input is
// acceptable — the data is a developer-supplied literal).
func MustHex(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi := HexDigit(s[i])
		lo := HexDigit(s[i+1])
		if hi < 0 || lo < 0 {
			panic("validatorbb: invalid hex literal: " + s)
		}
		out[i/2] = byte(hi<<4 | lo)
	}
	return out
}
