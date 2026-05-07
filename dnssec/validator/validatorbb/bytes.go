package validatorbb

// BytesLess reports whether a sorts strictly before b under big-endian
// byte ordering (lexicographic with "shorter prefix sorts before longer").
// It is used by the NSEC3 hash-interval check and matches RFC 5155's
// canonical hash ordering.
func BytesLess(a, b []byte) bool {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}
