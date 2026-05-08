package validatorbb

// BytesLess reports whether a sorts strictly before b under big-endian
// byte ordering (lexicographic with "shorter prefix sorts before longer").
// It is used by the NSEC3 hash-interval check and matches RFC 5155's
// canonical hash ordering.
func BytesLess(a, b []byte) bool {
	n := min(len(b), len(a))
	for i := range n {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}
