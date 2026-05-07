package validatorbb

// HashIntervalContains reports whether x falls strictly between owner and
// next under big-endian byte ordering, with apex wraparound handled per
// RFC 5155 §6.2 (next < owner means owner is the last hash in the zone).
func HashIntervalContains(owner, next, x []byte) bool {
	if BytesLess(owner, next) {
		return BytesLess(owner, x) && BytesLess(x, next)
	}
	// Wraparound.
	return BytesLess(owner, x) || BytesLess(x, next)
}
