package acidns

// RateLimitDebugLen returns the number of buckets the rate-limiter is
// currently tracking. Test-only.
func RateLimitDebugLen(h Handler) int {
	l, ok := h.(*limiter)
	if !ok {
		return -1
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
