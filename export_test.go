package acidns

// RateLimitDebugLen returns the number of buckets the rate-limiter is
// currently tracking across all shards. Test-only.
func RateLimitDebugLen(h Handler) int {
	l, ok := h.(*limiter)
	if !ok {
		return -1
	}
	total := 0
	for _, sh := range l.shards {
		sh.mu.Lock()
		total += len(sh.buckets)
		sh.mu.Unlock()
	}
	return total
}
