package acidns

import (
	"time"

	"github.com/lestrrat-go/acidns/resolvconf"
)

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

// SystemResolverConfigFromFile loads path via resolvconf, then runs
// the same option-application pipeline as [WithSystemResolvers] so a
// test can verify the propagation of Timeout / Attempts /
// nameservers without depending on /etc/resolv.conf being present.
// Test-only.
func SystemResolverConfigFromFile(path string) (perAttempt time.Duration, attempts int, err error) {
	cfg, lerr := resolvconf.Load(path)
	if lerr != nil {
		return 0, 0, lerr
	}
	c := resolverConfig{}
	applyResolvconfToConfig(&c, cfg)
	return c.perAttempt, c.attempts, nil
}
