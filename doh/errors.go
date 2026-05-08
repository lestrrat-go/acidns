package doh

import "fmt"

// HTTPStatusError is returned by Exchange when the DoH endpoint replies
// with a non-200 HTTP status. It preserves the response body (capped at
// 1 KiB) so callers can surface server-supplied diagnostic text without
// re-issuing the request.
type HTTPStatusError struct {
	// StatusCode is the HTTP status code (e.g. 503).
	StatusCode int
	// Status is the full status line as reported by net/http (e.g.
	// "503 Service Unavailable"), useful for logging.
	Status string
	// Body is the (possibly truncated) response body.
	Body []byte
}

func (e *HTTPStatusError) Error() string {
	if len(e.Body) == 0 {
		return fmt.Sprintf("doh: http %d", e.StatusCode)
	}
	return fmt.Sprintf("doh: http %d: %s", e.StatusCode, e.Body)
}

// Class returns the HTTP status-code class — 1, 2, 3, 4, or 5 — so callers
// can branch on "any 5xx" without remembering the exact code:
//
//	var hse *doh.HTTPStatusError
//	if errors.As(err, &hse) && hse.Class() == 5 {
//	    // upstream is unhealthy
//	}
func (e *HTTPStatusError) Class() int { return e.StatusCode / 100 }

// Is reports whether target is an *HTTPStatusError with the same
// StatusCode. This lets callers use errors.Is against pre-built
// sentinels (e.g. &HTTPStatusError{StatusCode: 503}).
func (e *HTTPStatusError) Is(target error) bool {
	t, ok := target.(*HTTPStatusError)
	if !ok {
		return false
	}
	return e.StatusCode == t.StatusCode
}
