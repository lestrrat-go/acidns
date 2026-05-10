package doh

import (
	"errors"
	"fmt"
)

// ErrNilHandler is returned by [NewServer] / [NewHandler] when no
// handler is supplied.
var ErrNilHandler = errors.New("doh: handler is nil")

// ErrTLSConfigRequired is returned by [NewServer] when no
// [WithServerTLSConfig] is supplied. DoH inherits HTTPS' TLS
// requirement; a server without TLS is not DoH.
var ErrTLSConfigRequired = errors.New("doh: WithServerTLSConfig is required")

// ErrInvalidEndpoint is returned by [New] when the supplied endpoint
// URL fails to parse.
var ErrInvalidEndpoint = errors.New("doh: invalid endpoint")

// ErrPlaintextRefused is returned by [New] when the supplied endpoint
// uses http:// without [WithInsecure]. Real DoH is HTTPS-only.
var ErrPlaintextRefused = errors.New("doh: refusing plaintext http:// endpoint")

// ErrInsecureTransport is returned by [New] when [WithHTTPClient]
// supplies a transport with InsecureSkipVerify enabled. Refused
// rather than silently bypassing certificate validation.
var ErrInsecureTransport = errors.New("doh: HTTPClient transport disables certificate verification")

// ErrUnexpectedContentType is returned by [Exchanger.Exchange] when
// the response is not application/dns-message.
var ErrUnexpectedContentType = errors.New("doh: unexpected response content type")

// ErrResponseTooLarge is returned by [Exchanger.Exchange] when the
// response body exceeds the configured byte cap.
var ErrResponseTooLarge = errors.New("doh: response exceeds size cap")

// ErrIDMismatch is returned by [Exchanger.Exchange] when the response
// transaction ID does not match the request.
var ErrIDMismatch = errors.New("doh: response ID does not match request")

// ErrQuestionMismatch is returned by [Exchanger.Exchange] when the
// response question section does not echo the request question.
var ErrQuestionMismatch = errors.New("doh: response question does not match request")

// ErrDuplicateWrite is returned by the server's [acidns.ResponseWriter]
// when WriteMsg is called more than once on a single HTTP response.
var ErrDuplicateWrite = errors.New("doh: WriteMsg called twice on a single HTTP response")

// HTTPStatusError is returned by Exchange when the DoH endpoint replies
// with a non-200 HTTP status. It preserves the response body (capped at
// 1 KiB) so callers can surface server-supplied diagnostic text without
// re-issuing the request.
type HTTPStatusError struct {
	statusCode int
	status     string
	body       []byte
}

func NewHTTPStatusError(code int, status string, body []byte) *HTTPStatusError {
	return &HTTPStatusError{statusCode: code, status: status, body: body}
}

// StatusCode returns the HTTP status code (e.g. 503).
func (e *HTTPStatusError) StatusCode() int { return e.statusCode }

// Status returns the full status line as reported by net/http (e.g.
// "503 Service Unavailable"), useful for logging.
func (e *HTTPStatusError) Status() string { return e.status }

// Body returns the (possibly truncated) response body.
func (e *HTTPStatusError) Body() []byte { return e.body }

func (e *HTTPStatusError) Error() string {
	if len(e.body) == 0 {
		return fmt.Sprintf("doh: http %d", e.statusCode)
	}
	return fmt.Sprintf("doh: http %d: %s", e.statusCode, e.body)
}

// Class returns the HTTP status-code class — 1, 2, 3, 4, or 5 — so callers
// can branch on "any 5xx" without remembering the exact code:
//
//	var hse *doh.HTTPStatusError
//	if errors.As(err, &hse) && hse.Class() == 5 {
//	    // upstream is unhealthy
//	}
func (e *HTTPStatusError) Class() int { return e.statusCode / 100 }

// Is reports whether target is an *HTTPStatusError with the same
// StatusCode. This lets callers use errors.Is against pre-built
// sentinels (e.g. doh.NewHTTPStatusError(503, "", nil)).
func (e *HTTPStatusError) Is(target error) bool {
	t, ok := target.(*HTTPStatusError)
	if !ok {
		return false
	}
	return e.statusCode == t.statusCode
}
