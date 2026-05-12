package acidns

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/lestrrat-go/acidns/wire"
)

// errNoSuchHost is the description string the stdlib net.Lookup* family
// puts on a [net.DNSError] for both NXDOMAIN and "name exists, no
// records of this type". Reusing the same wording lets callers that
// match on err.Error() (or compare against [net.DNSError]{Err: "no
// such host"} shapes) keep working unchanged.
const errNoSuchHost = "no such host"

// wrapLookupErr maps a Resolve / ResolveAs error into a *net.DNSError
// shaped like the ones the stdlib net.Lookup* family returns. nil
// input → nil output.
//
// The original *RCodeError (or any other underlying error) is carried
// on DNSError.UnwrapErr, so callers that want the wire-level shape can
// still recover it with errors.As. Likewise errors.Is(err,
// acidns.ErrNXDOMAIN) walks the chain into *RCodeError.Is and keeps
// matching after the wrap.
//
// host is the caller-supplied name; the trailing dot is stripped to
// match net.Lookup*'s convention of using the caller's string verbatim.
func wrapLookupErr(ctx context.Context, host string, err error) error {
	if err == nil {
		return nil
	}
	name := strings.TrimSuffix(host, ".")
	server := serverFromErr(err)

	// Protocol-shaped errors (non-NoError RCODEs) are independent of
	// the surrounding context state — check first so a transport
	// timeout never masks an RCODE that arrived just in time.
	var rcErr *RCodeError
	if errors.As(err, &rcErr) {
		switch rcErr.Code() {
		case wire.RCODENXDomain:
			return &net.DNSError{
				Err: errNoSuchHost, Name: name, Server: server,
				UnwrapErr: err, IsNotFound: true,
			}
		case wire.RCODEServFail:
			return &net.DNSError{
				Err: "server misbehaving", Name: name, Server: server,
				UnwrapErr: err, IsTemporary: true,
			}
		default:
			return &net.DNSError{
				Err: rcErr.Error(), Name: name, Server: server, UnwrapErr: err,
			}
		}
	}

	// Detect deadline / cancellation from three sources: the err chain
	// (transport returned ctx.Err() directly), ctx.Err() at wrap time,
	// or a transport timeout coinciding with a ctx deadline that has
	// passed. The third case is the race we have to handle defensively:
	// under load, conn.SetDeadline(ctx.Deadline()) can fire ~µs before
	// ctx.Err() becomes observable across goroutines, so a chain check
	// alone misses the "this WAS a ctx deadline" attribution.
	isDeadline := errors.Is(err, context.DeadlineExceeded)
	isCanceled := errors.Is(err, context.Canceled)
	if cerr := ctx.Err(); !isDeadline && !isCanceled && cerr != nil {
		isDeadline = errors.Is(cerr, context.DeadlineExceeded)
		isCanceled = errors.Is(cerr, context.Canceled)
	}
	var nerr net.Error
	isNetErr := errors.As(err, &nerr)
	if !isDeadline && !isCanceled && isNetErr && nerr.Timeout() {
		if d, ok := ctx.Deadline(); ok && !time.Now().Before(d) {
			isDeadline = true
		}
	}

	if isDeadline {
		return &net.DNSError{
			Err: "i/o timeout", Name: name, Server: server,
			UnwrapErr:   errors.Join(err, context.DeadlineExceeded),
			IsTimeout:   true,
			IsTemporary: true,
		}
	}
	if isCanceled {
		return &net.DNSError{
			Err: "operation was canceled", Name: name, Server: server,
			UnwrapErr: errors.Join(err, context.Canceled),
		}
	}

	// Generic net.Error (dial errors, ICMP unreachable, non-timeout I/O).
	if isNetErr {
		return &net.DNSError{
			Err: err.Error(), Name: name, Server: server, UnwrapErr: err,
			IsTimeout: nerr.Timeout(),
		}
	}

	return &net.DNSError{Err: err.Error(), Name: name, Server: server, UnwrapErr: err}
}

// notFoundErr is the synthetic *net.DNSError surfaced by the typed
// Lookup* functions when ResolveAs returned an empty slice with a
// NoError RCODE — the name exists, but carries no records of the
// requested type. server (if known) is the immediate upstream that
// answered, taken from Answer.Server().String().
func notFoundErr(host, server string) *net.DNSError {
	return &net.DNSError{
		Err:        errNoSuchHost,
		Name:       strings.TrimSuffix(host, "."),
		Server:     server,
		IsNotFound: true,
	}
}

// serverFromErr walks the err chain to recover the immediate upstream
// addr as a string suitable for [net.DNSError.Server]. Empty if no leaf
// in the chain carries one.
func serverFromErr(err error) string {
	var sErr *serverErr
	if errors.As(err, &sErr) && sErr.addr.IsValid() {
		return sErr.addr.String()
	}
	var rcErr *RCodeError
	if errors.As(err, &rcErr) && rcErr.Answer() != nil {
		if addr := rcErr.Answer().Server(); addr.IsValid() {
			return addr.String()
		}
	}
	return ""
}
