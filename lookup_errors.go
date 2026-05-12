package acidns

import (
	"context"
	"errors"
	"net"
	"strings"

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

	// Context errors take precedence — an Exchange that was cancelled
	// mid-flight may surface a wrapped transport error, so reach past it.
	if cerr := ctx.Err(); cerr != nil {
		out := &net.DNSError{Name: name, Server: server, UnwrapErr: cerr}
		switch {
		case errors.Is(cerr, context.DeadlineExceeded):
			out.Err = "i/o timeout"
			out.IsTimeout = true
			out.IsTemporary = true
		case errors.Is(cerr, context.Canceled):
			out.Err = "operation was canceled"
		default:
			out.Err = cerr.Error()
		}
		return out
	}

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

	// Generic net.Error (dial / read timeouts, ICMP unreachable, etc.)
	var nerr net.Error
	if errors.As(err, &nerr) {
		out := &net.DNSError{
			Err: err.Error(), Name: name, Server: server, UnwrapErr: err,
			IsTimeout: nerr.Timeout(),
		}
		return out
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
