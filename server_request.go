package acidns

import "context"

// rawRequestKey is the unexported context key under which the Server
// framework stashes the raw bytes of the incoming DNS message before
// dispatching to a Handler.
type rawRequestKey struct{}

// RawRequest returns the raw wire bytes of the inbound DNS message
// associated with ctx. The Server framework attaches the bytes before
// calling the Handler; handlers (and middleware/policies invoked from
// them) can use this to perform TSIG / SIG(0) verification, which
// signs over the original wire encoding rather than a re-marshalled
// view (compression isn't byte-stable).
//
// If ctx was not produced by the Server framework (e.g. a Handler is
// being unit-tested in isolation), the second return is false and the
// caller should fall back to re-marshalling [wire.Message] or refusing
// to verify a signature.
func RawRequest(ctx context.Context) ([]byte, bool) {
	b, ok := ctx.Value(rawRequestKey{}).([]byte)
	return b, ok
}

// contextWithRawRequest returns ctx with raw attached. Used by the
// Server framework's UDP and TCP listeners; not exported because the
// only legitimate caller is inside the framework itself.
func contextWithRawRequest(ctx context.Context, raw []byte) context.Context {
	return context.WithValue(ctx, rawRequestKey{}, raw)
}
