package recursive

import (
	"context"
	"errors"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// Compile-time assertion that *Recursive implements [acidns.Resolver].
var _ acidns.Resolver = (*Recursive)(nil)

// Resolve performs an iterative recursive resolution for (name, t) and
// returns an [*acidns.Answer] carrying the matched records plus the
// synthesised raw response. Non-NoError RCODEs are returned as
// [*acidns.RCodeError] carrying the answer, matching the contract of
// [acidns.Resolver.Resolve].
//
// DNSSEC bogus answers map to SERVFAIL on the returned RCodeError, in
// line with how [Recursive.ServeDNS] surfaces them on the wire.
func (r *Recursive) Resolve(ctx context.Context, name wire.Name, t rrtype.Type) (*acidns.Answer, error) {
	entry, err := r.ResolveEntry(ctx, name, t)
	if err != nil {
		if errors.Is(err, errBogusAnswer) {
			raw := buildSynthesisedResponse(name, t, Entry{rcode: wire.RCODEServFail}, false)
			return nil, acidns.NewRCodeError(wire.RCODEServFail, acidns.NewAnswer(wire.NewQuestion(name, t), nil, raw))
		}
		return nil, err
	}
	raw := buildSynthesisedResponse(name, t, entry, entry.ad)
	question := wire.NewQuestion(name, t)
	matched := acidns.MatchAnswers(entry.answer, name, t)
	ans := acidns.NewAnswer(question, matched, raw)
	if entry.rcode != wire.RCODENoError {
		return nil, acidns.NewRCodeError(entry.rcode, ans)
	}
	return ans, nil
}

// SearchList returns nil — the recursive resolver operates on absolute
// names and does not carry a stub-resolver-style search list. Callers
// that want search-list expansion should wrap [Recursive] in
// [acidns.NewResolver] with [acidns.WithSearchList].
func (r *Recursive) SearchList() []wire.Name { return nil }

// Ndots returns zero — see [Recursive.SearchList] for the rationale.
func (r *Recursive) Ndots() int { return 0 }

// buildSynthesisedResponse projects an [Entry] back to a [wire.Message]
// so [acidns.Answer.Raw] returns something callers can inspect. The ID
// is zero (no exchange happened); RA=1 because the resolver answered
// recursively; AD is propagated from the entry only when the caller
// asks for it (the validator chain is the source of truth, not the
// cache's last-recorded AD bit).
func buildSynthesisedResponse(name wire.Name, t rrtype.Type, e Entry, ad bool) wire.Message {
	b := wire.NewMessageBuilder().
		Response(true).
		RecursionDesired(true).
		RecursionAvailable(true).
		Question(wire.NewQuestion(name, t))
	if e.rcode != wire.RCODENoError {
		b = b.RCODE(e.rcode)
	}
	if ad {
		b = b.AuthenticData(true)
	}
	for _, rec := range e.answer {
		b = b.Answer(rec)
	}
	for _, rec := range e.authority {
		b = b.Authority(rec)
	}
	for _, rec := range e.additional {
		b = b.Additional(rec)
	}
	m, err := b.Build()
	if err != nil {
		fb, _ := wire.NewMessageBuilder().Response(true).RCODE(wire.RCODEServFail).Build()
		return fb
	}
	return m
}
