# Contributing to acidns

Thanks for your interest. acidns is a DNS toolkit; the wire codec, the
transport packages, the resolver and the server framework all share one
codebase, so cross-cutting changes are common. The notes below keep
review cycles short.

## Before opening a PR

- Run `go build ./...`, `go test ./...`, `go vet ./...`, and
  `golangci-lint run ./...` locally — CI runs all four and won't merge a
  red branch.
- For a non-trivial behavioural change, open an issue first describing
  the intended API surface. The package layout in `CLAUDE.md` and the
  RFC support matrix are deliberate; expect questions about both.
- Pre-1.0 the public API is not stable, but every breaking change still
  needs a one-line note in the PR description.

## Style

The repo follows the lestrrat-go house style codified in `CLAUDE.md`:

- Public types are interfaces only when they prevent footguns; plain
  value carriers are exported structs with unexported fields.
- Constructors take functional options (`New(...Option)`); options
  live in `option.go` per package.
- Builders for compound objects: `pkg.NewXxxBuilder().A(...).Build()`.
- No `interface{} / any` in public signatures unless genuinely
  polymorphic.
- Errors: sentinel `var ErrXxx = errors.New(...)` for matchable
  conditions; wrap with `fmt.Errorf("...: %w", err)`.
- Tests use `github.com/stretchr/testify/require`. Tests live in the
  external `xxx_test` package unless an internal-only invariant
  requires `xxx` package access.
- Wire code is hand-written, never reflection-based. Each RR type has a
  dedicated `pack` / `unpack` pair with bounds-checked reads.

## Commit messages

Single line, lowercase imperative, ≤ 50 characters, no body, no
trailing period. e.g. `add bailiwick check on glue`.

## Security

If you believe you've found a vulnerability, please follow the process
in [SECURITY.md](SECURITY.md) rather than opening a public issue.
