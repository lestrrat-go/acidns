# Security policy

## Scope

acidns is a DNS toolkit. Bugs that could allow:

- denial-of-service via crafted wire input,
- cache poisoning or response forgery on the resolver/forwarder side,
- authentication bypass on TSIG / SIG(0) / DNSSEC verification,
- cryptographic key recovery in DNSCrypt,
- bypass of the authoritative server's UPDATE policy,

are in scope and qualify as security issues.

Bugs purely affecting test code, examples, CLI tools, or that require
the operator to configure the server in a way the documentation
explicitly warns against, are not in scope but are still welcome as
ordinary bug reports.

## Reporting

Please report security issues privately, **not** as public GitHub
issues. Use either:

- the GitHub "Report a vulnerability" button on the repository's
  Security tab (preferred — creates a private advisory), or
- email to lestrrat@gmail.com with subject prefix `[acidns security]`.

A reply confirming receipt should arrive within 7 days. If you have not
received one, please re-send via a different channel — your message may
have been filtered.

When you report, please include:

- a description of the issue and its impact,
- a minimal reproducer if possible (a test case is ideal),
- the commit SHA / version you tested against,
- any constraints on disclosure timing.

## Disclosure

We aim to push a fix to `main` and tag a patched release within 30 days
of confirming an issue, and to publish a GitHub Security Advisory at or
shortly before the patched release. Reporters who wish to be credited
will be acknowledged in the advisory; anonymous reports are also fine.

## Supported versions

Until the project tags a 1.0 release, only `main` is supported. After
1.0, the most recent minor version receives security fixes; older
versions may receive backports at the maintainers' discretion.
