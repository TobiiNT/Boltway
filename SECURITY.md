# Security policy

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private reporting:
[Security → Report a vulnerability](https://github.com/TobiiNT/Boltway/security/advisories/new).

If that is unavailable to you, say so in a public issue *without any detail* - just that you have a
report and cannot file it privately - and a private channel will be opened. Never put the detail in
that issue.

What helps, roughly in order:

- The version, and whether you reproduced it against `main`.
- Which surface: an endpoint, a store, one of the seams a deployment implements.
- A request sequence or a failing test. A test that goes red on `main` and green on your fix is the
  fastest possible report.
- What an attacker gets. "This is reachable unauthenticated" and "this needs a valid token for
  another client" are different reports.

You will get an acknowledgement within a week. This is a small project and that is a real limit
rather than a promise dressed up as one - if a week passes with silence, send a reminder.

## What is in scope

Everything under `src/`, `hosts/` and `testing/`. In particular:

- Token issuance, validation, and the refresh rotation.
- Redirect URI matching, PKCE, and the consent flow.
- Anything that dereferences a URL somebody else supplied - CIMD documents, client `jwks_uri`,
  upstream issuers. These reach the network on an attacker's say-so and are the most interesting
  surface here.
- Authorization: the role and permission gates, and the scope-to-audience binding.
- The storage implementations, including the optimistic-concurrency behaviour.

## What is out of scope

Not because these do not matter, but because a report about them is not a vulnerability report:

- **Anything a deployment configures wrong.** A permissive redirect URI, `AllowPrivateAddresses`
  turned on, `DEV_TOKENS` in production. The README's *Production checklist* is the list; if you
  found a way to misconfigure it that the checklist does not warn about, that is a documentation
  issue and a welcome one.
- **The `DEV_TOKENS` static-token path.** It is a development affordance, it has no discovery
  surface on purpose, and it is not a credential system.
- **Missing capabilities.** *What is deliberately not implemented* and *What is simply not built
  yet* in the README are honest lists. An absent endpoint is not a vulnerability; an endpoint that
  is advertised and absent is, and that one is worth reporting.
- **Findings from a scanner with no reachability analysis.** A dependency advisory that no code path
  reaches is a maintenance issue - file it as an issue, not a report.

## Disclosure

Report privately, and give a fix a reasonable chance to ship before publishing. If the project is
unresponsive past what you consider reasonable, publish - an unmaintained security-critical library
that nobody knows is unmaintained is worse than a disclosed bug.

Reporters are credited in [`CHANGELOG.md`](CHANGELOG.md), under the version that carries the fix,
unless they ask not to be. That file rather than "the release notes": a release here cuts an
annotated tag, whose message is not visible to anyone who has not cloned, so the changelog is
where the credit would actually be read.

## A note on what this software is

Boltway issues credentials that grant access to somebody's data. A defect here is not a crash; it is
a stranger holding a token they should not have, usually silently. That is why the build treats
warnings as errors and why the architecture rules fail the build rather than warn. If you are
reading this file because you are evaluating the project, read *What is simply not built yet* in the
README first - the fastest way to be insecure with this library is to assume a capability it says
plainly that it does not have.
