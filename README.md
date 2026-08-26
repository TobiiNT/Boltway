# Boltway — OAuth 2.1 authorization server for MCP connectors

[![ci](https://github.com/TobiiNT/Boltway/actions/workflows/ci.yml/badge.svg)](https://github.com/TobiiNT/Boltway/actions/workflows/ci.yml)
[![Boltway.AuthorizationServer on NuGet](https://img.shields.io/nuget/v/Boltway.AuthorizationServer?label=Boltway.AuthorizationServer&color=004880)](https://www.nuget.org/packages/Boltway.AuthorizationServer)
[![Boltway.Mcp on NuGet](https://img.shields.io/nuget/v/Boltway.Mcp?label=Boltway.Mcp&color=004880)](https://www.nuget.org/packages/Boltway.Mcp)
[![.NET 10](https://img.shields.io/badge/.NET-10.0-512BD4)](https://dotnet.microsoft.com/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/TobiiNT/Boltway/blob/main/LICENSE)

Put an MCP server behind authentication that Claude and ChatGPT can complete with no administrator
in the loop. An OAuth 2.1 + OpenID Connect authorization server for .NET 10, written from scratch,
shipped as libraries you host — plus a resource-server half your MCP server references.

**Not** a general-purpose identity provider or an Entra ID replacement. No user registration, no
multi-tenancy. Some protocol endpoints are absent on purpose and some are simply unbuilt;
[Capabilities](https://github.com/TobiiNT/Boltway/blob/main/docs/CAPABILITIES.md) keeps the two
apart, because a list that blurs them is worse than none.

## What you get

On with no flag, in the configuration the quickstart builds.

| | |
|---|---|
| **Flow** | Authorization code, PKCE required of every client |
| **Tokens** | RFC 9068 `at+jwt`, ID token, refresh with derived rotation |
| **Replay** | A reused refresh token revokes its family and the grant |
| **Audience** | RFC 8707 resource indicators |
| **Discovery** | RFC 8414, OIDC, JWKS, `/userinfo` |
| **Clients** | CIMD — connect by URL, no registration step |
| **Pages** | Sign-in, consent and error, satisfying N-14 |
| **Accounts** | Argon2id locally, or any OIDC provider upstream |
| **MCP half** | Bearer gate, RFC 9728 metadata, per-tool policy on `tools/list` and `tools/call` |
| **Rotation** | Publish-ahead key ring; the RS follows `jwks_uri` |
| **Deployables** | Two images, plus a compose file and PostgreSQL |
| **Storage** | PostgreSQL or SQLite, one shared contract suite |
| **Observability** | Three meters and an append-only admin audit log |

`MetadataHonestyTests` drives every advertised grant through `/token` and hunts for an endpoint the
document promises and nothing routes. This table cannot drift without the build going red.

## Install

```bash
dotnet add package Boltway.AuthorizationServer   # the server you host
dotnet add package Boltway.Mcp                   # what your MCP server references

# In your test project. Eight assertions against your own wired pipeline, asking
# what a client asks — every one of them failed on a real deployment whose unit
# suite was green.
dotnet add package Boltway.ResourceServer.Testing
```

Watch a whole flow first — 15 steps, `401` through refresh:

```bash
dotnet run --project samples/Boltway.Sample.AuthorizationServer   # terminal 1
dotnet run --project samples/Boltway.Sample.ResourceServer        # terminal 2
./samples/drive-flow.sh                                           # terminal 3
```

Or `cp .env.example .env && docker compose up` for both images, PostgreSQL and a TLS proxy.

## Capabilities

Four states, kept apart on purpose. Full lists and the reasoning behind each:
**[docs/CAPABILITIES.md](https://github.com/TobiiNT/Boltway/blob/main/docs/CAPABILITIES.md)**.

| State | Examples |
|---|---|
| **On** | The table above |
| **Built, off by default** | `/revoke`, `/introspect`, `/logout`, `private_key_jwt`, `client_credentials`, admin API and CLI, self-service, password recovery |
| **Absent on purpose** | jwt-bearer grant, pairwise `sub`, CIMD persistence |
| **Not built yet** | Dynamic registration, `net8.0` targeting, rate limiting past two paths |

Off is not absent, and unbuilt is not refused. Conflating them is how a shipped capability spent a
release filed under "not implemented", with nothing breaking and nobody looking.

## Hosting it yourself

The authorization server is a library, so a deployment writes a `Program.cs`. The smallest one that
starts and serves discovery is 45 lines. `MapBoltwayAuthorizationServer` names **every** missing
service in one exception rather than one per restart.

Prefer not to write it? `hosts/Boltway.AuthorizationServer.Host` is the same library as one image,
configured entirely by environment.

→ **[docs/HOSTING.md](https://github.com/TobiiNT/Boltway/blob/main/docs/HOSTING.md)** — the
quickstart, the twelve services you supply, and signing in through an upstream provider.
→ **[docs/INTERACTION-PAGES.md](https://github.com/TobiiNT/Boltway/blob/main/docs/INTERACTION-PAGES.md)**
— theming the pages, in three tiers.
→ **[docs/LOCALIZATION.md](https://github.com/TobiiNT/Boltway/blob/main/docs/LOCALIZATION.md)** —
replacing the English text.

## Running it

**Every package targets `net10.0` only, and that is a limit.** An MCP server on net8.0 cannot
reference `Boltway.ResourceServer` at all. The blocker is `System.Buffers.Text.Base64Url`, .NET 9
and later — measured, not assumed. Fixing it means hand-writing unpadded base64url in the primitive
that encodes PKCE verifiers, so it is a decision about crypto-adjacent code rather than a packaging
chore.

→ **[Production checklist](https://github.com/TobiiNT/Boltway/blob/main/hosts/Boltway.AuthorizationServer.Host/README.md#production-checklist)**
— twelve settings with no safe default.
→ **[Before the second replica](https://github.com/TobiiNT/Boltway/blob/main/hosts/Boltway.AuthorizationServer.Host/README.md#before-the-second-replica)**
— everything counted per process, and what each costs at *n* > 1. One row is a security property
rather than a budget.

## Running the tests

```bash
./scripts/postgres.sh up          # once per machine boot, Docker or not
dotnet test Boltway.slnx
```

`Boltway.Storage.PostgreSql.Tests` **fails** rather than skips without a real server. A storage
suite that skips itself is green in exactly the situation where it measured nothing.

## Layout

| | |
|---|---|
| `src/` | The sixteen packages |
| `hosts/` | Two images: the server, and the admin BFF |
| `testing/` | Contracts, shipped so you run the suite we do |
| `samples/` | The smallest pair completing a whole flow |
| `tests/` | One suite per package, plus architecture and public-API |
| `spec/` | Requirements, pinned drafts, dated vendor captures |
| `docs/` | Everything else written down |

One tree, one solution. That is load-bearing: `Boltway.Mcp` once lived in a second tree, so the
architecture scan never walked it, and folding them together turned two rules red immediately. One
was a network fetch outside the guarded HTTP client, there since the code was written.

`Boltway.ResourceServer` does not reference `Boltway.AuthorizationServer`, and the absence is the
design.

**A wired pipeline is not a unit, and the defects that live there are the expensive ones.** Derive
`ProtectedResourceContract` from `Boltway.ResourceServer.Testing` against your own application and
it asks what a client asks: both RFC 9728 well-known forms answering without a credential, the
challenge naming a `resource_metadata` URL that is really reachable, a bad token producing a `401`
rather than a `403`. The first consumer outside this repository found three of those broken by hand,
with curl, after 402 unit tests passed — the usual cause being a host whose own authentication
middleware has never heard of the framework's anonymous marker.

## Where to read next

| | |
|---|---|
| [Capabilities](https://github.com/TobiiNT/Boltway/blob/main/docs/CAPABILITIES.md) | What is on, off, refused, unbuilt — and why |
| [Hosting](https://github.com/TobiiNT/Boltway/blob/main/docs/HOSTING.md) | Wiring a `Program.cs` |
| [Roadmap](https://github.com/TobiiNT/Boltway/blob/main/ROADMAP.md) | The gaps, measured against Keycloak |
| [Contributing](https://github.com/TobiiNT/Boltway/blob/main/CONTRIBUTING.md) | House rules, and how a release is cut |
| [Governance](https://github.com/TobiiNT/Boltway/blob/main/GOVERNANCE.md) | One maintainer, a bus factor of 1 stated as a number, and what constrains them |
| [Lessons](https://github.com/TobiiNT/Boltway/blob/main/LESSONS.md) | Thirteen times we recorded a guess as a fact |
| [Design](https://github.com/TobiiNT/Boltway/blob/main/docs/DESIGN.md) · [Requirements](https://github.com/TobiiNT/Boltway/blob/main/spec/REQUIREMENTS.md) | The decisions, and the ids cited from the code |
| [All documents](https://github.com/TobiiNT/Boltway/blob/main/docs/README.md) | Indexed, each marked current or dated |

## Versions and licence

`0.x`, where anything may break.
[VERSIONING.md](https://github.com/TobiiNT/Boltway/blob/main/VERSIONING.md) says what `1.0` will
promise; [CHANGELOG.md](https://github.com/TobiiNT/Boltway/blob/main/CHANGELOG.md) records every
break as it lands.

Apache-2.0 — see [LICENSE](https://github.com/TobiiNT/Boltway/blob/main/LICENSE) — chosen over MIT
for the patent grant, which is what matters to anyone adopting protocol code inside a company.
[NOTICE](https://github.com/TobiiNT/Boltway/blob/main/NOTICE) names the two IETF drafts under
`spec/` that are **not** covered by it.

Security reports go to
[SECURITY.md](https://github.com/TobiiNT/Boltway/blob/main/SECURITY.md), never the issue tracker.

**Links here are absolute on purpose.** This file is packed into all 18 packages, and a relative
link resolves to nothing on nuget.org.
