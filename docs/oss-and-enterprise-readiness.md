# Going open source, and what "enterprise" has to mean first

**Date:** 2026-08-22 · **Status:** proposal · **Scope:** the whole repository, not just `auth/`

Read against Keycloak at commit `24b761c0`, cloned shallow to `/home/user/keycloak/keycloak`.
Everything attributed to Keycloak below is `measured` — read from that source tree or from the docs
inside it — and the commit is named so a later reader can tell when it expired.

---

## 0. The scoping decision, because it changes every list below

"Enterprise level, compared against Keycloak" has two readings and they are different projects.

| | What it means | What it costs |
|---|---|---|
| **A. Enterprise-grade at what it already is** | An OAuth 2.1 authorization server for MCP connectors that an enterprise can deploy, audit, extend and depend on | Weeks |
| **B. A general-purpose identity provider** | Keycloak's job: SAML, LDAP/Kerberos federation, an admin console, themes, organizations, WebAuthn, fine-grained authorization, 107 extension points | Years, and it is Keycloak's job already |

**This document recommends A**, and the reason is not modesty. Keycloak is **744,394 lines of Java
across 8,327 files** with **1,711 test classes** and Red Hat behind it. B is not a gap list, it is a
different company. The README's own sentence — *not a general-purpose identity provider, not a
replacement for Entra ID or Auth0* — is the most valuable thing this project owns, because it is
what lets a 60,000-line codebase be complete rather than partial.

There is a real market position underneath that, and Keycloak's own documentation hands it over:

> **`2026-07-28` → "Partially Supported without Resource Indicators for OAuth 2.0"**
> — `docs/guides/securing-apps/mcp-authz-server.adoc`

RFC 8707 is a **MUST** in MCP from `2025-06-18` onward. Keycloak ships an experimental
`RESOURCE_INDICATORS` feature (177 lines, four files) whose model is *select one value from an
audience list that configuration already built*; this server's `N-01` makes the audience a
non-nullable `ResourceIdentifier` obtainable only from `IResourceRegistry`. And RFC 9728 — the
resource-server half — Keycloak correctly says is not an authorization server's job at all, which
means every Keycloak-based MCP deployment still has to write it.

**So: A. Be the thing that is finished, not the thing that is 4% of Keycloak.**

---

## 1. Tier 0 — the OSS blockers

These are not enterprise features. They are the difference between publishing source and being open
source, and the first one is legal rather than technical.

### 1.1 There is no LICENSE file. **This is the blocker.**

`find . -iname 'LICENSE*'` matches exactly one path, and it belongs to a third-party skill under
`.claude/` that `CLAUDE.md` says is never committed. **The repository itself carries no licence.**

Under the Berne Convention the default is not "public domain" and not "do what you like" — it is
**all rights reserved**. Source published without a licence grants nobody the right to use, copy,
modify or redistribute it. Every enterprise legal review terminates at that fact, and most corporate
dependency scanners refuse an unlicensed package outright.

It is worse than a missing file, because **fifteen packable projects are already publishing at
`0.7.1`**, and `.github/workflows/publish-packages.yml` says in its own comment: *"A package pushed
to a feed cannot be unpublished in any way."* Today they go to GitHub Packages; the same workflow
notes that moving to nuget.org is *"one URL in the consumer's NuGet.config"* — which is exactly the
move going OSS implies.

**Fix, in order:**

1. Choose a licence. **Apache-2.0** is the recommendation: it is what Keycloak uses, it carries an
   explicit patent grant that MIT does not, and it is the licence enterprise legal teams approve
   without a meeting. MIT is the alternative if brevity matters more than the patent grant.
2. `LICENSE` at the repository root, verbatim, unmodified.
3. `<PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>` in `auth/Directory.Build.props`
   — without it NuGet renders the package as unlicensed regardless of the repository's file.
4. A per-file header, or a deliberate decision not to have one, written down. Keycloak headers every
   file; .NET projects commonly do not. Either is defensible; silence is not.

**Do this before the next package push.** It is an afternoon, and everything else in this document
is worthless until it is done.

### 1.2 The package metadata is nearly empty

`Directory.Build.props` sets `Authors` and `RepositoryUrl` and stops. Missing: `Description`,
`PackageTags`, `PackageProjectUrl`, `PackageReadmeFile`, `PackageLicenseExpression`, `Copyright`.

A NuGet listing with no description is one a person cannot evaluate without cloning, and fifteen
packages named `Boltway.*` with no descriptions are indistinguishable from each other on a
search page. Cheap, and it is the first thing anyone sees.

### 1.3 The governance files that a contributor looks for and does not find

Keycloak carries `CONTRIBUTING.md`, `GOVERNANCE.md`, `MAINTAINERS.md`, `SECURITY.md`,
`PR-CHECKLIST.md`, `ADOPTERS.md`, `SECURITY-INSIGHTS.yml`. This repository carries `README.md` and
`LESSONS.md`.

Not all seven are needed. Two are, and one of those is a security obligation:

- **`SECURITY.md`** — **not optional for an authorization server.** It is where somebody who finds
  an authentication bypass is told how to report it privately. Without it, the reporting path is a
  public GitHub issue, which is a disclosure rather than a report. Enable GitHub private
  vulnerability reporting at the same time; it is a checkbox.
- **`CONTRIBUTING.md`** — and this repository has an unusually strong one available almost for free.
  The rules a contributor must know already exist and are unusually explicit: warnings are errors,
  `dotnet test` needs a live PostgreSQL and `scripts/postgres.sh` provides it, N-06 means never
  advertise what you do not serve, and `LESSONS.md` is what a claim about somebody else's system
  must survive. Today those are spread across `auth/README.md`, `CLAUDE.md` and code comments.
- `CODE_OF_CONDUCT.md` — conventional, cheap, expected by some corporate contributors.
- `GOVERNANCE.md` / `MAINTAINERS.md` — for two founders these are premature. Skip and say why.

### 1.4 `LESSONS.md` is a genuine differentiator and should be advertised as one

Most OSS auth projects publish a feature list. This one can publish *twelve recorded instances of
recording "we did not measure this" as "this is not there"*, and the rules that came out of them.
For a security project, a public register of the errors it has made is a stronger trust signal than
any feature table — it is the thing a careful reviewer cannot get from a competitor.

Put it above the fold in the README rather than in a "Before trusting any of it" section.

---

## 2. Tier 1 — enterprise table stakes an authorization server is actually judged on

Not Keycloak parity. The things an enterprise reviewer checks before deploying *any* AS, ranked by
how badly their absence lands.

| # | Gap | Where we are | Why it matters | Effort |
|---|---|---|---|---|
| 2.1 | **Nothing has run against a live upstream IdP** | `Boltway.Federation.Oidc` is generic and `Federation.Google` is configuration over it, but the only provider ever driven is a fake this repository hosts | An enterprise's first question is "does it federate to our Entra/Okta". "It should" is not an answer, and `D-10`'s `sub`-disambiguation concern is unresolved | 1–2 wks |
| 2.2 | **No conformance certification** | none | Keycloak is **OpenID-certified** (Core, Discovery, DCR, Session, RP-Initiated Logout, Back-Channel Logout, CIBA) and **FAPI 1.0 + 2.0 certified**. The OpenID self-certification suite is free to run and the result is a badge a procurement form has a box for | 1–2 wks |
| 2.3 | **Rate limiting is per process on two paths** | `README.md` "Before the second replica" now enumerates ten per-process facts; one — the in-memory assertion replay store — loses a security property at *n* = 2 | "How does it behave in a cluster" is asked in every review. The honest answer is written down now, which is a start; the shared-limiter seam is not built | 1 wk |
| 2.4 | **No password policy** | `Argon2idPasswordHasher` and a login throttle; no minimum length, no complexity, no reuse history, no expiry, no breach check | Every enterprise has a password standard and asks how to express it. Keycloak has a `PasswordPolicy` SPI and a Have-I-Been-Pwned provider. Note this only matters for local accounts — a federation-only deployment does not care, which is worth saying | 1 wk |
| 2.5 | **No second factor of any kind** | none — no TOTP, no WebAuthn, no recovery codes | Keycloak has all three at `DEFAULT`. For local accounts this is the most commonly-blocking single absence. **Interacts with 2.1**: if federation is the answer, MFA is the upstream's problem and this becomes a documented non-goal rather than a gap | 2–3 wks, or 0 with 2.1 |
| 2.6 | **Extension points are thin** | 31 public interfaces, several of them stores | Keycloak has **107 SPIs**, and that is why it survives requirements nobody anticipated. 107 is the wrong target; the right question is which five seams a deployment most often needs and cannot reach today — a token-claims mapper and an event sink are the obvious two | 1 wk to decide |
| 2.7 | **No structured event stream** | An append-only admin audit log, plus rejection logging | An audit log is not a SIEM feed. Enterprises want authentication events — sign-in, failure, token issued, consent granted — shipped to Splunk/Elastic. Keycloak has an events SPI plus `USER_EVENT_METRICS` at `DEFAULT`. We have metrics, which is half of it | 1–2 wks |
| 2.8 | **Upgrade and compatibility policy is unwritten** | Version `0.7.1`, no compatibility statement | At 0.x anything may break, which is fine and must be *said*. Enterprises need to know what 1.0 will promise: which surfaces are stable, what a migration looks like, how long a version is supported. Keycloak has rolling updates as a shipped feature | days |

**What we already have and should stop underselling.** The scan expected several of these to be
missing and they are not: `RealmId` threads through every lookup (14 files), three named meters with
an OpenTelemetry exporter, a health endpoint, an append-only admin audit store, a login throttle
with a documented lockout-vs-DoS trade, a full CLI, and an interaction layer with localisation.
That is a materially more complete operational surface than a 60k-line project usually has, and the
README does not say so anywhere a reviewer would look.

---

## 3. Tier 2 — protocol surface, from Keycloak's own table

Keycloak's `docs/guides/securing-apps/specifications.adoc` is the best-maintained OAuth conformance
index in open source, and it is a free roadmap. What it lists that we do not have, ranked by whether
an MCP-focused server has any reason to want it:

**Worth wanting**

- **RFC 9126 Pushed Authorization Requests** — already `D-01`, and `D-01` is the one deferral this
  repository records as costing real rework later, because FAPI 2.0 requires it. The
  `IAuthorizationRequestSource` seam it names does not exist yet. If certification (2.2) is ever the
  goal, this is on the path.
- **RFC 9449 DPoP** — `DEFAULT` in Keycloak. `D-02` defers it and the tripwire now watches for the
  day a vendor asks. Unchanged, correctly.
- **RFC 8705 mTLS / certificate-bound tokens** — `D-03`. Enterprise deployments behind a
  service mesh ask for this. Still no demand from our side.

**Probably not**

- SAML 2.0, CIBA, device flow, token exchange, identity chaining, JAR/JARM, OID4VC, AuthZEN, SCIM,
  Shared Signals. Each is a real capability and none of them is on the path from "a person authorises
  an MCP client" to "the connector serves a tool call". Listing them as *considered and declined*
  is worth more than silence — it tells a reviewer the scope is chosen rather than accidental.

---

## 4. What Keycloak has that we should deliberately never build

Stating this is load-bearing: the credibility of a small project rests on its refusals being
principled rather than incidental.

- **An admin console.** `Boltway.AdminBff` exists because `N-17` forbids a cookie principal on
  an admin endpoint. A full console is a product, and building one turns this into Keycloak's
  competitor on Keycloak's ground.
- **Themes.** Three tiers of interaction customisation already exist — theme, layout, renderer —
  with a contract test package so a custom renderer cannot silently drop an `N-14` field. That is a
  better answer than a theme engine for a server whose UI is three pages.
- **LDAP/Kerberos user federation.** A directory integration is a product. OIDC federation to
  whatever already fronts the directory is the right seam, and it is 2.1.
- **Scripting (`SCRIPTS` at `PREVIEW`).** Custom authenticators written in JavaScript inside an
  authorization server is a remote-code-execution surface with an on/off switch.

---

## 5. Suggested order

| # | Item | Effort | Why here |
|---|---|---|---|
| 1 | LICENSE + package metadata (§1.1, §1.2) | hours | Legally blocking, and a package pushed cannot be unpushed |
| 2 | `SECURITY.md` + private vulnerability reporting (§1.3) | hours | An AS without a private reporting path turns its first report into a disclosure |
| 3 | `CONTRIBUTING.md` (§1.3) | 1 day | The content already exists; it is scattered |
| 4 | Compatibility and 0.x/1.0 policy (§2.8) | 1 day | Cheap, and it is what an evaluator asks after the licence |
| 5 | One live upstream IdP, measured (§2.1) | 1–2 wks | Unblocks the federation answer, and 2.5 may fold into it |
| 6 | Structured event stream (§2.7) | 1–2 wks | The most-asked integration after federation |
| 7 | OpenID self-certification (§2.2) | 1–2 wks | Free, and it is a procurement checkbox |
| 8 | Password policy (§2.4) | 1 wk | Only if local accounts survive the §2.1 decision |

Items 1–4 total under a week and are the entire difference between *source is public* and *this is
open source*. Item 5 is the first one that changes what the software can do.

## 6. What this document is not

Not a Keycloak parity plan — §0 says why that is a different company. Not a claim that any Keycloak
capability listed here is unnecessary in general; every one of them exists because somebody needed
it. And not a market assessment: the observation that Keycloak's MCP guide reports partial
conformance is `measured` from their documentation, while what any customer will do about it is not
measured at all.
