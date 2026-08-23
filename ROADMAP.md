# Roadmap

What is not built here, measured against what an authorization server gets judged on. This is a
gap list rather than a plan with dates: nothing below is committed to, and the point of writing it
down is that a reader can tell an absence somebody chose from one nobody has looked at.

Everything attributed to Keycloak is `measured`, read from its source tree at commit `24b761c0` on
**2026-08-22**. The commit is named so a later reader can tell when it expired; nothing here has
been re-measured since.

**This was `docs/oss-and-enterprise-readiness.md`, and its Tier 0 — the section that called the
missing `LICENSE` file "the blocker" — was still telling readers this repository was unlicensed
after the licence, the package metadata, `SECURITY.md`, `CONTRIBUTING.md`, `VERSIONING.md` and
`CHANGELOG.md` had all shipped. That section is gone rather than corrected: a finished checklist is
not a roadmap, and a document that reports the state of the world has to be either true or
deleted.

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
| ~~2.8~~ | ~~**Upgrade and compatibility policy is unwritten**~~ — **done.** `VERSIONING.md` states what 0.x promises and what 1.0 will; `CHANGELOG.md` records the breaks; `EnablePackageValidation` makes an unintended one fail the pack | Was: version `0.7.1` (itself wrong — the feed says 0.1.0), no compatibility statement | At 0.x anything may break, which is fine and must be *said*. Enterprises need to know what 1.0 will promise: which surfaces are stable, what a migration looks like, how long a version is supported. Keycloak has rolling updates as a shipped feature | days |

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
| ~~1–4~~ | ~~LICENSE, package metadata, `SECURITY.md`, `CONTRIBUTING.md`, the 0.x/1.0 policy~~ | — | **Done.** Kept as rows rather than deleted so the ordering below still reads as an argument rather than a list starting at five |
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
