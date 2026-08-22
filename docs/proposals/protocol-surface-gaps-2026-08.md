# Protocol-surface gaps — an upgrade plan, read against better-auth 1.7.x

**Date:** 2026-08-22 · **Status:** proposal · **Scope:** `auth/`

## 0. Why this document exists

better-auth `v1.7.0` shipped on **2026-08-18** and landed, in one release, four things this
repository's README lists under *"what is simply not built yet"*: a CIMD plugin
(`@better-auth/cimd`), DPoP, `private_key_jwt`, and explicit per-resource modelling. It targets
**the same MCP authorization revision we do — `2026-07-28`** — and the same CIMD draft, `-02`.

That makes it the closest thing to a conformance oracle this project has ever had, and the useful
output is not a feature list. It is a ranked answer to *which of our gaps are real*.

**Confidence.** Everything stated here about better-auth is `stated`, not `measured` — read from
their published documentation on 2026-08-22. Nothing in this repository has run against a
better-auth instance. Every claim about *this* codebase is `measured`, by reading it, with file and
line cited. Rule 1 of `LESSONS.md` applies in both directions.

---

## 1. A correction that comes before the plan

`README.md` says, under **What is deliberately not implemented**:

> **Grant types other than `authorization_code` and `refresh_token`.**

That is wrong now. `client_credentials` is implemented:

- `src/Boltway.AuthorizationServer/Token/ClientCredentialsGrant.cs` — a full handler, in a
  deliberately narrowed shape (the client names an owner; a client acting purely for itself is
  refused with `ReasonCode.ClientHasNoOwner`).
- `Endpoints/TokenEndpoint.cs:169` — an arm in the dispatch switch.
- `Configuration/AuthorizationServerOptions.cs:668` — a row in `KnownGrantTypes`.

It is *off by default*, because `_grantTypesSupported` defaults to two names
(`AuthorizationServerOptions.cs:442`). **"Not in the default set" and "not implemented" are different
sentences, and the README prints the second.**

This is N-06 turned inward: a capability document that is wrong about what we have. It happens to be
wrong in the safe direction — under-claiming rather than over-claiming — which is exactly why nobody
noticed. Fix the README first; it costs an hour and it is the only item here that is a defect rather
than a gap.

While in there, the same sweep should re-check every other bullet in both capability sections
against the code. This one was found by reading; nothing tests it.

---

## 2. The gaps, ranked

Ranking axis: **does closing it remove a failure that has already happened here, or one a client can
trigger today?** Not "does better-auth have it".

### Tier 1 — real, small, and the parts already exist

#### 1.1 `/revoke` — RFC 7009, E-16

The last endpoint whose flag advertises a path nothing routes.

**Already present:**

| Part | Where |
|---|---|
| The flag, wired into the metadata document | `Configuration/AuthorizationServerOptions.cs:192`, `Metadata/MetadataBuilder.cs:112` |
| Grant revocation | `IGrantStore.RevokeAsync` (`Abstractions/Stores/IGrantStores.cs:336`) |
| Refresh-family revocation | `IRefreshTokenStore.RevokeFamilyAsync` (same file, :236) |
| Client authentication, confidential-only | `Token/ClientAuthentication.cs` — shared with introspection |
| The endpoint shape to copy | `Endpoints/IntrospectionEndpoint.cs`, 426 lines, same client-auth rule and the same "never tell the caller whether the token was real" rule |

**To write:** `Endpoints/RevocationEndpoint.cs`, routed from the existing flag so the flag both
routes and advertises — the invariant `MetadataHonestyTests` enforces.

**Then move the control.** `MetadataHonestyTests.The_sweep_catches_an_endpoint_that_is_advertised_
but_not_routed` uses `RevocationEnabled` as its deliberately-broken flag and says in its own comment
what to do next: move it to `IntrospectionEnabled`, and when no flag of that kind is left, build the
control from a broken options object instead. Doing this is part of the task, not follow-up.

**The rule most likely to be got wrong:** RFC 7009 §2.1 — an unrecognised token is `200`, not an
error. Same class as introspection's `{"active": false}`, and the reason is the same: a caller
holding a stolen token learns only that it does not work.

**Acceptance:** revoking a refresh token kills its family; revoking an access token resolves it to
its grant and denylists that, so `/introspect` flips to `active:false` and
`IAccessTokenRevocationCheck` in the resource server starts refusing; an unknown token still
answers `200`; the discovery document names `/revoke` only when it is routed.

**Effort:** ~1 day including tests. **Risk:** low — no new store, no new outbound path.

#### 1.2 Pairwise `sub` — **decided, 2026-08-22: deleted**

The decision this item asked for, with the fact that settled it. `ISubjectIdentifierService` took
`(UserAccount, ClientRecord)`; `TokenIssuer` carries `grant.Subject`, a bare `SubjectId`, and loads
no account at all — the account-claims mapper is opt-in and most deployments do not register it. So
the seam could not have been wired without adding a store read to every token issuance, which means
it would not have saved the hunt through call sites it existed to prevent. **It did not fit the path
it was declared for**, and that is a stronger reason than "unused".

Deleted rather than commented, on the precedent the top-level README sets for the JavaScript layer:
*the one nobody uses is the one that will be wrong when somebody finally does* — and this one was
already wrong. It also removes `Boltway.Identity`'s only reach into client types; password
hashing and subject minting have nothing to do with clients.

`D-11` now records what pairwise would actually cost instead of naming a seam that was not one. The
original entry follows.

#### 1.2a The original entry — pairwise `sub`, decide, do not build

`ISubjectIdentifierService` exists (`Boltway.Identity/Subjects/SubjectIds.cs:61`) and nothing on
the token path calls it. README says so, so this is not dishonest — it is dead.

We have two relying-party populations, both of them AI clients, and no correlation threat model that
pairwise addresses. better-auth ships it and also documents the trap: rotating the pairwise secret
changes every `sub` and breaks every existing session, so the secret is permanent once set. That is
a permanent operational obligation bought for a threat we do not have.

**Recommendation: delete it, or leave one comment on the interface saying it is unwired and why.**
Not a build item. It is in this document so it stops being re-discovered.

### Tier 2 — real, medium, and one of them has already been paid for

#### 2.1 A JWKS-backed key source for the resource server

**The highest value per day in this document.** Today `ProtectedResourceOptions.SigningKeys` is a
list the host fills, and nothing refreshes it — so a resource server stops accepting tokens the
moment the authorization server rotates a key. We have three-phase rotation (Pending → Active →
Retiring, `PublishLeadTime` default 24h), which means **we will rotate**, which means this is a
scheduled outage rather than a hypothetical one.

**It is a seam, not a rewrite.** `ProtectedResourceOptions.SigningKeySource` is already a
`Func<IReadOnlyList<SecurityKey>>` and `CurrentSigningKeys()` reads through it
(`Configuration/ProtectedResourceOptions.cs:159-167`). The work is a refresher behind that seam:
fetch the AS's `jwks_uri` from discovery, cache, refresh on a `kid` miss with a floor so a miss
storm cannot become a fetch storm, and fail closed on a bad document rather than emptying the list.

**Acceptance:** rotate a key on a running AS with the RS untouched, and the RS keeps accepting —
the test the sample cannot currently pass, since it fetches once at startup and says so.

**Effort:** ~1–2 days. **Risk:** low-medium (one new outbound path; reuse `Boltway.OAuth.Net`).

#### 2.2 `private_key_jwt` at `/token` — RFC 7523 · **done, 2026-08-22**

Both decisions the plan said to take first were taken. **The `aud` rule:** both the token endpoint
URL and the issuer identifier are accepted, compared ordinally. RFC 7523 §3 asks for a value
identifying the authorization server and OIDC Core §9 names the token endpoint while permitting the
issuer; real clients send one or the other, and **which one ChatGPT sends has not been measured** —
no assertion from it has been captured. Accepting both costs nothing here because there is exactly
one endpoint that takes assertions, so the cross-endpoint replay a broad audience would open has
nowhere to go. **Inline `jwks`:** unchanged. `CimdDocument` still validates it and `ClientRecord`
still has nowhere to put it, so an inline-`jwks` client is refused at resolution rather than
validated-then-dropped — the state the plan said not to leave it in was "silently discarded", and it
is not that.

The cost driver was the `jti` replay store, as predicted: a new interface, four implementations, two
sets of migrations and a contract suite. What the plan did not anticipate is that the store's
in-memory sibling is *less correct* rather than merely less durable — a per-process replay set
admits one use per replica — so startup refuses the method without a store, and the README says
plainly that the check cannot tell a shared store from a per-process one.

One thing is stricter than the RFC on purpose: a `jti` is **required**. §3 makes it optional and the
replay check a MAY, and an assertion without one is a credential whose reuse this server cannot
detect. It is also the one refusal here whose message names what is wrong, because the client can
act on it — every other one answers an opaque `invalid_client`.

The original entry follows.

**This one has already cost us.** LESSONS #8: on 2026-08-17 `chatgpt.com/oauth/client.json` was
measured carrying both spellings of the auth method, the singular naming `private_key_jwt`, and
every ChatGPT connection resolved to a confidential client **this server cannot authenticate** —
`invalid_client`, with the cause three hops away in a parser. The parser was fixed. The underlying
fact was not: we still cannot authenticate such a client.

**Already present, and it is more than expected:**

- `Clients/CimdDocument.cs` parses **and validates** `jwks` and `jwks_uri` — refuses both together
  (RFC 7591 §2), refuses a non-HTTPS `jwks_uri` (CIMD §8.6), refuses symmetric keys and private key
  material (CIMD §4.1), and **already refuses `private_key_jwt` with no `jwks_uri`** (CIMD §8.2,
  `CimdDocument.cs:209`).
- `ClientRecord.JwksUri` is carried through.
- `ClientAuthentication.cs` already reasons about `private_key_jwt` in its 401-vs-400 comment — a
  body-carried credential has no RFC 7235 challenge form, so it answers 400.
- `Boltway.OAuth.Net` is the hardened fetcher, with the RFC 6890 check and single-resolve
  pinning.

**To write:** a JWKS fetch-and-cache over `ISafeHttpFetcher` mirroring the CIMD cache's bounds; an
assertion validator; a `ClientAuthMethod.PrivateKeyJwt` arm; and the method added to
`TokenEndpointAuthMethods` **only once the authenticator is registered** — the grant rule applied to
auth methods.

**Two decisions to take before writing a line:**

1. **The `aud` rule.** RFC 7523 §3 says the token endpoint URL; OIDC Core has historically also
   accepted the issuer; live clients differ. Write the parser to accept the specification's shape
   and pin the observed values in a dated fixture — `LESSONS.md` #8 exactly, and
   `spec/cimd-live-*.json` is the precedent for where a dated observation belongs.
2. **Inline `jwks`.** `CimdDocument.cs:205` records that `ClientRecord` "carries a `jwks_uri` and has
   nowhere to put" an inline set. Either add the field or keep refusing inline-`jwks` clients
   explicitly. Do not leave it validated-then-dropped.

**The cost driver is not the crypto.** It is the `jti` replay store: a new store interface touching
all four storage providers (`InMemory`, `EntityFrameworkCore`, `Sqlite`, `PostgreSql`) and the shared
storage contract suite.

**Effort:** ~3–5 days. **Risk:** medium.

#### 2.3 Rate limiting beyond two paths — **trigger written, 2026-08-22**

The trigger is a README section, **Before the second replica**, and writing it turned out to be worth
more than this entry expected. The plan framed the gap as "the limiters are per process"; the actual
list is **ten** things, and one of them is not a budget at all.

Writing the table proved its own point twice: the first draft had nine rows and missed
`RecoveryThrottle`, whose own comment says a fleet of *n* replicas sends *n* times each number.
That one is not aimed at this server — it is *n* times the reset mail one person's address can be
made to receive.

`InMemoryClientAssertionReplayStore` — added by §2.2, after this entry was written — loses the
property it exists to provide at *n* = 2: each replica holds its own set, so one captured assertion
authenticates once per replica. Every other row loosens a bound; that row breaks a guarantee, and
**startup cannot detect it**, because the check verifies a store is registered rather than that it is
shared. So the trigger is no longer only "decide whether the numbers are enough" — it is "one of
these rows is a security decision and the others are capacity ones".

The facts were all already written down, each beside the code it describes — eleven places, each
locally honest, and nowhere to look on the day somebody adds a replica. That is the defect a trigger
fixes: not a missing fact, a missing index.

Still no shared limiter, and still for the reason below: `dec-0010` puts this on one VPS, and at one
replica per-process *is* fleet-wide. The original entry follows.

#### 2.3a The original entry — rate limiting, a trigger not a task

Today: `/authorize`'s CIMD fetch and `POST /login`, **per process**. A fleet of *n* replicas admits
*n* times each number.

`dec-0010` puts this on one VPS. **At one replica, per-process is fleet-wide**, so the gap is real
and currently costs nothing. Building a shared limiter now buys a store, a dependency and an
operational surface for a property we already have.

**Action:** add a line to the production checklist — *"before the second replica: a shared limiter,
or accept n× every number"* — and stop there. Revisit at the replica, not at this document.

### Tier 3 — prepare, do not ship

#### 3.1 DPoP — RFC 9449

`ResourceServer/Metadata/ProtectedResourceMetadata.cs:28-30` already records that setting
`dpop_bound_access_tokens_required: true` **breaks both Claude and ChatGPT today, since neither
sends DPoP**. `OAuth.Tokens/TokenDescriptors.cs:28` marks the seam where a `cnf`/`jkt` would go.

better-auth shipping DPoP is evidence about where the MCP profile is heading. It is **not** evidence
that any client we serve sends it. Those are different claims and conflating them is rule 1.

But that comment is a dated measurement written as a standing fact, which is the exact shape of
LESSONS #8 — correct when written, encoded as though it were a rule.

**Action, and it is cheap:** turn it into a **tripwire**. A test over the live client metadata
fixtures that fails when Claude or ChatGPT begins advertising DPoP, dated in its filename beside
`spec/cimd-live-2026-08-03.json` and `spec/cimd-live-2026-08-17.json`. Half a day, and it converts a
comment that will silently go stale into one that fails on purpose.

**Do not enforce it. Do not advertise it. Keep the seam.**

#### 3.2 CIMD cache parity — **read, 2026-08-22**

better-auth documents four properties for CIMD fetching. The read is done; this is what it found.
Two were already there, one was a real gap and is now closed, one is a gap and stays open.

| Property | Us | Where |
|---|---|---|
| Shared-cache freshness | **was partial, now done** | `GuardedTransport.Freshness` |
| Conditional revalidation (`ETag` / `If-None-Match`) | **no** | — |
| Per-origin fetch governor | **yes, and stricter** | `SafeHttpFetcher`, plus a second layer in the resolver |
| Fail-closed refresh preserving previous state | **yes, bounded** | `CimdClientResolver.StaleOr` |

**Freshness was reading the wrong member.** It was `response.Headers.CacheControl?.MaxAge` — the
directive for a *private* cache. Everything behind this transport is shared by construction: one
process holding one origin's document on behalf of every user of that client. RFC 9111 §5.2.2.10
gives `s-maxage` precedence for exactly that case, so an origin publishing
`s-maxage=60, max-age=3600` was being held for an hour it asked shared caches to hold for a minute —
an hour of acting on a redirect URI or a key it had already replaced. `Expires` was unread too, and
that one cost the *origin* rather than us: with no freshness at all the resolver falls back to its
300-second floor, so a document published with a day's `Expires` and no `Cache-Control` was refetched
on that floor. Both fixed, five tests, including the control that `max-age` alone still works and
that an already-past `Expires` is zero rather than absent — "stale" and "said nothing" are different
answers and only the second should get the floor.

**The per-origin governor exists, and this read got it wrong first.** Reading only
`CimdClientResolver.cs` shows a budget keyed on `client_id` — `MaxFetchesPerClientIdPerWindow`, ten a
minute — and that is genuinely not a per-origin bound: one origin can host unbounded distinct
`client_id` URLs, which is not hypothetical, because ChatGPT mints a document per connector instance.
That looked like an amplifier against any third-party origin, next to a comment claiming the opposite.
It is not: `SafeHttpFetcher` holds a second limiter keyed on `Url.Host`, 60 a minute, one layer down,
and that is what produces the `FetchOutcome.RateLimited` the resolver already handles. So we run two
governors where better-auth documents one, plus a `NegativeResultBreaker` on top. **The finding is
the near-miss, not the gap:** "I could not find it in the file I read" is not "it is not there", which
is LESSONS #9 pointed inward, and it was one edit away from a rate limiter changed for no reason.

**Conditional revalidation is a real gap and stays open.** `GuardedTransport` captures the `ETag` and
`FetchOutcome.Ok` carries it; nothing reads it, and there is no request-side field to send
`If-None-Match` with. So every refresh transfers the whole document. It is bounded rather than
alarming — the 300-second floor and 5 KB cap mean the worst case is a small body every five minutes
per client — and closing it needs a request field, a 304 arm, and a cache entry that keeps the
validator across a refresh. Worth doing when something else touches that path; not worth a change of
its own.

---

## 3. Won't do, and the reasons matter more than the list

- **Dynamic Client Registration (RFC 7591).** `/register` answers 404 on purpose. `U-02` records
  conflicting primary sources — the MCP spec ranks CIMD above DCR, and a live Auth0 tenant was
  measured with **DCR winning** — resolved defensively by advertising exactly one. better-auth calls
  DCR deprecated and never enables it implicitly. Closing this "gap" reopens a resolved question and
  risks the silent connection failure `U-02` is about.
- **Device authorization grant (RFC 8628).** No device without a browser exists in the connector
  story.
- **Back-channel logout.** Needs a client that registers a logout URI. CIMD clients do not — and
  better-auth's own CIMD plugin lists backchannel logout as unsupported for discovered clients.
- **2FA, passkey, magic link, email OTP, phone, organization/team, SAML, SCIM, API keys, captcha,
  billing.** A different product. `README.md`'s "what it is not" holds: not a general-purpose
  identity provider, not a replacement for Entra ID or Auth0. These are where better-auth is a
  framework and this is an authorization server, and reaching for them is how the second thing
  becomes a worse copy of the first.

**This half of the document is the load-bearing half.** A gap list read as a to-do list turns a
narrow server that does one job into a broad one that does none of them as well.

---

## 4. Suggested order

| # | Item | Effort | Why here |
|---|---|---|---|
| 1 | README capability correction (§1) | hours | It is a defect, not a gap. A wrong capability claim is the one thing this repository has paid for most often |
| 2 | RS JWKS refresher (§2.1) | 1–2d | Removes a scheduled outage; the seam already exists |
| 3 | `/revoke` (§1.1) | 1d | Completes the revocation story `/introspect` + `IAccessTokenRevocationCheck` already half-built |
| 4 | DPoP tripwire fixture (§3.1) | 0.5d | Cheapest item here; converts a stale-able comment into a failing test |
| 5 | CIMD cache read (§3.2) | 0.5d | Decides whether §3.2 is a task at all |
| 6 | `private_key_jwt` (§2.2) | 3–5d | Largest, and the only one with a failure already paid for |
| 7 | Rate limiting (§2.3) | — | On the second-replica trigger |
| 8 | Pairwise (§1.2) | — | Decide wire-or-delete; do not build |

Items 1–5 total under a week and close every gap that can bite at one replica. Item 6 is the one
worth scheduling deliberately.

## 5. What this document is not

Not a claim that better-auth was measured — see §0. Not a commitment to parity: parity with a
framework that has ~40 plugins is not a goal a server with one job should hold. And not a
re-litigation of build-versus-buy. That question has a different shape now than it did in June, and
it deserves its own document rather than a paragraph at the end of this one.
