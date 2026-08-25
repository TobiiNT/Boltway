# Per-tool authorization for MCP connectors — the endpoint gate does not reach a tool

**Date:** 2026-08-25 · **Status:** open; the measurement that blocked §2.4 is taken · **Scope:** `Boltway.Mcp`, `Boltway.ResourceServer`

> **Why this sits in `docs/decisions/` while most of its items are still open.** The convention in
> [`../README.md`](../README.md) warns that a gap list read as a to-do list is how a server that
> does one job becomes one that does none of them well. What is recorded here as *decided* is the
> shape, the ordering, and §3 — *won't do, and the reasons matter more than the list*. What is
> recorded as *open* carries the trigger that closes it, the way conditional revalidation stays open
> in [`protocol-surface-gaps-2026-08.md`](protocol-surface-gaps-2026-08.md) §3.2. §1 was a
> measurement rather than a task; it has been taken, and §2.4 is no longer waiting on anything.
>
> **Revised the same day it was written.** The first draft ranked the documentation fix last as the
> cheapest item, proposed shipping a per-tool gate, and did not mention the scope-claim gap at all.
> Reading a connector already built on this library moved all three: §2.1 is the documented example,
> and it has a six-and-a-half-hour production outage behind it; §2.2 is a fail-open nobody had
> written down; §2.5 is what is left of the gate after that connector showed which half is generic.
> The original ranking is preserved in git rather than restated here.
>
> **Citations name a file and a symbol, never a line.** Same reason as the sibling record: a line
> number is a claim that expires on the next edit anywhere above it, and nothing checks it.

## 0. Why this document exists

`RequireScope` gates an **endpoint**. An MCP server exposes every one of its tools through a
**single** endpoint. So the scope a connector advertises for an individual tool is enforced by
nothing, and withdrawing that scope takes no capability away.

This is not news to the codebase. `CallerPrincipal.Scopes` in `Boltway.Mcp/ConnectorAuth.cs` states
it exactly, and says carrying the granted set is what lets a connector gate a tool itself:

> `RequireScope` on an endpoint answers "may this request reach the server at all". It cannot answer
> "may this request write", because one MCP endpoint carries every tool: a required scope there is
> the intersection of what the tools need, so the widest scope a connector advertises is enforced by
> nothing.

What is new is that the same package teaches the opposite from the other side, and that a connector
built on it has already paid for the difference in production. The class-level `<summary>` on
`ResourceServerAuthenticator` shows the wiring as:

```csharp
app.MapMcp("/mcp").RequireScope("docs:read");   // what makes the gate apply
```

Read on its own — which is how a consumer reads a class summary — that sentence says the gate is
applied. It is not, and §2.1 is what the line costs beyond leaving tools ungated.

**Confidence.** Every claim about this repository is `measured`, by reading it, with file and symbol
cited. Every claim about the MCP C# SDK is `measured` against the XML documentation shipped in
`ModelContextProtocol` and `ModelContextProtocol.AspNetCore` **2.2.0**, the version pinned in
`Directory.Packages.props`. Claims about a connector built on this library are `measured` by reading
that connector's source on **2026-08-25**; the incident timings in §2.1 are that deployment's own
measurement, recorded in its source beside the code that fixed it, and are `stated` here. Claims
about a vendor client's behaviour are `stated`, quoted from `spec/REQUIREMENTS.md`, and §1 exists
because one of them has never been measured. Rule 1 of [`../../LESSONS.md`](../../LESSONS.md)
applies in every direction.

---

## 1. The measurement that came before §2.4 — **answered 2026-08-25**

`spec/REQUIREMENTS.md` carries two rows that cannot both be simply true.

**C-24**, on scope step-up, gives the MCP-side mechanism as:

> tool-level `_meta["mcp/www_authenticate"]` with `isError: true`

**C-25**, on the 401 handshake, records a measurement:

> `401` is **required** — "Claude does not honor a `WWW-Authenticate` header on a `200` response". A
> `200` + `isError:true` produces **no auth prompt at all**

A tool-level refusal rides inside a JSON-RPC result, and that result is carried by an HTTP `200`.
So C-24 describes a challenge delivered in exactly the envelope C-25 measured as producing nothing.
One of them is scoped more narrowly than its wording suggests, and which one decides the design.

**No `U-*` entry covers this.** `U-01` through `U-17` are the unresolved list, and the question of
whether a tool-level `_meta` challenge on a `200` is honoured is not among them. A mechanism named
in a requirement row, with no implementation and no entry in the unverified list, reads as settled.
It is not.

### The answer: **no**, and not because clients ignore it

The capture is [`../../spec/mcp-tool-challenge-2026-08-25.md`](../../spec/mcp-tool-challenge-2026-08-25.md).
Measured that day:

- `_meta["mcp/www_authenticate"]` is **SEP-1489**, *Tool Error Responses for Triggering OAuth
  Flows*, and it is in **Draft** status with a sponsor. It names no target revision and reports no
  client adoption.
- The substring `authenticat` — any casing, any position — occurs **zero times** in the
  `2025-11-25` schema and **zero times** in the `draft` schema the `2026-07-28` release candidate is
  cut from. Neither defines any `mcp/…` `_meta` key.

So the two rows never disagreed. C-25 measured a client ignoring a `WWW-Authenticate` **header** on
a `200`; C-24 named a **field inside a tool result** that no revision of the protocol asks any
client to read. There is no mechanism there to honour yet.

**This is the `no` branch, and it selects the design:** a per-tool refusal that wants to be
actionable must reach the client as an HTTP `401`/`403` challenge, not as a field inside a `200`.
`BearerChallenge` already writes that challenge, and getting it wrong is expensive in the way its
own remarks describe — a `403` without `error="insufficient_scope"` is terminal for that client, for
that user and that server, with no re-authentication prompt, permanently.

`REQUIREMENTS.md` C-24's MCP column moved in the same commit as the capture: it asserted a
mechanism, and it now says what that field actually is and points at the file. No `U-*` entry was
allocated, because the question is answered rather than unresolved — and a `U-*` row for a settled
question is the same defect one column over.

**What is still not measured** is whether some client honours the draft anyway. Nothing here drove a
live client against a server emitting the field, and nothing here says one refuses it. The claim is
narrower and sufficient: no client is *obliged* to. If SEP-1489 lands, §2.4 is worth reopening — a
tool-level channel is the better one when it exists, because it does not cost the JSON-RPC reply.

---

## 2. The gaps, ranked

### 2.1 The documented example instructs every client to ask for too little — **ready, and first**

`RequireScope` declares **two** things, and the second is the one nobody expects.
`RequiredScopeMetadata`'s own remarks are accurate about it:

> Metadata rather than a filter, so that the same declaration is visible to the middleware that
> writes the `401` as well as to the one that writes the `403`. […] the MCP scope-selection strategy
> reads the challenge's `scope` first and falls back to the metadata document's whole
> `scopes_supported` only when the challenge has none, so an endpoint that declares its scopes gets
> a minimal grant and one that does not gets everything.

*A minimal grant* is the intended reading when an endpoint's scopes are its tools' scopes. On an MCP
endpoint they are not, because every tool is behind one route — so the declaration silently becomes
an instruction to every client about what to request, for the whole server.

**What that cost, on a connector built on this library.** A read scope was declared on the MCP
endpoint. The write scope was declared in the host, advertised in both RFC 9728 documents, shown on
the consent screen, and enforced in the tools — every part correct on its own. But the challenge
named only the read scope, so every client asked for only that, consent never offered the write
scope, and no token that server minted ever carried it. Nothing reported it: reads worked, the
health endpoint was green, and the deployment's own verification script printed that its scopes
agreed. It surfaced only when the write scope became enforced at the tools, at which point every
write stopped at once and re-consenting could not help.

That deployment's own record, in its source: the last successful write landed at 09:19 UTC,
enforcement shipped at 10:01 UTC, and it was found six and a half hours later by a person reporting
they had lost write access.

Declaring both scopes is **not** the fix: `RequireScope` requires *every* named scope, so a genuine
read-only grant would be refused its reads. Declaring none leaves the challenge carrying the
resource's whole `ScopesSupported`, which is what lets a client ask for what the tools actually
need. That connector now maps its MCP endpoint with `RequireBearer()` and gates scopes in the tools.

**Decided.** The example on `ResourceServerAuthenticator` becomes `RequireBearer()`, and carries the
reason rather than only the call — a consumer who copies a line without the paragraph is the case
this item exists for. `RequiredScopeMetadata`'s remarks are already correct and stay; the problem is
that a reader reaches them only after copying the wrong example.

**Open, and worth answering in the same change:** whether the library can make this hard rather than
documented — a startup diagnostic when `RequiredScopeMetadata` is found on an endpoint the MCP
transport mapped. That is a design question, not a line, and this is `N-06`'s shape on the
customization surface: a documented extension point that does the opposite of what its example says.

### 2.2 A scope claim's absence is indistinguishable from its emptiness — **ready, and a fail-open**

`CallerPrincipal.Scopes` collapses three states into one empty set:

| The token | What the connector should do |
|---|---|
| carried no `scope` claim | fall back — the server publishes no scopes, and the connector's own table answers |
| carried a `scope` claim that granted nothing | refuse — the token was written to grant nothing |
| carried a `scope` claim this library could not parse | neither of the above, and certainly not the first |

`ResourceServerAuthenticator.FromClaims` yields the empty set for all three. The third is not
hypothetical: `ScopeSet.TryParse` rejects a claim **whole** when it carries any character outside
RFC 6749's scope-token set, so one stray character produces the same empty set as no claim at all.

A connector reading that has to pick a fallback, and the first two states want opposite ones. Picking
*fall back* — the reading `CallerPrincipal.Permissions` already documents for permissions, and the
one that keeps a static-token deployment working — means a **malformed scope claim grants more than
the token said**. That is the dangerous direction, and it is the direction the documented reading
points.

Measured on a connector built on this library: it reached that conclusion the hard way and now
carries its own helper that asks whether the claim key is present before trusting `Scopes`, with a
comment recording that one stray character made a restriction look like an absence and switched its
scope gate off for a caller whose token was written to restrict them.

**Decided.** Name the state on the type. Only this library knows which of the three produced the
empty set, and every connector that does not ask is failing open. `LESSONS.md`'s first rule is that
every axis needs a third value; this is an axis with three values collapsed into one, on the type
that decides how much authority a token carries.

The shape is a design choice — a nullable granted-set, or an explicit three-valued state beside
`Scopes` — but the requirement is not: a connector must be able to tell the three apart without
reading `Claims` by string key, and the existing `Scopes` property must keep working for consumers
that do not care.

### 2.3 `CallerPrincipal` does not name the audit identity tuple — **ready**

`CallerPrincipal` carries `Actor`, `Email`, `Roles`, `Permissions`, `Scopes`, `DownstreamToken` and
`Claims`. A connector writing an audit trail needs the calling client and a stable handle for the
authorization it is acting under. Both are in the token — `JwtTokenMinter.MintAccessToken` emits
`client_id`, `jti` and `gid`, and `AccessTokenDescriptor` documents `gid` as *"our own grant
identifier"* — and both are reachable only as string lookups into `Claims`.

That is the wrong side of the seam. `IConnectorAuthenticator` is *"deliberately the whole
interface"*, and `BearerAuthenticator` — this library's own static-token implementation — has
nothing to put in a dictionary key it was never told about. The result is every connector inventing
its own key strings, and the abstraction being shaped by whichever implementation was written first.
Measured: a connector on this library reads `Claims["client_id"]` by hand for exactly this.

**Decided:** three properties, **nullable and not `required`**:

| Property | Claim | Why it is separate |
|---|---|---|
| `ClientId` | `client_id` | Which client, as distinct from which person |
| `TokenId` | `jti` | Identifies one token. Changes on every refresh — `TokenIssuer` mints it as a fresh `Guid` per token |
| `GrantId` | `gid` | Stable across a whole refresh family. The grouping key an audit trail actually wants |

`TokenId` and `GrantId` are both present because they answer different questions and are trivially
confused: a connector reaching for "which session" will take `jti` unless the type tells it
otherwise, and will then find its records fragmenting at every refresh with nothing failing.

**`ClientId` is stored verbatim and never normalised.** Measured on a connector: that value is
written into a git trailer on every commit it makes, and its own note says the value is a surface
rather than a model, so mapping one to another would be `assumed` recorded as `measured`. Canonical
casing, trimming or URL normalisation here would silently rewrite what a consumer's history means.

`required` would break every existing consumer's initializer, so these are additive, and null means
*the authenticator did not learn one* — the reading `Permissions` and `Scopes` already carry.

**Also in this commit:** `ConnectorCaller` exposes shorthands for `Roles` and `Permissions` but not
for `Scopes`, which is the one `ConnectorAuth.cs` names as the thing a connector gates a tool on.

### 2.4 A refusal that cannot carry a challenge — **ready; §1 chose the HTTP challenge**

A connector that gates a tool on a scope has no way to tell the caller *which scope would fix it*,
in a form the caller can act on. Two mechanisms exist here and neither is reachable.

- **`ConnectorToolException` cannot carry structured data.** Its own remarks explain why: the SDK
  puts only the *message* of an `McpException` on the wire, so the type folds its error code into
  the message string. A `_meta` payload is not expressible.
- **`BearerChallenge` is `internal`**, and `Boltway.ResourceServer.csproj` grants
  `InternalsVisibleTo` to `Boltway.ResourceServer.Tests` and to nothing else. The measured challenge
  shape, the one three vendors were tested against, is unreachable from where a per-tool decision is
  made.

This has a caller before it is written: measured on a connector, its per-tool scope gate already
throws an `insufficient_scope` refusal, documented there as the refusal that re-consenting fixes and
a role refusal does not. Today that distinction reaches nobody.

**Compatibility constraints, measured rather than assumed.** `ConnectorToolException` is subclassed
by at least one consumer, using the two-argument constructor. Whatever this item adds:

- it must **not** seal the type;
- it must **not** change or remove `(string reason, string code = "invalid_input")`;
- a new optional parameter, or a sibling type, is safe.

**A related question belongs with this one.** The same connector filed it, in the remarks of its own
test: `UseConnectorCaller` is path-prefix middleware and runs **before** routing, so no endpoint is
resolved and no `RequiredScopeMetadata` can be read. Measured on that deployment, a `POST` to the
MCP path is challenged with the endpoint's declared scope while a `GET` to the same path is
challenged with the resource's whole scope list — two answers to one question, from one path. Their
note says routing cannot fix what happens before routing, that it belongs here next to the challenge
writer, and that it is a design question rather than a line. It is the same code as this item and
should be answered with it.

**Also part of this item, and true regardless of §1:** `S-42` records RFC 9470 as not implemented
because *"scope step-up via `insufficient_scope` covers the MCP case (D-07)"*, and `D-07` repeats
it. That justification holds at the endpoint and does not hold per tool — which is the whole of §0.
The deferral may well survive; its stated reason does not, and both entries move in the same commit.

### 2.5 Filtering `tools/list`, and a seam — **ready, and narrower than this document first proposed**

The SDK has the hooks, and `Boltway.Mcp` references the package that carries them without using
either:

| API | What it gives |
|---|---|
| `McpRequestFilterBuilderExtensions.AddListToolsFilter` | Filtering the advertised list per caller |
| `McpRequestFilterBuilderExtensions.AddCallToolFilter` | One interception point for every `tools/call` |
| `MessageContext.User` | The `ClaimsPrincipal`, documented as reaching handlers *"without requiring dependency on HTTP context accessors"* |

Both filters are registered through `McpServerBuilderExtensions.WithRequestFilters`.

Advertising a tool a caller will always be refused is a defect on its own: a model reads a tool list
as a capability list and will retry against it.

**Decided: ship the plumbing, not the policy.** The first draft of this document proposed a per-tool
scope gate. Measured on a connector built on this library, that is the wrong half to generalise. It
gates every tool on two axes — a scope check per tool, and a role-to-permission table with its own
resolution order — plus a reflection test that fails its build when a write tool ships without a
guard. None of that has a generic equivalent: the role vocabulary is a deployment's, and §2.2 shows
the scope fallback is subtle enough that a library shipping the wrong default would gate wrongly in
the dangerous direction for every consumer at once.

So: the list filter, the seam a connector plugs its own decision into, and the documentation that
the two belong together. Not a table, not a vocabulary, not a default answer.

**One configuration hazard to assert against.** `HttpServerTransportOptions.PerSessionExecutionContext`
defaults to `false`, which is correct here: handlers run with the execution context of the HTTP
request that carried them, so identity is per request. Set to `true` — a reasonable-looking choice
for session-wide `AsyncLocal` state — the identity that reaches a tool is the one from the request
that *opened the session*, and a narrowed or re-issued token stops taking effect with nothing
failing. A gate whose input can silently freeze is worse than no gate.

### 2.6 Move a consumer onto the baseline before shipping any of this — **ready, and first in wall-clock**

`EnablePackageValidation` diffs each packable project against `PackageValidationBaselineVersion`,
which is the release before the one being packed. **A consumer two releases back is not covered by
that diff at all.** Shipping the next version would validate the previous release against it, while
a consumer pinned to the one before that compiles a span the gate never looked at.

Measured: a connector on this library pins the first release. Every breaking entry in the second
release's `CHANGELOG.md` — the rendered class prefix, the translation-arity startup check, the
container's log-format default, and a test package withdrawn from the feed — lands on the
authorization server, the container image, or the storage packages, none of which that connector
references. So the uncovered span is empty **today**.

Nothing proves that, and nobody will check next time. Bringing the consumer to the current release
first costs nothing now and makes the gate mean what it claims for the release after.

---

## 3. Won't do, and the reasons matter more than the list

**A policy engine.** §2.5 is the long version. The short one: a deployment's role vocabulary is the
deployment's, and a shipped default for the scope fallback would be wrong in the fail-open direction
for every consumer simultaneously — which is precisely §2.2.

**Resource-argument matching.** Gating a tool on *which host* or *which path* an argument names is a
connector's decision, not this library's. Argument names, their meanings, and whether a given one
even denotes a resource are all connector-specific; a generic matcher would be configuration
pretending to be a security boundary.

**Anything that inspects the content of an argument.** Not a matcher, not a pattern list, not a
"looks dangerous" heuristic. A library that ships one is understood to have made a safety claim it
cannot keep, and consumers stop looking for the boundary that would actually hold.

**Hosts, paths, tenants or any other resource identity encoded into scope strings.** A scope set is
published in `scopes_supported`, which is an unauthenticated document, and it is rendered on a
consent screen a person is expected to read. Putting deployment topology in there publishes it,
makes consent unreadable, and turns every new resource into an authorization-server configuration
change plus a re-consent. Per-resource scopes already have a home: `ResourceRegistration` takes a
`ScopeSet` alongside the resource identifier.

**A second RFC 9728 implementation.** Settled once already, and the reasoning in `BoltwayExtensions`
holds unchanged: two half-supported implementations is worse than one supported one, and the one
nobody exercises is the one that will be wrong.

**Re-implementing what already ships.** Named so that a reader of §2 does not widen it:

| Already here | Where |
|---|---|
| RFC 8707 audience binding, enforced by the type system | `AccessTokenDescriptor.Audience` is non-nullable and obtainable only from the resource registry |
| Per-resource scope declaration | `ResourceRegistration` |
| Revocation without introspection on every call | `IAccessTokenRevocationCheck`, `IntrospectionRevocationCheck`, and the `gid` claim they read |
| Protected-resource metadata in both discovery shapes | `ProtectedResourceMetadataEndpoints`, `WellKnownResourceUri` |
| `insufficient_scope` at the endpoint, with the measured challenge shape | `BearerChallenge`, X-34 |

---

## 4. Order, and the ritual that binds it

```
§2.6  move the consumer to the current release ──► done 2026-08-25, unverified: no CI ran
§1    measure ──────────────────────────────────► done 2026-08-25, capture in spec/
         │
         └── chose the HTTP challenge for §2.4

§2.1  documented example + the startup-diagnostic question   ─┐
§2.2  scope-claim absence vs emptiness                        ├─ nothing blocks any of these
§2.3  the identity tuple                                      │
§2.5  list filter + seam                                      │
§2.4  the refusal, as a 401/403 rather than a _meta field     ─┘
```

§2.1 and §2.2 are the two a consumer is exposed to right now — one instructs clients to ask for too
little, the other fails open on a malformed claim — so they go first among the code changes. §2.6
goes before all of them because it is what makes the release gate cover the consumer at all.

Because §2.2, §2.3 and §2.5 change the public surface, the release ritual applies in full and in the
same commit as the surface move:

1. `<Version>` in `Directory.Build.props` moves off `0.2.0`.
2. `PackageValidationBaselineVersion` moves to the release before the new one — **after** the
   version moves, never equal to it. A test holds it to `CHANGELOG.md`'s second heading.
3. `CHANGELOG.md` gets the new heading. Anything breaking is marked in bold at the front; at 0.x a
   break is permitted and the point of permitting it is that it is announced.
4. §2.5 adds a capability, so `docs/CAPABILITIES.md` and the README's *What you get* table move in
   the same commit. `CAPABILITIES.md` currently mentions `Boltway.Mcp` once, for
   `AddJwksSigningKeys` — there is no row yet for anything MCP-authorization-shaped.
5. `tests/Boltway.PublicApi.Tests` compiles against the new members with no `InternalsVisibleTo`
   grant. That build **is** the check that §2.3's properties are genuinely public.
6. Every new rule gets a test that is red without the change, and a control proving the accepting
   path still accepts. §2.2 needs three cases, not two.
7. This document's index row in [`../README.md`](../README.md) moves with its status.

## 5. What this document is not

It is not a plan for any particular connector. The gap in §0 is a property of MCP's single-endpoint
transport and of `RequireScope`'s endpoint scope, and it holds for every connector built on this
library regardless of what its tools do. §2.1 and §2.2 were found on one, but neither is that
connector's bug — both are this library's surface behaving as documented.

It is not permission to widen `Boltway.Mcp` into a policy engine. §3's first three entries are the
boundary, and they are the half of this document most likely to still matter after §2 closes.

It is not a measurement of any client's runtime behaviour. §1 measured what the protocol defines and
what SEP-1489's status is, which is a different thing and is said as one in the capture: no client is
obliged to read that field, and nobody here watched one decide.
