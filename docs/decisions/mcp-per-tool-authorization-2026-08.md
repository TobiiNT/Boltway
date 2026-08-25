# Per-tool authorization for MCP connectors — the endpoint gate does not reach a tool

**Date:** 2026-08-25 · **Status:** open; the first item is blocked on a measurement · **Scope:** `Boltway.Mcp`, `Boltway.ResourceServer`

> **Why this sits in `docs/decisions/` while three of its four items are still open.** The
> convention in [`../README.md`](../README.md) warns that a gap list read as a to-do list is how a
> server that does one job becomes one that does none of them well. What is recorded here as
> *decided* is the shape, the ordering, and §3 — *won't do, and the reasons matter more than the
> list*. What is recorded as *open* carries the trigger that closes it, the way conditional
> revalidation stays open in [`protocol-surface-gaps-2026-08.md`](protocol-surface-gaps-2026-08.md)
> §3.2. **§1 is a measurement, not a task, and the three items after it must not be built before it
> lands** — its outcome selects between two incompatible designs for §2.1.
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

What is new is that the same package teaches the opposite from the other side. The class-level
`<summary>` on `ResourceServerAuthenticator` shows the wiring as:

```csharp
app.MapMcp("/mcp").RequireScope("docs:read");   // what makes the gate apply
```

Read on its own — which is how a consumer reads a class summary — that sentence says the gate is
applied. A consumer who follows it ships an ungated tool surface and gets **no error at any point**.
That is `N-06` on the customization surface, in the same shape as the `IStringLocalizerFactory`
episode: a documented extension point with nothing behind it.

**Confidence.** Every claim about this repository is `measured`, by reading it, with file and symbol
cited. Every claim about the MCP C# SDK is `measured` against the XML documentation shipped in
`ModelContextProtocol` and `ModelContextProtocol.AspNetCore` **2.2.0**, the version pinned in
`Directory.Packages.props`. Every claim about a vendor client's behaviour is `stated` — quoted from
`spec/REQUIREMENTS.md`, which carries its own provenance — and §1 exists precisely because one of
those `stated` claims has never been measured here. Rule 1 of [`../../LESSONS.md`](../../LESSONS.md)
applies in all three directions.

---

## 1. The measurement that comes before the plan — **open**

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

### What to measure

> Does a client honour `_meta["mcp/www_authenticate"]` on a tool result with `isError: true`,
> delivered over HTTP `200`, by prompting for re-authorization at the named scopes?
>
> **yes** / **no** / **could not tell** — never the first two alone.

Dated capture in `spec/`, filename carrying the date, attributed to how it was measured. A `U-*`
entry is allocated **in the same commit**, so the row and the capture cannot drift apart.

### What each outcome selects

| Outcome | §2.1 becomes |
|---|---|
| **yes** | A tool result carrying `_meta`. Cheap, and the JSON-RPC call completes normally |
| **no** | The refusal must short-circuit the HTTP response into a `403` challenge, abandoning the JSON-RPC reply |
| **could not tell** | Both, with the `403` as the path that is relied on, and the `_meta` as belt-and-braces — recorded as hedging rather than as knowledge |

**Nothing in §2 is built before this lands.** Building §2.1 against the wrong outcome is not a
wasted afternoon: the cost of a wrong challenge is stated in `BearerChallenge`'s own remarks —
a `403` without `error="insufficient_scope"` is *terminal* for that client, for that user and that
server, with no re-authentication prompt, permanently.

---

## 2. The gaps, ranked

### 2.1 A refusal that cannot carry a challenge — **blocked on §1**

A connector that gates a tool on a scope has no way to tell the caller *which scope would fix it*,
in a form the caller can act on. Two mechanisms exist in this repository and neither is reachable.

- **`ConnectorToolException` cannot carry structured data.** Its own remarks explain why: the SDK
  puts only the *message* of an `McpException` on the wire, so the type folds its error code into
  the message string. A `_meta` payload is not expressible.
- **`BearerChallenge` is `internal`**, and `Boltway.ResourceServer.csproj` grants
  `InternalsVisibleTo` to `Boltway.ResourceServer.Tests` and to nothing else — not to
  `Boltway.Mcp`, and certainly not to a consumer. The measured challenge shape, the one three
  vendors were tested against, is unreachable from where a per-tool decision is made.

So a connector's only options today are to hand-roll the challenge — the duplication
`BoltwayExtensions`' own remarks argue against, where the failure is permanent and silent — or to
refuse with a plain sentence and leave the caller with no way forward.

**Decided:** the step-up refusal belongs in `Boltway.Mcp`, as one public seam, whatever shape §1
selects. It is the package whose description already claims *tool-error semantics*.

**Also part of this item, and true regardless of §1:** `S-42` records RFC 9470 as not implemented
because *"scope step-up via `insufficient_scope` covers the MCP case (D-07)"*, and `D-07` repeats
it. That justification holds at the endpoint and does not hold per tool — which is the whole of §0.
The deferral may well survive; its stated reason does not, and both entries move in the same commit.

### 2.2 `CallerPrincipal` does not name the audit identity tuple — **ready**

`CallerPrincipal` carries `Actor`, `Email`, `Roles`, `Permissions`, `Scopes`, `DownstreamToken` and
`Claims`. A connector writing an audit trail needs the calling client and a stable handle for the
authorization it is acting under. Both are in the token — `JwtTokenMinter.MintAccessToken` emits
`client_id`, `jti` and `gid`, and `AccessTokenDescriptor` documents `gid` as *"our own grant
identifier"* — and both are reachable only as string lookups into `Claims`.

That is the wrong side of the seam. `IConnectorAuthenticator` is *"deliberately the whole
interface"*, and an implementation that authenticates without an authorization server has nothing to
put in a dictionary key it was never told about. The result is every connector inventing its own key
strings, and the abstraction being shaped by whichever implementation was written first.

**Decided:** three properties, **nullable and not `required`**:

| Property | Claim | Why it is separate |
|---|---|---|
| `ClientId` | `client_id` | Which client, as distinct from which person |
| `TokenId` | `jti` | Identifies one token. Changes on every refresh — `TokenIssuer` mints it as a fresh `Guid` per token |
| `GrantId` | `gid` | Stable across a whole refresh family. The grouping key an audit trail actually wants |

`TokenId` and `GrantId` are both present because they answer different questions and are trivially
confused: a connector reaching for "which session" will take `jti` unless the type tells it
otherwise, and will then find its records fragmenting at every refresh with nothing failing.

`required` would break every existing consumer's initializer, so these are additive and null means
*the authenticator did not learn one* — the same reading `Permissions` and `Scopes` already carry.

**Also in this commit:** `ConnectorCaller` exposes shorthands for `Roles` and `Permissions` but not
for `Scopes`, which is the one `ConnectorAuth.cs` names as the thing a connector gates a tool on.

### 2.3 A per-tool scope gate — **ready, and deliberately minimal**

The SDK now has the two hooks this needs, and `Boltway.Mcp` references the package that carries
them without using either:

| API | What it gives |
|---|---|
| `McpRequestFilterBuilderExtensions.AddCallToolFilter` | One interception point for every `tools/call` |
| `McpRequestFilterBuilderExtensions.AddListToolsFilter` | Filtering `tools/list` per caller |
| `MessageContext.User` | The `ClaimsPrincipal`, documented as reaching handlers *"without requiring dependency on HTTP context accessors"* |

Both are registered through `McpServerBuilderExtensions.WithRequestFilters`.

Filtering `tools/list` is not cosmetic. Without it a caller is advertised a tool it will always be
refused, and a model that reads a tool list as a capability list will retry against it.

**Decided:** ship the minimum — gate a tool on a scope set, and filter the advertised list to match.
Nothing about *arguments*. §3 says why.

**One configuration hazard to assert against.** `HttpServerTransportOptions.PerSessionExecutionContext`
defaults to `false`, which is correct here: handlers run with the execution context of the HTTP
request that carried them, so identity is per request. Set to `true` — a reasonable-looking choice
for session-wide `AsyncLocal` state — the identity that reaches a tool is the one from the request
that *opened the session*, and a narrowed or re-issued token stops taking effect with nothing
failing. A gate whose input can silently freeze is worse than no gate.

### 2.4 An example that teaches the wrong gate — **ready, documentation only**

Independent of whether 2.3 ships. The `ResourceServerAuthenticator` summary must stop reading as
"this is how tools are gated", and should point at whatever 2.3 leaves behind — or, if 2.3 does not
ship, at `CallerPrincipal.Scopes` and the paragraph that explains it.

This is the cheapest item here and the one with the worst ratio if left: it is the surface a
consumer copies from.

---

## 3. Won't do, and the reasons matter more than the list

**Resource-argument matching.** Gating a tool on *which host* or *which path* an argument names is
a connector's decision, not this library's. Argument names, their meanings, and whether a given one
even denotes a resource are all connector-specific; a generic matcher would be configuration
pretending to be a security boundary. What belongs here is the scope-to-tool decision, which every
MCP connector shares.

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
§1  measure ──────────────────────────► capture in spec/ + a U-* entry, same commit
        │
        ├── selects the design for §2.1
        │
§2.2 ───┼── independent of §1, and the one that shapes a consumer's abstraction
§2.4 ───┘   documentation only, independent of everything
        │
§2.3 ── independent of §1; §2.1 is what its refusal path then uses
        │
§2.1 ── last, because it is the only item §1 can invalidate
```

§2.2 and §2.4 can land before §1 returns. §2.1 cannot.

Because §2.2 and §2.3 both change the public surface, the release ritual applies in full and in the
same commit as the surface move:

1. `<Version>` in `Directory.Build.props` moves off `0.2.0`.
2. `PackageValidationBaselineVersion` moves to the release before the new one — **after** the
   version moves, never equal to it. A test holds it to `CHANGELOG.md`'s second heading.
3. `CHANGELOG.md` gets the new heading. Anything breaking is marked in bold at the front; at 0.x a
   break is permitted and the point of permitting it is that it is announced.
4. §2.3 adds a capability, so `docs/CAPABILITIES.md` and the README's *What you get* table move in
   the same commit. `CAPABILITIES.md` currently mentions `Boltway.Mcp` once, for `AddJwksSigningKeys`
   — there is no row yet for anything MCP-authorization-shaped.
5. `tests/Boltway.PublicApi.Tests` compiles against the new members with no `InternalsVisibleTo`
   grant. That build **is** the check that §2.2's properties are genuinely public.
6. Every new rule gets a test that is red without the change, and a control proving the accepting
   path still accepts.
7. This document's index row in [`../README.md`](../README.md) moves with its status.

## 5. What this document is not

It is not a plan for any particular connector. The gap in §0 is a property of MCP's single-endpoint
transport and of `RequireScope`'s endpoint scope, and it holds for every connector built on this
library regardless of what its tools do.

It is not permission to widen `Boltway.Mcp` into a policy engine. §3's first two entries are the
boundary, and they are the half of this document most likely to still matter after §2 closes.

It is not a measurement of any client. §1 is the measurement, it has not been taken, and until it is
dated in `spec/` the C-24 mechanism remains `stated` — which is the whole reason §2.1 is blocked
rather than merely last.
