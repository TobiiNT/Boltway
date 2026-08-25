# Can a per-tool refusal carry an authorization challenge? — measured 2026-08-25

**Question.** Does a client honour `_meta["mcp/www_authenticate"]` on a tool result with
`isError: true`, delivered over HTTP `200`, by prompting for re-authorization at the named scopes?

**Why it was asked.** `REQUIREMENTS.md` C-24 gave that as the MCP-side mechanism for scope step-up,
and C-25 records a measurement that a `200` produces no auth prompt at all. A tool result rides in a
`200`. Two rows, one of them describing a channel the other says is ignored, and no `U-*` entry
covering the difference. `docs/decisions/mcp-per-tool-authorization-2026-08.md` §1 blocked its own
§2.4 on this, because the answer selects between two incompatible designs.

**Answer: no, on both channels.** The tool-level field is not in the protocol — not "clients ignore
it", it is not there. And the HTTP challenge, which this file first said to design for, turns out to
be unreachable from a tool. §4 is that second measurement, taken after the first sent the design
that way.

---

## What was measured, and how

**1. The MCP schema, both revisions, fetched from the specification repository's `main` branch.**

| File | `LATEST_PROTOCOL_VERSION` | bytes | `www_authenticate` | any `authenticat*` | `"mcp/…"` `_meta` keys |
|---|---|---|---|---|---|
| `schema/2025-11-25/schema.ts` | `2025-11-25` | 66671 | 0 | **0** | none |
| `schema/draft/schema.ts` | `2026-07-28` | 98406 | 0 | **0** | none |

The string `authenticat` — in any casing, as any substring — does not occur in either schema. Not
the current stable revision, not the draft the 2026-07-28 release candidate is cut from.

**2. The proposal that defines it.** `_meta["mcp/www_authenticate"]` comes from **SEP-1489, *Tool
Error Responses for Triggering OAuth Flows***, `modelcontextprotocol/modelcontextprotocol` issue
1489. Read 2026-08-25: **status Draft**, carrying the repository's `draft` label — "SEP proposal
with a sponsor". It names no target specification revision. It describes intended client behaviour
as design rather than reporting adoption, and states nothing about which clients implement it.

Its shape, quoted, so a later reader can recognise it if it lands: `isError: true` together with
`_meta.mcp/www_authenticate` holding a string or array of RFC-compliant `WWW-Authenticate` header
values, plus `content` for human-readable display and backward compatibility.

**3. Vendor-side context**, `stated` rather than `measured`, from public issue trackers read the
same day: the well-specified path — `401` plus `WWW-Authenticate`, RFC 9728 metadata — has open
defects of its own in at least one vendor's connector infrastructure, including tokens that are
never refreshed on expiry and a `401` classified as a connection failure rather than as needing
authentication. Whatever weight a draft mechanism might have earned, it does not outrank a
specified path that is itself still settling.

## What was not measured

**Whether any specific client honours it anyway.** A client may implement a draft. Nothing here
drove a live client against a server emitting the field, and nothing here should be read as saying
one refuses it. What is established is narrower and enough: **no client is obliged to**, because no
revision of the protocol asks for it.

That gap closes the same way it would have before: stand a server up, emit the field, connect a
real client, and watch. If that is ever done, it belongs beside this file with its own date.

## 4. The other channel, measured 2026-08-25 after the first answer sent the design at it

The conclusion above was *use the HTTP challenge instead*. Building that closed the second door.

**Streamable HTTP has no buffered-JSON path.** A POST whose `Accept` does not include
`text/event-stream` is refused the transport outright with `406 Not Acceptable` and the message
*"Client must accept both application/json and text/event-stream"*. There is no client-side choice
that keeps the response buffered, and `HttpServerTransportOptions` exposes no server-side one — its
properties are `ConfigureSessionOptions`, `EnableLegacySse`, `EventStreamStore`, `IdleTimeout`,
`MaxIdleSessionCount`, `PerSessionExecutionContext`, `RunSessionHandler`, `SessionMigrationHandler`,
`SessionMode`, `Stateless`, `TimeProvider`, and none of them is about that.

**The event stream is open before any tool filter runs.** Measured with an `AddCallToolFilter` that
reads `IHttpContextAccessor.HttpContext.Response.HasStarted` on the way in: it is **true**, and the
client's status line is already `200`. The `HttpContext` itself is reachable — what has moved on is
the response.

So a per-tool refusal cannot be an HTTP `401` or `403`. Not "hard": the status was sent before the
tool was chosen. Whatever the connector decides, it decides it after the wire has committed.

**Both channels are therefore closed**, and a connector's per-tool refusal reaches a caller as text
in a tool result and nothing else. That is worse than a challenge and better than silence, and the
only honest thing to do is say which it is rather than implying the other.

`ToolRefusalReachTests` in `Boltway.Mcp.Tests` pins both halves as tests rather than as notes: a
client refusing the event stream gets `406`, and the filter sees `HasStarted` true. If a future SDK
buffers the response, or a future revision defines the tool-level field, one of them goes red — which
is the only way a closed door gets re-checked.

## 5. What it decides

`docs/decisions/mcp-per-tool-authorization-2026-08.md` §1 offered three outcomes and this is the
**"no"** branch on both. Its §2.4 closes without the public challenge seam it was going to need:
`BearerChallenge` stays `internal`, because the caller that would have justified opening it cannot
reach the response anyway. Surface bought for a path nobody can take is surface bought for nothing.

What the endpoint-level challenge still does, and does well, is unaffected — a token short of a
scope a **route** requires is answered `403` with `error="insufficient_scope"` before any of this,
including the part that makes it dangerous to hand-roll: a `403` without that error code is terminal
for that client, for that user and that server, with no re-authentication prompt, permanently.

**The consequence for `REQUIREMENTS.md`.** C-24's MCP column asserted a mechanism. It is a sponsored
draft that appears in no schema, and recording a proposal in a conformance matrix without its status
is the confidence error `LESSONS.md` exists to prevent — the same shape as recording "we did not
measure this" as "this is not there", one step in the other direction. That column now says what it
is and points here.

**Re-read before relying on this.** A draft with a sponsor is a draft that may land. If a future
revision adopts SEP-1489, this file becomes an archive entry and §2.4's design is worth reopening —
the tool-level channel is the better one when it exists, because it does not cost the JSON-RPC reply.
