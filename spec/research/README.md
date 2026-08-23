# spec/research/

Twelve primary-source distillations, written as twelve parallel research passes and consolidated
into [`../REQUIREMENTS.md`](../REQUIREMENTS.md). They are **dated reading, not a maintained
surface**, and that is the caveat the rest of this file exists to make unmissable.

Read these for the *why*: the verbatim quotes, the section numbers, and the traps that only show up
when somebody reads the RFC instead of remembering it. Read `REQUIREMENTS.md` for what this server
is actually held to. Where the two disagree, `REQUIREMENTS.md` wins — and §10 of it, a live
measurement, wins over both.

## What each one covers

| File | Covers |
|---|---|
| `oauth21-core.md` | `draft-ietf-oauth-v2-1-15` itself: PKCE mandatory for every client, ordinal redirect matching, one-time codes, refresh rotation, the six token-endpoint error codes, and the RFC 6749 registries 2.1 inherits |
| `pkce-and-native-apps.md` | RFC 7636 and RFC 8252: `S256` only, the loopback rule that ignores the port on both sides, `localhost` by name, and the downgrade check that makes a verifier required if and only if a challenge was stored |
| `discovery-metadata.md` | RFC 8414, OIDC Discovery 1.0 and RFC 9728, plus the order MCP clients really probe the well-known URLs in. Opens by correcting two premises of its own brief |
| `protected-resource-metadata-and-mcp.md` | The resource-server half: RFC 9728, the `WWW-Authenticate` challenge that points at it, and the MCP `2026-07-28` authorization pages |
| `dynamic-client-registration.md` | RFC 7591 and RFC 7592: `201` not `200`, JSON not form-encoding, MUST-ignore-unknown metadata, and `PUT` as full replacement rather than merge |
| `client-id-metadata-document.md` | CIMD `-02`, including the `-00`↔`-02` section mapping that MCP's own links still need, and the SSRF rules for dereferencing a `client_id` URL |
| `oidc-core.md` | OIDC Core 1.0 for a code-flow OP only: the `openid` gate, `nonce`, `auth_time`, UserInfo. Carries its own provenance caveat on three passages the fetcher would not reproduce |
| `token-formats-and-lifecycle.md` | RFC 9068 `at+jwt`, JWKS and `kid` rotation, introspection, revocation, and refresh-token families |
| `resource-indicators-and-audience.md` | RFC 8707: `resource` becoming `aud`, the grant set, and why a resource outside it is `invalid_target` rather than `invalid_grant` |
| `security-bcp-and-hardening.md` | RFC 9700 and RFC 6819 turned into a hardening checklist, with PAR and DPoP read and then deferred |
| `anthropic-claude-client-behavior.md` | What Claude and Claude Code put on the wire, from vendor docs, their live CIMD documents, and a field report of failures that could not be attributed |
| `openai-chatgpt-client-behavior.md` | The same for ChatGPT, and the only file here carrying a correction to itself |

## What "dated reading" means

Six of them state a fetch date, and it is **2026-08-03**: `anthropic-claude-client-behavior.md`,
`client-id-metadata-document.md`, `openai-chatgpt-client-behavior.md`, `pkce-and-native-apps.md`,
`protected-resource-metadata-and-mcp.md`, `token-formats-and-lifecycle.md`. The other six state no
fetch date at all. `REQUIREMENTS.md` names all twelve as the passes it consolidated, so they belong
to one effort — but a file that does not carry its own date cannot establish its own age, and a fact
with no date silently becomes a claim.

`openai-chatgpt-client-behavior.md` is the one that shows the shape of the risk rather than
describing it. Its first two rows said advertising `private_key_jwt` and implementing client
assertions were both mandatory. A live connection measured on **2026-08-17** said otherwise: a
server advertising only `none` links successfully. The rows were corrected in place with the
original reasoning struck through rather than deleted, because a reader who deletes it re-derives
it. That is `LESSONS.md` #8, and `../cimd-live-2026-08-17.json` is the capture that pins it.

**Nothing here is re-checked against later drafts, and no automation watches these files.**
`.github/workflows/pinned-drafts.yml` watches the two drafts pinned in `../`, not these. When a
revision lands, the requirement ids move and these do not — so a section number quoted in them may
have moved, and a "MUST" may have become something else. That is exactly why `REQUIREMENTS.md` is
the binding index and this folder is not: a distillation nobody is maintaining is safe to keep for
its reasoning and unsafe to enforce from.

Two things a reader used to trip over. Both are now corrected in place rather than in this list,
which is the useful record — a note here saying a path is wrong helps only the reader who finds the
note first:

- **Paths inside them pointed at directories that were never checked in** — a `raw/` beside
  `anthropic-claude-client-behavior.md` (git history has never held one), and a `scratchpad/rfc/` in
  `security-bcp-and-hardening.md` plus a `/tmp/…/scratchpad/cimd-02.txt` in
  `client-id-metadata-document.md`. The CIMD one now points at the draft this repository actually
  pins, `../draft-ietf-oauth-client-id-metadata-document-02.txt`; the other two say plainly that no
  local copy exists and leave the URLs as the source.
- **`REQUIREMENTS.md` cited this folder by its original scratchpad path**, and §10 cited
  `research/cimd-live-2026-08-03.json`. Both point where the files are: `spec/research/` and
  `spec/cimd-live-2026-08-03.json`.

One thing a reader still trips over, because it is real rather than a typo: **every target line here
was retargeted from ASP.NET Core 9 to .NET 10 without the framework notes being re-measured.** The
project builds on `net10.0`, so a header saying otherwise was false — but a "the default is X" claim
inside these files is still dated to when it was written. The `.NET 9` mentions that remain are a
different kind of statement and are deliberate: they say when `System.Buffers.Text.Base64Url`
appeared, which is what `docs/DESIGN.md` §1.2's struck multi-target row rests on.
