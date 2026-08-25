# spec/

Four kinds of document live here, and only the first is a statement of what this server is held to.
Telling them apart is what this file is for.

| | |
|---|---|
| [`REQUIREMENTS.md`](REQUIREMENTS.md) | the binding index. Requirement ids are cited from `src/`, `tests/` and the README |
| `draft-ietf-oauth-*.txt` | two Internet-Drafts, pinned. Somebody else's text under somebody else's licence — see below |
| `cimd-live-*.json` | dated captures of what two vendors actually serve, wired in as test fixtures |
| `mcp-tool-challenge-2026-08-25.md` | why a tool result cannot carry an authorization challenge: the field C-24 named is a sponsored draft and is in no schema. Read before designing a per-tool refusal |
| [`research/`](research/README.md) | twelve primary-source distillations, fetched once and not maintained |

## `REQUIREMENTS.md` is the binding index

Numbered requirements in eight id families: `S-*` conformance matrix (§1), `E-*` endpoint contract
(§2), `X-*` error codes (§4), `N-*` non-negotiables (§5), `C-*` client compatibility (§6), `A-*`
Auth0-trap requirements restated as acceptance criteria (§7), `D-*` deferred (§8), `U-*` unverified
and open (§9). `U` rows are questions; everything else binds unless its own row says otherwise. §3
prints the metadata document this server publishes; §11 adds the user-management ids.

**No count here, deliberately.** `REQUIREMENTS.md` used to carry a per-prefix tally and it was wrong
on five of the eight prefixes, with nothing reading the file to catch the sixth. Count from the
tables if you need a number — a number belongs here when something asserts it.

An id gets cited rather than its sentence copied, and `CLAUDE.md` makes the other half of that a
rule: **keep the id's own entry true in the same commit.** An id whose entry has drifted is worse
than no id, because the citation is what a reader follows instead of re-deriving the reason.

Two things about reading it:

- **§10 wins on conflict with §6 and §9.** It is a live measurement taken 2026-08-03 against real
  connections, and it corrects rows above it. `docs/DESIGN.md` says the same in its own header.
- **The section numbers are not the file order.** §10 sits at the end, after §11 and the appendix.
  Read the numbers, not the sequence.

## Why two Internet-Drafts are checked in

`draft-ietf-oauth-v2-1-15.txt` and `draft-ietf-oauth-client-id-metadata-document-02.txt`.

`S-01` requires citing the exact draft revision — "OAuth 2.1" unqualified is not a citation, because
there is no RFC number and the normative text still moves. `U-15` turns that into three obligations
on this repository: cite the revision, **pin a copy**, and re-diff on each new one.

The pinned copy is not redundancy. Each of these files says of itself that it "may be updated,
replaced, or obsoleted by other documents at any time", and both carry an expiry — 3 September 2026
for OAuth 2.1, 7 January 2027 for CIMD. A URL at `ietf.org` serves whatever revision is current, so
a link is not a citation of the text the requirement ids were written against. The file here is.

The third obligation is a standing instruction whose trigger lives on somebody else's website, and
nothing was watching it. [`.github/workflows/pinned-drafts.yml`](../.github/workflows/pinned-drafts.yml)
now asks the IETF datatracker every Monday whether each of these is still the current revision, and
when one is not it opens or updates a tracking issue rather than leaving a red run in a tab nobody
visits. **A red there is work owed, not a broken commit.** An unreachable datatracker fails the run
and files nothing, because an outage is not evidence and a signal that cries wolf gets trained out
of its reader.

## These two files are not under this repository's licence

Both drafts carry, verbatim and identically:

> Copyright (c) 2026 IETF Trust and the persons identified as the document authors.  All rights
> reserved.
>
> This document is subject to BCP 78 and the IETF Trust's Legal Provisions Relating to IETF
> Documents (https://trustee.ietf.org/license-info) in effect on the date of publication of this
> document. […] Code Components extracted from this document must include Revised BSD License text
> as described in Section 4.e of the Trust Legal Provisions and are provided without warranty as
> described in the Revised BSD License.

So, stated plainly: they are **IETF Internet-Drafts, © 2026 IETF Trust and the persons identified as
the document authors**, redistributed here under BCP 78 and the IETF Trust Legal Provisions, with
the Revised BSD grant of TLP §4.e attaching to Code Components taken out of them. **Neither file is
covered by this repository's Apache-2.0.** Redistributing them is fine; saying so is the part that
was missing.

The root [`LICENSE`](../LICENSE) is Apache-2.0, so without a statement to the contrary a licence
scanner walking this tree reads two third-party documents as ours to relicense. [`NOTICE`](../NOTICE)
is that statement, and it is the machine-findable one — this section is the reasoning behind it.
Both move together or neither does.

If a Code Component is ever lifted out of one of these into `src/`, TLP §4.e attaches the Revised
BSD text to the copy, and that copy gets named in `NOTICE` in the same commit. Until then the
packages carry none of this material and their metadata is Apache-2.0 with nothing attached.

## `cimd-live-*.json` are fixtures, not loose snapshots

Two captures of the Client ID Metadata Documents that Claude, Claude Code and ChatGPT actually
serve: `cimd-live-2026-08-03.json` and `cimd-live-2026-08-17.json`. The date is in the filename
because `LESSONS.md` #8 is about a measurement encoded as a standing fact, and a fixture that fails
when the world moves is the only place a dated observation belongs.

**Despite the extension, neither is a JSON document.** Each is a capture log — a `// url` comment
line followed by that URL's response body, repeated. The extension is there because the bodies are.
The 08-17 file opens with three comment lines recording what changed: both ChatGPT documents grew
`token_endpoint_auth_method`, the RFC 7591 singular, beside the RFC 8414 plural they already
carried.

**They are wired in, and adding one takes no edit anywhere.**
`tests/Boltway.AuthorizationServer.Tests` globs `spec/cimd-live-*.json` into its output directory as
`Content`; `CimdClientResolverTests` enumerates whatever it finds and drives every captured document
through the resolver, and `No_captured_vendor_document_asks_for_dpop` — the `D-02` tripwire — reads
the same files for any `dpop`-prefixed member. `Every_capture_in_spec_is_read` asserts both by name,
so a broken glob fails loudly instead of passing as a theory over an empty set.

That test exists because the opposite happened. `cimd-live-2026-08-17.json` — the capture recording
the change that made every ChatGPT connection resolve to a client this server could not
authenticate — sat in this directory for a release read by nothing, while the document it recorded
was transcribed into a `.cs` file instead. Dropping a new capture in here is now the whole ritual.

## `research/`

The twelve primary-source distillations `REQUIREMENTS.md` was consolidated from. Dated reading
rather than a maintained surface, and [`research/README.md`](research/README.md) says what each one
covers and why that distinction is the reason they are safe to keep.
