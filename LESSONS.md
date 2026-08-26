# One mistake, thirteen times

> **Where this comes from.** The ledger below was written against a different
> program: a read-only sweep that inspected what other operators published about
> their OAuth surface and drew conclusions from it. That program is not part of
> this repository. The document is here because the rule it produced governs this
> code and is cited by name from a dozen files under `src/` — and because it was
> learned expensively rather than reasoned out. The operators whose infrastructure
> was measured are not named: every technical claim below survives without them,
> and *Conduct* at the end is the reason they are not.

That program read other people's infrastructure without permission to write to
it, and then drew conclusions. Over two days of doing that — two sweeps of a few
hundred domains each, seven API doc reviews and three rounds of verification —
**every significant error was the same error**:

> **Recording "we did not measure this" as "this is not there."**

And it failed in the same direction every time: **inventing a defect in a
stranger's system.** Not once did the bug make someone look better than they
were. That asymmetry is the point of this document.

The individual bugs are written up where they live. This is the ledger, because
the pattern is worth more than any of them.

---

## The ledger

| # | Where | Not measured | Reported as | Blast radius |
|---|---|---|---|---|
| 1 | `discover` tier | Keycloak never emits `none` in `token_endpoint_auth_methods_supported` | "no public client" | 11 of 29 issuers |
| 2 | `discover` tier | IdentityServer does not either | "no public client" | 9 more — **20 of 29, 69%** |
| 3 | `discover` vendor | `vendorOf` tested the discovery *URL* for `/connect/`, which never matches | every IdentityServer filed as `self` | hid #2 for a week |
| 4 | prospect list | a readiness column judged the **company** | read as judging the **issuer** | 5 of 7 issuers had no relationship to the API |
| 5 | `classify` MCP | RFC 9728 present | "directory-ready" | one operator: complete discovery, no public client |
| 6 | `classify` AS | RFC 8414 §3.1 puts `.well-known` *between* host and path; we appended | "AS publishes no readable metadata" | every path-bearing issuer, including a very well-known one |
| 7 | `classify` http | timeout and 429 returned status `0` | "no readable metadata" | 3 wrong, 5 unknowable; **34 gaps → 26** |
| 8 | `verify.py` | any `WWW-Authenticate` header | "complete discovery chain" | RFC 9728 §5.1 needs a `resource_metadata` pointer |
| 9 | `classify` prose | sampled the top 8 of a sorted list | "no auth vocabulary in the docs" | 8 consecutive pages of 1 product line out of 5 |
| 10 | `classify` prose | extension filter tested the whole URL | a **stylesheet** containing "oauth" | an operator scored `connector?` off `batch.css` |
| 11 | `classify` docs | required the landing page to look like docs | GitBook renders client-side | regressed a correct answer |
| 12 | prospect list | 4 rows added by hand, unmarked | indistinguishable from measured | 3 of 7 Tier A rows |
| 13 | this repository | what makes a name resolve to a special-use address | "someone pointed the server at a private address"; "a rebinding signal" | every CIMD client on a network that filters its host — signed out, while the same block spelled `NXDOMAIN` kept them working |

Plus two that are the same shape one layer down, and were already known before
this: **soft 404s** (one operator answers 200 with its 510 KB homepage for any
path) and **wildcard DNS** (one apex made all 7 candidate doc hosts appear to
exist).

Row 13 is the first one in this repository's own code rather than in the survey
that produced the rest, and it is worth saying what it took to find: not a
failing test — the tests pinned the wrong behaviour and stayed green — but
somebody asking what a deployment would see if it were hosted where a fetch to
one client's host is blocked. The answer was a sentence naming an attacker.
A filtered resolver, split-horizon DNS for a name a company hosts internally,
and an actual attack are one observation from outside; picking the third and
writing it into a doc comment made the other two invisible. It also cost more
than the wording: the inference was load-bearing, and refusing to serve the
cache on the strength of it broke clients while refusing no further connection,
because the address check had already refused one.

Link-local is the exception and it is worth keeping straight, because "every
axis needs a third value" is not the same as "nothing can be concluded":
nothing benign resolves a public name into `169.254.0.0/16`. One reading is
sometimes all there is, and the rule is to say which case you are in.

---

## Why it always fails the same way

Because absence is cheap to observe and expensive to establish.

A request that fails produces *something* — a status, an exception, an empty
body. Code has to do work to distinguish "I asked and the answer was no" from "I
never got an answer." The lazy branch is `if (!ok) return notThere`, and it is
always sitting right there.

Then a second effect compounds it: **a stock constant reads like a measurement.**
Keycloak's `token_endpoint_auth_methods_supported` is the same five strings on
every realm on earth. It looks exactly like data. The tell was that four realms
across three unrelated operators returned byte-identical arrays — and nobody
looked until a subagent said "that inference is not sound."

The combination produces confident, specific, wrong claims about named
companies. #7 put nine of them in a committed file.

---

## The rules that come out of it

**1. Every axis needs a third value.** Not `yes`/`no` but `yes`/`no`/`could not
tell`. `discover` already had this in `coverageOf` and it is the best code in the
repository — it exists so that "no host was probed" cannot read like "no IdP is
there." `classify` shipped without an equivalent and reproduced the same bug one
layer up. Where you cannot measure, emit `unmeasurable` and rank it *above* the
measured negatives, because a question is cheaper to resolve than a change.

**2. A negative needs a control.** A `dev.` host looks like a doc host until you
fetch the apex and find the same bytes. Under wildcard DNS, a hostname nobody
ever created resolves too — the control is to ask for one you invented.
Before believing "not there", ask what a *known*-absent thing returns from the
same endpoint. Almost every false positive here would have died to one control
request.

**3. Validate against known answers, and re-run all of them every time.** Seven
domains whose answers were already established caught four bugs in `classify`.
Two of those four fixes **regressed a case the tool already had right**, and only
re-running the whole set caught it. A fix verified on the case that motivated it
is not verified.

**4. Distrust byte-identical results across unrelated operators.** That is the
signature of a constant, not a finding.

**5. Mark provenance.** A curated file that mixes measured rows with hand-added
ones, and says nothing about which is which, will be read as entirely measured.
Three of seven Tier A rows were hand-added.

**6. Read the RFC for the URL, not just for the field.** #6 and #8 are both
specification details — where `.well-known` goes, what a challenge must carry —
that produced confident wrong output for a whole class of targets.

**7. A test that skips is rule 1 with the third value thrown away.** The
PostgreSQL storage suite was `[SkippableFact]` because this environment has no
Docker daemon, with a stated reason and a `NotMeasured` result — which is
exactly what rule 1 asks for, and it still failed, because nobody reads the
third value in a test summary. `Passed! Failed: 0` is what a person sees, and
the leg that never ran is the one that deploys — every green run on this machine
exercised SQLite as the only relational store, while PostgreSQL is what the
deploy configures. The fix is not a better skip message: **make the suite fail,
and make the thing it needs easy to start** — `scripts/postgres.sh`, one
command, container or native. A dependency that is hard to set up will be
skipped, and then it will be skipped forever.

**8. A measurement of somebody else's live surface expires; the code written
from it does not.** On 2026-08-03 all four captured CIMD documents carried
exactly one spelling of the token endpoint auth method, so the reader was
written as `if (singular) … else if (plural)` and a note recorded that omitting
`private_key_jwt` was "safe rather than a vendor lockout, because ChatGPT's
live metadata declares both". Both halves were true when written. On 2026-08-17
`https://chatgpt.com/oauth/client.json` was measured carrying **both**
spellings — the singular naming `private_key_jwt`, the plural offering `none`
beside it — the `else` branch stopped being reached, and every ChatGPT
connection resolved to a confidential client this server cannot authenticate.
Nothing failed at the change; it failed at the next connection attempt, as
`invalid_client`, with the cause three hops away in a parser.

This is #1 through #12 with a clock on it: "no document carries both" was
measured, was correct, and was then encoded as though it were a rule. The
guard is not to distrust the measurement — it was good — but to **write the
parser to the specification's shape and the measurement to the test**. Reading
both members costs four lines; the snapshot then lives in a fixture that fails
when the world moves, which is the only place a dated observation belongs.
`spec/cimd-live-*.json` is that fixture, and it is dated in its filename for
this reason.

**9. The same rule, turned inward: "I could not do X" is not "X cannot be done."**
Every entry above is a claim about somebody else's system. On 2026-08-19 the same
shape turned up in claims about our own reach, three times in one session, and it
cost more than any single row in the ledger.

`Boltway.Mcp 0.4.2` — carrying #10's JWKS refusal and the unmapped-subpath
404 — was called blocked on *"publishing needs a `v*` tag"*, and then sat
unpublished for hours while other work went past it. `publish-packages.yml` has a
`workflow_dispatch` trigger, and all three previous publishes had used it. The
file had never been opened. Later, whether the package had reached the feed was
called unverifiable from that machine; `dotnet restore` resolved it on the first
try. Later still, `AUTH_TAG` was recommended as the way to make the authorization
server follow each release — in a file whose own comment argues the opposite two
lines above the variable.

The asymmetry at the top of this document is that every error invented a defect in
a stranger's system. This one inverts it: **it invents a wall in your own.** And
it is harder to catch, because a wrong "yes" produces an artefact somebody
reviews, while a wrong "no" produces nothing at all. No test, no CI run and no
reviewer ever looks at work that was not attempted.

The guard is cheaper here than anywhere else in this document. All three were one
command: read the `on:` block, run the restore, read the comment above the
variable. **Run the command that would falsify the "no" before saying it** — and
where no such command exists, say "I have not tried", which is rule 1 with the
third value pointed at yourself.

**10. A truncated list is not a count.** `git log … | head` stops at ten, and
"ten commits behind" went into a report and then into a workflow comment before
`rev-list --count` said eleven. `head`, `-n`, a default page size and a `limit`
parameter are the same trap: they return an answer of exactly the shape asked
for, carrying no mark that it was cut. Count with something that counts, and if a
truncated list has to be read, say that it was truncated.

---

## The counter-lesson: the tools were still right to build

This document is not an argument for reading documentation by hand.

One operator's live MCP server — textbook discovery — is documented nowhere.
Six agents reading API documentation and a hand review of that operator's entire
technical doc tree all missed it. **A `GET` found it in seconds**, and it
turned out to be the narrowest, most qualified lead in the whole exercise. The
2026-07-30 sweep contains none of the MCP servers found later, because it only
ever looked at auth-ish hostnames.

Tools see things people do not. They also state falsehoods with total
confidence, which people are worse at. The answer is not to stop building them;
it is to never publish their output without a control, a known-answer set, and —
for anything with a company's name attached — raw evidence a human has read.

---

## Conduct, which is not the same as correctness

The read-only line these tools draw is real and worth keeping: reading what an
operator published is safe against a stranger, writing to their server is not.
Nothing here ever registered a client, submitted a form, or created an account.

But that line does not cover everything it felt like it covered.

**We rate-limited a major file-sharing operator into an HTTP 429**, then recorded
our own load as their broken discovery chain. Concurrency 8 across 295 domains, followed immediately by
a verifier over the flagged rows, is not "just reading". The re-measurement runs
sequentially with backoff, and that is now the default posture, not a remedy.

Two other things surfaced incidentally: an operator serving an internal wiki's
REST API unauthenticated, and an error page leaking an internal database DSN.
Both were plain GETs of public URLs. **Neither value is recorded in this
repository, neither was probed further, and neither should be acted on.** They
are noted only so that whoever repeats this work is not surprised, and knows to
stop rather than look closer.

### An example domain is somebody's property too

This repository used `acme.com` in its README, its `DEV_TOKENS` documentation
and its test fixtures, on the assumption that a name that *sounds* fake is
fake. It is not: `acme.com` resolves, and so did the other placeholder we
reached for — it turned out to be a live business, a running image-generator
service with analytics on it. A reader copying an example points at a stranger's domain, and
any mail the example implies goes to their inbox.

That is worse here than in most codebases, because the thing this library does
is **dereference URLs somebody else supplied** — a CIMD `client_id`, a JWKS
endpoint, an upstream issuer. A resolvable placeholder is a live wire in a
codebase full of code whose job is to dial one.

**Only RFC 2606 gives a guarantee.** `example.com`, `example.net` and
`example.org` are held by IANA and can never be registered by anyone; the
reserved TLDs are `.test`, `.example`, `.invalid` and `.localhost`, and
`.invalid` is the one for a value that must never resolve at all. Everything
else — including any `<plausible-word>.<any TLD>` that reads as obviously a
placeholder — is a domain somebody can buy, and by the time it matters they
already have.

---

## The shortest version

Three separate rounds of measurement produced three different answers about the
same 42 companies: 34 defects, then 32-of-42-agree, then 26. Each round was
wrong in the same direction, and each was corrected only because somebody
re-measured instead of re-reading the output.

**The number you publish is the number you measured last, slowly, with a
control.** Everything before that is a draft.
