# Working in this repository

Boltway is a **generic** OAuth 2.1 + OIDC authorization server and MCP resource-server toolkit,
published as NuGet packages under Apache-2.0. It is the layer underneath a connector, not a
connector: `Boltway.ResourceServer` and `Boltway.Mcp` are what an MCP server references, and
`Boltway.AuthorizationServer` is a separate deployable that issues the tokens it validates.

The audience is strangers. Nobody reading this code has our context, our deployment, or our
vocabulary, and every rule below follows from that one fact.

## Where things are

| | |
|---|---|
| `src/` | the sixteen packages that ship to NuGet |
| `hosts/` | two runnable deployables — the authorization server and the admin BFF — each with a `Dockerfile`. Not packable |
| `testing/` | `Boltway.Interaction.Testing`, the layout and renderer contracts, shipped so a deployment can run them against its own markup |
| `samples/` | the smallest thing that completes a whole flow, plus `drive-flow.sh` |
| `tests/` | one suite per package, plus `Boltway.Architecture.Tests` and `Boltway.PublicApi.Tests`, which are about the shape rather than the behaviour |
| `spec/` | the requirements, the vendored drafts, and dated captures of live surfaces |
| `docs/` | everything written down that is not code — `docs/README.md` indexes it and marks each current, a decision record, or dated |

One tree, one solution, `Boltway.slnx`. The reason is under *the architecture tests* below.

## Nothing about one deployment lands here

This repository was extracted from a private deployment, and the extraction is the part that is
never finished. A rule, a role name, a lifetime or an example that is true of *our* install and
stated here as though it were true of the library is a defect, whether or not anything fails.

- **No company, product or person names** in identifiers, comments, XML docs, log lines, strings
  or fixtures. That includes using our people as the actors in an anecdote — *"a founder pressed
  Link Google"* narrates a deployment the reader does not have. Say *"a user"*.
- **No role vocabulary as though it were the library's.** `IRoleStore` and `IUserStore` hold role
  strings they never compare to a constant, and their doc comments say so by listing several
  unrelated examples on purpose. One example repeated everywhere reads as the built-in set.
- **Example values obey RFC 2606, always.** `example.com`, `.test`, `.invalid`, `.localhost`.
  Nothing else is guaranteed unregistrable, and this library's whole job is dereferencing URLs
  somebody else supplied — see *An example domain is somebody's property too* in `LESSONS.md`,
  which is there because `acme.com` shipped in this README and resolves to a real business.
- **A default is not a policy.** Anything a deployment could reasonably need to change is an option
  with a documented default, not a constant. If it cannot be changed, say why in the comment.

## Never advertise a capability you do not have

`N-06`, and the most expensive rule here. The metadata document is a promise, and a promise with a
`404` behind it is worse than an absence, because a client believes it.

`MetadataHonestyTests` drives every advertised grant through `/token` and sweeps for an endpoint
that is advertised but not routed. If a change makes the document claim something, the handler
lands in the same commit. `KnownGrantTypes` lists exactly the grants `TokenEndpoint` has an arm
for, so configuring a name with nothing behind it is a startup failure rather than a runtime one.

**The capability lists are part of that surface.** `docs/CAPABILITIES.md` holds four states — on,
built-and-off, absent on purpose, not built yet — and the README's *What you get* table plus its
opening paragraph are the same claims at the place every reader starts. Moving a capability between
states is part of the change that moved it, not a follow-up. A capability that grew a default and
stayed filed under "not implemented" is how that middle state was earned; a capability that shipped
a whole deployable while the opening paragraph still denied it is the same defect one level up.
Both files move together.

## A refusal names its boundary

An empty result where an error belongs produces a user who concludes the system lost their data.
Every refusal says what was refused and which rule refused it. This applies to startup validation
too: `MapBoltwayAuthorizationServer` reports **all** missing services in one exception rather than
one per restart, and `ConfigurationDoctor` distinguishes `NotMeasured` from `Pass`.

## Every claim about somebody else's system carries its confidence

`LESSONS.md` is twelve instances of recording *"we did not measure this"* as *"this is not there"*,
and every one invented a defect in a stranger's system. It is cited by name from a dozen files
under `src/`, and it is the shortest useful thing to read before a first change.

What comes out of it, in code and in prose:

- **Every axis needs a third value** — `yes` / `no` / `could not tell`, never the first two alone.
- **A measurement is dated and attributed.** Anything asserted about a vendor's client behaviour or
  a library's defaults carries how it was measured and when. Captures live in `spec/` with the date
  in the filename. A fact with no date silently becomes a claim.
- **"I could not find it" is not "it is not there."**

## Comments carry the reason, not the mechanism

The unusual thing about this codebase is comment density and it is deliberate. A comment does not
say what the code does — the code says that. It says **why this and not the obvious alternative**,
and where possible names the incident that settled it. Reviewers will ask for it. If you cannot say
why the obvious alternative is wrong, that is worth discovering before the change lands.

Keep the anecdote and lose the deployment: *what* went wrong is the reusable half, *who it happened
to* is not.

## The architecture tests are the design, and an exemption is almost never the answer

`tests/Boltway.Architecture.Tests` reflects over the compiled assemblies with Mono.Cecil and fails
the build on structural violations — the redirect decision never reaches a normalizing `System.Uri`
member, only the guarded fetcher touches `System.Net.Http`, only the rejection writer produces an
error response, nothing starts a process, nothing uses the non-cryptographic random, every project
in `src/` is covered by the scan, every project says whether it packs, and every
`InternalsVisibleTo` grant is one somebody approved.

One of these found a network fetch outside the guarded client that had been there since the code
was written, and it only found it because the project moved into the tree the scan walks. **That is
why there is one tree and one solution** (`Boltway.slnx`), and it is load-bearing rather than tidy:
a project outside the scan is not a project the scan approved, and nothing says so.

If a rule goes red, the answer is almost never an exemption. If you genuinely need one it goes in
the code with a justification saying what makes this case different, never in a suppression file
where nobody reads it.

`BannedSymbols.txt` sits beside the same idea: `System.Uri.AbsoluteUri` and its normalizing
siblings are banned because RFC 3986 §6.2.1 compares the raw string, and `System.Random` because it
is not a CSPRNG. Each ban carries its reason in the file.

## Two deployables, and the absence is the design

`Boltway.ResourceServer` does not reference `Boltway.AuthorizationServer`, and must not begin to. A
resource server validates tokens; it does not issue them, and a consumer who wants only the MCP
side must not drag the issuer in behind it.

`Boltway.AuthorizationServer.Abstractions` carries the seams with no ASP.NET Core dependency, so a
store or a policy can be implemented without one.

## Seams are `TryAdd`, and the order is part of the contract

`AddBoltwayAuthorizationServer` registers its defaults with `TryAdd`, so a registration made
**before** it wins and one made after it silently does nothing. Anything new that a deployment
might replace follows that pattern, and the XML doc says which side of the call it goes on.

Client resolvers run in registration order and CIMD is the only one that makes an outbound request,
so it belongs last.

**So is the wire.** Every opaque credential this server mints carries a prefix naming its kind —
`bw_ac_`, `bw_rt_`, `bw_rat_`, `bw_cs_` — and those strings are in deployments' databases and in
clients' hands. `OpaqueSecret.TryParse` still accepts the `ck_` spelling these carried under the
project's previous name, and the refresh grace window can still reconstruct a successor under it,
because refusing the old form on the deploy that renamed a string would sign out every session and
break every confidential client. Both compatibility paths carry the condition for removing them:
one refresh-token lifetime after the upgrade, and a re-issue for client secrets. Deleting them
early is not a tidy-up, it is a forced re-authorization for everyone.

**The rendered markup is part of the surface too.** A deployment's stylesheet hooks the class names
the default renderer emits, so renaming one is a breaking change for every consumer who themed the
pages — the cheapest tier of customization is the one with no compile error to warn them. Treat the
class vocabulary the way you treat a public method name, and keep it named after this project.

## Storage

PostgreSQL is the provider a deployment runs. SQLite is a development provider and does not meet
the concurrent-redemption requirement — the defect is undiagnosed and written up on
`SqliteRelationalStoreBehavior`; do not record the pooling change as a fix, because it removes a
route rather than the cause.

The in-memory stores are per process. Anything cached or counted per process belongs in the
**Before the second replica** table — in `hosts/Boltway.AuthorizationServer.Host/README.md`, beside
the operator who reads it — in the same change that adds it. Eleven files were each locally honest
about it and there was nowhere to look on the day it mattered. One row of that table is a security
property rather than a budget, and startup cannot detect it.

## Public surface and version

`<Version>` lives once, in `Directory.Build.props`. If a change alters anything a consumer compiles
against, move it in the same commit — doing it at release time has already cost an outage, and the
comment there says so.

**Check the feed before you believe the comment.** `Directory.Build.props` said 0.1.0 "because
nothing here has ever been published" while eighteen ids were live on nuget.org at exactly 0.1.0,
one of them `Boltway.Storage.Tests` — a test project that reached the feed by setting
`IsPackable=true`. A version already on the feed is pushed with `--skip-duplicate`, which reports
success and drops the package, and nuget.org has no delete, only unlist. One
`curl https://api.nuget.org/v3-flatcontainer/<id.lower()>/index.json` settles what is out there; a
sentence in this repository saying what has been published is a claim, and this one was wrong.

What packs is `StructuralRuleTests.PackableProjects`, checked by a test rather than counted by
hand. Adding a package is an edit to that list, made deliberately — an id cannot be taken back.

**A break is a decision, not an accident.** `EnablePackageValidation` diffs every packable project
against the 0.1.0 already on the feed, so a removed or re-signatured public member fails the pack
with `CP0002`. At 0.x a break is allowed — `VERSIONING.md` says so — and the gate exists to make it
something somebody chose. Its own error suggests `ApiCompatGenerateSuppressionFile`, which writes
the break into a file nobody reads again; record it in `CHANGELOG.md` instead, where the consumer
about to hit it will see it.

`tests/Boltway.PublicApi.Tests` compiles a consumer's-eye implementation of the seams in an
assembly with **no** `InternalsVisibleTo` grant, so it builds only while every member it touches is
genuinely public. The build is the test.

`testing/Boltway.Interaction.Testing` ships as a package so a deployment that replaces the layout or
the renderer can run the same contract we do. A seam worth replacing is a seam worth shipping a
contract for.

## User-facing strings are localizable; everything ordinal is English

- **English, and not a preference.** Identifiers, comments, commit messages, log lines, and anything
  matched character-for-character: enum values, id prefixes, header and form field names, claim
  names, scope names. Two implementations comparing these must not diverge on a translation.
- **Localizable, because a person reads it.** Sign-in, consent, logout, error and account page text,
  admin page text, notification text. It routes through the text seam; a literal that reaches HTML
  from a renderer or an endpoint is a defect even when it is in English.
- The localization tests use Vietnamese as the non-English locale on purpose, so the seam is
  exercised by something with diacritics rather than by a copy of English.

**A translation is data a deployment edits, so what it can silently break is a design question.**
Two rules come out of that, and both are enforced rather than asked for. Text is HTML-encoded and
then values are spliced into its placeholders — never `string.Format` on the raw text — so a
translation cannot introduce markup. And `InteractionText.Problems` refuses at startup a
translation whose placeholders do not match the English arity: a `ConsentClientAsking` without
`{0}` reads as a grammatical sentence with the client's host silently absent, which is the field
`N-14` makes a MUST, on the page it matters most. Nothing downstream can tell; startup is the only
place it can be caught.

The seam a deployment replaces is `IStringLocalizer`, registered **before**
`AddBoltwayInteractionLocalization`. It was documented for a while as a replaced
`IStringLocalizerFactory` — the way OrchardCore and ABP do it — and nothing here ever resolved a
factory, so anybody who followed that got English pages and no error. A documented extension point
with nothing behind it is `N-06` on the customization surface.

## Tests

- A new rule needs a test that goes **red without the change**. A test that would pass against the
  old code is a promise rather than a check.
- A control matters as much as the case: a test asserting a refusal proves nothing unless a sibling
  proves the same path accepts what it should.
- Do not assert on timing. Wait on the work — the fixtures expose completion signals.
- **Never skip, disable or quarantine a test to get green.** If a test is wrong, fix it and say in
  the diff why it was wrong.
- `Boltway.Storage.PostgreSql.Tests` fails rather than skips without a real server, deliberately: a
  storage suite that skips itself is green in exactly the situation where it measured nothing.

## No credentials, ever

Not in code, not in a test fixture, not in a commit message, not in a sample. Prefer a credential
that expires to one that does not: if a long-lived secret has to exist, make it the one that
derives short-lived ones.

`AllowPrivateAddresses` disables the RFC 6890 check entirely and turns `/authorize` into an
unauthenticated port scanner. It exists for development and for an on-premises upstream, and the
default is off. Do not widen it to make a test pass.

## After changing anything

```bash
./scripts/postgres.sh up      # once per machine boot
dotnet build Boltway.slnx     # must be 0 warnings
dotnet test  Boltway.slnx     # must be 0 failures
```

**Warnings are errors here.** This code issues credentials that grant access to somebody's data, so
a warning is a defect that has not been noticed yet.

Requirement ids are cited throughout the code and the README, and every one is defined in
[`spec/REQUIREMENTS.md`](spec/REQUIREMENTS.md): `S-*` conformance matrix (§1), `E-*` endpoint
contract (§2), `X-*` error codes (§4), `N-*` non-negotiables (§5), `C-*` client compatibility (§6),
`A-*` the Auth0-trap requirements restated positively, with acceptance criteria (§7), `D-*`
deferred (§8). Cite the id, and keep the id's own entry true
in the same commit — an id whose entry has drifted is worse than no id.
