# Contributing

## Before anything else

```bash
./scripts/postgres.sh up      # once per machine boot
dotnet build Boltway.slnx     # must be 0 warnings
dotnet test  Boltway.slnx     # must be 0 failures
```

Both must be clean before you open a pull request, and CI runs the same two commands. **Warnings are
errors here** — that is set in `Directory.Build.props` and the comment above it explains why
downgrading it silently weakens the security posture rather than breaking anything.

`Boltway.Storage.PostgreSql.Tests` fails rather than skips without a real server. That is
deliberate: a storage suite that skips itself when the database is missing is green in exactly the
situation where it measured nothing. `postgres.sh` gets you one with Docker or without.

**`global.json` names `10.0.100`, and the floor is the point.** With `rollForward: latestFeature`
that accepts any .NET 10 SDK from `10.0.100` up, which is what "this needs .NET 10" means. It used
to name `10.0.302` — one authoring machine's exact build — and under the same roll-forward rule
that refuses every lower feature band: an SDK of `10.0.111` did not build this repository at all,
it failed on the first `dotnet` command with nothing pointing at the cause. CI installs `10.0.x`
and so never saw it. Raise the floor only for a language or SDK feature the build actually needs,
and say which one.

## What this project is

An OAuth 2.1 authorization server. The code issues credentials that grant access to somebody's data,
so the bar for a change is higher than "it works and the tests pass". Two consequences worth stating
before you start:

- **A capability is never advertised before it exists.** If your change makes the metadata document
  claim something, the handler for it lands in the same commit. There is a test that reflects over
  the advertised grants and fails when one has no handler.
- **A refusal names its boundary.** An empty result where an error belongs produces a user who
  concludes the system lost their data. Say what was refused and why.

## Comments carry the reason, not the mechanism

The unusual thing about this codebase is comment density, and it is deliberate. A comment here does
not say what the code does — the code says that. It says **why this and not the obvious
alternative**, and where possible it names the incident that settled it.

That is the house style and reviewers will ask for it. If you cannot say why the obvious alternative
is wrong, that is worth discovering before the change lands, not after.

Two rules that come out of it:

- **A measurement is dated and attributed.** Anything asserted about somebody else's system — a
  vendor's client behaviour, a library's defaults — carries how it was measured and when. Live
  surfaces change; a fact with no date silently becomes a claim. Captures live in `spec/` with the
  date in the filename.
- **"I could not find it" is not "it is not there."** See `LESSONS.md`, which is twelve instances of
  exactly that mistake and is cited by name from a dozen files under `src/`. It is the shortest
  useful thing to read before your first change.

## Tests

- A new rule needs a test that goes **red without the change**. A test that would pass against the
  old code is a promise rather than a check, and there is a table in `RejectionLoggingTests` that
  says so about its own entries.
- A control matters as much as the case. A test asserting something is refused proves nothing unless
  a sibling proves the same path accepts what it should.
- Do not assert on timing. If a test needs to wait for work to happen, wait on the work — the test
  fixtures expose completion signals for this. A test that passes on a fast machine is a test that
  fails in CI at the worst moment.
- **Never skip, disable or quarantine a test to get green.** If a test is wrong, fix the test and say
  in the diff why it was wrong.

## Architecture rules

`tests/Boltway.Architecture.Tests` reflects over the compiled assemblies with Mono.Cecil and fails
the build on structural violations — the redirect matcher may not touch `System.Uri`, only the
guarded client may reach `System.Net.Http`, every write tool carries an authorization guard, every
project in `src/` is covered by the scan.

If one of these goes red, the answer is almost never to add an exemption. One of them found a
network fetch outside the guarded client that had been there since the code was written, and it only
found it because the project moved into the tree the scan walks.

If you genuinely need an exemption, it goes in the code with a justification that says what makes
this case different — not in a suppression file where nobody reads it.

## Pull requests

- One concern per pull request. A rename and a behaviour change in the same diff cannot be reviewed.
- Say what you measured. "Fixes the race" is not reviewable; "the diff was computed outside the
  `IsEnabled` guard, so a large key set paid for a sentence nobody was listening to" is.
- If you changed anything a consumer compiles against, move the version in `Directory.Build.props` in
  the same commit. The comment there explains why doing it at release time has already cost an
  outage. That commit moves three things together — the version, its `CHANGELOG.md` section, and
  `PackageValidationBaselineVersion` up to the version just released — and `StructuralRuleTests`
  fails if any one of them is left behind.
- Public API changes: `tests/Boltway.PublicApi.Tests` holds the approved surface. Update it in the
  same commit, so the diff shows what a consumer sees.

## Releasing

[`VERSIONING.md`](VERSIONING.md) says what the number promises; this is how it goes out.
[`CHANGELOG.md`](CHANGELOG.md) is what a consumer reads afterwards, and it is the record to keep
accurate. The release also publishes a page — the annotated tag's message, republished at
`github.com/TobiiNT/Boltway/releases` — which is a summary with an address, not a second changelog.
It exists because a tag message is something you can read and not something you can link, and both
tags cut before it shipped eighteen package ids while that page said nothing had ever been
released. Where the two disagree, the changelog is right.

**Once, and not from this repository:** nuget.org Trusted Publishing has to be set up — a policy
registered on nuget.org naming this repository and the publish workflow, and the `NUGET_USER`
repository variable set to the nuget.org profile name, the profile name rather than the email
address.

`NUGET_USER` being unset is now the publish workflow's **first** step and it fails there, before
the checkout — deliberately, because failing after the GitHub Packages push would leave one feed
written and the other not, with the version numbers burned on the half that succeeded. It used to
skip instead: GitHub Packages was still written, GitHub Packages needs a token to read even a
public package, and so a release that looked green went out to a feed no outside consumer can
restore from, with nothing reporting it because skipping is the correct behaviour in a fork. The
guard distinguishes the two — a fork still skips, the canonical repository stops.

Registering the Trusted Publishing policy is the half that cannot be checked from here at all: it
is a setting on nuget.org, and the workflow only finds out when `NuGet/login` fails to exchange
the token.

Then, per release, in this order:

1. **Bump `<Version>` in `Directory.Build.props` in the commit that moved the surface** — the rule
   above under *Pull requests*, restated because this is where forgetting it is discovered. Skip it
   and step 4 refuses. Skip it *and* the check, and you pack a version the feed already holds:
   `--skip-duplicate` reports success, drops the package, and the workflow stays green while the new
   assembly never ships.

   **`PackageValidationBaselineVersion` moves in that same commit, up to the version just
   released.** It decides what a break is measured against, and left behind it measures against a
   version nobody is on: a member the previous release *added* and this one removes packs green,
   because the baseline package never carried it — and that is exactly the member a consumer on the
   newest release compiles against. Measured on 2026-08-24 with the baseline a release behind:
   removing a member 0.1.0 shipped failed the pack with `CP0002`, removing one 0.2.0 added did not.
   Move it after the version, never to equal it — a baseline equal to the version being packed
   validates nothing.
2. **Date the version's section in `CHANGELOG.md`.** It is written as the surface moves, so by now
   it is a heading and a date rather than an archaeology exercise. Skip it and the file says
   `unreleased` about a version people are restoring — and `SECURITY.md` credits reporters there.

   Step 4 refuses an undated section, and refuses a date that is neither today nor tomorrow in UTC.
   The window is one-sided on purpose: a maintainer ahead of UTC dates by their own day, which is
   UTC's or the one after, never the one before. 0.2.0 was dated a day behind and nothing caught it
   but a re-read.
3. **Wait for `ci` to finish on the exact sha you are about to tag.** Its image job builds and
   pushes each image tagged with the commit sha, and the release adds the version tag to those
   manifests by digest rather than rebuilding — so the versioned image is the same bytes CI tested.
   Dispatch before that run finishes and the image step fails because the sha is not in the
   registry, **after** the tag is pushed and the packages are published, neither of which can be
   taken back.
4. **Dispatch the `release` workflow.** Three inputs: `tag`, which must be `v` followed by exactly
   the version in `Directory.Build.props` and is checked against it — dispatching `v0.3.0` against a
   tree reading `0.2.0` used to cut the tag, publish every package at `0.2.0` and report success;
   `message`, which becomes the annotated tag message *and*, verbatim, the notes on the release
   page — so it is written for somebody who has not read the diff; and `ref`, what to tag,
   defaulting to the branch it was dispatched on. A tag that already exists is refused rather than
   moved: it is what a consumer resolved a package version through, and cutting another one is
   cheap. It also refuses steps 1 and 2 left undone — a changelog section that is undated, misdated,
   or absent — because after the tag exists that file is not packed into the packages, so a
   correction leaves `main` saying one thing and the tagged tree another.

Do not publish by dispatching `publish packages` directly. It builds whatever the branch head is at
that moment and leaves no ref naming what went out, which is why nothing records the tree that
0.1.0 was built from.

`announce release` is the one piece that is dispatchable on its own, for a tag that has no page —
the two cut before it existed, or a release whose last job failed after everything irreversible had
already happened. It reads the tag and refuses a tag that is missing, lightweight, empty, or already
has a release; it never writes over notes somebody edited. Uncheck `latest` when filling in a tag
older than one that already has its page, or the Latest badge moves backwards.

## Language

Code, comments, identifiers, commit messages and log lines are **English**. So is anything matched
ordinally — enum values, id prefixes, header names — because two implementations comparing those
character-for-character must not diverge on a translation.

User-facing interface strings are a different question and are configurable per deployment; the
localization tests use Vietnamese as the non-English locale precisely so that the seam is exercised
by something with diacritics rather than by a copy of English.

## Security

Do not open an issue for a vulnerability. [`SECURITY.md`](SECURITY.md) has the private channel.

## Licence

Contributions are accepted under Apache-2.0, the licence the project ships under. By opening a pull
request you are licensing your contribution under it, including the patent grant in section 3 — which
is the main reason the project is Apache rather than MIT.
