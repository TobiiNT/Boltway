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
  outage.
- Public API changes: `tests/Boltway.PublicApi.Tests` holds the approved surface. Update it in the
  same commit, so the diff shows what a consumer sees.

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
