<!--
  Short on purpose. This project dislikes ceremony, and a checklist long enough to be skimmed is a
  checklist that gets ticked without being read.

  What is here is the two obligations CONTRIBUTING.md imposes that a reviewer would otherwise have
  to remember every single time, and both have already cost something when forgotten: a version left
  behind takes down a consumer at startup, and an unrecorded public surface is a diff that does not
  show what a stranger sees. Everything else in CONTRIBUTING.md fails a test or a reviewer catches
  it in the diff; these two are silent.

  Delete the lines that do not apply. An unticked box with a sentence saying why is a better pull
  request than a ticked one that is not true.
-->

## What this changes, and what you measured

<!--
  "Fixes the race" is not reviewable. "The diff was computed outside the `IsEnabled` guard, so a
  large key set paid for a sentence nobody was listening to" is. If the change is about somebody
  else's system, say how it was measured and when — a fact with no date silently becomes a claim.
-->

## Before merging

- [ ] `dotnet build Boltway.slnx` is **0 warnings** and `dotnet test Boltway.slnx` is 0 failures
      (`./scripts/postgres.sh up` first — the storage suite fails rather than skips without a server)
- [ ] **Anything a consumer compiles against moved?** Then `<Version>` in `Directory.Build.props`
      moved in the same commit, and `CHANGELOG.md`'s top section says what changed. Doing this at
      release time has already cost an outage: a frozen version is pushed with `--skip-duplicate`,
      which reports success and drops the package.
- [ ] **Public surface changed?** `tests/Boltway.PublicApi.Tests` holds the approved surface — it
      compiles with no `InternalsVisibleTo` grant, so the build is the test. Update it here, so the
      diff shows what a stranger sees.
- [ ] One concern. A rename and a behaviour change in the same diff cannot be reviewed.
- [ ] New rule? There is a test that goes **red without it** — a test that would have passed against
      the old code is a promise rather than a check.
- [ ] Nothing here names our deployment: no company, product or person names, and example values
      obey RFC 2606 (`example.com`, `.test`, `.invalid`, `.localhost`).

<!--
  Not a vulnerability report. SECURITY.md has the private channel; do not put the detail in a pull
  request either.
-->
