# docs/

Everything written down about Boltway that is not the code, plus the way out of this directory.

Three statuses, and the difference is what a reader is allowed to act on. **current** — true now,
and a change that makes it untrue is part of that change. **decision record** — a decision already
taken, kept so it is not re-argued from scratch; the reasoning binds, the surrounding detail may
have moved. **archive** — a dated measurement, wrong now on purpose, kept for what it measured on
the day.

| Document | Who it is for | What it assumes | Status |
|---|---|---|---|
| [`DESIGN.md`](DESIGN.md) | Someone about to change the authorization server | The requirement ids in `spec/REQUIREMENTS.md`; §10 of that file wins on conflict | decision record |
| [`USER-MANAGEMENT.md`](USER-MANAGEMENT.md) | The same reader, for accounts, administration, self-service and recovery | The same ids, plus §11. Written when none of this existed — the administration, self-service and recovery surfaces have since shipped behind flags, so the README's capability lists are current and this is not | decision record |
| [`CAPABILITIES.md`](CAPABILITIES.md) | Anyone asking whether this server does X | Nothing. Four states, and the reason they are four rather than three: *off* and *absent* are different words | current |
| [`HOSTING.md`](HOSTING.md) | Someone wiring a `Program.cs` rather than running the image | That startup names every missing service at once, so this is read in one pass | current |
| [`INTERACTION-PAGES.md`](INTERACTION-PAGES.md) | A deployment changing what the sign-in and consent pages look like | Nothing. Three tiers, and it says what each one hands you responsibility for — tier 3 means owning N-14 in full | current |
| [`LOCALIZATION.md`](LOCALIZATION.md) | A deployment replacing the English text | Nothing. Three surfaces with three different mechanisms, and it says which is which and what each silently ignores | current |
| [`examples/translations.vi.json`](examples/translations.vi.json) | The same reader, one file later | `LOCALIZATION.md` read first — a mistyped key is silently the English string | current |
| [`decisions/protocol-surface-gaps-2026-08.md`](decisions/protocol-surface-gaps-2026-08.md) | Anyone about to propose DPoP, dynamic client registration, pairwise `sub` or back-channel logout here | Nothing. §3, *won't do and why*, is the half that keeps mattering | decision record |
| [`archive/2026-08-05-mutation-testing.md`](archive/2026-08-05-mutation-testing.md) | Anyone about to run Stryker against this codebase | That its scores are a 2026-08-05 snapshot and its chunk globs no longer partition the assembly. Its header says how far off | archive |
| [`../README.md`](../README.md) | Everyone, first | Nothing. Deliberately short: its *What you get* table and opening paragraph are claims a reader acts on, and everything longer lives in a page linked from it | current |
| [`../ROADMAP.md`](../ROADMAP.md) | An evaluator asking what is missing | That "measured against Keycloak" means one named commit on 2026-08-22, not a standing comparison | current |
| [`../CHANGELOG.md`](../CHANGELOG.md) | Anyone upgrading | That every package moves on one version number, so an entry applies whether or not your package has a line in it | current |
| [`../VERSIONING.md`](../VERSIONING.md) | The same reader, before upgrading | That 0.x promises nothing, deliberately, and that the 0.2.0 in `Directory.Build.props` already carries breaking entries | current |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | Anyone opening a pull request | Docker, or a PostgreSQL you supply. Warnings are errors and the storage suite fails rather than skips | current |
| [`../GOVERNANCE.md`](../GOVERNANCE.md) | Anyone deciding whether to depend on this | Nothing. One maintainer, a bus factor of 1 stated as a number, and what is executable rather than social about the review | current |
| [`../CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md) | Anyone participating, and anyone who needs to report conduct | Nothing. Contributor Covenant 3.0 adapted, and the adaptation is that a report reaches one person. **Carries CC BY-SA 4.0, not this repository's licence** — see `NOTICE` | current |
| [`../SECURITY.md`](../SECURITY.md) | Anyone holding a vulnerability report | Nothing. It also says what is out of scope, which is most of what gets reported | current |
| [`../LESSONS.md`](../LESSONS.md) | Everyone, before a first change | Nothing. Twelve instances of one mistake; it is cited by name from a dozen files under `src/` | current |
| [`../spec/README.md`](../spec/README.md) | Anyone citing a requirement id, or wondering why two IETF drafts are checked in | Nothing. It carries the licence note for those two files, which are not Apache-2.0 | current |
| [`../spec/research/README.md`](../spec/research/README.md) | Anyone reading the twelve distillations for the reasoning behind a rule | That they were fetched on a date and are not maintained against later drafts | current |
| [`../hosts/Boltway.AuthorizationServer.Host/README.md`](../hosts/Boltway.AuthorizationServer.Host/README.md) | Whoever deploys the authorization server container | That every difference between deployments is configuration, and that it refuses to start rather than starting wrong | current |
| [`../hosts/Boltway.AdminBff/README.md`](../hosts/Boltway.AdminBff/README.md) | Whoever deploys the admin UI | That it is an OAuth client rather than a page on the server, because `N-17` leaves no other shape | current |
| [`../samples/README.md`](../samples/README.md) | Anyone who wants the whole handshake running locally before reading anything | The .NET SDK and a trusted development certificate — on Linux an `SSL_CERT_DIR` too, and it says why. Everything non-production in them is marked `DEV:` in the source | current |

Two conventions worth keeping, because both were paid for:

- **A document that records a decision already taken goes in `decisions/`**, not `proposals/`. A
  closed plan left filed as a proposal gets read as a to-do list, and a gap list read as a to-do
  list turns a server that does one job into one that does none of them well.
- **A document that has stopped being true goes to `archive/` with its date in the filename, body
  uncorrected**, and a header saying what has moved. Rewriting it destroys the one thing it is
  good for — what was true on the day somebody measured it.
