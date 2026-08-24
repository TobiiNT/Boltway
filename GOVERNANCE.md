# Governance

Who decides what happens to this project, and what an adopter should conclude from the answer.

This file exists because the answer is small. A project with one maintainer and no process is not
unusual and is not disqualifying; a project with one maintainer that *reads* as though it had a team
is, because somebody sizes their dependency on the impression. `docs/CAPABILITIES.md` splits *off*
from *absent* for the same reason this splits *one person* from *a foundation*.

## The short version

**One maintainer: Truong To ([@TobiiNT](https://github.com/TobiiNT)).** They decide what merges,
what releases, and what the project refuses to build. There is no second committer, no vote, and no
steering group.

Measured on 2026-08-24, on `main`: 27 commits, of which 12 are Dependabot and the rest are the
maintainer's, some authored with an AI assistant. Nobody outside the project has contributed yet.
`git shortlog -sne` re-measures this in one command, and it is the honest input to a bus-factor
question — which is 1.

## What that means if you are depending on this

Stated plainly, because these are the failure modes and none of them are hypothetical for a project
this young:

- **Nobody is on call.** `SECURITY.md` promises acknowledgement of a vulnerability report within a
  week and says that is a real limit rather than a promise dressed up as one. The same applies to
  every other kind of report.
- **If the maintainer stops, the project stops.** There is no succession plan, because a succession
  plan naming nobody is worse than saying this. What there *is* instead: Apache-2.0, a full history,
  a build that runs from a clone with no private inputs, and every design decision written down with
  the reasoning — `LESSONS.md`, `docs/decisions/`, `spec/REQUIREMENTS.md`. Forking is the continuity
  plan, and the repository is arranged so that a fork inherits the reasoning and not just the code.
- **Review is asymmetric.** The maintainer's own changes are reviewed by the maintainer. What
  actually constrains them is machinery rather than a second pair of eyes, and that is a deliberate
  substitute rather than an equivalent one — see below.
- **Versions promise little on purpose.** `VERSIONING.md` says what 0.x does and does not commit to.

## What constrains the maintainer

A single-maintainer project has no reviewer to catch a bad change, so the constraints are written
down and executable. These are the things that will stop a change the maintainer wants to make:

| | |
|---|---|
| `tests/Boltway.Architecture.Tests` | Structural rules over compiled IL. An exemption goes in the code with a justification, never in a suppression file |
| `MetadataHonestyTests` | Anything the metadata document advertises must be routed. `N-06` |
| `EnablePackageValidation` | A removed or re-signatured public member fails the pack against the previous release |
| `tests/Boltway.PublicApi.Tests` | Compiles as a consumer would, with no `InternalsVisibleTo` |
| `BannedSymbols.txt` | Each ban carries its reason and its requirement id |
| `spec/REQUIREMENTS.md` | The ids cited throughout the code. §10 wins on conflict |
| Warnings are errors | `Directory.Build.props`, and the comment there says why it is load-bearing |

**This is not a substitute for review and is not offered as one.** It catches the classes of mistake
somebody thought to encode. It cannot tell you a design is wrong.

## How a change gets in

1. Open an issue first for anything that changes a design decision, so the argument happens before
   the diff. Small fixes can skip straight to a pull request.
2. `CONTRIBUTING.md` is the house rules — one concern per pull request, say what you measured, and
   the version-bump rule that moves three files together.
3. The maintainer reviews and merges. External pull requests get a response; see the acknowledgement
   window above for what that is worth as a promise.
4. Everything runs through CI. A red build is not merged, and a test is never skipped, disabled or
   quarantined to get green.

`.github/CODEOWNERS` routes review requests. With one maintainer it resolves to the same person for
every path — its job here is to make that visible in the tree rather than to distribute anything.

## Becoming a maintainer

There is no formal ladder because there is nobody on it yet. What would earn the offer: a track
record of merged changes that follow the house rules without being asked, sound judgement on a
review of somebody else's diff, and enough interest in the problem to still be here in six months.
If that describes you, say so in an issue.

If it ever happens, this file is the thing that changes in the same commit — a maintainer list that
has drifted is worse than no maintainer list.

## Contributions and licence

Apache-2.0, inbound the same as outbound: opening a pull request licenses your contribution under
the project's licence, including the patent grant in section 3. That grant is the main reason the
project is Apache rather than MIT.

**There is no CLA and no DCO sign-off requirement.** That is a choice with a cost, stated so nobody
is surprised by it: the inbound licence rests on this paragraph and on Apache-2.0 §5 rather than on
a per-commit signed trail, and some legal reviews want the trail. If that blocks adoption at your
organization, open an issue — adding `Signed-off-by` enforcement is cheap, and the reason it is not
here is that no contributor has needed it yet, not that it was refused.

## Code of conduct

[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Reports go to one person, which that file says in the
place a reporter reads before deciding to write.
