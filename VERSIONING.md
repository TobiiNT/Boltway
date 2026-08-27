# Versioning and support

What a Boltway version number promises, and what it does not. This is the question an evaluator asks
straight after the licence, and until this file existed the answer was in nobody's head but the
maintainer's.

Changes are recorded in [`CHANGELOG.md`](CHANGELOG.md). The release procedure is
[*Releasing* in `CONTRIBUTING.md`](CONTRIBUTING.md#releasing).

## 0.x promises nothing

**Any release in the 0.x line may break any part of the public surface, and 0.2.0 does** - a
withdrawn package and a moved namespace, a renamed class vocabulary in the rendered markup, a
configuration file that now fails startup, and a changed default in the container image. Read the
`Breaking` entries in [`CHANGELOG.md`](CHANGELOG.md) before upgrading; there is no deprecation
period, no shim, and no parallel maintenance of an older 0.x.

That is deliberate rather than an admission. The README carries three lists - *deliberately not
implemented*, *built and off by default*, *simply not built yet* - and the last one is not empty.
Freezing a surface while a capability in that list is still unbuilt means shipping the wrong seam
for it and then owning that shape. The README's own account of `ISubjectIdentifierService` is what
that looks like: a seam whose signature took a `UserAccount` and a `ClientRecord` while the token
path carries a `SubjectId` off the grant and never loads an account, so it did not fit the thing it
was a seam for. Deleting it was the right answer. Under a 1.0 promise, deleting a public type costs
a major version, which for a project this young means the surface holds still because nobody wants
to spend one.

The version does move for a breaking change - the minor number, because 0.x has nowhere else to put
it. **A minor bump in 0.x carries no information about compatibility.** The changelog does.

## What 1.0 will promise

SemVer over the **public surface of everything under `src/`**: the types, members and behaviours
a consumer compiles or configures against. A breaking change to any of it takes a major version.

Three qualifications, because "the public surface" is not one thing here:

- **`Boltway.AuthorizationServer.Abstractions` is the stable seam**, and it is the one to build
  against if you are implementing a store, a policy or a provider. It carries every extensibility
  seam and the records they exchange, with **no ASP.NET Core reference** - a seam takes a
  request-shaped record rather than an `HttpContext`, so it can be implemented and unit tested in a
  plain class library. That constraint is what makes the seam narrow enough to hold still, and it is
  enforced by the project file rather than by intention. It is the only `*.Abstractions` package
  today; if others appear they inherit the same rule.
- **`hosts/` is a deployable, not an API.** `Boltway.AuthorizationServer.Host` and
  `Boltway.AdminBff` are containers configured entirely by environment. Neither packs, and neither
  is on nuget.org. Their environment variables *are* a contract - a deployment breaks if one is
  renamed - so a change to them is a changelog entry, but they are versioned as images rather than
  as API and they are outside the SemVer promise above.
- **`testing/` follows the family version without being API-stable in the same sense.**
  `Boltway.Interaction.Testing` and `Boltway.Storage.Testing` exist so a deployment that replaced a
  seam can run the same contract this repository runs. What they assert has to move when the
  obligation moves: a new requirement means a new assertion, and a new assertion fails a
  consumer's suite the moment they upgrade. That is the package working, not breaking. Treat a
  version bump there as "there is a new obligation to satisfy", and upgrade it deliberately.

Nothing here is a support window. **There is no long-term support branch and no backporting.** Fixes
land on `main` and go out in the next release. This is a small project, and - as `SECURITY.md` puts
it about acknowledgement times - that is a real limit rather than a promise dressed up as one.

## One version, one literal

Every package in this repository publishes at the same number, and that number is a single
`<Version>` in [`Directory.Build.props`](Directory.Build.props). The reason is in the comment above
it: everything here is built from one tree and released together, so a per-project version would be
one literal per package to forget instead of one in total.

The consequence people trip over: **a project whose own source did not change still needs the bump.**
A `ProjectReference` packs as a dependency on the referenced project's version, so leaving one
behind produces a frozen nuspec naming a dependency that is merely old - and a consumer pinning it
can never receive the newer one, no matter how often that one is published.

The number moves in the commit that changed the surface, not at release time. `CONTRIBUTING.md` says
so under *Pull requests*, and the tag check in the `release` workflow is an equality test against
this literal precisely because the literal is the decision and the tag is derivative.

Two other values move with it in the same commit, and a test fails if either is left behind: the
`CHANGELOG.md` heading, and `PackageValidationBaselineVersion` - which decides what a break is
measured against, and a release behind stops seeing anything the previous release added and this one
removes.

## A published version can never be reused

nuget.org has **unlist, not delete**. An unlisted package stops appearing in search and keeps
restoring for anyone who names the version, forever. So a version is frozen the moment it is
published, and the failure when you forget is silent in the worst direction: the push runs with
`--skip-duplicate`, which reports success and drops the package, the workflow stays green, and the
new assembly simply never ships. The consuming side is where it becomes loud - a downstream consumer
restores the frozen package, compiles green because the C# compiler does not check a call that lives
inside an already-compiled dependency, and throws `MissingMethodException` at startup. The version
comment in `Directory.Build.props` narrates what that cost the one time it happened; it is worth
reading there rather than being repeated here.

Two things follow, and both have already been needed:

- **One `curl https://api.nuget.org/v3-flatcontainer/<id.lower()>/index.json` settles what is out
  there.** A sentence in this repository saying what has been published is a claim; the feed is the
  fact, and the claim has been wrong.
- **A package id cannot be taken back either.** `Boltway.Storage.Tests` is on the feed at 0.1.0
  because a test project set `IsPackable=true`, and it will be there permanently. What packs is
  `StructuralRuleTests.PackableProjects` - an approved set checked by a test, so adding an id is an
  edit somebody makes deliberately.

## Two compatibility paths, and what retires them

These are version policy rather than implementation detail: each is a promise to accept something
this build no longer produces, with a stated condition for withdrawing it.

**The `ck_` credential prefix.** Every opaque credential minted now carries `bw_ac_`, `bw_rt_`,
`bw_rat_` or `bw_cs_`. `OpaqueSecret.TryParse` accepts either spelling and nothing mints the old one,
so the old prefix retires as fast as tokens turn over rather than all at once. Refusing it on the
deploy that renamed a string would sign out every session and break every confidential client.

> Removable once no deployment can still hold one: that is one refresh-token lifetime after the
> upgrade for tokens, and a re-issue for client secrets. Deleting it early is not a tidy-up - it is
> a forced re-authorization for everyone.
>
> - `OpaqueSecret.LegacyPrefixFor`

**The legacy reconstruction in the refresh grace window.** The grace path derives a successor rather
than generating one, so two racing redemptions compute the same plaintext, then checks the
reconstruction against the hash the store holds and **fails closed** when they differ. A row written
before the rename holds the hash of the old spelling, so `RefreshTokenDeriver.DeriveLegacy` tries
both. This is not a second chance for a wrong derivation key - a wrong key matches neither and the
refusal still fires. What it buys is that the refusal's message stays true, because every other
route into it really is a derivation-key problem.

> It expires with `LegacyPrefixFor`, and sooner: only a family whose successor was minted in the
> grace window that spans the upgrade can reach it.
>
> - `OpaqueSecret.FromLegacyDerivedMaterial`

Neither has been withdrawn. When one is, it is a breaking change for any deployment that has not met
the condition, and it goes in the changelog marked as such.
