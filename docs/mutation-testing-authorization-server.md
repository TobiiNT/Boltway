# Mutation testing: Boltway.AuthorizationServer

Stryker.NET 4.16.0, .NET 10, `--concurrency 3`, default (Standard) mutation level.
Run 2026-08-05 against `Boltway.AuthorizationServer` with its own test project.

This file records what was measured, what was fixed, and — the part that decays fastest and
matters most — **what was not measured**. A mutation score quoted without its scoping is a
number that cannot be compared to anything, including its own future self.

## How it was run

The project was split into seven chunks by `--mutate` glob, each producing its own JSON report.
Chunking is not cosmetic: an earlier single run lost 100% of its work to a container restart, and
this container was reclaimed roughly every five minutes for part of the run. Seven durable reports
cost one chunk per restart instead of everything.

The seven patterns were verified to partition the source set **exactly once each** — 40 files, zero
gaps, zero overlaps — before the run started. A chunking scheme that silently misses a file reports
a score for code it never mutated.

Scoping matters twice over:

- **`--solution` is a two-project solution** holding only this project and its test project. Pointed
  at the full solution, Stryker discovered 664 tests for a 77-test project and produced nothing
  usable in fifteen minutes.
- **Scores are not comparable across assemblies.** Scoping each assembly to one test project makes
  code exercised by *another* assembly's suite appear as `NoCoverage`. `ConfiguredResourceRegistry.cs`
  below shows 0 killed / 27 NoCoverage and a 0% score; that is an artefact of scoping, not a claim
  that the file is untested. Only **Survived** counts are meaningful under any scoping.

## Results

2910 mutants created, 414 CompileError, **2082 scored** — the same 2082 in every pass, which is
what makes them comparable at all. Three measured points, differing only in the test suite:

| | pass 1 | pass 3 | now |
|---|---:|---:|---:|
| tests | 573 | 598 | 619 |
| Killed | 1209 | 1239 | **1257** |
| Timeout | 2 | 3 | 4 |
| Survived | 662 | 648 | 631 |
| NoCoverage | 209 | 192 | 190 |
| score, Killed only | 58.07% | 59.51% | **60.37%** |
| score, Killed+Timeout | 58.17% | 59.65% | 60.57% |

**Quote the Killed-only figure.** The reason is in the next section and it is the most useful thing
this exercise produced.

| chunk | pass 1 | now | delta |
|---|---:|---:|---:|
| `token` | 44.25% | 47.13% | +2.87 |
| `authorize` | 60.13% | 63.40% | +3.27 |
| `cimd` | 80.42% | 80.42% | +0.00 |
| `external` | 51.81% | 57.51% | +5.70 |
| `interaction` | 50.00% | 52.24% | +2.24 |
| `config` | 56.91% | 59.45% | +2.53 |
| `metadata` | 55.48% | 55.48% | +0.00 |

### Timeouts are not a measurement on this machine

Stryker scores `Timeout` as killed. That is defensible — a mutant that never terminates has been
detected — but only if the timeouts are a property of the mutant rather than of the machine. Here
they are not, and it took three separate runs to establish it.

A full pass measured with other work on the box produced **14** timeouts against pass 3's 3. Their
shape gave them away: clusters of **exactly three** in four unrelated files, with `Killed` unchanged
in every one of them. Re-running those chunks on a quiet machine:

| file | loaded | quiet |
|---|---|---|
| `Endpoints/InteractionEndpoints.cs` | S30 **T3** | S33 **T0** |
| `Configuration/AuthorizationServerOptions.cs` | S46 **T3** | S49 **T0** |
| `DependencyInjection/…ServiceCollectionExtensions.cs` | S32 **T3** | S35 **T0** |
| `Metadata/MetadataBuilder.cs` | S15 **T3** | S18 **T0** |
| `Interaction/DefaultInteractionRenderer.cs` | S55 T0 | S53 **T2** |

Twelve false timeouts vanished and two new ones appeared somewhere else. Only
`Interaction/LoginThrottle.cs`'s two have reproduced in every run — four of them now — and those are
genuine non-termination.

`Killed` was **identical at 1257** across both runs. That is the whole argument: the Killed count is
stable under load and the Timeout count is not, so a score that folds them together moves with the
machine rather than with the tests. The same instability corrected itself in the other direction
earlier — a `CimdClientIdUrl` timeout recorded in pass 3, flagged then as "not a demonstrated kill
and I cannot explain it", is back to `Survived` now.

Do not run anything alongside a mutation run. When something did run alongside one anyway, prefer
the Killed-only number rather than re-litigating which timeouts were real.

### Where the 60 survivors went

| file | before | after |
|---|---:|---:|
| `Diagnostics/ConfigurationDoctor.cs` | 72 | 62 |
| `Authorize/AuthorizePipeline.cs` | 76 | 68 |
| `Token/ClientAuthentication.cs` | 72 | 65 |
| `Interaction/LoginThrottle.cs` | 22 | 16 |
| `Interaction/PendingExternalLogin.cs` | 17 | 11 |
| `Endpoints/ExternalLoginEndpoints.cs` | 75 | 70 |
| `Token/GrantHandlers.cs` | 89 | 86 |
| `Authorize/ValidatedRedirect.cs` | 9 | 7 |
| `Diagnostics/RejectionResult.cs` | 19 | 18 |

Two rows are deliberately **not** in that table, because they are timeout noise rather than work:
`DefaultInteractionRenderer.cs` reads 58 → 56 and `InteractionEndpoints.cs` reads 32 → 34. Neither
had a single mutant killed or resurrected; both are Survived↔Timeout churn.

### Per file (pass 1)

Ordered by survivors. `S` = Survived, `NC` = NoCoverage, `K` = Killed, `T` = Timeout.

| file | chunk | S | NC | K | T | score |
|---|---|---:|---:|---:|---:|---:|
| `Token/GrantHandlers.cs` | token | 60 | 29 | 65 | 0 | 42% |
| `Authorize/AuthorizePipeline.cs` | authorize | 73 | 3 | 116 | 0 | 60% |
| `Endpoints/ExternalLoginEndpoints.cs` | external | 59 | 16 | 56 | 0 | 43% |
| `Token/ClientAuthentication.cs` | token | 49 | 23 | 47 | 0 | 39% |
| `Diagnostics/ConfigurationDoctor.cs` | config | 43 | 29 | 54 | 0 | 43% |
| `Interaction/DefaultInteractionRenderer.cs` | interaction | 55 | 3 | 38 | 0 | 40% |
| `Configuration/AuthorizationServerOptions.cs` | config | 49 | 5 | 87 | 0 | 62% |
| `DependencyInjection/…ServiceCollectionExtensions.cs` | config | 35 | 3 | 73 | 0 | 66% |
| `Endpoints/InteractionEndpoints.cs` | interaction | 33 | 1 | 54 | 0 | 62% |
| `Resources/ConfiguredResourceRegistry.cs` | metadata | 0 | 27 | 0 | 0 | — (see scoping) |
| `Endpoints/TokenEndpoint.cs` | token | 16 | 9 | 29 | 0 | 54% |
| `Clients/CimdClientResolver.cs` | cimd | 19 | 5 | 69 | 0 | 74% |
| `Endpoints/AuthorizeEndpoint.cs` | authorize | 14 | 9 | 17 | 0 | 42% |
| `Interaction/LoginThrottle.cs` | interaction | 15 | 7 | 15 | 2 | 44% |
| `Clients/CimdClientIdUrl.cs` | cimd | 9 | 11 | 63 | 0 | 76% |
| `Metadata/MetadataBuilder.cs` | metadata | 18 | 2 | 41 | 0 | 67% |
| `Diagnostics/RejectionResult.cs` | config | 19 | 0 | 24 | 0 | 56% |
| `Interaction/PendingExternalLogin.cs` | external | 17 | 0 | 26 | 0 | 60% |
| `Clients/CimdServiceCollectionExtensions.cs` | cimd | 4 | 12 | 4 | 0 | 20% |
| `Clients/CimdDocument.cs` | cimd | 6 | 8 | 168 | 0 | 92% |
| `Endpoints/DiscoveryEndpoints.cs` | metadata | 12 | 1 | 27 | 0 | 68% |
| `Interaction/AuthorizeResumption.cs` | interaction | 11 | 1 | 7 | 0 | 37% |
| `Authorize/ValidatedRedirect.cs` | authorize | 8 | 1 | 28 | 0 | 76% |

Remaining files each hold fewer than 8 survivors.

### What the survivors actually are

Of pass 1's 871 survivors, **506 are string mutations** — replacing a literal in a log message, a hint, a
rendered page. Exactly **one** touched a protocol-visible literal. Dismissing that half is a
measured call, not an assumption.

The other **363 are behavioural**: equality, boolean, logical, conditional, arithmetic, block and
statement mutations. That is the set worth reading.

## Fixed, with controls

Every fix below was verified by applying the exact mutation, watching the specific new test fail,
and restoring. A test that does not fail under its mutation is not a test.

**`d5df483` — no confidential client had ever authenticated over HTTP.**
`TestClientSecretStore` returned `null` for every client, so `SecretAsync` could only ever reach its
"no secret is stored" refusal. Stryker marked the `Authenticated(...)` branch `NoCoverage` and every
guard leading to it survived. Six tests added covering both `client_secret_basic` and
`client_secret_post`. Re-measured: 4 mutants killed, 6 moved out of `NoCoverage`, file score
39.50% → 42.86%.

The second control there is the instructive one. The first version of the ill-formed-UTF-8 test
**passed under its own mutation**: the permissive decoder folds `0xC3 0x28` to U+FFFD, the folded
value still fails `OpaqueSecret.TryParse`, and the response is byte-identical. That also falsified
the source comment claiming strictness prevents two secrets comparing equal — it cannot. What
strictness buys is the diagnosis, and the test now asserts the `ReasonCode`.

**`0e91c07` — the external-login cookie's attributes were never asserted.**
`HttpOnly`, `Secure`, `SameSite` and the whole `CookieOptions` initializer could each be dropped, at
the write site and the delete site, with the suite green. The cookie is `__Host-` prefixed, so
dropping `Secure` makes a real browser reject it outright while `CookieContainer` — the thing the
tests use — does not enforce the prefix. Two tests, reading the raw `Set-Cookie` header.

**`0d34928` — two guards in `Boltway.OAuth.Primitives`** (strict UTF-8 in `Sha256Hash.OfString`,
the loopback gate in `RedirectUriMatcher`), plus one mutant proved *equivalent* and recorded as such
in the source so the next run does not reopen it.

## The findings, all fixed, all with controls

Each was verified against the source, turned into a test, and the test verified by applying the
exact mutation and watching it fail. Suite: 573 → 619 across three rounds.

### Round 1 — the eight found in the first pass

| finding | what the mutant did | commit |
|---|---|---|
| `ClientAuthentication.cs:112` | §2.4 method count, `+` → `-`; `client_assertion` appeared in **no test in the suite**, so the third operand had never been set | `426c308` |
| `GrantHandlers.cs:185` | `grant is null \|\| !grant.IsActive` → `&&`; a code redeems against a revoked grant | `82e2203` |
| `GrantHandlers.cs:548-549` | the two revocations on reuse detection, each masked by the other | `82e2203` |
| `ExternalLoginEndpoints.cs:529` | the resumed-return-URL gate collapsed to always-redirect | `3fff8e9` |
| `ExternalLoginEndpoints.cs:525` | `IsLocalPathTo` collapsed to the weaker `IsLocal` | `3fff8e9` |
| `ExternalLoginEndpoints.cs:422` | `email is not null && email_verified` → `\|\|`; unverified upstream claim provisions a verified account | `3fff8e9` |
| `ExternalLoginEndpoints.cs:460` | link-subject check → `&&`; upstream identity attached to whoever holds the browser | `2d9ba4c` |
| `LoginThrottle.cs:223-225` | both-limiters-blocked branch, `NoCoverage`; `Retry-After` could name the shorter block | `57a66b4` |
| `LoginThrottle.cs:81` | `Math.Max(2, ProcessorCount)` → `Math.Min` | `57a66b4` |

Three of them were reachable only through work the survivor list did not advertise:

- **`GrantHandlers` needed a grant id for a grant the test never exchanged**, and every
  `/authorize` mints a fresh `Guid`. A recording decorator over the store solved it; nothing was
  added to the server.
- **The `Resume` return-URL gate cannot be reached by any request.** It re-gates a value the start
  endpoint already gated — which is why both its mutants survived. Testing it means planting a
  pending request through the real store, which is precisely the "future change that writes a
  pending request from a path that did not gate" the source comment names.
- **`ExternalLoginEndpoints.cs:460` looked covered and was not.** A test asserts its exact
  `ReasonCode`, but refuses at the *start* endpoint, before the browser leaves — so it never
  reaches the callback where the line lives. A grep for the reason code said "covered"; the mutant
  was right and the grep was wrong.

### Round 2 — `AuthorizePipeline.cs`, 60.42% → 64.58%

The largest file in the assembly, and its chain order was the prize. Five `??` links:

```
ValidateResponseType(…) ?? ValidatePkce(…) ?? ValidateScope(…)
    ?? await ValidateResourcesAsync(…) ?? ValidateOidcParameters(…)
```

Reordered four ways, all four survived: nothing had ever sent a request failing **two** stages at
once, so no test could tell this order from any other. Clients branch on the error code. Plus four
limits nothing had reached — the resolver's own `Retry-After`, `GrantTypes.Count > 0`,
`AllowedScopes … Count > 0` (which under `>= 0` refuses *every* request from a client with an
allow-list, so the narrowing had only ever been proven to refuse and never to permit), and the
inclusive resource-count boundary.

**The methodological catch is the point of this round.** Stryker emits three mutators per `??`:
remove-left, remove-right, and left-to-right, which **swaps** the operands. The control run applied
remove-left — a mutation constructed by hand, not the one that was surviving. It failed the right
test, which read as confirmation and was not. Only the re-measure exposed it, and the theory row it
implicated turned out to violate a single stage rather than two, proving nothing about order. A
control is only worth the run if it is the mutation that actually survived.

### Round 3 — `ConfigurationDoctor.cs`, 42.86% → 50.79%

Seventeen behavioural survivors, and reading them one at a time gave a better answer than fixing
them would have: **twelve are equivalent mutants.**

- `CheckIssuerAgreement` — ten. Every URL is `Url(path) => issuer + path` and every path is a
  `const string`, so no configuration can make an endpoint fail to start with the issuer. `strays`
  is always empty and the `Warn` branch is unreachable. Said plainly: **this check cannot fail as
  the server is built.** The comment above it half-implies divergence is already possible; it is
  not.
- `CheckRegistrationProfile` — two. Options validation rejects two of the three profile values, so
  reaching those lines requires a configuration that validated, and `hasCimd` is then always true.

The five real gaps were: the `ThrowIfNull` on public `Run`, the `NotMeasured("issuer-agreement")`
line the existing test omitted, two `checks.Add(...)` calls that could vanish because one test
asserts every check passes (still true with a check missing) and another asserts ids are distinct
(also still true), and the key-ring arithmetic — reachable only because `CheckKeyRing` runs
*outside* the configured branch and so sees an out-of-range lifetime.

That last test first asserted `Fail`; the branch returns `Warn`. The test was wrong about the
server, not the other way round.

### Two mutants that do not compile in this repo

`GrantHandlers.cs:185` and `ExternalLoginEndpoints.cs:460` both become possible null dereferences
(CS8602) under `&&`, and this repo builds with `TreatWarningsAsErrors`. Stryker compiles with laxer
settings, which is why it scored them `Survived` rather than `CompileError`. Both controls needed a
null-forgiving operator to run at all — and the first attempt, applied literally, produced *no test
output*, which reads exactly like a pass.

### One assertion that is honestly vacuous on small hardware

`The_default_verification_bound_is_one_per_core_with_a_floor_of_two` cannot fail on a one- or
two-core machine, because `Max(2, n)` and `Min(2, n)` agree there. On a small CI runner the mutant
survives that test and the assertion passes without proving anything. Stated in the test itself
rather than left to be discovered.

## Reproducing

```bash
M=<scratch>/mut/as
dotnet-stryker --solution $M/as.slnx \
  --project Boltway.AuthorizationServer.csproj \
  --test-project tests/Boltway.AuthorizationServer.Tests/Boltway.AuthorizationServer.Tests.csproj \
  --mutate '**/Token/*.cs' --mutate '**/Endpoints/TokenEndpoint.cs' \
  --reporter cleartext --reporter json --output $M/out-token --concurrency 3
```

`as.slnx` holds only the two projects. `--mutate` does not reduce mutant *creation* — all 2910 are
created every time and the out-of-scope ones report as `Ignored: Removed by mutate filter` — but it
does reduce what is *tested*, which is where the time goes. Fixed overhead is about two minutes per
chunk for analysis, build and coverage capture.
