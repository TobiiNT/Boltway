# Changelog

Notable changes to Boltway, in [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) form.
[`VERSIONING.md`](VERSIONING.md) says what a version number here promises and what it does not.

Three conventions, because a changelog nobody can rely on is worse than none:

- **Every package moves together on one number.** There is a single `<Version>` in
  `Directory.Build.props`, so an entry below applies to the whole family whether or not the package
  you reference has a line in it.
- **The top section is headed with the number `<Version>` already reads**, and gets a date when the
  tag is cut. It is not `Unreleased` with a number assigned later: the version moves in the commit
  that moved the surface, so by the time there is anything to write down the number is decided.
- **Breaking entries say so, in bold, at the front.** The 0.x line permits breaking changes, and
  the whole point of permitting them is that they are announced rather than discovered. A deleted
  method announces itself at the consumer's next build; a renamed class in the rendered markup and
  a changed default in the container never do, so they carry the same marker.

## [0.2.0] — unreleased

### Added

- **`Boltway.Storage.Testing`**, the store contracts a deployment runs against its own
  implementation. New package id, first published at this version. It depends on xunit and nothing
  else — see *Removed* for what it replaces.
- `InteractionText.Problems(...)`, which reads placeholder arity off the English table.
  `AddBoltwayInteractionLocalization` calls it and reports every problem at once, so a translator
  fixes one file in one pass.
- `RefreshTokenDeriver.DeriveLegacy(...)`, for the one branch that needs it — see *Fixed*.
- Right-to-left rendering. `dir` did not appear anywhere in the tree, so the stylesheets' physical
  properties put every gutter and accent bar on the edge the reader finishes at. Both layouts now
  emit `dir` from the same string as `lang`, and both shipped stylesheets use logical properties.
  The direction comes from a list of primary subtags rather than `TextInfo.IsRightToLeft`, which
  under this build's `InvariantGlobalization` returns false for all nine RTL tags exactly as it does
  for `en` — not unavailable, a silent wrong answer for every language.
- Admin banner text is a key from a closed set rather than a sentence in a redirect's query string,
  so `ADMIN_TEXT_FILE` can change it. Unrecognised keys are warned about at startup, and a raw key
  is never rendered as though it were a sentence.
- Host image settings, all of which refuse a bad value rather than guessing: `LOG_FORMAT` (whose
  default is itself a change — see below), `FORWARDED_HOPS`, `ACCESS_TOKEN_LIFETIME`,
  `REFRESH_TOKEN_LIFETIME`, `AUTH_CODE_LIFETIME`, `SESSION_REVALIDATION` and `REAUTH_FRESHNESS`. A
  duration is a count and a unit — `30s`, `15m`, `24h`, `30d` — because `TimeSpan.Parse` reads a
  bare `30` as thirty days. Unset leaves the library's own default, still validated against its own
  floor and ceiling. `ProxyHeaders.BehindOneProxy` had taken a hop count all along and its own doc
  called it "the number to change if a CDN is ever put in front"; nothing read a value for it, so
  that sentence described a knob no operator could reach.
- [`docs/LOCALIZATION.md`](docs/LOCALIZATION.md), with a translation file to copy. The mechanism
  shipped at 0.1.0 and was documented nowhere a consumer looks: the README contained no occurrence
  of localization, translation, i18n, culture or `ui_locales`.

### Changed

- **Breaking.** The rendered class prefix is `bw-` rather than `ck-`, across eighteen classes in the
  default layout and renderer. A deployment's stylesheet hooks these names and theming is the
  customization tier the README says to reach for first, so this is a breaking change with no
  compile error behind it. The shipped stylesheets moved in the same change, so the pages this image
  serves keep their styling. `Boltway.Interaction.Testing` asserts on no class name at all, so a
  deployment running the contract against its own markup is unaffected.
- **Breaking.** Startup refuses a translation whose placeholders disagree with the English arity, in
  either direction. A `ConsentClientAsking` without `{0}` reads as a grammatical sentence with the
  host of the `client_id` URL silently absent — the field `N-14` makes a MUST, on the page it
  matters most, deletable by editing a JSON file with every other check passing. A deployment
  carrying such a file starts today and will not start on this version, which is the point. The same
  check now covers every string property of `NotificationText`; it previously covered eight of ten,
  missing both halves of the new-device notice.
- **Breaking, for the container.** `LOG_FORMAT` defaults to `json` — structured and
  vendor-neutral. The Google Cloud Logging formatter was previously installed unconditionally in an
  image the README calls one image for every deployment, and its field names are Google's. Set
  `LOG_FORMAT=cloud-logging` to keep the old payload shape; `simple` is the third option.
- Newly minted opaque credentials carry `bw_ac_`, `bw_rt_`, `bw_rat_` and `bw_cs_`. `ck` was
  ConnectorKit, a name this project no longer has, and it reached the wire — 0.1.0's packages mint
  and parse the old spelling only. **This is not breaking on the way in**: `OpaqueSecret.TryParse`
  accepts either, so a refresh token or client secret handed out before the upgrade stays valid and
  the old prefix retires as tokens turn over rather than all at once. Anything downstream that
  pattern-matches the prefix does need to know. [`VERSIONING.md`](VERSIONING.md) has the condition
  for removing the compatibility path.
- `AuthorizationServerOptions.UiLocalesSupported` may hold more than one entry. The one-entry rule
  existed because a second would have claimed a per-request mechanism that did not exist; it exists
  now, so being served is the rule rather than the count.
- `dpop` is no longer a `PackageTags` entry. `spec/REQUIREMENTS.md` S-37 defers DPoP and says to
  advertise nothing DPoP-related; a search tag is an advertisement, so somebody filtering nuget.org
  for `dpop` was shown a package that does not implement it — 0.1.0's nuspecs carry the tag.
  `rfc9728` is there instead, which this server does serve.
- The last of a private deployment's vocabulary is out of the XML docs, which ship to consumers'
  IntelliSense because `GenerateDocumentationFile` is on. A private product was named 24 times,
  including in a test fixture and a copy-pasteable JSON example; 22 sites narrated that
  deployment's people as the actors in an anecdote; three doc comments justified `A-08` as
  protecting "the property the product is sold on", which is a real property with a name a stranger
  can read — zero-registration. Every measurement survives; only the proper nouns are gone.
- The documented seam for replacing interface text is `IStringLocalizer`, registered before
  `AddBoltwayInteractionLocalization`. The XML docs said `IStringLocalizerFactory`, the way
  OrchardCore and ABP do it; nothing here has ever resolved a factory, so anyone who followed that
  got English pages and no error.

### Fixed

- **`ui_locales` now reaches the pages it selects the language for.** It arrives on `/authorize`;
  the pages are `/login` and `/consent`, which are separate requests, and the whole query went into
  `returnUrl` as one percent-encoded value — so the page read an empty `ui_locales` and rendered in
  the default language, with `ui_locales_supported` in the discovery document and the startup check
  that every advertised locale is served both passing. A deployment serving `vi` answered
  `/authorize?…&ui_locales=vi` with an English login page. The tests could not have caught it: they
  built `/login?returnUrl=…&ui_locales=vi` and requested it directly, a URL no client constructs.
- The refresh grace window no longer blames the operator's `RefreshTokenDerivationKey` for a prefix
  rename. It reconstructs a successor and checks it against the hash the store holds, failing closed
  when they differ; a row written before the rename holds the hash of the old spelling, so the
  reconstruction tries both. A wrong derivation key still matches neither and the refusal still
  fires — what this buys is that the refusal's sentence stays true, because every other route into
  it really is a derivation-key problem.
- Admin writes no longer round-trip their banner text through the query string, so `?notice=` cannot
  put caller-supplied text on the page; anything outside the closed key set renders nothing at all.
- `h2` in the shipped stylesheets no longer uppercases or letter-spaces. Uppercasing destroys
  Turkish's dotted and dotless i, and letter-spacing breaks Arabic cursive joining.
- Both `Dockerfile`s documented a build context that does not exist, so the one command a newcomer
  copies failed immediately at `unable to prepare context`. Every `COPY` in them assumes the
  repository root, and CI has always built with it.
- `scripts/check-pinned-drafts.py` defaulted to a path under an `auth/` directory, the layout this
  tree was curated out of, so running it by hand failed and its own error told the reader to open a
  path that is not here. `CK_PG_*` in `postgres.sh` went at the same time, from beside
  `BOLTWAY_TEST_POSTGRES` in the same file.
- README corrections, each of which a reader acts on — and this file is packed into all eighteen
  packages, so it is what a nuget.org visitor reads: the opening paragraph denied an admin UI and a
  durable storage implementation, both of which ship and both of which the same file describes 300
  lines later; the Layout table listed `src/` only, so `hosts/`, `testing/` and `samples/` appeared
  nowhere; the one place a package is named for a consumer to reference named
  `Boltway.Interaction.Tests`, which is `IsPackable=false`, and `docs/DESIGN.md` repeated it. It
  also gains build, package, framework and licence badges, with absolute URLs because a relative
  link resolves to nothing on nuget.org.

### Removed

- **Breaking. `Boltway.Storage.Tests` is no longer published.** What it put on the feed at 0.1.0 had
  three defects: dependencies on `Microsoft.NET.Test.Sdk`, `xunit.runner.visualstudio` and
  `coverlet.collector`, so referencing the contracts dragged a test runner into a consumer's
  project; a `runtimeconfig.json`, because an executable test project was packaged as a library; and
  seven of this repository's own `InMemory*Tests` classes, so a consumer running `dotnet test` ran
  Boltway's tests and read the results as being about their store. The contracts are
  `Boltway.Storage.Testing` now, and the namespace moved with them —
  `namespace Boltway.Storage.Tests` is `namespace Boltway.Storage.Testing`. **The old id cannot be
  taken back**: nuget.org has unlist rather than delete, so `Boltway.Storage.Tests` 0.1.0 keeps
  restoring for anyone who names that version, forever.

## [0.1.0] — 2026-08-23

The first release: the authorization server, the resource server, the MCP layer, the storage
providers, federation, notifications, and the specs and research they are built against. 506 files
in one curated commit, with no history carried over from the private tree it was assembled from,
plus three changes on top of it — the copyright holder named rather than a placeholder collective;
`Boltway.Mcp`'s own JWKS refresher replaced by `Boltway.OAuth.Net.JwksKeySource` behind the same
`AddJwksSigningKeys`; and the scope and permission vocabulary of a private deployment replaced with
`docs:` and `reports:`.

**Which tree that was is not recorded anywhere, so it was measured off the feed rather than read off
the log.** The packages went out from a `workflow_dispatch` that built whatever `main` was at that
moment and left no ref naming it — the gap the `release` workflow was written to close. Unpacking
`boltway.mcp` and `boltway.oauth.primitives` 0.1.0 on 2026-08-23 puts the boundary within one commit:
the nuspec names the single author, the XML docs describe `JwksRefresher` in the past tense, the
scope examples read `docs:read`, the credential prefixes are still `ck_`, the tags still include
`dpop`, and the packed README carries no badges. Everything above is on the far side of that.

Eighteen package ids are live at 0.1.0 — measured against the feed the same day, one
`curl https://api.nuget.org/v3-flatcontainer/<id.lower()>/index.json` per id. Seventeen are still in
the approved set; the eighteenth is `Boltway.Storage.Tests`, which reached the feed because a test
project set `IsPackable=true`. See *Removed* above.
