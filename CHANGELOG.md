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

## [0.5.1] - 2026-09-02

### Fixed

- **A service account recreated with different scopes is audienced at what those scopes name now.**
  The `client_credentials` grant derived the audience from the client's scopes only when no grant
  row existed, and read it back from the row when one did. That row is written on first use and
  never updated - `StoreAsync` is an insert and refuses a duplicate - so what it holds is the
  audience the client's scopes implied the first time it was used, cached with nothing to
  invalidate it.

  Deleting a service account does not remove the row, and cannot reach it: the client id is derived
  from the owner's handle and the grant id from (client, owner), so deleting and recreating one
  returns the same pair and finds the same row.

  Measured 2026-09-01 on a live deployment. An account holding the administrative scopes was
  recreated holding a resource server's, and every token afterwards carried the new scopes and the
  old audience. The resource server refused all of them with "the access token was not issued for
  this resource" while this server logged a clean 200, and naming the new resource explicitly
  failed with `invalid_target`, because the stale set is also what `resource` is checked against.
  Both ends reported success at every step, so the search started at the resource registry, which
  had been correct throughout.

  The audience is now derived on every request. That is the rule the same method already applied
  one line later to `Scope`: the grant is the revocation handle, the client is the authority on
  what it may ask for. The authorization-code and refresh paths are untouched, and deliberately so
  - there the stored set is what a person consented to, and reading it back is the point.

  Not a widening: a service account is still refused a resource its current scopes do not name.
  Both halves are held by `ServiceAccountEndToEndTests`, which goes in at the admin endpoint and
  comes out at `/token`.

  **A row written before this release still holds the stale value.** Nothing reads it now.
  Correcting it in storage would need an update method on `IGrantStore`, which is a published
  interface a deployment may implement, so the row is left as the historical record it now is.

## [0.5.0] - 2026-08-28

**Documentation only.** No type, member, signature or behaviour under `src/` moved. These packages
differ from 0.4.0's in their XML documentation and in nothing else, and the number moves anyway
because that documentation ships: `GenerateDocumentationFile` is on, so these comments are what a
consumer's IntelliSense shows, and a correction that stays on `main` reaches nobody. Every published
version up to and including 0.4.0 carries the earlier wording; this is the first that does not.

### Changed

- **The comments no longer describe this codebase in terms of one deployment.** "The deployment
  this was written for", "the connector this project came out of", "our vocabulary", "a private
  product": gone from every comment, document and fixture outside `spec/` and `docs/archive/`,
  among them `CLAUDE.md`'s own justification for the rule against exactly that and the pull request
  template's checklist item asking for it. Each keeps its measurement and loses the party.
  `AddSubjectClaimsFromAccounts` still records that every commit one connector made was attributed
  to a bare ULID; `StoredRows.BrowserId` still records that a column added after the fact stays
  blank on every row written before it; `SubjectId` still records why the `auth0|<hex>` shape forces
  a sanitiser and a collision-disambiguation path. The rule they serve now rests on something true
  of every library rather than on this repository's history.

  **Three passes, because the first two matched line by line.** An XML doc comment wraps, so a
  sentence can carry a phrase that no single line contains, and two of these survived a grep that
  read the tree honestly. The check that found the rest flattens whitespace and comment markers
  first, and the last one runs against the packed `.nupkg` documentation, which is the only thing
  that answers what a consumer actually receives.

- **`IRoleStore`'s example role strings are `founder`, `tier-2`, `reports_read`.** The third was
  `read_ledgers`, one of the permission names 0.1.0 replaced, surviving as a sample. Nothing compares
  any of them to a constant, which is the point the list makes.

- **No em-dash reaches a comment or a document, and `ci` fails on one.**
  `python3 scripts/check-dashes.py` separates what this repository writes from what the software
  says, because a string literal is output and changing one is a change to a message. `spec/`,
  `docs/archive/` and the example translations are out of scope: rewriting a vendored draft, a dated
  measurement or a deployment's own copy falsifies it. Measured on this release: 0 in prose or
  comments, 110 inside string literals.

## [0.4.0] - 2026-08-27

### Added

- **`Boltway.ResourceServer.Testing`, a new package: the resource-server pipeline contract, as an
  xunit base class a deployment derives.** Supply an `HttpClient` over your wired application, the
  resource identifier you configured and one path that needs a credential, and eight assertions ask
  what a client asks - both RFC 9728 well-known forms answering without a credential, the document's
  `resource` matching your configured identifier byte for byte, the challenge naming a
  `resource_metadata` URL that is really reachable, and a bad token producing a `401` rather than a
  `403` or a `500`.

  **Every one of those failed on a real deployment whose unit suite was green.** Measured
  2026-08-26 on the first consumer outside this repository: 402 tests passing, and the RFC 9728
  document answering `401` at the exact URL that server's own challenges pointed clients at. The
  cause is that a host running authentication of its own has a second vocabulary for "no credential
  needed" and neither middleware reads the other's - the library marks its metadata endpoints
  `AllowAnonymous`, and a host middleware keyed on its own marker refuses them. None of it is
  reachable from a unit test, because none of it is about a unit.

  The contract compiles against no Boltway assembly and spells RFC 9728's well-known suffix itself
  rather than importing this library's constant: a conformance check that shares a constant with the
  code under test agrees with that constant's bugs.

### Changed

- **`AddJwksSigningKeys` moved from `Boltway.Mcp` to `Boltway.ResourceServer`. The old call still
  works and is marked obsolete.** Nothing about it was ever MCP-shaped - it wires a `JwksKeySource`
  into `ProtectedResourceOptions` and touches no MCP type. Filing it next door had a measured cost:
  the first consumer outside this repository went looking for "how do I point verification keys at
  an issuer" in the resource-server package, did not find it, and wrote the class again by hand,
  down to the same sentence about a 401 that re-authenticating cannot fix.

  `Boltway.ResourceServer` gains a project reference to `Boltway.OAuth.Net` for it, which **adds no
  package a resource server did not already have** - that project's own dependencies are
  `Boltway.OAuth.Primitives` and `Microsoft.IdentityModel.Tokens`, both already present. It adds the
  guarded HTTP transport as an assembly, not as a running client: nothing is registered and no
  socket is opened until a deployment calls `AddJwksSigningKeys`.

  Nothing to do on upgrade. The forwarder in `Boltway.Mcp` calls the new one and will be removed at
  1.0.

- **`MapProtectedResourceMetadata` now says in its remarks that `AllowAnonymous` is only this
  pipeline's word for "no credential needed".** A host with its own authentication middleware has to
  mark these endpoints in its own vocabulary too, and the cheapest way is a route group carrying
  both markers - which covers whatever this package maps there, including anything a later version
  adds, and covers nothing else.

### Operations

- **`.github/workflows/vendor-cimd.yml` asks the two vendors twice a week whether the client
  documents `spec/REQUIREMENTS.md` section 6 describes still say what they said.** Nineteen `C-*`
  rows are measurements of somebody else's system, including their defects, and a defect is the kind
  of thing its owner fixes; the two captures in `spec/` are fourteen days apart and the newer one
  exists because something moved, found by hand. A change opens or updates one tracking issue; an
  unreachable vendor is retried and files nothing, because not being able to ask is not evidence
  that nothing changed. The sibling of `pinned-drafts.yml`, down to the exit-code contract.

## [0.3.0] - 2026-08-26

### Added

- **`BlockReason.LinkLocalAddress`, splitting the one address answer that has a single reading away
  from the ones that do not.** A CIMD fetch that resolved into `169.254.0.0/16` or `fe80::/10` and
  one that resolved to `0.0.0.0` were the same `BlockReason.SpecialUseAddress`, and the code around
  it said what that meant: "someone pointed the server at a private address", "a rebinding signal".
  That is an inference from a single lookup. A resolver that filters the name, split-horizon DNS for
  a name a company hosts internally, and an attack are the same observation from outside - so an
  operator on a filtered network was sent hunting an attacker who was not there. Link-local is the
  exception and now says so on its own: nothing benign resolves a public name into it, which is why
  it is the address the SSRF blocklist exists for.

  `SpecialUseAddresses.IsLinkLocal` is the classifier, and it decodes the forms the address is
  written in when somebody does not want it recognised - `::ffff:`, 6to4 `2002:a9fe:a9fe::`, and the
  deprecated IPv4-compatible `::169.254.169.254`. `SpecialUseAddresses.IsBlocked` is unchanged and
  still refuses every special-use address: **what a fetch connects to has not changed at all.** What
  changed is what this server claims about the answer.

  Do not read `0.0.0.0` as a harmless sinkhole on the strength of this entry. Measured 2026-08-26 on
  Linux 6.18: connecting to it reaches a service bound to `127.0.0.1`.

- **`CallerPrincipal.ScopeClaim` and `CallerPrincipal.Grants`, because an empty `Scopes` meant three
  different things and a connector had to guess which.** A token carrying no `scope` claim, a token
  carrying one that granted nothing, and a token carrying one `ScopeSet.TryParse` rejected all
  produced the same empty set. The first wants a fall-back to whatever the connector uses when an
  authorization server publishes no scopes; the other two want a refusal. `TryParse` rejects a claim
  **whole** on one character outside RFC 6749's scope-token set, so a single stray character turned a
  restriction into what looked like an absence - and a connector falling back on empty then granted
  *more* than the token said, to a caller whose token was written to restrict them, with nothing
  failing anywhere. Only this library ever knew which case produced the empty set.

  `ScopeClaimState` names the three (plus `Unknown`, the default, so silence is never mistaken for
  an answer). `Grants(scope)` returns `bool?` - and the nullable return is the feature: `bool?` does
  not convert to `bool`, so `if (!caller.Grants("x"))` does not compile and the third case cannot be
  folded into either of the other two. An unreadable claim answers `false`, never `null`.

  `Scopes` is unchanged and still empty in all three cases, so nothing compiled against the older
  shape behaves differently. A principal built without setting `ScopeClaim` gets `Unknown`, which
  falls back exactly as it did before. The static-token path reports `Absent` rather than `Unknown`:
  it *knows* there is no authorization server, and saying so is what lets a connector gate a tool on
  a scope and still run on static tokens.

- **`InsufficientScopeException`, because a per-tool refusal cannot carry a challenge and should say
  so rather than imply otherwise.** A tool refused for want of a scope wants to name the scope that
  would fix it in a form the caller can act on. Both channels for that are closed, and both were
  measured rather than assumed: the tool-level field is SEP-1489, a sponsored draft absent from the
  `2025-11-25` schema and from the draft the `2026-07-28` release candidate is cut from; and the
  HTTP challenge cannot be reached, because Streamable HTTP refuses a client that will not accept an
  event stream and the transport has opened that stream - status line sent - before any tool filter
  runs.

  So what ships is the honest half: a sealed `ConnectorToolException` carrying the
  `insufficient_scope` code and **every** scope the operation needs, for the same measured reason
  `X-34`'s challenge does - a client asks for the union of what it is told and what it had, so
  naming only the delta re-authorizes somebody into a narrower grant. Sharing the type keeps a scope
  refusal, which re-authorizing fixes, distinguishable from a role refusal, which it does not.

  `ToolRefusalReachTests` pins both measurements, so a future SDK that buffers the response or a
  future revision that adopts the field turns one of them red.

- **`IConnectorToolPolicy` and `WithBoltwayToolPolicy()`, so a per-tool decision reaches both places
  it has to hold.** One MCP endpoint carries every tool, so a scope required on the route is the
  intersection of what the tools need - the per-tool decision has to happen per tool, and until now
  a connector wiring that had to reach for the SDK's filter API itself and remember there were two
  of them.

  **Both filters, from one call, deliberately.** Filtering `tools/list` alone produces a surface
  that looks gated and is not: a caller that already knows a tool's name still reaches it. Gating
  `tools/call` alone leaves a model reading an advertised tool as a capability and retrying against
  something that always refuses. Shipping them separately would let a connector wire one and believe
  it had both.

  **Two questions, at the two moments they can be asked.** `Allows(caller, tool)` runs on the listing
  and the call, so refusing there hides a tool as well as blocking it.
  `AllowsArguments(caller, tool, arguments)` runs on the call alone, because a listing has no
  arguments - it refuses and cannot hide. That second one is the gate the first cannot express: an
  identifier naming somebody else's resource is refused on the argument or it is not refused, because
  the tool is the same tool either way. It has a default implementation returning `true`, so a policy
  that only gates whole tools does not have to mention it, and the arguments arrive as a read-only
  view: a policy decides, and rewriting a caller's arguments on the way past would be a behaviour
  nothing downstream could see.

  **What is not shipped is the answer.** No role table, no scope naming convention, no default
  policy, and no argument matcher - A deployment's role vocabulary is its own, and the fallback for a scope claim is subtle
  enough - see `ScopeClaimState` - that a shipped default would be wrong in the fail-open direction
  for every consumer at once. `Allows(caller, tool)` is synchronous because the decision is made
  from what the token already said and `tools/list` asks it once per tool.

  A refusal names the tool and the policy type rather than answering "unknown tool", which would be
  untrue and would send a reader looking for a registration bug. An unbound caller is reported as
  the wiring problem it is, not as a forbidden one.

- **`CallerPrincipal.ClientId`, `TokenId` and `GrantId`, so an audit trail is not assembled from
  string lookups.** All three were already on the principal - `FromClaims` copies the whole claim
  set - and a connector wanting to record which application made a change reached them as
  `Claims["client_id"]`. A key typed wrong there is silently null, on the surface whose whole job is
  saying who did what, and the static-token path had nothing to put in a dictionary key it was never
  told about.

  `TokenId` (`jti`) and `GrantId` (`gid`) are separate properties because they answer different
  questions and are trivially confused: a fresh `jti` is minted for every access token, so grouping
  records by it fragments them at every refresh with nothing failing, while `gid` is stable across a
  whole refresh family and is the key "what did this session do" actually wants.

  **`ClientId` is stored verbatim** - not lowercased, trimmed or canonicalised. It is a surface
  rather than a model, and a consumer writes it into the commit trailer recording which application
  made a change, so a value this library tidied would rewrite what that history means.

  All three are nullable and none is `required`, so existing initializers keep compiling; null means
  the authenticator did not learn one, and a connector should leave its own field unset rather than
  synthesise something plausible - the rule `Email` already carries. `ConnectorCaller` gains
  `Scopes` and `Grants` shorthands, so the set no longer names everything except what a tool gate
  reads.

### Changed

- **A CIMD client whose host has started resolving to a special-use address now keeps its cached
  document, instead of being signed out.** Stale-serve covered a timeout, a transport failure and an
  `NXDOMAIN`, and refused to cover a special-use address, on the reasoning that the latter is a
  rebinding signal that must not be papered over. Two things were wrong with that. It is not
  determinable - see the entry above - and it bought nothing: serving from the cache connects to
  nothing, because the address check has already refused, so refusing the cache as well refused no
  further connection. The visible effect was that one spelling of a DNS block (`NXDOMAIN`) kept a
  client working and another (`0.0.0.0`) signed it out.

  A link-local answer still refuses the cache, and there the original reasoning holds.

  If your deployment relied on a client dropping out when its name began resolving privately,
  `BlockReason.LinkLocalAddress` is the case that still does, and the fetch outcome is logged either
  way.

### Fixed

- **The shipped example told connectors to declare a required scope on their MCP route, which is
  the one place it must never go.** `ResourceServerAuthenticator`'s class summary ended
  `MapMcp("/mcp").RequireScope("docs:read")`, annotated "what makes the gate apply", and the
  diagnostic thrown when the middleware is mis-wired said the same. It does not gate: one MCP
  endpoint carries every tool, so a scope required there is the intersection of what the tools
  need - which `CallerPrincipal.Scopes` has always said from the other side.

  The expensive half is what it does instead. `RequireScope` also fills the `scope` parameter of
  the `401`, and the MCP scope-selection strategy reads that before the metadata document, so
  naming one scope there tells every client to ask for that and nothing else for the whole server.
  A connector that copied the line advertised a second scope in both RFC 9728 documents, showed it
  on its consent screen and enforced it in its tools, and no token its authorization server minted
  ever carried it. Reads worked and health was green; it surfaced only when the tools began
  enforcing, at which point every write stopped at once and re-consenting could not help.

  The example is now `RequireBearer()` and carries the reason rather than only the call. Naming
  both scopes would not have helped - `RequireScope` requires *every* scope listed, so a genuine
  read-only grant would lose its reads - and that is now said at the call site too.
  `RequiredScopeMetadata`'s remarks were already right about the mechanism and now say where "a
  minimal grant" stops being the intended reading. `StructuralRuleTests` fails the build if any
  shipped example puts the two calls back on one line.

  **This library cannot check a consumer's wiring for it.** `ProtectedResource` and its
  `ScopesSupported` are internal to `Boltway.ResourceServer`, so nothing in `Boltway.Mcp` can see
  the advertised set. The guard that works is a host-level test in the consumer asserting that
  every scope it advertises is named in the challenge - the property, not the line.

## [0.2.0] - 2026-08-24

### Added

- **`prompt_values_supported` in the discovery document.** `/authorize` honours `none`, `login`,
  `consent` and `select_account` and advertised none of them, so a client reading discovery to
  decide whether it may ask for a silent refresh found no answer and had to assume no. Nothing
  about the endpoint's behaviour changed; the document now says what it already did. A new field
  on `AuthorizationServerMetadata`, so a deployment reading the document as a typed object sees
  `PromptValuesSupported`.
- **`Boltway.Storage.Testing`**, the store contracts a deployment runs against its own
  implementation. New package id, first published at this version. It depends on xunit and nothing
  else - see *Removed* for what it replaces.
- `InteractionText.Problems(...)`, which reads placeholder arity off the English table.
  `AddBoltwayInteractionLocalization` calls it and reports every problem at once, so a translator
  fixes one file in one pass.
- `RefreshTokenDeriver.DeriveLegacy(...)`, for the one branch that needs it - see *Fixed*.
- Right-to-left rendering. `dir` did not appear anywhere in the tree, so the stylesheets' physical
  properties put every gutter and accent bar on the edge the reader finishes at. Both layouts now
  emit `dir` from the same string as `lang`, and both shipped stylesheets use logical properties.
  The direction comes from a list of primary subtags rather than `TextInfo.IsRightToLeft`, which
  under this build's `InvariantGlobalization` returns false for all nine RTL tags exactly as it does
  for `en` - not unavailable, a silent wrong answer for every language.
- Admin banner text is a key from a closed set rather than a sentence in a redirect's query string,
  so `ADMIN_TEXT_FILE` can change it. Unrecognised keys are warned about at startup, and a raw key
  is never rendered as though it were a sentence.
- Host image settings, all of which refuse a bad value rather than guessing: `LOG_FORMAT` (whose
  default is itself a change - see below), `FORWARDED_HOPS`, `ACCESS_TOKEN_LIFETIME`,
  `REFRESH_TOKEN_LIFETIME`, `AUTH_CODE_LIFETIME`, `SESSION_REVALIDATION` and `REAUTH_FRESHNESS`. A
  duration is a count and a unit - `30s`, `15m`, `24h`, `30d` - because `TimeSpan.Parse` reads a
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
  host of the `client_id` URL silently absent - the field `N-14` makes a MUST, on the page it
  matters most, deletable by editing a JSON file with every other check passing. A deployment
  carrying such a file starts today and will not start on this version, which is the point. The same
  check now covers every string property of `NotificationText`; it previously covered eight of ten,
  missing both halves of the new-device notice.
- **Breaking, for the container.** `LOG_FORMAT` defaults to `json` - structured and
  vendor-neutral. The Google Cloud Logging formatter was previously installed unconditionally in an
  image the README calls one image for every deployment, and its field names are Google's. Set
  `LOG_FORMAT=cloud-logging` to keep the old payload shape; `simple` is the third option.
- Newly minted opaque credentials carry `bw_ac_`, `bw_rt_`, `bw_rat_` and `bw_cs_`. `ck` was
  ConnectorKit, a name this project no longer has, and it reached the wire - 0.1.0's packages mint
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
  for `dpop` was shown a package that does not implement it - 0.1.0's nuspecs carry the tag.
  `rfc9728` is there instead, which this server does serve.
- The last vocabulary carried over from the setup this was first written against is out of the XML
  docs, which ship to consumers' IntelliSense because `GenerateDocumentationFile` is on. One
  unrelated product was named 24 times, including in a test fixture and a copy-pasteable JSON
  example; 22 sites named particular people as the actors in an anecdote; three doc comments
  justified `A-08` by what that product was sold on rather than by what this library guarantees,
  which is zero-registration and readable by a stranger. Every measurement survives; only the
  proper nouns are gone.
- The documented seam for replacing interface text is `IStringLocalizer`, registered before
  `AddBoltwayInteractionLocalization`. The XML docs said `IStringLocalizerFactory`, the way
  OrchardCore and ABP do it; nothing here has ever resolved a factory, so anyone who followed that
  got English pages and no error.

### Fixed

- **`ui_locales` now reaches the pages it selects the language for.** It arrives on `/authorize`;
  the pages are `/login` and `/consent`, which are separate requests, and the whole query went into
  `returnUrl` as one percent-encoded value - so the page read an empty `ui_locales` and rendered in
  the default language, with `ui_locales_supported` in the discovery document and the startup check
  that every advertised locale is served both passing. A deployment serving `vi` answered
  `/authorize?…&ui_locales=vi` with an English login page. The tests could not have caught it: they
  built `/login?returnUrl=…&ui_locales=vi` and requested it directly, a URL no client constructs.
- The refresh grace window no longer blames the operator's `RefreshTokenDerivationKey` for a prefix
  rename. It reconstructs a successor and checks it against the hash the store holds, failing closed
  when they differ; a row written before the rename holds the hash of the old spelling, so the
  reconstruction tries both. A wrong derivation key still matches neither and the refusal still
  fires - what this buys is that the refusal's sentence stays true, because every other route into
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
- README corrections, each of which a reader acts on - and this file is packed into all eighteen
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
  `Boltway.Storage.Testing` now, and the namespace moved with them -
  `namespace Boltway.Storage.Tests` is `namespace Boltway.Storage.Testing`. **The old id cannot be
  taken back**: nuget.org has unlist rather than delete, so `Boltway.Storage.Tests` 0.1.0 keeps
  restoring for anyone who names that version, forever.

## [0.1.0] - 2026-08-23

The first release: the authorization server, the resource server, the MCP layer, the storage
providers, federation, notifications, and the specs and research they are built against. 506 files
in one curated commit, with no history carried over from the working tree it was assembled from,
plus three changes on top of it - the copyright holder named rather than a placeholder collective;
`Boltway.Mcp`'s own JWKS refresher replaced by `Boltway.OAuth.Net.JwksKeySource` behind the same
`AddJwksSigningKeys`; and the scope and permission vocabulary of the setup it was first written
against replaced with `docs:` and `reports:`.

**Which tree that was is not recorded anywhere, so it was measured off the feed rather than read off
the log.** The packages went out from a `workflow_dispatch` that built whatever `main` was at that
moment and left no ref naming it - the gap the `release` workflow was written to close. Unpacking
`boltway.mcp` and `boltway.oauth.primitives` 0.1.0 on 2026-08-23 puts the boundary within one commit:
the nuspec names the single author, the XML docs describe `JwksRefresher` in the past tense, the
scope examples read `docs:read`, the credential prefixes are still `ck_`, the tags still include
`dpop`, and the packed README carries no badges. Everything above is on the far side of that.

Eighteen package ids are live at 0.1.0 - measured against the feed the same day, one
`curl https://api.nuget.org/v3-flatcontainer/<id.lower()>/index.json` per id. Seventeen are still in
the approved set; the eighteenth is `Boltway.Storage.Tests`, which reached the feed because a test
project set `IsPackable=true`. See *Removed* above.
