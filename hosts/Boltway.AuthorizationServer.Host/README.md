# Boltway.AuthorizationServer.Host

A deployable authorization server. Everything it needs arrives as configuration, so one image
serves every deployment and what differs between them is a secret rather than a build.

The two hosts in [`samples/`](../../samples/) exist to be read; each `DEV:` block in them is a
sentence about what a deployment does instead. **This is that.**

## It refuses to start rather than starting wrong

A server that comes up with a freshly generated signing key looks healthy, passes its probe,
is sent traffic, and issues tokens no resource server can verify. The user is told to sign in
again — forever, for a problem signing in cannot fix, in a session that worked a minute ago.

So every required setting is checked before the host binds a port, and there is no in-memory
store option: that would let a misconfigured deployment start and lose every grant on the next
scale event, which is a data-loss bug wearing a default's clothing.

## Configuration

| | |
| --- | --- |
| `ISSUER` | **required.** The public https URL. Every token carries it as `iss` and every resource server compares it ordinally — changing it invalidates everything outstanding. |
| `SIGNING_KEYS` | **required.** The JSON key ring. See below. |
| `REFRESH_TOKEN_DERIVATION_KEY` | **required.** 32 random bytes, base64. Every refresh token is derived from it, so a value that differs between restarts or replicas silently breaks all of them. |
| `RESOURCES` | **required.** `{"https://connector.example.com/mcp":{"name":"…","scopes":"docs:read docs:write email"}}`. The URL is the audience, compared byte for byte. Add `email` to a resource's scopes to release the caller's address to it — see below. |
| `DATABASE_URL` | Postgres. A `postgres://` URL is accepted and converted. |
| `SQLITE_PATH` | A file. **Development only** — see below. One of these two is required. |
| `SCOPE_DESCRIPTIONS` | `{"docs:read":"Read the knowledge base."}` — shown verbatim on the consent page. |
| `GOOGLE_CLIENT_ID` · `GOOGLE_CLIENT_SECRET` | Optional. Turns on "Sign in with Google". |
| `EXTERNAL_UNKNOWN_IDENTITY` | `refuse` (default) or `provision`. See below — the default matters. |
| `END_SESSION` | `true` (default) or `false`. Routes `/logout` and publishes `end_session_endpoint`; the two move together. See below. |
| `ADMIN_API` | `true` or `false` (default). Routes `/admin/*` and advertises `users:read` and `users:write`. See below. |
| `SELF_SERVICE` | `true` or `false` (default). Routes `/account/*` and advertises `users:self`. See below. |
| `SELF_SERVICE_PAGES` | `true` or `false` (default). Routes `/me/*` — the browser pages. Advertises nothing; they use the session cookie. See below. |
| `PASSWORD_RECOVERY` | `true` or `false` (default). Routes the reset-by-email flows, `E-39`–`E-44`. **Refused at startup without a sender.** See below. |
| `SMTP_HOST` | Setting it registers the SMTP sender. Unset means this image sends no mail at all. |
| `SMTP_PORT` | 587 by default — submission with STARTTLS. 25 is blocked outbound by most providers; 465 is implicit TLS, which this client cannot do. |
| `SMTP_STARTTLS` | `true` (default) or `false`. **`false` sends `SMTP_PASSWORD` in the clear.** |
| `SMTP_USERNAME` · `SMTP_PASSWORD` | Optional, for a server that wants authentication. |
| `SMTP_FROM` | **Required when `SMTP_HOST` is set.** The address mail comes from. |
| `SMTP_FROM_NAME` | Optional display name beside it. |
| `GOOGLE_CLOUD_PROJECT` | Optional. Adds `logging.googleapis.com/trace` to every line, which is what makes a log entry click through to its request. Omitted rather than guessed when unset. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Optional. Unset means no exporter is created at all. Set, it exports traces, metrics **and logs** — see below. |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | Optional, read by the exporter itself. `grpc` by default; set `http/protobuf` to match an endpoint given to you as an `https://` base URL. |
| `OTEL_EXPORTER_OTLP_HEADERS` | Optional, read by the exporter itself. `Authorization=Basic <base64>` for a gateway that authenticates. **A credential — store it the way you store `SIGNING_KEYS`.** |
| `UI_PRODUCT_NAME` | Optional. Appended to each page's `<title>`. Deliberately not a heading — see below. |
| `UI_STYLESHEETS` | Space-separated absolute paths on this origin. Defaults to `/css/authorization.css`, the sheet in this image; set it to `""` for the bare unstyled pages. |
| `UI_LOGO_PATH` | Optional. An absolute path on this origin, shown above the page. |
| `UI_CSP_NONCE` | `true` adds a per-response nonce to `script-src` and `style-src`. Only needed by a replacement layout with inline script or style; the pages this image serves have neither. |
| `UI_PROVIDERS_FIRST` | `true` puts the federated buttons above the password form. It reorders the markup rather than the stylesheet, so the tab order moves with them. |
| `UI_DEFAULT_LOCALE` | The language the pages are served in when nothing else applies. `en` if unset. **Setting it on its own advertises that language and still serves English words** — it is the translations that supply the words. |
| `UI_TRANSLATIONS_FILE` | Path to a JSON object of culture → key → sentence, the keys being the constants on `InteractionText`. Partial on purpose: anything left out falls back to English one string at a time. Prefer this to the variable — a translation is a document, and it is reviewed in a diff. |
| `UI_TRANSLATIONS` | The same JSON inline, for a deployment with nowhere to mount a file. **Setting this and `UI_TRANSLATIONS_FILE` together is refused at startup**, rather than one of them silently winning. |
| `NOTIFICATION_TEXT_FILE` | Path to a JSON object of property → sentence for the mail this server sends, the keys being the properties of `NotificationText`. Partial per property. One set per deployment rather than one per recipient — [`docs/LOCALIZATION.md`](../../docs/LOCALIZATION.md) says why. |
| `NOTIFICATION_TEXT` | The same JSON inline. **Setting this and `NOTIFICATION_TEXT_FILE` together is refused at startup**, and so is a sentence carrying a placeholder the message does not supply — that one would otherwise surface as a reset mail that silently never arrives. |

### The two account surfaces, and why each is a separate setting

`ADMIN_API` serves `/admin/*` — list, create, patch, reset a password, end somebody's sessions,
anonymise, and read the audit log. `SELF_SERVICE` serves `/account/*`, where a person reaches their
own account and nothing else.

**Both default to off, and both were unreachable before they were settings.** The endpoints were
built and routed behind flags in the library, and this image set neither and offered nothing that
could — the same defect `END_SESSION` turned out to be, found by looking for a second instance of
it. An endpoint nothing can turn on is an endpoint nobody has.

**Two settings rather than one**, because they are two decisions. The admin API is the highest-value
target in the system: a flaw there is not a leaked document, it is the directory, and a deployment
that manages accounts over ssh should not serve one at all. The self-service surface reaches exactly
one account — the caller's — and a deployment can reasonably want it while wanting no admin API.
One flag would make that combination impossible.

Turning either on also advertises the scopes it authorizes on, because a routed endpoint whose scope
is unadvertised is unreachable: no client can request a scope the discovery document does not name,
so the surface answers 403 to everyone and reads as a permissions bug in whatever the operator is
holding. Startup refuses that configuration rather than serving it.

`SELF_SERVICE_PAGES` serves the third surface: `/me`, `/me/password`, `/me/sessions` and
`/me/consents`, which are the pages a person uses in a browser. They are cookie-authenticated with
antiforgery and **refuse a bearer token**, which is the mirror image of the other two — `N-17` read
literally would mean a person changing their own password has to run an OAuth client, and the way
out is a third prefix rather than a softened rule. They advertise no scope, because there is no
token involved.

They are drawn through `IInteractionRenderer`, so a deployment that replaced the look of `/login`
and `/consent` gets these in the same look. A deployment that replaced the renderer *before* these
existed keeps compiling and gets the library's unthemed pages for the ones it has not written —
they are default interface members.

**Every string on every page is translatable except one.** `/error` shows the OAuth
`error_description`, which OAuth 2.1 §4.1.2.1 restricts to ASCII and `A-12` requires on the page so
that `curl -D-` debugs a client integration. That line is written for whoever built the application,
so it stays English under a translated label and inside `<p lang="en">`; the sentence a person reads
is above it, translated, and chosen by what they can actually do about the refusal.

`/me/consents` and `/me/sessions` both describe what a client may do with the same
`SCOPE_DESCRIPTIONS` the consent page used, because a person agreed to "Read the knowledge base" and
would not recognise `docs:read` as the same decision — and because they are two views of one
authorization, a click apart. A scope with no description configured is shown raw and flagged on
every one of the three, which is `A-14` and is decided in one function rather than by each page.

The two pages answer different questions and the difference is the point. `/me/consents` is what you
agreed to: withdrawing means the client has to ask again, and it does **not** end access already
granted. `/me/sessions` is what is currently granted, and ending one stops new tokens being issued.
Each page says so and links to the other.

### `PASSWORD_RECOVERY` needs somewhere for the mail to go, and is refused without it

It routes seven things at once — `POST /account/password/forgot`, `/account/password/reset` and
`/account/email/verify`, plus the `/reset` and `/verify-email` pages those links actually land on
and the `/forgot` page a person asks from. Endpoints and pages ship together because `E-40` and
`E-41` on their own are a design that mails somebody a URL answering 405.

`/forgot` is also what the sign-in page's "I have forgotten my password" link points at, and that
link appears **only when this flag is on** — the page is not routed otherwise, so an unconditional
link would hand a 404 to the one person least able to recover from it. `E-39` answers JSON and is
for a caller driving the flow programmatically; the page calls the same service in process, holds
to the same `S-48` rule (one answer, whether or not an account matched) and is charged against the
same throttle.

**Startup refuses `PASSWORD_RECOVERY=true` with no `INotificationSender` registered.** Without one,
the reset endpoint answers `202`, mints a link, and delivers nothing: every observable signal says
it worked, and the only thing that does not happen is the one the caller is waiting for. They find
out by watching an inbox stay empty. `SMTP_HOST` is what registers the shipped sender; a deployment
sending through an API registers its own before `AddBoltwayAuthorizationServer` and leaves
`SMTP_HOST` unset.

`SMTP_FROM` is required alongside `SMTP_HOST` and has no default this image could invent. Prefer a
real, deliverable address to `no-reply@` — the reply to a password-reset mail is usually somebody
saying "this was not me", which is the most useful message a deployment can receive and the one
`no-reply` throws away.

**The words are English and plain text, and that is a placeholder.** `DefaultNotificationRenderer`
has no branding and no signature, because a library cannot supply a product's voice. Register an
`INotificationRenderer` to replace it — separate from the sender, so writing your own subjects does
not mean reimplementing a transport. Plain text is not a simplification either: a reset mail is what
a phishing kit imitates, and a visible URL is one a person can read before following it.

**What the flows enforce, which is worth knowing before turning them on:** asking for a reset answers
identically whether or not the account exists and does the same work either way (`S-48`), so the
endpoint is not a way to test which addresses are registered. A link is single-use, expires in 15
minutes, and **dies the moment the password changes by any route** including the CLI's
`set-password` (`S-47`). Redeeming one revokes every session, unconditionally — somebody resetting
through email is usually doing it because they lost control of something. And the endpoints are rate
limited per submitted identifier and per source, because `E-39` sends mail to an address the caller
chooses; like every limit here that is **per process**.

### `END_SESSION` is on here and off in the library

`AuthorizationServerOptions.EndSessionEnabled` defaults to off, next to `UserInfoEnabled`,
`RevocationEnabled` and `IntrospectionEnabled`. Those three name endpoints that do not exist yet,
where the only safe default is "not advertised". `/logout` left that group when it was routed —
it is implemented and tested — and this host is the shared machine the sign-out work was written
about, so here the default is the other way.

It had to become a setting for a plainer reason: **nothing in this image set the flag and there
was no setting to set it with**, so the endpoint was unreachable from every deployment of it. The
symptom was quiet — `/logout` answered 404 and `end_session_endpoint` was absent, which is a
consistent pair and reads as a server that simply does not do sign-out. One deployment met it by
translating the six sign-out strings into Vietnamese and finding no page to put them on.

Routing and advertising move together in the library, so `false` is a supported answer and not a
way to reintroduce N-06: it removes the route and the metadata field in one go. Set it when a
front proxy or a client depends on the endpoint being absent.

### The sign-in and consent pages

These settings are the lowest of Boltway's three UI tiers, and the one to reach for
first: nothing here can touch the part of the consent page that says which host is asking and
where the authorization code will be sent, so a deployment gets its own look without acquiring
N-14. The two tiers above — `IInteractionLayout` and `IInteractionRenderer` — need code, and
the repository `README.md` covers what each of them costs.

**Every path must be an absolute path on this origin**, and a URL anywhere else is refused at
startup with the setting named. That is not fussiness: these pages send `default-src 'self'`, so
a stylesheet on a CDN is refused by the browser and the only symptom is an unstyled page with the
explanation in a console nobody is reading.

`UI_PRODUCT_NAME` lands in the `<title>` rather than in a heading. A browser tab is how a user
with several open works out which server is asking for their password; the most prominent text on
the page itself has to remain the client's hostname, which is what N-14 is about.

The stylesheet lives at `/app/wwwroot/css/authorization.css` in the image. A deployment with its
own design mounts a volume over `/app/wwwroot/css` and points `UI_STYLESHEETS` at what it put
there — no rebuild and no fork.

### `SQLITE_PATH` is for development, and the host says so at startup

It used to read "a file, for a single instance". That was an offer this repository cannot keep: a
single instance still serves concurrent requests, and **the SQLite provider does not currently meet
the concurrent-redemption requirement.** Under concurrent load a redemption intermittently fails
with `SQLite Error 1: 'cannot start a transaction within a transaction'` — measured, reproducible in
roughly a third of runs of the storage contract, one worker in sixteen, and undiagnosed. It is
written up on `SqliteRelationalStoreBehavior`, where the two mechanisms once recorded as ruled out
are corrected.

On the authorization server that failure is a user who cannot finish signing in, on a code that then
cannot be retried. Use `DATABASE_URL`. `SQLITE_PATH` is there so a developer can run the host
without a database server, and the host logs a warning naming this when it starts on one.

Connection pooling is off for a SQLite file database, which removes the one poisoning route that has
been proven to exist. That is not the same as a fix, and it is not recorded as one.

### Logs

Every line is JSON, in the shape Cloud Logging indexes: `severity`, `message`, and each of the
log's named properties as its own field. A refusal arrives as `Reason`, `Surface`,
`CorrelationId`, `RequirementId`, `Status` and `Error` — so *"how many `AccessTokenRejected` in
the last hour, and did they all name the same `kid`"* is a query rather than a grep, which is
what `RejectionResult` was built for and what the console provider was undoing at the last step.

The field names are Google's and are not interchangeable. The framework's own `AddJsonConsole`
writes `LogLevel` and `Message`; Cloud Logging reads `severity` and `message`, so wiring the
built-in one gets structure and loses severity — every line arrives at DEFAULT and a page of
errors reads like a page of chatter.

Verified by running the host and parsing what it wrote: 15 lines, 15 valid JSON objects, levels
mapping to `INFO`/`WARNING`, and no `ck_*` secret, JWT or PEM block anywhere in them.

### Traces, metrics and logs

`OTEL_EXPORTER_OTLP_ENDPOINT` unset means **no exporter is registered**. Always exporting to a
default that is not reachable is a background thread retrying forever and a line about it every
minute, which is how observability becomes the thing being diagnosed.

Set it and three signals leave the process:

- **Traces** — ASP.NET Core instrumentation, `/health` filtered out. Nothing hand-rolled:
  `DESIGN.md` says "no custom tracing… no trace viewer or sampling policy".
- **Metrics** — ASP.NET Core's own `http.server.request.duration`, plus the `Boltway.Auth`
  and `Boltway.Storage` meters. Two meters because
  `Boltway.Storage.EntityFrameworkCore` cannot reference the authorization server; the
  dependency runs the other way, and that is what lets storage be replaced.
- **Logs** — every `ILogger` record, alongside the JSON already going to stdout.

**The logs are new, and they turn on for a deployment that has set nothing but this one
variable.** `UseOtlpExporter` enables all three signals, and logs — unlike metrics and traces —
need no source or meter enabled first, so records start leaving the moment the endpoint is set.
That is deliberate: Docker deletes a container's logs along with the container, so on a
compose host every deploy takes with it the evidence of whatever it was fixing. If you want the
other two signals and not this one, the endpoint variable is not the knob — use per-signal
`OTEL_EXPORTER_OTLP_*_ENDPOINT` variables and change this block back to per-signal exporters.

`IncludeFormattedMessage` is set, and it has to be. It is `false` by default — measured against
1.17.0 — and false means the exported body is the message template, `realm {Realm}`, with the
values only in the attributes beside it.

#### Pointing it at a vendor

The endpoint most vendors give you is a **base URL** with no signal path, e.g.
`https://otlp-gateway-<region>.grafana.net/otlp`. Two variables have to go with it, both read by
the exporter rather than by this host:

```
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
OTEL_EXPORTER_OTLP_HEADERS=Authorization=Basic <base64 of instanceID:token>
```

The protocol is not optional decoration. The .NET exporter defaults to **gRPC**, so an `https://`
base URL pasted in on its own is sent to the wrong transport.

`UseOtlpExporter` appends `/v1/traces`, `/v1/metrics` and `/v1/logs` to that base URL. The
per-signal `AddOtlpExporter` does not — upstream's README: *"the full URL MUST be provided,
including the signal-specific path v1/{signal}"* — which is why this host uses the former.
Measured against a listener recording what it was called with: one base URL plus
`http/protobuf` produced POSTs to all three paths, each carrying the `Authorization` header.

Google's Telemetry API accepts OTLP at `https://telemetry.googleapis.com`, and per their
documentation an in-process exporter must attach Application Default Credentials to reach it.
**That auth header is not wired here** — `OTEL_EXPORTER_OTLP_HEADERS` carries a static header, not
a refreshed ADC token — so pointing this variable straight at Google still needs a collector
configured with `googleclientauth`. Any gateway authenticated by a static header works as-is.

### `/userinfo`, and what it is for

Advertised and routed together, on by default. An OIDC client that is not a resource server has no
business reading an access token — it is not the audience — so a client that needs to know who
signed in has two channels: the ID token, and this.

The ID token deliberately carries neither the address nor the role, because a client "has no
business routing on somebody's role" out of a token whose job is to prove who signed in. That
argument does not reach here: this endpoint is called **with** the access token, which already
carries the role, so nothing is disclosed the caller was not already holding.

| claim | when |
| --- | --- |
| `sub` | always — OIDC Core §5.3.2 |
| `preferred_username` | always, if the account has a handle |
| `email`, `email_verified` | with `email` |
| `role` | always, if the account has one |

Neither `preferred_username` nor `role` is behind a scope, and that matches the access token,
which already releases the handle ungated and gates only the address. The asymmetry is deliberate: an address is personal data the
subject consents to release, while a role is what a client needs in order to decide what this person
may do at all. Behind a scope, a client that forgot to ask gets a login that succeeds and grants
nothing — which reaches a person as "my account is broken" rather than as a missing scope.

Everything is read **from the directory, not from the token**. A token is a snapshot up to half an
hour old, so a demotion would otherwise reach a client at the next token expiry rather than the next
sign-in.

Bearer only, like every other API here — `N-17`. Set `UserInfoEnabled` to false and the endpoint is
neither routed nor advertised.

### What an access token says about the caller

`iss`, `aud`, `sub`, `scope`, `client_id`, `gid`, `iat`, `exp`, `jti` — plus **`preferred_username`**,
because this host calls `AddSubjectClaimsFromAccounts()`.

Without that call the token names nobody. It is a correct library default: a resource server that
only needs to know a request is authorised should not be handed a name. It is a bad *deployment*
default, and the failure is silent — the connector this was built for had a whole attribution path,
and every commit it made came out authored by `01KZAWCB5XY91G8N9XG84WR1EN` the moment it moved off
static tokens. Nothing errored. The git history simply stopped naming people.

`email` and `email_verified` go out only when the grant covers the **`email`** scope, which a
resource asks for by listing it among its own scopes in `RESOURCES`:

```
RESOURCES='{"https://connector.example.com/mcp":{"name":"…","scopes":"docs:read docs:write email"}}'
```

A resource that does not list it gets the handle and nothing else. The handle is unscoped because
it goes into an audit trail rather than a mailing list, and it is already what the sign-in page
showed the user; an address is a way to reach them, so it is a thing they agree to on the consent
page.

None of this can restate a protocol claim. `JwtTokenMinter` refuses `sub`, `aud`, `scope` and the
rest with an exception rather than a silent skip — which is what keeps the claims seam a
convenience rather than a way to mint a token for somebody else.

### A Google account is not an account here

With `refuse`, a Google identity nobody has linked is turned away. That is the right default
for a company that demos to prospects: under `provision`, anyone in the world holding an
account at the configured upstream gets one here — including the prospect who clicks through
your demo and lands in your production directory.

There is deliberately no match-by-email. Linking an upstream identity to an existing local
account because the addresses agree is the classic federated takeover, and `IUserStore` has no
method that finds an account by email, so there is no path to make an exception in.

The supported route is: create a local account, sign in with it once, then link Google through
`POST /external/{scheme}/link`, which requires a live session for the account being linked to.

## Four commands, so the image is self-sufficient

```bash
# Mint the first key, or start a rotation. Put the output in the SIGNING_KEYS secret.
… -- new-key 2026-08
… -- new-key 2026-11 pending

# Apply pending migrations, then exit.
… -- migrate

# Create the first account. Nothing else here creates one: there is no registration
# endpoint, and federated sign-in refuses an unknown identity by default — so without
# this the first deployment comes up healthy with no way in at all.
… -- new-user ada ada@example.com founder

# Change what an account's tokens claim it is. `-` clears the role.
… -- set-role ada employee
```

The two trailing arguments of `new-user` are matched by shape, not by position: whichever has
an `@` is the address and the other is the role. Two optional positionals in a fixed order is
the shape where `new-user ada founder` silently creates an account whose email is `founder`.

### There is no admin console, and roles are a column

**Creating accounts** is `new-user`, and that is the only path in. No registration endpoint, no
match-by-email: there is no setting that links an upstream identity to a local account because the
addresses agree, and federated sign-in refuses an identity nobody has linked, by default. An
upstream identity reaches an existing account exactly one way — `POST /external/{scheme}/link`,
submitted from a page that account is already signed in to.

That used to rest on `IUserStore` having no method that finds an account by an address at all.
It has one now — the sign-in form takes a verified address as well as a handle — so what holds the
rule up is that only the sign-in form may call it, checked in the IL by
`StructuralRuleTests.Only_the_sign_in_form_resolves_an_account_by_address`.

**Permissions come in two layers, and conflating them is the usual mistake.**

*Scope* is what the **client** may ask for — `docs:read`, `docs:write`, `email`. It is shown on the
consent screen, the subject approves it, and this server enforces it. That is an OAuth concept
and it is fully built.

*Role* is what the **person** is — one string, stored on the account, emitted as the `role`
claim in the access token. This server never compares it to anything. `founder`, `admin`,
`tier-2` are all the same to it; deciding what a role permits is the resource server's job, and
a library that shipped a vocabulary would be shipping one customer's org chart to every other.

The claim name is `role` because that is what `ResourceServerAuthenticator.FromClaims` reads by
default. Those two live in assemblies with no compiler relationship between them, so the only
thing holding them to the same string is a test — `An_access_token_carries_the_role`.

**Single-valued**, and that is a matched pair rather than a limitation: `FromClaims` reads it
with `FindFirst`, which takes one value and drops the rest. Storing a set here would emit tokens
whose second role no consumer reads.

**No groups, no tenants, no organizations.** An account is a subject, a handle, an address, a
password hash, a disabled-at and a role. If a deployment needs group membership, the seam is
`IAccessTokenClaims` — implement it against whatever holds the org chart and register it instead
of `AddSubjectClaimsFromAccounts()`. Nothing in this server needs changing for that.

**An account with no role gets a token with no `role` claim**, which a resource server answers
with whatever it treats as least privileged. `new-user` says so when it creates one, because the
alternative is discovering it as "nothing is readable" during a demo.

**Tokens already issued keep the old role until they expire** — 30 minutes by default. A role is
copied into the token at issue, not looked up per request, which is what makes the resource
server able to validate offline.

The password is generated rather than taken as an argument, because an argument is visible in
the process list and in shell history, and printed once.

Migrations are a command rather than something startup does. Two replicas starting together
would race the same migration, and a half-applied schema is the one state neither a retry nor
a rollback fixes.

## Rotating a key

All three steps are edits to one secret, because the ring stores each key's **state** and not
just its material:

1. Add a second key with `"state":"pending"`. It appears in JWKS and signs nothing.
2. Wait out the lead time — the discovery document is served `max-age=300` and clients cache
   with their own staleness window on top. A key that signs before every verifier has seen it
   produces signature errors nobody diagnoses as a timing problem.
3. Flip the new key to `active` and the old one to `retiring`. Delete the old entry once every
   token it signed has expired; `retired` is not an accepted state, because carrying a dead key
   in the secret invites promoting it back.

## Verified, not assumed

```
new-key 2026-08          → kid=2026-08 state=active alg=RS256
migrate                  → Applied 1 migration(s): 20260805023325_InitialSchema
GET /.well-known/jwks.json    kid=[2026-08]  n=oUEga_ROJCYxhdrl…
<restart>
GET /.well-known/jwks.json    kid=[2026-08]  n=oUEga_ROJCYxhdrl…   ← same key
```

That last line is the whole reason this host exists.

And the whole flow, against this host, with the `client_id` Claude publishes — dereferenced over
the network by the server, not stubbed:

```
GET  /authorize   client_id=https://claude.ai/oauth/mcp-oauth-client-metadata  → 303 /login
POST /login                                                                    → 303 /authorize
GET  /consent     "See your email address. | Read the knowledge base. | Write to it.
                   | Stay connected without asking you again."
POST /consent     decision=approve  → 303 https://claude.ai/api/mcp/auth_callback
                                        code=bw_ac_j4Y5mI…  state ok  iss=…
POST /token       → 200  scope="email docs:read docs:write offline_access"
                    sub=01KZB0MH1074XVDAQEJH924RBM  preferred_username=ada
                    email=ada@example.com          email_verified=false
POST /token       grant_type=refresh_token → same preferred_username, same email
```

`email_verified` is `false` because `new-user` does not verify an address and nothing else has —
which is the honest answer, and the reason the claim ships beside the address rather than instead
of it.

The resource server on the other end of that token attributed its commit to
`ada <ada@example.com>`. The same write, in the same run, with a token differing only in
those three claims:

```
author  = null
message = "…\n\nActor: 01KZB0MH1074XVDAQEJH924RBM"
```

Same key, same subject, same request. The difference in what git records is the claims.

## How long it takes to start

Measured before this mattered, and kept because it is a fact about the host rather than about
any one platform: process start to the first `200` from `/health`, Release build, against a real
PostgreSQL, five runs.

```
2468 ms   cold page cache, nothing JITted
 546 ms   577 ms   586 ms   547 ms   warm
```

So the application contributes about half a second warm and two and a half seconds on a genuinely
cold start. It is what a healthcheck's `start_period` has to clear, and it is what to weigh
against keeping an instance warm on a platform that scales to zero.

This number was written down inside a Cloud Run deploy workflow that no longer exists. It moved
here rather than going with it, because a measurement is the expensive part and the deployment
target is not.
