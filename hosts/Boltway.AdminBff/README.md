# Boltway.AdminBff

The admin UI, and it is an OAuth client rather than a page on the authorization server.

`N-17` says no admin endpoint may be reached with a cookie principal, so there is no
cookie-authenticated admin page — the UI has to be a client. Of the two shapes for one, a
single-page app keeps the token in the browser (one XSS from exfiltration, plus CORS on the admin
API and a `connect-src` widening here) and a backend-for-frontend keeps it server side at the cost
of one more small deployable. What is behind this API is the directory rather than a document, so
this is the BFF.

**`N-17` is untouched by it.** The browser's cookie is scoped to this app's hostname and this app's
session; the admin API only ever sees a bearer token.

## The token never reaches the browser, and that needs a ticket store

Saying "the token lives server side" is only true if it does. The default ASP.NET Core cookie
handler serialises the tokens *into* the cookie — encrypted, so a script cannot read them, but still
handed to the browser on every response and written wherever the browser writes cookies. An
`ITicketStore` is what makes the claim exact: the cookie holds a 256-bit key and the ticket stays
here.

The shipped store is in memory, which is the honest limit of it. Signing every operator out on a
deploy is acceptable — the population is small and signing in again is a redirect — but **a second
replica needs a shared store**, or an operator is signed out whenever the load balancer moves them.

## Deploying it

`ghcr.io/<owner>/boltway-adminbff`, built from `Dockerfile` beside this file and pushed by the
same CI job that pushes the authorization server. Both are built from every commit, so a tag exists
for each; pin the sha rather than `latest` in anything a person is not editing by hand.

**That image did not exist for the first stretch of this project's life.** There was no Dockerfile
and no line in CI, so this was a host that built, passed its probes against `dotnet run`, and could
not be deployed by anybody — the same defect this repository has now found seven times, and one that
nothing except an image build asks about.

It needs no volume. The authorization server mounts one for its Data Protection keys because its
cookie is a person's session with the identity provider; this app's cookie is a key into an
in-memory ticket store that a restart empties anyway, so persisting the keys would preserve cookies
whose tickets are gone. An operator whose cookie outlives a deploy is bounced to the authorization
server, is already signed in there, and comes straight back.

## Configuration

| | |
| --- | --- |
| `AUTHORITY` | **required.** The authorization server's issuer URL. Discovery hangs off it. |
| `ADMIN_API` | The base URL of `/admin/*`. Defaults to `AUTHORITY`; §1.4 puts it on its own hostname in a deployment that wants one. |
| `CLIENT_ID` | **required.** What this app is registered as, in the server's `CLIENTS`. |
| `CLIENT_SECRET` | **required.** Mint it with the server's `new-client-secret` — see below. |
| `ADMIN_RESOURCE` | The admin API's resource URL, sent as RFC 8707 `resource`. Defaults to `AUTHORITY` + `/admin`, which is how the authorization server derives it too — override both together or neither. |
| `ADMIN_ROLES` | Which roles administer the directory, so the pages can say what a role means. Optional; unset means the pages say nothing about administration rather than naming a set they were never given. |
| `ADMIN_TEXT_FILE` | A JSON object of key to sentence, keys being the constants on `AdminText`. Optional, and partial: every key falls back to English on its own. `$language` sets the document's `lang`. A key this build does not know is named on stderr at startup and then ignored — per-string fallback means a typo renders correct English, so a sentence that did not change is the only other signal there is. |
| `ADMIN_STYLESHEETS` | What to link, in order. Defaults to `/css/admin.css`, the sheet this app ships. Setting it **replaces** the list — name `/css/admin.css` alongside your own to keep it. Each must be an absolute path on this origin, and one that is not is refused at startup. |

On the authorization server side the matching configuration is `ADMIN_API=true` and a `CLIENTS`
entry naming this app's redirect URI (`https://<this app>/signin-oidc`) and the **hash** of its
secret. That is all of it: the server derives its own resource URL and adds it to the registry with
the scopes it serves, so there is nothing to keep in step by hand.

### The secret cannot be a passphrase

`ClientAuthenticator` parses a presented client secret as an `OpaqueSecret` before it hashes
anything, so a value this server did not mint fails authentication whatever its hash says — and the
refusal is the same `invalid_client` as a wrong password, which is a bad afternoon. Run the
authorization server with `new-client-secret`; it prints both halves, which go to two different
places:

```
secret bw_cs_…      → CLIENT_SECRET here
sha256 …            → secretSha256 in the server's CLIENTS
```

Neither side ever needs the other's copy.

## Two things this app does by hand, and why

**It redeems its own authorization code**, to authenticate with `client_secret_basic`. RFC 6749
§2.3.1 says a client with a password SHOULD use Basic; the .NET OIDC handler puts the secret in the
body and this package version exposes no switch. Thirty lines, and it is the whole of the
hand-rolled OAuth here — PKCE, `state`, `nonce`, the cookie and the refresh are all still the
handler's.

**It asks for `response_mode=query`**, because that is what the server advertises. The handler's
default for the code flow is `form_post`, and asking for a mode the metadata does not list is the
client half of `N-06`.

## It will show you a consent screen

Once, and it reads oddly and is correct: consent is what binds `users:write` to a person entitled to
it (§1.3), and an admin UI that skipped it would be the one client exempt from the check. A
deployment whose `IConsentPolicy` always asks will see it on every sign-in.

## Changing how it looks

Three tiers, in the order to reach for them. Each one hands over more and asks for more back.

| | What it replaces | How | Can it lose something? |
| --- | --- | --- | --- |
| `ADMIN_STYLESHEETS` | Colours, type, spacing | Configuration | No — it cannot reach the markup |
| `IAdminLayout` | The document around a page: header, navigation, footer | One method | One way: drop `AdminPage.Body`, which is checked on every render |
| `IAdminRenderer` | The pages themselves | Six methods, all optional | One way per value, and no check can find them |

**Most of the demand is the middle one.** Restyling this app for a real deployment needed three
things a stylesheet could not supply, and two of them were the shell — a current-item state on the
navigation, and somewhere for the rail to be a rail. The third was an audit timestamp, which is a
renderer concern. So the tier that requires rewriting no pages at all covers two thirds of it.

**Every member of `IAdminRenderer` has a default implementation**, so a deployment overrides the one
page it cares about and inherits five, and a page added in a later release is not a compile error in
anything that already implemented the interface. The cost is that `class Mine : IAdminRenderer { }`
compiles, and so does one whose override has a typo in its signature — it silently becomes a new
method nobody calls. `AdminRendererContract` in the test project is what catches that; inherit it and
point it at the renderer.

**A default member renders in the shipped shell rather than the deployment's**, because a default
interface member has no dependency injection and cannot reach the registered `IAdminLayout`. The
mismatch is the signal that the page has not been written.

### The honest limit

This project is `IsPackable=false` and ships as a container image, so **there is no way to register
your own implementation from outside it** — you would be building a different image. What the seam
buys today is that a fork replaces one class instead of doing surgery inside a static one, and that
the stylesheet is configuration rather than a path you have to land a file on. Making this packable,
so a deployment could reference it and register a renderer, is a separate decision about publishing
an API surface.

## Signing out ends both sessions

`POST /signout` clears this app's cookie and then hands the browser to the authorization server's
`end_session_endpoint`, taken from the discovery document rather than composed from `AUTHORITY`.

**It used to clear only the local cookie, and that was not a sign-out.** Reported from production:
pressing the button appeared to do nothing, and reloading came back to the consent page. One cause
for both — the cookie went, `/` demanded authentication, the handler went to `/authorize`, the
authorization server still held its own session, and the operator was signed straight back in,
pausing only at the consent screen a deployment whose `IConsentPolicy` always asks shows every time.

No `post_logout_redirect_uri` is sent, and that is not an omission. The server refuses one: an
unregistered redirect target on the issuer's own hostname is an open redirector, and OIDC says MUST
NOT redirect to a URI that has not been validated. So the operator lands on the authorization
server's sign-out page and stays there — a page that says the session ended, rather than a bounce.

A deployment whose authorization server advertises no `end_session_endpoint` keeps the old
behaviour, because this app cannot end a session on a server that offers no way to end one.

## The header names the operator by handle, and falls back to the subject

The rail names whoever is signed in, above the sign-out control. It used to name them
`01KZX253NGXW6MPB13Y4X2GPE7`: this server's ID token carries `sub iss aud exp iat auth_time nonce
at_hash` and nothing else, so both name lookups missed and the subject was all that was left — 26
characters to compare against a table whose first column is the handle.

`OnTokenValidated` now asks `/userinfo` for `preferred_username` once per sign-in and adds it to the
principal, where the header's existing lookup finds it first. Two things about that are decisions:

- **No scope was added to reach it.** That endpoint releases the handle to any token granted
  `openid`, deliberately, because the access token already carries the same fact ungated. Adding
  `profile` to look more like OIDC would be refused with `invalid_scope` before a page rendered —
  `profile` is not a scope this server knows, since `scopes_supported` is whatever a deployment
  configured.
- **`GetClaimsFromUserInfoEndpoint` is still `false`, and the fetch is this app's.** The framework's
  switch fetches the same document and fails the sign-in when it cannot. `UserInfoEnabled` defaults
  to true and is a deployment's to turn off; on one that had, that switch would be an admin UI
  nobody can enter — a label in eleven-pixel grey deciding whether the directory is reachable.

So every way it can fail ends at the ULID rather than at an error: a server advertising no
`userinfo_endpoint`, an account with no username, a token the endpoint will not take, one
unreachable moment during a sign-in. The failure is a worse label, and it is logged.

## What it does not do

- **No JavaScript and no templating engine.** The pages send `default-src 'self'` and mean it: no
  inline `<script>` or `<style>`, no `style=` attribute, no `data:` URI, nothing off-origin. A
  layout or renderer that adds any of those is refused by the browser rather than by review.
- **It reaches nothing on the server side.** No project reference to the authorization server, its
  abstractions, or a storage package: the contract between them is HTTP. A BFF that reached into
  `IUserStore` would be a second implementation of what `UserAdministration` owns, and the audit
  entry — written on the service's path — is the half that would drift first.
