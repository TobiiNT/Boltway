# Capabilities

Four states, and keeping them apart is the whole point of this file.

| State | Where |
|---|---|
| **On, with no flag** | The table in [`README.md`](../README.md#what-you-get) |
| **Built, off by default** | [below](#built-and-off-by-default) |
| **Absent on purpose** | [below](#absent-on-purpose) |
| **Not built yet** | [below](#not-built-yet) |
| *(built, on, and not advertised)* | [a fifth state, found and closed](#a-fifth-state-found-by-looking--closed-2026-08-23) |

**Off is not absent, and unbuilt is not refused.** Two categories — absent on purpose, and absent
because nobody wrote it — leave no room for *present, and not switched on*. A capability that grew
a default therefore got filed as one of the two and stayed there: `client_credentials` sat under
"deliberately not implemented" for a release after it was implemented. Under-claiming is the safe
direction to be wrong in, which is exactly why it survived — nothing breaks, and nobody looks.

The rule underneath all of it is **N-06: never advertise a capability you do not have.**
`MetadataHonestyTests` enforces it on the metadata document. This file is the prose half, and a
person reading is what keeps it true.

---

## Built, and off by default

**This section exists because its absence made the next one wrong.** Two categories — absent on
purpose, and absent because nobody has written it — have no room for *present, and not switched on*,
so a capability that grew a default got filed as one of the two and stayed there.
`client_credentials` sat under "deliberately not implemented" after it was implemented.
Under-claiming is the safe direction to be wrong in, which is exactly why it survived: nothing
breaks, and nobody looks.

Off is the right default for every row here. The point is that "off" and "absent" are different
words.

| Capability | Turned on by | Why off |
|---|---|---|
| `client_credentials` grant | adding the name to `GrantTypesSupported` | `Token/ClientCredentialsGrant.cs`, and an arm in `TokenEndpoint`'s dispatch. Narrowed on purpose: the client names an **owner** and the token is issued for that account. A client acting purely for itself is refused with `ReasonCode.ClientHasNoOwner`, because a `sub` that is a client id resolves against no account, so roles and attribution have nothing to read |
| `/introspect` | `IntrospectionEnabled` | it answers questions about somebody else's token, so an unnecessary one is a surface that exists to be probed |
| `private_key_jwt` client authentication | adding `ClientAuthMethod.PrivateKeyJwt` to `TokenEndpointAuthMethods` | RFC 7523. The client signs an assertion with its own key and this server verifies it against the `jwks_uri` in the client's metadata — an outbound fetch to a URL the client chose, which is why it goes through the guarded fetcher and why enabling it is a decision rather than a default. Both vendors currently offer `none` beside it and this server prefers `none`, so switching it on changes nothing for them; it changes what a client that offers **only** assertions gets. Startup refuses the method without an `IClientAssertionReplayStore` |
| `/revoke` | `RevocationEnabled` | RFC 7009. Confidential clients only — `none` is never advertised for it, because an endpoint that accepted an unauthenticated caller would revoke on anyone's say-so. Revoking either token type revokes the grant behind it: the denylist is keyed on the grant and access tokens are signed rather than stored, so "revoke this access token and leave the session running" is not a state this server can represent |
| `/logout` | `EndSessionEnabled` | routed by `MapInteraction`, not by `MapBoltwayAuthorizationServer` — it is a page |
| Administration API and CLI | `AdministrationEnabled` | one `UserAdministration` behind both callers, with `RealmId` threaded through every lookup. Seven CLI verbs — `new-user`, `set-role`, `set-password`, `disable`/`enable`, `set-email`, `revoke-sessions`, `anonymise` — and `/admin/users` list-create-read-patch plus password reset, session revocation and anonymise, and `/admin/audit` over an append-only audit log. Bearer-only: an architecture test over the routing table refuses a cookie principal on it (N-17) |
| Self-service API (`/account/*`) | `SelfServiceEnabled` | `E-33`–`E-38`, bearer-only. A person reads their own account, changes their own password with the current one, sees and ends their own sessions, and sees and withdraws what they have approved |
| Self-service pages (`/me`, `/me/password`, `/me/sessions`, `/me/consents`) | `SelfServicePagesEnabled` | `E-46`, the same capabilities as a browser page. Cookie-authenticated with antiforgery, and refuses a bearer — the mirror of the row above, on purpose |
| Password reset by email (`/forgot`) | `PasswordRecoveryEnabled` | `E-39`–`E-44`. Startup refuses it without an `INotificationSender`, and the sign-in page draws the link only when it is on, because a dead link is worst for the one person least able to recover from it. `/forgot` is a page rather than a link to `E-39`, which answers JSON — pointing a browser at the endpoint would have shown somebody a line of JSON |
| Access-token revocation actually taking effect | `IAccessTokenRevocationCheck` on the resource server, plus `/introspect` here | signed tokens are not looked up, so without it a revoked grant lags by one access-token lifetime |
| Durable storage | `AddBoltwayPostgreSqlStores(...)` instead of the in-memory call | see the next section for the sample's wiring and for why not the SQLite one |

`/userinfo` is **on** by default, so it is in [What you get](../README.md#what-you-get) rather than here. It is
the one endpoint of this kind that discloses only what the caller's own access token already

## Absent on purpose

These are absent on purpose. The rule is N-06 — never advertise a capability you do not have — and
each of these was measured returning `404` while the discovery document promised it.

- **The jwt-bearer assertion grant** (`urn:ietf:params:oauth:grant-type:jwt-bearer`). It and
  `client_credentials` were both once accepted by configuration with no handler behind them.
  `KnownGrantTypes` now lists exactly the grants `TokenEndpoint`'s dispatch has an arm for, so
  enabling a name with nothing behind it is a startup failure rather than a runtime surprise, and
  `MetadataHonestyTests.Every_advertised_grant_has_a_handler` drives every listed name through
  `/token`. `client_credentials` has since grown an arm and moved to the table above; this one
  has not.
- **A second `authorization_servers` entry on the resource server.** RFC 9728 permits an array;
  Claude reads only the first. A second entry would be advertised and then refused.
- **Persisting a CIMD client.** A hundred sequential CIMD connections leave the client table
  unchanged, by design. The cache is in memory, bounded and expiring.
- **Pairwise subject identifiers**, and now with no seam pretending otherwise.
  `ISubjectIdentifierService` used to sit under *not built yet* as "exists and nothing on the token
  path calls it", which was true and was the wrong thing to keep: its signature took a `UserAccount`
  and a `ClientRecord`, while the token path carries a `SubjectId` off the grant and never loads an
  account. Wiring it would have meant a store read per token issuance, so it would not have saved
  the hunt through call sites it existed to prevent — a seam that did not fit its own seam. A seam
  nothing can call is a claim that a decision has been made, and deleting it is how the claim stops
  being made. Pairwise, if ever wanted, is `(subject, client)` threaded through `TokenIssuer` and
  `UserInfoEndpoint` plus a salt that is permanent once set.

`/revoke` and `private_key_jwt` are **not** on this list any more; both are built and both are in
the table above. That closes the set that started it — `/userinfo`, `/logout`, `/introspect` and
`/revoke` were the four endpoints this server advertised and did not serve, and each one now routes

## Not built yet

Not decisions. Gaps. [`ROADMAP.md`](../ROADMAP.md) is the wider version of this list — what an
authorization server gets judged on, measured against Keycloak on a named commit — and says plainly
that nothing in it is committed to. What is here is narrower and closer to the code.

- **Dynamic client registration (RFC 7591).** `ClientRegistrationProfile.DynamicRegistration` exists
  and **selecting it is a startup failure**, with a message naming CIMD as the way out. Nothing
  routes `/register`. Refusing at startup rather than quietly not advertising is deliberate: a
  deployment that asked for dynamic registration wants it, and publishing a document without it and
  starting anyway answers a different question than the one the operator asked.
- **SQLite does not meet the concurrent-redemption requirement.** It is a supported provider for
  development and is not one for a deployment. Under concurrent load
  `Redeeming_many_times_in_parallel_still_succeeds_exactly_once` intermittently fails with
  `SQLite Error 1: 'cannot start a transaction within a transaction'` — reproducible in roughly a
  third of runs of the storage contract, one worker in sixteen, and **undiagnosed**. What is known,
  what was wrongly recorded as ruled out, and what is now measured is on
  `SqliteRelationalStoreBehavior`. Pooling is off for a SQLite file database because a pooled handle
  is the one poisoning route that has been demonstrated; that removes a route, not the cause, and is
  not recorded as a fix. PostgreSQL is unaffected and runs the same contract.
- **The samples still wire the in-memory stores**, so a sample loses everything on restart. Durable
  storage itself is built: call `AddBoltwaySqliteStores(connectionString)` or
  `AddBoltwayPostgreSqlStores(connectionString)` instead of `AddBoltwayInMemoryStores()`, and run
  `dotnet ef database update` as a deploy step — neither call creates or migrates the database,
  deliberately.
- **Rate limiting beyond `/authorize`'s CIMD fetch and `POST /login`.** Those two are bounded (X-31,
  and `DESIGN.md` §4.1 gives the numbers and the measurements). Nothing else is: there is no
  ASP.NET Core rate limiter, no per-subject budget, and no load shedding at `/token`. **And every
  limit that does exist is per process** — each instance counts only its own traffic, so a fleet of
  *n* replicas admits *n* times each number and a caller spread across the fleet is counted
  separately by each. They bound what one instance can be made to spend; they are not an account
  lockout and not a fleet-wide quota. Put a shared limiter in front if you need one, and read
  [Before the second replica](../hosts/Boltway.AuthorizationServer.Host/README.md#before-the-second-replica) first — the limiters are one row of a
  longer list, and one of the others is a security property rather than a budget.
- **A kid-miss trigger on the resource server's key source.** `JwksKeySource` fetches the
  authorization server's discovery document, checks its `issuer`, reads `jwks_uri`, and refreshes in
  the background as the snapshot ages, so a rotation no longer stops a resource server dead. What it
  does **not** do is react to a token naming a `kid` it has not seen:
  `ProtectedResourceOptions.SigningKeySource` is synchronous and on the request path, so there is
  nowhere to await a fetch, and `CurrentKeys` deliberately returns the stale snapshot rather than
  blocking.

  That is survivable because of `PublishLeadTime`, not because it does not matter. A key ring
  publishes a key at least `PublishLeadTime` before it signs — 24 hours by default, floor ten
  minutes — and `CacheLifetime` defaults to five, so an ordinary rotation is seen long before it is
  used. **An emergency rotation that skips the lead time is the case with no cover**, and there the
  first token signed by the new key is rejected and the ones after the next refresh are not.

  Assign `JwksKeySource.CurrentKeys` to `SigningKeySource`, not to `SigningKeys` — the list is
  mutable state a request enumerates while a refresher writes it, which is a rotation-day failure of
  its own. In an MCP connector, `services.AddJwksSigningKeys(issuer)` from `Boltway.Mcp` wires the
  source, primes it at startup, and refuses to start without keys.
- **Upstream identity providers other than one.** Federated sign-in ships —
  `Boltway.Federation.Oidc` is a generic OpenID Connect relying party and
  `Boltway.Federation.Google` is configuration over it — but only one has been driven against
  a live provider's real behaviour, and that one is a fake this repository hosts. Nothing here has
  talked to Google, Entra or Okta; the discovery form probed is OIDC Discovery's append spelling
  only, and an upstream that omits the `typ` header on its ID tokens is refused. D-10's
  `sub`-disambiguation concern is unchanged: a second issuer is the point at which it starts to
  matter.
- **Multi-target for the resource server package.** `DESIGN.md` calls for `net8.0;net10.0`. It is
  `net10.0` only, and [the README](../README.md#running-it) has the measured
  reason and what it would cost.

- **Four protocol surfaces the token endpoint and `/authorize` do not have.** Each is absent
  because nobody built it, not because anything decided against it, and each is written here with
  what it would buy rather than as a to-do:
  - **The device authorization grant.** There is no second endpoint issuing a user code for a
    client that cannot open a browser. Every flow here assumes a redirect, which is true of the
    clients measured so far and stops being true the moment one runs somewhere without a browser
    at all — a terminal, a headless agent, a device.
  - **Pushed authorization requests.** An authorization request arrives entirely in the query
    string, so its parameters cross the user's browser and land in logs and history. Pushing them
    to a back channel first and passing a reference instead is the mitigation, and it is also the
    only way to make a request that is too large for a URL work at all.
  - **Token exchange.** There is no way to trade one token for another, so a service that holds a
    token for one audience and needs one for a second has to send the user back through
    `/authorize`. That is the delegation case, and it is the shape a chain of agents acting for one
    person takes.
  - **Encrypted ID tokens and userinfo responses.** Both are signed and readable. Signing proves
    who wrote a token; it does nothing to stop whoever holds it from reading the claims inside.
    Every claim this server puts in an ID token is therefore visible to the client, which is
    correct today because the client is the audience — and would not be if a token ever had to
    pass through a party that must forward it without reading it.

  None of the four is required by the client behaviour captured in `spec/`, which is why the
  absence has cost nothing yet. That is a measurement of the clients this has met, not a property
  of the protocol.

- **`acr` is neither emitted nor advertised, and the two agree.** No authentication-context class
  reaches a token and the metadata document claims none. Listing this under a gap rather than under
  *absent on purpose* is deliberate: nobody has decided it, and a deployment that federates to an
  upstream carrying step-up context has nowhere to put it.

**Two things landed narrower than their design and say so here as well as in code.** The
administrative audit entry is written *immediately after* the change rather than in the same
transaction, because every relational store here creates its own `DbContext` per call. And revoking
sessions kills refresh chains but reaches **access tokens already issued** only where a resource
server asks: those tokens are signed rather than looked up, so nothing about them changes when a
grant is revoked. `IGrantStore.IsRevokedAsync` is the denylist, `/introspect` is how a resource
server reads it, and `IAccessTokenRevocationCheck` is what calls it on the way in — all three off
unless a deployment turns them on, and a deployment that has not is back to one access-token
lifetime of lag. Designed in [`docs/USER-MANAGEMENT.md`](USER-MANAGEMENT.md), requirements in
`spec/REQUIREMENTS.md` §11.

## A fifth state, found by looking — **closed, 2026-08-23**

The four states above are what a capability can be *in*. There was a fifth this file had no box
for, and it took measuring the discovery document against the code to see it: **built, on, and not
advertised.**

`/authorize` honours four values of `prompt` — `none`, `login`, `select_account` and `consent` —
and the metadata document named none of them. A client reading discovery to decide whether it may
ask for a silent refresh found no answer and had to conclude it may not, so a capability that
existed was one nobody could discover.

**Fixed in the same pass that found it.** `prompt_values_supported` is published, and
`The_advertised_prompt_values_are_exactly_the_ones_authorize_acts_on` pins the list to the code
that reads the parameter rather than to a second list written by hand — so a fifth value honoured
without being advertised fails, and so does advertising one nothing reads. The entry stays because
the reasoning below is why the test exists, and because the state it names can recur on any other
field the document could carry.

**This is N-06 pointing the other way.** That rule refuses to advertise what is not served, and the
whole of `MetadataHonestyTests` runs in that direction: every advertised endpoint answers, every
advertised grant has a handler, the sweep catches a promise with a `404` behind it. Exactly one of
its four assertions runs both ways — the advertised claims are *exactly* what the two token
surfaces emit — and that one exists because a claim list that under-states is as wrong as one that
over-states. Nothing extends the same reasoning to anything else the document could name.

Over-advertising is the expensive direction and is guarded. Under-advertising is the cheap
direction, which is why it went unseen for a release: nothing breaks, no test goes red, and the
only cost is a client taking the long way round. There are now two assertions running
served-to-advertised rather than one, and no reason to think four is the end of the list.
