# User management — design

What exists today is `new-user`, `set-role` and `set-password`. This is the design for the rest of
it: an account lifecycle, an administrative surface, self-service, and the two flows that need to
reach a person by email.

Requirement IDs follow [`spec/REQUIREMENTS.md`](../spec/REQUIREMENTS.md) — `S-nn` spec, `E-nn`
endpoint, `X-nn` error, `N-nn` non-negotiable, `A-nn` Auth0-trap, `D-nn` deferred. The new ones are
written into §11 of that file rather than only cited here; §0.1 below says why that mattered.

---

## 0. What is actually there, measured

Before designing, the gap was measured rather than assumed.

| | |
| --- | --- |
| `UserAccount` | `Subject` (ULID), `Username`, `Email`, `EmailVerified`, `PasswordHash`, `DisabledAt`, `Role` |
| `IUserStore` | find by subject / username / external login, add-only `StoreAsync`, `LinkExternalLoginAsync`, `SetRoleAsync`, `SetPasswordHashAsync` |
| CLI | `new-key`, `migrate`, `new-user`, `set-role`, `set-password` |
| Enforced | `IsActive` is checked on **both** sign-in paths — `InteractionEndpoints` local, `ExternalLoginEndpoints` federated |

And the holes that produced this document:

- **`DisabledAt` is enforced and unsettable.** Two code paths refuse a disabled account and nothing
  in the library, the CLI or any store method can disable one. The rule exists; the control does not.
- **`email_verified` is emitted and never true.** `UserAccountClaims` puts it in every token.
  Nothing anywhere sets it. Every token this server has ever issued says `false`, so a resource
  server that trusts the claim is reading a constant.
- **No account can be listed.** There is no way to answer "who has an account" without opening the
  database.
- **No self-service of any kind.** A person cannot change their own password, see their own
  sessions, or withdraw a consent they granted.
- **No sessions view is possible even in principle.** `IRefreshTokenStore` can revoke a family by
  id, and nothing can list the families belonging to a subject. `IConsentStore` can find and revoke
  one consent by `(subject, clientId)`, and cannot enumerate a subject's consents.
- **No audit.** Nothing records that an administrative change happened, let alone who made it.
- **User management is in neither list in the README** — not under "deliberately not implemented",
  not under "simply not built yet". An unwritten gap is worse than a written one, which is the whole
  point of `N-06`.

### 0.1 One cross-reference in the design documents points at nothing

`DESIGN.md` cites **§7's traceability test** twice — *"fails the build for any binding requirement
without a covering test"* — including as the mitigation for the weakness §0 admits about its own
provenance. **`DESIGN.md` has no §7.** Measured: fifteen headings, the last is §6, and no heading
numbered 7 at any level.

That is the failure `DESIGN.md` §3.1 already records about `A-09` — *"true in the document and
false in the code for the whole of the project's history"* — repeated in the same document, about
the mechanism that was supposed to catch it. It is not fixed here, because writing a traceability
test is its own piece of work; it is named so that the next person does not lean on it.

**The requirement IDs this design introduces are therefore written into `REQUIREMENTS.md` §11, not
merely cited here.** Citing what does not exist is the defect above, and a design that assigned
seventeen endpoint ids to a document that never received them would be committing it a third time.

> `REQUIREMENTS.md` §10 was also written up here as missing, and it is not — it exists, after the
> appendix, which is why a truncated listing of the headings missed it. The claim was withdrawn on
> measurement rather than left standing. Recording *"we did not look"* as *"it is not there"* is
> what `LESSONS.md` is about, and it took one careless `head` to do it.

---

## 1. Decisions

### 1.1 The admin surface is HTTP, which reverses cut list #6

Cut #6 was *"the admin HTTP surface — keep `ConfigSchema.Build()` behind the CLI"*. That is
reversed deliberately: Boltway is deployed into customer projects, and "manage your users over
ssh" is not a thing most customers will accept.

The reversal is not free, and the cost is concentrated in one place: **an admin API on an
authorization server is the highest-value target in the system.** A flaw there is not a leaked
document, it is the directory. Every decision below that looks paranoid is paying for this one.

### 1.2 Authorization is by scope. The role stays opaque

`UserAccount.Role` is documented as opaque — *"this library stores a string and emits it as a
claim; it never compares it to a constant… a library that shipped a vocabulary would be shipping one
customer's org chart to every other customer"*. That holds. The admin API therefore authorizes on
**scopes**, which the library already owns end to end, and never on the role.

Two scopes, and no more, because each one is a thing a customer must reason about:

| scope | grants |
| --- | --- |
| `users:read` | read accounts and the audit log |
| `users:write` | every mutation |

Self-service is **not** a narrower `users:*`. See §1.6.

### 1.3 `IScopeEntitlementPolicy` — the hole that scope-based authorization opens, and its plug

Scopes are requested by a client and granted by consent. So without a further check, **any account
could obtain `users:write`** by signing in to a client that asks for it and clicking allow. Scope is
a statement about what a client may do on someone's behalf; it has never been a statement about
whether that someone is allowed to do it.

```csharp
public interface IScopeEntitlementPolicy
{
    /// Narrow `requested` to what this subject may ever be granted.
    ValueTask<ScopeSet> FilterAsync(UserAccount user, ScopeSet requested, CancellationToken ct);
}
```

- **Default implementation returns `requested` unchanged**, so every existing deployment behaves
  exactly as it does today and this is not a breaking change.
- One deployment configures: `users:read` and `users:write` only for `Role == "founder"`. **The comparison to
  a constant happens in the host**, which is exactly where the role's own documentation says
  vocabulary belongs.
- Applied at `/authorize` **and again at token issuance**. Once is not enough: a consent granted
  while someone was a founder must not keep minting `users:write` after they are not.
- **It filters, it does not refuse.** OAuth already means "granted may be narrower than requested".
  A refusal turns a demotion into a client that cannot connect at all. If filtering leaves the set
  empty, *that* is `invalid_scope` — the client asked for nothing it can have.

### 1.4 The admin API is a separate resource, bearer-only, and a cookie must never authenticate it

**`N-17` (new, non-negotiable).** No admin or account endpoint may be reachable with a cookie
principal.

The sign-in pages live on the same origin. If the session cookie authenticated the admin API, then
any XSS on the login page, or any CSRF against it, would be takeover of the entire directory rather
than of one session. Bearer-only also makes CSRF structurally impossible there — there is no
ambient credential for a browser to attach.

This is the rule most likely to be broken by a well-meaning change ("it would be so much easier to
call this from the consent page"), so it gets an **architecture test**, not a code review
convention — the same reasoning `DESIGN.md` gives for the sixteen `N-nn`.

The admin API is also its own **resource** in the `IResourceRegistry`, so `resource` → `aud` binding
applies and a token minted for a customer's connector cannot be replayed against it. That binding is
already on the never-cut list; this design is the first thing that would be catastrophic without it.

**A separate hostname is what turns `N-17` from a rule a test enforces into one the browser
enforces.** ASP.NET Core's cookie handler sets no `Domain` attribute, so the session cookie is
**host-only**: a browser will not attach a cookie set on `auth.example.com` to a request for
`admin.example.com`. Serving the admin API from its own hostname removes the ambient credential from
that origin entirely, rather than relying on every future handler being registered against the right
policy.

`N-17` and its architecture test stay regardless. Not every deployment will run two hostnames, a
library cannot require one, and a rule enforced two independent ways is the shape this repository
already uses elsewhere: PKCE is unconditional *and* the presence XOR stays, "because someone will
add a legacy escape hatch".

The cost, named: a second certificate, a second edge site block, and CORS becomes a real
consideration for any browser-based admin UI where same-origin would have hidden it. That is worth
paying for a directory. It may not be for a smaller resource, which is why the hostname is the deployment's
deployment decision and `N-17` is the library's requirement.

### 1.5 Every mutation is audited, in the same transaction as the change

```csharp
public interface IAdminAuditStore
{
    Task RecordAsync(AdminAuditEntry entry, CancellationToken ct);   // append-only
    Task<IReadOnlyList<AdminAuditEntry>> ReadAsync(AuditQuery query, CancellationToken ct);
}
```

`AdminAuditEntry`: `at`, `actorSubject`, `actorClient`, `action`, `targetSubject`, `outcome`,
`correlationId`.

- **Same transaction as the write it describes**, through `IRelationalStoreBehavior.BeginWriteAsync`.
  A change that lands without its audit line is the half-state problem, and here the half that
  survives is the one nobody can see.
- **Append-only.** No update, no delete, not through the API and not through the CLI. An audit log
  an administrator can edit is a log that proves nothing about administrators.
- The correlation id is the one `Rejection` already carries, so a refused administrative action and
  its log line join up.

### 1.6 Self-service is a different surface, not the admin surface with an `if`

`/account/*`, scope `users:self`, and a handler may only ever act on the subject in the token.

The alternative — one set of handlers with "unless the target is yourself" — is how an authorization
bug is written. Two surfaces means the self-service handler has no code path that can reach another
account, rather than having one that is currently guarded.

`users:self` is granted by the default entitlement policy to everyone, because it conveys no
authority over anyone else.

### 1.7 `RealmId` now, single-tenant behaviour, and filtered from day one

Cut #7 said *"keep the `RealmId` column and parameter"*. **It is not there** — measured, `realm`
appears only as a `WWW-Authenticate` parameter. The reasoning that kept the `ExternalLogin` table
applies unchanged: it is *"a migration we would otherwise pay for across every customer database"*.

So the column is added now. Two refinements:

- **It goes only where lookups use a human-chosen key** — `users.username`, `users.email`,
  `external_logins`. Subjects are ULIDs and globally unique, so grants, consents and refresh
  families are already isolated by their subject and need no realm column. This keeps the migration
  small and each column justified.
- **Every lookup filters on it from day one**, with one realm configured. A column that exists and
  is not enforced reads as tenancy and is not — precisely the `A-09` shape. The store contract gains
  a test that two realms may hold the same username and that a lookup in one never returns the
  other's row. That test passes today, with one realm, and is what makes multi-tenancy later a
  configuration change instead of an audit of every query.

Unique index becomes `(realm, username_normalized)`.

### 1.8 Notifications: a seam, plus one SMTP implementation, in separate packages

- `Boltway.Notifications` — `INotificationSender`, `INotificationRenderer`, and typed messages
  (`VerifyEmail`, `ResetPassword`, `PasswordChanged`).
- `Boltway.Notifications.Smtp` — the implementation. **Separate package**, so
  `Boltway.AuthorizationServer` takes no mail dependency and a customer using SES, Postmark or
  their own queue replaces one package rather than forking.

Messages are typed rather than strings so the library never composes a subject line in one
customer's voice — the same decision `IInteractionRenderer` records for the pages.

`PasswordChanged` is a notification, not a request: telling someone their password changed is how
they find out it was not them.

### 1.9 Reset and verification tokens

Single-use, hashed at rest with the existing `Sha256Hash`, and stored in a new small table.

| | |
| --- | --- |
| reset | 15 minutes. The email is the slow part; the token does not need to outlive the walk to the inbox |
| verification | 24 hours |

- Deleted on use.
- **All outstanding reset tokens for a subject are deleted when the password changes**, by any
  route. Otherwise an old link is a second key.
- **`/account/password/forgot` answers identically whether or not the account exists**, and does the
  same work either way, so neither the body nor the timing is an oracle for which addresses are
  registered.

### 1.10 A reset through email revokes sessions; an operator reset does not, unless asked

Different reasons, different defaults:

- Someone resetting their own password through email is usually doing it because they lost control
  of something. **Revoke every refresh family for that subject.**
- An operator resetting for a colleague who forgot theirs is not responding to a compromise, and
  signing that person out of every device is a surprise. `set-password` keeps today's behaviour and
  gains `--revoke-sessions`.

`set-password` already prints *"Sessions and refresh tokens already issued keep working"*. That
sentence stays and the flag is named beside it.

### 1.11 Disable, anonymise; never delete

- **Disable** is reversible and already enforced at both sign-in paths.
- **Anonymise** is irreversible: username and email become a tombstone, the password hash is
  cleared, external links are removed, every refresh family is revoked. The **subject row stays**,
  so audit entries and grant history keep their referent.
- **Delete is not offered.** Erasing a user with outstanding grants leaves dangling references, and
  an audit trail that can be emptied by the person being audited is not an audit trail. Anonymise is
  the erasure that a person is actually owed; it is a different operation and it is named as one.

### 1.12 The admin API validates bearer tokens with `Boltway.ResourceServer`. There is no second validator

Measured: the AS host references `AuthorizationServer`, `Identity`, `Federation.Google`,
`Storage.PostgreSql` and `Storage.Sqlite` — **not `Boltway.ResourceServer`**. It has no bearer
path at all today, because everything it serves is either public metadata or a cookie-authenticated
page. §1.4 changes that, and the first instinct — a `JsonWebTokenHandler` call inside an admin
middleware — is how RFC 9068's rules end up implemented twice with `ValidTypes` pinned in only one
of them. `N-09` is a non-negotiable precisely because the stock configuration gets it wrong.

So the host takes a project reference on `Boltway.ResourceServer` and calls
`AddBoltwayProtectedResource` / `UseBoltwayProtectedResource`, like any other resource
server.

**This does not break the rule that project states most loudly.** Its csproj says *"THERE IS NO
REFERENCE TO Boltway.AuthorizationServer, AND THAT ABSENCE IS THE DESIGN"* — an RS-only
customer must not have a grant store, a key ring and a consent pipeline dragged into their process.
That is a rule about the **package**. A host is a composition root; referencing both is what
composition roots are for, and the direction that must never exist — RS depending on AS — is
untouched.

**The verification keys come from the local `SigningKeyRing`, not over HTTP from the server's own
JWKS.** Fetching your own well-known document through your own edge is a startup dependency on
yourself, and it fails exactly when the edge is already broken. `SigningKeyRing.PublishedKeys()` is
the same set the JWKS endpoint renders, one call away in the same process.

**Wiring it that way exposed a defect that is already shipped, and it is not only the AS host's
problem.** `ProtectedResourceOptions.SigningKeys` is an `IList<SecurityKey>` reached through
`IOptions<T>`, and `AccessTokenValidator` hands that same list instance to
`Rfc9068ValidationParameters.ForAccessToken` on every validation. `JwksRefresher` in
`Boltway.Mcp` kept it current by calling `Add` and `Remove` on it from a background timer,
with no lock and no copy. (That type is gone — `JwksKeySource` replaced it — but the defect below
is what the `SigningKeySource` seam was built to close, so it is recorded as it was found.)

- **Measured:** the mutation and the read touch one `IList<SecurityKey>` instance, from different
  threads, with nothing synchronising them. The refresher never `Clear()`s — it adds, then removes —
  so there is no window where the list is empty.
- **Assumed, from `List<T>`'s documented behaviour rather than from a reproduction:** a validation
  that enumerates the list while a rotation is mutating it can throw *"Collection was modified"*.
  The window is only as wide as an actual key change, which is why this has never been seen; a
  connector under load during a rotation is where it would first appear.

The fix is small, belongs in the library, and serves both callers:

```csharp
// Boltway.ResourceServer.Configuration.ProtectedResourceOptions
public Func<IReadOnlyList<SecurityKey>>? SigningKeySource { get; set; }   // BINDING
```

Read per validation. Default: an immutable snapshot of `SigningKeys`, so no existing consumer
changes. The producer publishes a new list instead of editing one, which is a smaller change than
the lock it would otherwise need — `JwksKeySource` does that now, replacing the `JwksRefresher` this
was originally written against.

**The AS host's source is `SigningKeyRing`, and it needs one small addition to be safe.**
`PublishedKeys()` returns `SigningKeyHandle`s, and a handle's `Key` is the **signing** key — the
private half. Handing those to a validator would work, because verification only touches the public
half, but it would put the private key on the request path of a bearer middleware for no reason.
Measured: no public projection exists — `JsonWebKeySet.ToPublicJwk` is private and the only public
member renders a JSON document. So the key ring gains a `PublicVerificationKeys()` that exports
public-only parameters, the JWKS endpoint keeps using `Render`, and the private key stays where it
is minted. It is the same discipline as `N-16`'s test that the JWKS body contains none of `d`, `p`,
`q` — applied to an object graph rather than to a response body.

Without it, the admin API stops accepting tokens at the first key rotation — a scheduled event this
server performs on **itself**, so the failure is certain rather than possible, and it arrives hours
after the change that caused it.

`ScopesSupported` on those options lists `users:read`, `users:write` and `users:self`. The deploy's
`verify.sh` already asserts that every scope named in a 401 challenge is advertised by the
authorization server, so a scope added on one side and forgotten on the other fails a deploy rather
than a client.

### 1.13 One `UserAdministration` service. The CLI and the HTTP handlers are two callers of it

Measured: the verbs are inline in the host's `Program.cs` — `if (args is [ "set-password", var who,
..])` and its two neighbours, each reaching `IUserStore` directly.

When §1.4's endpoints arrive, `set-password <handle>` and `POST /admin/users/{subject}/password`
become two implementations of one operation. The one that drifts is the one nobody tests, and the
first thing to drift is §1.5's audit write — on the operator path, which is the one used at 2am
during an incident, and therefore the one where a missing line costs the most.

So the verbs move out of `Program.cs` into `UserAdministration`, an application service in
`Boltway.AuthorizationServer`; `Program.cs` keeps argument parsing and printing. Three rules
live in the service rather than in either caller:

- **The password is generated, never accepted.** `set-password` already refuses to take one. Putting
  the generation inside the service means an HTTP handler cannot add a `password` field without
  deleting a line the CLI depends on — the change becomes visible instead of additive.
- **The audit entry is written by the service, in the same transaction as the change** (§1.5).
  Neither caller can forget it, because neither caller writes it.
- **The actor is passed in, and the CLI's is honestly null.** `actorSubject` null, `actor_kind =
  cli`. Inventing a subject for a shell — or reusing the target's — is worse than recording the true
  and useful fact, which is that someone with shell access did it.

This is the connector's rule from the other side: *"Any rule that exists on one surface and not the
other is not a rule."* Two implementations of one contract there agreed for about a month. There is
no reason to expect this pair to do better.

### 1.14 What an MCP client may reach, and what must never be shared with a document connector

The question this answers: with an HTTP API in the design, can the API and the MCP tool calls share
authentication, tokens and services?

**Tokens: no — and that is `N-01`, not a preference.** The admin API is its own resource (§1.4), a
document connector is another, and `resource` → `aud` binding means a token minted for one is
rejected by the other.

What makes it concrete rather than theoretical is what the connector on the other side of this is
for. A document connector of the kind this is built for ingests third-party documents **verbatim**,
deliberately — summarising a source away is what makes a claim uncheckable — and a model reads them.
That is attacker-authored text sharing a context with the caller's token. If that same token also opened the directory, a sentence inside an
ingested PDF would be a privilege-escalation primitive with the user directory as its payload.
Audience binding is what makes that sentence inert, and it is the reason the admin API can never be
a tool on the document connector.

**Sign-in, the authorization server and the account: shared.** One person, one password, one disabled
flag. Two directories is how one of them keeps serving an account the other disabled.

**The bearer-validation code: shared** — §1.12, the same `Boltway.ResourceServer` in both
processes, so the two cannot come to disagree about `typ`, `alg` or `aud`.

**The application service: shared, but only downstream of authorization.** If account tools are ever
exposed over MCP they call the same `UserAdministration`, for §1.13's reasons. What is not shared is
the *entry*: resource identifier, scope check and consent are per surface, and they are the part
that decides whether the caller may act at all.

**So account management over MCP is possible — as a separate connector**, with its own resource
identifier, its own consent screen and its own token. Never a tool sitting beside the document tools
on one token. Nothing in this design ships one; the shape is recorded so that the answer to "can we just
add a tool for it" is already worked out, and is no.

Measured on the Northwind side, because it decides where the admin API is deployed rather than only how
it is designed: the connector has **no user data at all** — `src/` contains no `IUserStore`, no
`UserAccount`, no `IPasswordHasher` and no database connection string, and its only dependencies are
`Boltway.Mcp` and the MCP SDK. The admin API belongs in the authorization server because that
is where the directory already lives. Putting it in the connector would mean handing a database
connection to the one process whose job is to ingest strangers' documents.

---

## 2. Interfaces

Binding where marked. The rest is settled at implementation.

```csharp
// ── extended, Boltway.AuthorizationServer.Abstractions ───────────────────
public interface IUserStore                                              // BINDING
{
    // existing, gaining a realm on the human-keyed lookups
    Task<UserAccount?> FindByUsernameAsync(RealmId realm, string username, CancellationToken ct);

    Task<bool> SetEnabledAsync(SubjectId subject, bool enabled, CancellationToken ct);
    Task<bool> SetEmailAsync(SubjectId subject, string? email, bool verified, CancellationToken ct);
    Task<bool> AnonymiseAsync(SubjectId subject, CancellationToken ct);

    // Keyset, never OFFSET: subjects are ULIDs and therefore ordered by creation, so
    // `after` is a cursor that cannot degrade into a scan as the table grows.
    Task<IReadOnlyList<UserAccount>> ListAsync(
        RealmId realm, SubjectId? after, int limit, CancellationToken ct);
}

// Both additions landed on IGrantStore rather than here, and the reason is worth keeping: the
// link already existed in the schema — refresh rows carry a grant id, grants carry the subject —
// so what was missing was a method, not a column. Denormalising the subject onto refresh rows
// would have been a second copy of a fact, kept in step by nothing. `RefreshFamilySummary` was
// never needed and does not exist.
public interface IGrantStore                                             // BINDING (additions)
{
    // Revokes rather than enumerating: the moment this is called is the moment somebody is
    // responding to a compromise, and read-then-revoke-each leaves a window. Step 7.
    Task<int> RevokeAllForSubjectAsync(SubjectId subject, DateTimeOffset now, CancellationToken ct);

    // The read, added separately in step 8 because a *view* is E-35's whole requirement and a view
    // has no window to leave. Active grants only — a revoked grant is not a session, and rows are
    // never deleted on revocation.
    Task<IReadOnlyList<GrantRecord>> ListForSubjectAsync(SubjectId subject, CancellationToken ct);
}

public interface IConsentStore                                           // BINDING (addition)
{
    Task<IReadOnlyList<ConsentRecord>> ListAsync(SubjectId subject, CancellationToken ct);
}

// ── new ──────────────────────────────────────────────────────────────────────
public interface IScopeEntitlementPolicy                                 // BINDING
{
    ValueTask<ScopeSet> FilterAsync(UserAccount user, ScopeSet requested, CancellationToken ct);
}

public interface IAdminAuditStore { /* §1.5 */ }                         // BINDING

public interface INotificationSender
{
    Task SendAsync(NotificationMessage message, CancellationToken ct);
}

// The one implementation of each administrative operation. The CLI verbs and the `/admin/*`
// handlers are both callers; neither contains the rule, the audit write, or the generator. §1.13.
public sealed class UserAdministration                                   // BINDING (shape)
{
    Task<GeneratedPassword> ResetPasswordAsync(Actor actor, SubjectId target, ResetOptions o, CancellationToken ct);
    Task<bool> SetEnabledAsync(Actor actor, SubjectId target, bool enabled, CancellationToken ct);
    // …one method per §3 mutation. `Actor` carries a nullable subject and a kind: cli | client.
}

// ── Boltway.ResourceServer, one added option ─────────────────────────────
// Read per validation, so a key ring that rotates under a live process is a supported
// configuration rather than a race. Defaults to a snapshot of `SigningKeys`. §1.12.
public sealed class ProtectedResourceOptions
{
    public Func<IReadOnlyList<SecurityKey>>? SigningKeySource { get; set; }   // BINDING
}

// ── Boltway.OAuth.Tokens ────────────────────────────────────────────────
// The public halves of the published keys, so an in-process resource server never holds a
// signing key it only needs to verify with. `Render` keeps producing the JWKS document. §1.12.
public sealed class SigningKeyRing
{
    public IReadOnlyList<SecurityKey> PublicVerificationKeys();
}
```

`RealmId` is a wrapped string with a configured default, following `SubjectId`'s shape so it needs
no sanitising as a column value or a cache key.

---

## 3. Endpoints

| method | path | scope | id |
| --- | --- | --- | --- |
| `GET` | `/admin/users` | `users:read` | `E-25` |
| `GET` | `/admin/users/{subject}` | `users:read` | `E-26` |
| `POST` | `/admin/users` | `users:write` | `E-27` |
| `PATCH` | `/admin/users/{subject}` | `users:write` | `E-28` |
| `POST` | `/admin/users/{subject}/password` | `users:write` | `E-29` |
| `DELETE` | `/admin/users/{subject}/sessions` | `users:write` | `E-30` |
| `POST` | `/admin/users/{subject}/anonymise` | `users:write` | `E-31` |

> **Built: all of `E-25`–`E-32`**, keyed on the handle rather than the subject — both callers start
> from what somebody typed, and the realm comes from configuration.
>
> **`E-30` and `E-31` were blocked on one measured fact and are not any more.** Nothing could
> enumerate a subject's sessions: `IRefreshTokenStore` revoked a family by id, `IGrantStore` revoked
> a grant by id, and neither could be asked what a person holds. The join existed in the schema —
> refresh rows carry a grant id, grants carry the subject — so what was missing was a method, and
> the choice was between putting it on `IGrantStore` by subject or denormalising a subject column
> onto the refresh rows. **The grant side won**: the second copy of a fact is kept in step by
> nothing.
>
> It is `IGrantStore.RevokeAllForSubjectAsync`, and it **revokes** rather than enumerating, which is
> the security-relevant half. Reading the grants and revoking them one at a time leaves a window in
> which a grant created in between survives — and the moment this is called is the moment somebody
> is responding to a compromise. One statement has no such window. Enumeration was owed to `E-35`
> (`/account/sessions`), where a *view* is the requirement; it is `ListForSubjectAsync`, additive on
> the same interface as predicted, and step 8 added it.
>
> **What it reaches, exactly.** Refresh chains die immediately: the refresh handler loads the grant
> and refuses when it is not active. Access tokens already issued **keep working until they
> expire** — they are signed rather than looked up, and `IsRevokedAsync`, which exists for a
> resource server to consult, is called by nothing in this repository. So the responses carry counts
> and never a `signed_out` flag, and the CLI says the same sentence `disable` already says. Closing
> that gap is a resource-server change and a separate decision (introspection, a shared denylist, or
> short token lifetimes); pretending it is closed would be the confidence rule broken exactly where
> an operator is acting on it.
>
> **`E-31` is `POST .../anonymise`, not `DELETE .../users/{handle}`.** The row stays. Sessions are
> revoked first and the account rewritten second, because these are two writes and nothing here can
> make them one: dying in between this way leaves an ordinary account whose owner has been signed
> out, and the other way leaves a tombstone whose refresh tokens still mint.
| `GET` | `/admin/audit` | `users:read` | `E-32` |
| `GET` | `/account` | `users:self` | `E-33` |
| `POST` | `/account/password` | `users:self` | `E-34` |
| `GET` | `/account/sessions` | `users:self` | `E-35` |
| `DELETE` | `/account/sessions/{grant}` | `users:self` | `E-36` |
| `GET` | `/account/consents` | `users:self` | `E-37` |
| `DELETE` | `/account/consents/{clientId}` | `users:self` | `E-38` |
| `POST` | `/account/password/forgot` | public | `E-39` |
| `POST` | `/account/password/reset` | public | `E-40` |
| `POST` | `/account/email/verify` | public | `E-41` |

> **Built: `E-33`–`E-41`,** with the pages §7.3 names — on their own they are a design that mails
> somebody a URL answering 405.
>
> **No handler takes an identifier**, which is §1.6 made mechanical rather than argued. Every one
> reads its subject out of the token, so there is no parameter a request could fill with somebody
> else's account and no guard that could later acquire an exception. The two that do take a path
> value — a grant id and a client id — check ownership before acting, and answer 404 rather than 403
> when it fails: a 403 confirms the id exists, which turns the endpoint into a way to enumerate the
> deployment's grants.
>
> **`E-36` is keyed on the grant, not the refresh family.** The table said `{family}`. A family is
> descended from a grant, revoking the grant ends every family under it, and the grant id is what
> `E-35` returns — so it is both the thing a person means by "this session" and the only one of the
> two they can see.
>
> **`E-38` uses a catch-all path segment.** A client id here is often a URL —
> `https://claude.ai/oauth/mcp-oauth-client-metadata` — because this server supports client ID
> metadata documents. `{clientId}` matches none of it, and asking callers to percent-encode the
> slashes makes the answer depend on whether the proxy in front normalises `%2F`, which this
> repository cannot promise about somebody else's deployment.
>
> Its page equivalent, `/me/consents`, does **not** put the id in the path: a page has a form, so the
> id rides in a field. That is not only tidiness — `{**clientId}` under `/me/` would swallow every
> `/me/` page added after it.
>
> **`E-38` withdraws the approval and does not end the sessions**, and the response says so rather
> than leaving it to be discovered. "Ask me again next time" is not "sign me out"; doing the second
> quietly would make the button lie about what it did.

Every one of them is **routed or absent**, never advertised-and-404 — `N-06`, and the reason the
"deliberately not implemented" list in the README is as long as it is. For `/account/*` that is
`SelfServiceEnabled`, reachable from the deployable host as `SELF_SERVICE`; turning it on also
advertises `users:self`, and startup refuses the combination where one happens without the other.

`POST /account/password` requires the current password. A bearer token is not enough: the point of
asking is that a stolen token alone should not become a permanent credential.

### 3.1 The three public endpoints are an outbound spam vector

`E-39` sends mail to an address chosen by the caller. It is bounded per account and per source,
reusing `LoginThrottle`'s shape and its reasoning about lockout length being a denial-of-service
tool if it is long.

**And every limit in this server is per process** — `X-31`, restated here because it is easy to read
a throttle as a guarantee. A fleet of *n* replicas will send *n* times each number. Put a shared
limiter in front, or accept the multiple knowingly.

---

## 4. What this design does not do

Stated, so that the next person does not have to work out whether it was considered.

- **No role vocabulary, no groups, no permission model.** Scopes are the authorization currency and
  the role stays an opaque string. A customer who needs groups builds them behind
  `IScopeEntitlementPolicy`, which is the seam that exists for it.
- **No MFA.** Deferred with the cost named, and the cost is genuinely lower than `RealmId`'s: a
  second factor needs a **new table**, and a new empty table is a cheap migration, where a `NOT
  NULL` column on a populated `users` table is not. That asymmetry is why one is in this design and
  the other is not.
- **No SCIM.** A directory-sync protocol is a product, not a feature, and nobody has asked.
- **No impersonation.** "Sign in as this user" defeats the audit trail this design just added, and
  every incident where it mattered would be the one where the log is ambiguous.
- **No password composition rules** beyond a length floor. The defences are Argon2id and the
  throttle; a composition rule is how a directory fills up with `Password1!`.
- **No email change without re-verification.** Changing the address and keeping `email_verified`
  true would make the claim mean nothing.
- **No MCP tools for account management.** Shipping none is a scope decision; the rule that one
  could never live beside document tools on a shared token is not, and §1.14 is where it is written down.

---

## 5. Build order

One list. §7 used to carry a second one, and two orderings of the same work in one document is the
defect this whole design keeps writing about.

Each step leaves the server working and is independently shippable. **Steps 0.1–0.5 are not part of
this design** — they are defects in what already ships, they are smaller than anything below them,
and three of the five are rules the code already documents and does not enforce.

> **Every step in this build order is built.** Phase 0, phase 1 and steps 6–11.
>
> The one thing still standing narrower than written: the audit entry is recorded immediately after
> the change rather than in the same transaction, because no two relational stores here can share
> one today (`IAdminAuditStore.RecordAsync`, and `S-45` in the spec).
>
> **Six surfaces turned out to be unreachable from the deployable image**, found one at a time and
> each by running the thing rather than by reading it: `/logout`, `/admin/*`, `/account/*`, `/me/*`,
> the sign-in page's route into password recovery — `E-39` answers JSON, so the missing piece was a
> `/forgot` page rather than a missing `<a>` — and, the one that made the admin API useless rather
> than merely absent, bearer validation for the two API surfaces. Worth keeping as a class: *a flag
> added to the library is half a feature until a deployment can reach it, and the only way to know is
> to run it.*
>
> The seventh and eighth are the same rule pointing the other way, and they are why "run it" has to
> mean more than one configuration. The host added `UseBoltwayProtectedResource()` unconditionally while
> registering its options only under `ADMIN_API || SELF_SERVICE`, so a deployment turning on **only**
> the cookie surfaces — `SELF_SERVICE_PAGES` and `PASSWORD_RECOVERY`, which need no bearer validation
> at all — refused to start, naming an internal type and nothing an operator could act on. Every
> probe until then had happened to set one of those two flags. The middleware and its registration
> now read one variable.
>
> And the eighth: with the admin resource in `RESOURCES` but both bearer surfaces off, the metadata
> advertised `users:read users:write`, `/authorize` showed a consent screen for them, `/token`
> minted a signed token with that audience — and every call it could make answered 404. The fix
> that stuck was not a check but a deletion: `ADMIN_API=true` now derives the resource URL,
> registers it with exactly the scopes that flag serves, and ships descriptions for them, so there
> is no second place to state any of it and no state in which the two disagree. Four settings and
> an ssh ceremony became one flag. **A validation that a configuration matches something the
> program already computed is a design defect wearing a check's clothes.**
>
> One thing still stands narrower than written: the audit entry is recorded immediately after the
> change rather than in the same transaction, because no two relational stores here can share one
> today (`IAdminAuditStore.RecordAsync`, and `S-45` in the spec).
>
> `UiLocalesSupported` was on that list and is not any more. It landed refusing more than one locale
> rather than being generated — generation needed the localization step to generate from — and step
> 6 supplied it: `InteractionLocalization.SupportedCultures` is now the one function that answers
> "which languages is this", with both the middleware and `UiLocalesSupported` derived from it.
>
> **Both surfaces were also unreachable from the deployable host**, which is a defect of the
> endpoints' *deployment* rather than of the endpoints. `AdministrationEnabled` and
> `SelfServiceEnabled` are library flags, and nothing in the image set them or offered a setting
> that could. They are `ADMIN_API` and `SELF_SERVICE` now. Found while looking for a second instance
> of the same shape after `END_SESSION` turned out to be the first — worth remembering as a class:
> *a flag added to the library is half a feature until a deployment can reach it.*

### Phase 0 — what is already broken

| | | why it is first |
| --- | --- | --- |
| ✅ 0.1 | **Sign-out** (`E-45`, `S-56`) | No `Logout` endpoint and no `SignOutAsync` call exists. A person on a shared machine cannot end their session. One endpoint |
| ✅ 0.2 | **`SigningKeySource`** + `SigningKeyRing.PublicVerificationKeys()` (`S-52`, §1.12) | Closes a shipped race: `JwksRefresher` (since replaced by `JwksKeySource`) mutated the list the validator enumerates. Also the prerequisite for the AS validating its own tokens in step 7 |
| ✅ 0.3 | **`/error` behind `IInteractionRenderer`** (`S-55`) | Two of three pages are themeable and nobody is told which |
| ✅ 0.4 | **`UiLocalesSupported` generated** (`S-57`, §7.5.1) | A deployment can advertise `vi` today and serve English. The property's own comment forbids exactly that |
| ✅ 0.5 | **Publish `Boltway.Interaction.Testing`** (`S-59`, §7.6) | The contract is `IsPackable` and unpublished, so the suite written for customers cannot be obtained by one |

### Phase 1 — the foundations, in the only order that works

1. ✅ **`RealmId`** — column, filtering, contract test for cross-realm isolation. First because it is
   the only step that touches every existing query, and doing it under new features is how one gets
   missed.
2. ✅ **`UserAdministration`**, with the three existing CLI verbs moved onto it and behaviour unchanged
   (§1.13). Before any new operation, so nothing is written twice and then reconciled.
3. ✅ **`SetEnabledAsync`, `SetEmailAsync`** and their CLI verbs. Closes the two measured holes: a rule
   that cannot be applied and a claim that cannot be made true.
4. ⚠️ **`IAdminAuditStore`**, before any HTTP surface. An admin API that predates its audit log has a
   window nobody can reconstruct.
5. ✅ **`IScopeEntitlementPolicy`** with the permissive default, and the Northwind policy. Before the
   endpoints, so `users:write` is never issuable to everyone, not even for an afternoon.

### Phase 2 — the surfaces

6. ✅ **Localization** (§7.5): `IStringLocalizer`, the neutral resx, `UseRequestLocalization` with the
   `ui_locales` provider. Before the new pages rather than after, so each one is written against the
   localizer instead of being retrofitted — and it is what makes every rung of §7.6's ladder
   multilingual.
7. ✅ **`/admin/*`**, with the cookie-refusal architecture test written first, on its own hostname
   (§1.4) and behind `UseBoltwayProtectedResource` (§1.12). All of `E-25`–`E-32`; the two that
   were blocked on a store method have one now, and §3 says what it reaches and what it does not.
8. ✅ **`/account/*`**, plus the store reads it needs — which turned out to be two, not three:
   `IGrantStore.ListForSubjectAsync` and `IConsentStore.ListAsync`. The third,
   `IUserStore.FindBySubjectAsync`, was already there. `E-34` also needed a service method, and it
   is the one place `UserAdministration` accepts a password — §2 below says why that does not
   reopen what the no-password rule was protecting.
9. ✅ **`/me/*`** (`E-46`, §7.2) — the self-service pages, cookie plus antiforgery, on the service
   from step 2. Three pages, three default interface members on `IInteractionRenderer`, and 27 more
   `InteractionText` keys — 27 to 55. Two things the design did not predict, both recorded where they bit:
   `/login`'s `returnUrl` check had to become a closed list rather than one path, and the password
   page has to sign the browser out itself when somebody asks to be signed out everywhere —
   revoking grants does not touch a cookie.

   ✅ **`/me/consents` is the fourth page**, added after step 11. §7.2 named three paths and shipped
   three, leaving withdrawal in a browser impossible — the gap was named in `auth/README.md` rather
   than closed by inventing a path, and this is closing it rather than renaming it.

   It describes each approval with the deployment's `ScopeDescriptions`, not with the wire scope: a
   person agreed to "Read the knowledge base" and does not recognise `docs:read` as the same decision.
   That makes `A-14` reachable in a way it is not on the consent page — a description can be removed
   from configuration *after* the approval that used it — so an undescribed scope renders raw with a
   warning here too.

   Withdrawal needs no ownership check, unlike `/me/sessions`: `IConsentStore.RevokeAsync` is keyed
   on `(subject, client)` and the subject is the session's, so the id in the form cannot reach
   another account's record however it is spelled. A grant id is a global key, which is why that
   handler has to load and compare and this one does not.

   With it, `/forgot` and the error page's five reader sentences, `InteractionText` holds **87** keys.
10. ✅ **Notifications** and the two public flows, with their pages (`E-42`–`E-44`, §7.3). The pages
    and the endpoints ship together, so a mail link lands on a page rather than on a `405`.
    `Boltway.Notifications` and `Boltway.Notifications.Smtp` are two packages as §1.8
    asked; `IUserTokenStore` is the new table, with a migration on both providers.

    Three things the design did not predict, all found by running it: `IUserStore` has no lookup by
    email, so `S-48`'s "same work either way" is bought by walking the realm on a rate-limited
    endpoint and that is stated where it is done; the reset **page** cannot tell a live link from a
    dead one without consuming it, so a dead link is refused on submit rather than on arrival; and
    the "sessions ended" sentence needed its newline moved into the sentence, because zero is the
    ordinary case and the template left a blank line in every message.
11. ✅ **The admin BFF** (§7.1). Last, because it cannot be built before the API it calls and should
    not be built before the audit log that records what it does. `hosts/Boltway.AdminBff`,
    which references nothing on the server side — the contract between them is HTTP.

    **§7.1 said "it uses the client store and `client_secret_basic` that already exist". They did
    not.** `IClientResolver`, `IClientSecretStore` and the auth method were all shipped and the only
    resolver in `src/` was the CIMD one, so a confidential client could not be registered at all.
    `ConfiguredClientResolver` and `CLIENTS` are that, and they sit beside CIMD rather than
    replacing it: a deployment serves Claude, which names itself by a metadata URL, and its own
    admin UI, which cannot.

    **And `/admin/*` had never worked from the deployable image.** §1.12 says the surfaces validate
    bearer tokens with `Boltway.ResourceServer`, and nothing in the host wired it — so
    `AdminAuthorization.Check` read a `HttpContext.User` that no bearer had ever populated and
    answered "Unauthenticated" to every token. The library half was a defect too:
    `BearerAuthenticationMiddleware` skipped any `AllowAnonymous` endpoint entirely, and those
    routes are `AllowAnonymous` on purpose. Anonymous means credentials are not *required*, not that
    they are ignored, so it now validates a presented token and challenges nothing.

    Three smaller things the design did not predict: a client secret cannot be a passphrase — the
    authenticator parses it as an `OpaqueSecret` before hashing, so the host gained
    `new-client-secret`; the .NET OIDC handler puts the secret in the body and this package version
    has no switch, so the BFF redeems its own code to send Basic; and it asks for `response_mode=query`
    because that is what the server advertises.

**The deployment's own work sits beside this, not inside it**, and both halves are done. ✅ All 87 strings
in `deploy/ui/translations.json`, supplied through `UI_TRANSLATIONS_FILE` — no
`IStringLocalizerFactory` of its own was needed, because the dictionary implementation step 6 ships
is the seam filled rather than replaced. It started at 27 and grew with the pages; the interval in
between is what the per-string fallback is for, and it was visible as English sentences on a
Vietnamese page rather than as a failure. ✅ `ToolMessages` in the connector, 23 sentences,
English by choice: they go to the model, which answers the person in their own language either way.

One line on a Northwind page stays English, and it is now a deliberate one rather than a gap. The
`/error` page's description is the OAuth `error_description`, which **cannot** be translated: OAuth
2.1 §4.1.2.1 restricts it to `%x20-21 / %x23-5B / %x5D-7E` and `ErrorText.Safe` enforces that by
dropping everything else, so a Vietnamese sentence there arrives as its ASCII fragments. `A-12` also
requires it on the page, so that `curl -D-` debugs a client integration without a log in.

**What was wrong was treating it as the sentence a person reads.** It is written for whoever is
integrating the client. The page now carries two: `ErrorViewModel.Guidance`, localized and chosen by
what the reader can do about this class of refusal, above the reference id; and `Description`, the
unchanged English, below a rule and a translated label, in `<p lang="en">`. Twenty-six reason codes
reach that page and there are five things a person can do about any of them — start again, wait,
tell whoever runs the application, ask an administrator, or nothing because they declined — so
`InteractionText.ErrorSentenceFor` maps by remedy rather than by cause. An unmapped reason gets
"not your fault, here is the reference", which is the one guess that cannot blame somebody for a bug.

The precision is not lost, it moves: `RejectionLog` now carries `Description` as its own property on
both servers, so the exact English is on the line the correlation id joins to, along with the reason,
the requirement id and the private detail the page never shows. Removing it from the page without
that would have destroyed the only copy an operator could reach — `A-09`'s whole promise — and the
paired property-set tests in both suites are what forced the two declarations to move together.

**There were two, and the other was ours.** `/me/sessions` rendered the raw wire scope while
`/me/consents` rendered `ScopeDescriptions`, so one authorization read
`email docs:read docs:write openid` on one page and as sentences on another a click away. Fixed rather
than recorded: `SessionLine` now carries the same described scopes and resources `ConsentLine` does,
both pages draw them through one method in the renderer, and all three pages that describe scopes —
consent, sessions, approvals — get them from `ConsentModelBuilder.Describe`, which is where `A-14`
is now decided. It cost a source-breaking change to a public record, which is the right price: the
alternative was a fourth page one day describing permissions a fourth way.

Worth keeping as its own class, separate from the unreachable-surface one above: *the same fact
shown on two screens will be shown two ways unless one function produces it.* Every test passed
while this was wrong, because none of them compared the two pages — the assertion that catches it is
differential, and it is in `MeSurfaceTests` now.

---

## 6. Cut list

If this halves:

1. **`/admin/audit` as an endpoint** — keep the store and read it with SQL. The record is what
   matters; the view is convenience.
2. **`E-41` email verification** — `email_verified` stays false and honest.
3. **Anonymise** — disable covers the operational need; erasure is a promise nobody has made yet.
4. **The SMTP implementation** — ship the seam, let the first customer who needs it write one.
5. **The separate admin hostname** — `N-17` and its architecture test are the requirement; the
   hostname is the deployment that makes them structural. Cutting it costs one layer of two.

**Never cut:** the cookie refusal (`N-17`), the audit write being in the same transaction, the
entitlement filter running at token issuance as well as at `/authorize`, the realm filter, and the
admin API being its own resource with its own audience (§1.4, §1.14). Each of those is a guarantee
that is not recoverable by adding it later — the audience one because every token already minted
would be valid somewhere it was never meant to reach, the realm one because it is a migration across
every customer database, and the rest because the window they leave open is silent.

**And one that is not on either list, because it is not part of this design to trade away:** a
single `UserAdministration` (§1.13). Halving the scope means fewer operations, not two
implementations of the ones that remain.

---

## 7. UI

Everything above is endpoints and stores. None of it is reachable by a person without pages, and the
page layer is where `N-17` turns out to have a consequence that needs deciding rather than
restating.

### 7.0 What exists, measured — and two gaps found while measuring

| | |
| --- | --- |
| Pages | `/login`, `/consent`, `/error` |
| Seam | `IInteractionRenderer` (`RenderLogin`, `RenderConsent`), `IInteractionLayout`, both public |
| Default | `DefaultInteractionRenderer`, 272 lines, `public` so a customer can wrap rather than replace |
| Styling | one 212-line stylesheet in the host's `wwwroot` |
| JavaScript | **none.** Not one `.js` file in `auth/` |
| CSP, every page | `default-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'`, with an opt-in nonce |
| Antiforgery | on the login and consent POSTs |

Two things turned up that are not part of this design and are worth more than most of it:

- **There is no sign-out.** Measured: no `Logout` endpoint and no `SignOutAsync` call anywhere in
  `src`. A session cookie ends when it expires or when the browser closes, and a person on a
  shared machine has no way to end it deliberately. `N-15`'s own acceptance criteria lists `/logout`
  among the pages whose headers must be asserted — a test named against a page that does not exist,
  which is the `DESIGN.md` §7 shape again. It costs one endpoint and it belongs before any of this.
- **`/error` is not behind `IInteractionRenderer`.** Login and consent go through the seam; the
  error page renders through `AuthorizeResults.Html`. So a customer who implements the renderer
  restyles two pages out of three and discovers the third from a screenshot. A rule that exists on
  one surface and not the other is not a rule.

### 7.1 The admin UI cannot be a page on the authorization server, and that decides its shape

`N-17` is bearer-only, so there is no cookie-authenticated admin page. The admin UI is therefore an
**OAuth client**, and there are two shapes for one:

| | token lives | cost |
| --- | --- | --- |
| SPA — public client, PKCE | in the browser | one XSS from exfiltration; needs CORS on the admin API and a `connect-src` widening on the UI's CSP |
| **BFF — confidential client** | server side, never sent to the browser | one more small deployable |

**Take the BFF**, for the reason §1.1 gives: what is behind this API is the directory, not a
document. *OAuth 2.0 for Browser-Based Apps* reaches the same recommendation for the same class of
application, and it is one of the few places where the safer option is also the smaller one here —
a BFF that renders forms server-side keeps `auth/`'s zero-JavaScript property, reuses the existing
stylesheet, and needs neither CORS nor a CSP exception.

`N-17` is untouched by it. The browser's cookie is scoped to the BFF's own hostname and its own
session; the admin API only ever sees a bearer token, which is exactly what the rule says.

The BFF is a **confidential** client — it has a secret and is not a browser app — so it uses the
client store and `client_secret_basic` that already exist. It will show its own consent screen to
the founder once, which reads oddly and is correct: consent is what binds `users:write` to a person
who is entitled to it (§1.3), and an admin UI that skipped it would be the one client exempt from
the check.

### 7.2 Self-service pages and the self-service API are different surfaces, and `N-17` has to say which

Taken literally, `N-17` covers `/account/*` as well, which would mean a founder changing their own
password needs an OAuth client to do it. That is absurd, and the way out is **not** to soften the
rule.

`/account/*` stays exactly as designed: bearer-only, no cookie path, for programmatic callers. The
pages are **different paths** — `/me`, `/me/password`, `/me/sessions`, `/me/consents` —
cookie-authenticated interaction pages like `/consent`, with antiforgery, calling
`UserAdministration` and the stores **in process** (§1.13) rather than calling their own API over
HTTP.

Why that is a different rule rather than a hole in this one: `N-17` exists because an XSS on the
login page would otherwise reach `users:write`, and `users:write` is everyone. These pages reach
exactly one account — the one already signed in — and `S-49` makes a password change require the
current password, which an XSS does not have. Different blast radius, different rule, and both are
written down.

The architecture test stays mechanical because the prefixes are disjoint: **nothing under `/admin/`
or `/account/` may carry a cookie scheme; nothing under `/me/` may carry bearer.** Two assertions,
no judgement — plus a third asserting the disjointness itself, because both scans sort by prefix and
a path matching two of them would be governed by whichever test ran first.

> **Built, and two things this section did not predict.**
>
> **`/login`'s `returnUrl` check had to widen.** It accepted exactly one path — `/authorize` — so a
> person sent from `/me` to sign in was refused at the page they had just been sent to. It now takes
> `AuthorizationServerPaths.LoginReturnTargets`, a compile-time list. A closed set rather than "any
> local path", which would have handed the sign-in page's redirect to whatever page exists next.
>
> Adding a page therefore means adding it to that list, and forgetting is invisible until a session
> expires. `MeSurfaceTests` reads the routing table for `GET`s under `/me` and asserts each is on it,
> so the forgetting is a failing test rather than a refusal in front of a person whose session just
> ran out.
>
> **"Sign me out everywhere" needs an explicit sign-out.** The obvious implementation calls
> `ChangePasswordAsync` with `revokeSessions` and stops, and it is wrong in a way nothing would
> report: revoking grants ends OAuth sessions and does not touch the browser's cookie, so the person
> who ticked the box stays signed in on the page they ticked it on. Grants and cookie sessions are
> different things, and the page ends both.

### 7.3 The email flows need pages, which §1.9 implied and did not name

A link in an email lands on a **page**. `E-40` and `E-41` are the APIs behind them, and on their own
they are a design that mails somebody a URL that answers `405`.

| method | path | id | |
| --- | --- | --- | --- |
| `GET` | `/reset?token=…` | `E-42` | the form. Public |
| `POST` | `/reset` | `E-43` | sets the password, then redirects to `/login` |
| `GET` | `/verify-email?token=…` | `E-44` | landing page. Public |
| `GET` | `/logout` · `POST /logout` | `E-45` | §7.0. Not part of user management; blocked on nothing |

An expired or unknown token says so plainly. That is not the oracle `S-48` is about: a reset token
is 256 bits of CSPRNG output and there is nothing to enumerate, while a person who is not told their
link expired will click it again rather than ask for a new one.

> **The same argument reaches the other end of the flow, which this table missed.** `E-39` is where
> a person *asks* for the link, and it answers JSON — so the sign-in page had nothing to link to,
> and a deployment turning recovery on had to tell people a URL by hand. `GET`/`POST /forgot` is
> that page, public and top-level like `/reset`, and `/login` links to it **only when
> `PasswordRecoveryEnabled`**, because the route is absent otherwise.
>
> It calls `AccountRecovery` in process rather than posting to `E-39`, for the reason §1.13 gives
> and one more: `E-39`'s value is that it answers identically every time, and content-negotiating it
> would put a branch on the one surface whose whole design is not to have one. `S-48` and the
> throttle therefore have to hold on a second code path, and `RecoverySurfaceTests` asserts both —
> byte-identical answers for a known and an unknown account, and the fourth request in a window
> refused rather than told a link is on its way.

### 7.4 Adding pages to the renderer is a breaking change unless it is done deliberately

`IInteractionRenderer` is public and implemented by customers. Widening it breaks every
implementation at compile time; a second interface makes them implement two.

**Use default interface members**, returning the built-in rendering. An existing implementer keeps
compiling, gets the library's pages for anything they have not overridden, and overrides one method
at a time. This is the case default interface members exist for.

Fold `/error` into the seam in the same change (§7.0), because it is the same defect and doing it
separately means saying "some pages" twice.

### 7.5 Localization

This section has now been wrong twice, and the second version was wrong in a way worth keeping on
the page: it invented a mechanism the framework already ships, and the two reasons it gave for
inventing one were both false. Measured, not argued:

| claim made here | measurement |
| --- | --- |
| "a resource lookup falls back to the **key**, so an untranslated string renders `Consent_Allow` to a user" | **False.** With a neutral English `.resx` present, a key missing from `vi` resolves to the English value with `ResourceNotFound=false`. The key is returned only when the name is in *no* resource file at all — a library bug, not a translation gap, and one `ResourceNotFound` reports |
| "satellite assemblies are a packaging story for a library that ships one DLL and no configuration" | **Irrelevant.** `Microsoft.Extensions.Localization`, `.Abstractions` and `Microsoft.AspNetCore.Localization` are all in the ASP.NET Core 10 shared framework, which `Boltway.AuthorizationServer` already references with `FrameworkReference Microsoft.AspNetCore.App`. The standard stack costs **zero** new package references |

Run against .NET 10, `CurrentUICulture = vi`, a neutral resx with `SignIn`/`Password` and a `vi` resx
with only `Password`:

```
Password       value=Mật khẩu     ResourceNotFound=False
SignIn         value=Sign in      ResourceNotFound=False     ← neutral fallback, not the key
NotInAnyResx   value=NotInAnyResx ResourceNotFound=True
```

So: **use the framework.** What follows names a standard component for every part.

#### 7.5.1 The capability is already advertised and does not exist

This part stands, and it is the thing to fix first. Measured:

- `AuthorizationServerOptions.UiLocalesSupported` is a **freely configurable `IList<string>`**,
  copied into the discovery document by `MetadataBuilder` with no check of any kind.
- Its own doc comment says *"Locales with a shipped resource file"* and *"N-06: this is generated
  from what exists, not from what is aspired to."*
- **There is no resource file and nothing reads one**, and **nothing reads the `ui_locales` request
  parameter** — it appears in `src` only as the name of the metadata property.
- `DefaultInteractionLayout` and `RejectionResult` both hardcode `<html lang="en">`.

A deployment can advertise `["vi"]` today and serve English to everyone who asks for it, with the
comment warning against exactly that sitting on the property that permits it.

> **Closed, in two steps.** Phase 0 shipped the half needing nothing: startup refused more than one
> locale, because two was a claim about per-request selection and no such mechanism existed. Step 6
> built the mechanism, so the count check became the real one — **map time compares the advertised
> list against the cultures `RequestLocalizationMiddleware` will actually honour and refuses a
> mismatch in either direction.** That is stronger than generation: it catches an advertised locale
> nobody serves *and* a served locale nobody advertises, and it does not care which of the two
> configuration calls ran first.
>
> One thing had to give, and it was not the security posture. `InvariantGlobalization` is `true`
> repo-wide — *"an authorization server has no business calling unmanaged code"* — and it implies
> `PredefinedCulturesOnly`, so `new CultureInfo("vi")` throws and every test here failed on it.
> `PredefinedCulturesOnly` is now `false` and `InvariantGlobalization` is untouched: culture
> *identity* without culture *data*. Nothing on these pages formats a number, a date or a currency,
> and no comparison in this repository is culture-sensitive, so a culture that carries invariant data
> is exactly enough to be a dictionary key, an `<html lang>` value and something the middleware can
> match `ui_locales` against. ICU stays out of the image.

#### 7.5.2 Text: `IStringLocalizer`, with the library shipping neutral English resources

The standard type, resolved from `IStringLocalizerFactory`, reading `CultureInfo.CurrentUICulture`
— so nothing threads a culture through the renderer and nothing invents a lookup.

- `Boltway.AuthorizationServer` embeds `InteractionStrings.resx`, English, neutral culture. Out
  of the box the server behaves exactly as it does today.
- A missing translation falls back to English, measured above. A missing *name* returns the key and
  sets `ResourceNotFound`, which a **startup check asserts is false for every key** — that is the
  one place the "page shows an identifier" failure can occur, and it is mechanical to close.

**The honest gap, because it is the reason libraries keep reinventing this:** .NET has no
first-class story for an *application* overriding a *library's* resources. Satellite assemblies
belong to the assembly that owns the resx, so a customer cannot add `vi` to ours. Every mature
library solves it the same way and it is the documented seam — **replace `IStringLocalizerFactory`
in DI**. OrchardCore does it with PO files, ABP with its own file system.

So Boltway ships one small `IStringLocalizerFactory` backed by an in-memory dictionary, and
Northwind registers Vietnamese as data. That is a supplied *implementation* of the framework's
interface, not a replacement for it — the distinction the previous version of this section failed to
make.

#### 7.5.3 Culture selection: `RequestLocalizationMiddleware`, with one custom provider

`UseRequestLocalization`, standard, with:

| | |
| --- | --- |
| `SupportedUICultures` | the allowlist. The middleware already matches against it and falls back to `DefaultRequestCulture`, so "never build a `CultureInfo` from a query parameter" is **the framework's behaviour, not a rule this design adds** |
| custom `RequestCultureProvider` | reads OIDC `ui_locales` (Core §3.1.2.1). `CustomRequestCultureProvider` exists for exactly this |
| `CookieRequestCultureProvider` | the framework's own, and how the choice survives `/authorize` → `/login` → `/consent`. Without it the consent page — the one `N-14` requires to be read carefully — reverts to English mid-flow |
| `AcceptLanguageHeaderRequestCultureProvider` | already in the default list |

Order: `ui_locales`, then cookie, then `Accept-Language`. An unsupported `ui_locales` is **not an
error** — OIDC makes it a hint, and refusing would be a client that cannot connect because of a
language.

`<html lang="…">` is `CultureInfo.CurrentUICulture.Name` — the resolved culture, which is what the
middleware produced, so the requested value is never reflected into the document.

#### 7.5.4 `UiLocalesSupported` becomes generated, and the setter goes away

Derived from `RequestLocalizationOptions.SupportedUICultures`, so the discovery document lists what
the middleware will actually honour. That is what the property's comment already claims, which makes
this a change that turns a comment true rather than a new rule.

`/error` comes along in the same change: it hardcodes `lang="en"` and is not behind the renderer
seam (§7.0), so it is both undressable and untranslatable, and one fix closes both.

**Right-to-left is deferred**, with nothing to build for it later: `dir` is a function of the
resolved culture the layout already has.

#### 7.5.5 English is a fallback, which is not the same thing as a language you can ask for

Found by running the real host rather than the test suite, and it looked like a defect for about
ten minutes. With `UI_DEFAULT_LOCALE=vi` and a table holding only `vi`, `/error?ui_locales=en`
returns the Vietnamese page — byte for byte the same page as without the parameter.

Measured, on the host, `UI_TRANSLATIONS_FILE` pointing at a deployment's 27 Vietnamese strings:

```
ui_locales_supported: ["vi"]
/error                 → lang="vi"  Lỗi uỷ quyền
/error?ui_locales=en   → lang="vi"  Lỗi uỷ quyền
```

That is correct and it is §7.5.3 working. `SupportedUICultures` is `[vi]`, `en` matches nothing,
and the middleware falls back to the default exactly as it does for `ja`. **English is the
per-string fallback — the thing that makes a half-translated page readable — and being a fallback
is not being a registered culture.** `ui_locales_supported` is right not to advertise it, because
nothing would honour it.

The way to offer both is to list it, and a culture with an empty table is served entirely from the
fallback. Same host, same file, with `"en": {}` added:

```
ui_locales_supported: ["vi","en"]
/error                        → lang="vi"  Lỗi uỷ quyền
/error?ui_locales=en          → lang="en"  Authorization error
/error?ui_locales=ja          → lang="vi"  Lỗi uỷ quyền
Accept-Language: en-US        → lang="en"  Authorization error
```

`{"en": {}}` is not an incantation and should not become one: the rule is that a culture translates
as many keys as it has and the rest fall back, and an empty table is that rule's zero case. Both
directions are now pinned by tests, because the first one reads as a bug to whoever meets it next.

The last line is the part worth deciding rather than discovering. **Listing a culture puts it in
`Accept-Language` negotiation**, so a Vietnamese deployment that offers English serves English to a
browser that asks for it, default or no default. That is what the header is for and it is the
standard behaviour — and it means the language a founder sees depends on their browser rather than
on the deployment's configuration. Northwind ships `vi` alone for that reason; `deploy/ui/README.md`
states the consequence beside the change that turns it on.

One thing this does **not** cover, and it is visible in the transcripts above: `<p>The authorization
request could not be completed.</p>`. The rejection *description* is not in `InteractionText` — it
is a per-reason sentence written at each rejection site across the whole server, so a Vietnamese
page still has one English line on it. Not a gap in the mechanism; a much larger surface that has
not been brought into it, and `SCOPE_DESCRIPTIONS` is the same shape from the other direction —
deployment text, in the deployment's own configuration, which Northwind now sets in Vietnamese.

### 7.6 How much of the UI a customer takes — a ladder that mostly already exists

"Expose the UI so the layer above customizes it" is not an alternative to a string seam. They are
two rungs of one ladder, and **two of the three rungs are already built and better than what §7.5
proposed to add**. Measured, because §7.5's first version called this seam "a fork wearing a seam's
clothes" without looking:

| rung | seam | state |
| --- | --- | --- |
| 1. words | — | **missing.** §7.5 |
| 2. shell, branding, `<head>` | `IInteractionLayout` | **built.** `TryAddSingleton`, its own tier, plus a `ThemedDefaultInteractionLayout` |
| 3. the whole body | `IInteractionRenderer` | **built**, and guarded — below |

`AuthorizationServerServiceCollectionExtensions` already says why they are two registrations:
*"Replacing `IInteractionLayout` changes the shell around markup the server still renders; replacing
`IInteractionRenderer` replaces…"*.

#### The renderer seam is already safe to hand over, and that was measured rather than assumed

`Boltway.Interaction.Tests` is **`IsPackable=true`** — deliberately, with the reason in the
csproj: *"a contract nobody outside this repository can run is a contract only this repository is
held to."* `InteractionRendererContract` is an abstract class a customer derives from, supplying
their renderer, and it asserts the whole security surface of the page:

- the host of the `client_id`, shown **before** the self-asserted name, qualified rather than bare —
  `N-14`, a MUST in the MCP specification
- the requested redirect host, and the warning when the code goes to the user's own device
- the antiforgery field and return URL on both forms, and the field names the endpoints actually read
- interpolated markup encoded rather than rendered
- **non-ASCII text encoded exactly once** — the bug a Vietnamese page walks into first
- every page rendering within the CSP the server sends

And `ContractCatchesDefectsTests` sabotages the renderer with each known defect and asserts the
contract catches it, then asserts the undamaged renderer passes the whole suite. The contract is
tested, not just written.

**It refuses to assert wording, on purpose**, and its own remarks give the example in Vietnamese:
a renderer saying *"chưa được xác minh"* instead of *"is not verified"* is translated, not broken,
*"and a contract that fails it would be teaching customers to fork the suite"*. The interesting half
is differential: "did it warn about a loopback redirect" is asked by rendering twice with only
`RedirectsToThisDevice` changed and failing if the output is identical. Semantics checked, prose
untouched.

So: **yes, take rung 3 and Northwind owns every word.** What it costs is real and is not the escaping —
that is contract-checked — it is that a renderer is frozen at the model it was written against. Every
page this design adds (§7.2, §7.3) arrives in the library and not in the deployment's renderer, and rung 3
means implementing each one. Rung 1 means getting them in English until someone translates them.

#### What "expose the UI" does not do on its own

**It gives you one language, not many.** A renderer with Vietnamese literals is Vietnamese for
everybody, which is a fine answer for a two-person company and is not what
`ui_locales_supported` advertises. Turning it into more than one language needs the same thing
either way: `UseRequestLocalization` setting `CultureInfo.CurrentUICulture` per request (§7.5.3), at
which point a customer's own renderer reads the ambient culture like anything else in ASP.NET Core
and needs nothing added to the view models.

That is why §7.5 and this section are not competing. The middleware is what makes either rung
multilingual; the string seam is what lets someone be multilingual **without** taking rung 3 — and
without inheriting `N-14`, the antiforgery fields, and every page added later.

#### The one thing to build here — done in phase 0, with a correction

The contract was packable and unpublished. The reason recorded here was *"zero tags exist, so
`publish-packages.yml` has never run"*, and the inference was wrong in the way `LESSONS.md` #9 is
about: that workflow had a `workflow_dispatch` trigger and had run four times, and the absence of
tags was evidence of nothing. The package was simply never packed at a moment anyone was looking.
Cutting a tag is a form now — the `release` workflow — so the absence of one has stopped being a
fact about anything at all.
Measured on the package it *would* have produced, the problem was worse than the missing feed —
`Boltway.Interaction.Tests` carried `Microsoft.NET.Test.Sdk`, `xunit.runner.visualstudio` and
`coverlet.collector` as dependencies, and it carried this repository's own concrete tests, including
the deliberately broken renderer. A customer referencing it would have run Boltway's tests
inside their suite and read the results as being about their renderer.

So the contracts moved into `Boltway.Interaction.Testing` — `xunit` and nothing else, no
runner, the derivations and the sabotage suite left behind. Publishing still needs a tag; the
package is now one worth publishing.

> The move took two of this repository's own suites with it. `DefaultInteractionLayoutTests` and
> `ThemedDefaultInteractionLayoutTests` lived at the bottom of the contract file, went into the
> shipped project, and stopped running — the Testing project has no runner, deliberately. That is
> the same defect the move was fixing, one directory along, and the only sign was the total dropping
> from 146 to 126. Moved back.

### 7.7 What ships where

| | Boltway | Northwind |
| --- | --- | --- |
| `/login`, `/consent`, `/error`, `/logout` | pages + seam | Vietnamese renderer |
| `/me/*` self-service pages | pages + seam | Vietnamese renderer |
| `/reset`, `/verify-email` | pages + seam | Vietnamese renderer, mail templates |
| Admin UI (BFF) | nothing | the whole thing |
| Stylesheet | one default | its own |

The admin UI is deliberately not in the library. It is the piece most shaped by one company's
vocabulary — roles, teams, what an operator is allowed to see — and a shipped one would be one deployment's
org chart in every customer's deployment, which is the argument `UserAccount.Role` already makes
about itself.

### 7.8 Where this lands in the build order

In §5, with everything else. There is no second ordering here on purpose — the UI work is steps 0.1,
0.3, 0.4, 0.5, 6 and 9 through 11 of the one list.
