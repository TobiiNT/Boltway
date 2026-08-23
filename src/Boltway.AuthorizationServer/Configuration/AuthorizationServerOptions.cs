using System.Collections.ObjectModel;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Token;
using Boltway.OAuth.Net;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.OAuth.Tokens;

namespace Boltway.AuthorizationServer.Configuration;

/// <summary>
/// How clients register. Exactly one, never both.
/// </summary>
/// <remarks>
/// N-06 and A-05. Advertising <c>registration_endpoint</c> and
/// <c>client_id_metadata_document_supported</c> together is not "offering a choice": a live Auth0
/// measurement showed Claude picking DCR when both were present, contradicting the priority order
/// the MCP specification states. Modelling this as an enum rather than two booleans means the
/// invalid combination has no representation, so the "refuses to boot" rule has nothing left to
/// catch.
/// </remarks>
public enum ClientRegistrationProfile
{
    /// <summary>Unset. Refused at validation, so a forgotten setting fails loudly.</summary>
    Unspecified = 0,

    /// <summary>The default. Clients are identified by a URL that serves their metadata.</summary>
    ClientIdMetadataDocument = 1,

    /// <summary>Opt-in. RFC 7591 dynamic registration, with <c>/register</c> routed.</summary>
    DynamicRegistration = 2,
}

/// <summary>
/// Everything the server needs to know about itself.
/// </summary>
/// <remarks>
/// Deliberately not an <c>IOptions&lt;T&gt;</c>-shaped bag of nullable strings validated at first
/// use. <see cref="TryValidate"/> runs at startup and the host refuses to start when it fails,
/// because every setting here is one a misconfiguration turns into a security property: a
/// request-derived issuer, an advertised scope no client may request, a 24-hour access token
/// against a stateless resource server.
/// </remarks>
public sealed class AuthorizationServerOptions
{
    /// <summary>The shortest access-token lifetime that is not thrash. See <see cref="AccessTokenLifetime"/>.</summary>
    public static TimeSpan MinimumAccessTokenLifetime { get; } = TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(1);

    /// <summary>The longest access-token lifetime. Beyond this, revocation lag is unbounded in practice.</summary>
    public static TimeSpan MaximumAccessTokenLifetime { get; } = TimeSpan.FromHours(24);

    /// <summary>
    /// The issuer identifier, exactly as it should appear on the wire.
    /// </summary>
    /// <remarks>
    /// Configured as a string and emitted as that string. See <see cref="IssuerString"/> for why it
    /// is never rebuilt from a <see cref="Uri"/> or from the request.
    /// </remarks>
    public string? Issuer { get; set; }

    /// <summary>How clients register. <see cref="ClientRegistrationProfile.ClientIdMetadataDocument"/> unless changed.</summary>
    public ClientRegistrationProfile RegistrationProfile { get; set; } = ClientRegistrationProfile.ClientIdMetadataDocument;

    /// <summary>
    /// Every scope this server will issue.
    /// </summary>
    /// <remarks>
    /// The rule that governs this list is "never advertise a scope any valid client would be
    /// refused" — ChatGPT requests every advertised OIDC scope by default, so an aspirational entry
    /// here becomes a refused authorization for that client. <c>offline_access</c> must be present
    /// for Claude to ever ask for a refresh token.
    /// </remarks>
    public IList<string> ScopesSupported => _scopesSupported;

    /// <summary>
    /// A human description per scope, rendered on the consent page <b>verbatim</b>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A-14. The consent page never derives text by parsing a scope name — the field failure that
    /// rule comes from is a screen that assumed <c>action:resource</c> and rendered "read: story your
    /// read" as the thing a user was agreeing to.
    /// </para>
    /// <para>
    /// A missing description is a startup <b>warning</b>, not an error, and the page falls back to
    /// the raw scope plus a note that none is configured. Refusing to boot would make a cosmetic
    /// omission an outage; rendering a guess would be worse than either.
    /// </para>
    /// </remarks>
    public IDictionary<string, string> ScopeDescriptions => _scopeDescriptions;

    /// <summary>
    /// Scopes with no configured description. Populated by <see cref="TryValidate"/>.
    /// </summary>
    /// <remarks>
    /// Surfaced rather than logged so the doctor can report it. A-15 forbids a switch that turns
    /// A-14 off, and a warning nobody can see is that switch by another name.
    /// </remarks>
    public IReadOnlyList<string> ScopesWithoutDescriptions { get; private set; } = [];

    /// <summary>
    /// The grants this deployment will honour, and therefore advertise.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The two the code flow needs, and — today — the only two that can be set. Advertising a grant
    /// is a promise: Claude Enterprise Managed Auth will only offer the jwt-bearer feature to a
    /// customer when the URN appears here, and a customer who is then refused at <c>/token</c> has
    /// been sent down a path this server invited them onto.
    /// </para>
    /// <para>
    /// Validation rejects any name not in <c>KnownGrantTypes</c>, which lists precisely the grants
    /// <c>TokenEndpoint</c> dispatches. So enabling a grant with no handler is a startup failure
    /// rather than a runtime surprise. That sentence was here before the property was true —
    /// <c>client_credentials</c> and the jwt-bearer URN were both accepted with nothing behind them
    /// — and the fix was to the code rather than to the sentence.
    /// </para>
    /// </remarks>
    public IList<string> GrantTypesSupported => _grantTypesSupported;

    /// <summary>
    /// How clients may authenticate at <c>/token</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="ClientAuthMethod.None"/> is what Claude's CIMD selection gate requires, and it is
    /// what both vendors' MCP clients actually use.
    /// </para>
    /// <para>
    /// <see cref="ClientAuthMethod.PrivateKeyJwt"/> is <b>not</b> in the default set, because it is
    /// not implemented yet — and advertising it would be N-06 exactly: a capability in the metadata
    /// with nothing behind it. Add it here once there is a JWKS-fetching authenticator to honour it.
    /// </para>
    /// <para>
    /// Omitting it is not a vendor lockout, because ChatGPT's live metadata offers
    /// <c>["none", "private_key_jwt"]</c> — <i>both</i> — so there is a method left that both sides
    /// can complete. <b>That sentence used to end the paragraph above, and on its own it was not
    /// enough.</b> It describes what ChatGPT offers; it says nothing about whether this server reads
    /// the offer. On 2026-08-17 it did not: ChatGPT had added
    /// <c>"token_endpoint_auth_method":"private_key_jwt"</c> beside the plural, the CIMD reader took
    /// the singular and never looked at the array, and every ChatGPT connection failed at
    /// <c>/token</c> with <c>invalid_client</c> while this comment read as though the case were
    /// covered. <c>CimdDocument.TryReadAuthMethod</c> now reads both members and
    /// <c>The_live_chatgpt_document_is_a_public_client</c> pins the document that broke it — the
    /// interop claim belongs to a test, and this is the note saying which one.
    /// </para>
    /// </remarks>
    public IList<ClientAuthMethod> TokenEndpointAuthMethods => _tokenEndpointAuthMethods;

    /// <summary>
    /// Whether <c>/userinfo</c> is routed and advertised. RFC 9068 / OIDC Core §5.3. <b>On.</b>
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Implemented, and on by default, which is the flip the history below asked for.</b>
    /// <c>UserInfoEndpoint</c> routes it; this flag both routes and advertises, so the two cannot
    /// disagree.
    /// </para>
    /// <para>
    /// Default <c>true</c> rather than <c>false</c>: it is a standard OIDC endpoint, it discloses
    /// only what the caller's own access token already carries, and an OIDC client that finds no
    /// <c>userinfo_endpoint</c> in the discovery document has no channel at all for the address or
    /// the role — the ID token deliberately carries neither. A deployment that wants it gone sets
    /// this to false and the document stops naming it.
    /// </para>
    /// <para>
    /// <b>The history, kept because three sibling flags point here for it.</b>
    /// These four flags all defaulted to <see langword="true"/>, and an operability review measured
    /// what that meant against a running server built from the shipped defaults:
    /// </para>
    /// <code>
    /// /userinfo    -> 404      /revoke    -> 404
    /// /introspect  -> 404      /logout    -> 404
    /// </code>
    /// <para>
    /// All four published in the discovery document; none routed by
    /// <c>MapBoltwayAuthorizationServer</c>. That is four simultaneous N-06 violations —
    /// "advertised capability == actual capability" — in the default configuration, which is the
    /// configuration nearly every deployment runs. The doctor reported the metadata check as Pass
    /// throughout, because it validated the document's shape rather than whether anything answered.
    /// </para>
    /// <para>
    /// The option stays, because a deployment may route its own. But the default now describes what
    /// this package actually does, and <c>Every_advertised_endpoint_answers</c> walks the served
    /// document and requests every URL in it, so turning one on without routing it is a red test.
    /// Flip a flag when the endpoint exists.
    /// </para>
    /// <para>
    /// <b>And the correction to that history spent a release where nobody could read it.</b> It was
    /// written as a <i>second</i> <c>&lt;remarks&gt;</c> element on this property, beside a
    /// <c>&lt;summary&gt;</c> left reading "Off, because it is not implemented" — so the one line a
    /// doc viewer, an IDE tooltip and a reader all actually show was the stale one, and the true
    /// text sat in an element that renders second or not at all. A capability claim in the wrong
    /// element is a capability claim nobody sees corrected. Keep this property's summary true first.
    /// </para>
    /// </remarks>
    public bool UserInfoEnabled { get; set; } = true;

    /// <summary>
    /// Whether <c>/revoke</c> is routed and advertised. RFC 7009. Off; see
    /// <see cref="UserInfoEnabled"/> for why the two halves are one flag.
    /// </summary>
    public bool RevocationEnabled { get; set; }

    /// <summary>Whether <c>/introspect</c> is routed and advertised. RFC 7662.</summary>
    /// <remarks>
    /// <para>
    /// <b>Implemented now, and this flag does both halves</b> — the pairing <see cref="UserInfoEnabled"/>
    /// describes, so the document cannot name an endpoint nothing serves.
    /// </para>
    /// <para>
    /// <b>Off by default, unlike <see cref="UserInfoEnabled"/>, and the asymmetry is deliberate.</b>
    /// UserInfo discloses only what the caller's own access token already carries. Introspection
    /// answers questions about <i>somebody else's</i> token, so an unnecessary one is a surface that
    /// exists to be probed. A deployment turns it on when it has a resource server that needs
    /// revocation to take effect before the token expires, and configures a confidential client for
    /// it to call with.
    /// </para>
    /// </remarks>
    public bool IntrospectionEnabled { get; set; }

    /// <summary>
    /// Whether <c>/logout</c> is routed and advertised. OIDC RP-Initiated Logout §2.1. Off; see
    /// <see cref="UserInfoEnabled"/>. <c>MapInteraction</c> routes it rather than
    /// <c>MapBoltwayAuthorizationServer</c> directly, because it is a page a person looks at —
    /// the pairing is the same one, one flag layer down.
    /// </summary>
    public bool EndSessionEnabled { get; set; }

    /// <summary>
    /// How often a session cookie is checked against the account it names.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This number is how long an invalidated session keeps working.</b> Somebody who has just
    /// changed their password, or pressed the control that ends every session, is told the job is
    /// done; for up to this long a browser holding the old cookie is still signed in. Five minutes
    /// is the default because the check reads the directory and the alternative is a query in front
    /// of every authenticated page load — the same trade, and the same honesty about it, as the
    /// resource server's introspection cache.
    /// </para>
    /// <para>
    /// <b>Zero or less means check every request.</b> Correct, and affordable for a deployment whose
    /// directory is local or whose traffic is small. It is not the default because a library cannot
    /// know either of those.
    /// </para>
    /// <para>
    /// Has no effect unless <c>SessionRevalidation</c> is registered and wired into the cookie
    /// handler's <c>OnValidatePrincipal</c>. A value set on a host that did not wire it is a number
    /// nothing reads, which is why <c>AddBoltwayAuthorizationServer</c> registers the service
    /// and the host's own <c>AddCookie</c> names the callback.
    /// </para>
    /// </remarks>
    public TimeSpan SessionRevalidation { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// How long an access token is valid.
    /// </summary>
    /// <remarks>
    /// 30 minutes, and the number is a tradeoff rather than a default worth copying. Claude
    /// refreshes proactively up to 5 minutes early (C-19), so a 10-minute token refreshes every
    /// 5 minutes — thrash. An hour means up to an hour of revocation lag against a resource server
    /// that validates offline and therefore never asks us whether the token still stands. 30 gives
    /// roughly 25-minute refresh spacing and bounded lag.
    /// </remarks>
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>
    /// Which algorithm signs the tokens this server issues.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>RS256 because it is the interop floor</b> — RFC 9068 §2.1 makes it mandatory to
    /// implement, so it is the one every relying party can verify. It is a default rather than a
    /// rule: the key ring, the JWKS document and the verifier already handle ES256, and a
    /// deployment whose key policy is elliptic-curve could not use this server at all while the
    /// minting site named one algorithm directly.
    /// </para>
    /// <para>
    /// <b>It sets what is advertised as well as what is minted, and that is the point.</b>
    /// <c>id_token_signing_alg_values_supported</c> is built from this, so the document cannot come
    /// to promise an algorithm the issuer will not produce. That has happened here before, the
    /// other way round: the list was filled from the verifier's allow-list, so the server
    /// advertised ES256 while minting RS256 and nothing else, and a relying party configuring
    /// <c>id_token_signed_response_alg=ES256</c> from that document would reject every token this
    /// server can make. <c>SigningAlgorithms.Issued</c> carries the argument.
    /// </para>
    /// <para>
    /// The ring must hold an active key for it. <c>ConfigurationDoctor</c> reports a ring that does
    /// not, which is otherwise a failure on the first token rather than at startup.
    /// </para>
    /// </remarks>
    public SigningAlgorithm TokenSigningAlgorithm { get; set; } = SigningAlgorithm.RS256;

    /// <summary>
    /// How long an authorization code is valid.
    /// </summary>
    /// <remarks>
    /// OAuth 2.1 §4.1.2: "a maximum authorization code lifetime of 10 minutes is RECOMMENDED".
    /// One minute is enough for a browser redirect and a token request; the code is single-use and
    /// its exposure window is the point.
    /// </remarks>
    public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// How recently the user must have authenticated for <c>prompt=login</c> and <c>max_age</c> to
    /// count as already satisfied.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Both parameters mean "re-authenticate", and both are carried in the <c>returnUrl</c> — so
    /// without a floor, an authentication that has just happened does not satisfy the parameter that
    /// asked for it, and <c>/authorize</c> sends the user to <c>/login</c> forever. <c>max_age=0</c>
    /// is the certain case: any elapsed time exceeds zero.
    /// </para>
    /// <para>
    /// It must comfortably exceed how long a user spends on the consent page, since that time also
    /// elapses between authenticating and returning.
    /// </para>
    /// </remarks>
    public TimeSpan ReauthenticationFreshness { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>How long a refresh token is valid before the user must authorize again.</summary>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// The key refresh tokens are derived from. At least 32 bytes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Must be stable across restarts <b>and across instances</b>. A per-process key makes the
    /// refresh grace window work only when both racers happen to land on the same node, which is a
    /// half-failure that looks like flakiness rather than like a bug.
    /// </para>
    /// <para>
    /// It is equivalent in value to every refresh token this server will ever issue, so it belongs
    /// wherever the signing keys live rather than in configuration a deployment prints.
    /// </para>
    /// </remarks>
    public byte[]? RefreshTokenDerivationKey { get; set; }

    /// <summary>Documentation for developers integrating with this server. Emitted only when set.</summary>
    public string? ServiceDocumentation { get; set; }

    /// <summary>The privacy policy shown on the consent page. Emitted only when set.</summary>
    public string? PolicyUri { get; set; }

    /// <summary>The terms of service. Emitted only when set.</summary>
    public string? TermsOfServiceUri { get; set; }

    /// <summary>
    /// Which directory this deployment's usernames are unique within.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="RealmId.Default"/> unless a deployment says otherwise, and one realm is the only
    /// shape this server has today: there is no per-request realm selection, so every lookup uses
    /// this value.
    /// </para>
    /// <para>
    /// <b>It is set now so that it does not have to be added later.</b> A realm column arriving
    /// after a directory is populated is a migration across every deployed database, run against
    /// tables holding live credentials. Arriving with the first schema it costs one column and one
    /// index, and every single-realm deployment behaves exactly as it did.
    /// </para>
    /// </remarks>
    public RealmId Realm { get; set; } = RealmId.Default;

    /// <summary>
    /// Whether to serve the administrative HTTP surface.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Off. An admin API on an authorization server is the highest-value target in the system — a
    /// flaw there is not a leaked document, it is the directory — so a deployment that manages
    /// accounts over ssh should not be serving one at all.
    /// </para>
    /// <para>
    /// It is also <c>N-06</c>: routed or absent, never advertised-and-404 and never
    /// present-and-unmentioned. Turning this on is a deployment saying it wants the surface.
    /// </para>
    /// </remarks>
    public bool AdministrationEnabled { get; set; }

    /// <summary>
    /// Whether to serve the self-service HTTP surface, <c>/account/*</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Off, and for a milder reason than <see cref="AdministrationEnabled"/>. The blast radius here
    /// is one account rather than the directory: <c>users:self</c> conveys no authority over anyone
    /// else, and no handler on that surface takes an identifier. The default is off because
    /// <c>N-06</c> applies to every endpoint equally — a deployment gets what it asked for — not
    /// because turning it on is dangerous.
    /// </para>
    /// <para>
    /// <b>Separate from <see cref="AdministrationEnabled"/> because the two are different
    /// decisions.</b> A deployment that manages accounts over ssh and still wants people to be able
    /// to see their own sessions is an ordinary configuration, and one flag would make it
    /// impossible without also exposing the directory.
    /// </para>
    /// </remarks>
    public bool SelfServiceEnabled { get; set; }

    /// <summary>
    /// Whether to serve the self-service <b>pages</b>, <c>/me/*</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Off, and separate from <see cref="SelfServiceEnabled"/> because they are separate surfaces
    /// with opposite authentication. <c>/account/*</c> is bearer-only for programmatic callers;
    /// these are cookie-authenticated pages with antiforgery, for a person in a browser. Either is
    /// useful without the other — a headless deployment wants the API, and a deployment whose users
    /// are people rather than programs wants the pages — so one flag would force a choice nobody
    /// asked to make.
    /// </para>
    /// <para>
    /// <b>Turning this on advertises no scope</b>, unlike the other two surfaces. There is no token
    /// involved: the pages authenticate with the session cookie this server already sets, so there
    /// is nothing for a client to request and nothing for the discovery document to name.
    /// </para>
    /// </remarks>
    public bool SelfServicePagesEnabled { get; set; }

    /// <summary>
    /// Whether to serve the password-recovery and email-verification flows. <c>E-39</c>–<c>E-44</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Off, and the one of the four surface flags with a hard prerequisite: turning it on without an
    /// <c>INotificationSender</c> registered is refused at startup. The endpoints would answer 202,
    /// mint a token, and deliver nothing — a flow that reports success and does not work, which is
    /// the failure shape this server refuses to start into.
    /// </para>
    /// <para>
    /// <b>Endpoints and pages together</b>, unlike the other surfaces, because a link in an email
    /// lands on a page and <c>E-40</c>/<c>E-41</c> on their own mail somebody a URL that answers
    /// 405. §7.3.
    /// </para>
    /// </remarks>
    public bool PasswordRecoveryEnabled { get; set; }

    /// <summary>
    /// The resources this server issues tokens for, as advertised in the metadata.
    /// </summary>
    /// <remarks>
    /// RFC 9728 §4 permits a partial list, so a client cross-checking its resource against this and
    /// not finding it must not treat that as a refusal. Emitted only when non-empty.
    /// </remarks>
    public IList<string> ProtectedResources => _protectedResources;

    /// <summary>
    /// The language this deployment's pages are actually written in. Emitted only when non-empty.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Every entry is served, and startup refuses the list otherwise.</b> The comment here used
    /// to say "locales with a shipped resource file", generated "from what exists, not from what is
    /// aspired to" — and there was no resource file, nothing that read one, and nothing anywhere
    /// that read the <c>ui_locales</c> request parameter. A deployment could list <c>vi</c> and
    /// serve English to everyone who asked for it, with the warning against exactly that sitting on
    /// the property that permitted it. That is <c>N-06</c>, on the field whose own documentation
    /// cited <c>N-06</c>.
    /// </para>
    /// <para>
    /// <b>This then said at most one entry, because two would be "a claim about per-request
    /// selection and there is no mechanism for it".</b> There is one now:
    /// <c>UiLocalesRequestCultureProvider</c> reads the parameter,
    /// <c>AddBoltwayInteractionLocalization</c> supplies the tables, and
    /// <c>AuthorizeEndpoint.LocalReturn</c> carries the resolved culture on to the pages. So the
    /// count is not the rule — being served is. <c>RequireAdvertisedLocalesAreServed</c> compares
    /// this list against <c>SupportedUICultures</c> at map time and refuses a mismatch in either
    /// direction, which catches an advertised locale nobody serves and a served locale nobody
    /// advertises, without caring which configuration call ran first.
    /// </para>
    /// <para>
    /// Leaving it empty is also honest, and is the default: no claim is not a false claim, and a
    /// client that sends <c>ui_locales</c> anyway gets what OIDC says it may get, which is whatever
    /// the provider has. The limit lifts when locale negotiation exists — see
    /// <c>docs/USER-MANAGEMENT.md</c> §7.5.
    /// </para>
    /// </remarks>
    public IList<string> UiLocalesSupported => _uiLocalesSupported;

    private IList<string> _scopesSupported = new List<string>();
    private IDictionary<string, string> _scopeDescriptions = new Dictionary<string, string>(StringComparer.Ordinal);
    private IList<string> _grantTypesSupported = new List<string> { "authorization_code", "refresh_token" };
    private IList<string> _protectedResources = new List<string>();
    private IList<string> _uiLocalesSupported = new List<string>();

    // `client_secret_post` was here and no registration path in this build produces a client
    // that uses it: EfClientStore and ConfiguredClients yield None or ClientSecretBasic
    // depending on whether a secret hash exists, service accounts are created ClientSecretBasic
    // outright, and CIMD §4.1 refuses every symmetric method. So an integrator read it out of
    // the discovery document, configured `client_secret_post` — the default in a great many
    // OAuth libraries — and got `invalid_client` saying "This client must authenticate with a
    // client secret" while sending exactly that. N-06 again, and the same shape as the four
    // advertised-but-unrouted endpoints and `form_post`.
    //
    // The authenticator still handles it: a deployment with its own IClientStore can register
    // such a client and add the method back here. What is removed is the default advertising a
    // capability this build's own registration paths cannot reach.
    private IList<ClientAuthMethod> _tokenEndpointAuthMethods = new List<ClientAuthMethod>
    {
        ClientAuthMethod.None,
        ClientAuthMethod.ClientSecretBasic,
    };

    /// <summary>
    /// The validated issuer. Meaningful only while the most recent <see cref="TryValidate"/> succeeded.
    /// </summary>
    /// <remarks>
    /// Cleared at the start of every validation run, so a failed run leaves this <c>default</c>
    /// rather than the previously-valid value. It used to be assigned only on success and never
    /// reset, which meant setting <c>Issuer</c> to something invalid produced
    /// <c>TryValidate() == false</c> alongside a <c>ValidatedIssuer</c> that still returned the old
    /// https URL — a property whose name asserted something it had stopped guaranteeing.
    /// </remarks>
    public IssuerString ValidatedIssuer { get; private set; }

    /// <summary>The validated scope set. Cleared and recomputed on every validation run.</summary>
    public ScopeSet ValidatedScopes { get; private set; }

    /// <summary>
    /// Federated sign-in. Validated with the rest of this object, and registered as the singleton
    /// the federation endpoints read.
    /// </summary>
    /// <remarks>
    /// A nested object rather than a separately registered one, so there is a single place a
    /// deployment configures this server and a single validation run that either passes or refuses
    /// to start. A second registration point would be a second thing to remember and a second thing
    /// to get out of step with the first.
    /// </remarks>
    public ExternalLoginOptions ExternalLogin { get; } = new();

    /// <summary>
    /// How the sign-in and consent pages look.
    /// </summary>
    /// <remarks>
    /// Nested here for the reason <see cref="ExternalLogin"/> is: one place a deployment is
    /// configured and one validation run. It is also the reason these settings are validated at all
    /// — a stylesheet path the browser will refuse is the kind of mistake that otherwise surfaces as
    /// "the login page looks wrong", weeks later, to somebody who did not configure it.
    /// </remarks>
    public InteractionOptions Interaction { get; } = new();

    /// <summary>Whether <see cref="Freeze"/> has run.</summary>
    public bool IsFrozen { get; private set; }

    /// <summary>
    /// Make every collection read-only.
    /// </summary>
    /// <remarks>
    /// Called by the registration extension once the metadata document has been serialized. After
    /// that point the served bytes are fixed, so a host that adds a scope is creating a divergence
    /// nothing would detect: the options singleton would report a scope the published document does
    /// not advertise, and — since the authorize pipeline is built from the same options — one that
    /// clients cannot discover but the server would accept. Mutating a frozen collection throws
    /// where the mutation happens instead.
    /// </remarks>
    public void Freeze()
    {
        if (IsFrozen)
        {
            return;
        }

        _scopesSupported = new ReadOnlyCollection<string>([.. _scopesSupported]);
        _scopeDescriptions = new ReadOnlyDictionary<string, string>(_scopeDescriptions);
        _grantTypesSupported = new ReadOnlyCollection<string>([.. _grantTypesSupported]);
        _protectedResources = new ReadOnlyCollection<string>([.. _protectedResources]);
        _uiLocalesSupported = new ReadOnlyCollection<string>([.. _uiLocalesSupported]);
        _tokenEndpointAuthMethods = new ReadOnlyCollection<ClientAuthMethod>([.. _tokenEndpointAuthMethods]);
        Interaction.Freeze();

        IsFrozen = true;
    }

    /// <summary>
    /// Check every setting, collecting <b>all</b> the problems.
    /// </summary>
    /// <param name="errors">Everything wrong, in configuration order.</param>
    /// <returns><see langword="true"/> when the server may start.</returns>
    /// <remarks>
    /// All of them, not the first. An operator fixing a misconfiguration one restart at a time is
    /// the experience A-12 exists to prevent, and each restart of a real deployment is minutes.
    /// </remarks>
    public bool TryValidate(out IReadOnlyList<string> errors)
    {
        var found = new List<string>();

        // Cleared before anything runs. Leaving a stale value behind on failure is what made
        // ValidatedIssuer a lie: it survived a subsequent failing validation and kept handing out
        // an issuer the current configuration no longer describes.
        ValidatedIssuer = default;
        ValidatedScopes = ScopeSet.Empty;

        ValidateIssuer(found);
        ValidateProfile(found);
        ValidateScopes(found);
        ValidateGrantsAndAuthMethods(found);
        ValidateLifetimes(found);
        ValidateOptionalUrls(found);
        ValidateUiLocales(found);

        if (!ExternalLogin.TryValidate(out var federation))
        {
            found.AddRange(federation);
        }

        if (!Interaction.TryValidate(out var interaction))
        {
            found.AddRange(interaction);
        }

        errors = found;
        return found.Count == 0;
    }

    private void ValidateProfile(List<string> errors)
    {
        if (RegistrationProfile is ClientRegistrationProfile.Unspecified)
        {
            errors.Add(
                "RegistrationProfile is Unspecified. Choose ClientIdMetadataDocument, which is the " +
                "default and what both vendors' MCP clients prefer.");
        }

        // N-06, reached through configuration rather than through code. Selecting this profile makes
        // MetadataBuilder publish registration_endpoint, and nothing routes /register — measured, GET
        // and POST both 404. That is the same shape as the four endpoint flags that defaulted to
        // advertising /userinfo, /revoke, /introspect and /logout while all four 404'd, and it
        // survived that fix because it is a profile rather than a flag.
        //
        // Refused at startup rather than quietly not advertised. A deployment that asked for dynamic
        // registration wants dynamic registration; publishing a document without it and starting
        // anyway would answer a different question than the one the operator asked.
        if (RegistrationProfile is ClientRegistrationProfile.DynamicRegistration)
        {
            errors.Add(
                "RegistrationProfile is DynamicRegistration, which advertises registration_endpoint " +
                "in the discovery document — and /register is not implemented, so every client that " +
                "reads the document and follows it gets a 404. Use ClientIdMetadataDocument: it needs " +
                "no registration step at all, and Claude selects it when the document advertises " +
                "client_id_metadata_document_supported and `none` in token_endpoint_auth_methods_" +
                "supported. Measured end to end against this server with Claude's own client_id.");
        }
    }

    private void ValidateGrantsAndAuthMethods(List<string> errors)
    {
        if (!GrantTypesSupported.Contains("authorization_code", StringComparer.Ordinal))
        {
            errors.Add(
                "'authorization_code' must be among GrantTypesSupported: this server exists to " +
                "serve the authorization code flow, and every other grant it offers is an addition " +
                "to that one.");
        }

        foreach (var grant in GrantTypesSupported)
        {
            if (!KnownGrantTypes.Contains(grant, StringComparer.Ordinal))
            {
                errors.Add(
                    $"'{grant}' is not a grant type this server implements. Advertising it would " +
                    $"offer clients a path that ends at the token endpoint refusing them. Known: " +
                    $"{string.Join(", ", KnownGrantTypes)}.");
            }
        }

        var duplicateGrants = GrantTypesSupported
            .GroupBy(g => g, StringComparer.Ordinal)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        if (duplicateGrants.Count > 0)
        {
            errors.Add($"Grant types are configured more than once: {string.Join(", ", duplicateGrants)}.");
        }

        if (TokenEndpointAuthMethods.Count == 0)
        {
            errors.Add(
                "At least one token endpoint authentication method is required. RFC 8414 §2 defaults " +
                "an omitted list to [\"client_secret_basic\"], which refuses every public client — " +
                "including both vendors' MCP clients.");
        }
    }

    /// <summary>
    /// The grant types this server has a handler for. <b>Exactly these, no aspirational entries.</b>
    /// </summary>
    /// <remarks>
    /// <para>
    /// This list used to also carry <c>client_credentials</c> and the jwt-bearer URN, for which
    /// <c>TokenEndpoint</c> has no arm. So a customer who enabled either got it advertised in the
    /// discovery document and then refused at runtime by the dispatch switch's fallthrough — which
    /// is N-06 (advertised capability must equal actual capability) reached through configuration,
    /// and it directly contradicted the claim <see cref="GrantTypesSupported"/> makes about itself.
    /// </para>
    /// <para>
    /// The two names are not a coincidence to be maintained by care.
    /// <c>MetadataHonestyTests.Every_advertised_grant_has_a_handler</c> drives every entry here
    /// through <c>/token</c> and fails if the answer is <c>unsupported_grant_type</c>, so adding a
    /// name here without an arm in the switch is a red test rather than a promise to a client. Grow
    /// this list when a handler exists, not before.
    /// </para>
    /// </remarks>
    private static readonly string[] KnownGrantTypes =
    [
        "authorization_code",
        "refresh_token",
        "client_credentials",
    ];

    private void ValidateIssuer(List<string> errors)
    {
        if (!IssuerString.TryCreate(Issuer, out var issuer, out var error))
        {
            errors.Add(error!);
            return;
        }

        // A product requirement rather than an RFC one, so it lives here and not in IssuerString.
        //
        // RFC 8414 §3 inserts the well-known segment before the issuer's path while OIDC Discovery
        // §4.1 appends it after, and MCP clients probe both spellings plus two more. A path-bearing
        // issuer therefore has to serve four live URLs that no rule derives from one another, and
        // every one of them is a place for a deployment to be half-configured. A path-less issuer
        // collapses all four onto two.
        if (Uri.TryCreate(issuer.Value, UriKind.Absolute, out var parsed)
            && !string.Equals(parsed.GetComponents(UriComponents.Path, UriFormat.UriEscaped), string.Empty, StringComparison.Ordinal))
        {
            errors.Add(
                $"The issuer '{issuer.Value}' has a path. This server requires a path-less issuer: " +
                "RFC 8414 §3 inserts '/.well-known/...' before an issuer path and OIDC Discovery " +
                "§4.1 appends it after, so a path-bearing issuer must serve four discovery URLs " +
                "that clients probe in an order none of them agree on. Give the server its own " +
                "host or subdomain instead.");
            return;
        }

        ValidatedIssuer = issuer;
    }

    private void ValidateScopes(List<string> errors)
    {
        if (ScopesSupported.Count == 0)
        {
            errors.Add("At least one scope must be configured; a server that advertises none can issue nothing.");
            return;
        }

        var valid = true;

        foreach (var scope in ScopesSupported)
        {
            if (!ScopeSet.TryValidateName(scope, out var error))
            {
                errors.Add(error!);
                valid = false;
            }
        }

        if (!valid)
        {
            return;
        }

        var duplicates = ScopesSupported
            .GroupBy(s => s, StringComparer.Ordinal)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        if (duplicates.Count > 0)
        {
            errors.Add($"Scopes are configured more than once: {string.Join(", ", duplicates)}.");
            return;
        }

        _ = ScopeSet.TryParse(string.Join(' ', ScopesSupported), out var parsed, out _);
        ValidatedScopes = parsed;

        // A-14: reported, never guessed at, and never fatal.
        ScopesWithoutDescriptions = [.. parsed.Values.Where(s => !ScopeDescriptions.ContainsKey(s))];

        // OIDC Discovery §3: an OP "MUST support the openid scope value". We publish the OIDC
        // superset document from the same object, so omitting it would advertise an OP that is not
        // one. It costs nothing — `openid` gates OIDC behaviour rather than granting access.
        if (!parsed.Contains("openid"))
        {
            errors.Add(
                "The 'openid' scope must be configured: this server publishes an OpenID Provider " +
                "metadata document, and OIDC Discovery §3 requires an OP to support it.");
        }

        // Claude appends `offline_access` to its authorization request only when the AS metadata
        // lists it. Without it no refresh token is ever requested, so every connection dies at the
        // access token's expiry and the user re-authorizes — with nothing in any log saying why.
        if (!parsed.Contains("offline_access"))
        {
            errors.Add(
                "The 'offline_access' scope must be configured: clients request a refresh token " +
                "only when this scope is advertised, and without one every connection ends when " +
                "the first access token expires.");
        }
    }

    private void ValidateLifetimes(List<string> errors)
    {
        if (AccessTokenLifetime < MinimumAccessTokenLifetime || AccessTokenLifetime > MaximumAccessTokenLifetime)
        {
            errors.Add(
                $"AccessTokenLifetime is {AccessTokenLifetime}, outside [{MinimumAccessTokenLifetime}, " +
                $"{MaximumAccessTokenLifetime}]. Below the floor, a client that refreshes 5 minutes " +
                "early refreshes continuously; above the ceiling, a resource server validating " +
                "offline honours a revoked token for a day.");
        }

        if (AuthorizationCodeLifetime <= TimeSpan.Zero || AuthorizationCodeLifetime > TimeSpan.FromMinutes(10))
        {
            errors.Add(
                $"AuthorizationCodeLifetime is {AuthorizationCodeLifetime}; OAuth 2.1 §4.1.2 " +
                "recommends a maximum of 10 minutes.");
        }

        if (RefreshTokenDerivationKey is null || RefreshTokenDerivationKey.Length < RefreshTokenDeriver.MinimumKeyBytes)
        {
            errors.Add(
                $"RefreshTokenDerivationKey must be at least {RefreshTokenDeriver.MinimumKeyBytes} bytes. "
                + "Refresh tokens are derived from it so that two concurrent redemptions compute the "
                + "same successor; a short or absent key is a brute-force target that yields every "
                + "refresh token this server will ever issue.");
        }

        if (RefreshTokenLifetime <= AccessTokenLifetime)
        {
            errors.Add(
                $"RefreshTokenLifetime ({RefreshTokenLifetime}) must exceed AccessTokenLifetime " +
                $"({AccessTokenLifetime}); otherwise the refresh token expires before it is first used.");
        }
    }

    /// <summary>
    /// One realm, set; one language, or none. See each property for why.
    /// </summary>
    private void ValidateUiLocales(List<string> errors)
    {
        if (AdministrationEnabled)
        {
            // N-06 for this surface. The endpoints authorize on `users:read` and `users:write`, and a
            // scope this server does not advertise is one no client will ever put in an authorization
            // request — so the surface would be routed, guarded, and unreachable, which reads to an
            // operator as a permissions bug in whatever they are holding.
            //
            // `roles:read`/`roles:write` are deliberately not in this list: the role endpoints accept
            // them as narrower alternatives, but the users pair alone keeps every endpoint reachable,
            // so a deployment that never advertises them has lost an option rather than a surface.
            foreach (var required in new[] { "users:read", "users:write" })
            {
                if (!ScopesSupported.Contains(required, StringComparer.Ordinal))
                {
                    errors.Add(
                        $"AdministrationEnabled is set and '{required}' is not in ScopesSupported. "
                        + "The admin endpoints authorize on it, and a client cannot request a scope "
                        + "this server does not advertise — the surface would be routed and "
                        + "unreachable.");
                }
            }
        }

        // The same rule for the self-service surface, and it needs stating separately rather than
        // being folded into the loop above: the two flags are independent, so a deployment serving
        // only `/account/*` advertises only `users:self` and must not be asked for the other two.
        if (SelfServiceEnabled && !ScopesSupported.Contains("users:self", StringComparer.Ordinal))
        {
            errors.Add(
                "SelfServiceEnabled is set and 'users:self' is not in ScopesSupported. Every "
                + "/account endpoint authorizes on it, and a client cannot request a scope this "
                + "server does not advertise — the surface would be routed and unreachable.");
        }

        if (Realm.IsUnset)
        {
            errors.Add(
                "Realm is unset. Leave it alone for a single-directory deployment — it defaults to "
                + "RealmId.Default — or set it with RealmId.TryParse; a default(RealmId) would be "
                + "written into a NOT NULL column as null.");
        }

        // More than one used to be refused outright, because nothing read `ui_locales` and there was
        // no per-locale text. Both exist now, so the check moved rather than went away: map time
        // compares this list against the cultures RequestLocalizationMiddleware will actually
        // honour and refuses a mismatch in either direction. That is a stronger rule than counting —
        // one advertised locale that the middleware does not serve is the same lie as five.

        foreach (var locale in UiLocalesSupported)
        {
            if (string.IsNullOrWhiteSpace(locale))
            {
                errors.Add("UiLocalesSupported contains a blank entry.");
            }
        }
    }

    private void ValidateOptionalUrls(List<string> errors)
    {
        Check(ServiceDocumentation, nameof(ServiceDocumentation));
        Check(PolicyUri, nameof(PolicyUri));
        Check(TermsOfServiceUri, nameof(TermsOfServiceUri));

        foreach (var resource in ProtectedResources)
        {
            Check(resource, nameof(ProtectedResources));
        }

        void Check(string? value, string name)
        {
            if (string.IsNullOrEmpty(value))
            {
                return;
            }

            if (!AbsoluteHttpsUrl.TryCreate(value, out _))
            {
                errors.Add($"{name} is '{value}', which is not an absolute https URL.");
            }
        }
    }
}
