using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Resources;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Errors;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Pkce;
using Boltway.OAuth.Primitives.Redirects;
using Boltway.OAuth.Primitives.Scopes;

namespace Boltway.AuthorizationServer.Authorize;

/// <summary>What validating an authorization request produced.</summary>
public abstract record AuthorizeOutcome
{
    private AuthorizeOutcome() { }

    /// <summary>Everything validated. The request may proceed to authentication and consent.</summary>
    public sealed record Validated(AuthorizeContext Context) : AuthorizeOutcome;

    /// <summary>Refused before a redirect URI was trusted. Rendered on our own origin.</summary>
    public sealed record Html(AuthorizeHtmlError Error) : AuthorizeOutcome;

    /// <summary>Refused after the redirect URI was trusted. Delivered by redirect.</summary>
    public sealed record Redirect(AuthorizeRedirectError Error) : AuthorizeOutcome;
}

/// <summary>
/// Validates an authorization request, in the one order that is safe.
/// </summary>
/// <remarks>
/// <para>
/// The ordering is <c>client_id</c>, then <c>redirect_uri</c>, then everything else — RFC 6749
/// §4.1.2.1 — and it is enforced by method signatures rather than by the sequence of calls. Every
/// stage that can redirect takes a <see cref="ValidatedRedirect"/> as a parameter, and the only
/// place one exists is after <see cref="TryValidateRedirectUri"/> has produced it. Hoisting such a
/// stage above that call does not compile: <c>CS0841, cannot use local variable 'redirect' before
/// it is declared</c>.
/// </para>
/// <para>
/// That is a stronger claim than this class made before, and the difference was measured. The
/// stages used to read <c>context.Redirect!</c>, so reordering them <i>did</i> compile and failed
/// at runtime with "Nullable object must have a value" — a 500 from the authorization endpoint,
/// caught by tests but not by the type system the comment credited.
/// </para>
/// <para>
/// Reversing the order is not a tidiness problem. It makes the authorization endpoint an open
/// redirector on a domain the user has been taught to trust, it leaks <c>state</c>, and with
/// <c>prompt=none</c> it needs no interaction at all.
/// </para>
/// </remarks>
public sealed class AuthorizePipeline(
    IReadOnlyList<IClientResolver> clientResolvers,
    IResourceRegistry resources,
    ScopeSet supportedScopes)
{
    private readonly IReadOnlyList<IClientResolver> _clientResolvers =
        clientResolvers ?? throw new ArgumentNullException(nameof(clientResolvers));

    private readonly IResourceRegistry _resources = resources ?? throw new ArgumentNullException(nameof(resources));

    /// <summary>
    /// The most <c>resource</c> values one request may carry.
    /// </summary>
    /// <remarks>
    /// RFC 8707 §2 permits repetition and sets no limit, but each value costs a registry lookup
    /// inside the endpoint's latency budget (C-29 gives <c>/authorize</c> ten seconds). An
    /// unbounded list is a cheap way to spend all of it.
    /// </remarks>
    public const int MaxResourceValues = 16;

    /// <summary>
    /// The largest <c>max_age</c> accepted: a hundred years, in seconds.
    /// </summary>
    /// <remarks>
    /// Far below the point where <see cref="TimeSpan.FromSeconds(double)"/> throws, and far above
    /// any session age a relying party could mean. A bound chosen at the type's limit would be
    /// correct and would still admit values whose only purpose is to be absurd.
    /// </remarks>
    public const long MaxMaxAgeSeconds = 100L * 365 * 24 * 60 * 60;

    /// <summary>
    /// The scopes that ask for nothing at a protected resource. OIDC Core §5.4 and §11, exactly.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This list is a spec citation, not a policy. Every name in it is registered by OpenID Connect
    /// Core and describes the sign-in itself — who the user is, and whether the session may be
    /// refreshed. None of them can name an operation at somebody's API without colliding with the
    /// spec, which is what makes "the request asked for only these" mean "the request is not
    /// reaching a protected resource".
    /// </para>
    /// <para>
    /// <b>Only ever shrink this.</b> Adding a scope here says "a request carrying this still needs no
    /// audience of its own", and a deployment scope added by mistake would be granted at the OIDC
    /// resource without the request ever naming it — the silent cross-resource grant N-01 exists to
    /// prevent, arriving through a list nobody re-reads. Names not in <c>scopes_supported</c> are
    /// refused a stage earlier, so listing the full OIDC set costs nothing and keeps the citation
    /// whole rather than tracking one deployment's configuration.
    /// </para>
    /// </remarks>
    internal static readonly ScopeSet OidcOwnScopes =
        ScopeSet.FromStorage("openid profile email address phone offline_access");

    /// <summary>Run every validation stage.</summary>
    public async ValueTask<AuthorizeOutcome> ValidateAsync(
        AuthorizeContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        // `state` is read before anything can fail, so an error response can echo it. It is not
        // validated: RFC 6749 gives it no grammar, and the client is the only party that ascribes
        // meaning to it.
        if (!context.Parameters.TrySingle("state", out var state))
        {
            return Html(
                context,
                ReasonCode.RepeatedParameter,
                OAuthErrorCode.InvalidRequest,
                "The 'state' parameter appeared more than once.",
                "parameter=state");
        }

        context.State = state;

        // ───────── before a redirect URI is trusted: HTML only ─────────

        var clientOutcome = await ResolveClientAsync(context, cancellationToken);
        if (clientOutcome is not null)
        {
            return clientOutcome;
        }

        if (!TryValidateRedirectUri(context, out var redirect, out var redirectError))
        {
            return redirectError;
        }

        // ───────── redirecting is now permitted, and `redirect` is the proof ─────────
        //
        // Every stage below takes it as an argument. That is what makes the ordering structural:
        // hoisting one of these above the call that produced `redirect` is a compile error.

        AuthorizeOutcome? refusal =
            ValidateResponseType(context, redirect)
            ?? ValidatePkce(context, redirect)
            ?? ValidateScope(context, redirect)
            ?? await ValidateResourcesAsync(context, redirect, cancellationToken)
            ?? ValidateOidcParameters(context, redirect);

        return refusal ?? new AuthorizeOutcome.Validated(context);
    }

    /// <summary>Stage 2: turn <c>client_id</c> into a client. X-01, X-03.</summary>
    private async ValueTask<AuthorizeOutcome.Html?> ResolveClientAsync(
        AuthorizeContext context, CancellationToken cancellationToken)
    {
        if (!context.Parameters.TrySingle("client_id", out var raw))
        {
            return Html(
                context,
                ReasonCode.RepeatedParameter,
                OAuthErrorCode.InvalidRequest,
                "The 'client_id' parameter appeared more than once.",
                "parameter=client_id");
        }

        if (!ClientIdentifier.TryParseFromRequest(raw, out var clientId))
        {
            return Html(
                context,
                ReasonCode.ClientIdMalformed,
                OAuthErrorCode.InvalidClient,
                "The 'client_id' parameter is missing or malformed.",
                raw is null ? "client_id absent" : $"client_id={raw}");
        }

        foreach (var resolver in _clientResolvers)
        {
            if (!resolver.CanResolve(clientId))
            {
                continue;
            }

            var resolution = await resolver.ResolveAsync(clientId, cancellationToken);

            if (resolution.Client is { } client)
            {
                if (!client.IsEnabled)
                {
                    return Html(
                        context,
                        ReasonCode.ClientDisabled,
                        OAuthErrorCode.InvalidClient,
                        "This client is disabled.",
                        $"client_id={clientId.Value}");
                }

                context.Client = client;
                return null;
            }

            // X-31. A resolver that declined to look is not a resolver that looked and found
            // nothing, and the difference is the whole point of the separate error: answering
            // invalid_client here would tell a client with a perfectly good identifier to change it,
            // and would drop the one fact that makes the response actionable — when to try again.
            //
            // No fall-through to the next resolver either, for the same reason as below: this one
            // recognised the identifier, and it is the one that knows why it did not answer.
            if (resolution.Error is ClientResolutionError.RateLimited)
            {
                return new AuthorizeOutcome.Html(AuthorizeHtmlError.Throttled(
                    resolution.Detail ?? "This request was refused by a rate limit.",
                    context.CorrelationId,
                    resolution.RetryAfter ?? TimeSpan.FromSeconds(60)));
            }

            // A resolver that recognised the identifier and then failed is authoritative: falling
            // through to the next one would turn "your metadata document is malformed" into
            // "unknown client", which is the diagnosis Auth0 gave and the reason A-07 exists.
            if (resolution.Error is not ClientResolutionError.NotFound)
            {
                // A-09's sharpest case at this endpoint, alongside the resource server's. The client is
                // told which check failed, because A-07 requires that; the log additionally gets the
                // identifier it was asked about and which resolver in the chain answered, which is what
                // separates "the customer published a bad document" from "our fetcher is being blocked".
                return Html(
                    context,
                    ReasonCode.ClientMetadataUnusable,
                    OAuthErrorCode.InvalidClient,
                    resolution.Detail ?? "The client could not be resolved.",
                    $"client_id={clientId.Value}; resolver={resolver.GetType().Name}; outcome={resolution.Error}");
            }
        }

        return Html(
            context,
            ReasonCode.ClientUnknown,
            OAuthErrorCode.InvalidClient,
            "No client is registered with that identifier.",
            $"client_id={clientId.Value}; resolvers={_clientResolvers.Count}");
    }

    /// <summary>Stage 3: match the redirect URI. X-02, N-03, N-04. The line.</summary>
    private static bool TryValidateRedirectUri(
        AuthorizeContext context,
        [NotNullWhen(true)] out ValidatedRedirect? redirect,
        [NotNullWhen(false)] out AuthorizeOutcome.Html? error)
    {
        redirect = null;
        error = null;

        var client = context.Client!;

        if (!context.Parameters.TrySingle("redirect_uri", out var raw))
        {
            error = Html(
                context,
                ReasonCode.RepeatedParameter,
                OAuthErrorCode.InvalidRequest,
                "The 'redirect_uri' parameter appeared more than once.",
                "parameter=redirect_uri");
            return false;
        }

        if (raw is null)
        {
            // RFC 6749 §3.1.2.3 permits omitting it only when exactly one is registered. With
            // several, the server cannot pick — and picking would let a client that registered a
            // second URI receive codes at whichever one this server happened to sort first.
            //
            // The count is deliberately not in the message: it is a fact about the client's
            // registration, and an unauthenticated caller has no business learning it. The branch
            // below withholds *which* URIs are registered for the same reason.
            if (client.RedirectUris.Count != 1)
            {
                error = Html(
                    context,
                    ReasonCode.RedirectUriAmbiguous,
                    OAuthErrorCode.InvalidRequest,
                    "'redirect_uri' is required: this client does not have exactly one registered.",
                    $"client_id={client.ClientId.Value}; registered={client.RedirectUris.Count}");
                return false;
            }

            if (!TryMatchRegistered(client.RedirectUris[0], out var only))
            {
                error = Html(
                    context,
                    ReasonCode.RedirectUriRegistrationUnusable,
                    OAuthErrorCode.InvalidRequest,
                    "The registered redirect URI is unusable.",
                    $"client_id={client.ClientId.Value}; registered={client.RedirectUris[0].Value}");
                return false;
            }

            context.Redirect = only;
            redirect = only;
            return true;
        }

        if (raw.Length == 0)
        {
            // Present and empty is malformed, not omitted. RFC 6749 §3.1.2.3's permission is for a
            // parameter that is *absent*; an empty value is a client that built its URL wrongly, and
            // silently substituting the registered URI hides that from whoever has to debug it.
            error = Html(
                context,
                ReasonCode.RedirectUriEmpty,
                OAuthErrorCode.InvalidRequest,
                "The 'redirect_uri' parameter is empty.",
                $"client_id={client.ClientId.Value}");
            return false;
        }

        if (!RequestedRedirectUri.TryParse(raw, out var requested, out var parseError))
        {
            error = Html(
                context,
                ReasonCode.RedirectUriMalformed,
                OAuthErrorCode.InvalidRequest,
                $"The 'redirect_uri' is invalid ({parseError}).",
                $"client_id={client.ClientId.Value}; requested={raw}");
            return false;
        }

        if (!ValidatedRedirect.From(RedirectUriMatcher.Match(requested.Value, client.RedirectUris), out var matched))
        {
            // Deliberately says nothing about WHICH registered URI was close. A diff would let a
            // caller enumerate the registrations one character at a time.
            // The log gets what the response withholds. The response says nothing about WHICH
            // registration was close, because a diff lets a caller enumerate the registrations one
            // character at a time; the operator holding the log already knows them, and the one
            // question they have — "is this the port, the trailing slash, or a different host" — needs
            // both strings side by side.
            error = Html(
                context,
                ReasonCode.RedirectUriMismatch,
                OAuthErrorCode.InvalidRequest,
                "The 'redirect_uri' does not match any registered for this client.",
                $"client_id={client.ClientId.Value}; requested={raw}; registered={string.Join(' ', client.RedirectUris.Select(u => u.Value))}");
            return false;
        }

        context.Redirect = matched;
        redirect = matched;
        return true;
    }

    /// <summary>Stage 4: <c>response_type</c>. X-05, X-07.</summary>
    private static AuthorizeOutcome.Redirect? ValidateResponseType(AuthorizeContext context, ValidatedRedirect redirect)
    {
        if (!context.Parameters.TrySingle("response_type", out var responseType))
        {
            return Redirect(
                context,
                redirect,
                ReasonCode.RepeatedParameter,
                OAuthErrorCode.InvalidRequest,
                "The 'response_type' parameter appeared more than once.",
                "parameter=response_type");
        }

        // Absent is `invalid_request`, not `unsupported_response_type`. RFC 6749 §4.1.2.1 reserves
        // the latter for "obtaining an authorization code using this method", which presupposes a
        // method was named — and the two codes send a client debugging in different directions.
        if (string.IsNullOrEmpty(responseType))
        {
            return Redirect(
                context,
                redirect,
                ReasonCode.ResponseTypeMissing,
                OAuthErrorCode.InvalidRequest,
                "The 'response_type' parameter is required.");
        }

        // `code` and nothing else. OAuth 2.1 §10 removes the implicit grant, so `token` and
        // `id_token token` are not "unsupported here" — they no longer exist.
        if (!string.Equals(responseType, "code", StringComparison.Ordinal))
        {
            return Redirect(
                context,
                redirect,
                ReasonCode.ResponseTypeUnsupported,
                OAuthErrorCode.UnsupportedResponseType,
                "Only the authorization code flow is supported; 'response_type' must be 'code'.",
                $"response_type={responseType}");
        }

        var client = context.Client!;

        if (client.GrantTypes.Count > 0 && !client.GrantTypes.Contains("authorization_code", StringComparer.Ordinal))
        {
            return Redirect(
                context,
                redirect,
                ReasonCode.ClientNotRegisteredForGrantType,
                OAuthErrorCode.UnauthorizedClient,
                "This client is not registered for the authorization code grant.",
                $"client_id={client.ClientId.Value}; grant_types={string.Join(' ', client.GrantTypes)}");
        }

        // The second half of X-05, and a separate declaration from the grant type: a client may
        // declare `grant_types: ["authorization_code"]` alongside `response_types: ["token"]`, and
        // issuing it a code honours neither half of what it said about itself.
        //
        // An empty list means "did not say", which C-14 requires be read as permission rather than
        // refusal — a client that declares nothing is a client that also works elsewhere.
        if (client.ResponseTypes.Count > 0 && !client.ResponseTypes.Contains("code", StringComparer.Ordinal))
        {
            return Redirect(
                context,
                redirect,
                ReasonCode.ClientNotRegisteredForResponseType,
                OAuthErrorCode.UnauthorizedClient,
                "This client is not registered for the 'code' response type.",
                $"client_id={client.ClientId.Value}; response_types={string.Join(' ', client.ResponseTypes)}");
        }

        return null;
    }

    /// <summary>Stage 5: PKCE. N-02, X-04.</summary>
    private static AuthorizeOutcome.Redirect? ValidatePkce(AuthorizeContext context, ValidatedRedirect redirect)
    {
        if (!context.Parameters.TrySingle("code_challenge", out var challenge)
            || !context.Parameters.TrySingle("code_challenge_method", out var method))
        {
            return Redirect(
                context,
                redirect,
                ReasonCode.RepeatedParameter,
                OAuthErrorCode.InvalidRequest,
                "A PKCE parameter appeared more than once.",
                "parameter=code_challenge|code_challenge_method");
        }

        // Required for every client, with no carve-out. OAuth 2.1 draft-15 offers one for
        // confidential clients using the OIDC nonce, and it is not taken: §4.1.3's final bullet
        // makes a code issued under that carve-out unredeemable, so the draft contradicts itself
        // there. Requiring it universally also removes the attacker-controllable flag that the
        // downgrade attack targets.
        if (string.IsNullOrEmpty(challenge))
        {
            return Redirect(
                context,
                redirect,
                ReasonCode.PkceChallengeMissing,
                OAuthErrorCode.InvalidRequest,
                "PKCE is required: 'code_challenge' is missing.");
        }

        var parsedMethod = CodeChallenge.ParseMethod(method);

        if (parsedMethod is CodeChallengeMethod.None)
        {
            // An absent method is refused rather than defaulted to `plain`, which is what RFC 7636
            // §4.3 says it means. Under `plain` the challenge IS the verifier, so anyone who can
            // read the authorization request can redeem the code — and the parameter an attacker
            // can strip must not be the one that selects the weaker mode.
            //
            // The offending value is not quoted back. It is caller-controlled, and naming the one
            // supported method is the whole of what a client needs to fix its request.
            return Redirect(
                context,
                redirect,
                ReasonCode.PkceMethodUnsupported,
                OAuthErrorCode.InvalidRequest,
                "'code_challenge_method' is required and must be 'S256'.",
                // Quoted into the log and not into the response, which is the split the comment above
                // is about: the client needs the one supported method named, and nothing else; the
                // operator needs to know whether a fleet is sending `plain` or sending nothing.
                method is null ? "code_challenge_method absent" : $"code_challenge_method={method}");
        }

        if (!CodeChallenge.TryParse(challenge, parsedMethod, out var parsed))
        {
            return Redirect(
                context,
                redirect,
                ReasonCode.PkceChallengeMalformed,
                OAuthErrorCode.InvalidRequest,
                "'code_challenge' must be 43 characters of unpadded base64url (RFC 7636 §4.2).",
                // The length, not the value. A code_challenge is not itself a secret — it is the
                // public half — but it identifies one, and the length is the whole diagnosis.
                $"code_challenge_length={challenge.Length}");
        }

        context.Challenge = parsed;
        return null;
    }

    /// <summary>Stage 6: scopes. X-08.</summary>
    private AuthorizeOutcome.Redirect? ValidateScope(AuthorizeContext context, ValidatedRedirect redirect)
    {
        if (!context.Parameters.TrySingle("scope", out var raw))
        {
            return Redirect(
                context,
                redirect,
                ReasonCode.RepeatedParameter,
                OAuthErrorCode.InvalidRequest,
                "The 'scope' parameter appeared more than once.",
                "parameter=scope");
        }

        if (!ScopeSet.TryParse(raw, out var requested, out _))
        {
            // The invalid token is not quoted back. RFC 6749 §3.3's scope-token grammar admits '<',
            // '>' and '/', so an unfiltered echo is a caller-chosen payload on the error page —
            // measured, `scope=<script>alert(1)</script>` came back whole.
            return Redirect(
                context,
                redirect,
                ReasonCode.ScopeMalformed,
                OAuthErrorCode.InvalidScope,
                "The 'scope' parameter contains an invalid value.",
                // Echoed to the log and never to the response. The measured payload that motivated
                // withholding it — `scope=<script>alert(1)</script>` — came back whole in the body;
                // in a log field with the control characters stripped it is just the input.
                $"scope={raw}");
        }

        if (requested.Except(supportedScopes).Count > 0)
        {
            return Redirect(
                context,
                redirect,
                ReasonCode.ScopeUnsupported,
                OAuthErrorCode.InvalidScope,
                "One or more requested scopes are not supported.",
                $"unsupported={string.Join(' ', requested.Except(supportedScopes))}");
        }

        var client = context.Client!;
        if (!client.AllowedScopes.IsEmpty && requested.Except(client.AllowedScopes).Count > 0)
        {
            return Redirect(
                context,
                redirect,
                ReasonCode.ScopeNotAllowedForClient,
                OAuthErrorCode.InvalidScope,
                "This client may not request one or more of those scopes.",
                $"client_id={client.ClientId.Value}; refused={string.Join(' ', requested.Except(client.AllowedScopes))}");
        }

        context.Scope = requested;
        context.IsOidc = requested.Contains("openid");
        return null;
    }

    /// <summary>Stage 7: resources. N-01, X-09.</summary>
    private async ValueTask<AuthorizeOutcome.Redirect?> ValidateResourcesAsync(
        AuthorizeContext context, ValidatedRedirect redirect, CancellationToken cancellationToken)
    {
        var client = context.Client!;
        var raw = context.Parameters.All("resource");

        if (raw.Count == 0)
        {
            // A request that asked for only OIDC's own scopes is asking to sign in, not to reach an
            // API, so it is answered before the ambiguity rule below rather than by it. The
            // distinction is the whole point: `DefaultForAsync` returns null with two registrations
            // because a request naming no resource might have meant either of them, and here it
            // cannot have meant either — there is no operation in `openid email` to perform at one.
            //
            // Measured, and this is why the branch exists: Grafana's OIDC client sends no `resource`
            // (RFC 8707 is an OAuth extension it does not implement), so on a server with two
            // registrations every sign-in died at the `invalid_target` below, naming a parameter the
            // client has no way to send and no metadata field to discover it needed.
            //
            // Both halves of the condition carry weight. `openid` present is what makes it a sign-in
            // at all; nothing outside `OidcOwnScopes` is what keeps it one. Drop the second half and
            // `scope=openid docs:write` would be audienced at the OIDC resource — a write scope
            // granted at a resource the request never named, which is the failure N-01 is about.
            if (context.IsOidc && context.Scope.Except(OidcOwnScopes).Count == 0)
            {
                var oidcDefault = await _resources.DefaultForOidcAsync(client, cancellationToken);

                if (oidcDefault is not null)
                {
                    context.Resources = [oidcDefault];
                    return null;
                }

                // Falls through on purpose. A server that nominates no OIDC resource is in exactly
                // the position it was in before this branch existed, and the answer there is the
                // ambiguity rule and its error — not a resource picked on the deployment's behalf.
            }

            // A-02: the configured default applies ONLY when none was requested, never as a
            // fallback for one that failed to resolve.
            var fallback = await _resources.DefaultForAsync(client, cancellationToken);

            if (fallback is null)
            {
                // The count is in the detail because the message says "no unambiguous default" and
                // that sentence has two causes an operator cannot tell apart from the outside: no
                // resource is registered at all, or several are and none was nominated. Those need
                // opposite fixes — register one, or name which one — and the log line that used to
                // carry only `client_id` sent people to the client to look for a bug in the party
                // that had done nothing wrong.
                var registrations = await _resources.AllAsync(cancellationToken);

                return Redirect(
                    context,
                    redirect,
                    ReasonCode.ResourceDefaultUnavailable,
                    OAuthErrorCode.InvalidTarget,
                    "The 'resource' parameter is required: this server has no unambiguous default.",
                    $"client_id={client.ClientId.Value}; registrations={registrations.Count}");
            }

            context.Resources = [fallback];
            return null;
        }

        if (raw.Count > MaxResourceValues)
        {
            return Redirect(
                context,
                redirect,
                ReasonCode.ResourceTooMany,
                OAuthErrorCode.InvalidTarget,
                $"At most {MaxResourceValues} 'resource' values may be requested at once.",
                $"requested={raw.Count}");
        }

        var resolved = new List<ResourceIdentifier>(raw.Count);
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var candidate in raw)
        {
            // Deduplicated on the raw value before the registry is asked. A repeated value is not an
            // error — RFC 8707 says nothing about it — but it should not appear twice in the grant
            // set, and it should not cost a second lookup inside the latency budget.
            if (!seen.Add(candidate))
            {
                continue;
            }

            if (!RequestedResource.TryParse(candidate, out var requested))
            {
                return Redirect(
                    context,
                    redirect,
                    ReasonCode.ResourceMalformed,
                    OAuthErrorCode.InvalidTarget,
                    "Each 'resource' must be an absolute URI with no fragment (RFC 8707 §2).",
                    $"resource={candidate}");
            }

            var resource = await _resources.ResolveAsync(requested, client, cancellationToken);

            if (resource is null)
            {
                // Unknown and not-permitted are reported identically, on purpose. Distinguishing
                // them lets a caller enumerate which resource identifiers exist, which maps the
                // customer's internal service topology.
                // The log distinguishes what the response must not. Unknown and not-permitted are one
                // answer on the wire because telling them apart maps the customer's service topology
                // for anyone who asks; the operator already has the topology and is trying to work out
                // which of the two they are looking at.
                return Redirect(
                    context,
                    redirect,
                    ReasonCode.ResourceUnavailable,
                    OAuthErrorCode.InvalidTarget,
                    "The requested 'resource' is not available to this client.",
                    $"client_id={client.ClientId.Value}; resource={requested.Value}");
            }

            resolved.Add(resource);
        }

        context.Resources = resolved;
        return null;
    }

    /// <summary>Stage 8: OIDC parameters. X-16, C-13.</summary>
    private static AuthorizeOutcome.Redirect? ValidateOidcParameters(AuthorizeContext context, ValidatedRedirect redirect)
    {
        // We publish request_parameter_supported: false and friends, so using them is a request for
        // something we said we do not do.
        foreach (var (name, code) in UnsupportedParameters)
        {
            if (context.Parameters.Contains(name))
            {
                return Redirect(
                    context,
                    redirect,
                    ReasonCode.ParameterNotSupported,
                    code,
                    $"The '{name}' parameter is not supported by this server.",
                    $"parameter={name}");
            }
        }

        if (!context.Parameters.TrySingle("nonce", out var nonce))
        {
            return Redirect(
                context,
                redirect,
                ReasonCode.RepeatedParameter,
                OAuthErrorCode.InvalidRequest,
                "The 'nonce' parameter appeared more than once.",
                "parameter=nonce");
        }

        // Never required and never invented. This is an OAuth flow unless the client asked for
        // OIDC, and both vendors' MCP clients omit `openid` entirely — requiring a nonce would
        // refuse every one of them. A server-generated nonce would be worse than none: the client
        // compares it against what it stored, so inventing one passes a replay check the client
        // believes it is performing.
        context.Nonce = nonce;

        if (!context.Parameters.TrySingle("prompt", out var prompt))
        {
            return Redirect(
                context,
                redirect,
                ReasonCode.RepeatedParameter,
                OAuthErrorCode.InvalidRequest,
                "The 'prompt' parameter appeared more than once.",
                "parameter=prompt");
        }

        if (!string.IsNullOrEmpty(prompt))
        {
            var values = prompt.Split(' ', StringSplitOptions.RemoveEmptyEntries);

            // OIDC Core §3.1.2.1: `none` must not be combined with anything else, because the
            // combination asks for both "do not interact" and "definitely interact".
            if (values.Contains("none", StringComparer.Ordinal) && values.Length > 1)
            {
                return Redirect(
                    context,
                    redirect,
                    ReasonCode.PromptCombinationInvalid,
                    OAuthErrorCode.InvalidRequest,
                    "'prompt=none' cannot be combined with other prompt values.",
                    $"prompt={prompt}");
            }

            // Carried, not dropped. Stage 9 needs `login` to force re-authentication and stage 10
            // needs `consent` to force re-consent; without this the validation above is dead code
            // and those stages would have to re-read the raw parameters.
            context.Prompt = values;
        }

        if (!context.Parameters.TrySingle("max_age", out var maxAge))
        {
            return Redirect(
                context,
                redirect,
                ReasonCode.RepeatedParameter,
                OAuthErrorCode.InvalidRequest,
                "The 'max_age' parameter appeared more than once.",
                "parameter=max_age");
        }

        if (!string.IsNullOrEmpty(maxAge))
        {
            // NumberStyles.None, so a sign, a decimal point and surrounding whitespace are all
            // refused rather than parsed into something plausible.
            // NumberStyles.None, so a sign, a decimal point and surrounding whitespace are all
            // refused rather than parsed into something plausible.
            //
            // The upper bound is not decoration. `long` accepts up to 9.2e18 and
            // TimeSpan.FromSeconds throws above 922337203685 — so before this check, max_age
            // 922337203686 left the pipeline through the exception boundary as `server_error`,
            // telling the client the server broke when the request was malformed, and writing one
            // unbounded "unhandled exception" log line per request for any caller who asked.
            // X-04 says an out-of-range max_age is invalid_request.
            if (!long.TryParse(maxAge, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)
                || seconds > MaxMaxAgeSeconds)
            {
                return Redirect(
                    context,
                    redirect,
                    ReasonCode.MaxAgeInvalid,
                    OAuthErrorCode.InvalidRequest,
                    "'max_age' must be a non-negative number of seconds.",
                    $"max_age={maxAge}");
            }

            context.MaxAge = TimeSpan.FromSeconds(seconds);
        }

        return null;
    }

    private static readonly (string Name, OAuthErrorCode Code)[] UnsupportedParameters =
    [
        ("request", OAuthErrorCode.RequestNotSupported),
        ("request_uri", OAuthErrorCode.RequestUriNotSupported),
        ("registration", OAuthErrorCode.RegistrationNotSupported),
    ];

    /// <summary>
    /// Run a registration back through the matcher, so there is one production site.
    /// </summary>
    /// <remarks>
    /// The <c>TryParse</c> result is honoured. It used to be discarded and the out-parameter
    /// dereferenced, which meant a client record holding a <c>default(RegisteredRedirectUri)</c> —
    /// constructible by any <see cref="IClientResolver"/>, since the struct is public and the list
    /// is unvalidated — threw out of <c>/authorize</c> before the redirect line, where there is not
    /// even a <c>server_error</c> redirect to fall back to.
    /// </remarks>
    private static bool TryMatchRegistered(
        RegisteredRedirectUri registered, [NotNullWhen(true)] out ValidatedRedirect? redirect)
    {
        redirect = null;

        if (!RequestedRedirectUri.TryParse(registered.Value, out var requested, out _))
        {
            return false;
        }

        return ValidatedRedirect.From(RedirectUriMatcher.Match(requested.Value, [registered]), out redirect);
    }

    /// <summary>
    /// Build the pre-redirect refusal. A-09's payload is a parameter, not an afterthought.
    /// </summary>
    /// <remarks>
    /// <paramref name="detail"/> is the half the client never sees, and every stage that has
    /// something an operator would want passes one. It is filtered for control characters inside
    /// <see cref="Rejection.Of"/> — several of these carry a caller-supplied <c>client_id</c> or
    /// <c>redirect_uri</c>, and a CR/LF pair in a log field is a forged second line.
    /// </remarks>
    private static AuthorizeOutcome.Html Html(
        AuthorizeContext context, ReasonCode reason, OAuthErrorCode code, string description, string? detail = null) =>
        new(new AuthorizeHtmlError(Rejection.Of(reason, code, description, detail), context.CorrelationId));

    private static AuthorizeOutcome.Redirect Redirect(
        AuthorizeContext context,
        ValidatedRedirect redirect,
        ReasonCode reason,
        OAuthErrorCode code,
        string description,
        string? detail = null) =>
        new(AuthorizeRedirectError.Create(
            redirect, Rejection.Of(reason, code, description, detail), context.State, context.Issuer, context.CorrelationId));
}
