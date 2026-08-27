using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Authorize;
using Boltway.OAuth.Primitives.Errors;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The authorize pipeline, stage by stage, with the ordering property first.
/// </summary>
public sealed class AuthorizePipelineTests
{
    private static async Task<AuthorizeOutcome> RunAsync(
        Dictionary<string, string[]> parameters, AuthorizePipeline? pipeline = null) =>
        await (pipeline ?? Build.Pipeline()).ValidateAsync(Build.Context(parameters), CancellationToken.None);

    private static Dictionary<string, string[]> Without(string parameter)
    {
        var request = Build.ValidRequest();
        request.Remove(parameter);
        return request;
    }

    private static Dictionary<string, string[]> With(string parameter, params string[] values)
    {
        var request = Build.ValidRequest();
        request[parameter] = values;
        return request;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The ordering property. Everything else in this file is a detail by comparison.
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Anything that fails before the redirect URI is trusted must be HTML, never a redirect.
    /// </summary>
    /// <remarks>
    /// The failure this guards against is an open redirector on a domain the user has been taught
    /// to trust, which also leaks <c>state</c>. It is enumerated rather than spot-checked because
    /// the property is about the <i>set</i> of pre-trust failures: a new one added later is only
    /// safe if it lands in this list.
    /// </remarks>
    [Theory]
    [InlineData("client_id", "the client is unknown")]
    [InlineData("redirect_uri", "the redirect URI is unregistered")]
    public async Task Failures_before_the_redirect_is_validated_are_html(string parameter, string why)
    {
        var request = With(parameter, "https://attacker.example/steal");

        var outcome = await RunAsync(request);

        var html = Assert.IsType<AuthorizeOutcome.Html>(outcome);
        Assert.Equal("test-correlation", html.Error.CorrelationId);
        Assert.False(string.IsNullOrWhiteSpace(why));
    }

    /// <summary>
    /// An unregistered redirect URI never reaches a stage that could redirect to it.
    /// </summary>
    /// <remarks>
    /// The sharpest version of the same property: the request below is invalid in <i>four</i> later
    /// ways at once (no PKCE, an implicit response type, an unknown scope, an unknown resource). If
    /// any of those stages ran first, the answer would be a redirect carrying an OAuth error to an
    /// address the attacker chose. The stage that fails is the redirect URI, and the answer is HTML.
    /// </remarks>
    [Fact]
    public async Task An_attacker_controlled_redirect_uri_cannot_be_reached_by_a_later_failure()
    {
        var request = Build.ValidRequest();
        request["redirect_uri"] = ["https://attacker.example/steal"];
        request["response_type"] = ["token"];
        request.Remove("code_challenge");
        request["scope"] = ["nonexistent:scope"];
        request["resource"] = ["https://nonexistent.example/api"];

        var outcome = await RunAsync(request);

        var html = Assert.IsType<AuthorizeOutcome.Html>(outcome);
        Assert.Equal(OAuthErrorCode.InvalidRequest, html.Error.Code);
        Assert.DoesNotContain("attacker.example", html.Error.Description, StringComparison.Ordinal);
    }

    /// <summary>
    /// The HTML error names no registered redirect URI, so it is not an enumeration oracle.
    /// </summary>
    [Fact]
    public async Task A_redirect_mismatch_does_not_disclose_what_was_registered()
    {
        var client = Build.Client(redirectUris: ["https://claude.ai/api/mcp/auth_callback", "https://claude.ai/other"]);
        var pipeline = Build.Pipeline(new TestClientResolver(client));

        var outcome = await RunAsync(With("redirect_uri", "https://claude.ai/api/mcp/auth_callbacX"), pipeline);

        var html = Assert.IsType<AuthorizeOutcome.Html>(outcome);
        Assert.DoesNotContain("auth_callback", html.Error.Description, StringComparison.Ordinal);
        Assert.DoesNotContain("other", html.Error.Description, StringComparison.Ordinal);
    }

    /// <summary>
    /// Failures after the redirect is trusted redirect, and carry <c>state</c> and <c>iss</c>.
    /// </summary>
    /// <remarks>
    /// <c>iss</c> is asserted on an <b>error</b> response on purpose. RFC 9207's mix-up defence
    /// works by letting the client see which server answered, and an error response is as useful to
    /// that attack as a successful one - a client that saw
    /// <c>authorization_response_iss_parameter_supported</c> and then a response without <c>iss</c>
    /// must reject it, so omitting it here would break the flow rather than merely weaken it.
    /// </remarks>
    [Theory]
    [InlineData("response_type", "token", OAuthErrorCode.UnsupportedResponseType)]
    [InlineData("scope", "unknown:scope", OAuthErrorCode.InvalidScope)]
    [InlineData("resource", "https://elsewhere.example/api", OAuthErrorCode.InvalidTarget)]
    [InlineData("code_challenge_method", "plain", OAuthErrorCode.InvalidRequest)]
    public async Task Failures_after_the_redirect_is_validated_redirect_with_state_and_iss(
        string parameter, string value, OAuthErrorCode expected)
    {
        var outcome = await RunAsync(With(parameter, value));

        var redirect = Assert.IsType<AuthorizeOutcome.Redirect>(outcome);
        Assert.Equal(expected, redirect.Error.Code);
        Assert.Equal("opaque-state", redirect.Error.State);
        Assert.Equal(Build.Issuer, redirect.Error.Issuer.Value);
        Assert.Equal("https://claude.ai/api/mcp/auth_callback", redirect.Error.Target.Value);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Repeated parameters
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A repeated parameter is refused, not silently resolved to one of its values.
    /// </summary>
    /// <remarks>
    /// The reason to test every name rather than one: which value a framework binds for a repeated
    /// parameter is a framework detail, and an attacker who can append a second
    /// <c>redirect_uri</c> to a URL is asking exactly that question. "First wins" and "last wins"
    /// are both exploitable; only refusing is not.
    /// </remarks>
    [Theory]
    [InlineData("client_id")]
    [InlineData("redirect_uri")]
    [InlineData("response_type")]
    [InlineData("code_challenge")]
    [InlineData("code_challenge_method")]
    [InlineData("scope")]
    [InlineData("state")]
    [InlineData("nonce")]
    [InlineData("prompt")]
    [InlineData("max_age")]
    public async Task A_repeated_parameter_is_refused(string parameter)
    {
        var request = Build.ValidRequest();
        request[parameter] = ["a", "b"];

        var outcome = await RunAsync(request);

        var code = outcome switch
        {
            AuthorizeOutcome.Html html => html.Error.Code,
            AuthorizeOutcome.Redirect redirect => redirect.Error.Code,
            _ => OAuthErrorCode.None,
        };

        Assert.Equal(OAuthErrorCode.InvalidRequest, code);
    }

    /// <summary>
    /// <c>resource</c> is the exception: RFC 8707 §2 permits repetition.
    /// </summary>
    [Fact]
    public async Task Resource_may_repeat()
    {
        var registry = new TestResourceRegistry()
            .Add(Build.Resource, "mcp:tools")
            .Add("https://second.example/api", "mcp:tools");

        var request = With("resource", Build.Resource, "https://second.example/api");

        var outcome = await RunAsync(request, Build.Pipeline(resources: registry));

        var validated = Assert.IsType<AuthorizeOutcome.Validated>(outcome);
        Assert.Equal(2, validated.Context.Resources.Count);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PKCE
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>PKCE is required, with no client-type carve-out.</summary>
    [Theory]
    [InlineData(ClientType.Public)]
    [InlineData(ClientType.Confidential)]
    public async Task Pkce_is_required_for_every_client_type(ClientType type)
    {
        var pipeline = Build.Pipeline(new TestClientResolver(Build.Client(type: type)));

        var outcome = await RunAsync(Without("code_challenge"), pipeline);

        var redirect = Assert.IsType<AuthorizeOutcome.Redirect>(outcome);
        Assert.Equal(OAuthErrorCode.InvalidRequest, redirect.Error.Code);
    }

    /// <summary>
    /// An absent <c>code_challenge_method</c> is refused rather than defaulted to <c>plain</c>.
    /// </summary>
    /// <remarks>
    /// RFC 7636 §4.3 says absent means <c>plain</c>, under which the challenge <i>is</i> the
    /// verifier - so anyone who can read the authorization request can redeem the code. The
    /// parameter an attacker can strip must not be the one that selects the weaker mode.
    /// </remarks>
    [Fact]
    public async Task An_absent_challenge_method_is_not_plain()
    {
        var outcome = await RunAsync(Without("code_challenge_method"));

        var redirect = Assert.IsType<AuthorizeOutcome.Redirect>(outcome);
        Assert.Equal(OAuthErrorCode.InvalidRequest, redirect.Error.Code);
        Assert.Contains("S256", redirect.Error.Description, StringComparison.Ordinal);
    }

    /// <summary>A challenge that is not 43 characters of base64url is refused.</summary>
    [Theory]
    [InlineData("too-short")]
    [InlineData("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM=")]
    [InlineData("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM")]
    [InlineData("")]
    public async Task A_malformed_challenge_is_refused(string challenge)
    {
        var outcome = await RunAsync(With("code_challenge", challenge));

        var redirect = Assert.IsType<AuthorizeOutcome.Redirect>(outcome);
        Assert.Equal(OAuthErrorCode.InvalidRequest, redirect.Error.Code);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Response type, scope, resource, OIDC
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>OAuth 2.1 removed the implicit grant, so these are not "unsupported here".</summary>
    [Theory]
    [InlineData("token")]
    [InlineData("id_token")]
    [InlineData("id_token token")]
    [InlineData("code token")]
    [InlineData("CODE")]
    public async Task Only_the_code_response_type_is_accepted(string responseType)
    {
        var outcome = await RunAsync(With("response_type", responseType));

        var redirect = Assert.IsType<AuthorizeOutcome.Redirect>(outcome);
        Assert.Equal(OAuthErrorCode.UnsupportedResponseType, redirect.Error.Code);
    }

    /// <summary>A client that did not register the code grant is refused, and not as invalid_request.</summary>
    [Fact]
    public async Task A_client_without_the_code_grant_is_unauthorized_client()
    {
        var client = Build.Client() with { GrantTypes = ["client_credentials"] };

        var outcome = await RunAsync(Build.ValidRequest(), Build.Pipeline(new TestClientResolver(client)));

        var redirect = Assert.IsType<AuthorizeOutcome.Redirect>(outcome);
        Assert.Equal(OAuthErrorCode.UnauthorizedClient, redirect.Error.Code);
    }

    /// <summary>A scope the client may not request is refused even though the server supports it.</summary>
    [Fact]
    public async Task A_scope_outside_the_clients_allowance_is_refused()
    {
        var client = Build.Client() with { AllowedScopes = Build.Scopes("mcp:tools") };

        var outcome = await RunAsync(With("scope", "mcp:tools story:read"), Build.Pipeline(new TestClientResolver(client)));

        var redirect = Assert.IsType<AuthorizeOutcome.Redirect>(outcome);
        Assert.Equal(OAuthErrorCode.InvalidScope, redirect.Error.Code);

        // The refused scope is deliberately NOT quoted back. RFC 6749 §3.3's scope-token grammar
        // admits '<', '>' and '/', so echoing it puts a caller-chosen payload on the error page.
        Assert.DoesNotContain("story:read", redirect.Error.Description, StringComparison.Ordinal);
    }

    /// <summary><c>openid</c> is what turns an OAuth request into an OIDC one.</summary>
    [Theory]
    [InlineData("mcp:tools", false)]
    [InlineData("openid mcp:tools", true)]
    public async Task Openid_gates_oidc(string scope, bool expected)
    {
        var outcome = await RunAsync(With("scope", scope));

        var validated = Assert.IsType<AuthorizeOutcome.Validated>(outcome);
        Assert.Equal(expected, validated.Context.IsOidc);
    }

    /// <summary>
    /// An unknown resource and a forbidden one produce the same error and the same words.
    /// </summary>
    /// <remarks>
    /// Distinguishing them turns the authorize endpoint into an enumeration oracle over the
    /// customer's internal service topology. Asserting the <i>description</i> matches, not only the
    /// code, is the point - a helpful "you may not access this resource" is the leak.
    /// </remarks>
    [Fact]
    public async Task An_unknown_resource_and_a_forbidden_one_are_indistinguishable()
    {
        var registry = new TestResourceRegistry().Add(Build.Resource, "mcp:tools").Add("https://forbidden.example/api");
        registry.Forbidden.Add("https://forbidden.example/api");

        var unknown = await RunAsync(With("resource", "https://unknown.example/api"), Build.Pipeline(resources: registry));
        var forbidden = await RunAsync(With("resource", "https://forbidden.example/api"), Build.Pipeline(resources: registry));

        var a = Assert.IsType<AuthorizeOutcome.Redirect>(unknown);
        var b = Assert.IsType<AuthorizeOutcome.Redirect>(forbidden);

        Assert.Equal(a.Error.Code, b.Error.Code);
        Assert.Equal(a.Error.Description, b.Error.Description);
    }

    /// <summary>
    /// A configured default applies only when no <c>resource</c> was sent.
    /// </summary>
    /// <remarks>
    /// A-02. Falling back to the default for a resource that failed to resolve would mint a token
    /// for an audience the client did not ask for - and the client would use it, because it looks
    /// like success.
    /// </remarks>
    [Fact]
    public async Task The_default_resource_is_not_a_fallback_for_one_that_failed()
    {
        var registry = new TestResourceRegistry().Add(Build.Resource, "mcp:tools");

        var absent = await RunAsync(Without("resource"), Build.Pipeline(resources: registry));
        var wrong = await RunAsync(With("resource", "https://elsewhere.example/api"), Build.Pipeline(resources: registry));

        var validated = Assert.IsType<AuthorizeOutcome.Validated>(absent);
        Assert.Equal(Build.Resource, Assert.Single(validated.Context.Resources).Canonical);

        var redirect = Assert.IsType<AuthorizeOutcome.Redirect>(wrong);
        Assert.Equal(OAuthErrorCode.InvalidTarget, redirect.Error.Code);
    }

    /// <summary>With no unambiguous default and no request, the answer is an error, not a guess.</summary>
    [Fact]
    public async Task Two_registered_resources_and_no_request_is_invalid_target()
    {
        var registry = new TestResourceRegistry().Add(Build.Resource).Add("https://second.example/api");

        var outcome = await RunAsync(Without("resource"), Build.Pipeline(resources: registry));

        var redirect = Assert.IsType<AuthorizeOutcome.Redirect>(outcome);
        Assert.Equal(OAuthErrorCode.InvalidTarget, redirect.Error.Code);
    }

    /// <summary>
    /// That error says how many resources are registered, because "no unambiguous default" has two
    /// causes needing opposite fixes.
    /// </summary>
    /// <remarks>
    /// None registered and several registered produce the same sentence, and the detail used to
    /// carry only <c>client_id</c> - which pointed an operator at the client, the one party in the
    /// exchange that had done nothing wrong. Zero means register a resource; two means nominate
    /// one. The count is the smallest thing that tells them apart.
    /// </remarks>
    [Fact]
    public async Task The_no_default_error_says_how_many_resources_are_registered()
    {
        var two = new TestResourceRegistry().Add(Build.Resource).Add("https://second.example/api");

        var outcome = await RunAsync(Without("resource"), Build.Pipeline(resources: two));

        var redirect = Assert.IsType<AuthorizeOutcome.Redirect>(outcome);
        Assert.Contains("registrations=2", redirect.Error.Rejection.PrivateDetail, StringComparison.Ordinal);

        // And in the log only. The client is told `invalid_target` and nothing about how many
        // resources this server has - the count is an operator's diagnostic, not a topology hint
        // for whoever can reach /authorize.
        Assert.DoesNotContain("registrations=", redirect.Error.Description, StringComparison.Ordinal);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Signing in is not reaching a resource
    //
    // An OIDC client sends no `resource`: RFC 8707 is an OAuth extension, and there is no metadata
    // field through which a server could tell it one were needed. Measured with Grafana against a
    // two-resource deployment, every sign-in died on `invalid_target` naming a parameter the client
    // had no way to send.
    //
    // The pair that matters is the first two tests below. One says the nomination works; the other
    // says it cannot be reached by a request that also asks for something at an API. Delete the
    // second and the feature becomes a way to be granted a write scope at a resource the request
    // never named, which is the whole of N-01 undone by a convenience.
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>A request for only OIDC's own scopes is audienced at the nominated resource.</summary>
    [Theory]
    [InlineData("openid")]
    [InlineData("openid email")]
    [InlineData("openid email offline_access")]
    public async Task A_sign_in_with_no_resource_gets_the_nominated_one(string scope)
    {
        var registry = new TestResourceRegistry()
            .Add(Build.Resource, "mcp:tools")
            .Add(Build.OtherResource, "users:read")
            .WithOidcDefault(Build.OtherResource);

        var request = Without("resource");
        request["scope"] = [scope];

        var outcome = await RunAsync(
            request,
            Build.Pipeline(resources: registry, supportedScopes: "openid email offline_access mcp:tools"));

        var validated = Assert.IsType<AuthorizeOutcome.Validated>(outcome);
        Assert.Equal(Build.OtherResource, Assert.Single(validated.Context.Resources).Canonical);
    }

    /// <summary>
    /// One scope outside OIDC's own, and the nomination does not apply.
    /// </summary>
    /// <remarks>
    /// The guard against widening. <c>openid mcp:tools</c> is a request to reach an API, and the
    /// ambiguity rule is right about it: a server with two registrations cannot know which one. If
    /// this passed, a client could be granted <c>mcp:tools</c> at a resource it never named by
    /// prefixing its scope list with <c>openid</c>.
    /// </remarks>
    [Theory]
    [InlineData("openid mcp:tools")]
    [InlineData("openid email mcp:tools")]
    public async Task A_scope_outside_oidcs_own_does_not_reach_the_nomination(string scope)
    {
        var registry = new TestResourceRegistry()
            .Add(Build.Resource, "mcp:tools")
            .Add(Build.OtherResource, "users:read")
            .WithOidcDefault(Build.OtherResource);

        var request = Without("resource");
        request["scope"] = [scope];

        var outcome = await RunAsync(
            request,
            Build.Pipeline(resources: registry, supportedScopes: "openid email offline_access mcp:tools"));

        var redirect = Assert.IsType<AuthorizeOutcome.Redirect>(outcome);
        Assert.Equal(OAuthErrorCode.InvalidTarget, redirect.Error.Code);
    }

    /// <summary>
    /// A request without <c>openid</c> does not reach the nomination either, whatever else it holds.
    /// </summary>
    /// <remarks>
    /// The other half of the condition. <c>email</c> and <c>offline_access</c> are in the OIDC set,
    /// so a check written as "nothing outside <c>OidcOwnScopes</c>" alone would call
    /// <c>scope=offline_access</c> a sign-in - a refresh token minted at the OIDC resource for a
    /// request that never claimed to be authenticating anyone.
    /// </remarks>
    [Theory]
    [InlineData("email")]
    [InlineData("offline_access")]
    [InlineData("email offline_access")]
    public async Task Without_openid_the_nomination_does_not_apply(string scope)
    {
        var registry = new TestResourceRegistry()
            .Add(Build.Resource, "mcp:tools")
            .Add(Build.OtherResource, "users:read")
            .WithOidcDefault(Build.OtherResource);

        var request = Without("resource");
        request["scope"] = [scope];

        var outcome = await RunAsync(
            request,
            Build.Pipeline(resources: registry, supportedScopes: "openid email offline_access mcp:tools"));

        var redirect = Assert.IsType<AuthorizeOutcome.Redirect>(outcome);
        Assert.Equal(OAuthErrorCode.InvalidTarget, redirect.Error.Code);
    }

    /// <summary>
    /// An explicit <c>resource</c> wins over the nomination, and is still checked.
    /// </summary>
    /// <remarks>
    /// A-02 one level down: the nomination is a default, and a default that could override a value
    /// the client actually sent would mint a token for an audience nobody asked for. The second
    /// half - an unregistered resource on a sign-in is still <c>invalid_target</c> - is what stops
    /// the branch from becoming a fallback for a resolution that failed.
    /// </remarks>
    [Fact]
    public async Task An_explicit_resource_beats_the_nomination_and_is_still_validated()
    {
        var registry = new TestResourceRegistry()
            .Add(Build.Resource, "mcp:tools")
            .Add(Build.OtherResource, "users:read")
            .WithOidcDefault(Build.OtherResource);

        var pipeline = Build.Pipeline(resources: registry, supportedScopes: "openid email offline_access mcp:tools");

        var named = Build.ValidRequest();
        named["scope"] = ["openid email"];
        named["resource"] = [Build.Resource];

        var unknown = Build.ValidRequest();
        unknown["scope"] = ["openid email"];
        unknown["resource"] = ["https://unregistered.example/api"];

        var validated = Assert.IsType<AuthorizeOutcome.Validated>(await RunAsync(named, pipeline));
        Assert.Equal(Build.Resource, Assert.Single(validated.Context.Resources).Canonical);

        var redirect = Assert.IsType<AuthorizeOutcome.Redirect>(await RunAsync(unknown, pipeline));
        Assert.Equal(OAuthErrorCode.InvalidTarget, redirect.Error.Code);
    }

    /// <summary>
    /// A registry that nominates nothing behaves exactly as it did before the nomination existed.
    /// </summary>
    /// <remarks>
    /// <c>DefaultForOidcAsync</c> is a default interface member returning null, so every registry
    /// written before it - including a customer's - is in this state without being recompiled. The
    /// test is here to say that "nothing changes unless you nominate one" is a property of the
    /// pipeline and not of the shipped registry's constructor.
    /// </remarks>
    [Fact]
    public async Task With_nothing_nominated_a_sign_in_is_still_invalid_target()
    {
        var registry = new TestResourceRegistry().Add(Build.Resource, "mcp:tools").Add(Build.OtherResource);

        var request = Without("resource");
        request["scope"] = ["openid email"];

        var outcome = await RunAsync(
            request,
            Build.Pipeline(resources: registry, supportedScopes: "openid email offline_access mcp:tools"));

        var redirect = Assert.IsType<AuthorizeOutcome.Redirect>(outcome);
        Assert.Equal(OAuthErrorCode.InvalidTarget, redirect.Error.Code);
    }

    /// <summary>
    /// A single-resource server keeps answering from <c>DefaultForAsync</c>, nomination or not.
    /// </summary>
    /// <remarks>
    /// A-02's single-registration case is not superseded by this feature, and a sign-in on such a
    /// server has to keep landing on the same audience as every other request - otherwise turning
    /// on an admin surface would silently move where existing OIDC tokens are valid.
    /// </remarks>
    [Fact]
    public async Task One_registration_is_unaffected_by_the_nomination()
    {
        var registry = new TestResourceRegistry().Add(Build.Resource, "mcp:tools");

        var request = Without("resource");
        request["scope"] = ["openid email"];

        var outcome = await RunAsync(
            request,
            Build.Pipeline(resources: registry, supportedScopes: "openid email offline_access mcp:tools"));

        var validated = Assert.IsType<AuthorizeOutcome.Validated>(outcome);
        Assert.Equal(Build.Resource, Assert.Single(validated.Context.Resources).Canonical);
    }

    /// <summary>The parameters we publish as unsupported get the error code that says so.</summary>
    [Theory]
    [InlineData("request", OAuthErrorCode.RequestNotSupported)]
    [InlineData("request_uri", OAuthErrorCode.RequestUriNotSupported)]
    [InlineData("registration", OAuthErrorCode.RegistrationNotSupported)]
    public async Task Unsupported_oidc_parameters_get_their_own_error_code(string parameter, OAuthErrorCode expected)
    {
        var outcome = await RunAsync(With(parameter, "anything"));

        var redirect = Assert.IsType<AuthorizeOutcome.Redirect>(outcome);
        Assert.Equal(expected, redirect.Error.Code);
    }

    /// <summary>OIDC Core §3.1.2.1: <c>none</c> cannot be combined with another prompt value.</summary>
    [Theory]
    [InlineData("none login")]
    [InlineData("login none")]
    [InlineData("none consent")]
    public async Task Prompt_none_cannot_be_combined(string prompt)
    {
        var outcome = await RunAsync(With("prompt", prompt));

        var redirect = Assert.IsType<AuthorizeOutcome.Redirect>(outcome);
        Assert.Equal(OAuthErrorCode.InvalidRequest, redirect.Error.Code);
    }

    /// <summary>A nonce is carried through untouched, and never invented.</summary>
    /// <remarks>
    /// Inventing one would be worse than omitting it: the client compares the nonce in the ID token
    /// against the value it stored, so a server-generated nonce passes a replay check the client
    /// believes it is performing.
    /// </remarks>
    [Fact]
    public async Task A_nonce_is_carried_and_never_invented()
    {
        var withNonce = await RunAsync(With("nonce", "client-nonce"));
        var without = await RunAsync(Without("nonce"));

        Assert.Equal("client-nonce", Assert.IsType<AuthorizeOutcome.Validated>(withNonce).Context.Nonce);
        Assert.Null(Assert.IsType<AuthorizeOutcome.Validated>(without).Context.Nonce);
    }

    /// <summary><c>max_age</c> must be a non-negative integer.</summary>
    [Theory]
    [InlineData("-1")]
    [InlineData("soon")]
    [InlineData("3.5")]
    public async Task A_malformed_max_age_is_refused(string maxAge)
    {
        var outcome = await RunAsync(With("max_age", maxAge));

        var redirect = Assert.IsType<AuthorizeOutcome.Redirect>(outcome);
        Assert.Equal(OAuthErrorCode.InvalidRequest, redirect.Error.Code);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Client resolution
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A resolver that recognised the identifier and failed stops the chain.
    /// </summary>
    /// <remarks>
    /// A-07. Falling through to the next resolver turns "your metadata document is malformed" into
    /// "unknown client", which is the diagnosis that costs a customer a day.
    /// </remarks>
    [Fact]
    public async Task An_authoritative_resolution_failure_does_not_fall_through()
    {
        var first = new TestClientResolver
        {
            ForcedFailure = ClientResolution.Failed(
                ClientResolutionError.MetadataUnusable, "client_id_metadata_document is missing redirect_uris."),
        };

        var second = new TestClientResolver(Build.Client());
        var pipeline = new AuthorizePipeline([first, second], new TestResourceRegistry().Add(Build.Resource), Build.Scopes("mcp:tools"));

        var outcome = await pipeline.ValidateAsync(Build.Context(Build.ValidRequest()), CancellationToken.None);

        var html = Assert.IsType<AuthorizeOutcome.Html>(outcome);
        Assert.Contains("redirect_uris", html.Error.Description, StringComparison.Ordinal);
        Assert.Empty(second.Attempted);
    }

    /// <summary>A NotFound resolution does fall through, so the resolver chain works at all.</summary>
    [Fact]
    public async Task A_not_found_resolution_falls_through_to_the_next_resolver()
    {
        var first = new TestClientResolver();
        var second = new TestClientResolver(Build.Client());
        var pipeline = new AuthorizePipeline([first, second], new TestResourceRegistry().Add(Build.Resource), Build.Scopes("mcp:tools"));

        var outcome = await pipeline.ValidateAsync(Build.Context(Build.ValidRequest()), CancellationToken.None);

        Assert.IsType<AuthorizeOutcome.Validated>(outcome);
        Assert.Single(second.Attempted);
    }

    /// <summary>A disabled client is refused, and the refusal cannot redirect.</summary>
    [Fact]
    public async Task A_disabled_client_is_refused_without_a_redirect()
    {
        var client = Build.Client() with { IsEnabled = false };

        var outcome = await RunAsync(Build.ValidRequest(), Build.Pipeline(new TestClientResolver(client)));

        var html = Assert.IsType<AuthorizeOutcome.Html>(outcome);
        Assert.Equal(OAuthErrorCode.InvalidClient, html.Error.Code);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // redirect_uri omission and the loopback exception
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Omitting <c>redirect_uri</c> works with one registration and is refused with two.
    /// </summary>
    /// <remarks>
    /// RFC 6749 §3.1.2.3. Picking one of several would let a client that later registered a second
    /// URI receive codes at whichever this server happened to sort first - a change in behaviour
    /// caused by a registration edit, with no request having changed.
    /// </remarks>
    [Fact]
    public async Task Omitting_the_redirect_uri_needs_exactly_one_registration()
    {
        var single = Build.Pipeline(new TestClientResolver(Build.Client()));
        var several = Build.Pipeline(new TestClientResolver(
            Build.Client(redirectUris: ["https://claude.ai/api/mcp/auth_callback", "https://claude.ai/other"])));

        var ok = await RunAsync(Without("redirect_uri"), single);
        var ambiguous = await RunAsync(Without("redirect_uri"), several);

        var validated = Assert.IsType<AuthorizeOutcome.Validated>(ok);
        Assert.Equal("https://claude.ai/api/mcp/auth_callback", validated.Context.Redirect!.Value);

        Assert.IsType<AuthorizeOutcome.Html>(ambiguous);
    }

    /// <summary>
    /// A loopback client redirects to the port it asked for, not the one it registered.
    /// </summary>
    /// <remarks>
    /// RFC 8252 §7.3. Claude Code registers <c>http://127.0.0.1/callback</c> and listens on an
    /// ephemeral port; redirecting to the registered string would send the browser to port 80,
    /// where nothing is listening. This is the whole reason <see cref="ValidatedRedirect.Value"/>
    /// carries the requested URI rather than the registered one.
    /// </remarks>
    [Fact]
    public async Task A_loopback_client_is_redirected_to_the_port_it_requested()
    {
        var client = Build.Client(redirectUris: ["http://127.0.0.1/callback"]);
        var request = With("redirect_uri", "http://127.0.0.1:49321/callback");

        var outcome = await RunAsync(request, Build.Pipeline(new TestClientResolver(client)));

        var validated = Assert.IsType<AuthorizeOutcome.Validated>(outcome);
        Assert.Equal("http://127.0.0.1:49321/callback", validated.Context.Redirect!.Value);
    }

    /// <summary>
    /// A request cannot promote itself into port-agnostic matching by pointing at loopback.
    /// </summary>
    [Fact]
    public async Task A_non_loopback_registration_does_not_get_the_loopback_exception()
    {
        var client = Build.Client(redirectUris: ["https://claude.ai/api/mcp/auth_callback"]);

        var outcome = await RunAsync(With("redirect_uri", "https://claude.ai:1337/api/mcp/auth_callback"),
            Build.Pipeline(new TestClientResolver(client)));

        Assert.IsType<AuthorizeOutcome.Html>(outcome);
    }

    /// <summary>A valid request produces a context every later stage can read.</summary>
    [Fact]
    public async Task A_valid_request_validates()
    {
        var outcome = await RunAsync(Build.ValidRequest());

        var context = Assert.IsType<AuthorizeOutcome.Validated>(outcome).Context;

        Assert.Equal("opaque-state", context.State);
        Assert.NotNull(context.Client);
        Assert.NotNull(context.Redirect);
        Assert.NotNull(context.Challenge);
        Assert.Equal(["mcp:tools"], context.Scope.Values);
        Assert.Equal(Build.Resource, Assert.Single(context.Resources).Canonical);
    }
}
