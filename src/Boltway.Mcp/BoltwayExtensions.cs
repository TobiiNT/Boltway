using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Boltway.OAuth.Primitives.Http;
using ModelContextProtocol;

namespace Boltway.Mcp;

/// <summary>
/// A tool refused for a reason the caller could act on — a schema violation, a missing
/// record, a credential detected on the way in.
///
/// <para>
/// The distinction that matters: this is <em>content the model reads</em>, not a transport
/// fault. A tool failure surfaced as a broken pipe cannot be corrected, and the user gets a
/// shrug instead of the sentence telling them what to fix.
/// </para>
///
/// <para>
/// <strong>It derives from <see cref="McpException"/> for a load-bearing reason.</strong>
/// The SDK returns <c>isError</c> for any exception, but it only puts the
/// <em>message</em> on the wire for this one type — every other exception is replaced with
/// "An error occurred invoking '<c>tool</c>'." That is the right default, because an
/// arbitrary exception message can carry a connection string. It also means a refusal
/// thrown as a plain <see cref="Exception"/> is silently reduced to noise: the server logs
/// the sentence it carefully wrote and the model never sees it. Deriving from
/// <see cref="Exception"/> here cost exactly that for one release, and nothing reported it
/// — the tool still "failed", just uselessly.
/// </para>
///
/// <para>
/// So: everything passed to this type is on the wire by construction. Do not put anything
/// in the message that the caller may not see.
/// </para>
/// </summary>
public class ConnectorToolException : McpException
{
    /// <summary>Refuse with a sentence the caller can act on, and a code they can branch on.</summary>
    /// <param name="reason">What is wrong and what would fix it. Reaches the model verbatim.</param>
    /// <param name="code">Machine-readable reason, e.g. <c>schema_violation</c> or <c>forbidden</c>.</param>
    public ConnectorToolException(string reason, string code = "invalid_input")
        // The code travels inside the message because that is the only field the SDK puts
        // on the wire — a property here would stay on this side of the connection.
        : base($"ToolError [{code}]: {reason}")
    {
        Code = code;
        Reason = reason;
    }

    /// <summary>Machine-readable reason, e.g. <c>schema_violation</c> or <c>forbidden</c>.</summary>
    public string Code { get; }

    /// <summary>The sentence on its own, without the code prefix that goes on the wire.</summary>
    public string Reason { get; }
}

/// <summary>
/// A tool refused because the token does not carry a scope it needs.
/// </summary>
/// <remarks>
/// <para>
/// A scope refusal and a role refusal are different answers and only one of them is worth acting
/// on: re-authorizing fixes a missing scope and cannot fix a missing role. Sharing one type and
/// one code across connectors is what lets that difference survive the trip to whoever reads it.
/// </para>
/// <para>
/// <b>This does not become an authorization challenge, and that is measured rather than assumed.</b>
/// Both channels for one are closed. The tool-level field — <c>_meta["mcp/www_authenticate"]</c> on
/// an <c>isError</c> result — is SEP-1489, a sponsored draft, absent from the <c>2025-11-25</c>
/// schema and from the draft the <c>2026-07-28</c> release candidate is cut from. And the HTTP
/// challenge the resource server writes cannot be reached from here: Streamable HTTP requires the
/// client to accept an event stream, and the transport has opened it before any tool filter runs,
/// so the status line is already <c>200</c> and already sent. <c>ToolRefusalReachTests</c> pins
/// both, and <c>spec/mcp-tool-challenge-2026-08-25.md</c> is the write-up.
/// </para>
/// <para>
/// So what a caller gets is this sentence, and the sentence is the whole of it. That is worse than
/// a challenge and better than a bare refusal, and saying which it is beats implying the other.
/// </para>
/// <para>
/// Sealed, while <see cref="ConnectorToolException"/> is not: the base is the type a connector
/// derives its own root from, and this one is a leaf whose <c>insufficient_scope</c> code means one
/// thing.
/// </para>
/// </remarks>
public sealed class InsufficientScopeException : ConnectorToolException
{
    /// <summary>Refuse, naming every scope the operation needs.</summary>
    /// <param name="required">
    /// <b>Every</b> scope the operation needs, not only the ones missing. The reason is the same one
    /// <c>X-34</c> gives for the <c>403</c> challenge, measured against a vendor client: it asks for
    /// the union of what it is told and what it already had, and does not reliably carry forward
    /// what an earlier step-up granted — so naming only the delta re-authorizes somebody into a
    /// narrower grant than they started with.
    /// </param>
    public InsufficientScopeException(params string[] required)
        : base(Describe(required), "insufficient_scope") => Required = [.. required ?? []];

    /// <summary>Every scope the refused operation needs.</summary>
    public IReadOnlyList<string> Required { get; }

    private static string Describe(string[]? required) =>
        required is { Length: > 0 }
            ? "The access token does not carry a scope this tool needs. Required: "
                + string.Join(' ', required)
                + ". Re-authorizing with those scopes is what fixes it."
            : "The access token does not carry a scope this tool needs.";
}

/// <summary>
/// The authenticated caller for one request, and whatever the connector bound to them.
///
/// <para>
/// Scoped, and populated exactly once by the middleware. Nothing about one request
/// survives into the next — that is not tidiness, it is the difference between a connector
/// that writes as the right person and one that will eventually write as the wrong one.
/// </para>
/// </summary>
public sealed class ConnectorCaller
{
    private static readonly CallerPrincipal Anonymous = new() { Actor = "anonymous" };

    /// <summary>The authenticated caller. Anonymous until the middleware resolves one.</summary>
    public CallerPrincipal Principal { get; internal set; } = Anonymous;

    /// <summary>Nothing has bound a caller to this request yet.</summary>
    /// <remarks>
    /// Reference identity against the one shared placeholder rather than a flag, so there is no
    /// second piece of state to keep true. Anywhere a request has reached a tool, this being true
    /// is a wiring problem rather than an anonymous caller.
    /// </remarks>
    internal bool IsAnonymous => ReferenceEquals(Principal, Anonymous);

    /// <summary>Whatever the connector attached at authentication time — a store, a client, a tenant.</summary>
    public object? State { get; set; }

    /// <summary>Shorthand for <see cref="CallerPrincipal.Actor"/>.</summary>
    public string Actor => Principal.Actor;

    /// <summary>Shorthand for <see cref="CallerPrincipal.Roles"/>.</summary>
    public IReadOnlyList<string> Roles => Principal.Roles;

    /// <summary>Shorthand for <see cref="CallerPrincipal.Permissions"/>.</summary>
    public IReadOnlySet<string> Permissions => Principal.Permissions;

    /// <summary>Shorthand for <see cref="CallerPrincipal.Scopes"/>.</summary>
    /// <remarks>
    /// Here for symmetry with the two above; <see cref="Grants"/> is what a tool gate should
    /// actually call. An empty set is three different situations and this property cannot say
    /// which — see <see cref="ScopeClaimState"/>.
    /// </remarks>
    public IReadOnlySet<string> Scopes => Principal.Scopes;

    /// <summary>Shorthand for <see cref="CallerPrincipal.Grants"/>.</summary>
    public bool? Grants(string scope) => Principal.Grants(scope);

    /// <summary>The bound state, or a message naming where it should have been bound.</summary>
    /// <typeparam name="T">What the connector attached at authentication time.</typeparam>
    public T StateAs<T>() where T : class =>
        State as T ?? throw new InvalidOperationException(
            $"No {typeof(T).Name} was bound to this caller. Bind it in the onAuthenticated callback of UseConnectorAuth.");
}

/// <summary>
/// Wiring for a connector: the authentication seam and the per-request caller.
///
/// <para>
/// <strong>The RFC 9728 discovery surface is not here.</strong> It used to be, and for a
/// while this repository carried two implementations of it — this one and
/// <c>Boltway.ResourceServer</c>'s. That collided by name four times in one afternoon,
/// once failing a host at startup rather than at compile time, because an unqualified call
/// to an extension method binds by namespace proximity rather than by intent.
/// </para>
///
/// <para>
/// The one that survived is the better one at the job: a challenge shape measured against
/// three vendors, RFC 9728 §3.1 path insertion, audience binding, and header values reduced
/// to the RFC 6750 §3 character set rather than escaped. The argument is the same one that
/// deleted the JavaScript transport layer — two half-supported implementations is worse than
/// one supported one, and the one nobody exercises is the one that will be wrong.
/// </para>
/// </summary>
public static class BoltwayExtensions
{
    /// <summary>
    /// Register the authentication seam and the per-request caller.
    /// </summary>
    public static IServiceCollection AddBoltway(
        this IServiceCollection services,
        IConnectorAuthenticator authenticator)
    {
        services.AddSingleton(authenticator);
        services.AddScoped<ConnectorCaller>();
        return services;
    }

    /// <summary>
    /// Bind the caller for everything under <paramref name="pathPrefix"/>, <strong>without
    /// authenticating or challenging</strong> — something upstream already did both.
    ///
    /// <para>
    /// Use this when <c>Boltway.ResourceServer</c> validates the token: it owns the
    /// 401, with the challenge shape three vendors were measured against, and a second 401
    /// written here would be the duplication this library exists to prevent. What is left
    /// for this middleware is turning the validated result into a caller the tools can read.
    /// </para>
    /// </summary>
    /// <param name="app">The application.</param>
    /// <param name="pathPrefix">Usually the MCP endpoint, <c>/mcp</c>.</param>
    /// <param name="bindState">Attach whatever the tools need for this caller.</param>
    public static IApplicationBuilder UseConnectorCaller(
        this IApplicationBuilder app,
        string pathPrefix,
        Func<HttpContext, CallerPrincipal, object?>? bindState = null)
    {
        var authenticator = app.ApplicationServices.GetRequiredService<IConnectorAuthenticator>();

        return app.Use(async (context, next) =>
        {
            if (!context.Request.Path.StartsWithSegments(pathPrefix))
            {
                await next();
                return;
            }

            // A path under the prefix that routed to nothing is not this middleware's to
            // authenticate, and demanding a token for it is how a probe becomes a 500.
            //
            // The resource server already decided this: BearerAuthenticationMiddleware passes a
            // request with no endpoint straight through and sets no token feature. This asked for
            // one anyway, so ResourceServerAuthenticator threw "No validated access token on this
            // request" — a diagnostic naming a wiring mistake, for a pipeline that is wired
            // correctly — and with no exception handler registered that reached the client as an
            // empty 500. Measured live: GET /mcp/zzq7x4v-nope returned 500 with no body, while
            // /mcphello and /nope-unrouted both returned 404, and the same path on the static-token
            // branch returned 401. Three answers to one question. A client probing paths in
            // sequence reads 500 as "the server is broken" and stops, which is the failure
            // ProtectedResourceOptions warns about.
            //
            // Falling through leaves Principal at its Anonymous default and State null — exactly
            // the state a request has when this middleware was never added — so nothing downstream
            // can mistake it for an authenticated caller, and routing answers 404 as it does for
            // every other unmapped path.
            //
            // What this cannot distinguish, measured rather than assumed (EndpointFeatureProbeTests):
            // a request that routed to nothing and a request that has not been routed yet look
            // identical — neither carries an endpoint and neither carries IEndpointFeature. So this
            // skip reads "not routed yet" as "routed to nothing". Reaching that arrangement takes an
            // explicit UseRouting() placed *after* this call; leaving UseRouting() out does not do
            // it, because a WebApplication inserts routing at the front of the pipeline. And that
            // arrangement puts UseBoltwayProtectedResource() ahead of routing too, where it
            // authenticates nothing — so the pipeline it would weaken is one that authenticates no
            // request at all today.
            if (context.GetEndpoint() is null)
            {
                await next();
                return;
            }

            var principal = await authenticator.AuthenticateAsync(context, context.RequestAborted);
            var caller = context.RequestServices.GetRequiredService<ConnectorCaller>();
            caller.Principal = principal;
            caller.State = bindState?.Invoke(context, principal);

            await next();
        });
    }

    /// <summary>
    /// Authenticate everything under <paramref name="pathPrefix"/>, refusing with a
    /// challenge that always carries the discovery pointer.
    /// </summary>
    /// <param name="app">The application.</param>
    /// <param name="pathPrefix">Usually the MCP endpoint, <c>/mcp</c>.</param>
    /// <param name="realm">Shown in the challenge. Usually the server name.</param>
    /// <param name="bindState">
    /// Attach whatever the tools need for this caller — a store, a client, a tenant.
    /// Returning null leaves <see cref="ConnectorCaller.State"/> unset.
    /// </param>
    public static IApplicationBuilder UseConnectorAuth(
        this IApplicationBuilder app,
        string pathPrefix,
        string realm,
        Func<HttpContext, CallerPrincipal, object?>? bindState = null)
    {
        var authenticator = app.ApplicationServices.GetRequiredService<IConnectorAuthenticator>();

        return app.Use(async (context, next) =>
        {
            if (!context.Request.Path.StartsWithSegments(pathPrefix))
            {
                await next();
                return;
            }

            CallerPrincipal principal;
            try
            {
                principal = await authenticator.AuthenticateAsync(context, context.RequestAborted);
            }
            catch (UnauthorizedException ex)
            {
                // A real challenge, built by the one header builder in this repository —
                // Boltway.OAuth.Primitives, which reduces every value to the RFC 6750
                // §3 character set so a quote cannot close the quoted string early and a
                // newline cannot split the response.
                //
                // Deliberately **no** `resource_metadata`. Static tokens mean there is no
                // authorization server, so there is nothing to point at — and a pointer to a
                // document naming no issuer is precisely LESSONS #8: a client told it needs a
                // token and handed a dead end that looks like a discovery chain. Saying "this
                // server has no discovery" is the honest answer, and the reason to move to
                // Boltway.ResourceServer rather than to dress this up.
                context.Response.Headers.WWWAuthenticate = WwwAuthenticate.Bearer(
                    error: "invalid_token",
                    errorDescription: ex.Message,
                    scopes: ex.Scope is { Length: > 0 } scope ? [scope] : null,
                    realm: realm);

                context.Response.Headers.AccessControlExposeHeaders = "WWW-Authenticate";

                await Results.Json(new
                {
                    error = "invalid_token",
                    error_description = ex.Message,
                    // Named rather than implied: a client that finds no pointer should stop
                    // looking for one instead of retrying discovery forever.
                    discovery = "none — this server authenticates with static tokens",
                }, statusCode: StatusCodes.Status401Unauthorized).ExecuteAsync(context);

                return;
            }

            var caller = context.RequestServices.GetRequiredService<ConnectorCaller>();
            caller.Principal = principal;
            caller.State = bindState?.Invoke(context, principal);

            await next();
        });
    }
}
