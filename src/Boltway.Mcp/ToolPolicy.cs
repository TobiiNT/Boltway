using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.Mcp;

/// <summary>
/// Whether a caller may use a tool. <b>The connector's decision, not this library's.</b>
/// </summary>
/// <remarks>
/// <para>
/// One MCP endpoint carries every tool, so a scope required on the route is the intersection of
/// what the tools need and the widest one a connector advertises is enforced by nothing - see
/// <see cref="CallerPrincipal.Scopes"/>. The per-tool decision has to happen per tool, and this is
/// where a connector puts it.
/// </para>
/// <para>
/// <b>What this library deliberately does not ship is the answer.</b> No role table, no scope
/// naming convention, no default. A deployment's role vocabulary is its own, and the fallback for a
/// scope claim is subtle enough - <see cref="ScopeClaimState"/> - that a shipped default would be
/// wrong in the fail-open direction for every consumer at once. What is shipped is the plumbing:
/// the two places the decision has to be applied, and the guarantee that it is applied to both.
/// </para>
/// <para>
/// <b>Synchronous on purpose.</b> The decision is made from what the token already said, and
/// <c>tools/list</c> asks it once per tool: a policy doing I/O per call turns a listing into
/// <i>n</i> round trips. An implementation that needs a store caches in its own constructor.
/// </para>
/// </remarks>
public interface IConnectorToolPolicy
{
    /// <summary>May <paramref name="caller"/> use <paramref name="tool"/>?</summary>
    /// <param name="caller">The authenticated caller for this request.</param>
    /// <param name="tool">The tool's protocol name, compared however the connector chooses.</param>
    /// <returns><see langword="true"/> to advertise and allow it; <see langword="false"/> for both.</returns>
    /// <remarks>
    /// Asked on both <c>tools/list</c> and <c>tools/call</c>, so a tool this refuses is neither
    /// advertised nor reachable. It is the question "may you see this at all", and it is answered
    /// without reference to what a call would carry.
    /// </remarks>
    bool Allows(CallerPrincipal caller, string tool);

    /// <summary>
    /// May <paramref name="caller"/> use <paramref name="tool"/> <em>with these arguments</em>?
    /// </summary>
    /// <param name="caller">The authenticated caller for this request.</param>
    /// <param name="tool">The tool's protocol name.</param>
    /// <param name="arguments">
    /// The arguments as they arrived, before the SDK binds them to parameters. Null when the call
    /// carried none.
    /// <para>
    /// Read-only, deliberately: the transport hands over a mutable dictionary and this seam does
    /// not pass it on. A policy decides; rewriting a caller's arguments on the way past would be a
    /// behaviour nothing downstream could see, on the one path whose job is to be reviewable.
    /// </para>
    /// </param>
    /// <returns><see langword="true"/> to allow the call.</returns>
    /// <remarks>
    /// <para>
    /// <b>Asked only on <c>tools/call</c>, and that is the shape of the question rather than a
    /// limitation.</b> A listing has no arguments, and whether somebody may see a tool does not
    /// depend on what they would pass it. So this cannot hide anything - it refuses.
    /// </para>
    /// <para>
    /// The case it exists for is an argument that names a <em>resource</em>: which host, which
    /// path, which job. An identifier that refers to something the caller may not reach is the one
    /// gate <see cref="Allows"/> cannot express, because the tool is the same tool either way - a
    /// caller allowed to poll their own long-running work and handed somebody else's identifier is
    /// refused here or nowhere.
    /// </para>
    /// <para>
    /// <b>This library reads no argument and matches nothing.</b> It hands over what arrived and
    /// keeps out of the decision: which arguments name resources, and what reaching one means, is
    /// the connector's to know. A generic matcher here would be configuration pretending to be a
    /// security boundary.
    /// </para>
    /// <para>
    /// Default <see langword="true"/>, so an implementation that only gates whole tools does not
    /// have to say so.
    /// </para>
    /// </remarks>
    bool AllowsArguments(CallerPrincipal caller, string tool, IReadOnlyDictionary<string, JsonElement>? arguments) => true;
}

/// <summary>Applies an <see cref="IConnectorToolPolicy"/> to both places it has to hold.</summary>
public static class ConnectorToolPolicyExtensions
{
    /// <summary>
    /// Filter <c>tools/list</c> and refuse <c>tools/call</c> with the registered
    /// <see cref="IConnectorToolPolicy"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Both, always, and that is the point of it being one call.</b> Filtering the listing alone
    /// produces a surface that looks gated and is not - a caller that already knows a name still
    /// reaches the tool. Gating the call alone leaves a model reading an advertised tool as a
    /// capability and retrying against something that will always refuse. Shipping them separately
    /// would let a connector wire one and believe it had both, which is the shape of <c>N-06</c> this
    /// package exists downstream of.
    /// </para>
    /// <para>
    /// <b>The caller this reads is the one on the request carrying the call</b>, which is what
    /// makes a policy decision mean anything: a token narrowed or re-issued since the client
    /// connected takes effect on the next call. That is unconditional under
    /// <c>HttpServerSessionMode.Stateless</c>, the default since the 2026-07-28 revision removed
    /// sessions from Streamable HTTP altogether. Under the stateful back-compat modes it holds
    /// unless the transport is also told to run handlers on one execution context for the whole
    /// session - an option the SDK has since obsoleted, and one that would freeze a policy's input
    /// at session start with nothing else in the pipeline failing.
    /// </para>
    /// <para>
    /// <b>Two questions, asked at the two moments they can be asked.</b>
    /// <see cref="IConnectorToolPolicy.Allows"/> runs on both the listing and the call, so refusing
    /// there hides the tool as well as blocking it.
    /// <see cref="IConnectorToolPolicy.AllowsArguments"/> runs on the call only, because a listing
    /// has no arguments - it refuses and cannot hide, which is the honest shape for a gate about
    /// which resource a call names rather than which tool it is.
    /// </para>
    /// <para>
    /// Register the policy before calling this - any lifetime, resolved per request.
    /// </para>
    /// <code>
    /// builder.Services.AddSingleton&lt;IConnectorToolPolicy, MyPolicy&gt;();
    /// builder.Services.AddMcpServer().WithHttpTransport().WithTools&lt;MyTools&gt;().WithBoltwayToolPolicy();
    /// </code>
    /// </remarks>
    /// <param name="builder">The MCP server builder.</param>
    /// <returns>The same builder.</returns>
    public static IMcpServerBuilder WithBoltwayToolPolicy(this IMcpServerBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.WithRequestFilters(filters =>
        {
            filters.AddListToolsFilter(next => async (context, ct) =>
            {
                var result = await next(context, ct);
                var (caller, policy) = Resolve(context.Services);

                // A page that filters to nothing is still a page: `nextCursor` is carried through
                // untouched so a client keeps paging rather than concluding the server has no
                // tools. Dropping the cursor here would turn a filtered first page into an empty
                // tool list.
                result.Tools = [.. result.Tools.Where(tool => policy.Allows(caller.Principal, tool.Name))];

                return result;
            });

            filters.AddCallToolFilter(next => async (context, ct) =>
            {
                var name = context.Params?.Name;

                // No name is the SDK's own error to report, not a policy decision. Refusing here
                // would answer "forbidden" to a malformed request, which sends whoever is
                // debugging it looking at their token.
                if (name is not null)
                {
                    var (caller, policy) = Resolve(context.Services);

                    if (!policy.Allows(caller.Principal, name))
                    {
                        // Named rather than hidden. Answering "unknown tool" would be untrue and
                        // would send a reader looking for a registration bug; a refusal says which
                        // boundary refused and leaves re-authorizing as something the caller can
                        // reason about.
                        throw new ConnectorToolException(
                            $"Tool `{name}` is not available to this caller. {policy.GetType().Name} refused it.",
                            "forbidden");
                    }

                    // Second, and only here: the listing had no arguments to ask about. Refusing on
                    // an argument is not the same answer as refusing the tool, and the sentences
                    // differ so a caller can tell "you may not do this at all" from "not to that".
                    if (!policy.AllowsArguments(caller.Principal, name, context.Params?.Arguments?.AsReadOnly()))
                    {
                        throw new ConnectorToolException(
                            $"Tool `{name}` is available to this caller, but not with these arguments. "
                            + $"{policy.GetType().Name} refused them.",
                            "forbidden");
                    }
                }

                return await next(context, ct);
            });
        });

        return builder;
    }

    private static (ConnectorCaller Caller, IConnectorToolPolicy Policy) Resolve(IServiceProvider? services)
    {
        if (services is null)
        {
            throw new InvalidOperationException(
                "No service provider on this MCP request, so the tool policy cannot be applied. This is a "
                + "transport wiring problem rather than a caller's.");
        }

        var caller = services.GetService<ConnectorCaller>()
            ?? throw new InvalidOperationException(
                "No ConnectorCaller is registered, so there is nobody to apply the tool policy to. Call "
                + "AddBoltway(...) during startup.");

        if (caller.IsAnonymous)
        {
            // A wiring bug, and reported as one. Answering "forbidden" would present it as the
            // caller's problem and leave it in production; treating an unbound caller as a real one
            // would apply the policy to a principal nothing authenticated.
            throw new InvalidOperationException(
                "The caller on this request was never bound, so no policy decision can be made about it. Call "
                + "UseConnectorCaller(prefix, ...) or UseConnectorAuth(prefix, ...) for the path the MCP "
                + "endpoint is mapped under, ahead of the endpoint.");
        }

        return (caller, services.GetRequiredService<IConnectorToolPolicy>());
    }
}
