using Microsoft.AspNetCore.Http;

namespace Boltway.Mcp;

/// <summary>
/// What a token said about <c>scope</c>, which is not the same question as what it granted.
/// </summary>
/// <remarks>
/// <para>
/// Three states, because collapsing them into one empty set is a fail-open. A token carrying no
/// <c>scope</c> claim and a token carrying one that granted nothing want <b>opposite</b> readings
/// from a connector: the first says the authorization server publishes no scopes and the
/// connector's own table should answer, the second says this token was written to grant nothing.
/// <see cref="CallerPrincipal.Scopes"/> is empty in both, and in a third case too — a claim this
/// library could not read.
/// </para>
/// <para>
/// The third is not hypothetical. <c>ScopeSet.TryParse</c> rejects a claim <b>whole</b> when it
/// carries any character outside RFC 6749's scope-token set, so one stray character yields the same
/// empty set as no claim at all. A connector that falls back on empty then grants <i>more</i> than
/// the token said, to a caller whose token was written to restrict them, with nothing failing.
/// Only this library knows which case produced the empty set, so only this library can name it.
/// </para>
/// <para>
/// The first rule of <c>LESSONS.md</c> is that every axis needs a third value. This is an axis with
/// three collapsed into one, on the type that decides how much authority a token carries.
/// </para>
/// </remarks>
public enum ScopeClaimState
{
    /// <summary>
    /// Not a real state, and the default so that silence is never mistaken for an answer.
    /// </summary>
    /// <remarks>
    /// An authenticator that sets <see cref="CallerPrincipal.Scopes"/> sets this beside it. One
    /// that does not leaves this here, and <see cref="CallerPrincipal.Grants"/> then answers
    /// <see langword="null"/> — the same fall-back a principal built before this existed already
    /// got, so nothing that compiled against the older shape changes behaviour.
    /// </remarks>
    Unknown = 0,

    /// <summary>
    /// The token carried no <c>scope</c> claim. Fall back to whatever the connector uses when an
    /// authorization server publishes none — the static-token path is always this.
    /// </summary>
    Absent = 1,

    /// <summary>
    /// The token carried a <c>scope</c> claim and it was read.
    /// <see cref="CallerPrincipal.Scopes"/> is exactly what it granted, and may be empty — a token
    /// that granted nothing is a refusal, not an absence.
    /// </summary>
    Readable = 2,

    /// <summary>
    /// The token carried a <c>scope</c> claim that could not be read.
    /// </summary>
    /// <remarks>
    /// <b>Never fall back on this.</b> The claim exists, so the authorization server had something
    /// to say about this caller's authority; what is missing is our ability to read it, and reading
    /// less than a token said is the safe direction while granting more is not.
    /// </remarks>
    Unreadable = 3,
}

/// <summary>Who the transport authenticated, and what they may do.</summary>
public sealed class CallerPrincipal
{
    /// <summary>
    /// Stable handle for the person. What a connector attributes this request's writes to —
    /// though whether it actually does is the connector's to deliver, not this library's to
    /// claim. See <see cref="Email"/>.
    /// </summary>
    public required string Actor { get; init; }

    /// <summary>
    /// Address to attribute a downstream write to, when the store records one — git wants a
    /// name and an email on every commit.
    ///
    /// <para>
    /// Null means unknown, and a connector should then leave the field unset rather than
    /// synthesise something plausible. An invented author is worse than an absent one: it
    /// is indistinguishable from a real one, so the trail stops being evidence for every
    /// entry rather than just this one.
    /// </para>
    /// </summary>
    public string? Email { get; init; }

    /// <summary>
    /// Whatever role vocabulary the connector uses. This library does not interpret it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This was a single string, and widening it was a change to both halves at once.</b> The
    /// authorization server's <c>IUserStore</c> said so from the other side: it stored one role
    /// because <c>FromClaims</c> read the claim with <c>FindFirst</c>, which takes one value and
    /// ignores the rest, so a set stored there would have produced tokens whose second and third
    /// roles were dropped by the only consumer shipped here — a rule existing on one surface and
    /// not the other. Both halves moved together.
    /// </para>
    /// <para>
    /// Empty for a caller holding none, never null. A connector deciding what that means — a floor,
    /// a refusal, an empty view — is the connector's decision and not this library's.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string> Roles { get; init; } = [];

    /// <summary>
    /// What those roles stand for, if the authorization server resolved them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Uninterpreted here, like everything else about a role. A server that keeps role definitions
    /// can put the resolved set in the token, which saves the resource server a lookup it would
    /// otherwise have to make on every call — and costs the freshness of one, because a token
    /// carries what was true when it was minted.
    /// </para>
    /// <para>
    /// <b>Empty means "the token said nothing", not "this caller may do nothing".</b> A connector
    /// with its own role table falls back to that table when this is empty, which is the same
    /// arrangement a static-token deployment has always had. Treating empty as a refusal would make
    /// every connector break the day it pointed at a server that does not publish permissions.
    /// </para>
    /// </remarks>
    public IReadOnlySet<string> Permissions { get; init; } = new HashSet<string>(StringComparer.Ordinal);

    /// <summary>
    /// The scopes the access token actually carried.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>RequireScope</c> on an endpoint answers "may this request reach the server at all". It
    /// cannot answer "may this request write", because one MCP endpoint carries every tool: a
    /// required scope there is the intersection of what the tools need, so the widest scope a
    /// connector advertises is enforced by nothing. That gap is not visible from the endpoint —
    /// the metadata document lists the scope, the consent screen shows it, the user agrees to it,
    /// and withdrawing it takes no capability away. Carrying the granted set here is what lets a
    /// connector gate a tool on it.
    /// </para>
    /// <para>
    /// <b>Empty does not mean the token carried no <c>scope</c> claim.</b> It is also what a claim
    /// granting nothing produces, and what an unreadable claim produces. This property cannot tell
    /// them apart and never could; <see cref="ScopeClaim"/> is the field that does, and
    /// <see cref="Grants"/> is the read that cannot get it wrong. Branching on
    /// <c>Scopes.Count == 0</c> is the fail-open <see cref="ScopeClaimState"/> exists to close.
    /// </para>
    /// </remarks>
    public IReadOnlySet<string> Scopes { get; init; } = new HashSet<string>(StringComparer.Ordinal);

    /// <summary>
    /// Which of the three things an empty <see cref="Scopes"/> means.
    /// </summary>
    public ScopeClaimState ScopeClaim { get; init; }

    /// <summary>
    /// Does this caller hold <paramref name="scope"/>, or is there no readable claim to judge by?
    /// </summary>
    /// <param name="scope">The scope name, compared ordinally.</param>
    /// <returns>
    /// <see langword="true"/> when a readable claim carried it; <see langword="false"/> when a
    /// readable claim did not, or when the claim could not be read; <see langword="null"/> when
    /// there was no claim at all, and the connector's own table has to answer.
    /// </returns>
    /// <remarks>
    /// <para>
    /// <b>The nullable return is the point, not an inconvenience.</b> <c>bool?</c> does not
    /// convert to <c>bool</c>, so <c>if (!caller.Grants("x"))</c> does not compile: the third case
    /// cannot be silently folded into either of the other two. That is the same trick
    /// <c>AccessTokenDescriptor.Audience</c> plays with N-01 — a rule that stops being a rule and
    /// becomes a fact about the type system.
    /// </para>
    /// <para>
    /// <see cref="ScopeClaimState.Unreadable"/> answers <see langword="false"/> rather than
    /// <see langword="null"/>, deliberately. A claim that exists but cannot be read is not an
    /// absent one, and treating it as absent is exactly the fail-open this method was added to
    /// remove.
    /// </para>
    /// </remarks>
    public bool? Grants(string scope)
    {
        ArgumentNullException.ThrowIfNull(scope);

        return ScopeClaim switch
        {
            ScopeClaimState.Readable => Scopes.Contains(scope),
            ScopeClaimState.Unreadable => false,

            // Absent, and Unknown: an authenticator that said nothing is not evidence of a
            // restriction. Both fall back, which is what a principal built before ScopeClaim
            // existed already did.
            _ => null,
        };
    }

    /// <summary>
    /// The caller's own credential for whatever the connector writes to.
    ///
    /// Carrying the caller's token rather than a service account's is what makes an audit
    /// trail worth having: a store where every change is authored by the connector has a
    /// log, not an audit trail.
    /// </summary>
    public string? DownstreamToken { get; init; }

    /// <summary>
    /// Which client the token was minted for — the <c>client_id</c> claim, RFC 9068 §2.2.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Distinct from <see cref="Actor"/>, and a connector writing an audit trail wants both: one
    /// says who, the other says what they were using. The caller does not get to choose what it
    /// says — the signature was checked before this was read — which is what separates it from a
    /// user agent or anything else self-reported.
    /// </para>
    /// <para>
    /// <b>Stored verbatim, and never normalised.</b> Not lowercased, not trimmed, not
    /// URL-canonicalised. It is a surface rather than a model: a consumer writes it into the commit
    /// trailer that answers "which application made this change", so a value this library tidied
    /// would silently rewrite what that history means. Mapping one form to another is
    /// <c>assumed</c> recorded as <c>measured</c>.
    /// </para>
    /// <para>
    /// Null when the authenticator did not learn one — the static-token path has no authorization
    /// server to mint anything. Null is what a connector should record, for the reason
    /// <see cref="Email"/> gives: an invented value cannot be told from a real one, so guessing
    /// costs the trail its worth on every entry rather than only this one.
    /// </para>
    /// </remarks>
    public string? ClientId { get; init; }

    /// <summary>
    /// Which <em>token</em> this is — the <c>jti</c> claim.
    /// </summary>
    /// <remarks>
    /// <b>Not a session identifier, and the difference is the whole reason this is a separate
    /// property from <see cref="GrantId"/>.</b> A fresh <c>jti</c> is minted for every access
    /// token, so it changes on every refresh: a connector that groups its audit records by this
    /// finds them fragmenting into pieces the length of one token lifetime, with nothing failing.
    /// What it is good for is correlating one token — a revocation, a single rejected call.
    /// </remarks>
    public string? TokenId { get; init; }

    /// <summary>
    /// Which <em>authorization</em> this is — the <c>gid</c> claim, stable across a whole refresh
    /// family.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The grouping key an audit trail actually wants: every token minted from one grant carries
    /// the same value, so "what did this session do" is a query rather than a reconstruction.
    /// </para>
    /// <para>
    /// <c>gid</c> is this project's own claim rather than a registered one, so it is null against
    /// an authorization server that does not emit it. A deployment whose server names it something
    /// else supplies its own mapping through the <see cref="ResourceServerAuthenticator"/>
    /// constructor rather than reaching for a parameter here — the shipped reader stays the one
    /// that matches the tokens this project mints.
    /// </para>
    /// </remarks>
    public string? GrantId { get; init; }

    /// <summary>Anything else the authenticator learned. This library does not interpret it.</summary>
    public IReadOnlyDictionary<string, string> Claims { get; init; } = new Dictionary<string, string>();
}

/// <summary>
/// Refuses a request, and says what would fix it. Thrown by an authenticator; turned into
/// an RFC 9728 challenge by the middleware, never into a JSON-RPC error — a client that
/// cannot find the authorization server has no way to recover from one.
/// </summary>
public sealed class UnauthorizedException(string message, string? scope = null) : Exception(message)
{
    /// <summary>The scope the caller lacked, surfaced in the challenge when known.</summary>
    public string? Scope { get; } = scope;
}

/// <summary>
/// The seam between a transport credential and an identity.
///
/// Deliberately the whole interface. A connector starts with a static token map, moves to
/// OAuth introspection, and later to a signed JWT, without anything above this changing.
/// </summary>
public interface IConnectorAuthenticator
{
    /// <summary>Resolve the caller, or throw <see cref="UnauthorizedException"/>.</summary>
    Task<CallerPrincipal> AuthenticateAsync(HttpContext context, CancellationToken ct = default);
}

/// <summary>
/// Bearer tokens resolved by a delegate.
///
/// <para>
/// Useful as a stepping stone before an authorization server exists, and the cost of
/// stopping there is specific rather than vague: with one shared static token every write
/// is authored by the same identity, so the trail records the tool and not the person.
/// That is exactly the property the audit trail was for.
/// </para>
/// </summary>
public sealed class BearerAuthenticator(Func<string, CancellationToken, Task<CallerPrincipal?>> resolve)
    : IConnectorAuthenticator
{
    /// <summary>A static map, for getting a connector deployed and learned from.</summary>
    public static BearerAuthenticator FromTokens(IReadOnlyDictionary<string, CallerPrincipal> tokens) =>
        new((token, _) => Task.FromResult(tokens.TryGetValue(token, out var principal) ? principal : null));

    /// <summary>
    /// Parse <c>DEV_TOKENS="tokenA:ada:editor:ada@example.com,tokenB:bob:editor"</c>.
    /// Entries that are not <c>token:actor[:role[:email]]</c> are skipped rather than
    /// guessed at. A missing email stays null — see <see cref="CallerPrincipal.Email"/>.
    /// </summary>
    public static IReadOnlyDictionary<string, CallerPrincipal> ParseTokenMap(string? spec, string? downstreamToken = null)
    {
        var map = new Dictionary<string, CallerPrincipal>(StringComparer.Ordinal);

        foreach (var entry in (spec ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = entry.Split(':');
            if (parts.Length < 2 || parts[0].Length == 0 || parts[1].Length == 0) continue;

            map[parts[0]] = new CallerPrincipal
            {
                Actor = parts[1],
                // Still one role on this path, and the entry format is unchanged. A static token is
                // pasted by hand into an environment variable; making it carry a set would be a
                // second syntax to get right for a path that exists to be simple, and the connector's
                // own table resolves the one it does carry.
                Roles = parts.Length > 2 && parts[2].Length > 0 ? [parts[2]] : [],
                Email = parts.Length > 3 && parts[3].Length > 0 ? parts[3] : null,
                DownstreamToken = downstreamToken,

                // Not Unknown: this path is *known* to carry no scope claim, because there is no
                // authorization server to mint one. Saying so is what lets a connector gate a tool
                // on a scope and still work here, instead of having to special-case the deployment
                // it is running in.
                ScopeClaim = ScopeClaimState.Absent,
            };
        }

        return map;
    }

    /// <inheritdoc />
    public async Task<CallerPrincipal> AuthenticateAsync(HttpContext context, CancellationToken ct = default)
    {
        var header = context.Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedException("No bearer token");

        var token = header[7..].Trim();
        if (token.Length == 0) throw new UnauthorizedException("Empty bearer token");

        return await resolve(token, ct) ?? throw new UnauthorizedException("Token not recognised");
    }
}
