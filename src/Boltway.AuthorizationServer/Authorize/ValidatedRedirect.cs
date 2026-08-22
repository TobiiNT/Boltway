using System.Diagnostics.CodeAnalysis;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Errors;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Redirects;

namespace Boltway.AuthorizationServer.Authorize;

/// <summary>
/// Proof that a redirect URI was matched against a client's registrations.
/// </summary>
/// <remarks>
/// <para>
/// A capability token, and the mechanism behind N-11. There is no public constructor: the only way
/// to get one is <see cref="From"/>, which takes a successful <see cref="RedirectMatch"/>, and the
/// only thing that can produce one of those is <see cref="RedirectUriMatcher.Match"/>.
/// </para>
/// <para>
/// <b>A class, not a struct, and that is the whole difference between a guarantee and a comment.</b>
/// This was a <c>readonly struct</c>, and every struct has a public parameterless constructor — so
/// <c>default</c> was a forged capability that any assembly could mint without
/// <c>InternalsVisibleTo</c>, and <c>AuthorizeRedirectError.Create(default, …)</c> compiled and ran.
/// As a class, <c>default</c> is <see langword="null"/>, the factory is the only source, and the
/// null check is the compiler's.
/// </para>
/// <para>
/// Because <see cref="AuthorizeRedirectError"/> <i>requires</i> one, an error cannot be delivered
/// by redirect before the redirect URI has been validated — and because the pipeline stages that
/// redirect take one as a <b>parameter</b> rather than reading it back off the context, a stage
/// moved ahead of the redirect check does not compile.
/// </para>
/// </remarks>
public sealed class ValidatedRedirect
{
    private ValidatedRedirect(string value) => Value = value;

    /// <summary>
    /// Where to send the browser: the <b>requested</b> URI, not the registered one.
    /// </summary>
    /// <remarks>
    /// The distinction carries RFC 8252 §7.3. A native client registers
    /// <c>http://127.0.0.1/callback</c> with no port and listens on an ephemeral one, so redirecting
    /// to the registered string would send the browser to port 80 where nothing is listening.
    /// </remarks>
    public string Value { get; }

    /// <summary>Mint from a successful match. Returns <see langword="false"/> for a non-match.</summary>
    public static bool From(in RedirectMatch match, [NotNullWhen(true)] out ValidatedRedirect? redirect)
    {
        redirect = null;

        // A match can be successful and still carry a null RequestedValue if a caller built one by
        // hand. RedirectUriMatcher cannot produce that, but the check costs nothing and the whole
        // point of this type is that it does not depend on who its callers are.
        if (!match.Matched || match.RequestedValue is null)
        {
            return false;
        }

        redirect = new ValidatedRedirect(match.RequestedValue);
        return true;
    }
}

/// <summary>
/// An authorization error that will be delivered by redirect. RFC 6749 §4.1.2.1.
/// </summary>
/// <remarks>
/// Constructible only with a <see cref="ValidatedRedirect"/>, so it cannot exist before the
/// redirect URI is trusted. <c>state</c> and <c>iss</c> are constructor parameters rather than
/// settable properties, so "we forgot to echo state" and "we forgot the RFC 9207 iss" have no code
/// path either.
/// </remarks>
public sealed record AuthorizeRedirectError
{
    private AuthorizeRedirectError(
        ValidatedRedirect target, Rejection rejection, string description, string? state, IssuerString issuer, string correlationId)
    {
        Target = target;
        Rejection = rejection;
        Description = description;
        State = state;
        Issuer = issuer;
        CorrelationId = correlationId;
    }

    /// <summary>Where it goes.</summary>
    public ValidatedRedirect Target { get; }

    /// <summary>
    /// Why the request was refused, in the form the log needs. A-09.
    /// </summary>
    /// <remarks>
    /// Required rather than optional, and that is the compile-time half of A-09: there is no
    /// overload of <see cref="Create"/> that takes a bare code and description, so a redirect error
    /// cannot be constructed without the payload the writer logs.
    /// </remarks>
    public Rejection Rejection { get; }

    /// <summary>Which error.</summary>
    public OAuthErrorCode Code => Rejection.Error;

    /// <summary>A safe, human-readable detail. Already filtered and length-capped.</summary>
    public string Description { get; }

    /// <summary>The client's <c>state</c>, echoed verbatim when it sent one.</summary>
    public string? State { get; }

    /// <summary>The issuer, for RFC 9207's <c>iss</c> response parameter.</summary>
    public IssuerString Issuer { get; }

    /// <summary>The correlation id, echoed in <c>X-Request-Id</c> and carried in the log line.</summary>
    public string CorrelationId { get; }

    /// <summary>
    /// The only factory.
    /// </summary>
    /// <remarks>
    /// RFC 9207's <c>iss</c> is required on <b>every</b> authorization response including error
    /// redirects, because the mix-up attack it defends against works precisely by sending a
    /// response from the wrong authorization server — and an error response is as useful to that
    /// attack as a successful one. The metadata advertises
    /// <c>authorization_response_iss_parameter_supported</c>, and a client that sees that flag and
    /// then a response without <c>iss</c> is required to reject it.
    /// </remarks>
    /// <param name="target">The validated redirect URI. The capability, not a string.</param>
    /// <param name="rejection">Why the request was refused.</param>
    /// <param name="state">The client's <c>state</c>, or <see langword="null"/>.</param>
    /// <param name="issuer">The configured issuer, for <c>iss</c>.</param>
    /// <param name="correlationId">The id that joins the response to its log line.</param>
    public static AuthorizeRedirectError Create(
        ValidatedRedirect target,
        Rejection rejection,
        string? state,
        IssuerString issuer,
        string correlationId)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(rejection);

        return new AuthorizeRedirectError(
            target, rejection, ErrorText.Safe(rejection.Description), state, issuer, correlationId);
    }
}

/// <summary>
/// An authorization failure that must <b>not</b> redirect. RFC 6749 §4.1.2.1.
/// </summary>
/// <remarks>
/// Rendered on the authorization server's own origin, at 400. Used when the client is unknown or
/// the redirect URI does not validate — there is no address it is safe to send the user to, and
/// redirecting anyway makes the authorization endpoint an open redirector that also leaks
/// <c>state</c>.
/// </remarks>
public sealed record AuthorizeHtmlError
{
    /// <summary>Build one, filtering the description.</summary>
    /// <param name="rejection">Why the request was refused. Required — see A-09.</param>
    /// <param name="correlationId">The id that joins the response to its log line.</param>
    public AuthorizeHtmlError(Rejection rejection, string correlationId)
    {
        ArgumentNullException.ThrowIfNull(rejection);

        Rejection = rejection;
        Description = ErrorText.Safe(rejection.Description);
        CorrelationId = correlationId;
    }

    /// <summary>
    /// Why the request was refused, in the form the log needs. A-09.
    /// </summary>
    /// <remarks>
    /// Required rather than optional. There is no constructor that takes a bare code and
    /// description, so an HTML error cannot exist without the payload the writer logs.
    /// </remarks>
    public Rejection Rejection { get; }

    /// <summary>Which error.</summary>
    public OAuthErrorCode Code => Rejection.Error;

    /// <summary>A safe, human-readable detail. Already filtered and length-capped.</summary>
    public string Description { get; }

    /// <summary>The correlation id, so a report and a log line can be joined.</summary>
    public string CorrelationId { get; }

    /// <summary>
    /// How long the caller should wait. <see langword="null"/> unless the refusal says so.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Settable only through <see cref="Throttled"/> and <see cref="StoreUnavailable"/> — the two
    /// refusals on this surface that tell the caller when to come back. That it is not a public
    /// setter is the guard: the thing to keep out is a <c>Retry-After</c> beside a code that
    /// contradicts it, such as a 429 also carrying <c>invalid_client</c>, which would tell the
    /// client two different things about whose fault the request was.
    /// </para>
    /// <para>
    /// <b>Carrying a code is no longer what distinguishes the two.</b> That reading held while X-31
    /// was the only refusal here with a wait, and it read as "a wait means no code". X-11 has one and
    /// a code, and they agree: <c>temporarily_unavailable</c> and "try again in five seconds" are the
    /// same statement twice. What the writer keys on is therefore the reason, not the presence of
    /// this value — see <c>RejectionHtmlResult.UntabledSpec</c>.
    /// </para>
    /// </remarks>
    public TimeSpan? RetryAfter { get; private init; }

    /// <summary>
    /// A refusal by a rate limit or a quota. X-31.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="OAuthErrorCode.None"/> is not an omission and not a placeholder. X-31's row in the
    /// requirements is the only one whose <c>error</c> column is literally <i>(none)</i> — being
    /// over a limit is a transport condition, and RFC 6749 §4.1.2.1 registers no code that means it.
    /// <c>OAuthErrors</c> therefore has no row for this and cannot be given one:
    /// <c>The_none_code_is_not_in_the_table</c> asserts precisely that, on the reasoning that
    /// <see cref="OAuthErrorCode.None"/> describes a response rather than names an error. The status
    /// and the <c>Retry-After</c> are the machine-readable part; the description is the human one.
    /// </para>
    /// <para>
    /// The alternative — borrowing <c>temporarily_unavailable</c> — was rejected because it says the
    /// server is at fault, while 429 says the caller is, and the two surfaces this is emitted from
    /// have an existing test asserting that a <c>temporarily_unavailable</c> before redirect
    /// validation is a 5xx.
    /// </para>
    /// </remarks>
    /// <param name="description">What was exceeded, in words.</param>
    /// <param name="correlationId">The correlation id.</param>
    /// <param name="retryAfter">How long until the caller should try again. Must be positive.</param>
    /// <param name="privateDetail">Which limit refused it. Logged, never sent.</param>
    public static AuthorizeHtmlError Throttled(
        string description, string correlationId, TimeSpan retryAfter, string? privateDetail = null) =>
        new(
            Rejection.Of(ReasonCode.RateLimited, OAuthErrorCode.None, description, privateDetail),
            correlationId)
        {
            RetryAfter = retryAfter > TimeSpan.Zero ? retryAfter : TimeSpan.FromSeconds(1),
        };

    /// <summary>
    /// A refusal because the store could not be reached, before any redirect was validated. X-11.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Unlike <see cref="Throttled"/> this one has a code, and the asymmetry is not an
    /// inconsistency.</b> RFC 6749 registers no error meaning "you are over a limit" anywhere, so
    /// X-31 has none to carry. It registers <c>temporarily_unavailable</c> for this endpoint
    /// specifically, in §4.1.2.1, and it means exactly what happened — so the honest answer here is
    /// to use the code that exists rather than to imitate X-31's silence. That the same condition at
    /// <c>/token</c> carries no code is a fact about §5.2's closed set, not about the condition.
    /// </para>
    /// <para>
    /// <b>This is the pre-redirect half, which is the one a store outage actually reaches.</b>
    /// Validating a redirect URI means reading the client, so a store that is down usually fails
    /// before there is an address to send anyone to — and redirecting to an unvalidated one is the
    /// open redirector §4.1.2.1 forbids. The redirect half exists for a failure later in the flow and
    /// is built by the endpoint's boundary from <c>context.Redirect</c>, which is only set once that
    /// validation has succeeded.
    /// </para>
    /// </remarks>
    /// <param name="description">What the page and the log say. Filtered on the way in.</param>
    /// <param name="correlationId">The id that joins the response to its log line.</param>
    /// <param name="retryAfter">How long to wait. Floored at one second.</param>
    /// <param name="privateDetail">Detail for the log only.</param>
    /// <param name="cause">The exception, for the log.</param>
    /// <param name="code">
    /// <see cref="OAuthErrorCode.TemporarilyUnavailable"/> at <c>/authorize</c>, where §4.1.2.1
    /// registers it, and <see cref="OAuthErrorCode.None"/> on the interaction pages, where no
    /// specification registers anything because they are not a protocol surface. The default is the
    /// authorization endpoint's, because that is the caller this factory was written for; the pages
    /// pass <c>None</c> explicitly, which is also what selects their untabled row in the writer.
    /// </param>
    public static AuthorizeHtmlError StoreUnavailable(
        string description,
        string correlationId,
        TimeSpan retryAfter,
        string? privateDetail = null,
        Exception? cause = null,
        OAuthErrorCode code = OAuthErrorCode.TemporarilyUnavailable) =>
        new(
            Rejection.Of(ReasonCode.StoreUnavailable, code, description, privateDetail, cause),
            correlationId)
        {
            RetryAfter = retryAfter > TimeSpan.Zero ? retryAfter : TimeSpan.FromSeconds(1),
        };
}

/// <summary>
/// Makes a description safe to put on the wire.
/// </summary>
/// <remarks>
/// <para>
/// OAuth 2.1 §4.1.2.1: "Values for the <c>error_description</c> parameter MUST NOT include
/// characters outside the set %x20-21 / %x23-5B / %x5D-7E." The set excludes CR and LF, and that is
/// not a formatting preference — a description is echoed into an HTML body on our own origin and
/// into a <c>Location</c> query string, and several of them interpolate a request parameter the
/// caller chose.
/// </para>
/// <para>
/// Applied in the error types' constructors rather than at each call site, deliberately. A call
/// site is a place to forget; a constructor is not. Measured before this existed:
/// <c>code_challenge_method=a%0D%0ASet-Cookie:%20x=1</c> reached <c>Description</c> with the CRLF
/// intact, and a 4000-character scope was echoed whole.
/// </para>
/// </remarks>
internal static class ErrorText
{
    /// <summary>
    /// The cap. Long enough for the longest description this server writes plus a quoted value,
    /// short enough that an error page cannot be used to reflect a payload of interesting size.
    /// </summary>
    internal const int MaxLength = 240;

    /// <summary>Filter to the permitted set and truncate.</summary>
    internal static string Safe(string? description)
    {
        if (string.IsNullOrEmpty(description))
        {
            return string.Empty;
        }

        var builder = new System.Text.StringBuilder(Math.Min(description.Length, MaxLength));

        foreach (var c in description)
        {
            if (builder.Length == MaxLength)
            {
                builder.Length = MaxLength - 1;
                builder.Append('~');
                break;
            }

            // Characters outside the set are dropped, not replaced. A replacement character is
            // itself a value the caller chose the position of, and a run of them reads like data.
            if (c is '\x20' or '\x21' or (>= '\x23' and <= '\x5B') or (>= '\x5D' and <= '\x7E'))
            {
                builder.Append(c);
            }
        }

        return builder.ToString();
    }
}
