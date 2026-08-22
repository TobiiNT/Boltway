using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace Boltway.ResourceServer.Bearer;

/// <summary>How the request presented its credentials, before anything is validated.</summary>
internal enum BearerCredentialKind
{
    /// <summary>Nothing to authenticate with. X-32.</summary>
    Absent,

    /// <summary>A syntactically valid <c>Authorization: Bearer &lt;b64token&gt;</c>.</summary>
    Present,

    /// <summary>Something is wrong with how the token was presented. X-35.</summary>
    Malformed,
}

/// <summary>The result of reading credentials off a request.</summary>
/// <param name="Kind">Which of the three cases this is.</param>
/// <param name="Token">The credential, when <see cref="BearerCredentialKind.Present"/>.</param>
/// <param name="Reason">
/// Why it was rejected, when <see cref="BearerCredentialKind.Malformed"/>. A constant chosen from a
/// closed set — never assembled from the request. See <see cref="BearerCredential"/>.
/// </param>
internal readonly record struct BearerCredentialResult(BearerCredentialKind Kind, string? Token, string? Reason);

/// <summary>
/// RFC 6750 §2.1: reading <c>Authorization: Bearer</c> off a request.
/// </summary>
/// <remarks>
/// <para>
/// The split this type exists to get right is <c>400</c> versus <c>401</c>, and X-35 is explicit
/// that a malformed <c>Authorization</c> header is a <c>400</c>: "getting this backwards makes
/// clients retry-loop forever on refresh". A client that receives <c>401</c> refreshes its token
/// and retries; if the header itself is malformed, the fresh token is presented the same broken way
/// and the loop never terminates.
/// </para>
/// <para>
/// So the boundary drawn here is a <b>syntactic</b> one. Absent or non-Bearer credentials are not
/// malformed — they are the case where the client has not authenticated, and the answer is a
/// <c>401</c> carrying a challenge that says how. Malformed means the client did claim to present a
/// Bearer token and the presentation itself does not parse: an empty credential, a credential
/// outside RFC 6750's <c>b64token</c> grammar, two <c>Authorization</c> headers, or a token in the
/// query string, which §3.1 names as <c>invalid_request</c> and the MCP specification forbids
/// outright.
/// </para>
/// <para>
/// <b>No part of the request reaches the reason string.</b> Every value this type returns is a
/// constant, and that is a security property rather than a style: the reason becomes
/// <c>error_description</c> in a <c>WWW-Authenticate</c> header, and while
/// <c>WwwAuthenticate.Bearer</c> strips <c>"</c> and control characters, the way to be sure an
/// attacker-controlled byte never lands in a response header is for one never to be put there.
/// </para>
/// </remarks>
internal static class BearerCredential
{
    /// <summary>RFC 6750 §2.3 names this query parameter. We refuse it; see the remarks.</summary>
    private const string QueryParameter = "access_token";

    private const string Scheme = "Bearer";

    internal const string TwoHeaders = "The request carried more than one Authorization header.";
    internal const string EmptyCredential = "The Bearer credential is empty.";
    internal const string NotB64Token = "The Bearer credential is not a valid b64token (RFC 6750 §2.1).";
    internal const string TokenInQuery =
        "An access token must be sent in the Authorization header, not the query string.";

    /// <summary>Read the credential, or say why there is not one.</summary>
    internal static BearerCredentialResult Read(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var authorization = request.Headers[HeaderNames.Authorization];

        // RFC 6750 §3.1 makes "more than one method for including an access token" an
        // invalid_request. Two Authorization headers is the degenerate form of that, and the choice
        // of which one to honour is exactly the kind of decision a proxy and an origin can make
        // differently.
        if (authorization.Count > 1)
        {
            return new BearerCredentialResult(BearerCredentialKind.Malformed, null, TwoHeaders);
        }

        var header = authorization.Count == 1 ? authorization[0] : null;
        var queryToken = ReadQueryToken(request);

        if (string.IsNullOrEmpty(header))
        {
            // A token in the query string and nowhere else. The MCP specification forbids it and
            // bearer_methods_supported advertises "header" only, so this is not a fallback route —
            // it is a request this server declines to read, and 400 says so without inviting a
            // token refresh that would change nothing.
            return queryToken
                ? new BearerCredentialResult(BearerCredentialKind.Malformed, null, TokenInQuery)
                : new BearerCredentialResult(BearerCredentialKind.Absent, null, null);
        }

        if (queryToken)
        {
            return new BearerCredentialResult(BearerCredentialKind.Malformed, null, TokenInQuery);
        }

        // RFC 6750 §2.1 credentials = "Bearer" 1*SP b64token. The scheme match is case-insensitive
        // per RFC 9110 §11.1 — "Bearer", "bearer" and "BEARER" are one scheme, and a client sending
        // the lower-case spelling is conformant.
        if (!header.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase))
        {
            return NotBearer();
        }

        if (header.Length == Scheme.Length)
        {
            // Exactly "Bearer" with nothing after it. The scheme was claimed, so this is a
            // malformed presentation rather than an absent credential.
            return new BearerCredentialResult(BearerCredentialKind.Malformed, null, EmptyCredential);
        }

        if (header[Scheme.Length] is not ' ')
        {
            // "BearerToken" — the prefix matched but this is some other scheme whose name starts
            // with the same six letters, not a badly spaced Bearer credential.
            return NotBearer();
        }

        var credential = header[(Scheme.Length + 1)..].TrimStart(' ');

        if (credential.Length == 0)
        {
            return new BearerCredentialResult(BearerCredentialKind.Malformed, null, EmptyCredential);
        }

        return IsB64Token(credential)
            ? new BearerCredentialResult(BearerCredentialKind.Present, credential, null)
            : new BearerCredentialResult(BearerCredentialKind.Malformed, null, NotB64Token);
    }

    /// <summary>
    /// A credential in some scheme other than Bearer is treated as no credential.
    /// </summary>
    /// <remarks>
    /// <c>401</c> rather than <c>400</c>, and the reasoning is the one X-35 gives inverted: a client
    /// holding a Basic credential for some other system has not failed to <i>form</i> a Bearer
    /// request, it has failed to <i>make</i> one. The challenge that comes back tells it which
    /// scheme this resource speaks and where to find the metadata, which is actionable; a <c>400</c>
    /// would be terminal for a client that could have authenticated correctly.
    /// </remarks>
    private static BearerCredentialResult NotBearer() =>
        new(BearerCredentialKind.Absent, null, null);

    private static bool ReadQueryToken(HttpRequest request)
    {
        // Presence is the whole question — the value is never read, so there is nothing here for a
        // crafted parameter to reach.
        return request.Query.ContainsKey(QueryParameter);
    }

    /// <summary>
    /// RFC 6750 §2.1: <c>b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="</c>.
    /// </summary>
    /// <remarks>
    /// A JWT's compact serialization is base64url segments joined by <c>.</c>, so every token this
    /// server issues satisfies this. Checking it here means the JWT parser is never handed
    /// arbitrary header bytes, and it is the concrete meaning of "malformed" that X-35's <c>400</c>
    /// attaches to.
    /// </remarks>
    private static bool IsB64Token(string credential)
    {
        var index = 0;

        while (index < credential.Length && IsB64TokenChar(credential[index]))
        {
            index++;
        }

        if (index == 0)
        {
            return false;
        }

        while (index < credential.Length && credential[index] is '=')
        {
            index++;
        }

        return index == credential.Length;
    }

    private static bool IsB64TokenChar(char c) =>
        c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9')
            or '-' or '.' or '_' or '~' or '+' or '/';
}
