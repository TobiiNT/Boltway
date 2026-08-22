using System.Diagnostics.CodeAnalysis;

namespace Boltway.OAuth.Primitives.Redirects;

/// <summary>
/// A redirect URI as it arrived on an authorization request.
/// </summary>
/// <remarks>
/// <para>
/// The mirror of <see cref="RegisteredRedirectUri"/>, with one deliberate asymmetry: <b>this type
/// does not normalize.</b> A request carrying <c>https://Claude.ai/api/mcp/auth_callback</c> fails
/// to match a registration for <c>https://claude.ai/api/mcp/auth_callback</c>, and that is correct
/// RFC 3986 §6.2.1 Simple String Comparison.
/// </para>
/// <para>
/// It looks unhelpful and it is the point. Normalizing here would mean an attacker chooses the
/// input to the normalizer, and every normalization step maps several distinct strings onto one —
/// which is precisely how a redirect allowlist gets widened.
/// </para>
/// </remarks>
public readonly struct RequestedRedirectUri
{
    private RequestedRedirectUri(string value, RedirectUriParts parts)
    {
        Value = value;
        Kind = parts.Kind;
        Host = parts.Host;
        PathAndQuery = parts.PathAndQuery;
    }

    /// <summary>The raw request bytes, untouched. The comparison input.</summary>
    public string Value { get; }

    /// <summary>
    /// The shape this request has. Note this does <b>not</b> decide which matching rule applies:
    /// the registration's <see cref="RegisteredRedirectUri.Kind"/> does. A request cannot promote
    /// itself to port-agnostic matching.
    /// </summary>
    public RedirectKind Kind { get; }

    internal string Host { get; }

    internal string PathAndQuery { get; }

    /// <summary>Parse a redirect URI from a request. Validates shape; changes nothing.</summary>
    public static bool TryParse(
        string? raw,
        [NotNullWhen(true)] out RequestedRedirectUri? result,
        out RedirectUriError error)
    {
        result = null;

        if (!RedirectUriParts.TryParse(raw, out var parts, out error))
        {
            return false;
        }

        result = new RequestedRedirectUri(raw!, parts.Value);
        return true;
    }

    /// <inheritdoc />
    public override string ToString() => Value;
}
