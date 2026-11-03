using System.Diagnostics.CodeAnalysis;

namespace Boltway.OAuth.Primitives.Redirects;

/// <summary>
/// A redirect URI as stored against a client. Normalized once, here, at registration.
/// </summary>
/// <remarks>
/// The rule this type exists to enforce is <b>normalize on write, compare exactly on read</b>.
/// Normalizing at match time would mean the incoming request gets to influence the normalization,
/// and every normalization widens the match set.
/// </remarks>
public readonly struct RegisteredRedirectUri : IEquatable<RegisteredRedirectUri>
{
    private RegisteredRedirectUri(string value, RedirectUriParts parts)
    {
        Value = value;
        Kind = parts.Kind;
        Host = parts.Host;
        PathAndQuery = parts.PathAndQuery;
    }

    /// <summary>
    /// The canonical raw string. This, and only this, is the comparison input for an exact match.
    /// </summary>
    public string Value { get; }

    /// <summary>How this URI may be matched. Stored, never re-derived from a request.</summary>
    public RedirectKind Kind { get; }

    internal string Host { get; }

    internal string PathAndQuery { get; }

    /// <summary>
    /// The only way to make one. Validates, then lowercases scheme and authority in place.
    /// </summary>
    /// <param name="raw">The URI as the operator or the client document supplied it.</param>
    /// <param name="result">The registration, when this returns <see langword="true"/>.</param>
    /// <param name="error">Which rule refused it, when this returns <see langword="false"/>.</param>
    public static bool TryRegister(
        string? raw,
        [NotNullWhen(true)] out RegisteredRedirectUri? result,
        out RedirectUriError error)
    {
        result = null;

        if (raw is null)
        {
            error = RedirectUriError.Malformed;
            return false;
        }

        // Normalize FIRST, then parse the normalized form - one parse, and the thing validated is
        // the thing stored.
        //
        // Parsing before normalizing looks equivalent and is not. Host classification is ordinal,
        // so `HTTP://LocalHost/cb` presents a host of `LocalHost`, which is not one of the three
        // loopback literals, so `http` on a non-loopback host is refused and a legitimate
        // registration is rejected. Lowercasing first means classification sees the canonical form,
        // which is the whole intent of normalize-on-write.
        var normalized = RedirectUriParts.LowercaseSchemeAndAuthority(raw);

        if (!RedirectUriParts.TryParse(normalized, out var parts, out error))
        {
            return false;
        }

        // Registration only, not Rehydrate: a row stored before this rule existed still loads, and
        // a store that refused to start over one would be an outage this check caused.
        if (QueryNamesAResponseParameter(normalized))
        {
            error = RedirectUriError.QueryHasResponseParameter;
            return false;
        }

        result = new RegisteredRedirectUri(normalized, parts.Value);
        error = RedirectUriError.None;
        return true;
    }

    /// <summary>
    /// Rehydrate a registration already validated and normalized on a previous pass.
    /// </summary>
    /// <remarks>
    /// Internal, and used only by the storage layer reading its own rows back. Making this public
    /// would hand callers a way to construct a registration that never passed
    /// <see cref="TryRegister"/>, which is the invariant the type exists to hold.
    /// </remarks>
    internal static RegisteredRedirectUri Rehydrate(string normalizedValue)
    {
        if (!RedirectUriParts.TryParse(normalizedValue, out var parts, out var error))
        {
            throw new InvalidOperationException(
                $"Stored redirect URI '{normalizedValue}' no longer parses ({error}). The row was " +
                "written by a different version of the validation rules, or the column was edited " +
                "by hand.");
        }

        return new RegisteredRedirectUri(normalizedValue, parts.Value);
    }

    /// <summary>The parameters OAuth 2.1 -17 §4.1.2 and §4.1.2.1 put in an authorization response.</summary>
    private static readonly string[] ResponseParameters = ["code", "state", "iss", "error", "error_description", "error_uri"];

    /// <summary>Whether the query names any of <see cref="ResponseParameters"/>, compared ordinally.</summary>
    private static bool QueryNamesAResponseParameter(string value)
    {
        var start = value.IndexOf('?', StringComparison.Ordinal);

        if (start < 0)
        {
            return false;
        }

        foreach (var pair in value[(start + 1)..].Split('&'))
        {
            var name = pair.Split('=', 2)[0];

            if (ResponseParameters.Contains(Uri.UnescapeDataString(name), StringComparer.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    /// <inheritdoc />
    public bool Equals(RegisteredRedirectUri other) =>
        string.Equals(Value, other.Value, StringComparison.Ordinal);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is RegisteredRedirectUri other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Value);

    /// <inheritdoc />
    public override string ToString() => Value;

    /// <summary>Ordinal equality.</summary>
    public static bool operator ==(RegisteredRedirectUri left, RegisteredRedirectUri right) => left.Equals(right);

    /// <summary>Ordinal inequality.</summary>
    public static bool operator !=(RegisteredRedirectUri left, RegisteredRedirectUri right) => !left.Equals(right);
}
