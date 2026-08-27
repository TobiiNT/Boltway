namespace Boltway.OAuth.Primitives.Scopes;

/// <summary>
/// A set of scopes, in the one wire format OAuth defines: space-delimited.
/// </summary>
/// <remarks>
/// <para>
/// One representation, used everywhere - the <c>scope</c> request parameter, the <c>scope</c> claim
/// (RFC 9068 §2.2.3 makes it a <b>string</b>, not an array), the challenge header, and the database
/// column. No JSON, no join table, no serializer: the bytes stored are the bytes emitted.
/// </para>
/// <para>
/// Validation happens on write, and the reason is A-13. A scope configured as <c>"story:read "</c>
/// with a trailing space is a <i>different</i> scope from <c>story:read</c> - every comparison is
/// literal - and a dashboard renders the two identically. That cost real hours on a market-leading
/// IdP. Refusing the whitespace at the point of writing means the ambiguity never exists, and it
/// also makes the space delimiter unambiguous by construction.
/// </para>
/// </remarks>
public readonly struct ScopeSet : IEquatable<ScopeSet>
{
    private readonly string[] _scopes;

    private ScopeSet(string[] scopes) => _scopes = scopes;

    /// <summary>The empty set.</summary>
    public static ScopeSet Empty { get; } = new([]);

    /// <summary>The scopes, sorted ordinally.</summary>
    public IReadOnlyList<string> Values => _scopes ?? [];

    /// <summary>Whether the set has no scopes.</summary>
    public bool IsEmpty => _scopes is null || _scopes.Length == 0;

    /// <summary>Whether a scope is present. Ordinal.</summary>
    public bool Contains(string scope)
    {
        foreach (var s in Values)
        {
            if (string.Equals(s, scope, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Parse a space-delimited <c>scope</c> value.
    /// </summary>
    /// <param name="raw">The parameter as sent, or <see langword="null"/>.</param>
    /// <param name="scopes">The parsed set. Sorted and deduplicated.</param>
    /// <param name="invalid">The first token that is not a valid <c>scope-token</c>.</param>
    /// <remarks>
    /// RFC 6749 §3.3 defines <c>scope-token</c> as <c>%x21 / %x23-5B / %x5D-7E</c> - printable
    /// ASCII without space, without <c>"</c> and without <c>\</c>. Anything else fails here rather
    /// than being quietly dropped, because a silently-dropped scope becomes a token with less
    /// authority than the client asked for, and the failure surfaces much later as a 403 the client
    /// cannot explain.
    /// </remarks>
    public static bool TryParse(string? raw, out ScopeSet scopes, out string? invalid)
    {
        scopes = Empty;
        invalid = null;

        if (string.IsNullOrWhiteSpace(raw))
        {
            return true;
        }

        var parts = raw.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var set = new SortedSet<string>(StringComparer.Ordinal);

        foreach (var part in parts)
        {
            if (!IsScopeToken(part))
            {
                invalid = part;
                return false;
            }

            set.Add(part);
        }

        scopes = new ScopeSet([.. set]);
        return true;
    }

    /// <summary>
    /// Validate a scope name at configuration time, naming the offending character.
    /// </summary>
    /// <remarks>
    /// A-13's acceptance criterion is that configuring <c>"story:read "</c> is refused <i>with the
    /// offending codepoint named</i>. "Invalid scope" alone sends an operator hunting for a
    /// difference their terminal will not render.
    /// </remarks>
    public static bool TryValidateName(string? name, out string? error)
    {
        error = null;

        if (string.IsNullOrEmpty(name))
        {
            error = "A scope name is required.";
            return false;
        }

        for (var i = 0; i < name.Length; i++)
        {
            if (IsScopeTokenChar(name[i]))
            {
                continue;
            }

            var description = name[i] switch
            {
                ' ' => "a space",
                '\t' => "a tab",
                '"' => "a double quote",
                '\\' => "a backslash",
                _ => $"U+{(int)name[i]:X4}",
            };

            error =
                $"Scope '{name}' contains {description} at position {i}. RFC 6749 §3.3 allows only " +
                "%x21 / %x23-5B / %x5D-7E. Every comparison against this value is literal, so a " +
                "stray character makes it a different scope from the one you meant — and most " +
                "consoles render the two identically.";
            return false;
        }

        return true;
    }

    /// <summary>The space-delimited wire form. What is stored and what is emitted.</summary>
    public string ToWireString() => string.Join(' ', Values);

    /// <summary>Rehydrate from a stored wire string, which was validated when written.</summary>
    public static ScopeSet FromStorage(string? wire) =>
        TryParse(wire, out var scopes, out _) ? scopes : Empty;

    /// <summary>The scopes in this set that are not in <paramref name="permitted"/>.</summary>
    public IReadOnlyList<string> Except(ScopeSet permitted)
    {
        var extra = new List<string>();

        foreach (var scope in Values)
        {
            if (!permitted.Contains(scope))
            {
                extra.Add(scope);
            }
        }

        return extra;
    }

    private static bool IsScopeToken(string token)
    {
        foreach (var c in token)
        {
            if (!IsScopeTokenChar(c))
            {
                return false;
            }
        }

        return token.Length > 0;
    }

    private static bool IsScopeTokenChar(char c) =>
        c is '\x21' or (>= '\x23' and <= '\x5B') or (>= '\x5D' and <= '\x7E');

    /// <inheritdoc />
    public bool Equals(ScopeSet other) =>
        string.Equals(ToWireString(), other.ToWireString(), StringComparison.Ordinal);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is ScopeSet other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(ToWireString());

    /// <inheritdoc />
    public override string ToString() => ToWireString();

    /// <summary>Set equality.</summary>
    public static bool operator ==(ScopeSet left, ScopeSet right) => left.Equals(right);

    /// <summary>Set inequality.</summary>
    public static bool operator !=(ScopeSet left, ScopeSet right) => !left.Equals(right);
}
