namespace Boltway.OAuth.Primitives.Ids;

/// <summary>
/// Which directory a human-chosen key is unique within.
/// </summary>
/// <remarks>
/// <para>
/// <b>It exists before anyone needs two of them, and that is the whole decision.</b> A realm column
/// added later is a migration across every deployed database, run against tables holding live
/// credentials, by somebody who has just discovered they need it. Added now it is one column on two
/// tables, and every deployment stays single-realm without noticing.
/// </para>
/// <para>
/// <b>It goes only where the lookup key is chosen by a person</b> — usernames, emails, upstream
/// subjects. Grants, consents and refresh families are keyed on <see cref="SubjectId"/>, which is a
/// ULID and therefore already unique across every realm there will ever be; adding a realm column to
/// those would be a second isolation mechanism for something already isolated, and two mechanisms
/// disagree eventually.
/// </para>
/// <para>
/// <b>Constrained at creation, like <see cref="SubjectId"/> and for the same reason.</b> The value
/// lands in a composite unique index and is a candidate for a cache key and a URL segment. A
/// character set of <c>[a-z0-9-]</c> means no caller anywhere downstream has to sanitise it, and
/// nothing this server writes can produce two realms whose names differ only by case — which would
/// be two directories that look like one.
/// </para>
/// </remarks>
public readonly struct RealmId : IEquatable<RealmId>
{
    /// <summary>The longest a realm name may be.</summary>
    /// <remarks>
    /// It shares an index with a 256-character username on providers whose index rows are size
    /// limited, and nothing legible needs more.
    /// </remarks>
    public const int MaxLength = 64;

    private RealmId(string value) => Value = value;

    /// <summary>
    /// The realm every single-realm deployment is in.
    /// </summary>
    /// <remarks>
    /// A named value rather than the empty string, because it is written into a NOT NULL column and
    /// read back by tests: a blank realm reads as "this row predates realms" and invites code that
    /// treats absent and default as different things.
    /// </remarks>
    public static RealmId Default { get; } = new("default");

    /// <summary>The realm name.</summary>
    public string Value { get; }

    /// <summary>Whether this is the uninitialised value.</summary>
    /// <remarks>
    /// <c>default(RealmId)</c> has a null <see cref="Value"/>, and a struct cannot prevent that.
    /// Anything reading a realm out of a model should treat this as
    /// <see cref="Default"/> — <see cref="OrDefault"/> does — rather than writing a null into a
    /// column and finding out at the database.
    /// </remarks>
    public bool IsUnset => Value is null;

    /// <summary>This realm, or <see cref="Default"/> when it was never set.</summary>
    public RealmId OrDefault => IsUnset ? Default : this;

    /// <summary>
    /// Validate and wrap a configured realm name.
    /// </summary>
    /// <param name="value">The name.</param>
    /// <param name="realm">The realm, when it is one.</param>
    /// <param name="error">Why it is not, when it is not.</param>
    /// <returns>Whether <paramref name="value"/> is a realm name.</returns>
    public static bool TryParse(string? value, out RealmId realm, out string? error)
    {
        realm = default;
        error = null;

        if (string.IsNullOrEmpty(value))
        {
            error = "A realm name is required.";
            return false;
        }

        if (value.Length > MaxLength)
        {
            error = $"A realm name may be at most {MaxLength} characters; this one is {value.Length}.";
            return false;
        }

        foreach (var c in value)
        {
            if (c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-')
            {
                continue;
            }

            error =
                $"A realm name may contain only lowercase letters, digits and '-'; '{value}' does not. " +
                "The value is part of a unique index and a candidate cache key, so it is constrained " +
                "where it is created rather than sanitised everywhere it is read.";
            return false;
        }

        if (value[0] is '-' || value[^1] is '-')
        {
            error = $"A realm name may not start or end with '-'; '{value}' does.";
            return false;
        }

        realm = new RealmId(value);
        return true;
    }

    /// <summary>
    /// Wrap a realm name already in a database.
    /// </summary>
    /// <remarks>
    /// The rehydration path, and it validates nothing — the same split
    /// <see cref="SubjectId.FromStorage"/> records. A shape is a promise about what gets created, so
    /// the creation site is the only place it can be kept; refusing here would make a row written by
    /// an older version unreadable rather than merely unusual.
    /// </remarks>
    /// <param name="value">The stored name.</param>
    public static RealmId FromStorage(string value) => new(value);

    /// <inheritdoc />
    public bool Equals(RealmId other) => string.Equals(Value, other.Value, StringComparison.Ordinal);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is RealmId other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => Value is null ? 0 : StringComparer.Ordinal.GetHashCode(Value);

    /// <inheritdoc />
    public override string ToString() => Value ?? "<unset>";

    /// <summary>Ordinal equality.</summary>
    public static bool operator ==(RealmId left, RealmId right) => left.Equals(right);

    /// <summary>Ordinal inequality.</summary>
    public static bool operator !=(RealmId left, RealmId right) => !left.Equals(right);
}
