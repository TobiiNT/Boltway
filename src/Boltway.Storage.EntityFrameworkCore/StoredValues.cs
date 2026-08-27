using System.Globalization;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.Storage.EntityFrameworkCore;

/// <summary>
/// Conversions between the abstraction records and the column types.
/// </summary>
/// <remarks>
/// One place, so both directions of every conversion are next to each other and a round trip can be
/// read rather than inferred.
/// </remarks>
internal static class StoredValues
{
    /// <summary>The separator inside a resource-list column.</summary>
    /// <remarks>
    /// A newline. Resources are absolute HTTPS URLs, in which a raw newline cannot appear - and
    /// <see cref="EncodeResources"/> refuses one rather than writing a value it would read back
    /// differently, so "cannot appear" is checked at the boundary instead of assumed.
    /// </remarks>
    private const char ResourceSeparator = '\n';

    /// <summary>UTC ticks, which is what every timestamp column holds.</summary>
    internal static long ToTicks(DateTimeOffset value) => value.UtcTicks;

    /// <summary>The instant those ticks name, at offset zero.</summary>
    internal static DateTimeOffset FromTicks(long ticks) => new(ticks, TimeSpan.Zero);

    /// <summary>UTC ticks, or null.</summary>
    internal static long? ToTicks(DateTimeOffset? value) => value is { } v ? v.UtcTicks : null;

    /// <summary>The instant, or null.</summary>
    internal static DateTimeOffset? FromTicks(long? ticks) => ticks is { } t ? FromTicks(t) : null;

    /// <summary>The digest bytes that go in the column.</summary>
    internal static byte[] ToBytes(Sha256Hash hash) => hash.Value.ToArray();

    /// <summary>The digest bytes, or null.</summary>
    internal static byte[]? ToBytes(Sha256Hash? hash) => hash is { } h ? ToBytes(h) : null;

    /// <summary>Rehydrate a digest read back from a column.</summary>
    /// <exception cref="InvalidOperationException">
    /// The column did not hold 32 bytes. Returning <see langword="default"/> instead would produce a
    /// hash that equals every other absent one, so two unrelated rows would compare equal.
    /// </exception>
    internal static Sha256Hash ToHash(byte[] bytes)
    {
        if (!Sha256Hash.TryFromBytes(bytes, out var hash))
        {
            var length = bytes?.Length.ToString(CultureInfo.InvariantCulture) ?? "no";

            throw new InvalidOperationException(
                $"A hash column holds {length} bytes rather than {Sha256Hash.Length}.");
        }

        return hash;
    }

    /// <summary>Rehydrate a digest, or null.</summary>
    /// <remarks>
    /// A different name rather than an overload: <c>byte[]</c> and <c>byte[]?</c> are one type at
    /// runtime, so the two would be the same signature.
    /// </remarks>
    internal static Sha256Hash? ToHashOrNull(byte[]? bytes) => bytes is null ? null : ToHash(bytes);

    /// <summary>
    /// Rebuild a client identifier from its value and its kind.
    /// </summary>
    /// <remarks>
    /// Both columns, because <c>ClientIdKind</c> is not recoverable from the value - that is the
    /// whole reason <see cref="ClientIdentifier"/> stores it rather than testing for an
    /// <c>https://</c> prefix, and a store that dropped the column would silently turn a
    /// pre-registered client whose id happens to be a URL into a CIMD one.
    /// </remarks>
    internal static ClientIdentifier ToClientIdentifier(string value, int kind) => (ClientIdKind)kind switch
    {
        ClientIdKind.ClientIdMetadataDocument => ClientIdentifier.ForCimd(value),
        ClientIdKind.Dynamic => ClientIdentifier.ForDynamic(value),
        ClientIdKind.PreRegistered => ClientIdentifier.ForPreRegistered(value),
        _ => ClientIdentifier.TryParseFromRequest(value, out var parsed)
            ? parsed
            : throw new InvalidOperationException("A client_id column holds a value no ClientIdentifier accepts."),
    };

    /// <summary>The resource list as one column value.</summary>
    /// <exception cref="ArgumentException">
    /// A resource contains the separator, so the value would not read back as it was written.
    /// </exception>
    internal static string EncodeResources(IReadOnlyList<string> resources)
    {
        ArgumentNullException.ThrowIfNull(resources);

        foreach (var resource in resources)
        {
            if (resource is null || resource.Contains(ResourceSeparator, StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "A resource identifier may not be null or contain a newline: this column is newline-separated, "
                    + "so such a value would be read back as two resources.",
                    nameof(resources));
            }
        }

        return string.Join(ResourceSeparator, resources);
    }

    /// <summary>The resource list, back out of one column value.</summary>
    internal static IReadOnlyList<string> DecodeResources(string stored) =>
        string.IsNullOrEmpty(stored)
            ? []
            : stored.Split(ResourceSeparator);

    /// <summary>
    /// The form the unique username index is built on.
    /// </summary>
    /// <remarks>
    /// The uppercase invariant form. <see cref="StringComparer.OrdinalIgnoreCase"/>, which the
    /// in-memory store keys its username index with, is documented as an ordinal comparison of the
    /// uppercase invariant forms - so folding here and comparing ordinally is the same question
    /// asked in SQL, without depending on the database's collation to agree.
    /// </remarks>
    internal static string NormalizeUsername(string username) => username.ToUpperInvariant();

    /// <summary>
    /// The form the email index is built on, or null for an account with no address.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The same fold as a username, for the same reason: the comparison happens on a stored column
    /// so the answer does not depend on the provider's collation. It is a separate method because
    /// the two are separate decisions - a username is a name this server assigns meaning to, an
    /// address belongs to a mail system - and one of them changing should not silently change the
    /// other's index.
    /// </para>
    /// <para>
    /// The whole address, not the local part only. Folding the local part is what a mail server may
    /// do with its own users and is not something a directory may assume about somebody else's:
    /// <c>Ada@example.com</c> and <c>ada@example.com</c> are the same mailbox in practice and this
    /// treats them as one, while <c>a.da@</c> and <c>ada@</c> stay distinct because only Gmail says
    /// they are not.
    /// </para>
    /// </remarks>
    internal static string? NormalizeEmail(string? email) =>
        string.IsNullOrEmpty(email) ? null : email.ToUpperInvariant();
}
