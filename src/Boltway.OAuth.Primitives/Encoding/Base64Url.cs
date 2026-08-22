using System.Buffers;

namespace Boltway.OAuth.Primitives.Encoding;

/// <summary>
/// base64url without padding, RFC 4648 §5.
/// </summary>
/// <remarks>
/// The encoding every OAuth and JOSE value uses: PKCE code challenges, JWT segments, <c>jti</c>,
/// <c>at_hash</c>, JWK thumbprints, and every opaque secret this server mints. Distinct from
/// ordinary base64 in three ways that all matter on the wire: <c>+</c> becomes <c>-</c>, <c>/</c>
/// becomes <c>_</c>, and the <c>=</c> padding is dropped.
/// <para>
/// Padding is the one worth naming. RFC 7636 §4.2 defines the code challenge as base64url
/// <i>without</i> padding, and the comparison against a stored challenge is byte-exact — so an
/// encoder that emits <c>abc=</c> where the client sent <c>abc</c> produces a PKCE mismatch on
/// every single request, with an error that says nothing about padding.
/// </para>
/// </remarks>
public static class Base64Url
{
    /// <summary>Encode bytes as unpadded base64url.</summary>
    public static string Encode(ReadOnlySpan<byte> bytes) => System.Buffers.Text.Base64Url.EncodeToString(bytes);

    /// <summary>
    /// Decode unpadded base64url. Returns <see langword="false"/> rather than throwing, because
    /// every caller is parsing attacker-supplied input.
    /// </summary>
    public static bool TryDecode(string? value, out byte[] bytes)
    {
        bytes = [];

        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        // Decode must be the inverse of Encode, and the framework decoder is more permissive than
        // that: measured on .NET 10 it accepts "AA==", "AA=", " AA" and "AA\n", all of which decode
        // to the same single byte as "AA". Four spellings of one value is an aliasing bug waiting
        // for a caller that keys anything on the string form — a replay table, a revocation list, a
        // cache — while identity comes from the decoded bytes.
        foreach (var c in value)
        {
            var ok = c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_';
            if (!ok)
            {
                return false;
            }
        }

        // A base64 quantum is 4 characters encoding 3 bytes; a remainder of 1 character encodes
        // nothing and cannot be produced by any input.
        if (value.Length % 4 == 1)
        {
            return false;
        }

        var buffer = new byte[System.Buffers.Text.Base64Url.GetMaxDecodedLength(value.Length)];

        if (System.Buffers.Text.Base64Url.DecodeFromChars(value, buffer, out _, out var written)
            != OperationStatus.Done)
        {
            return false;
        }

        bytes = buffer[..written];
        return true;
    }
}
