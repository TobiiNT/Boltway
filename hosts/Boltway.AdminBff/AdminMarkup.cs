using System.Net;
using System.Text.Json;

namespace Boltway.AdminBff;

/// <summary>
/// Turning a value into something safe to put on a page, and reading the API's JSON.
/// </summary>
/// <remarks>
/// <para>
/// <b>Public because a replacement renderer needs it.</b> Every page here renders handles, email
/// addresses, roles and audit details that an operator typed and that this app has never validated —
/// it is a client, not the directory — so "it came from our own API" is not a reason to trust a
/// string. An implementer of <see cref="IAdminRenderer"/> who had to bring their own encoder would
/// be one <c>string.Format</c> away from the injection this app's own pages are careful about, and
/// the seam would have handed them that risk on its first day.
/// </para>
/// <para>
/// It was a set of private statics on the old <c>Pages</c> class, where there was exactly one
/// renderer and nothing to share them with.
/// </para>
/// </remarks>
public static class AdminMarkup
{
    /// <summary>Encode a value for HTML. The only route from a value to a page.</summary>
    /// <param name="value">Anything, including <see langword="null"/>, which encodes to nothing.</param>
    /// <remarks>
    /// <b>Once, and only once.</b> Sentences coming out of <see cref="AdminText"/>'s indexer are
    /// already encoded and must not go through here again: the authorization server's renderer
    /// carries a comment about exactly this, where a second pass rendered <c>Café</c> as
    /// <c>Caf&amp;#233;</c>. Vietnamese is made almost entirely of characters that would go the same
    /// way. Use <see cref="AdminText.Plain"/> when a sentence is headed somewhere that encodes.
    /// </remarks>
    public static string Encode(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);

    /// <summary>A string property, or empty when it is absent or is not a string.</summary>
    /// <param name="o">An object from the admin API.</param>
    /// <param name="name">The property to read.</param>
    /// <remarks>
    /// Total rather than throwing, because the alternative is an admin page that 500s when the API
    /// adds or drops a field. A missing value renders as a blank cell, which an operator can see and
    /// report; an exception renders as nothing at all.
    /// </remarks>
    public static string Text(JsonElement o, string name) =>
        o.ValueKind is JsonValueKind.Object
        && o.TryGetProperty(name, out var v)
        && v.ValueKind is JsonValueKind.String
            ? v.GetString()!
            : string.Empty;

    /// <summary>
    /// A property that is a list of strings, joined with spaces.
    /// </summary>
    /// <param name="o">An object from the admin API.</param>
    /// <param name="name">The property to read.</param>
    /// <remarks>
    /// <para>
    /// <b>Written after this exact shape shipped broken.</b> <c>AdminUserView</c> serialises an
    /// account's roles under the key <c>role</c>, and that value became an <i>array</i> when an
    /// account started holding several. <see cref="Text"/> requires a JSON string and answers empty
    /// for anything else, so every role rendered blank — and because the patch form posts every
    /// field it shows, saving an unrelated change then cleared the account's roles.
    /// </para>
    /// <para>
    /// A string is still accepted, and not for elegance: the admin UI and the authorization server
    /// are separate deployables on separate images, so during any rollout one of them is older than
    /// the other. Refusing the scalar would make the page blank for exactly as long as that lasts,
    /// which is the same failure by a different route.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<string> Texts(JsonElement o, string name)
    {
        if (o.ValueKind is not JsonValueKind.Object || !o.TryGetProperty(name, out var v))
        {
            return [];
        }

        if (v.ValueKind is JsonValueKind.String)
        {
            return v.GetString() is { Length: > 0 } single ? [single] : [];
        }

        if (v.ValueKind is not JsonValueKind.Array)
        {
            return [];
        }

        return [.. v.EnumerateArray()
            .Where(e => e.ValueKind is JsonValueKind.String)
            .Select(e => e.GetString()!)
            .Where(s => s.Length > 0)];
    }

    /// <summary>The same, as one space-separated string. Empty when there are none.</summary>
    /// <param name="o">An object from the admin API.</param>
    /// <param name="name">The property to read.</param>
    public static string TextList(JsonElement o, string name) => string.Join(' ', Texts(o, name));

    /// <summary>A boolean property, true only when it is literally <c>true</c>.</summary>
    /// <param name="o">An object from the admin API.</param>
    /// <param name="name">The property to read.</param>
    /// <remarks>
    /// Absent is false, and so is any other kind. The two flags read through here —
    /// <c>email_verified</c> and the presence of a password — are both cases where guessing "true"
    /// from a value this app did not understand would state a security property that may not hold.
    /// </remarks>
    public static bool Flag(JsonElement o, string name) =>
        o.ValueKind is JsonValueKind.Object
        && o.TryGetProperty(name, out var v)
        && v.ValueKind is JsonValueKind.True;
}
