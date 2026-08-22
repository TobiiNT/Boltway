using System.Net;
using System.Text.Json;

namespace Boltway.AdminBff.Tests;

/// <summary>
/// Building a renderer and giving it something to draw.
/// </summary>
/// <remarks>
/// The words and the privileged roles moved from a parameter on every page to the renderer's own
/// state when <c>IAdminRenderer</c> replaced the static <c>Pages</c> class, so a test that varies
/// either of them varies the renderer rather than the call. That is the same shape the app has:
/// <c>Program.cs</c> builds one renderer at startup and the endpoints pass only what the request
/// carried.
/// </remarks>
internal static class Render
{
    /// <summary>A renderer in the shipped shell, with a deployment's words, roles and vocabulary.</summary>
    internal static DefaultAdminRenderer With(
        AdminText? text = null, IReadOnlyCollection<string>? adminRoles = null,
        IReadOnlyCollection<string>? permissions = null)
    {
        var words = text ?? AdminText.Default;

        return new DefaultAdminRenderer(
            new DefaultAdminLayout(words, [DefaultAdminLayout.ShippedStylesheet]), words, adminRoles,
            permissions);
    }

    /// <summary>A table of words, from pairs, for a deployment that translated some of them.</summary>
    internal static AdminText Text(params (string Key, string Value)[] pairs) =>
        new(pairs.ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal));

    /// <summary>
    /// A stand-in antiforgery pair.
    /// </summary>
    /// <remarks>
    /// Every page takes one, because the shell draws a sign-out form on every page. It was only on
    /// the two pages with an operator-filled form until that form was found to be answering 400.
    /// </remarks>
    internal static AntiforgeryTokens Tokens { get; } = new("__field", "__token");

    /// <summary>JSON as the admin API would have returned it.</summary>
    internal static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement;

    /// <summary>An account with a password, an address and a role.</summary>
    internal static JsonElement Account(string role = "employee") => Json(
        $$"""
        {"handle":"grace","email":"grace@example.com","email_verified":true,"role":"{{role}}",
         "subject":"01JBK7Q2VN8XW4M0ZC3RTA9HDE","realm":"northwind","has_password":true}
        """);

    /// <summary>The account page, which is where most of the words appear.</summary>
    internal static string AccountPage(
        JsonElement account, AdminText? text = null, IReadOnlyCollection<string>? adminRoles = null) =>
        With(text, adminRoles).RenderAccount(new AccountViewModel(account, Tokens, null, "ada"));

    /// <summary>A refusal with no body, which is what the admin API sends when it refuses.</summary>
    internal static AdminResult Refusal(HttpStatusCode status, string? error, string? description) =>
        new(status, default, error, description);

    /// <summary>What a browser puts on the screen, rather than what went down the wire.</summary>
    internal static string Decoded(string html) => WebUtility.HtmlDecode(html);
}
