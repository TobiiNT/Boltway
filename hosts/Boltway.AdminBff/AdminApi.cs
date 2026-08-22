using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;

namespace Boltway.AdminBff;

/// <summary>What the admin API said, and whether it was willing to say it.</summary>
/// <param name="Status">The status it answered with.</param>
/// <param name="Body">The parsed body, when there was one.</param>
/// <param name="Error">The <c>error</c> code from a refusal, when there was one.</param>
/// <param name="Description">The sentence beside it.</param>
public sealed record AdminResult(
    HttpStatusCode Status, JsonElement Body, string? Error = null, string? Description = null)
{
    /// <summary>Whether the call did what it was asked.</summary>
    public bool Ok => (int)Status is >= 200 and < 300;

    /// <summary>Whether the token is no longer accepted, so the operator has to sign in again.</summary>
    public bool Unauthenticated => Status is HttpStatusCode.Unauthorized;
}

/// <summary>
/// The one place this app talks to the authorization server.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every call carries a bearer token and nothing else — <c>N-17</c> from the client's side.</b>
/// The browser's cookie authenticates the operator to <i>this</i> app, on this app's hostname; the
/// admin API never sees it. That is what makes the BFF shape leave the rule intact rather than
/// bending it.
/// </para>
/// <para>
/// <b>The token comes out of the session, and the session lives in the ticket store</b>, so it is
/// read here and never rendered, logged, or put in a form. A page that needed the token would be
/// the beginning of a single-page app.
/// </para>
/// <para>
/// <b>Refusals are returned rather than thrown.</b> A 403 from the admin API is an ordinary answer
/// — an operator whose entitlement has been narrowed — and turning it into an exception would make
/// the page that renders it an error page rather than one that says which permission is missing.
/// </para>
/// </remarks>
/// <param name="clients">Where the <c>HttpClient</c> comes from.</param>
/// <param name="options">Where the admin API is.</param>
public sealed class AdminApi(IHttpClientFactory clients, AdminBffOptions options)
{
    /// <summary>A page of accounts. <c>E-25</c>.</summary>
    public Task<AdminResult> ListUsersAsync(HttpContext http, string? after, CancellationToken ct) =>
        SendAsync(http, HttpMethod.Get, "/admin/users?limit=50" + (after is { Length: > 0 } ? "&after=" + Uri.EscapeDataString(after) : ""), null, ct);

    /// <summary>One account. <c>E-26</c>.</summary>
    public Task<AdminResult> GetUserAsync(HttpContext http, string handle, CancellationToken ct) =>
        SendAsync(http, HttpMethod.Get, "/admin/users/" + Uri.EscapeDataString(handle), null, ct);

    /// <summary>Create one. <c>E-27</c>.</summary>
    public Task<AdminResult> CreateUserAsync(HttpContext http, object body, CancellationToken ct) =>
        SendAsync(http, HttpMethod.Post, "/admin/users", body, ct);

    /// <summary>Change role, email or enabled. <c>E-28</c>.</summary>
    public Task<AdminResult> PatchUserAsync(HttpContext http, string handle, object body, CancellationToken ct) =>
        SendAsync(http, HttpMethod.Patch, "/admin/users/" + Uri.EscapeDataString(handle), body, ct);

    /// <summary>Generate a new password. <c>E-29</c>.</summary>
    public Task<AdminResult> ResetPasswordAsync(HttpContext http, string handle, CancellationToken ct) =>
        SendAsync(http, HttpMethod.Post, "/admin/users/" + Uri.EscapeDataString(handle) + "/password", null, ct);

    /// <summary>End every session. <c>E-30</c>.</summary>
    public Task<AdminResult> RevokeSessionsAsync(HttpContext http, string handle, CancellationToken ct) =>
        SendAsync(http, HttpMethod.Delete, "/admin/users/" + Uri.EscapeDataString(handle) + "/sessions", null, ct);

    /// <summary>Anonymise. <c>E-31</c>. Irreversible.</summary>
    public Task<AdminResult> AnonymiseAsync(HttpContext http, string handle, CancellationToken ct) =>
        SendAsync(http, HttpMethod.Post, "/admin/users/" + Uri.EscapeDataString(handle) + "/anonymise", null, ct);

    /// <summary>This account's service account, if it has one. <c>E-33</c>.</summary>
    public Task<AdminResult> GetServiceAccountAsync(HttpContext http, string handle, CancellationToken ct) =>
        SendAsync(http, HttpMethod.Get,
            "/admin/users/" + Uri.EscapeDataString(handle) + "/service-account", null, ct);

    /// <summary>Create one, or rotate its secret. The response carries the only copy.</summary>
    public Task<AdminResult> CreateServiceAccountAsync(
        HttpContext http, string handle, object body, CancellationToken ct) =>
        SendAsync(http, HttpMethod.Post,
            "/admin/users/" + Uri.EscapeDataString(handle) + "/service-account", body, ct);

    /// <summary>Stop or restart it obtaining tokens.</summary>
    public Task<AdminResult> SetServiceAccountEnabledAsync(
        HttpContext http, string handle, object body, CancellationToken ct) =>
        SendAsync(http, HttpMethod.Patch,
            "/admin/users/" + Uri.EscapeDataString(handle) + "/service-account", body, ct);

    /// <summary>Remove it.</summary>
    public Task<AdminResult> DeleteServiceAccountAsync(
        HttpContext http, string handle, CancellationToken ct) =>
        SendAsync(http, HttpMethod.Delete,
            "/admin/users/" + Uri.EscapeDataString(handle) + "/service-account", null, ct);

    /// <summary>Every role this realm defines.</summary>
    public Task<AdminResult> ListRolesAsync(HttpContext http, CancellationToken ct) =>
        SendAsync(http, HttpMethod.Get, "/admin/roles", null, ct);

    /// <summary>Define one. The id is what tokens will carry.</summary>
    public Task<AdminResult> CreateRoleAsync(HttpContext http, object body, CancellationToken ct) =>
        SendAsync(http, HttpMethod.Post, "/admin/roles", body, ct);

    /// <summary>
    /// Change what it is called or what it stands for. Never what it is.
    /// </summary>
    /// <remarks>
    /// There is no route here that changes an id, because the API has none: an id reaches every
    /// token, both halves of <c>ADMIN_ROLES</c> and any external role mapping, so it is chosen once.
    /// Renaming one is defining a second role and moving accounts to it.
    /// </remarks>
    public Task<AdminResult> PatchRoleAsync(HttpContext http, string id, object body, CancellationToken ct) =>
        SendAsync(http, HttpMethod.Patch, "/admin/roles/" + Uri.EscapeDataString(id), body, ct);

    /// <summary>Remove it, and every assignment of it.</summary>
    public Task<AdminResult> DeleteRoleAsync(HttpContext http, string id, CancellationToken ct) =>
        SendAsync(http, HttpMethod.Delete, "/admin/roles/" + Uri.EscapeDataString(id), null, ct);

    /// <summary>The audit log. <c>E-32</c>.</summary>
    public Task<AdminResult> AuditAsync(HttpContext http, CancellationToken ct) =>
        SendAsync(http, HttpMethod.Get, "/admin/audit?limit=100", null, ct);

    private async Task<AdminResult> SendAsync(
        HttpContext http, HttpMethod method, string path, object? body, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(http);

        var token = await http.GetTokenAsync("access_token");

        if (token is not { Length: > 0 })
        {
            // No token in a session that authenticated is a session whose tokens expired and could
            // not be refreshed. Answering 401 sends the page down the same path a rejected token
            // would, which is the one that ends in signing in again.
            return new AdminResult(HttpStatusCode.Unauthorized, default, "no_token", "This session has no access token.");
        }

        using var request = new HttpRequestMessage(method, options.AdminApi.TrimEnd('/') + path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        using var response = await clients.CreateClient("admin").SendAsync(request, ct);

        JsonElement parsed = default;
        string? error = null;
        string? description = null;

        if (response.Content.Headers.ContentLength is not 0)
        {
            try
            {
                parsed = await response.Content.ReadFromJsonAsync<JsonElement>(ct);

                if (parsed.ValueKind is JsonValueKind.Object)
                {
                    error = parsed.TryGetProperty("error", out var e) ? e.GetString() : null;
                    description = parsed.TryGetProperty("error_description", out var d) ? d.GetString() : null;
                }
            }
            catch (JsonException)
            {
                // A body this app cannot parse is a proxy's error page or a bug on the other side.
                // Neither is worth a 500 here: the status is the part a page acts on.
            }
        }

        return new AdminResult(response.StatusCode, parsed, error, description);
    }
}
