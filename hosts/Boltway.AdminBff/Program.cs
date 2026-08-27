// The admin UI, as a backend-for-frontend. §7.1.
//
// N-17 says no admin endpoint may be reached with a cookie principal, so the admin UI cannot be a
// page on the authorization server: it has to be an OAuth client. Of the two shapes for one, the
// SPA keeps the token in the browser - one XSS from exfiltration, and it needs CORS on the admin
// API plus a connect-src widening here - and the BFF keeps it server side at the cost of one more
// small deployable. What is behind this API is the directory rather than a document, so this is the
// BFF.
//
// N-17 is untouched by it. The browser's cookie is scoped to this app's hostname and this app's
// session; the admin API only ever sees a bearer token, which is exactly what the rule says.
//
// It shows its own consent screen to the operator once, which reads oddly and is correct: consent
// is what binds users:write to a person entitled to it (§1.3), and an admin UI that skipped it
// would be the one client exempt from the check.

using System.Globalization;
using System.Text.Json;
using System.Security.Claims;
using Boltway.AdminBff;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

var authority = Required("AUTHORITY", "the authorization server's issuer URL");

// The roles the authorization server grants users:read and users:write to. Read here only to say
// what a role means on the page - this app decides nothing, and AdminRoleScopePolicy on the server
// remains the only thing that enforces it.
//
// Optional, and unset is not an error: a deployment that has not told this app simply gets pages
// that say nothing about administration, which is better than a page confidently naming a set it
// was never given. It is the same string as the authorization server's ADMIN_ROLES and has to be
// kept in step with it; there is no way for this app to check that, because the server exposes no
// endpoint saying which roles it privileges.
var adminRoles = (config["ADMIN_ROLES"] ?? string.Empty)
    .Split([',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
    .Distinct(StringComparer.Ordinal)
    .ToArray();

// What the pages say, when a deployment wants them to say it in its own language. The file is a
// JSON object of key to sentence, keys being the constants on AdminText.
//
// Optional, and a partial file is a partial translation rather than a broken page: every key falls
// back to English on its own. That is the property the authorization server's translation file has,
// and this now has the other half of it too - see the sweep below.
var adminText = AdminText.Default;

if (config["ADMIN_TEXT_FILE"] is { Length: > 0 } textPath)
{
    var strings = JsonSerializer.Deserialize<Dictionary<string, string>>(
        File.ReadAllText(textPath), JsonSerializerOptions.Web)
        ?? throw new InvalidOperationException($"{textPath} is not a JSON object.");

    // Keys this build does not know, named at startup. The authorization server has done this for
    // its own translation file since that file existed, and the comment here used to record the
    // asymmetry as a fact of life: "a typo'd key is silently the English sentence". That is the
    // worst way for this to fail. Per-string fallback means a mistyped key produces a page that is
    // correct English rather than a page that is broken, so the one signal a translator gets is a
    // sentence that did not change - and the natural conclusion is that the file is not being read
    // at all. AdminText.Keys is public for exactly this check.
    //
    // Reported, not fatal, for the reason the server gives: a key this version does not have is a
    // translation written for another one, and refusing to start over it would make upgrading this
    // app a coordinated change with whoever holds the strings.
    //
    // LanguageKey is excluded rather than reported. It is a legal entry and deliberately not in
    // Keys - it names the language rather than saying anything - so warning about it would train a
    // reader to ignore this line, which costs more than the line is worth.
    var known = AdminText.Keys.ToHashSet(StringComparer.Ordinal);

    var unknown = strings.Keys
        .Where(key => !known.Contains(key) && key != AdminText.LanguageKey)
        .ToList();

    if (unknown.Count > 0)
    {
        Console.Error.WriteLine(
            $"{textPath} has {unknown.Count} key(s) this build does not know, which will be "
            + $"ignored: {string.Join(", ", unknown)}");
    }

    adminText = new AdminText(strings);
}

// The permission vocabulary the deployment's resource server understands, for the roles page to
// offer as checkboxes. The same contract as ADMIN_ROLES, including the honest part: this is a
// hand-written copy of a list that lives in the resource server, kept in step by hand, and this
// app has no way to check it. Drift costs a checkbox too many or too few - never enforcement,
// which stays wherever the resource server put it. Unset keeps the free-text box.
var adminPermissions = (config["ADMIN_PERMISSIONS"] ?? string.Empty)
    .Split([',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
    .Distinct(StringComparer.Ordinal)
    .ToArray();

var options = new AdminBffOptions
{
    Authority = authority,
    AdminApi = config["ADMIN_API"] ?? authority,
    ClientId = Required("CLIENT_ID", "what this app is registered as on the authorization server"),
    ClientSecret = Required("CLIENT_SECRET", "this app's secret — it is a confidential client"),

    // Derived, and it has to be derived the same way the authorization server derives it: issuer
    // plus `/admin`. That server computes the audience of the tokens it mints from its own issuer,
    // so a value typed separately here is a value that can disagree with it - and the symptom is
    // an `invalid_target` at /authorize, or worse a token with the wrong `aud` that the resource
    // server refuses much later.
    //
    // It was `Required` and cost a setting on both sides for a string neither end had a choice
    // about. ADMIN_RESOURCE remains as an override for the deployment that puts the admin API on
    // its own hostname (§1.4), which is the only case where the two differ.
    Resource = config["ADMIN_RESOURCE"] ?? authority.TrimEnd('/') + "/admin",

    // What to link, in order. Unset keeps the sheet this app ships and serves out of wwwroot, so a
    // deployment that says nothing is unchanged; setting it replaces the list rather than adding to
    // it, which is why a deployment layering an override names both.
    //
    // It exists because the shell used to write `href="/css/admin.css"` as a literal, so the only
    // way to restyle this app was to land a file at that exact path - one deployment mounts a
    // whole directory over wwwroot/css to do it, and carries a paragraph of compose comment
    // explaining why it must be that name.
    StylesheetPaths = config["ADMIN_STYLESHEETS"] is { Length: > 0 } sheets
        ? sheets.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        : [DefaultAdminLayout.ShippedStylesheet],
};

// At startup, naming the setting. These pages send default-src 'self', so a stylesheet on another
// origin is refused by the browser - and the only trace of that is a line in a console nobody has
// open, on a page that renders unstyled in production.
if (!options.TryValidate(out var problems))
{
    throw new InvalidOperationException(string.Join(Environment.NewLine, problems));
}

builder.Services.AddSingleton(options);

// The three tiers of changing this UI, wired in the order they nest: the stylesheet is configuration,
// the layout is the document around a page, and the renderer is the pages themselves. A deployment
// forking this app replaces one of the two implementations here and leaves the endpoints alone.
builder.Services.AddSingleton<IAdminLayout>(new DefaultAdminLayout(adminText, options.StylesheetPaths));
builder.Services.AddSingleton<IAdminRenderer>(sp =>
    new DefaultAdminRenderer(sp.GetRequiredService<IAdminLayout>(), adminText, adminRoles, adminPermissions));
builder.Services.AddHttpClient("admin");
builder.Services.AddSingleton<AdminApi>();
builder.Services.AddAntiforgery(o => o.Cookie.SecurePolicy = CookieSecurePolicy.Always);

// The whole reason this is a BFF. Without it the cookie handler serialises the tokens into the
// cookie - encrypted, but handed to the browser on every response - and "the token never reaches
// the browser" would be approximately true rather than true.
builder.Services.AddSingleton<ITicketStore, InMemoryTicketStore>();
builder.Services.AddSingleton<IPostConfigureOptions<CookieAuthenticationOptions>, UseTicketStore>();

builder.Services
    .AddAuthentication(o =>
    {
        o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(o =>
    {
        o.Cookie.Name = "boltway.admin";
        o.Cookie.SameSite = SameSiteMode.Lax;
        o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        o.Cookie.HttpOnly = true;

        // Short, because this is the directory. An operator signing in again is a redirect they
        // barely notice; a session left open on a shared machine is the whole surface.
        o.ExpireTimeSpan = TimeSpan.FromHours(8);
        o.SlidingExpiration = true;
    })
    .AddOpenIdConnect(o =>
    {
        o.Authority = options.Authority;
        o.ClientId = options.ClientId;
        o.ClientSecret = options.ClientSecret;

        // The code flow with PKCE and a secret. Confidential, so the handler authenticates at
        // /token with client_secret_basic - which is what a CIMD client cannot do, and the reason
        // CLIENTS exists on the server side.
        o.ResponseType = OpenIdConnectResponseType.Code;
        o.UsePkce = true;

        // `query`, because that is what the server advertises. The handler's default for the code
        // flow is `form_post`, and asking for a response mode a server's metadata does not list is
        // the client half of N-06 - the request looks fine and the answer comes back in a shape
        // nobody agreed on. Measured: the discovery document says response_modes_supported: ["query"].
        o.ResponseMode = OpenIdConnectResponseMode.Query;

        o.Scope.Clear();
        o.Scope.Add("openid");
        o.Scope.Add("users:read");
        o.Scope.Add("users:write");

        // Tokens are kept, and kept in the ticket store above rather than in the cookie.
        o.SaveTokens = true;

        // **False, and this app fetches the same document itself - see OnTokenValidated below.**
        // Not an oversight and not a default left alone: this switch fails the whole sign-in when
        // /userinfo cannot be reached or is not served, and the only thing this app wants from
        // there is the label in the header. `UserInfoEnabled` is a deployment's to turn off, so
        // true here would be an admin UI that cannot be entered on a deployment that did.
        o.GetClaimsFromUserInfoEndpoint = false;

        // RFC 8707. The access token's `aud` is bound to the admin API, so a token minted here
        // cannot be replayed against the customer's connector - which is the whole point of the
        // admin API being its own resource.
        o.Events.OnRedirectToIdentityProvider = context =>
        {
            context.ProtocolMessage.SetParameter("resource", options.Resource);

            return Task.CompletedTask;
        };

        // Redeeming the code by hand, for one reason: to authenticate with `client_secret_basic`.
        //
        // §7.1 says this client "uses the client store and client_secret_basic that already exist",
        // and RFC 6749 §2.3.1 says a client with a password SHOULD use Basic - the form-encoded
        // alternative is for clients that cannot. The handler's built-in redemption puts the secret
        // in the body and this package version exposes no switch, so the choice is between doing
        // this or quietly using the method the RFC treats as the fallback. Measured before writing
        // it: the server answered `invalid_client`, "This client must authenticate with a client
        // secret", because the record declares Basic and the body carried the secret instead.
        //
        // It is thirty lines and it is the whole of the hand-rolled OAuth in this app. Everything
        // else - PKCE, state, nonce, the cookie, the refresh - is still the handler's.
        o.Events.OnAuthorizationCodeReceived = async context =>
        {
            var request = context.TokenEndpointRequest!;

            request.SetParameter("resource", options.Resource);

            // Out of the body: sending it in both places is not "belt and braces", it is a request
            // that two conformant servers read differently.
            request.ClientSecret = null;

            var form = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["grant_type"] = "authorization_code",
                ["code"] = request.Code,
                ["redirect_uri"] = request.RedirectUri,
                ["code_verifier"] = request.GetParameter("code_verifier") ?? string.Empty,
                ["resource"] = options.Resource,
            };

            // Through the configuration manager rather than `Options.Configuration`, which is only
            // populated when a deployment pinned the document by hand. This is the same call the
            // handler makes, so the endpoint used here is the one discovery published.
            var discovery = await context.Options.ConfigurationManager!.GetConfigurationAsync(
                context.HttpContext.RequestAborted);

            using var token = new HttpRequestMessage(HttpMethod.Post, discovery.TokenEndpoint)
            {
                Content = new FormUrlEncodedContent(form),
            };

            // RFC 6749 §2.3.1: both halves are form-urlencoded before the base64, because a client
            // id may contain characters the colon separator would otherwise swallow.
            token.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
                "Basic",
                Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(
                    Uri.EscapeDataString(options.ClientId) + ":" + Uri.EscapeDataString(options.ClientSecret))));

            using var response = await context.Backchannel.SendAsync(token, context.HttpContext.RequestAborted);
            var body = await response.Content.ReadAsStringAsync(context.HttpContext.RequestAborted);

            if (!response.IsSuccessStatusCode)
            {
                // The server's own words. Its refusals name the rule that was broken, and a
                // paraphrase here would lose the part an operator acts on.
                context.Fail($"The token endpoint refused this: {body}");

                return;
            }

            context.HandleCodeRedemption(new OpenIdConnectMessage(body));
        };

        // The handle behind the ULID, asked once per sign-in.
        //
        // The rail names whoever is signed in, and until this it named them by subject: this
        // server's ID token carries no name of any kind, so `Who` fell through to `sub` and an
        // operator got 26 characters to compare against a table keyed by handle. `/userinfo` is the
        // only channel a client has for it - see OperatorProfile, which also has why this is not
        // `GetClaimsFromUserInfoEndpoint` and why no scope is added to reach it.
        //
        // Out of the discovery document rather than composed from AUTHORITY, for the reason every
        // other endpoint in this app is: a server that does not serve /userinfo names none, and that
        // absence is the answer rather than a 404 to interpret. It is a dictionary lookup by this
        // point - the handler resolved the same document to redeem the code and to find the signing
        // keys - so this costs one request, not two.
        o.Events.OnTokenValidated = async context =>
        {
            if (context.Principal?.Identity is not ClaimsIdentity identity)
            {
                return;
            }

            try
            {
                var discovery = await context.Options.ConfigurationManager!.GetConfigurationAsync(
                    context.HttpContext.RequestAborted);

                var handle = await OperatorProfile.HandleAsync(
                    context.Options.Backchannel,
                    discovery.UserInfoEndpoint,
                    context.TokenEndpointResponse?.AccessToken,
                    context.HttpContext.RequestAborted);

                if (handle is { Length: > 0 })
                {
                    identity.AddClaim(new Claim(OperatorProfile.ClaimType, handle));
                }
            }
            catch (Exception failed) when (failed is not OperationCanceledException)
            {
                // Swallowed, and this is the second place in this app where that is right. The
                // tokens are valid and the session is about to be established; the only thing lost
                // is a label. Letting this throw would turn a completed sign-in into an error page
                // - which is the shape of the defect this whole event exists to fix, arriving by a
                // different route.
                context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>()
                    .CreateLogger("Boltway.AdminBff.SignIn")
                    .LogWarning(
                        failed,
                        "Signed in, but could not read the operator's handle from /userinfo. The "
                        + "header will name them by subject.");
            }
        };
    });

builder.Services.AddAuthorization();

// Behind a proxy in every real deployment, so the scheme has to come from the header or every
// redirect this app builds is http and the cookie's Secure policy refuses to write.
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    // Cleared, because the proxy in front is not on a known private range in every deployment and
    // an unlisted one has its headers ignored. The trade is stated rather than hidden: this app must
    // not be reachable except through that proxy, or the headers are attacker-controlled.
    o.KnownIPNetworks.Clear();
    o.KnownProxies.Clear();
});

var app = builder.Build();

app.UseForwardedHeaders();

// Zero JavaScript, so the policy can be this tight. §7.1 counted that as one of the BFF's
// advantages; it is only an advantage if it is actually asserted.
app.Use(async (http, next) =>
{
    http.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'";
    http.Response.Headers["X-Frame-Options"] = "DENY";
    http.Response.Headers["Referrer-Policy"] = "no-referrer";
    http.Response.Headers["X-Content-Type-Options"] = "nosniff";

    // The authorization server sends no-store on every interaction page and this app sent it on
    // none, which was wrong before and is wronger now. Its argument there is that a cached consent
    // page on a shared machine shows the next user what the last one was asked to approve; here the
    // pages hold the directory, one of them holds a generated password that exists nowhere else, and
    // since antiforgery moved into the shell every page carries a token as well.
    //
    // Documents only, and deciding that needs the content type, which is not known yet - hence
    // OnStarting rather than a line beside the others. UseStaticFiles is downstream of this
    // middleware, so an unconditional header would also land on the stylesheet, the four icons and
    // the six woff2 subsets: bytes that are identical for every operator, hold nothing, and would be
    // re-fetched on every navigation. Pragma is for a proxy that only speaks HTTP/1.0.
    http.Response.OnStarting(static state =>
    {
        var response = (HttpResponse)state;

        if (response.ContentType?.StartsWith("text/html", StringComparison.OrdinalIgnoreCase) is true)
        {
            response.Headers.CacheControl = "no-store";
            response.Headers.Pragma = "no-cache";
        }

        return Task.CompletedTask;
    }, http.Response);

    await next();
});

app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { ok = true })).AllowAnonymous();

// ─────────────────────────────────────────────────────────────────────────────
// Pages
// ─────────────────────────────────────────────────────────────────────────────

app.MapGet("/", async (
    HttpContext http, AdminApi api, IAntiforgery antiforgery, IAdminRenderer renderer, CancellationToken ct) =>
{
    var after = http.Request.Query["after"].ToString();
    var result = await api.ListUsersAsync(http, after, ct);

    return result.Ok
        ? Html(renderer.RenderAccounts(new AccountsViewModel(
            result.Body, Tokens(http, antiforgery), http.Request.Query["notice"], Who(http))
        {
            // The key names the sentence and this fills its {0}; neither is the sentence itself.
            // Both arrive from a link, so the renderer treats them that way - see its Notice.
            NoticeValue = http.Request.Query["notice_value"],
        }))
        : Refused(http, result);
}).RequireAuthorization();

app.MapGet("/users/new", (HttpContext http, IAntiforgery antiforgery, IAdminRenderer renderer) =>
{
    var tokens = Tokens(http, antiforgery);

    return Html(renderer.RenderNewAccount(new NewAccountViewModel(
        tokens, http.Request.Query["error"], Who(http))));
}).RequireAuthorization();

app.MapPost("/users/new", async (
    HttpContext http, AdminApi api, IAntiforgery antiforgery, IAdminRenderer renderer, CancellationToken ct) =>
{
    if (await Forged(http, antiforgery) is { } refusal)
    {
        return refusal;
    }

    var form = await http.Request.ReadFormAsync(ct);

    var result = await api.CreateUserAsync(
        http,
        new
        {
            handle = form["handle"].ToString(),
            email = Blank(form["email"]),
            // Singular here on purpose: the create form offers one box and the API takes either.
            // A new account holding several roles is an edit, not a creation.
            role = Blank(form["role"]),
        },
        ct);

    // A taken handle goes back to the form, because it is something to retype rather than something
    // to give up on, and it carries the server's own sentence saying which field is the problem.
    //
    // **Only when there is one.** The `?? "Refused."` this replaces was the last sentence in this
    // file that no ADMIN_TEXT_FILE could reach - an English word on a translated form, and one that
    // named nothing an operator could act on. A conflict the server declined to explain is an
    // unexplained refusal like any other, and the refusal page already has a translated sentence for
    // exactly that. So what this app puts here is the API's words or nothing.
    //
    // Unlike the notice banner, this parameter is still whatever a link says it is - an error on the
    // create form is the server's sentence rather than one of a closed set, so there is nothing to
    // match it against, and the renderer encodes it for that reason. What changed is only that this
    // app has stopped adding a sentence of its own to a channel it cannot translate.
    if (!result.Ok)
    {
        return result.Status is System.Net.HttpStatusCode.Conflict
               && result.Description is { Length: > 0 } conflict
            ? Results.Redirect("/users/new?error=" + Uri.EscapeDataString(conflict))
            : Refused(http, result);
    }

    // Straight to the password page, because the create response carries the generated password and
    // this is the only moment it exists anywhere.
    return Html(renderer.RenderPassword(new PasswordViewModel(
        result.Body.GetProperty("handle").GetString()!,
        result.Body.GetProperty("password").GetString()!,
        Tokens(http, antiforgery), Who(http))));
}).RequireAuthorization();

app.MapGet("/users/{handle}", async (
    HttpContext http, AdminApi api, IAntiforgery antiforgery, IAdminRenderer renderer, string handle,
    CancellationToken ct) =>
{
    var result = await api.GetUserAsync(http, handle, ct);

    if (!result.Ok)
    {
        return Refused(http, result);
    }

    // Asked for separately and tolerated when it fails. An authorization server that predates the
    // endpoint answers 404, and the section then renders as absent rather than turning an upgrade
    // into a broken account page.
    var service = await api.GetServiceAccountAsync(http, handle, ct);

    return Html(renderer.RenderAccount(new AccountViewModel(
        result.Body, Tokens(http, antiforgery), http.Request.Query["notice"], Who(http))
    {
        // See the accounts page: a key and its {0}, never a composed sentence.
        NoticeValue = http.Request.Query["notice_value"],

        // Normalised rather than passed through. The API answers 200 with a JSON `null` for an
        // account that holds none, and whether ReadFromJsonAsync turns that into ValueKind.Null or
        // leaves the struct at Undefined is a framework detail this page must not depend on - the
        // renderer shows the section for Null and hides it for Undefined, so getting it wrong hides
        // the create button on exactly the accounts that need one.
        //
        // So: an object is the service account, anything else the server answered is "none", and a
        // failed call is "the server did not say" - which is the one case that hides the section,
        // for the older-image reason the renderer documents.
        ServiceAccount = service.Ok
            ? service.Body.ValueKind is JsonValueKind.Object ? service.Body : NoServiceAccount()
            : default,

        // Carried through the redirect rather than held anywhere. It is in this one response and
        // then gone - the server keeps a digest, so nothing can produce it again.
        NewSecret = http.Request.Query["secret"],

        // What the create form offers to tick. Null when discovery could not be read, and then the
        // form is the box it was before rather than a page that failed to render.
        ScopesSupported = await ScopesSupportedAsync(http),
    }));
}).RequireAuthorization();

app.MapPost("/users/{handle}/service-account", async (
    HttpContext http, AdminApi api, IAntiforgery antiforgery, string handle, CancellationToken ct) =>
{
    await antiforgery.ValidateRequestAsync(http);

    var form = await http.Request.ReadFormAsync(ct);

    var result = await api.CreateServiceAccountAsync(
        http,
        handle,
        new
        {
            // Both shapes, because the form sends either - see AdminForm.Scopes for which and why
            // reading it as one string is the bug it looks like it is not.
            scopes = AdminForm.Scopes(form["scopes"]),
        },
        ct);

    // The refusal page rather than a banner, which is what every other write in this app has always
    // done and what these four should have been doing. The banner carried `error_description` back
    // through the query string - the one sentence on the page that names the rule that was broken,
    // travelling by the one route a link can write. It is the API's sentence, so it comes out of the
    // API's response: RenderRefusal prints it from the body, where nobody else can reach it.
    if (!result.Ok)
    {
        return Refused(http, result);
    }

    // In the query string, which is the ugly part of showing a secret once and is chosen
    // deliberately: the alternative is holding it in a session, and a secret that lives in server
    // state until somebody's session expires is a secret with a lifetime nobody chose. This one is
    // in one URL, in one browser, until the next navigation.
    var secret = result.Body.TryGetProperty("client_secret", out var minted)
        ? minted.GetString() ?? string.Empty
        : string.Empty;

    return Results.Redirect(
        $"/users/{Uri.EscapeDataString(handle)}?secret={Uri.EscapeDataString(secret)}");
}).RequireAuthorization();

// Rotate. The admin API has no separate verb for it - POSTing to /service-account a second time
// rotates - but the scopes it stores are the ones in the request body, so a form that sent none
// would empty the grant and one that sent hidden fields would let a tampered post silently widen
// it. Both are the same defect: a button labelled "new secret" changing something that is not the
// secret. So the current scopes are read back here, server-side, and sent unchanged.
//
// A separate route rather than a second button on the create form, because the two are different
// operations to an operator even where they are one call to the API: one asks which scopes, and
// this one must not.
app.MapPost("/users/{handle}/service-account/rotate", async (
    HttpContext http, AdminApi api, IAntiforgery antiforgery, string handle, CancellationToken ct) =>
{
    await antiforgery.ValidateRequestAsync(http);

    var existing = await api.GetServiceAccountAsync(http, handle, ct);

    // Two failures, and they were one branch because both ended in the same banner. They are not
    // the same thing: the first is the API refusing and saying why, the second is this app stopping
    // on its own.
    if (!existing.Ok)
    {
        return Refused(http, existing);
    }

    // The account holds no service account. Rotating something that is not there would create it -
    // with no scopes, which the server refuses - so this stops rather than turning a stale page into
    // a confusing error, and it is the one refusal in this app that is allowed to say nothing was
    // changed: the read ran ahead of the write, so the absence is known rather than assumed.
    if (existing.Body.ValueKind is not JsonValueKind.Object)
    {
        return Results.Redirect($"/users/{Uri.EscapeDataString(handle)}?notice={AdminText.NoticeRefused}");
    }

    var result = await api.CreateServiceAccountAsync(
        http, handle, new { scopes = AdminMarkup.Texts(existing.Body, "scopes") }, ct);

    if (!result.Ok)
    {
        return Refused(http, result);
    }

    // The same one-URL hand-off the create path uses, and the comment there is the argument for it.
    var rotated = result.Body.TryGetProperty("client_secret", out var minted)
        ? minted.GetString() ?? string.Empty
        : string.Empty;

    return Results.Redirect(
        $"/users/{Uri.EscapeDataString(handle)}?secret={Uri.EscapeDataString(rotated)}");
}).RequireAuthorization();

app.MapPost("/users/{handle}/service-account/enabled", async (
    HttpContext http, AdminApi api, IAntiforgery antiforgery, string handle, CancellationToken ct) =>
{
    await antiforgery.ValidateRequestAsync(http);

    var form = await http.Request.ReadFormAsync(ct);

    var result = await api.SetServiceAccountEnabledAsync(
        http, handle, new { enabled = form["enabled"].Count > 0 }, ct);

    return result.Ok
        ? Results.Redirect($"/users/{Uri.EscapeDataString(handle)}?notice={AdminText.NoticeApplied}")
        : Refused(http, result);
}).RequireAuthorization();

app.MapPost("/users/{handle}/service-account/delete", async (
    HttpContext http, AdminApi api, IAntiforgery antiforgery, string handle, CancellationToken ct) =>
{
    await antiforgery.ValidateRequestAsync(http);

    var result = await api.DeleteServiceAccountAsync(http, handle, ct);

    return result.Ok
        ? Results.Redirect($"/users/{Uri.EscapeDataString(handle)}?notice={AdminText.NoticeDeleted}")
        : Refused(http, result);
}).RequireAuthorization();

app.MapPost("/users/{handle}/patch", async (
    HttpContext http, AdminApi api, IAntiforgery antiforgery, string handle, CancellationToken ct) =>
{
    if (await Forged(http, antiforgery) is { } refusal)
    {
        return refusal;
    }

    var form = await http.Request.ReadFormAsync(ct);

    // A checkbox that is unchecked sends nothing, so "enabled" is read as presence rather than as a
    // value - and both are sent every time, because the API's PATCH treats absent as unchanged and
    // this form is showing the whole state.
    var result = await api.PatchUserAsync(
        http,
        handle,
        new
        {
            // `roles`, plural, and an array. The field used to post `role` as a scalar, which
            // combined with an empty box - the roles rendered blank, because the API returns an
            // array under that key - to send "-" and clear every role the account held. Saving an
            // unrelated change wiped the account's permissions, silently and in the safe-looking
            // direction: fewer roles, no error, an almost-empty knowledge base at the next sign-in.
            //
            // Split on whitespace so two roles can be typed in one box. Empty stays an empty array,
            // which is still "clear them" - that is what the placeholder says and it has to remain
            // possible - but it now takes deleting the text rather than opening the page.
            roles = form["roles"].ToString()
                .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            email = form["email"].ToString() is { Length: > 0 } e ? e : "-",
            email_verified = form["email_verified"].Count > 0,
            enabled = form["enabled"].Count > 0,
        },
        ct);

    return result.Ok
        ? Results.Redirect($"/users/{Uri.EscapeDataString(handle)}?notice={AdminText.NoticeApplied}")
        : Refused(http, result);
}).RequireAuthorization();

app.MapPost("/users/{handle}/password", async (
    HttpContext http, AdminApi api, IAntiforgery antiforgery, IAdminRenderer renderer, string handle,
    CancellationToken ct) =>
{
    if (await Forged(http, antiforgery) is { } refusal)
    {
        return refusal;
    }

    var result = await api.ResetPasswordAsync(http, handle, ct);

    return result.Ok
        ? Html(renderer.RenderPassword(new PasswordViewModel(
            handle, result.Body.GetProperty("password").GetString()!, Tokens(http, antiforgery), Who(http))))
        : Refused(http, result);
}).RequireAuthorization();

app.MapPost("/users/{handle}/sessions", async (
    HttpContext http, AdminApi api, IAntiforgery antiforgery, string handle, CancellationToken ct) =>
{
    if (await Forged(http, antiforgery) is { } refusal)
    {
        return refusal;
    }

    var result = await api.RevokeSessionsAsync(http, handle, ct);

    if (!result.Ok)
    {
        return Refused(http, result);
    }

    // The count, and no claim beyond it. Access tokens already issued keep working until they
    // expire, and telling an operator responding to an incident "signed out" would overstate it by
    // one token lifetime. The sentence saying so is AdminText.NoticeSessionsRevoked, so a deployment
    // can put it in its own words; what travels here is the number that goes in its {0}.
    var revoked = result.Body.GetProperty("revoked").GetInt32();

    return Results.Redirect(
        $"/users/{Uri.EscapeDataString(handle)}?notice={AdminText.NoticeSessionsRevoked}"
        + $"&notice_value={revoked.ToString(CultureInfo.InvariantCulture)}");
}).RequireAuthorization();

app.MapPost("/users/{handle}/anonymise", async (
    HttpContext http, AdminApi api, IAntiforgery antiforgery, string handle, CancellationToken ct) =>
{
    if (await Forged(http, antiforgery) is { } refusal)
    {
        return refusal;
    }

    var result = await api.AnonymiseAsync(http, handle, ct);

    // To the account list, because the account page this came from no longer names anybody. The
    // handle is the {0} of the sentence there and is escaped as query-string data - it is a string
    // an operator typed and this app never validated, like every other value on these pages.
    return result.Ok
        ? Results.Redirect(
            $"/?notice={AdminText.NoticeAnonymised}&notice_value={Uri.EscapeDataString(handle)}")
        : Refused(http, result);
}).RequireAuthorization();

app.MapGet("/audit", async (
    HttpContext http, AdminApi api, IAntiforgery antiforgery, IAdminRenderer renderer, CancellationToken ct) =>
{
    var result = await api.AuditAsync(http, ct);

    return result.Ok
        ? Html(renderer.RenderAudit(new AuditViewModel(result.Body, Tokens(http, antiforgery), Who(http))))
        : Refused(http, result);
}).RequireAuthorization();

// ─────────────────────────────────────────────────────────────────────────────
// Roles
// ─────────────────────────────────────────────────────────────────────────────
//
// The definitions an account's roles point at. The admin API and the CLI have been able to write
// these since they existed; nothing could read them without a shell on the box, so "what does
// `editor` actually allow" was a question with no answer in the UI that assigns it.

app.MapGet("/roles", async (
    HttpContext http, AdminApi api, IAntiforgery antiforgery, IAdminRenderer renderer,
    CancellationToken ct) =>
{
    var result = await api.ListRolesAsync(http, ct);

    if (!result.Ok)
    {
        return Refused(http, result);
    }

    // Who holds what, walked from the same paged listing the accounts page reads. Capped, because
    // this is a decoration on a page about definitions: ten pages of fifty covers any directory
    // this console is for, and a bigger one gets the truncation sentence rather than an unbounded
    // walk per view. A failed page is the sharper case - the walk stops and the page says nothing
    // about holders at all, because a partial list rendered as the whole one claims "nobody holds
    // this" for every role whose holders were in the pages that never loaded, next to a delete
    // button.
    var accounts = new List<System.Text.Json.JsonElement>();
    var truncated = false;
    string? after = null;

    for (var page = 0; ; page++)
    {
        if (page == 10)
        {
            truncated = true;
            break;
        }

        var users = await api.ListUsersAsync(http, after, ct);

        if (!users.Ok)
        {
            accounts = null;
            break;
        }

        if (users.Body.TryGetProperty("users", out var listed)
            && listed.ValueKind is System.Text.Json.JsonValueKind.Array)
        {
            accounts.AddRange(listed.EnumerateArray());
        }

        after = users.Body.TryGetProperty("next", out var next) ? next.GetString() : null;

        if (after is not { Length: > 0 })
        {
            break;
        }
    }

    return Html(renderer.RenderRoles(new RolesViewModel(
        result.Body, Tokens(http, antiforgery), http.Request.Query["notice"], Who(http))
    {
        Accounts = accounts is null
            ? default
            : System.Text.Json.JsonSerializer.SerializeToElement(accounts),
        HoldersTruncated = truncated,
    }));
}).RequireAuthorization();

app.MapPost("/roles", async (
    HttpContext http, AdminApi api, IAntiforgery antiforgery, CancellationToken ct) =>
{
    await antiforgery.ValidateRequestAsync(http);

    var form = await http.Request.ReadFormAsync(ct);

    var result = await api.CreateRoleAsync(
        http,
        new
        {
            id = form["id"].ToString().Trim(),

            // Absent rather than blank, because the API defaults a missing name to the id and an
            // empty string is a name the store refuses. Leaving the box empty should mean "call it
            // what it is", not "fail".
            name = Blank(form["name"]),
            permissions = AdminForm.Permissions(form["permissions"]),
        },
        ct);

    return result.Ok
        ? Results.Redirect($"/roles?notice={AdminText.NoticeDefined}")
        : Refused(http, result);
}).RequireAuthorization();

app.MapPost("/roles/{id}", async (
    HttpContext http, AdminApi api, IAntiforgery antiforgery, string id, CancellationToken ct) =>
{
    await antiforgery.ValidateRequestAsync(http);

    var form = await http.Request.ReadFormAsync(ct);

    // No `id` here, and there is no route that carries one: an id reaches every token this realm
    // has issued and both halves of ADMIN_ROLES, so it is chosen once. The page says so where the
    // box would have been.
    var result = await api.PatchRoleAsync(
        http,
        id,
        new
        {
            name = Blank(form["name"]),
            permissions = AdminForm.Permissions(form["permissions"]),
        },
        ct);

    return result.Ok
        ? Results.Redirect($"/roles?notice={AdminText.NoticeApplied}")
        : Refused(http, result);
}).RequireAuthorization();

app.MapPost("/roles/{id}/delete", async (
    HttpContext http, AdminApi api, IAntiforgery antiforgery, string id, CancellationToken ct) =>
{
    await antiforgery.ValidateRequestAsync(http);

    var result = await api.DeleteRoleAsync(http, id, ct);

    return result.Ok
        ? Results.Redirect($"/roles?notice={AdminText.NoticeDeleted}")
        : Refused(http, result);
}).RequireAuthorization();

// A POST, because signing somebody out is a state change and a GET would let any page on the
// internet do it to them.
//
// **This used to clear the local cookie and redirect to `/`, and that was not a sign-out.** Reported
// from production: pressing it appeared to do nothing, and reloading came back to the consent page.
// Both halves follow from the same cause. The cookie went, `/` demanded authentication, the handler
// went to /authorize, the authorization server still held its own session - so the operator was
// signed straight back in, pausing only at the consent screen this deployment's IConsentPolicy shows
// every time. The one thing the button is for is the one thing it did not do.
//
// It now ends the local session and then hands the browser to the provider's `end_session_endpoint`,
// which is OIDC RP-Initiated Logout §2 and is what the discovery document advertises it for.
app.MapPost("/signout", async (HttpContext http, IAntiforgery antiforgery) =>
{
    if (await Forged(http, antiforgery) is { } refusal)
    {
        return refusal;
    }

    await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

    // Out of the discovery document rather than composed from AUTHORITY, for the reason every other
    // endpoint in this app is: the server publishes where its own endpoints are, and a path built
    // here is a second opinion that can be wrong. Read through the handler's own configuration
    // manager, so it is the same document the sign-in half used.
    //
    // A deployment whose authorization server advertises none keeps the old behaviour, which is the
    // honest fallback: this app cannot end a session on a server that offers no way to.
    var endSession = await EndSessionAsync(http);

    // No `post_logout_redirect_uri`, and not because it was forgotten. That server refuses one on
    // purpose - an unregistered redirect target on the issuer's own hostname is an open redirector,
    // and OIDC says MUST NOT redirect to a URI that has not been validated. So the operator lands on
    // its sign-out page and stays there, which is a page that says the session ended rather than a
    // bounce that leaves them wondering.
    return Results.Redirect(endSession ?? "/");
}).RequireAuthorization();

app.Run();

// ─────────────────────────────────────────────────────────────────────────────

static IResult Html(string html) => Results.Content(html, "text/html; charset=utf-8");

static string? Blank(string? value) => value is { Length: > 0 } ? value : null;

// Who is signed in, for the header. The three lookups are three different answers, in the order a
// reader would want them: the handle OnTokenValidated puts here from /userinfo, a name claim no
// deployment of this server sends today, and the subject.
//
// **The order is the fallback, and the fallback is load-bearing rather than tidy.** A deployment
// with UserInfoEnabled off, an account with no username, or a /userinfo that was unreachable during
// this sign-in all land on the ULID - which is what the header drew for every operator before that
// event existed. Degrading to a worse label is the whole point; null is still an ordinary answer,
// and what the header must not do is hang the sign-out button off it, which is the defect
// DefaultAdminLayout's remarks describe.
//
// `sub` is last and is spelled as ASP.NET Core stores it. The handler's MapInboundClaims defaults
// to true and renames `sub` to ClaimTypes.NameIdentifier before the principal is built, so the
// obvious `FindFirst("sub")` matches nothing - it was here, it looked right, and it was dead.
static string? Who(HttpContext http) =>
    http.User.FindFirst("preferred_username")?.Value
    ?? http.User.FindFirst(ClaimTypes.Name)?.Value
    ?? http.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

// Answer a refusal, or send an expired session back to sign in.
//
// The renderer comes out of the request's own services rather than being a parameter, and that is
// the one thing worth saying about it: half the endpoints that can refuse do not otherwise render
// anything, so taking it as an argument would add a parameter to six lambdas for the benefit of the
// two lines below. It is the same trade the previous version made by closing over `adminText`.
// The element meaning "this account has no service account".
//
// A parsed literal rather than `default`, because the two are different answers on this page: Null
// renders the create form and Undefined renders nothing at all. Going through a literal keeps that
// distinction from depending on how a JSON body happened to deserialize.
static JsonElement NoServiceAccount() => JsonDocument.Parse("null").RootElement;

static IResult Refused(HttpContext http, AdminResult result) =>
    result.Unauthenticated
        // The tokens have expired or been revoked, so a page saying "refused" would be wrong about
        // why. Challenge instead: the operator goes round the flow and comes back where they were.
        ? Results.Challenge(
            new AuthenticationProperties { RedirectUri = http.Request.Path + http.Request.QueryString },
            [OpenIdConnectDefaults.AuthenticationScheme])
        : Results.Content(
            http.RequestServices.GetRequiredService<IAdminRenderer>().RenderRefusal(new RefusalViewModel(
                result,
                Tokens(http, http.RequestServices.GetRequiredService<IAntiforgery>()),
                Who(http))),
            "text/html; charset=utf-8");

// Where the authorization server ends its own session, or null when it advertises nowhere.
//
// Failures are swallowed to null on purpose, and this is the one place in this app where that is
// right: the local cookie is already gone by the time this runs, so the operator is signed out of
// this app whatever happens next. Letting a discovery timeout throw here would turn a completed
// sign-out into a 500 and leave them believing it did not work - which is the defect this whole
// endpoint exists to fix, arriving by a different route.
static async Task<string?> EndSessionAsync(HttpContext http)
{
    try
    {
        var options = http.RequestServices
            .GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);

        var discovery = await options.ConfigurationManager!.GetConfigurationAsync(http.RequestAborted);

        return discovery.EndSessionEndpoint is { Length: > 0 } endpoint ? endpoint : null;
    }
    catch (Exception failed) when (failed is not OperationCanceledException)
    {
        http.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("Boltway.AdminBff.SignOut")
            .LogWarning(
                failed,
                "Signed out locally, but could not read end_session_endpoint from discovery. The "
                + "session on the authorization server is still open.");

        return null;
    }
}

// Every scope the authorization server publishes, for the service-account form to offer.
//
// Through the configuration manager, which is the same object the sign-in handler uses and holds
// the document it already fetched - so this is a dictionary lookup on all but the first call and
// after each refresh, not a request per page view. It is also what makes a server that starts
// publishing a new scope offer it here without this app being restarted.
//
// **Tolerated when it fails, like the service-account call itself.** The alternative is an account
// page that 500s because a metadata document was briefly unreachable, which would take the whole
// directory down over one form's suggestions. Null means "not known" and the form falls back to a
// box an operator types into - narrower than before, never broken.
//
// Empty is folded into null on purpose: `scopes_supported` is optional in the document, and an
// absent list means the server did not say rather than that it will issue nothing. Rendering zero
// checkboxes would state the second.
static async Task<IReadOnlyList<string>?> ScopesSupportedAsync(HttpContext http)
{
    try
    {
        var options = http.RequestServices
            .GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);

        var discovery = await options.ConfigurationManager!.GetConfigurationAsync(http.RequestAborted);

        return discovery.ScopesSupported is { Count: > 0 } scopes ? [.. scopes] : null;
    }
    catch (Exception failed) when (failed is not OperationCanceledException)
    {
        http.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("Boltway.AdminBff.Scopes")
            .LogWarning(
                failed,
                "Could not read scopes_supported from discovery. The service-account form will ask "
                + "for scopes to be typed instead of offering them.");

        return null;
    }
}

// This request's antiforgery pair, for every form on the page it is about to render.
//
// Called on every page rather than on the two that draw a form an operator fills in, because the
// shell draws one too: sign-out. That form went out without a field for as long as it existed, and
// `POST /signout` validates one - so the button answered 400. GetAndStoreTokens is what writes the
// cookie half, so a page that never calls it cannot have a working form of any kind.
static AntiforgeryTokens Tokens(HttpContext http, IAntiforgery antiforgery)
{
    var tokens = antiforgery.GetAndStoreTokens(http);

    return new AntiforgeryTokens(tokens.FormFieldName, tokens.RequestToken!);
}

// The refusal, or null when the antiforgery token is good.
static async Task<IResult?> Forged(HttpContext http, IAntiforgery antiforgery)
{
    try
    {
        await antiforgery.ValidateRequestAsync(http);

        return null;
    }
    catch (AntiforgeryValidationException)
    {
        // Every form here is a state change on the directory, and this app holds an ambient cookie,
        // so without the check any page on the internet could submit them.
        return Results.StatusCode(StatusCodes.Status400BadRequest);
    }
}

string Required(string key, string what) =>
    config[key] is { Length: > 0 } value
        ? value
        : throw new InvalidOperationException($"{key} is not set. It is {what}.");
