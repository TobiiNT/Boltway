using System.Globalization;
using System.Net;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Interaction;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Pkce;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The pages in a language the deployment chose, selected by <c>ui_locales</c>.
/// </summary>
/// <remarks>
/// <c>ui_locales_supported</c> was in the discovery document with nothing behind it: no per-locale
/// text, and nothing anywhere reading the request parameter. A deployment could advertise <c>vi</c>
/// and serve English to everyone who asked, with no error either side could see.
/// </remarks>
public sealed class LocalizationTests
{
    private static readonly CodeVerifier Verifier = CodeVerifier.Generate();

    private const string Vietnamese = "vi";

    private static readonly Dictionary<string, IReadOnlyDictionary<string, string>> Translations =
        new(StringComparer.OrdinalIgnoreCase)
        {
            [Vietnamese] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [InteractionText.LoginTitle] = "Đăng nhập",
                [InteractionText.LoginUsername] = "Tên đăng nhập",

                // Deliberately not every key. The rest must fall back to English rather than
                // rendering the key, which is the difference between a partial translation and a
                // broken page.
            },
        };

    private static Task<FlowFixture> StartAsync() => StartAsync("en", Translations);

    private static Task<FlowFixture> StartAsync(
        string defaultCulture,
        IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> translations) =>
        FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client("https://claude.ai/.well-known/oauth-client", ClientType.Confidential);
            seed.SignedInUser = null;

            seed.ConfigureServices = services =>
            {
                services.AddBoltwayInteractionLocalization(defaultCulture, translations);
                services.AddSingleton<AuthorizationServerOptionsHook>(new AuthorizationServerOptionsHook());
            };

            seed.ConfigureOptions = o =>
            {
                // Advertised because it is served, from the one function that answers which is
                // which. The map-time check refuses the two disagreeing.
                foreach (var culture in InteractionLocalization.SupportedCultures(defaultCulture, translations))
                {
                    o.UiLocalesSupported.Add(culture);
                }
            };

            seed.ConfigureApp = app => app.UseRequestLocalization();
        });

    /// <summary>A marker, so the fixture's service hook has something to register.</summary>
    private sealed class AuthorizationServerOptionsHook;

    /// <summary>The authorization request a client actually sends, with an optional language ask.</summary>
    private static string AuthorizeUrl(string? uiLocales)
    {
        var url = "/authorize?response_type=code"
            + "&client_id=" + HttpUtility.UrlEncode("https://claude.ai/.well-known/oauth-client")
            + "&redirect_uri=" + HttpUtility.UrlEncode("https://claude.ai/api/mcp/auth_callback")
            + "&scope=openid&state=xyz"
            + "&resource=" + HttpUtility.UrlEncode(Build.Resource)
            + "&code_challenge=" + Verifier.ComputeS256Challenge()
            + "&code_challenge_method=S256";

        return uiLocales is null ? url : url + "&ui_locales=" + HttpUtility.UrlEncode(uiLocales);
    }

    /// <summary>
    /// The sign-in page as a client reaches it: <c>/authorize</c>, then the redirect it answers with.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Both hops, because the defect lived between them.</b> These tests used to build
    /// <c>/login?returnUrl=…&amp;ui_locales=vi</c> and request that directly — a URL no client
    /// constructs, since /login is only ever reached through this redirect. Against it the
    /// parameter was read straight off the query and every assertion below passed, while a real
    /// client got an English page: /authorize puts its whole query inside a single percent-encoded
    /// <c>returnUrl</c>, so nothing named <c>ui_locales</c> survives to the page.
    /// </para>
    /// <para>
    /// Driving the real shape is what makes these tests able to fail. They go red against the code
    /// as it was.
    /// </para>
    /// </remarks>
    private static async Task<HttpResponseMessage> SignInPageAsync(FlowFixture fixture, string? uiLocales)
    {
        var redirect = await fixture.Client.GetAsync(new Uri(AuthorizeUrl(uiLocales), UriKind.Relative));

        Assert.Equal(HttpStatusCode.SeeOther, redirect.StatusCode);

        var location = (redirect.Headers.Location
            ?? throw new InvalidOperationException("/authorize answered 303 with no Location.")).ToString();

        // A 303 is also how an OAuth error leaves /authorize, and that one goes to the client's
        // redirect_uri. Asserting the destination keeps a broken request from arriving here as a
        // 404 on claude.ai rather than as the refusal it is.
        Assert.StartsWith("/login?returnUrl=", location, StringComparison.Ordinal);

        return await fixture.Client.GetAsync(new Uri(location, UriKind.Relative));
    }

    /// <summary>The sign-in page's body, reached the way a client reaches it.</summary>
    private static async Task<string> SignInHtmlAsync(FlowFixture fixture, string? uiLocales)
    {
        var response = await SignInPageAsync(fixture, uiLocales);

        response.EnsureSuccessStatusCode();

        return await response.Content.ReadAsStringAsync();
    }

    [Fact]
    public async Task ui_locales_selects_the_language()
    {
        await using var fixture = await StartAsync();

        // Decoded once. `WebUtility.HtmlEncode` writes non-ASCII as numeric entities, so the page
        // carries `&#272;&#259;ng nh&#7853;p` — correct, and what the renderer contract's
        // "encoded exactly once" assertion is about. Decoding here asserts what a reader sees.
        var page = System.Net.WebUtility.HtmlDecode(
            await SignInHtmlAsync(fixture, Vietnamese));

        Assert.Contains("Đăng nhập", page, StringComparison.Ordinal);
        Assert.Contains("Tên đăng nhập", page, StringComparison.Ordinal);
    }

    /// <summary>
    /// An untranslated key falls back to English rather than rendering the key.
    /// </summary>
    /// <remarks>
    /// The failure mode a key-based lookup has by default: a missed entry returns the name, and a
    /// page reading <c>ConsentApprove</c> reaches production because nothing distinguishes it from a
    /// translation. <c>ResourceNotFound</c> is what makes the fallback explicit.
    /// </remarks>
    [Fact]
    public async Task An_untranslated_string_falls_back_to_english()
    {
        await using var fixture = await StartAsync();

        var page = await SignInHtmlAsync(fixture, Vietnamese);

        Assert.Contains("Password", page, StringComparison.Ordinal);
        Assert.DoesNotContain(InteractionText.LoginPassword, page, StringComparison.Ordinal);
    }

    /// <summary>
    /// The document's <c>lang</c> is the resolved culture, not the requested one.
    /// </summary>
    /// <remarks>
    /// A locale nobody serves falls back, and the attribute has to say what the page is actually in.
    /// Emitting the request's value would reflect a query parameter into the document and lie to a
    /// screen reader about which language to pronounce.
    /// </remarks>
    [Theory]
    [InlineData(Vietnamese, "vi")]
    [InlineData("ja", "en")]
    [InlineData(null, "en")]
    public async Task The_lang_attribute_is_the_resolved_culture(string? requested, string expected)
    {
        await using var fixture = await StartAsync();

        var page = await SignInHtmlAsync(fixture, requested);

        Assert.Contains($"<html lang=\"{expected}\"", page, StringComparison.Ordinal);
    }

    /// <summary>
    /// An unsupported <c>ui_locales</c> is not an error.
    /// </summary>
    /// <remarks>
    /// OIDC makes it a hint. Refusing would be a client that cannot connect because of a language,
    /// which is a much larger failure than being served the default one.
    /// </remarks>
    [Fact]
    public async Task An_unsupported_locale_is_served_in_the_default_language()
    {
        await using var fixture = await StartAsync();

        var response = await SignInPageAsync(fixture, "ja");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Sign in", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    /// <summary>
    /// The discovery document lists what the middleware will honour.
    /// </summary>
    [Fact]
    public async Task The_advertised_locales_are_the_served_ones()
    {
        await using var fixture = await StartAsync();

        var json = await fixture.Client.GetStringAsync("/.well-known/oauth-authorization-server");
        using var document = System.Text.Json.JsonDocument.Parse(json);

        var advertised = document.RootElement
            .GetProperty("ui_locales_supported")
            .EnumerateArray()
            .Select(e => e.GetString())
            .ToList();

        Assert.Equal(["en", Vietnamese], advertised);
    }

    /// <summary>
    /// The error page's sentence to the reader is translated, and the developer's half is not.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Found by reading a Northwind page, not by a failing test.</b> Every line on <c>/error</c> was
    /// Vietnamese except the middle one, and there was no key that would change it: the line is the
    /// <c>error_description</c>, which <c>ErrorText.Safe</c> filters to
    /// <c>%x20-21 / %x23-5B / %x5D-7E</c> because OAuth 2.1 §4.1.2.1 requires that — so a Vietnamese
    /// sentence put there arrives as its ASCII fragments. It was never written for the person in
    /// front of it.
    /// </para>
    /// <para>
    /// So the page carries two sentences with two jobs, and this asserts both. The reader's is
    /// chosen by what they can do about the refusal and is translated; the developer's is the exact
    /// <c>error_description</c>, stays English, and stays on the page because <c>A-12</c> requires
    /// the code and a safe description in the body so that <c>curl -D-</c> debugs an integration.
    /// The label above it is translated, because unlabelled English on a translated page reads as a
    /// string somebody forgot.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task The_error_pages_guidance_is_translated_and_its_technical_detail_is_not()
    {
        await using var fixture = await StartAsync(
            Vietnamese,
            new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.OrdinalIgnoreCase)
            {
                [Vietnamese] = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [InteractionText.ErrorHeading] = "Yêu cầu này không thể được uỷ quyền",
                    [InteractionText.ErrorStartAgain] = "Hãy bắt đầu lại từ ứng dụng bạn đang kết nối.",
                    [InteractionText.ErrorDeveloperDetail] = "Chi tiết kỹ thuật, dành cho người quản lý ứng dụng:",
                },
            });

        // /error is the InteractionErrorPage refusal — somebody landed here with no request to
        // speak for them — which maps to "start again".
        var response = await fixture.Client.GetAsync(new Uri("/error", UriKind.Relative));
        var page = WebUtility.HtmlDecode(await response.Content.ReadAsStringAsync());

        Assert.Contains("<html lang=\"vi\"", page, StringComparison.Ordinal);
        Assert.Contains("Hãy bắt đầu lại từ ứng dụng bạn đang kết nối.", page, StringComparison.Ordinal);
        Assert.Contains("Chi tiết kỹ thuật, dành cho người quản lý ứng dụng:", page, StringComparison.Ordinal);

        // A-12, unchanged: the OAuth code and the exact English description are still in the body.
        Assert.Contains("server_error", page, StringComparison.Ordinal);
        Assert.Contains("The authorization request could not be completed.", page, StringComparison.Ordinal);

        // And the reference, which is what turns the English half into something an operator can
        // look up rather than the only copy of it.
        Assert.Contains("Reference:", page, StringComparison.Ordinal);
    }

    /// <summary>
    /// Each class of refusal gets the sentence for what its reader can do.
    /// </summary>
    /// <remarks>
    /// The mapping is by remedy rather than by cause — five sentences for twenty-six reason codes —
    /// so what has to be true is that a refusal a person caused, a refusal they must wait out and a
    /// refusal only the client's author can fix do not all say the same thing. Asserted through the
    /// public surface rather than on the switch, because a switch tested directly still proves
    /// nothing about which reason code the endpoint actually raises.
    /// </remarks>
    [Theory]
    [InlineData(ReasonCode.InteractionErrorPage, InteractionText.ErrorStartAgain)]
    [InlineData(ReasonCode.AntiforgeryTokenInvalid, InteractionText.ErrorStartAgain)]
    [InlineData(ReasonCode.RateLimited, InteractionText.ErrorTooMany)]
    [InlineData(ReasonCode.ClientUnknown, InteractionText.ErrorApplication)]
    [InlineData(ReasonCode.RedirectUriMismatch, InteractionText.ErrorApplication)]
    [InlineData(ReasonCode.Unhandled, InteractionText.ErrorApplication)]
    [InlineData(ReasonCode.ExternalAccountDisabled, InteractionText.ErrorAccount)]
    [InlineData(ReasonCode.ExternalIdentityUnlinked, InteractionText.ErrorAccount)]
    [InlineData(ReasonCode.ExternalAuthorizationDenied, InteractionText.ErrorDeclined)]
    public void A_refusal_gets_the_sentence_for_what_its_reader_can_do(ReasonCode reason, string expected) =>
        Assert.Equal(expected, InteractionText.ErrorSentenceFor(reason));

    /// <summary>
    /// On a deployment whose default is not English, English is reachable only if something lists it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Measured against the real host before it was a test: <c>UI_DEFAULT_LOCALE=vi</c> with a
    /// <c>vi</c> table and nothing else served <c>/error?ui_locales=en</c> in Vietnamese, byte for
    /// byte the same page as without the parameter. That reads as a defect and is not one — the
    /// supported set is <c>[vi]</c>, <c>en</c> matches nothing, and the middleware falls back to the
    /// default exactly as it does for <c>ja</c>.
    /// </para>
    /// <para>
    /// The distinction worth keeping: English is the <b>per-string fallback</b>, which is a
    /// different thing from a <b>registered culture</b>. The fallback is why a half-translated
    /// <c>vi</c> page is readable. It is not a language a client can ask for, and
    /// <c>ui_locales_supported</c> is right not to advertise it.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task English_is_not_served_by_a_vietnamese_deployment_that_does_not_list_it()
    {
        await using var fixture = await StartAsync(Vietnamese, Translations);

        var page = WebUtility.HtmlDecode(await SignInHtmlAsync(fixture, "en"));

        Assert.Contains("<html lang=\"vi\"", page, StringComparison.Ordinal);
        Assert.Contains("Đăng nhập", page, StringComparison.Ordinal);

        var json = await fixture.Client.GetStringAsync("/.well-known/oauth-authorization-server");
        using var document = System.Text.Json.JsonDocument.Parse(json);

        Assert.Equal(
            [Vietnamese],
            document.RootElement.GetProperty("ui_locales_supported")
                .EnumerateArray().Select(e => e.GetString()).ToList());
    }

    /// <summary>
    /// A culture with no strings of its own is served, entirely from the fallback.
    /// </summary>
    /// <remarks>
    /// The other half of the test above, and the answer it points a deployment at. <c>{"en": {}}</c>
    /// is not an incantation: the rule is that a culture translates as many keys as it has and the
    /// rest fall back, and an empty table is that rule's zero case. It is what lets a Vietnamese
    /// deployment offer English without restating 27 sentences it already ships.
    /// </remarks>
    [Fact]
    public async Task A_culture_with_an_empty_table_is_served_entirely_from_english()
    {
        var withEnglishListed = new Dictionary<string, IReadOnlyDictionary<string, string>>(
            StringComparer.OrdinalIgnoreCase)
        {
            [Vietnamese] = Translations[Vietnamese],
            ["en"] = new Dictionary<string, string>(StringComparer.Ordinal),
        };

        await using var fixture = await StartAsync(Vietnamese, withEnglishListed);

        var page = WebUtility.HtmlDecode(await SignInHtmlAsync(fixture, "en"));

        Assert.Contains("<html lang=\"en\"", page, StringComparison.Ordinal);
        Assert.Contains("Sign in", page, StringComparison.Ordinal);
        Assert.DoesNotContain("Đăng nhập", page, StringComparison.Ordinal);

        // And the default is still Vietnamese: listing a culture offers it, it does not promote it.
        var byDefault = WebUtility.HtmlDecode(await SignInHtmlAsync(fixture, null));

        Assert.Contains("<html lang=\"vi\"", byDefault, StringComparison.Ordinal);
    }

    /// <summary>
    /// <see cref="InteractionLocalization.SupportedCultures"/> puts the default first and repeats nothing.
    /// </summary>
    /// <remarks>
    /// Order is not cosmetic here: it is what <c>ui_locales_supported</c> is built from, and OIDC
    /// readers take the first entry as the deployment's own language. The de-duplication matters
    /// because a deployment naming its default in the translation table — which is the ordinary
    /// thing to do — would otherwise advertise it twice.
    /// </remarks>
    [Fact]
    public void The_supported_set_is_the_default_first_then_the_translated_cultures()
    {
        var translations = new Dictionary<string, IReadOnlyDictionary<string, string>>(
            StringComparer.OrdinalIgnoreCase)
        {
            ["VI"] = new Dictionary<string, string>(StringComparer.Ordinal),
            ["fr"] = new Dictionary<string, string>(StringComparer.Ordinal),
        };

        Assert.Equal(
            [Vietnamese, "fr"],
            InteractionLocalization.SupportedCultures(Vietnamese, translations));
    }

    /// <summary>
    /// A translation cannot introduce markup.
    /// </summary>
    /// <remarks>
    /// A translation is data a deployment edits rather than code it reviews, and the sentences carry
    /// <c>{0}</c> placeholders that this server splices markup into. Encoding the translation and
    /// then splicing — rather than formatting the raw text — is what keeps a translated
    /// <c>&lt;script&gt;</c> a piece of text somebody typed.
    /// </remarks>
    /// <summary>
    /// A refused sign-in is refused in the deployment's language.
    /// </summary>
    /// <remarks>
    /// The regression, and the reason this key exists at all. The sentence used to be a literal in
    /// <c>PostLoginAsync</c>, handed to the renderer on the view model — so a deployment serving
    /// every page in Vietnamese answered a wrong password with <i>"That username and password did
    /// not match."</i> There was no key to translate, and nothing reported the gap: the page was
    /// complete, correct and in the wrong language. Measured on a running server, by getting a
    /// password wrong.
    /// </remarks>
    [Fact]
    public void A_refused_sign_in_is_refused_in_the_deployments_language()
    {
        var vietnamese = new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.OrdinalIgnoreCase)
        {
            ["vi"] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [InteractionText.LoginRejected] = "Tên đăng nhập hoặc mật khẩu không đúng.",
            },
        };

        var previous = CultureInfo.CurrentUICulture;

        try
        {
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("vi");

            var renderer = new DefaultInteractionRenderer(
                new DefaultInteractionLayout(), new DictionaryStringLocalizer(vietnamese));

            var page = renderer.RenderLogin(new LoginViewModel
            {
                ReturnUrl = "/me",
                Rejected = true,
                AntiforgeryFieldName = "__t",
                AntiforgeryToken = "value",
                LocalPasswordsEnabled = true,
                ExternalProviders = [],
                PasswordRecoveryEnabled = false,
                Nonce = null,
            });

            // Decoded first, and that is not a convenience. WebUtility.HtmlEncode escapes the
            // Latin-1 supplement and leaves the rest of the BMP alone, so this page carries
            // `T&#234;n` for "Tên" and a plain `đăng` beside it — a raw Contains against Vietnamese
            // passes or fails on which vowels the sentence happens to use.
            var text = WebUtility.HtmlDecode(page);

            Assert.Contains("Tên đăng nhập hoặc mật khẩu không đúng.", text, StringComparison.Ordinal);
            Assert.DoesNotContain("did not match", text, StringComparison.Ordinal);
        }
        finally
        {
            CultureInfo.CurrentUICulture = previous;
        }
    }

    [Fact]
    public void A_translation_containing_markup_renders_as_text()
    {
        var hostile = new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.OrdinalIgnoreCase)
        {
            ["xx"] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [InteractionText.ConsentClientAsking] = "<script>alert(1)</script> {0}",
            },
        };

        var previous = CultureInfo.CurrentUICulture;

        try
        {
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("xx");

            var rendered = InteractionText.Format(
                new DictionaryStringLocalizer(hostile),
                InteractionText.ConsentClientAsking,
                "<strong>claude.ai</strong>");

            Assert.DoesNotContain("<script>", rendered, StringComparison.Ordinal);
            Assert.Contains("&lt;script&gt;", rendered, StringComparison.Ordinal);

            // And the placeholder still received real markup, which is the half that would be lost
            // by encoding everything.
            Assert.Contains("<strong>claude.ai</strong>", rendered, StringComparison.Ordinal);
        }
        finally
        {
            CultureInfo.CurrentUICulture = previous;
        }
    }

    /// <summary>
    /// Advertising a locale the middleware does not serve refuses at startup.
    /// </summary>
    [Fact]
    public void A_deployment_can_supply_its_own_localizer()
    {
        // The seam, checked rather than asserted in prose. The XML docs used to say a deployment
        // overrides the text by registering an IStringLocalizerFactory — the way OrchardCore and
        // ABP do it — and nothing here has ever resolved a factory. Somebody following that got
        // English pages and no error, so the sentence now names IStringLocalizer and this is what
        // keeps it true: registered first, it wins, because the library's own is TryAdd.
        var services = new ServiceCollection();

        services.AddSingleton<IStringLocalizer>(new PoFileShapedLocalizer());
        services.AddBoltwayInteractionLocalization(Vietnamese, Translations);

        var resolved = services.BuildServiceProvider().GetRequiredService<IStringLocalizer>();

        Assert.IsType<PoFileShapedLocalizer>(resolved);
        Assert.Equal("from the deployment", resolved[InteractionText.LoginTitle].Value);
    }

    /// <summary>Whatever a deployment already keeps its text in — the point is that it is not ours.</summary>
    private sealed class PoFileShapedLocalizer : IStringLocalizer
    {
        public LocalizedString this[string name] => new(name, "from the deployment", resourceNotFound: false);

        public LocalizedString this[string name, params object[] arguments] => this[name];

        public IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures) => [];
    }

    [Fact]
    public void A_translation_that_drops_a_placeholder_refuses_to_start()
    {
        // ConsentClientAsking carries the host of the client_id URL, which N-14 makes a MUST — it is
        // the one field on the consent page that says which application is actually asking. A
        // translation without {0} renders a grammatical sentence with that host silently absent,
        // and every other check passes: the key is known, the page renders, the renderer contract
        // is satisfied. Startup is the only place this can be caught.
        var translations = new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.OrdinalIgnoreCase)
        {
            [Vietnamese] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [InteractionText.ConsentClientAsking] = "Ứng dụng này muốn truy cập tài khoản của bạn.",
            },
        };

        var refusal = Assert.Throws<InvalidOperationException>(
            () => new ServiceCollection().AddBoltwayInteractionLocalization(Vietnamese, translations));

        Assert.Contains(InteractionText.ConsentClientAsking, refusal.Message, StringComparison.Ordinal);
        Assert.Contains("{0}", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_translation_that_keeps_its_placeholders_starts()
    {
        // The control. Without it the test above passes against a build that refuses every
        // translation, which is the same page in the same language and a much worse bug.
        var translations = new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.OrdinalIgnoreCase)
        {
            [Vietnamese] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [InteractionText.ConsentClientAsking] = "Ứng dụng tại {0} muốn truy cập tài khoản của bạn.",
                [InteractionText.LoginTitle] = "Đăng nhập",
            },
        };

        new ServiceCollection().AddBoltwayInteractionLocalization(Vietnamese, translations);
    }

    [Fact]
    public void A_translation_that_invents_a_placeholder_refuses_to_start()
    {
        // The other direction, and it reaches the page as the literal text `{1}`: nothing supplies
        // an argument for a placeholder the English string does not have.
        var translations = new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.OrdinalIgnoreCase)
        {
            [Vietnamese] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [InteractionText.ConsentClientAsking] = "Ứng dụng tại {0} muốn truy cập {1}.",
            },
        };

        var refusal = Assert.Throws<InvalidOperationException>(
            () => new ServiceCollection().AddBoltwayInteractionLocalization(Vietnamese, translations));

        Assert.Contains("{1}", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Advertising_a_locale_nobody_serves_refuses_to_start()
    {
        var failure = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await FlowFixture.StartAsync(seed =>
            {
                seed.ConfigureServices = services =>
                    services.AddBoltwayInteractionLocalization("en", Translations);

                seed.ConfigureOptions = o =>
                {
                    o.UiLocalesSupported.Add("en");
                    o.UiLocalesSupported.Add("ja");
                };

                seed.ConfigureApp = app => app.UseRequestLocalization();
            }));

        Assert.Contains("Advertised and not served: ja", failure.Message, StringComparison.Ordinal);
    }
}
