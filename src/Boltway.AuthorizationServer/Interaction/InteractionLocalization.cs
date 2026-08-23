using System.Globalization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Localization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Localization;

namespace Boltway.AuthorizationServer.Interaction;

/// <summary>
/// A localizer over a dictionary a deployment supplies.
/// </summary>
/// <remarks>
/// <para>
/// <b>.NET has no first-class way for an application to override a library's resources</b>, because
/// satellite assemblies belong to the assembly that owns the <c>.resx</c> — a customer cannot add a
/// language to ours. So the text comes from a dictionary a deployment supplies, and this is an
/// implementation of the framework's <see cref="IStringLocalizer"/> over it.
/// </para>
/// <para>
/// <b>The seam is <see cref="IStringLocalizer"/> itself, registered before
/// <c>AddBoltwayInteractionLocalization</c>.</b> A deployment that prefers PO files, a database or
/// its own resx registers its own implementation and this one stands aside, because the
/// registration below is <c>TryAdd</c>.
/// </para>
/// <para>
/// This paragraph said the seam was a replaced <see cref="IStringLocalizerFactory"/>, the way
/// OrchardCore and ABP do it. Nothing here has ever resolved a factory: the three consumption sites
/// resolve the bare non-generic <see cref="IStringLocalizer"/>, which <c>AddLocalization()</c> does
/// not register at all. A consumer following that sentence got English pages and no error — a
/// documented extension point with nothing behind it, which is the shape of defect <c>N-06</c> is
/// about, on the customization surface rather than the protocol one.
/// </para>
/// <para>
/// <b>A missing key reports itself.</b> <c>ResourceNotFound</c> is what
/// <see cref="InteractionText"/> reads to fall back to English, so an untranslated string renders in
/// English rather than as <c>ConsentApprove</c>.
/// </para>
/// </remarks>
public sealed class DictionaryStringLocalizer : IStringLocalizer
{
    private readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> _byCulture;

    /// <summary>Create a localizer over translations keyed by culture name.</summary>
    /// <param name="translations">
    /// Culture name to key-to-text, looked up by the current UI culture.
    /// <para>
    /// <b>Do not rely on a parent-culture walk.</b> This said <c>vi-VN</c> would find a <c>vi</c>
    /// dictionary without a deployment listing both. Measured 2026-08-23 on .NET SDK 10.0.111:
    /// under this build's <c>InvariantGlobalization</c>, <c>GetCultureInfo("vi-VN").Parent.Name</c>
    /// is the empty string, so the walk ends immediately — and the framework's middleware does not
    /// fall back either, with or without ICU, so a request for <c>vi-VN</c> resolves to the default
    /// culture before it ever reaches this dictionary. List the region-specific tag too, or list
    /// the neutral one and let clients ask for it.
    /// </para>
    /// </param>
    public DictionaryStringLocalizer(
        IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> translations)
    {
        ArgumentNullException.ThrowIfNull(translations);

        _byCulture = translations;
    }

    /// <inheritdoc />
    public LocalizedString this[string name] => Find(name);

    /// <inheritdoc />
    public LocalizedString this[string name, params object[] arguments] => Find(name);

    /// <inheritdoc />
    public IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures) =>
        Current() is { } table
            ? table.Select(pair => new LocalizedString(pair.Key, pair.Value))
            : [];

    private LocalizedString Find(string name)
    {
        if (Current() is { } table && table.TryGetValue(name, out var text))
        {
            return new LocalizedString(name, text);
        }

        // The name as the value and resourceNotFound: true. The flag is the contract — the caller
        // reads it rather than the value, which is what stops a key reaching a page.
        return new LocalizedString(name, name, resourceNotFound: true);
    }

    private IReadOnlyDictionary<string, string>? Current()
    {
        var culture = CultureInfo.CurrentUICulture;

        while (culture is not null && culture != CultureInfo.InvariantCulture)
        {
            if (_byCulture.TryGetValue(culture.Name, out var table))
            {
                return table;
            }

            culture = culture.Parent.Name.Length == 0 ? null : culture.Parent;
        }

        return null;
    }
}

/// <summary>
/// Reads the OIDC <c>ui_locales</c> parameter as a culture request.
/// </summary>
/// <remarks>
/// <para>
/// OIDC Core §3.1.2.1: a space-separated list of BCP 47 tags, most preferred first. It is the
/// client's explicit per-request signal and the thing <c>ui_locales_supported</c> advertises, so it
/// goes ahead of <c>Accept-Language</c>.
/// </para>
/// <para>
/// <b>The value is never turned into a <see cref="CultureInfo"/> here.</b> It is a query parameter,
/// and building culture objects from one is unbounded allocation from user input. This returns the
/// requested names and <c>RequestLocalizationMiddleware</c> matches them against
/// <c>SupportedUICultures</c> — that matching is the framework's, not a rule this file adds, and it
/// is what makes the resolved culture something the server chose rather than something the caller
/// sent.
/// </para>
/// </remarks>
public sealed class UiLocalesRequestCultureProvider : RequestCultureProvider
{
    /// <summary>How many tags are read before the rest are ignored.</summary>
    /// <remarks>
    /// The middleware tries them in order and stops at the first supported one, so a long list is
    /// only ever wasted work — but it is attacker-controlled wasted work, and this is the bound.
    /// </remarks>
    public const int MaxLocales = 8;

    /// <inheritdoc />
    public override Task<ProviderCultureResult?> DetermineProviderCultureResult(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var raw = httpContext.Request.Query["ui_locales"].ToString();

        if (string.IsNullOrEmpty(raw))
        {
            return Task.FromResult<ProviderCultureResult?>(null);
        }

        var requested = raw
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Take(MaxLocales)
            .Select(tag => new Microsoft.Extensions.Primitives.StringSegment(tag))
            .ToList();

        return Task.FromResult<ProviderCultureResult?>(
            requested.Count == 0 ? null : new ProviderCultureResult(requested, requested));
    }
}

/// <summary>Wiring for the interaction pages' language.</summary>
public static class InteractionLocalization
{
    /// <summary>
    /// The languages a given configuration serves, in the order they are registered.
    /// </summary>
    /// <param name="defaultCulture">The language the pages are in when nothing else applies.</param>
    /// <param name="translations">Culture name to key-to-text, as passed to the registration.</param>
    /// <returns>The default culture first, then every translated culture, without repeats.</returns>
    /// <remarks>
    /// <para>
    /// Public because a host needs the same answer twice: once to configure the middleware and once
    /// to fill <c>UiLocalesSupported</c>, and those are separate calls. Deriving both from this
    /// makes them impossible to set differently — the map-time check that compares them stays as the
    /// backstop for a host that computes one of them some other way.
    /// </para>
    /// <para>
    /// <b>A culture with no strings of its own is still a culture this serves.</b> Every key falls
    /// back to English, so <c>{"en": {}}</c> means "offer English as well", and
    /// <c>{"fr": {"LoginTitle": "Connexion"}}</c> means "offer French, one sentence of it
    /// translated". Those are the same rule, and the empty table is its zero case rather than a
    /// special form — which matters because English is otherwise unreachable on a deployment whose
    /// default is something else: it is the per-string fallback, and being a fallback is not being a
    /// registered culture.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<string> SupportedCultures(
        string defaultCulture,
        IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> translations)
    {
        ArgumentException.ThrowIfNullOrEmpty(defaultCulture);
        ArgumentNullException.ThrowIfNull(translations);

        var supported = new List<string> { defaultCulture };

        foreach (var culture in translations.Keys)
        {
            if (!supported.Contains(culture, StringComparer.OrdinalIgnoreCase))
            {
                supported.Add(culture);
            }
        }

        return supported;
    }

    /// <summary>
    /// Configure which languages the pages are served in, and where the words come from.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="defaultCulture">
    /// The language the pages are in when nothing else applies. Must be one of
    /// <paramref name="translations"/>' keys or the built-in English.
    /// </param>
    /// <param name="translations">
    /// Culture name to key-to-text, using <see cref="InteractionText"/>'s constants as keys. A
    /// culture may translate some keys and not others; the rest fall back to English. A culture may
    /// translate none of them — see <see cref="SupportedCultures"/> for why that is the way to offer
    /// English from a deployment whose default is not English.
    /// </param>
    /// <remarks>
    /// <para>
    /// This registers the services. <b>The host still calls
    /// <see cref="ApplicationBuilderExtensions.UseRequestLocalization(IApplicationBuilder)"/></b>,
    /// because middleware order belongs to the host — the pages need the culture resolved before the
    /// endpoint runs, and only the host knows what else is in its pipeline.
    /// </para>
    /// <para>
    /// The supported set is what <c>ui_locales_supported</c> is generated from, so the discovery
    /// document lists what the middleware will actually honour rather than what somebody hoped.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddBoltwayInteractionLocalization(
        this IServiceCollection services,
        string defaultCulture,
        IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> translations)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrEmpty(defaultCulture);
        ArgumentNullException.ThrowIfNull(translations);

        // Refused here rather than reported to a host that may not ask. A translation that drops a
        // placeholder deletes the value it was carrying — on the consent page that is the host of
        // the client_id URL, which N-14 makes a MUST — and the page still renders, so there is no
        // later moment at which anybody finds out. InteractionText.Problems explains the check;
        // this is the line that makes it a refusal to start.
        //
        // All of them at once, like every other startup check here: a translator fixes one file in
        // one pass rather than one restart per key.
        var problems = InteractionText.Problems(translations);

        if (problems.Count > 0)
        {
            throw new InvalidOperationException(
                "These translations would render a page missing something the caller supplied:"
                + Environment.NewLine
                + string.Join(Environment.NewLine, problems.Select(p => "  " + p)));
        }

        var supported = SupportedCultures(defaultCulture, translations)
            .Select(CultureInfo.GetCultureInfo)
            .ToList();

        services.Configure<RequestLocalizationOptions>(options =>
        {
            options.DefaultRequestCulture = new RequestCulture(defaultCulture);
            options.SupportedCultures = supported;
            options.SupportedUICultures = supported;

            // ui_locales first — the client said it about this request. The framework's own
            // providers keep the order it gave them: query string, then cookie, then
            // Accept-Language.
            //
            // The query-string one is load-bearing rather than incidental, and this comment used to
            // credit the cookie provider instead. /authorize, /login and /consent are three
            // requests and `ui_locales` arrives only on the first, so something has to carry the
            // choice; the claim was that the cookie did. Nothing in this repository ever wrote that
            // cookie, so nothing carried it, and the consent page — the one N-14 requires to be
            // read carefully — rendered in the default language for every real client while
            // `ui_locales_supported` advertised otherwise.
            //
            // What carries it is `AuthorizeEndpoint.LocalReturn`, which appends the culture this
            // middleware resolved to the interaction URL. The comment there has the rest.
            // A deployment that would rather use the cookie can still write one: the framework's
            // provider is registered and will read it.
            options.RequestCultureProviders.Insert(0, new UiLocalesRequestCultureProvider());
        });

        services.TryAddSingleton<IStringLocalizer>(
            _ => new DictionaryStringLocalizer(translations));

        return services;
    }
}
