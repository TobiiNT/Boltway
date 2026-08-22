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
/// language to ours. The documented seam is to replace <see cref="IStringLocalizerFactory"/>, which
/// is what OrchardCore does with PO files and ABP with its own file system. This is that seam
/// filled, not replaced: it is an implementation of the framework's interface, and a deployment that
/// prefers PO files, a database or its own resx registers its own factory instead.
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
    /// Culture name to key-to-text. Looked up by the current UI culture and then by its parent, so
    /// <c>vi-VN</c> finds a <c>vi</c> dictionary without a deployment listing both.
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

        var supported = SupportedCultures(defaultCulture, translations)
            .Select(CultureInfo.GetCultureInfo)
            .ToList();

        services.Configure<RequestLocalizationOptions>(options =>
        {
            options.DefaultRequestCulture = new RequestCulture(defaultCulture);
            options.SupportedCultures = supported;
            options.SupportedUICultures = supported;

            // ui_locales first — the client said it about this request. Then the framework's cookie
            // provider, which is what carries the choice across /authorize → /login → /consent:
            // those are three requests and the parameter arrives on the first, so without it the
            // consent page — the one N-14 requires to be read carefully — reverts to the default
            // mid-flow. Accept-Language and the query-string provider stay where the framework put
            // them, last.
            options.RequestCultureProviders.Insert(0, new UiLocalesRequestCultureProvider());
        });

        services.TryAddSingleton<IStringLocalizer>(
            _ => new DictionaryStringLocalizer(translations));

        return services;
    }
}
