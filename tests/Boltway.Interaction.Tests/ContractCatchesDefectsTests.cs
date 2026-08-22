using System.Net;
using System.Reflection;
using System.Text;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Interaction;
using Xunit.Sdk;

using Boltway.Interaction.Testing;

namespace Boltway.Interaction.Tests;

/// <summary>Which rule a renderer is being made to break.</summary>
[Flags]
public enum Defect
{
    /// <summary>A renderer that satisfies the whole contract. The control.</summary>
    None = 0,

    /// <summary>The self-asserted name leads and the hostname follows it — N-14 reversed.</summary>
    NameBeforeHost = 1,

    /// <summary>The name is printed with nothing next to it saying it is unverified.</summary>
    BareName = 1 << 1,

    /// <summary><see cref="ConsentViewModel.RedirectsToThisDevice"/> is ignored.</summary>
    NoDeviceWarning = 1 << 2,

    /// <summary>An undescribed scope renders as bare text, with no configuration warning — A-14.</summary>
    NoUndescribedWarning = 1 << 3,

    /// <summary>A configured-but-unavailable provider is dropped instead of disabled — A-11.</summary>
    DropDisabledProvider = 1 << 4,

    /// <summary>Interpolated values are written through unencoded.</summary>
    NoEncoding = 1 << 5,

    /// <summary>Interpolated values are encoded twice — the mojibake regression.</summary>
    DoubleEncode = 1 << 6,

    /// <summary>A <c>style</c> attribute the page's own CSP refuses.</summary>
    InlineStyle = 1 << 7,

    /// <summary>A stylesheet on a CDN, which <c>default-src 'self'</c> refuses.</summary>
    OffOrigin = 1 << 8,

    /// <summary>The decision control is named something the consent endpoint does not read.</summary>
    WrongDecisionField = 1 << 9,

    /// <summary>
    /// <see cref="LogoutViewModel.State"/> is ignored, so both halves of the sign-out page render as
    /// the confirmation — what a renderer written against an older model produces.
    /// </summary>
    IgnoreLogoutState = 1 << 10,

    /// <summary>
    /// <see cref="LoginViewModel.PasswordRecoveryEnabled"/> is ignored, so the sign-in page never
    /// offers a reset — a deployment with recovery configured that nobody in a browser can reach.
    /// </summary>
    DropForgotLink = 1 << 11,
}

/// <summary>
/// The contract, measured against renderers built to break it.
/// </summary>
/// <remarks>
/// <para>
/// A suite that passes against the implementation it was written for has demonstrated nothing —
/// every assertion could be tautological and the run would look identical. What makes a contract
/// worth shipping is evidence that each guard bites, so each row below breaks exactly one rule and
/// names the test that must notice.
/// </para>
/// <para>
/// <b><see cref="Defect.None"/> is the control, and it is the row that makes the others mean
/// something.</b> Without it, a sabotaged renderer failing its guard could equally be a renderer
/// that fails everything for an unrelated reason — the defect would not be attributable. The control
/// asserts the same renderer with no defect passes the entire contract, so a failure elsewhere is
/// the one defect that was introduced.
/// </para>
/// </remarks>
public sealed class ContractCatchesDefectsTests
{
    [Theory]
    [InlineData(Defect.NameBeforeHost, nameof(InteractionRendererContract.Consent_shows_the_client_host_before_the_self_asserted_name))]
    [InlineData(Defect.BareName, nameof(InteractionRendererContract.Consent_qualifies_the_self_asserted_name_rather_than_printing_it_bare))]
    [InlineData(Defect.NoDeviceWarning, nameof(InteractionRendererContract.Consent_warns_when_the_code_goes_to_the_users_own_device))]
    [InlineData(Defect.NoUndescribedWarning, nameof(InteractionRendererContract.Consent_shows_the_raw_scope_and_a_warning_when_no_description_is_configured))]
    [InlineData(Defect.DropDisabledProvider, nameof(InteractionRendererContract.Login_renders_a_disabled_provider_as_disabled_with_its_reason))]
    [InlineData(Defect.NoEncoding, nameof(InteractionRendererContract.Interpolated_markup_is_encoded_rather_than_rendered))]
    [InlineData(Defect.DoubleEncode, nameof(InteractionRendererContract.Non_ascii_text_is_encoded_exactly_once))]
    [InlineData(Defect.WrongDecisionField, nameof(InteractionRendererContract.Consent_names_the_decision_field_the_way_the_endpoint_reads_it))]
    [InlineData(Defect.IgnoreLogoutState, nameof(InteractionRendererContract.Logout_draws_the_two_states_differently))]
    [InlineData(Defect.DropForgotLink, nameof(InteractionRendererContract.Login_offers_password_recovery_only_when_the_deployment_has_it))]
    public void A_defect_fails_the_guard_that_covers_it(Defect defect, string guard)
    {
        var probe = new Probe(new SabotagedRenderer(defect));

        var method = typeof(InteractionRendererContract).GetMethod(guard)
            ?? throw new InvalidOperationException($"No contract test named '{guard}'.");

        Assert.IsAssignableFrom<XunitException>(Unwrap(Record.Exception(() => method.Invoke(probe, null))));
    }

    /// <summary>The two CSP defects, which the one theory covers on both pages.</summary>
    [Theory]
    [InlineData(Defect.InlineStyle)]
    [InlineData(Defect.OffOrigin)]
    public void A_defect_the_browser_would_refuse_fails_the_policy_guard(Defect defect)
    {
        var probe = new Probe(new SabotagedRenderer(defect));

        Assert.IsAssignableFrom<XunitException>(
            Unwrap(Record.Exception(() =>
                probe.Pages_render_within_the_policy_the_server_sends(login: false, nonce: null))));
    }

    /// <summary>
    /// The control: the same renderer, with nothing broken, satisfies every rule in the contract.
    /// </summary>
    [Fact]
    public void The_undamaged_renderer_passes_the_whole_contract()
    {
        var probe = new Probe(new SabotagedRenderer(Defect.None));

        var tests = typeof(InteractionRendererContract)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(method => method.GetCustomAttribute<FactAttribute>() is not null)
            .Where(method => method.GetParameters().Length == 0)
            .ToList();

        // A control that controls nothing is worse than none, because it reports as a pass. If the
        // reflection above ever stops matching — a renamed attribute, a contract test that grows a
        // parameter — this is what says so instead of quietly asserting over an empty list. The
        // number is the count of parameterless [Fact]s on the contract; raise it when one is added.
        Assert.Equal(35, tests.Count);

        foreach (var test in tests)
        {
            var failure = Unwrap(Record.Exception(() => test.Invoke(probe, null)));

            Assert.True(failure is null, $"{test.Name} failed on the undamaged renderer: {failure?.Message}");
        }

        // The one [Theory] on the contract, whose arguments the loop above cannot supply. Both
        // nonce states, because the undamaged renderer emits no inline content either way and a
        // control that only checked one would stop noticing if that changed.
        foreach (var nonce in new string?[] { null, "r4nd0m-nonce-value" })
        {
            probe.Pages_render_within_the_policy_the_server_sends(login: false, nonce);
            probe.Pages_render_within_the_policy_the_server_sends(login: true, nonce);
        }
    }

    /// <summary>Reflection wraps what the test threw; the wrapper is not the finding.</summary>
    private static Exception? Unwrap(Exception? thrown) =>
        thrown is TargetInvocationException invocation && invocation.InnerException is not null
            ? invocation.InnerException
            : thrown;

    private sealed class Probe(IInteractionRenderer renderer) : InteractionRendererContract
    {
        protected override IInteractionRenderer NewRenderer() => renderer;
    }

    /// <summary>
    /// A contract-clean renderer with one rule removable at a time.
    /// </summary>
    /// <remarks>
    /// Written out rather than delegating to <see cref="DefaultInteractionRenderer"/> with patches,
    /// because a defect injected by string-replacing the shipped output would be measuring the
    /// replacement rather than a renderer somebody could plausibly write. This is roughly the shape
    /// of a customer's own first attempt, which is the thing the contract is aimed at.
    /// </remarks>
    private sealed class SabotagedRenderer(Defect defect) : IInteractionRenderer
    {
        public string RenderConsent(ConsentViewModel model)
        {
            var body = new StringBuilder();

            var host = $"<p>The application at <strong>{E(model.ClientHost)}</strong> is asking for access.</p>";

            var name = model.ClientName is null
                ? string.Empty
                : defect.HasFlag(Defect.BareName)
                    ? $"<p>{E(model.ClientName)}</p>"
                    : $"<p>{E(model.ClientName)} (this name is chosen by the application and is not verified)</p>";

            body.Append(defect.HasFlag(Defect.NameBeforeHost) ? name + host : host + name);

            body.Append("<p>The code will be sent to <strong>").Append(E(model.RedirectHost)).Append("</strong>.</p>");

            if (model.RedirectsToThisDevice && !defect.HasFlag(Defect.NoDeviceWarning))
            {
                body.Append("<p>This application receives the code on your own device. Approve only if you started it.</p>");
            }

            body.Append("<ul>");

            foreach (var scope in model.Scopes)
            {
                body.Append("<li>");
                body.Append(
                    scope.HasDescription ? E(scope.Description)
                    : defect.HasFlag(Defect.NoUndescribedWarning) ? E(scope.Name)
                    : E(scope.Name) + " (no description configured for this scope)");
                body.Append("</li>");
            }

            body.Append("</ul><ul>");

            foreach (var resource in model.Resources)
            {
                body.Append("<li>").Append(E(resource)).Append("</li>");
            }

            body.Append("</ul>");

            var decision = defect.HasFlag(Defect.WrongDecisionField) ? "choice" : "decision";

            body.Append("<form method=\"post\" action=\"").Append(AuthorizationServerPaths.Consent).Append("\">")
                .Append(Hidden(model.AntiforgeryFieldName, model.AntiforgeryToken))
                .Append(Hidden("returnUrl", model.ReturnUrl))
                .Append($"<button type=\"submit\" name=\"{decision}\" value=\"approve\">Approve</button>")
                .Append($"<button type=\"submit\" name=\"{decision}\" value=\"deny\">Deny</button>")
                .Append("</form>");

            return Page("Authorize access", body.ToString());
        }

        public string RenderLogin(LoginViewModel model)
        {
            var body = new StringBuilder("<h1>Sign in</h1>");

            if (model.Rejected)
            {
                // This stand-in words it itself, which is the point of the flag: a renderer that is
                // not this library's own says it in its own language.
                body.Append("<p>That combination was not recognised.</p>");
            }

            if (model.LocalPasswordsEnabled)
            {
                body.Append("<form method=\"post\" action=\"").Append(AuthorizationServerPaths.Login).Append("\">")
                    .Append(Hidden(model.AntiforgeryFieldName, model.AntiforgeryToken))
                    .Append(Hidden("returnUrl", model.ReturnUrl))
                    .Append("<input name=\"username\" type=\"text\">")
                    .Append("<input name=\"password\" type=\"password\">")
                    .Append("<button type=\"submit\">Sign in</button></form>");

                if (model.PasswordRecoveryEnabled && !defect.HasFlag(Defect.DropForgotLink))
                {
                    body.Append("<p><a href=\"").Append(AuthorizationServerPaths.Forgot).Append("\">")
                        .Append("I have forgotten my password</a></p>");
                }
            }

            foreach (var provider in model.ExternalProviders)
            {
                if (!provider.Enabled && defect.HasFlag(Defect.DropDisabledProvider))
                {
                    continue;
                }

                body.Append("<form method=\"post\" action=\"").Append(E(provider.StartUrl)).Append("\">")
                    .Append(Hidden(model.AntiforgeryFieldName, model.AntiforgeryToken))
                    .Append("<button type=\"submit\"").Append(provider.Enabled ? string.Empty : " disabled").Append('>')
                    .Append("Sign in with ").Append(E(provider.DisplayName)).Append("</button>");

                if (!provider.Enabled)
                {
                    body.Append(" <em>").Append(E(provider.DisabledReason)).Append("</em>");
                }

                body.Append("</form>");
            }

            if (!model.LocalPasswordsEnabled && model.ExternalProviders.Count == 0)
            {
                body.Append("<p>This server has no sign-in method configured.</p>");
            }

            return Page("Sign in", body.ToString());
        }

        /// <summary>
        /// Written out here rather than inherited from the interface's default member, and that is
        /// the whole reason this method exists.
        /// </summary>
        /// <remarks>
        /// <c>IInteractionRenderer.RenderLogout</c> has a default implementation, so a renderer that
        /// says nothing about sign-out silently gets the library's correct one — and a sabotage suite
        /// probing that renderer would be probing the shipped page, not the customer's. The defect
        /// this file has to be able to introduce is the one a real implementation makes: writing the
        /// page and ignoring the state.
        /// </remarks>
        public string RenderLogout(LogoutViewModel model)
        {
            var confirm = defect.HasFlag(Defect.IgnoreLogoutState)
                || model.State is LogoutState.ConfirmationNeeded;

            var body = new StringBuilder(confirm ? "<h1>Sign out</h1>" : "<h1>Signed out</h1>");

            if (confirm)
            {
                body.Append("<form method=\"post\" action=\"").Append(AuthorizationServerPaths.EndSession).Append("\">")
                    .Append(Hidden(model.AntiforgeryFieldName, model.AntiforgeryToken))
                    .Append("<button type=\"submit\">Sign out</button></form>");
            }

            return Page(confirm ? "Sign out" : "Signed out", body.ToString());
        }

        private string E(string? value) => defect switch
        {
            _ when defect.HasFlag(Defect.NoEncoding) => value ?? string.Empty,
            _ when defect.HasFlag(Defect.DoubleEncode) => WebUtility.HtmlEncode(WebUtility.HtmlEncode(value ?? string.Empty)),
            _ => WebUtility.HtmlEncode(value ?? string.Empty),
        };

        private string Hidden(string name, string value) =>
            $"<input type=\"hidden\" name=\"{E(name)}\" value=\"{E(value)}\">";

        private string Page(string title, string body)
        {
            var head = defect.HasFlag(Defect.OffOrigin)
                ? "<link rel=\"stylesheet\" href=\"https://cdn.example.com/theme.css\">"
                : string.Empty;

            var attribute = defect.HasFlag(Defect.InlineStyle) ? " style=\"font-family:sans-serif\"" : string.Empty;

            return "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                + head
                + $"<title>{WebUtility.HtmlEncode(title)}</title></head><body{attribute}>{body}</body></html>";
        }
    }
}
