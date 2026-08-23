using System.Globalization;
using System.Net;
using System.Text;
using Boltway.AuthorizationServer.Configuration;
using Microsoft.Extensions.Localization;

namespace Boltway.AuthorizationServer.Interaction;

/// <summary>
/// The shipped consent and login pages.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately plain, and deliberately not Razor. A view engine here would mean a second package,
/// a runtime compilation step, and a template language in which the N-14 fields are optional. The
/// model already carries only safe values, so the job left is putting them on the page.
/// </para>
/// <para>
/// <b>Nothing inline.</b> The server's own CSP is <c>default-src 'self'</c> with no
/// <c>style-src</c> or <c>script-src</c> override, so both inherit <c>'self'</c> — an inline
/// <c>&lt;style&gt;</c> or <c>style="…"</c> attribute is blocked by the browser, not by review.
/// These pages are readable unstyled, and a deployment that wants otherwise sets
/// <see cref="InteractionOptions.StylesheetPaths"/> and serves the file itself; <c>'self'</c>
/// covers a same-origin stylesheet, so that needs no change to the policy.
/// </para>
/// </remarks>
public sealed class DefaultInteractionRenderer : IInteractionRenderer
{
    private readonly IInteractionLayout _layout;
    private readonly IStringLocalizer? _localizer;
    private readonly bool _providersFirst;

    /// <summary>
    /// The unthemed pages, as one shared instance.
    /// </summary>
    /// <remarks>
    /// What <see cref="IInteractionRenderer"/>'s default members fall back to. It exists because a
    /// default interface member has no dependency injection: it cannot reach the layout a
    /// deployment registered, so the only thing it can honestly render is the library's own page in
    /// the library's own shell. Stateless and immutable, hence shared.
    /// </remarks>
    public static DefaultInteractionRenderer Unthemed { get; } = new();

    /// <summary>The pages with no theme: no stylesheet, no logo, no product name.</summary>
    /// <remarks>
    /// What a deployment gets before it configures anything, and what the contract suite measures.
    /// Readable, and plainly unstyled rather than half-styled.
    /// </remarks>
    public DefaultInteractionRenderer()
        : this(new DefaultInteractionLayout())
    {
    }

    /// <summary>The pages, themed by a deployment's own configuration.</summary>
    /// <param name="options">
    /// The theme. Its paths have been through <see cref="InteractionOptions.TryValidate"/> when it
    /// came from <c>AddBoltwayAuthorizationServer</c>, which is what makes them safe to write
    /// into an attribute there.
    /// </param>
    public DefaultInteractionRenderer(InteractionOptions options)
        : this(new DefaultInteractionLayout(options), localizer: null, options.ProvidersFirst)
    {
    }

    /// <summary>The pages, inside a deployment's own page shell.</summary>
    /// <param name="layout">Where the server's markup goes.</param>
    public DefaultInteractionRenderer(IInteractionLayout layout)
        : this(layout, localizer: null)
    {
    }

    /// <summary>The pages, in a deployment's shell and a deployment's words.</summary>
    /// <param name="layout">Where the server's markup goes.</param>
    /// <param name="localizer">
    /// Where the sentences come from, or <see langword="null"/> for the built-in English. Keys are
    /// the constants on <see cref="InteractionText"/>; anything it has no entry for falls back
    /// rather than rendering the key.
    /// </param>
    public DefaultInteractionRenderer(IInteractionLayout layout, IStringLocalizer? localizer)
        : this(layout, localizer, providersFirst: false)
    {
    }

    /// <summary>The pages, in a deployment's shell, words and sign-in ordering.</summary>
    /// <param name="layout">Where the server's markup goes.</param>
    /// <param name="localizer">Where the sentences come from, or <see langword="null"/> for English.</param>
    /// <param name="providersFirst">
    /// <see cref="InteractionOptions.ProvidersFirst"/>. Reordering belongs here rather than in a
    /// stylesheet because CSS <c>order</c> moves the buttons without moving the tab order.
    /// </param>
    public DefaultInteractionRenderer(
        IInteractionLayout layout, IStringLocalizer? localizer, bool providersFirst)
    {
        ArgumentNullException.ThrowIfNull(layout);

        _layout = layout;
        _localizer = localizer;
        _providersFirst = providersFirst;
    }

    /// <inheritdoc />
    public string RenderConsent(ConsentViewModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        var body = new StringBuilder();

        body.Append("<h1>").Append(Text(InteractionText.ConsentTitle)).Append("</h1>");

        // The hostname first and as the identity, with the self-asserted name subordinate to it.
        // Reversing that order is the whole attack: a page led by "Claude" and a logo, with the real
        // host in small print, is a phishing surface this server has endorsed.
        //
        // The class is what lets a stylesheet keep that order. These three paragraphs are
        // structurally identical — a <p> containing a <strong> — so a sheet trying to enlarge the
        // hostname by position enlarges the redirect host and the name claim with it, and the
        // ordering N-14 fixes becomes three things the same size. Named rather than counted, for the
        // reason the device warning below has carried since it was the only class here: position is
        // not a contract.
        body.Append("<p class=\"bw-client\">")
            .Append(Text(InteractionText.ConsentClientAsking, Strong(model.ClientHost)))
            .Append("</p>");

        if (model.ClientName is not null)
        {
            // Encoded here, once. The model builder used to encode it too, and "encoded again is
            // harmless" — what this comment said — was measured false: the double pass rendered
            // `Acme & "Claude"` as the literal text `Acme &amp; &quot;Claude&quot;`, and `Café` as
            // `Caf&#233;`. Every value on the model is now plain text, so this method's uniform
            // Encode is both correct and the only place encoding happens.
            body.Append("<p class=\"bw-name\">");

            // Inside this paragraph, and after the hostname's, because both facts about where it
            // sits are the whole of what makes it safe to draw. A logo is the same self-assertion
            // the name is — anyone can publish one at their own URL — but it is far harder to be
            // sceptical of, because a familiar mark reads as proof in a way a familiar word does
            // not. So it lives inside the sentence that says nobody verified it, and it never
            // precedes the host, which is the only thing on this page a domain owner had to prove.
            //
            // Empty alt, deliberately. The name is in the very next words, so a screen reader
            // announcing the image would repeat it — and this code has never seen the picture, so
            // any description it invented would be a claim about a stranger's file. It is also what
            // makes the missing-image case read correctly: the endpoint 404s for a dead host, a
            // non-image body or a type it will not re-serve, and an empty alt renders as nothing at
            // all rather than as a broken-image box beside the client's name.
            if (model.ClientLogoUrl is { Length: > 0 } logo)
            {
                body.Append("<img class=\"bw-client-logo\" src=\"").Append(Encode(logo))
                    .Append("\" alt=\"\" width=\"20\" height=\"20\"> ");
            }

            body.Append(Text(InteractionText.ConsentNameClaim, Encode(model.ClientName)))
                .Append(" <em>")
                .Append(Text(InteractionText.ConsentNameUnverified))
                .Append("</em></p>");
        }

        body.Append("<p class=\"bw-redirect\">")
            .Append(Text(InteractionText.ConsentCodeGoesTo, Strong(model.RedirectHost)))
            .Append("</p>");

        if (model.RedirectsToThisDevice)
        {
            // Covers loopback and private-use schemes alike. For neither of them did a domain owner
            // prove anything: RFC 8252 §8.4 notes that any application can register a private-use
            // scheme, and any process can bind a loopback port. The user is the only party who knows
            // whether they started this.
            // The one class in this markup, and it is here because a stylesheet cannot find this
            // paragraph without it. Structurally it is a <p> containing a <strong>, which is also
            // true of the two paragraphs naming the hostnames — `:first-child` does not separate
            // them, because it counts elements and ignores the leading text node. A stylesheet
            // trying anyway highlights all three, which drowns the one warning N-14 asks for in two
            // that are merely informational. Measured, on this page, before this class existed.
            body.Append("<p class=\"bw-warning\"><strong>")
                .Append(Text(InteractionText.ConsentDeviceWarning))
                .Append("</strong> ")
                .Append(Text(InteractionText.ConsentDeviceWarningAdvice))
                .Append("</p>");
        }

        body.Append("<h2>").Append(Text(InteractionText.ConsentScopesHeading))
            .Append("</h2><ul class=\"bw-scopes\">");

        foreach (var scope in model.Scopes)
        {
            body.Append("<li>");

            if (scope.HasDescription)
            {
                body.Append(Encode(scope.Description));
            }
            else
            {
                // A-14: the raw scope plus a configuration warning, never a description derived by
                // parsing the name.
                body.Append("<code>").Append(Encode(scope.Name)).Append("</code> ")
                    .Append("<em>").Append(Text(InteractionText.ConsentScopeUndescribed)).Append("</em>");
            }

            body.Append("</li>");
        }

        body.Append("</ul>");

        if (model.Resources.Count > 0)
        {
            body.Append("<h2>").Append(Text(InteractionText.ConsentResourcesHeading))
                .Append("</h2><ul class=\"bw-resources\">");

            foreach (var resource in model.Resources)
            {
                body.Append("<li><code>").Append(Encode(resource)).Append("</code></li>");
            }

            body.Append("</ul>");
        }

        body.Append("<form class=\"bw-decision\" method=\"post\" action=\"")
            .Append(Encode(AuthorizationServerPaths.Consent)).Append("\">")
            .Append(Hidden(model.AntiforgeryFieldName, model.AntiforgeryToken))
            .Append(Hidden("returnUrl", model.ReturnUrl))
            .Append("<button type=\"submit\" name=\"decision\" value=\"approve\">")
            .Append(Text(InteractionText.ConsentApprove))
            .Append("</button> ")
            .Append("<button type=\"submit\" name=\"decision\" value=\"deny\">")
            .Append(Text(InteractionText.ConsentDeny))
            .Append("</button>")
            .Append("</form>");

        return Wrap(InteractionPageKind.Consent, Plain(InteractionText.ConsentTitle), body.ToString(), model.Nonce);
    }

    /// <inheritdoc />
    public string RenderLogin(LoginViewModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        var body = new StringBuilder();

        body.Append("<h1>").Append(Text(InteractionText.LoginTitle)).Append("</h1>");

        if (model.Rejected)
        {
            // Same hook as the consent page's device warning: a failed sign-in and "approve only if
            // you started this" are the two things on these pages a user must not skim past, and a
            // deployment styling one should get the other for free.
            body.Append("<p class=\"bw-warning\"><strong>")
                .Append(Text(InteractionText.LoginRejected))
                .Append("</strong></p>");
        }

        // The two ways in, each as a local function, so the order below is one decision stated once
        // rather than the same markup written twice. `ProvidersFirst` is what chooses; see the
        // remarks on it for why a stylesheet cannot make this choice without breaking tab order.
        void Password()
        {
            if (!model.LocalPasswordsEnabled)
            {
                return;
            }

            // Classed, unlike the provider forms below it, which a stylesheet finds by their action
            // prefix — `/external/{scheme}/start`, where the scheme is constrained at startup, so
            // the prefix cannot shift. This form's action is one path and could have been matched
            // the same way; the class is here because "the password form" is what a sheet means,
            // and a deployment that mounts the server under a prefix moves the path.
            body.Append("<form class=\"bw-signin\" method=\"post\" action=\"")
                .Append(Encode(AuthorizationServerPaths.Login)).Append("\">")
                .Append(Hidden(model.AntiforgeryFieldName, model.AntiforgeryToken))
                .Append(Hidden("returnUrl", model.ReturnUrl))
                .Append("<p><label for=\"username\">").Append(Text(InteractionText.LoginUsername)).Append("</label><br>")
                .Append("<input id=\"username\" name=\"username\" type=\"text\" autocomplete=\"username\" required></p>")
                .Append("<p><label for=\"password\">").Append(Text(InteractionText.LoginPassword)).Append("</label><br>")
                .Append("<input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required></p>")
                .Append("<button type=\"submit\">").Append(Text(InteractionText.LoginSubmit)).Append("</button>")
                .Append("</form>");

            // Under the password form and only when there is one: a deployment with no local
            // passwords has nothing here to reset, and an account that signs in through an upstream
            // provider is told that on /me rather than being offered a reset that cannot help.
            //
            // Only when the deployment can actually send it. /forgot is not routed with
            // PasswordRecoveryEnabled off, so drawing this unconditionally would hand somebody who
            // has forgotten their password a 404.
            if (model.PasswordRecoveryEnabled)
            {
                body.Append("<p class=\"bw-aside\"><a href=\"")
                    .Append(Encode(AuthorizationServerPaths.Forgot)).Append("\">")
                    .Append(Text(InteractionText.LoginForgotPassword)).Append("</a></p>");
            }
        }

        // Every configured provider, enabled or not — A-11. A disabled one renders as a disabled
        // button with its reason beside it rather than being dropped from the page, because a method
        // that vanishes is indistinguishable from one nobody configured.
        //
        // Each is its own form POST rather than a link. The request writes a cookie binding this
        // browser to a state, a nonce and a PKCE verifier, so it carries the antiforgery token like
        // the other two state-changing forms on this origin.
        void Providers()
        {
            foreach (var provider in model.ExternalProviders)
            {
                body.Append("<form method=\"post\" action=\"").Append(Encode(provider.StartUrl)).Append("\">")
                    .Append(Hidden(model.AntiforgeryFieldName, model.AntiforgeryToken))
                    .Append(Hidden("returnUrl", model.ReturnUrl))
                    .Append("<p><button type=\"submit\"")
                    .Append(provider.Enabled ? string.Empty : " disabled")
                    .Append('>')
                    .Append(Text(InteractionText.LoginWithProvider, Encode(provider.DisplayName)))
                    .Append("</button>");

                if (!provider.Enabled)
                {
                    body.Append(" <em>").Append(Encode(provider.DisabledReason)).Append("</em>");
                }

                body.Append("</p></form>");
            }
        }

        // The order, and the one sentence that only exists when there are two things to separate.
        if (_providersFirst)
        {
            Providers();

            if (model.LocalPasswordsEnabled && model.ExternalProviders.Count > 0)
            {
                body.Append("<p class=\"bw-or\">").Append(Text(InteractionText.LoginOrPassword)).Append("</p>");
            }

            Password();
        }
        else
        {
            Password();
            Providers();
        }

        if (!model.LocalPasswordsEnabled && model.ExternalProviders.Count == 0)
        {
            // Reachable only if a host registers a provider list that then answers empty, since
            // startup validation refuses a deployment with neither passwords nor a provider. A blank
            // page would be the worst possible answer to it.
            body.Append("<p>").Append(Text(InteractionText.LoginNoMethod)).Append("</p>");
        }

        return Wrap(InteractionPageKind.Login, Plain(InteractionText.LoginTitle), body.ToString(), model.Nonce);
    }

    /// <inheritdoc />
    public string RenderLogout(LogoutViewModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        var body = new StringBuilder();

        if (model.State is LogoutState.SignedOut)
        {
            // The same page answers "you have just signed out" and "you were not signed in", and
            // that is deliberate rather than lazy: distinguishing them tells an unauthenticated
            // caller whether this browser holds a session for this server, which is a fact about
            // somebody else's browsing and not one the page is owed.
            body.Append("<h1>").Append(Text(InteractionText.LogoutDoneTitle)).Append("</h1>")
                .Append("<p>").Append(Text(InteractionText.LogoutDoneBody)).Append("</p>")
                .Append("<p>").Append(Text(InteractionText.LogoutDoneTokens)).Append("</p>");

            // Last, under the sentence about tokens this does not revoke, because signing out and
            // signing back in is the ordinary reason somebody is here — and until this line the
            // page was a one-way door. See LogoutViewModel.SignInUrl.
            SignIn(body, model.SignInUrl);

            return Wrap(
                InteractionPageKind.Logout,
                Plain(InteractionText.LogoutDoneTitle),
                body.ToString(),
                model.Nonce);
        }

        body.Append("<h1>").Append(Text(InteractionText.LogoutTitle)).Append("</h1>")
            .Append("<p>").Append(Text(InteractionText.LogoutQuestion)).Append("</p>")
            .Append("<form method=\"post\" action=\"").Append(Encode(AuthorizationServerPaths.EndSession)).Append("\">")
            .Append(Hidden(model.AntiforgeryFieldName, model.AntiforgeryToken))
            .Append("<button type=\"submit\">").Append(Text(InteractionText.LogoutSubmit)).Append("</button>")
            .Append("</form>");

        return Wrap(InteractionPageKind.Logout, Plain(InteractionText.LogoutTitle), body.ToString(), model.Nonce);
    }

    /// <inheritdoc />
    public string RenderError(ErrorViewModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        var body = new StringBuilder("<h1>").Append(Text(InteractionText.ErrorHeading)).Append("</h1>");

        // The person's sentence first, and the reference immediately under it, because between them
        // they are the whole of what a reader can act on: what to do, and the value to quote when
        // they ask somebody. Everything below is for whoever wrote the client.
        body.Append("<p>").Append(Encode(model.Guidance)).Append("</p>")
            .Append("<p>")
            .Append(Text(InteractionText.ErrorReference, "<code>" + Encode(model.CorrelationId) + "</code>"))
            .Append("</p>");

        // A-12: the OAuth code and a safe description are in the body, so `curl -D-` debugs an
        // integration without a log in. Labelled rather than left bare — it is English on a page a
        // deployment may have translated entirely, and unlabelled it reads as a string somebody
        // forgot. It cannot be translated: it is the `error_description`, which OAuth 2.1 §4.1.2.1
        // restricts to ASCII.
        body.Append("<hr><p>").Append(Text(InteractionText.ErrorDeveloperDetail)).Append("</p>");

        if (!string.IsNullOrEmpty(model.Code))
        {
            body.Append("<p><code>").Append(Encode(model.Code)).Append("</code></p>");
        }

        body.Append("<p lang=\"en\">").Append(Encode(model.Description)).Append("</p>");

        return Wrap(InteractionPageKind.Error, Plain(InteractionText.ErrorTitle), body.ToString(), model.Nonce);
    }

    /// <inheritdoc />
    public string RenderAccount(AccountPageModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        var body = new StringBuilder("<h1>").Append(Text(InteractionText.AccountTitle)).Append("</h1>")
            .Append("<dl>")
            .Append("<dt>").Append(Text(InteractionText.AccountHandle)).Append("</dt>")
            .Append("<dd>").Append(Encode(model.Handle)).Append("</dd>")
            .Append("<dt>").Append(Text(InteractionText.AccountEmail)).Append("</dt>")
            .Append("<dd>");

        if (string.IsNullOrEmpty(model.Email))
        {
            body.Append(Text(InteractionText.AccountEmailNone));
        }
        else
        {
            body.Append(Encode(model.Email));

            // Said beside the address rather than left out. An unverified address is one nobody has
            // proven belongs to this person, and it is the field a reader is most likely to assume
            // has been checked.
            if (!model.EmailVerified)
            {
                body.Append(" <em>(").Append(Text(InteractionText.AccountEmailUnverified)).Append(")</em>");
            }
        }

        body.Append("</dd>");

        // The offer, and only when the endpoint says there is one to make. Saying an address is
        // unverified and giving no way to fix it is the shape this page was in until the endpoint
        // behind this button existed at all — E-41 had a page to land on and nothing that could send
        // you there.
        if (!string.IsNullOrEmpty(model.VerifyEmailUrl))
        {
            body.Append("<dd><form method=\"post\" action=\"").Append(Encode(model.VerifyEmailUrl))
                .Append("\">")
                .Append(Hidden(model.AntiforgeryFieldName, model.AntiforgeryToken))
                .Append("<button type=\"submit\">").Append(Text(InteractionText.AccountVerifyEmail))
                .Append("</button></form></dd>");
        }

        // After, not instead: the address is still unverified until somebody opens the link, so the
        // qualification above stays and this says what is in flight.
        if (model.VerificationNotice is not EmailVerificationNotice.None)
        {
            body.Append("<dd><p class=\"bw-notice\">")
                .Append(Text(model.VerificationNotice is EmailVerificationNotice.Sent
                    ? InteractionText.AccountVerifyEmailSent
                    : InteractionText.AccountVerifyEmailTooSoon))
                .Append("</p></dd>");
        }

        // Joined for display only. The model carries every role, because a page that showed one of
        // several would be the same "rule on one surface and not the other" the token half was
        // widened to avoid — it would just fail silently on a page instead of in a token.
        if (model.Roles.Count > 0)
        {
            body.Append("<dt>").Append(Text(InteractionText.AccountRole)).Append("</dt>")
                .Append("<dd>").Append(Encode(string.Join(", ", model.Roles))).Append("</dd>");
        }

        body.Append("</dl><ul>");

        // The link is absent, not disabled, when there is nothing to change — and the sentence
        // saying why takes its place. A control that cannot work is a question a person spends time
        // on before finding out the answer is no.
        body.Append("<li>");

        if (model.HasPassword)
        {
            body.Append("<a href=\"").Append(Encode(AuthorizationServerPaths.MePassword)).Append("\">")
                .Append(Text(InteractionText.AccountChangePassword)).Append("</a>");
        }
        else
        {
            body.Append(Text(InteractionText.AccountNoPassword));
        }

        body.Append("</li>")
            .Append("<li><a href=\"").Append(Encode(AuthorizationServerPaths.MeSessions)).Append("\">")
            .Append(Text(InteractionText.AccountSessions)).Append("</a></li>")

            // Listed beside the sessions rather than folded into them, because they are two
            // different questions — "what can reach my account right now" and "what did I agree to"
            // — and E-38 is the reason the second one cannot be answered by the first.
            .Append("<li><a href=\"").Append(Encode(AuthorizationServerPaths.MeConsents)).Append("\">")
            .Append(Text(InteractionText.AccountConsents)).Append("</a></li>")

            .Append("</ul>");

        // The way out. It was missing until someone read this page and asked where the button was:
        // /logout existed and nothing led to it, so signing out meant knowing to type the path. A
        // page listing everything a person can do to their account, except leave, is one that
        // quietly assumes they never want to.
        //
        // Absent rather than dead when the deployment has no end-session page, the same rule the
        // password link above follows. /logout is only routed when EndSessionEnabled is set, and a
        // link drawn anyway is a 404 offered by the page whose job is to say what can be done here.
        //
        // A form and not a link, and it used to be the other way round. The note here said a link was
        // safe because GET /logout only renders the question, with the sign-out itself behind the
        // POST that page submits — true, and it made this control a two-step one on the page where
        // people come to end their session. Somebody pressed it, read the question, went elsewhere
        // without answering it, and believed for the next two minutes that they had signed out. A
        // control that leaves a reader more confident and no less signed in is worse than one that
        // asks nothing.
        //
        // E-18's requirement is that a sign-out is a POST, not that it is confirmed, and this keeps
        // that: an <img> cannot POST and a cross-site form fails the antiforgery check below. The
        // question page is untouched for anyone who reaches /logout by its URL — a bookmark, a link
        // from elsewhere — where there is no page to have pressed a button on and confirming is the
        // only way to know the request was meant.
        if (!string.IsNullOrEmpty(model.SignOutUrl))
        {
            body.Append("<form method=\"post\" action=\"").Append(Encode(model.SignOutUrl)).Append("\">")
                .Append(Hidden(model.AntiforgeryFieldName, model.AntiforgeryToken))
                .Append("<button type=\"submit\">")
                .Append(Text(InteractionText.AccountSignOut)).Append("</button></form>");
        }

        // Absent rather than empty when nothing is configured: a deployment with no federation gets
        // no heading, no explanation and no reassuring blank box.
        if (model.Providers.Count > 0)
        {
            body.Append("<h2>").Append(Text(InteractionText.AccountLinkHeading)).Append("</h2>")
                .Append("<p>").Append(Text(InteractionText.AccountLinkExplanation)).Append("</p>");

            foreach (var provider in model.Providers)
            {
                if (provider.Linked)
                {
                    // The sentence replaces the button rather than sitting beside it. Offering to
                    // connect something already connected is the shape that sent somebody round the
                    // whole round trip a second time to find out nothing had changed.
                    body.Append("<p>")
                        .Append(Text(InteractionText.AccountLinked, Encode(provider.DisplayName)))
                        .Append("</p>");

                    continue;
                }

                // A form and not a link, because linking changes the account: a GET that does it is
                // reachable from an <img> tag on any page, which is the same reason /logout asks.
                //
                // returnUrl is /me — this page — so somebody who links lands back where the button
                // was. The link intent accepts any local path, which is looser than the sign-in
                // intent's closed list; the value here is a constant rather than anything submitted,
                // so that looseness is not reachable from this form.
                body.Append("<form method=\"post\" action=\"").Append(Encode(provider.LinkUrl)).Append("\">")
                    .Append(Hidden(model.AntiforgeryFieldName, model.AntiforgeryToken))
                    .Append(Hidden("returnUrl", AuthorizationServerPaths.Me))
                    .Append("<button type=\"submit\">")
                    .Append(Text(InteractionText.AccountLinkProvider, Encode(provider.DisplayName)))
                    .Append("</button></form>");
            }
        }

        return Wrap(InteractionPageKind.Account, Plain(InteractionText.AccountTitle), body.ToString(), model.Nonce);
    }

    /// <inheritdoc />
    public string RenderChangePassword(ChangePasswordPageModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        var body = new StringBuilder("<h1>").Append(Text(InteractionText.PasswordTitle)).Append("</h1>");

        if (model.Changed)
        {
            body.Append("<p>").Append(Text(InteractionText.PasswordChanged)).Append("</p>");

            if (model.SessionsRevoked > 0)
            {
                body.Append("<p>")
                    .Append(Text(
                        InteractionText.PasswordChangedRevoked,
                        Encode(model.SessionsRevoked.ToString(CultureInfo.InvariantCulture))))
                    .Append("</p>");
            }

            body.Append("<p><a href=\"").Append(Encode(AuthorizationServerPaths.Me)).Append("\">")
                .Append(Text(InteractionText.AccountBack)).Append("</a></p>");

            return Wrap(
                InteractionPageKind.ChangePassword,
                Plain(InteractionText.PasswordTitle),
                body.ToString(),
                model.Nonce);
        }

        if (model.Problem is not ChangePasswordProblem.None)
        {
            body.Append("<p role=\"alert\">").Append(Text(model.Problem switch
            {
                ChangePasswordProblem.WrongPassword => InteractionText.PasswordWrong,
                ChangePasswordProblem.Mismatch => InteractionText.PasswordMismatch,
                ChangePasswordProblem.Blank => InteractionText.PasswordBlank,
                _ => InteractionText.PasswordNone,
            })).Append("</p>");
        }

        // No form at all when there is no password to change, so the page is a sentence rather than
        // a form that can only be refused.
        if (model.Problem is ChangePasswordProblem.NoPassword)
        {
            body.Append("<p><a href=\"").Append(Encode(AuthorizationServerPaths.Me)).Append("\">")
                .Append(Text(InteractionText.AccountBack)).Append("</a></p>");

            return Wrap(
                InteractionPageKind.ChangePassword,
                Plain(InteractionText.PasswordTitle),
                body.ToString(),
                model.Nonce);
        }

        // `autocomplete` values are the ones password managers read: without them a manager offers
        // to save the *current* password as the new one, which is a lockout a person discovers at
        // their next sign-in. Empty every time — see the model's remarks.
        body.Append("<form method=\"post\" action=\"")
            .Append(Encode(AuthorizationServerPaths.MePassword)).Append("\">")
            .Append(Hidden(model.AntiforgeryFieldName, model.AntiforgeryToken))
            .Append("<label for=\"current\">").Append(Text(InteractionText.PasswordCurrent)).Append("</label>")
            .Append("<input id=\"current\" name=\"current\" type=\"password\" "
                + "autocomplete=\"current-password\" required>")
            .Append("<label for=\"new\">").Append(Text(InteractionText.PasswordNew)).Append("</label>")
            .Append("<input id=\"new\" name=\"new\" type=\"password\" autocomplete=\"new-password\" required>")
            .Append("<label for=\"confirm\">").Append(Text(InteractionText.PasswordConfirm)).Append("</label>")
            .Append("<input id=\"confirm\" name=\"confirm\" type=\"password\" "
                + "autocomplete=\"new-password\" required>")
            .Append("<label><input name=\"revoke\" type=\"checkbox\" value=\"true\"> ")
            .Append(Text(InteractionText.PasswordRevokeSessions)).Append("</label>")
            .Append("<button type=\"submit\">").Append(Text(InteractionText.PasswordSubmit)).Append("</button>")
            .Append("</form>")
            .Append("<p><a href=\"").Append(Encode(AuthorizationServerPaths.Me)).Append("\">")
            .Append(Text(InteractionText.AccountBack)).Append("</a></p>");

        return Wrap(
            InteractionPageKind.ChangePassword,
            Plain(InteractionText.PasswordTitle),
            body.ToString(),
            model.Nonce);
    }

    /// <inheritdoc />
    public string RenderSessions(SessionsPageModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        var body = new StringBuilder("<h1>").Append(Text(InteractionText.SessionsTitle)).Append("</h1>");

        if (model.Ended)
        {
            body.Append("<p>").Append(Text(InteractionText.SessionsEnded)).Append("</p>");
        }

        // Said before the list rather than after it: once everything is ended the list is empty, and
        // a message under an empty list reads as a caption for the emptiness. Zero is worth printing
        // too — it is the answer for somebody who pressed this twice.
        if (model.EndedAll is { } endedAll)
        {
            body.Append("<p>")
                .Append(Text(InteractionText.SessionsEndedAll, Count(endedAll)))
                .Append("</p>")

                // The half revoking cannot do. Linked rather than described, because this is read by
                // somebody who has just been told they may be under attack, and "go and find the
                // password page" is a step at which people stop.
                .Append("<p><a href=\"").Append(Encode(AuthorizationServerPaths.MePassword)).Append("\">")
                .Append(Text(InteractionText.SessionsEndedAllNext))
                .Append("</a></p>");
        }

        if (model.Sessions.Count == 0)
        {
            body.Append("<p>").Append(Text(InteractionText.SessionsNone)).Append("</p>");
        }
        else
        {
            body.Append("<ul>");

            foreach (var session in model.Sessions)
            {
                body.Append("<li>");

                Authorization(body, session.ClientHost, session.ClientId, session.Scopes, session.Resources);

                body.Append("<p>")
                    .Append(Text(InteractionText.SessionsStarted, Stamp(session.CreatedAt)))
                    .Append("</p>");

                // Only when one was recorded. Every grant older than the column has none, and a row
                // reading "unknown device" says less than a row that does not mention one.
                //
                // Encoded, and that is load-bearing rather than routine: this is the one value on
                // this page that came from a header the caller chose, so it is the one a stranger
                // would try to put markup in.
                if (session.Device is { Length: > 0 } device)
                {
                    body.Append("<p>")
                        .Append(Text(InteractionText.SessionsDevice, Encode(device)))
                        .Append("</p>");
                }

                // Only when there is one. A session authorized minutes ago has not renewed yet and
                // is perfectly ordinary, so a line reading "never" would report freshness as
                // something wrong on the page somebody opens when they already suspect it is.
                if (session.LastRefreshedAt is { } refreshed)
                {
                    body.Append("<p>")
                        .Append(Text(InteractionText.SessionsRefreshed, Stamp(refreshed)))
                        .Append("</p>");
                }

                body
                    .Append("<form method=\"post\" action=\"")
                    .Append(Encode(AuthorizationServerPaths.MeSessions)).Append("\">")
                    .Append(Hidden(model.AntiforgeryFieldName, model.AntiforgeryToken))
                    .Append(Hidden("grant", session.Id))
                    .Append("<button type=\"submit\">").Append(Text(InteractionText.SessionsEnd)).Append("</button>")
                    .Append("</form></li>");
            }

            body.Append("</ul>");
        }

        // Only when a renewal is actually shown above, unlike SessionsTokens below. This one
        // explains a line on the page rather than the page itself, so on a list where no session
        // has ever renewed it would be a caveat about nothing — and a reader looking for the thing
        // it qualifies would not find it.
        if (model.Sessions.Any(s => s.LastRefreshedAt is not null))
        {
            body.Append("<p>").Append(Text(InteractionText.SessionsRefreshedNote)).Append("</p>");
        }

        // The control that ends all of them, and the confirmation it leads to. Only with something
        // to end: on an empty list the button would offer to do nothing, and the reader most likely
        // to press it is the one who arrived alarmed and will read any control as the response.
        if (model.Sessions.Count > 0)
        {
            if (model.Confirming)
            {
                body.Append("<p>").Append(Text(InteractionText.SessionsEndAllQuestion)).Append("</p>")
                    .Append("<form method=\"post\" action=\"")
                    .Append(Encode(AuthorizationServerPaths.MeSessions)).Append("\">")
                    .Append(Hidden(model.AntiforgeryFieldName, model.AntiforgeryToken))

                    // The intent rides on the button rather than on a hidden field, and both steps
                    // are one field with two values. A hidden input would be a second thing on this
                    // page describing what pressing it means, sitting beside every row's own form —
                    // and a form's hidden fields are exactly what something reading the page cannot
                    // tell apart from another form's.
                    .Append("<button type=\"submit\" name=\"all\" value=\"confirm\">")
                    .Append(Text(InteractionText.SessionsEndAllConfirm)).Append("</button>")
                    .Append("</form>")

                    // A link rather than a second button: the way out of a destructive confirmation
                    // should not look like the way through it.
                    .Append("<p><a href=\"").Append(Encode(AuthorizationServerPaths.MeSessions)).Append("\">")
                    .Append(Text(InteractionText.SessionsEndAllCancel)).Append("</a></p>");
            }
            else
            {
                body.Append("<form method=\"post\" action=\"")
                    .Append(Encode(AuthorizationServerPaths.MeSessions)).Append("\">")
                    .Append(Hidden(model.AntiforgeryFieldName, model.AntiforgeryToken))
                    .Append("<button type=\"submit\" name=\"all\" value=\"ask\">")
                    .Append(Text(InteractionText.SessionsEndAll)).Append("</button>")
                    .Append("</form>");
            }
        }

        // Said whether or not there are any, because it is the sentence that stops "I ended it"
        // from being read as "it is gone now". Which of those it is depends on whether the
        // application's own server asks this one, and nothing reachable from here knows that — so
        // the sentence carries both branches and this call site chooses neither.
        body.Append("<p>")
            .Append(Text(InteractionText.SessionsTokens, Minutes(model.AccessTokenLifetime)))
            .Append("</p>")
            .Append("<p><a href=\"").Append(Encode(AuthorizationServerPaths.Me)).Append("\">")
            .Append(Text(InteractionText.AccountBack)).Append("</a></p>");

        return Wrap(
            InteractionPageKind.Sessions,
            Plain(InteractionText.SessionsTitle),
            body.ToString(),
            model.Nonce);
    }

    /// <inheritdoc />
    public string RenderConsents(ConsentsPageModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        var body = new StringBuilder("<h1>").Append(Text(InteractionText.ConsentsTitle)).Append("</h1>");

        if (model.Withdrawn)
        {
            body.Append("<p>").Append(Text(InteractionText.ConsentsWithdrawn)).Append("</p>");
        }

        if (model.Consents.Count == 0)
        {
            body.Append("<p>").Append(Text(InteractionText.ConsentsNone)).Append("</p>");
        }
        else
        {
            body.Append("<ul>");

            foreach (var consent in model.Consents)
            {
                body.Append("<li>");

                Authorization(body, consent.ClientHost, consent.ClientId, consent.Scopes, consent.Resources);

                body.Append("<p>")
                    .Append(Text(InteractionText.ConsentsGranted, Stamp(consent.GrantedAt)))
                    .Append("</p>")
                    .Append("<form method=\"post\" action=\"")
                    .Append(Encode(AuthorizationServerPaths.MeConsents)).Append("\">")
                    .Append(Hidden(model.AntiforgeryFieldName, model.AntiforgeryToken))
                    .Append(Hidden("client", consent.ClientId))
                    .Append("<button type=\"submit\">").Append(Text(InteractionText.ConsentsWithdraw))
                    .Append("</button>")
                    .Append("</form></li>");
            }

            body.Append("</ul>");
        }

        // Said whether or not there are any, and the link beside it, because "withdraw" is the word
        // a person reads as "cut it off". E-38 is that it does not: the next authorization asks
        // again, and a token already issued is unaffected. Ending the access is the other page, and
        // somebody who wants both has to be told there are two.
        body.Append("<p>").Append(Text(InteractionText.ConsentsNotSessions)).Append("</p>")
            .Append("<p><a href=\"").Append(Encode(AuthorizationServerPaths.MeSessions)).Append("\">")
            .Append(Text(InteractionText.ConsentsSeeSessions)).Append("</a></p>")
            .Append("<p><a href=\"").Append(Encode(AuthorizationServerPaths.Me)).Append("\">")
            .Append(Text(InteractionText.AccountBack)).Append("</a></p>");

        return Wrap(
            InteractionPageKind.Consents,
            Plain(InteractionText.ConsentsTitle),
            body.ToString(),
            model.Nonce);
    }

    /// <inheritdoc />
    public string RenderResetPassword(ResetPasswordPageModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        var body = new StringBuilder("<h1>").Append(Text(InteractionText.ResetTitle)).Append("</h1>");

        if (model.State is ResetPasswordState.Done)
        {
            body.Append("<p>").Append(Text(InteractionText.ResetDone)).Append("</p>");

            if (model.SessionsRevoked > 0)
            {
                body.Append("<p>")
                    .Append(Text(
                        InteractionText.ResetDoneRevoked,
                        Encode(model.SessionsRevoked.ToString(CultureInfo.InvariantCulture))))
                    .Append("</p>");
            }

            SignIn(body, model.SignInUrl);

            return Wrap(
                InteractionPageKind.ResetPassword, Plain(InteractionText.ResetTitle), body.ToString(), model.Nonce);
        }

        if (model.State is ResetPasswordState.Expired)
        {
            // Said plainly, and §7.3 is why that is not an oracle: a token is 256 bits of CSPRNG
            // output, so there is nothing to enumerate — while a person who is not told their link
            // expired will click it again rather than ask for a new one.
            //
            // No form, because there is nothing a value in it could redeem.
            body.Append("<p role=\"alert\">").Append(Text(InteractionText.ResetExpired)).Append("</p>")
                .Append("<p>").Append(Text(InteractionText.ResetExpiredAdvice)).Append("</p>");

            return Wrap(
                InteractionPageKind.ResetPassword, Plain(InteractionText.ResetTitle), body.ToString(), model.Nonce);
        }

        if (model.State is ResetPasswordState.Mismatch or ResetPasswordState.Blank)
        {
            body.Append("<p role=\"alert\">")
                .Append(Text(model.State is ResetPasswordState.Mismatch
                    ? InteractionText.PasswordMismatch
                    : InteractionText.PasswordBlank))
                .Append("</p>");
        }

        // The token rides in a hidden field, not in the form's action. It arrives in the URL because
        // an email link has nowhere else to put it; keeping it there would write a live credential
        // into access logs, browser history and any `Referer` this page sends.
        body.Append("<p>").Append(Text(InteractionText.ResetInstruction)).Append("</p>")
            .Append("<form method=\"post\" action=\"")
            .Append(Encode(AuthorizationServerPaths.Reset)).Append("\">")
            .Append(Hidden(model.AntiforgeryFieldName, model.AntiforgeryToken))
            .Append(Hidden("token", model.Token))
            .Append("<label for=\"new\">").Append(Text(InteractionText.PasswordNew)).Append("</label>")
            .Append("<input id=\"new\" name=\"new\" type=\"password\" autocomplete=\"new-password\" required>")
            .Append("<label for=\"confirm\">").Append(Text(InteractionText.PasswordConfirm)).Append("</label>")
            .Append("<input id=\"confirm\" name=\"confirm\" type=\"password\" "
                + "autocomplete=\"new-password\" required>")
            .Append("<button type=\"submit\">").Append(Text(InteractionText.ResetSubmit)).Append("</button>")
            .Append("</form>");

        return Wrap(
            InteractionPageKind.ResetPassword, Plain(InteractionText.ResetTitle), body.ToString(), model.Nonce);
    }

    /// <inheritdoc />
    public string RenderForgotPassword(ForgotPasswordPageModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        var body = new StringBuilder("<h1>").Append(Text(InteractionText.ForgotTitle)).Append("</h1>");

        if (model.State is not ForgotPasswordState.Form)
        {
            // No form on either of the two answers. Redrawing it under "a link is on its way" reads
            // as an invitation to try again, which is how somebody spends their three attempts
            // before the first mail has arrived.
            body.Append(model.State is ForgotPasswordState.Sent
                ? "<p>" + Text(InteractionText.ForgotSent) + "</p>"
                : "<p role=\"alert\">" + Text(InteractionText.ForgotThrottled) + "</p>");

            SignIn(body, model.SignInUrl);

            return Wrap(
                InteractionPageKind.ForgotPassword,
                Plain(InteractionText.ForgotTitle),
                body.ToString(),
                model.Nonce);
        }

        // One field, taking either a handle or an address, because the person using this page has
        // forgotten something and asking them which of the two they are typing is a question they
        // may also get wrong. `autocomplete="username"` covers both — a manager offering the stored
        // handle here is offering the right thing.
        body.Append("<p>").Append(Text(InteractionText.ForgotInstruction)).Append("</p>")
            .Append("<form method=\"post\" action=\"")
            .Append(Encode(AuthorizationServerPaths.Forgot)).Append("\">")
            .Append(Hidden(model.AntiforgeryFieldName, model.AntiforgeryToken))
            .Append("<label for=\"account\">").Append(Text(InteractionText.ForgotAccount)).Append("</label>")
            .Append("<input id=\"account\" name=\"account\" type=\"text\" autocomplete=\"username\" required>")
            .Append("<button type=\"submit\">").Append(Text(InteractionText.ForgotSubmit)).Append("</button>")
            .Append("</form>");

        SignIn(body, model.SignInUrl);

        return Wrap(
            InteractionPageKind.ForgotPassword,
            Plain(InteractionText.ForgotTitle),
            body.ToString(),
            model.Nonce);
    }

    /// <inheritdoc />
    public string RenderVerifyEmail(VerifyEmailPageModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        var body = new StringBuilder("<h1>").Append(Text(InteractionText.VerifyTitle)).Append("</h1>");

        body.Append(model.Verified
            ? "<p>" + Text(InteractionText.VerifyDone, Strong(model.Email)) + "</p>"
            : "<p role=\"alert\">" + Text(InteractionText.VerifyExpired) + "</p>");

        return Wrap(
            InteractionPageKind.VerifyEmail, Plain(InteractionText.VerifyTitle), body.ToString(), model.Nonce);
    }

    /// <summary>
    /// One client, and what it may do — the block <c>/me/sessions</c> and <c>/me/consents</c> share.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>One method, because the two pages are two views of one authorization and a reader moves
    /// between them in a click.</b> They were written separately and drifted immediately: the
    /// approvals page rendered the configured descriptions and the sessions page rendered the wire
    /// scope, so a reader saw <c>email docs:read docs:write</c> on one and sentences on the other, for
    /// the same client, in the same session. Sharing the markup makes "described the same way" a
    /// property of this file rather than a thing two loops happen to agree on.
    /// </para>
    /// <para>
    /// <b>The host leads and the full id follows it</b>, the order the consent page uses and for the
    /// same <c>N-14</c> reason: the id is chosen by the client, and for a CIMD client it is a URL
    /// long enough to push everything else off a phone. The host is an A-label — computed by the
    /// server, not derived here — so a homograph cannot be what a reader sees.
    /// </para>
    /// </remarks>
    private void Authorization(
        StringBuilder body,
        string clientHost,
        string clientId,
        IReadOnlyList<ConsentScope> scopes,
        IReadOnlyList<string> resources)
    {
        body.Append("<p>").Append(Strong(clientHost)).Append("</p>")
            .Append("<p><code>").Append(Encode(clientId)).Append("</code></p>")
            .Append("<ul>");

        foreach (var scope in scopes)
        {
            body.Append("<li>");

            if (scope.HasDescription)
            {
                body.Append(Encode(scope.Description));
            }
            else
            {
                // A-14, the same as on the consent page. The case this reaches that the consent page
                // cannot is a scope whose description was removed from configuration after the
                // approval that used it — inventing words for it here would describe an agreement
                // in terms the person never saw.
                body.Append("<code>").Append(Encode(scope.Name)).Append("</code> ")
                    .Append("<em>").Append(Text(InteractionText.ConsentScopeUndescribed)).Append("</em>");
            }

            body.Append("</li>");
        }

        body.Append("</ul>");

        if (resources.Count > 0)
        {
            body.Append("<p>").Append(Text(InteractionText.ConsentResourcesHeading)).Append("</p><ul>");

            foreach (var resource in resources)
            {
                body.Append("<li><code>").Append(Encode(resource)).Append("</code></li>");
            }

            body.Append("</ul>");
        }
    }

    /// <summary>A sentence, encoded, with our own markup in its placeholders.</summary>
    private string Text(string key, params string[] safeHtml) =>
        InteractionText.Format(_localizer, key, safeHtml);

    /// <summary>A sentence as plain text, for the title the layout encodes itself.</summary>
    private string Plain(string key) => InteractionText.Plain(_localizer, key);

    /// <summary>
    /// "Go to sign in", when there is somewhere to go.
    /// </summary>
    /// <remarks>
    /// <para>
    /// All three recovery pages used to write <c>href="/login"</c> unconditionally, and
    /// <c>GET /login</c> with no <c>returnUrl</c> is a <c>400</c> — it has no client, no redirect
    /// URI and nowhere to send anybody afterwards. So the last thing a person saw at the end of a
    /// successful password reset was <i>"This page was opened without a valid authorization
    /// request"</i>. Measured on a running deployment, by resetting a password and pressing the
    /// button the page offers.
    /// </para>
    /// <para>
    /// <b>Omitted rather than pointed somewhere hopeful.</b> When the self-service pages are off
    /// there is no standalone destination at all — <c>/authorize</c> needs a request in flight and
    /// nothing else accepts a bare arrival — and a link that lands on an error page is worse than
    /// no link, because it spends the reader's trust before it fails. The caller decides; this
    /// draws what it is given.
    /// </para>
    /// <para>
    /// The sign-out page is the fourth caller and was found the same way, a day later: it had no
    /// link at all, which is the same dead end reached by having nothing to press rather than the
    /// wrong thing.
    /// </para>
    /// <para>
    /// <see cref="InteractionText.ResetSignIn"/> on all four, and the key keeps its recovery-shaped
    /// name deliberately. Renaming it would not be a rename: the constant's value <i>is</i> the
    /// lookup key, so every deployment's translation file would stop matching and quietly serve the
    /// English fallback — which is the failure a translated deployment is least able to see.
    /// </para>
    /// </remarks>
    private void SignIn(StringBuilder body, string? url)
    {
        if (url is not { Length: > 0 })
        {
            return;
        }

        // The same class the sign-in page's "I forgot my password" carries, because they are the
        // same thing on four pages: the one link under the decision, pointing at the other page a
        // reader might have wanted. A sheet that centres one and not the other is a sheet that had
        // to find them separately.
        body.Append("<p class=\"bw-aside\"><a href=\"").Append(Encode(url)).Append("\">")
            .Append(Text(InteractionText.ResetSignIn)).Append("</a></p>");
    }

    private static string Strong(string? value) => "<strong>" + Encode(value) + "</strong>";

    private static string Hidden(string name, string value) =>
        $"<input type=\"hidden\" name=\"{Encode(name)}\" value=\"{Encode(value)}\">";

    private static string Encode(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);

    /// <summary>
    /// A moment, as a <c>&lt;time&gt;</c> element a machine can read and a person can too.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Round-trip in the attribute, which is what makes the element parseable, and the shorter
    /// <c>u</c> form as the text, which is what somebody reads. Both invariant: these are UTC
    /// instants rather than anything the reader's locale should reformat.
    /// </para>
    /// <para>
    /// Here rather than inline because three timestamps now render this way — when a session
    /// started, when it last renewed, when an approval was given — and the third copy is where a
    /// pair of them starts silently disagreeing about the format.
    /// </para>
    /// </remarks>
    private static string Stamp(DateTimeOffset value) =>
        "<time datetime=\"" + Encode(value.ToString("O", CultureInfo.InvariantCulture)) + "\">"
        + Encode(value.ToString("u", CultureInfo.InvariantCulture))
        + "</time>";

    /// <summary>A duration as whole minutes, rounded up.</summary>
    /// <remarks>
    /// <para>
    /// <b>Up, because the one sentence that uses it says "at most".</b> The shortest lifetime a
    /// deployment may configure is five minutes and one second; rounding that down to five would
    /// print a ceiling this server does not honour, and understating how long somebody stays
    /// exposed is the direction not to be wrong in on this page.
    /// </para>
    /// <para>
    /// Invariant, like <see cref="Stamp"/> and like the revoked-session count above: these digits
    /// are a deployment's configuration rather than anything the reader's locale should reformat.
    /// </para>
    /// </remarks>
    /// <summary>A count, for a sentence that names one.</summary>
    /// <remarks>
    /// Invariant, like <see cref="Minutes"/> and like <c>Stamp</c>: the digits are not something a
    /// reader's locale should regroup, and the value is spliced into an already-encoded string where
    /// a thousands separator chosen by the server's culture would be one more thing to explain.
    /// </remarks>
    private static string Count(int value) =>
        Encode(value.ToString(CultureInfo.InvariantCulture));

    private static string Minutes(TimeSpan value) =>
        Encode(((long)Math.Ceiling(value.TotalMinutes)).ToString(CultureInfo.InvariantCulture));

    /// <summary>
    /// Hand the body to the layout, and refuse the result if the body is not in it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The check is what makes the layout seam worth having.</b> Everything N-14, A-11 and A-14
    /// require is inside <paramref name="body"/> already, so a layout has exactly one way to lose
    /// any of it — leaving the body out — and one condition is a condition that can be verified.
    /// Without this, the middle tier would be the top tier with a smaller interface: a deployment
    /// could still ship a consent page with no client hostname, no scope list and no form, and the
    /// first sign would be a user unable to connect.
    /// </para>
    /// <para>
    /// Throws rather than falling back to the default shell. A fallback would mean a deployment
    /// whose layout is broken serves unbranded pages that work, which nobody investigates, and the
    /// bug is found the day someone changes the layout again. This fails on the first render, in
    /// the deployment's own testing, naming the type.
    /// </para>
    /// <para>
    /// An ordinal <c>Contains</c> over a few kilobytes, on a page a user waits on and reads. It is
    /// not on any hot path — these two pages are rendered a handful of times per sign-in — and the
    /// alternative to paying for it is not knowing.
    /// </para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">The layout dropped the server's markup.</exception>
    private string Wrap(InteractionPageKind kind, string title, string body, string? nonce)
    {
        var page = new InteractionPage { Kind = kind, Title = title, Body = body, Nonce = nonce };

        var document = _layout.Wrap(page)
            ?? throw new InvalidOperationException(
                $"{_layout.GetType().FullName}.Wrap returned null for the {kind} page.");

        if (!document.Contains(body, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"{_layout.GetType().FullName}.Wrap did not include InteractionPage.Body in the "
                + $"{kind} page it returned. That markup is the whole of the page the server is "
                + "responsible for — on the consent page it carries the client's hostname, the "
                + "unverified-name notice, where the code will be sent, the scope list and the "
                + "form itself. Write it out verbatim and unencoded, wherever the shell should "
                + "place it. If the intent is to build that markup rather than to wrap it, "
                + "implement IInteractionRenderer instead and run InteractionRendererContract "
                + "against it.");
        }

        return document;
    }
}
