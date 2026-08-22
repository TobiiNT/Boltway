using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Interaction;

namespace Boltway.Interaction.Testing;

/// <summary>
/// The <see cref="IInteractionRenderer"/> contract, run against every implementation.
/// </summary>
/// <remarks>
/// <para>
/// The seam a deployment is most likely to take, and the one where taking it wrongly is invisible.
/// A store that loses a grant produces a failing request; a consent page missing the client hostname
/// produces a page that looks finished and has quietly dropped the only mitigation there is against
/// a client calling itself Claude from someone else's origin. Nothing fails, nobody is told, and the
/// requirement it breaks — N-14 — is a MUST in the MCP specification.
/// </para>
/// <para>
/// <b>What this suite refuses to assert:</b> wording. Every check below is either a value the
/// <i>server</i> put on the view model, a structural property of the markup, or a difference between
/// two renders. None of them pins a sentence, because a renderer that says
/// "chưa được xác minh" instead of "is not verified" is translated, not broken — and a contract that
/// fails it would be teaching customers to fork the suite, which defeats the point of shipping one.
/// </para>
/// <para>
/// The differential checks are the interesting half. "Did the renderer warn about a loopback
/// redirect" cannot be asked of wording, but it can be asked of two renders that differ only in
/// <see cref="ConsentViewModel.RedirectsToThisDevice"/>: if the output is identical, the flag was
/// ignored. That catches the real defect — a renderer built against an older model, or a template
/// where the warning was dropped in a redesign — without owning anybody's prose.
/// </para>
/// </remarks>
public abstract class InteractionRendererContract
{
    /// <summary>The renderer under test.</summary>
    protected abstract IInteractionRenderer NewRenderer();

    /// <summary>
    /// How much text, beyond an interpolated value itself, counts as the renderer having said
    /// something about it.
    /// </summary>
    /// <remarks>
    /// Twenty characters. Low enough that a terse or translated warning passes — "Không xác minh
    /// được" is 21 — and high enough that wrapping a value in punctuation does not. The number is
    /// arbitrary in the way a threshold has to be; what is not arbitrary is that <i>some</i> floor
    /// exists, because the defect being caught is a renderer that prints an attacker-chosen name
    /// with nothing next to it.
    /// </remarks>
    private const int Qualification = 20;

    // ─────────────────────────────────────────────────────────────────────────
    // N-14 — who is asking, and where the code goes
    // ─────────────────────────────────────────────────────────────────────────
    /// <summary>N-14: the host of the <c>client_id</c> URL appears — the relying party's real identity.</summary>

    [Fact]
    public void Consent_shows_the_host_of_the_client_id()
    {
        var text = Markup.Text(NewRenderer().RenderConsent(Consent()));

        Assert.Contains("evil.example", text, StringComparison.Ordinal);
    }

    /// <summary>
    /// The hostname leads and the self-asserted name follows it.
    /// </summary>
    /// <remarks>
    /// Order is the requirement, not merely presence. A page led by "Claude" with the real host in
    /// small print underneath displays every field N-14 asks for and is still the phishing surface
    /// N-14 exists to prevent — the shipped renderer's own comment calls reversing them "the whole
    /// attack". The fixture is that attack: a document at <c>evil.example</c> claiming the name
    /// <c>Claude</c>.
    /// </remarks>
    [Fact]
    public void Consent_shows_the_client_host_before_the_self_asserted_name()
    {
        var text = Markup.Text(NewRenderer().RenderConsent(Consent()));

        var host = text.IndexOf("evil.example", StringComparison.Ordinal);
        var name = text.IndexOf("Claude", StringComparison.Ordinal);

        Assert.True(host >= 0, "The client host is not on the page at all.");
        Assert.True(name >= 0, "The client name is not on the page at all.");
        Assert.True(
            host < name,
            $"The self-asserted name appears at {name}, before the client host at {host}. N-14: the "
            + "hostname is the identity and the name is subordinate to it.");
    }
    /// <summary>
    /// The client's logo comes after the hostname, and is never the first thing on the page.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The same rule as the one above, applied to the half a reader is least able to doubt. A logo
    /// is exactly as self-asserted as the name — anyone can put an image at their own URL, the same
    /// way anyone can publish <c>{"client_name":"Claude"}</c> — but a familiar mark reads as proof
    /// in a way a familiar word does not, so a page that leads with one has done the attacker's
    /// work in the most convincing form available. The fixture is that page: <c>evil.example</c>
    /// serving Claude's name and Claude's mark.
    /// </para>
    /// <para>
    /// Asserted on the markup rather than the text, because an image contributes no text and
    /// <see cref="Markup.Text"/> would find nothing to order. That also means this is the one
    /// N-14 assertion a renderer can pass while showing the reader something different — a
    /// stylesheet can move an image anywhere — which is why the shipped theme keeps it inline in
    /// the paragraph and why that is written down beside the rule rather than only here.
    /// </para>
    /// </remarks>
    [Fact]
    public void Consent_shows_the_client_host_before_the_logo()
    {
        var html = NewRenderer().RenderConsent(Consent());
        var logo = html.IndexOf("/client-logo", StringComparison.Ordinal);

        if (logo < 0)
        {
            // A renderer is free to draw no logo at all, and several should: it is the one field on
            // this model whose safest treatment is omission. Nothing to order, nothing to fail.
            return;
        }

        Assert.Contains("evil.example", Markup.Text(html), StringComparison.Ordinal);

        var host = html.IndexOf("evil.example", StringComparison.Ordinal);

        Assert.True(
            host < logo,
            $"The client's logo appears at {logo}, before the client host at {host}. N-14: the "
            + "hostname is the identity, and a logo is a claim the client made about itself.");
    }

    /// <summary>
    /// A client that published no logo gets no image, and no empty one either.
    /// </summary>
    /// <remarks>
    /// The proxy answers 404 for a host that is down, a body that is not an image and a type this
    /// server will not re-serve, so a renderer must not depend on the URL resolving. A page that
    /// lays out a slot for it shows a broken-image box beside the client's name on every one of
    /// those, which reads as "something is wrong with this page" on the page where a reader is
    /// deciding whether to trust something.
    /// </remarks>
    [Fact]
    public void Consent_draws_no_logo_when_the_client_published_none()
    {
        var html = NewRenderer().RenderConsent(Consent() with { ClientLogoUrl = null });

        Assert.DoesNotContain("/client-logo", html, StringComparison.Ordinal);
    }

    /// <summary>The self-asserted client name is qualified, never printed on its own.</summary>

    [Fact]
    public void Consent_qualifies_the_self_asserted_name_rather_than_printing_it_bare()
    {
        var renderer = NewRenderer();

        var named = Markup.Text(renderer.RenderConsent(Consent()));
        var anonymous = Markup.Text(renderer.RenderConsent(Consent() with { ClientName = null }));

        Assert.Contains("Claude", named, StringComparison.Ordinal);

        var beyondTheName = named.Length - anonymous.Length - "Claude".Length;

        Assert.True(
            beyondTheName >= Qualification,
            $"Rendering a client name added {beyondTheName} characters beyond the name itself. N-14: "
            + "the name is attacker-chosen and must be presented as unverified, not printed bare.");
    }
    /// <summary>Where the code is about to be sent appears, which is the one thing CIMD cannot attest.</summary>

    [Fact]
    public void Consent_shows_the_requested_redirect_host()
    {
        var text = Markup.Text(NewRenderer().RenderConsent(Consent()));

        Assert.Contains("127.0.0.1", text, StringComparison.Ordinal);
    }

    /// <summary>
    /// A redirect that lands on the user's own machine says so.
    /// </summary>
    /// <remarks>
    /// Loopback and private-use schemes both. For neither did a domain owner prove anything: any
    /// process can bind a loopback port, and RFC 8252 §8.4 says any application can register a
    /// private-use scheme. The user is the only party who knows whether they started this, so the
    /// page has to ask them — and a renderer that ignores the flag renders the same page either way,
    /// which is what this measures.
    /// </remarks>
    [Fact]
    public void Consent_warns_when_the_code_goes_to_the_users_own_device()
    {
        var renderer = NewRenderer();

        var device = Markup.Text(renderer.RenderConsent(Consent()));
        var web = Markup.Text(renderer.RenderConsent(Consent() with { RedirectsToThisDevice = false }));

        var added = device.Length - web.Length;

        Assert.True(
            added >= Qualification,
            $"RedirectsToThisDevice changed the page by {added} characters. N-14 requires an explicit "
            + "warning for a redirect the user's own machine receives.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A-14 — what is being asked for
    // ─────────────────────────────────────────────────────────────────────────
    /// <summary>A-14: a configured scope description is rendered as configured, never reworded.</summary>

    [Fact]
    public void Consent_renders_a_configured_scope_description_verbatim()
    {
        var text = Markup.Text(NewRenderer().RenderConsent(Consent()));

        Assert.Contains("Read the knowledge base", text, StringComparison.Ordinal);
    }

    /// <summary>
    /// A scope with no configured description shows the raw scope and says a description is missing.
    /// </summary>
    /// <remarks>
    /// A-14's second half, and the reason it is a rule: a screen that assumed <c>action:resource</c>
    /// and rendered "read: story your read" presented nonsense to a user as the thing they were
    /// agreeing to. Deriving text by parsing the name is banned; showing the name and admitting the
    /// gap is the required behaviour.
    /// </remarks>
    [Fact]
    public void Consent_shows_the_raw_scope_and_a_warning_when_no_description_is_configured()
    {
        var renderer = NewRenderer();

        var undescribed = Markup.Text(renderer.RenderConsent(
            Consent() with { Scopes = [new ConsentScope("kb:read", string.Empty, false)] }));

        // The same scope, described with its own name — so the two renders carry identical text
        // except for whatever the renderer adds to say the description is missing.
        var described = Markup.Text(renderer.RenderConsent(
            Consent() with { Scopes = [new ConsentScope("kb:read", "kb:read", true)] }));

        Assert.Contains("kb:read", undescribed, StringComparison.Ordinal);

        var added = undescribed.Length - described.Length;

        Assert.True(
            added >= Qualification,
            $"An undescribed scope rendered {added} characters differently from a described one. "
            + "A-14: show the raw scope and a configuration warning, never a derived description.");
    }
    /// <summary>Every resource the tokens will be valid at appears. RFC 8707 §2.1.</summary>

    [Fact]
    public void Consent_lists_every_resource()
    {
        var text = Markup.Text(NewRenderer().RenderConsent(Consent()));

        Assert.Contains("https://mcp.example.com/mcp", text, StringComparison.Ordinal);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The wire contract — field names the endpoints read
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// The decision field is named <c>decision</c> and approval is spelled <c>approve</c>.
    /// </summary>
    /// <remarks>
    /// <c>PostConsentAsync</c> reads <c>form["decision"]</c> and compares it to <c>"approve"</c>
    /// ordinally; everything else is a denial. So a renderer that names the control <c>action</c>,
    /// or spells the value <c>Approve</c>, produces a page whose Approve button denies. It fails
    /// closed, which is why nothing catches it — no error, no log line, just a user who cannot
    /// connect and a server that believes they declined.
    /// </remarks>
    [Fact]
    public void Consent_names_the_decision_field_the_way_the_endpoint_reads_it()
    {
        var html = NewRenderer().RenderConsent(Consent());

        Assert.Matches(@"name\s*=\s*[""']decision[""']", html);
        Assert.Matches(@"value\s*=\s*[""']approve[""']", html);
    }
    /// <summary>The form posts to this server's consent path, not anywhere the request named.</summary>

    [Fact]
    public void Consent_posts_to_the_local_consent_path()
    {
        var html = NewRenderer().RenderConsent(Consent());

        Assert.Matches(@"action\s*=\s*[""']" + AuthorizationServerPaths.Consent + @"[""']", html);
    }
    /// <summary>The account page offers a way out of the session it describes.</summary>
    /// <remarks>
    /// <para>
    /// In the contract rather than in the shipped renderer's own tests, because the page is where a
    /// person goes to manage their account and a renderer that lists everything except how to leave
    /// leaves signing out to whoever knows the path. That is a property of the page, not of one
    /// implementation of it, so a themed renderer has to keep it too.
    /// </para>
    /// <para>
    /// <b>A link or a form, because the property is a way out and not an element.</b> This asserted
    /// <c>href</c> alone until the shipped renderer stopped drawing one: a link goes to the
    /// confirmation page, so signing out took two presses on two pages, and somebody pressed once,
    /// read the question, left, and believed they had signed out. Measured in production — the
    /// <c>GET</c> was there and no <c>POST</c> followed it.
    /// </para>
    /// <para>
    /// <b>A form is the better answer and is deliberately not required.</b> Forcing one would make
    /// every themed renderer that draws a link fail a contract over a control that works, and this
    /// suite exists to pin properties rather than to propagate preferences. The reasoning is here so
    /// that an author choosing between them is choosing rather than guessing.
    /// </para>
    /// </remarks>
    [Fact]
    public void Account_links_to_the_sign_out_page()
    {
        var html = NewRenderer().RenderAccount(Account());

        // Not merely "the string /logout appears": that passes on a page that names the path in
        // prose and offers nothing to press.
        Assert.Matches(
            @"(href|action)\s*=\s*[""']" + AuthorizationServerPaths.EndSession + @"[""']", html);
    }


    /// <summary>
    /// An unverified address comes with a way to prove it.
    /// </summary>
    /// <remarks>
    /// The page said an address was "not verified" and offered nothing to do about it, because
    /// nothing in the server could send the link — <c>E-41</c> had a page to land on and no endpoint
    /// that could send you there. A renderer that draws the qualification and drops the button
    /// rebuilds that dead end in the theme layer.
    /// </remarks>
    [Fact]
    public void Account_offers_to_send_a_verification_link_for_an_unproven_address()
    {
        var html = NewRenderer().RenderAccount(UnverifiedAccount());

        Assert.Matches(
            @"action\s*=\s*[""']" + AuthorizationServerPaths.MeEmailVerify + @"[""']", html);
    }

    /// <summary>
    /// The offer carries the antiforgery token, because it is a state change.
    /// </summary>
    /// <remarks>
    /// A form that posts without one is refused by the endpoint, so a renderer that draws the
    /// button and forgets the field ships a control that always fails — and fails at the point where
    /// the person has already decided to press it.
    /// </remarks>
    [Fact]
    public void Account_verification_form_carries_the_antiforgery_token()
    {
        var model = UnverifiedAccount();
        var html = NewRenderer().RenderAccount(model);

        Assert.Contains(model.AntiforgeryFieldName, html, StringComparison.Ordinal);
        Assert.Contains(model.AntiforgeryToken, html, StringComparison.Ordinal);
    }

    /// <summary>Nothing to offer when the address is already proven.</summary>
    [Fact]
    public void Account_does_not_offer_verification_for_a_proven_address()
    {
        var html = NewRenderer().RenderAccount(Account());

        Assert.DoesNotMatch(
            @"action\s*=\s*[""']" + AuthorizationServerPaths.MeEmailVerify + @"[""']", html);
    }

    /// <summary>
    /// Nothing to offer on a deployment that cannot send mail.
    /// </summary>
    /// <remarks>
    /// The same rule as the sign-out link beside it: the endpoint decides, and a renderer that draws
    /// the control from a constant offers a button that mints a token and delivers nothing.
    /// </remarks>
    [Fact]
    public void Account_omits_the_verification_offer_when_the_server_cannot_send_it()
    {
        var html = NewRenderer().RenderAccount(UnverifiedAccount() with { VerifyEmailUrl = null });

        Assert.DoesNotMatch(
            @"action\s*=\s*[""']" + AuthorizationServerPaths.MeEmailVerify + @"[""']", html);
    }

    /// <summary>
    /// After a link is sent the page says something it did not say before.
    /// </summary>
    /// <remarks>
    /// Differential, like the consent warnings, and for the reason this suite states up front: the
    /// sentence is the renderer's to translate. What is measured is that the notice reaches the page
    /// at all — a renderer built against the older model ignores the field and renders the same page
    /// whether or not a link is in flight.
    /// </remarks>
    [Fact]
    public void Account_says_something_when_a_verification_link_has_been_sent()
    {
        var renderer = NewRenderer();

        var sent = Markup.Text(renderer.RenderAccount(
            UnverifiedAccount() with { VerificationNotice = EmailVerificationNotice.Sent }));
        var quiet = Markup.Text(renderer.RenderAccount(UnverifiedAccount()));

        var added = sent.Length - quiet.Length;

        Assert.True(
            added >= Qualification,
            $"Sending a link changed the page by {added} characters. Somebody who has just pressed "
            + "the button needs to be told it worked.");
    }

    /// <summary>
    /// A link in flight does not make the page claim the address is proven.
    /// </summary>
    /// <remarks>
    /// Nobody has opened it yet. A renderer that swapped the "not verified" qualification for the
    /// sent notice would be asserting something no one has done — so the unverified case must still
    /// read differently from the verified one while the notice is showing.
    /// </remarks>
    [Fact]
    public void Account_still_qualifies_the_address_while_a_link_is_in_flight()
    {
        var renderer = NewRenderer();

        var unproven = Markup.Text(renderer.RenderAccount(
            UnverifiedAccount() with { VerificationNotice = EmailVerificationNotice.Sent }));
        var proven = Markup.Text(renderer.RenderAccount(
            Account() with { VerificationNotice = EmailVerificationNotice.Sent }));

        var added = unproven.Length - proven.Length;

        Assert.True(
            added >= Qualification,
            $"An unverified address with a link in flight rendered {added} characters differently "
            + "from a verified one. The address is not proven until somebody opens the link.");
    }

    /// <summary>
    /// Asking too often is said, and said differently from succeeding.
    /// </summary>
    /// <remarks>
    /// A page that ignores a press looks broken, and the next thing the person does is press it
    /// again — which is what the throttle exists to stop. Two renders that differ only in the notice
    /// must not be identical, or the distinction was dropped.
    /// </remarks>
    [Fact]
    public void Account_distinguishes_a_throttled_request_from_a_sent_one()
    {
        var renderer = NewRenderer();

        var tooSoon = Markup.Text(renderer.RenderAccount(
            UnverifiedAccount() with { VerificationNotice = EmailVerificationNotice.TooSoon }));
        var sent = Markup.Text(renderer.RenderAccount(
            UnverifiedAccount() with { VerificationNotice = EmailVerificationNotice.Sent }));

        Assert.NotEqual(sent, tooSoon);

        var quiet = Markup.Text(renderer.RenderAccount(UnverifiedAccount()));

        Assert.True(
            tooSoon.Length - quiet.Length >= Qualification,
            "A refused request rendered the same page as one that was never made.");
    }

    /// <summary>The way out does not depend on how the person signs in.</summary>
    /// <remarks>
    /// The password link is absent for a federated account — deliberately, since there is nothing
    /// here to change — and the sign-out link sits beside it. Asserting the federated case
    /// separately is what stops a future edit from folding the two together and taking the exit
    /// away from exactly the accounts that never had a password to begin with.
    /// </remarks>
    [Fact]
    public void Account_links_to_the_sign_out_page_for_a_federated_account()
    {
        var html = NewRenderer().RenderAccount(Account(hasPassword: false));

        // Either shape, for the reason the non-federated case above records at length.
        Assert.Matches(
            @"(href|action)\s*=\s*[""']" + AuthorizationServerPaths.EndSession + @"[""']", html);
    }

    /// <summary>No sign-out link when the deployment routes no sign-out page.</summary>
    /// <remarks>
    /// <c>/logout</c> exists only when <c>EndSessionEnabled</c> is set, so a renderer that draws
    /// the link from a constant instead of from the model offers a 404 — and it does it on the page
    /// a person opens to find out what they are allowed to do. Found by loading the running sample,
    /// whose self-service pages are on and whose end-session page is not; every renderer unit test
    /// had passed, because none of them could see the routing table.
    /// </remarks>
    [Fact]
    public void Account_omits_the_sign_out_link_when_there_is_no_sign_out_page()
    {
        var html = NewRenderer().RenderAccount(Account() with { SignOutUrl = null });

        Assert.DoesNotMatch(
            @"href\s*=\s*[""']" + AuthorizationServerPaths.EndSession + @"[""']", html);
    }
    /// <summary>The consent form carries the antiforgery field and the return URL the server computed.</summary>

    [Fact]
    public void Consent_carries_the_antiforgery_field_and_the_return_url()
    {
        var html = NewRenderer().RenderConsent(Consent());

        Assert.Contains("__RequestVerificationToken", html, StringComparison.Ordinal);
        Assert.Contains("a-token-value", html, StringComparison.Ordinal);

        // Decoded once, because the return URL carries a query string and therefore an `&` that a
        // correct renderer writes as `&amp;`. Asserting the raw value appeared would be asserting
        // the renderer forgot to encode it; asserting it survives one decode is asserting the
        // browser will post back what the server put on the model.
        Assert.Contains(ReturnUrl, Markup.Decoded(html), StringComparison.Ordinal);
    }
    /// <summary>The credential inputs use the names the login endpoint reads.</summary>

    [Fact]
    public void Login_names_the_credential_fields_the_way_the_endpoint_reads_them()
    {
        var html = NewRenderer().RenderLogin(Login());

        Assert.Matches(@"name\s*=\s*[""']username[""']", html);
        Assert.Matches(@"name\s*=\s*[""']password[""']", html);
    }
    /// <summary>The sign-in form carries the antiforgery field.</summary>

    [Fact]
    public void Login_carries_the_antiforgery_field()
    {
        var html = NewRenderer().RenderLogin(Login());

        Assert.Contains("__RequestVerificationToken", html, StringComparison.Ordinal);
        Assert.Contains("a-token-value", html, StringComparison.Ordinal);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A-10 / A-11 — every sign-in method, available or not
    // ─────────────────────────────────────────────────────────────────────────
    /// <summary>A-11: every configured provider appears, available or not.</summary>

    [Fact]
    public void Login_renders_every_configured_provider()
    {
        var text = Markup.Text(NewRenderer().RenderLogin(Login()));

        Assert.Contains("Google", text, StringComparison.Ordinal);
        Assert.Contains("Okta", text, StringComparison.Ordinal);
    }

    /// <summary>
    /// A configured-but-unavailable method is disabled with its reason, never dropped.
    /// </summary>
    /// <remarks>
    /// A-11. A method that vanishes is indistinguishable from one nobody configured, and the user
    /// who was told to sign in with Okta is left looking for a button that is not there. The reason
    /// is a value the server computed, so unlike a warning it can be asserted verbatim.
    /// </remarks>
    [Fact]
    public void Login_renders_a_disabled_provider_as_disabled_with_its_reason()
    {
        var html = NewRenderer().RenderLogin(Login());

        Assert.Contains("disabled", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Not available for this client", Markup.Text(html), StringComparison.Ordinal);
    }
    /// <summary>A federation-only deployment gets no password form.</summary>

    [Fact]
    public void Login_omits_the_password_form_when_local_passwords_are_off()
    {
        var html = NewRenderer().RenderLogin(Login() with { LocalPasswordsEnabled = false });

        Assert.DoesNotMatch(@"type\s*=\s*[""']password[""']", html);
    }

    /// <summary>
    /// A deployment with nothing configured still renders something a person can read.
    /// </summary>
    /// <remarks>
    /// Startup validation refuses this shape, so it is reachable only when a host registers a
    /// provider list that then answers empty. A blank page is the worst available answer to it — the
    /// user cannot tell a misconfigured server from a broken browser.
    /// </remarks>
    [Fact]
    public void Login_is_never_blank_when_nothing_is_configured()
    {
        var text = Markup.Text(NewRenderer().RenderLogin(
            Login() with { LocalPasswordsEnabled = false, ExternalProviders = [] }));

        Assert.True(
            text.Trim().Length >= Qualification,
            $"A login page with no configured method rendered {text.Trim().Length} characters of text.");
    }
    /// <summary>A refused attempt says so on the page.</summary>
    /// <remarks>
    /// <para>
    /// Differential, and it used to pin the sentence: the model carried the prose and this asserted
    /// it arrived verbatim. That was the assertion this suite says in its own header it will not
    /// make — and it had a cost beyond tidiness. Prose on the model is prose the endpoint chose, so
    /// no renderer could translate it, and a Vietnamese deployment served
    /// <i>"That username and password did not match."</i> under a heading reading "Đăng nhập".
    /// Measured on a running server.
    /// </para>
    /// <para>
    /// What has to be true is that the flag reached the page. A renderer that ignores it renders
    /// the same page either way, which is what the length difference measures — and it holds for a
    /// renderer whose wording is in any language.
    /// </para>
    /// </remarks>
    [Fact]
    public void Login_says_so_when_the_previous_attempt_was_refused()
    {
        var renderer = NewRenderer();

        var refused = Markup.Text(renderer.RenderLogin(Login() with { Rejected = true }));
        var first = Markup.Text(renderer.RenderLogin(Login()));

        var added = refused.Length - first.Length;

        Assert.True(
            added >= Qualification,
            $"Rejected changed the page by {added} characters. A refused sign-in that looks "
            + "identical to a first visit leaves somebody retyping a password that was received "
            + "and refused.");
    }

    /// <summary>
    /// The reset link is offered when the deployment can send one, and not when it cannot.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Differential, like the two sign-out states, and for the reason that class of assertion
    /// exists: what has to be true is that the flag reached the page. A renderer that ignores it
    /// draws the same thing twice, and both halves of that are defects — a link to a route that is
    /// not mapped when recovery is off, or, with it on, a deployment that has configured mail,
    /// tokens and three pages that nobody in a browser can reach.
    /// </para>
    /// <para>
    /// The path is asserted rather than the wording, because the wording is a translation and the
    /// path is a constant. It is checked only on the enabled half — <c>N-06</c>'s routed-or-absent
    /// rule is what makes the disabled half's absence the requirement.
    /// </para>
    /// </remarks>
    [Fact]
    public void Login_offers_password_recovery_only_when_the_deployment_has_it()
    {
        var renderer = NewRenderer();

        var on = renderer.RenderLogin(Login());
        var off = renderer.RenderLogin(Login() with { PasswordRecoveryEnabled = false });

        Assert.Matches(@"href\s*=\s*[""']" + AuthorizationServerPaths.Forgot + @"[""']", on);
        Assert.DoesNotMatch(@"href\s*=\s*[""']" + AuthorizationServerPaths.Forgot + @"[""']", off);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sign-out
    // ─────────────────────────────────────────────────────────────────────────
    /// <summary>The sign-out confirmation posts to the end-session path, with antiforgery.</summary>

    [Fact]
    public void Logout_confirmation_posts_to_the_end_session_path_with_the_antiforgery_field()
    {
        var html = NewRenderer().RenderLogout(Logout(LogoutState.ConfirmationNeeded));

        Assert.Matches(@"action\s*=\s*[""']" + AuthorizationServerPaths.EndSession + @"[""']", html);
        Assert.Contains("__RequestVerificationToken", html, StringComparison.Ordinal);
        Assert.Contains("a-token-value", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The two states are two pages, and a renderer that ignores the flag draws one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Differential, like the loopback warning, and for the same reason: what has to be true is that
    /// the state reached the page, and that cannot be asked of wording. A renderer built against an
    /// older model, or a template where one branch was lost in a redesign, produces identical
    /// output for both — and the visible symptom is a "sign out?" form on a page that has already
    /// signed you out, or worse, the reverse.
    /// </para>
    /// <para>
    /// The confirmation is the half with a form, and the signed-out half must not have one: a form
    /// that posts to <c>/logout</c> on the page shown to a browser with no session is a button that
    /// does nothing, offered to somebody who has already done it.
    /// </para>
    /// </remarks>
    [Fact]
    public void Logout_draws_the_two_states_differently()
    {
        var renderer = NewRenderer();

        var confirmation = renderer.RenderLogout(Logout(LogoutState.ConfirmationNeeded));
        var signedOut = renderer.RenderLogout(Logout(LogoutState.SignedOut));

        Assert.NotEqual(confirmation, signedOut);
        Assert.Matches(@"<form[^>]*method\s*=\s*[""']post[""']", confirmation);
        Assert.DoesNotMatch(@"<form[^>]*action\s*=\s*[""']" + AuthorizationServerPaths.EndSession + @"[""']", signedOut);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Encoding
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Attacker-chosen text arrives as text, on both pages.
    /// </summary>
    /// <remarks>
    /// The client name is the obvious one and the provider's display name is the one that gets
    /// forgotten, because it reads as configuration rather than as input — it is configuration that
    /// a federation provider can supply.
    /// </remarks>
    [Fact]
    public void Interpolated_markup_is_encoded_rather_than_rendered()
    {
        var renderer = NewRenderer();
        const string Injected = "<script>alert(1)</script>";

        var consent = renderer.RenderConsent(Consent() with { ClientName = Injected });
        var login = renderer.RenderLogin(Login() with
        {
            ExternalProviders = [new LoginProviderOption("x", Injected, "/external/x/start", true, null)],
        });

        Assert.False(Markup.HasInlineScript(consent), "A client name reached the consent page as markup.");
        Assert.False(Markup.HasInlineScript(login), "A provider name reached the login page as markup.");

        Assert.Contains(Injected, Markup.Text(consent), StringComparison.Ordinal);
        Assert.Contains(Injected, Markup.Text(login), StringComparison.Ordinal);
    }

    /// <summary>
    /// Non-ASCII text is encoded once, so it reads back as itself.
    /// </summary>
    /// <remarks>
    /// The regression this is here for was measured, not imagined: the model builder encoded the
    /// client name and the renderer encoded it again, so <c>Café</c> displayed as <c>Caf&amp;#233;</c>
    /// and <c>Acme &amp; "Claude"</c> as <c>Acme &amp;amp; &amp;quot;Claude&amp;quot;</c> — mojibake
    /// on the one page whose whole job is to be read carefully. It also quietly quadrupled the
    /// length cap, since each <c>&lt;</c> became six rendered characters.
    /// </remarks>
    [Fact]
    public void Non_ascii_text_is_encoded_exactly_once()
    {
        const string Name = "Café & \"Claude\"";

        var text = Markup.Text(NewRenderer().RenderConsent(Consent() with { ClientName = Name }));

        Assert.Contains(Name, text, StringComparison.Ordinal);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // N-15 — what the CSP on these pages will actually execute
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Nothing on either page is blocked by the policy the server sends with it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The authorization pages ship <c>default-src 'self'; form-action 'self'; frame-ancestors
    /// 'none'; base-uri 'none'; object-src 'none'</c>, with no <c>style-src</c> or <c>script-src</c>
    /// override — so both inherit <c>'self'</c>, and an inline style, an inline script, an
    /// <c>onclick</c>, a <c>data:</c> image and a CDN stylesheet are all refused by the browser.
    /// </para>
    /// <para>
    /// This is the check that moves that discovery from a customer's staging environment to their
    /// build. A renderer developed against a fixture that does not send the headers looks correct
    /// until it is deployed, and then renders unstyled with no error anywhere except the browser
    /// console.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(false, null)]
    [InlineData(true, null)]
    [InlineData(false, "r4nd0m-nonce-value")]
    [InlineData(true, "r4nd0m-nonce-value")]
    public void Pages_render_within_the_policy_the_server_sends(bool login, string? nonce)
    {
        var renderer = NewRenderer();

        var html = login
            ? renderer.RenderLogin(Login() with { Nonce = nonce })
            : renderer.RenderConsent(Consent() with { Nonce = nonce });

        // With no nonce configured every inline block is refused; with one, only the blocks carrying
        // it run. Both rows are here because a renderer that emits inline content unconditionally
        // passes whichever single row it was written against.
        Assert.Empty(Markup.UnnoncedInlineBlocks(html, nonce));

        // Neither of these is ever nonceable, whatever the deployment configured.
        Assert.False(Markup.HasInlineStyleAttribute(html), "A style attribute cannot carry a nonce.");
        Assert.False(Markup.HasEventHandlerAttribute(html), "An event handler attribute cannot carry a nonce.");

        Assert.Empty(Markup.OffOriginReferences(html));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Fixtures
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>The local URL that resumes the authorization request.</summary>
    protected const string ReturnUrl = "/authorize?client_id=https%3A%2F%2Fevil.example%2Fc.json&state=xyz";

    /// <summary>
    /// The attack N-14 is written against: a metadata document at one origin, claiming another
    /// vendor's name, redirecting to a port on the user's own machine.
    /// </summary>
    protected static ConsentViewModel Consent() => new()
    {
        ClientHost = "evil.example",
        RedirectHost = "127.0.0.1",
        RedirectsToThisDevice = true,
        ClientName = "Claude",

        // The attack completed: the document claiming another vendor's name also carries that
        // vendor's mark, which is the half a reader is least equipped to doubt. Set here rather
        // than left null so that every assertion below about where the hostname ranks is made
        // against the page at its most persuasive.
        ClientLogoUrl = "/client-logo?client_id=https%3A%2F%2Fevil.example%2Fc.json",
        Scopes =
        [
            new ConsentScope("kb:read", "Read the knowledge base", true),
        ],
        Resources = ["https://mcp.example.com/mcp"],
        ReturnUrl = ReturnUrl,
        AntiforgeryFieldName = "__RequestVerificationToken",
        AntiforgeryToken = "a-token-value",

        // The deployment default. The nonce rows of the policy theory set it explicitly.
        Nonce = null,
    };

    /// <summary>Local passwords plus one available provider and one that is not — A-11's shape.</summary>
    protected static LoginViewModel Login() => new()
    {
        ReturnUrl = ReturnUrl,
        Rejected = false,
        AntiforgeryFieldName = "__RequestVerificationToken",
        AntiforgeryToken = "a-token-value",
        Nonce = null,
        LocalPasswordsEnabled = true,
        ExternalProviders =
        [
            new LoginProviderOption("google", "Google", "/external/google/start", true, null),
            new LoginProviderOption("okta", "Okta", "/external/okta/start", false, "Not available for this client"),
        ],
        PasswordRecoveryEnabled = true,
    };

    /// <summary>Either half of the sign-out page.</summary>
    /// <param name="state">Which half.</param>
    /// <param name="signInUrl">
    /// Where "go to sign in" points, and <see langword="null"/> for a deployment that routes no
    /// standalone destination. Defaulted here so the contract's existing cases keep asking what
    /// they asked, and overridable so a renderer can be held to both answers.
    /// </param>
    protected static LogoutViewModel Logout(
        LogoutState state, string? signInUrl = "/login?returnUrl=%2Fme") => new()
    {
        State = state,
        AntiforgeryFieldName = "__RequestVerificationToken",
        AntiforgeryToken = "a-token-value",
        Nonce = null,
        SignInUrl = signInUrl,
    };

    /// <summary>The account page.</summary>
    /// <param name="hasPassword">
    /// Whether this account signs in with a password here. False is the federated account, which is
    /// the case that decides whether the way out is reachable for everyone or only for some.
    /// </param>
    protected static AccountPageModel Account(bool hasPassword = true) => new(
        Handle: "a-handle",
        Email: "someone@example.com",
        EmailVerified: true,
        Roles: ["employee"],
        HasPassword: hasPassword,
        Nonce: null,
        Providers: [],
        AntiforgeryFieldName: "__RequestVerificationToken",
        AntiforgeryToken: "a-token-value",
        SignOutUrl: AuthorizationServerPaths.EndSession);

    /// <summary>An account whose address nobody has proven, on a server that can send the link.</summary>
    protected static AccountPageModel UnverifiedAccount() => Account() with
    {
        EmailVerified = false,
        VerifyEmailUrl = AuthorizationServerPaths.MeEmailVerify,
    };
}
