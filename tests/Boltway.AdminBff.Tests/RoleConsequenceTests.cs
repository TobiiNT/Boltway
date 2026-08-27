using Boltway.AdminBff;

namespace Boltway.AdminBff.Tests;

/// <summary>
/// What the admin pages say about a role, which is the only field on them that is a privilege.
/// </summary>
/// <remarks>
/// <para>
/// The Role box is free text and the server keeps it that way on purpose - <c>AdminAuthorization</c>
/// treats the role as an opaque string it never compares to a constant, and turning a role into an
/// entitlement belongs to the deployment through <c>IScopeEntitlementPolicy</c>. So nothing refuses
/// <c>foundeur</c>, and nothing should: an unknown role is a legitimate thing for a directory to
/// hold.
/// </para>
/// <para>
/// What was wrong is that the page said nothing either. Typing a role one letter off saved cleanly,
/// returned no error, and silently took administration away from the account. These assertions are
/// about the sentence that now sits beside the box, and about the fact that it is a sentence rather
/// than a validation rule.
/// </para>
/// </remarks>
public sealed class RoleConsequenceTests
{
    private static readonly string[] AdminRoles = ["founder"];

    private static string Page(string role, IReadOnlyCollection<string>? adminRoles) =>
        Render.AccountPage(Render.Account(role), adminRoles: adminRoles);

    /// <summary>A privileged role is stated as one.</summary>
    [Fact]
    public void An_admin_role_says_it_administers()
    {
        var html = Page("founder", AdminRoles);

        Assert.Contains("This role administers the directory", html, StringComparison.Ordinal);
    }

    /// <summary>An ordinary role is stated as one, and names what would not be.</summary>
    [Fact]
    public void A_non_admin_role_says_it_does_not()
    {
        var html = Page("employee", AdminRoles);

        Assert.Contains("does not administer the directory", html, StringComparison.Ordinal);
        Assert.Contains("founder", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The typo is the whole reason this exists.
    /// </summary>
    /// <remarks>
    /// <c>foundeur</c> is one keystroke from <c>founder</c> and means the opposite. The page has to
    /// say so, and it has to say so without refusing the value - which is why the assertion is that
    /// the sentence appears and the input still carries what was typed.
    /// </remarks>
    [Fact]
    public void A_role_one_letter_off_is_reported_as_not_administering()
    {
        var html = Page("foundeur", AdminRoles);

        Assert.Contains("does not administer the directory", html, StringComparison.Ordinal);
        Assert.Contains("value=\"foundeur\"", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// Told nothing, the page claims nothing.
    /// </summary>
    /// <remarks>
    /// <c>ADMIN_ROLES</c> is optional on this app, and a deployment that has not set it gets pages
    /// with no administration wording at all. Silence is correct here: naming a set this app was
    /// never given would be a confident answer to a question it cannot see.
    /// </remarks>
    [Fact]
    public void Without_configured_roles_the_page_says_nothing_about_administration()
    {
        var html = Page("founder", adminRoles: null);

        Assert.DoesNotContain("administers the directory", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<datalist", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// Case matters, because it matters to the server.
    /// </summary>
    /// <remarks>
    /// <c>AdminRoleScopePolicy</c> compares ordinally, so <c>Founder</c> is not <c>founder</c> and
    /// does not administer anything. A page that matched case-insensitively would tell an operator
    /// the account is privileged while the server refuses it - a wrong answer being worse here than
    /// no answer.
    /// </remarks>
    [Fact]
    public void Matching_is_ordinal_because_the_server_is()
    {
        var html = Page("Founder", AdminRoles);

        Assert.Contains("does not administer the directory", html, StringComparison.Ordinal);
    }

    /// <summary>The suggestions are suggestions, not a set of choices.</summary>
    /// <remarks>
    /// A <c>select</c> here would invent a validation rule the server does not have and would stop
    /// a deployment setting a role this app was never told about. The datalist offers the roles
    /// that mean something and constrains nothing, so the assertion is that both are true: the
    /// options exist, and the control is still a text input.
    /// </remarks>
    [Fact]
    public void Roles_are_suggested_by_a_datalist_and_not_constrained_by_a_select()
    {
        var html = Page("employee", AdminRoles);

        Assert.Contains("<datalist id=\"admin-roles\">", html, StringComparison.Ordinal);
        Assert.Contains("<option value=\"founder\">", html, StringComparison.Ordinal);
        Assert.Contains("<input id=\"role\"", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<select", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// A role carrying markup is encoded, on the page and in the suggestions.
    /// </summary>
    /// <remarks>
    /// The role is a string an operator typed and this app never validated, and it reaches the page
    /// three times now - the input's value, the sentence, and the datalist - so it is three chances
    /// to get encoding wrong rather than one.
    /// </remarks>
    [Fact]
    public void A_role_containing_markup_is_encoded_everywhere_it_appears()
    {
        var html = Render.AccountPage(Render.Account("ops"), adminRoles: ["<script>alert(1)</script>"]);

        Assert.DoesNotContain("<script>", html, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
    }

    /// <summary>The account list marks who can administer, so the question is answered in one look.</summary>
    [Fact]
    public void The_account_list_marks_administrators()
    {
        var html = Render.With(adminRoles: AdminRoles).RenderAccounts(new AccountsViewModel(
            Render.Json(
                """
                {"users":[
                  {"handle":"ada","email":"ada@example.com","role":"founder","email_verified":true},
                  {"handle":"grace","email":"grace@example.com","role":"employee","email_verified":true}]}
                """),
            Render.Tokens, null, "ada"));

        Assert.Contains("admin-badge", html, StringComparison.Ordinal);

        // One badge, not two: the marker means something only if it is not on every row.
        Assert.Equal(1, html.Split("admin-badge").Length - 1);
    }

    /// <summary>
    /// The two checkboxes say what clearing them does, not merely what they are.
    /// </summary>
    /// <remarks>
    /// They used to read "Address is proven" and "May sign in", which name a state and leave the
    /// operator to work out the consequence - and the consequences are not guessable. An unverified
    /// address cannot be typed at sign-in but the handle still can, and disabling an account refuses
    /// new sign-ins while every token already issued keeps working. Both facts are load-bearing and
    /// neither was on the page.
    /// </remarks>
    [Fact]
    public void The_verification_checkbox_says_what_it_costs()
    {
        var html = Page("employee", AdminRoles);

        Assert.Contains("Email is verified", html, StringComparison.Ordinal);
        Assert.Contains("Only a verified address can be typed at sign-in", html, StringComparison.Ordinal);
        Assert.Contains("The handle always works", html, StringComparison.Ordinal);
    }

    /// <inheritdoc cref="The_verification_checkbox_says_what_it_costs"/>
    [Fact]
    public void The_sign_in_checkbox_says_that_tokens_outlive_it()
    {
        var html = Page("employee", AdminRoles);

        Assert.Contains("Sign-in is allowed", html, StringComparison.Ordinal);
        Assert.Contains("refuses new sign-ins", html, StringComparison.Ordinal);
        Assert.Contains("keep working until they expire", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// And it does not offer a way to cut them off, because there is not one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This note used to end "— end every session to cut those off". `RevokeSessionsAsync` stops
    /// refresh chains; an access token is a signed JWT and no resource server checks it against a
    /// denylist. `IGrantStore.IsRevokedAsync` has no production caller in either repository, and a
    /// test in Boltway.OAuth.Tokens.Tests says so in as many words. The caveat on the very
    /// button it pointed at, rendered seven lines below on the same page, already said the true
    /// thing - so the page contradicted itself for whoever read both.
    /// </para>
    /// <para>
    /// The test above pinned the two halves that were true and nothing pinned the half that was
    /// not, which is why deleting the false clause left the suite green. This is that half: an
    /// operator working a compromise is told what ending every session does, and what it does not.
    /// </para>
    /// </remarks>
    [Fact]
    public void The_sign_in_note_does_not_claim_a_cutoff_it_cannot_perform()
    {
        var html = Page("employee", AdminRoles);

        Assert.Contains("stops them being renewed", html, StringComparison.Ordinal);
        Assert.DoesNotContain("cut those off", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The consequence is outside the label, so reading it does not toggle the box.
    /// </summary>
    /// <remarks>
    /// A <c>&lt;p&gt;</c> inside a <c>&lt;label&gt;</c> makes every word of it a click target for
    /// the checkbox. The sentence exists to be read before deciding; inside the label, reading it
    /// with a mouse is deciding.
    /// </remarks>
    [Fact]
    public void A_consequence_note_is_not_inside_its_label()
    {
        var html = Page("employee", AdminRoles);

        Assert.DoesNotContain("<p class=\"field-note\">Only a verified", html[..html.IndexOf("</label>", StringComparison.Ordinal)], StringComparison.Ordinal);
        Assert.Contains("</label><p class=\"field-note\">", html, StringComparison.Ordinal);
    }
}
