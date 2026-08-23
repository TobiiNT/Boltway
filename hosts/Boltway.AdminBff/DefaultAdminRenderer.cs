using System.Globalization;
using System.Text;
using System.Text.Json;

using static Boltway.AdminBff.AdminMarkup;

namespace Boltway.AdminBff;

/// <summary>
/// The shipped admin pages.
/// </summary>
/// <remarks>
/// <para>
/// <b>Everything interpolated is encoded, without exception.</b> These pages render handles, email
/// addresses, roles and audit details that an operator typed and that this app has never validated —
/// it is a client, not the directory — so "it came from our own API" is not a reason to trust a
/// string. <see cref="AdminMarkup.Encode"/> is the only way a value reaches the output.
/// </para>
/// <para>
/// <b>Every sentence comes from <see cref="AdminText"/>, and none is a literal here.</b> That said
/// "English only" for a while and gave a reason that was true when it was written — an internal
/// tool's second localization mechanism is a cost with no reader. The reader appeared: the
/// deployment this ships to runs every other page in Vietnamese and its operators are the two people
/// who read these.
/// </para>
/// </remarks>
public sealed class DefaultAdminRenderer : IAdminRenderer
{
    private readonly IAdminLayout _layout;
    private readonly AdminText _text;
    private readonly IReadOnlyCollection<string>? _adminRoles;
    private readonly IReadOnlyCollection<string>? _permissions;

    /// <summary>
    /// The one script this app serves, and the only page element that needs any.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A file in <c>wwwroot</c>, so <c>default-src 'self'</c> covers it and the policy the shell
    /// sends is unchanged — no <c>script-src</c>, no nonce, nothing inline. It is emitted beside the
    /// copy buttons rather than in the shell, so the six pages with nothing to copy are still the
    /// zero-JavaScript pages §7.1 counted as the BFF's advantage.
    /// </para>
    /// <para>
    /// Public for the same reason <see cref="DefaultAdminLayout.ShippedStylesheet"/> is: a
    /// deployment serving this app behind a path prefix, or a replacement renderer wanting the same
    /// behaviour, should not have to re-derive the path from a string in a method body.
    /// </para>
    /// </remarks>
    public const string ClipboardScript = "/js/copy.js";

    /// <summary>
    /// The shipped pages in the shipped shell, as one shared instance.
    /// </summary>
    /// <remarks>
    /// What <see cref="IAdminRenderer"/>'s default members fall back to. It exists because a default
    /// interface member has no dependency injection: it cannot reach the layout, the words or the
    /// roles a deployment configured, so the only thing it can honestly render is this app's own
    /// page in this app's own shell. Stateless and immutable, hence shared.
    /// </remarks>
    public static DefaultAdminRenderer Shipped { get; } = new();

    /// <summary>The shipped pages, in the shipped shell and the built-in English.</summary>
    public DefaultAdminRenderer()
        : this(new DefaultAdminLayout(), AdminText.Default, adminRoles: null)
    {
    }

    /// <summary>The shipped pages, in a deployment's shell, words and roles.</summary>
    /// <param name="layout">Where the markup goes.</param>
    /// <param name="text">The deployment's words. <see cref="AdminText.Default"/> for English.</param>
    /// <param name="adminRoles">
    /// The roles this deployment grants <c>users:read</c> and <c>users:write</c> to, from
    /// <c>ADMIN_ROLES</c>. <see langword="null"/> or empty when the app was not told, and then the
    /// pages say nothing about administration rather than naming a set they were never given.
    /// </param>
    /// <param name="permissions">
    /// The permission vocabulary this deployment's resource server understands, from
    /// <c>ADMIN_PERMISSIONS</c>. <see langword="null"/> or empty when the app was not told, and the
    /// roles page keeps its free-text box. This is the deployment's own list, not the server's
    /// rule — the server stores any permission string — which is why the picker it feeds keeps an
    /// extras box beside it rather than becoming a closed list.
    /// </param>
    public DefaultAdminRenderer(
        IAdminLayout layout, AdminText text, IReadOnlyCollection<string>? adminRoles,
        IReadOnlyCollection<string>? permissions = null)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(text);

        _layout = layout;
        _text = text;
        _adminRoles = adminRoles is { Count: > 0 } ? adminRoles : null;
        _permissions = permissions is { Count: > 0 } ? permissions : null;
    }

    /// <summary>
    /// An audit timestamp, as something a person reads.
    /// </summary>
    /// <param name="value">The API's <c>at</c>, an RFC 3339 instant.</param>
    /// <remarks>
    /// <para>
    /// The API sends <c>2026-08-13T08:00:31.0367474+00:00</c> and the page printed it. Seven
    /// fractional digits and a <c>T</c> is a wire format, and it was the widest column on the page —
    /// the audit table's whole left edge given over to precision no operator uses. It is public
    /// because it is the third thing a stylesheet could not supply, and a replacement renderer
    /// wanting the same answer should not have to re-derive it.
    /// </para>
    /// <para>
    /// <b>Still UTC, and it says so.</b> Converting to the reader's zone means knowing it, and this
    /// app is not told — a deployment's operators are not necessarily where its server is. Printing
    /// a local-looking time that is actually UTC is how somebody reads an incident an hour wrong, so
    /// the suffix stays until there is a real timezone to use.
    /// </para>
    /// <para>
    /// Anything that does not parse is passed through untouched. A timestamp this app cannot read is
    /// still evidence, and swallowing it would be the audit log losing a row to a formatting rule.
    /// </para>
    /// </remarks>
    public static string Moment(string value) =>
        DateTimeOffset.TryParse(
            value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var at)
            ? at.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture)
            : value;

    /// <inheritdoc />
    public string RenderAccounts(AccountsViewModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        var body = new StringBuilder(Notice(model.Notice, model.NoticeValue));

        body.Append("<h1>").Append(_text[AdminText.NavAccounts]).Append("</h1>")
            .Append("<p><a href=\"/users/new\">").Append(_text[AdminText.CreateAccount]).Append("</a></p>")
            .Append("<table><thead><tr><th>").Append(_text[AdminText.ColumnHandle])
            .Append("</th><th>").Append(_text[AdminText.ColumnEmail])
            .Append("</th><th>").Append(_text[AdminText.ColumnRole])
            .Append("</th><th>").Append(_text[AdminText.ColumnState])
            .Append("</th></tr></thead><tbody>");

        var users = model.Page.TryGetProperty("item1", out var a) ? a
            : model.Page.TryGetProperty("users", out var b) ? b
            : model.Page.ValueKind is JsonValueKind.Array ? model.Page
            : default;

        if (users.ValueKind is JsonValueKind.Array)
        {
            foreach (var user in users.EnumerateArray())
            {
                var handle = Text(user, "handle");

                body.Append("<tr><td><a href=\"/users/").Append(Encode(Uri.EscapeDataString(handle))).Append("\">")
                    .Append(Encode(handle)).Append("</a></td><td>")
                    .Append(Encode(Text(user, "email")))
                    .Append(Flag(user, "email_verified") ? " ✓" : string.Empty)
                    .Append("</td><td>").Append(Encode(TextList(user, "role")))
                    // Marked in the list as well as on the detail page, because "who can administer
                    // this directory" is a question asked of the whole table, and answering it
                    // one account at a time means opening every row.
                    .Append(_adminRoles is not null
                        // Any of them, not the whole string. An account holding two roles has a
                        // space-separated value, which matched no configured role at all.
                        && Texts(user, "role").Any(r => _adminRoles.Contains(r, StringComparer.Ordinal))
                            ? " <span class=\"admin-badge\">" + _text[AdminText.AdminBadge] + "</span>"
                            : string.Empty)
                    // Classed by which state it is, not just that it is one. "Active" and "disabled"
                    // are the two answers in the column an operator scans this table for, and a
                    // stylesheet that can only find "the state cell" can mark neither of them.
                    .Append("</td><td>")
                    .Append(Text(user, "disabled_at") is { Length: > 0 }
                        ? "<span class=\"state disabled\">" + _text[AdminText.StateDisabled] + "</span>"
                        : "<span class=\"state active\">" + _text[AdminText.StateActive] + "</span>")
                    .Append("</td></tr>");
            }
        }

        body.Append("</tbody></table>");

        // The cursor, not a page number. E-25 is keyset-paged because subjects are ULIDs, and an
        // offset would make the last page read every page before it.
        if (model.Page.ValueKind is JsonValueKind.Object
            && model.Page.TryGetProperty("next", out var next)
            && next.ValueKind is JsonValueKind.String)
        {
            body.Append("<p><a href=\"/?after=").Append(Encode(Uri.EscapeDataString(next.GetString()!)))
                .Append("\">").Append(_text[AdminText.NextPage]).Append("</a></p>");
        }

        body.Append(RoleDatalist());

        return Wrap(
            AdminPageKind.Accounts, _text.Plain(AdminText.NavAccounts), body.ToString(),
            model.OperatorName, model.Antiforgery);
    }

    /// <inheritdoc />
    public string RenderAccount(AccountViewModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        var user = model.Account;
        var handle = Text(user, "handle");
        var hidden = Hidden(model.Antiforgery);
        var body = new StringBuilder(Notice(model.Notice, model.NoticeValue));

        body.Append("<h1>").Append(Encode(handle)).Append("</h1>")
            .Append("<dl>")
            .Append("<dt>").Append(_text[AdminText.FieldSubject]).Append("</dt><dd><code>")
            .Append(Encode(Text(user, "subject"))).Append("</code></dd>")
            .Append("<dt>").Append(_text[AdminText.FieldRealm]).Append("</dt><dd>")
            .Append(Encode(Text(user, "realm"))).Append("</dd>")
            .Append("<dt>").Append(_text[AdminText.FieldPassword]).Append("</dt><dd>")
            .Append(Flag(user, "has_password") ? _text[AdminText.PasswordSet] : _text[AdminText.PasswordNone])
            .Append("</dd></dl>");

        var disabled = Text(user, "disabled_at") is { Length: > 0 };

        body.Append("<h2>").Append(_text[AdminText.SectionChange]).Append("</h2>")
            .Append("<form method=\"post\" action=\"/users/").Append(Encode(Uri.EscapeDataString(handle)))
            .Append("/patch\">")
            .Append(hidden)
            .Append("<label for=\"role\">").Append(_text[AdminText.ColumnRole]).Append("</label>")
            .Append("<input id=\"role\" name=\"roles\" value=\"").Append(Encode(TextList(user, "role")))
            .Append("\" placeholder=\"").Append(_text[AdminText.PlaceholderClear]).Append('"')
            .Append(_adminRoles is not null ? " list=\"admin-roles\"" : string.Empty)
            .Append('>')
            .Append(RoleConsequence(TextList(user, "role")))
            .Append("<label for=\"email\">").Append(_text[AdminText.ColumnEmail]).Append("</label>")
            .Append("<input id=\"email\" name=\"email\" value=\"").Append(Encode(Text(user, "email")))
            .Append("\" placeholder=\"").Append(_text[AdminText.PlaceholderClear]).Append("\">")
            // Both labels used to name a state — "Address is proven", "May sign in" — and neither
            // said what turning it off does, which is the only thing an operator is deciding. The
            // caveats under Operations were already written that way; these now match them.
            //
            // The note sits outside the <label>, deliberately. Inside, every word of it would be a
            // click target for the checkbox, so reading the consequence would toggle it.
            .Append("<label><input type=\"checkbox\" name=\"email_verified\" value=\"true\"")
            .Append(Flag(user, "email_verified") ? " checked" : string.Empty)
            .Append("> ").Append(_text[AdminText.EmailVerified]).Append("</label>")
            .Append("<p class=\"field-note\">").Append(_text[AdminText.EmailVerifiedNote]).Append("</p>")
            .Append("<label><input type=\"checkbox\" name=\"enabled\" value=\"true\"")
            .Append(disabled ? string.Empty : " checked")
            .Append("> ").Append(_text[AdminText.SignInAllowed]).Append("</label>")
            .Append("<p class=\"field-note\">").Append(_text[AdminText.SignInAllowedNote]).Append("</p>")
            .Append("<button type=\"submit\">").Append(_text[AdminText.Apply]).Append("</button></form>");

        // Each of the three is its own form and its own verb, which is the shape the API has and the
        // reason it has it: none of them is a field somebody could pass to an update by accident.
        body.Append("<h2>").Append(_text[AdminText.SectionOperations]).Append("</h2><div class=\"ops\">")
            .Append(Op(handle, "password", hidden, _text[AdminText.OpPassword], _text[AdminText.OpPasswordCaveat]))
            .Append(Op(handle, "sessions", hidden, _text[AdminText.OpSessions], _text[AdminText.OpSessionsCaveat]))
            .Append(Op(handle, "anonymise", hidden, _text[AdminText.OpAnonymise], _text[AdminText.OpAnonymiseCaveat]))
            .Append("</div>")
            .Append(ServiceAccount(model, handle, hidden))
            .Append(RoleDatalist());

        return Wrap(AdminPageKind.Account, handle, body.ToString(), model.OperatorName, model.Antiforgery);
    }

    /// <summary>The service-account section, and the one place a secret is ever shown.</summary>
    /// <remarks>
    /// <para>
    /// Rendered only when the authorization server answered about one. An older server returns
    /// nothing here and the page is simply the page it was — a section that appeared as an error
    /// would make an upgrade look like a fault.
    /// </para>
    /// <para>
    /// <b>The owner's roles are stated next to the button on purpose.</b> A service account can do
    /// whatever this account can, so creating one on a founder's page is creating a credential with
    /// a founder's reach, and the moment to know that is before pressing rather than after.
    /// </para>
    /// <para>
    /// <b>A live secret takes the whole section over, and everything else waits.</b> It is on screen
    /// for one render and is then gone from every copy anywhere, so the page it is on is the page
    /// for taking it — the enabled checkbox and the two irreversible buttons under it are things
    /// that can be come back to and this cannot. That is also why the two credential fields sit
    /// together in one card: the client id is useless without the secret and the operator is about
    /// to paste both into the same configuration file.
    /// </para>
    /// </remarks>
    private string ServiceAccount(AccountViewModel model, string handle, string hidden)
    {
        if (model.ServiceAccount.ValueKind is not (JsonValueKind.Object or JsonValueKind.Null))
        {
            return string.Empty;
        }

        var none = model.ServiceAccount.ValueKind is JsonValueKind.Null;
        var secret = model.NewSecret is { Length: > 0 } minted ? minted : null;

        // ── the row, and when it is already open ────────────────────────────
        //
        // A disclosure, the same shape as a role and for the same reason: this is the rarest thing
        // on the longest page here — most accounts hold no service account and most visits are not
        // about one — and it sat below three sections a reader had to scroll past every time.
        //
        // Open on the two states where the body is the point. With none, the only thing that can be
        // done is inside it, and a create form behind a triangle is a capability nobody finds. With
        // a secret, the body holds a credential that exists in this response and in no other copy
        // anywhere — collapsed, that is a page that has destroyed something by rendering.
        var body = new StringBuilder("<details class=\"service\"")
            .Append(none || secret is not null ? " open" : string.Empty)
            .Append("><summary><span class=\"role-title\">")
            .Append(_text[AdminText.SectionServiceAccount]).Append("</span>");

        // The identifying pair rides on the row, so "does this account have one, and what may it
        // do" is answered without opening anything — the question the whole section is usually
        // visited for. Not when a secret is on screen: the card below is then showing the same id
        // beside the value it goes with, and printing it twice on the one render where it is most
        // closely read would make the reader check whether the two agreed.
        if (!none && secret is null)
        {
            body.Append("<code>").Append(Encode(Text(model.ServiceAccount, "client_id")))
                .Append("</code><span class=\"perms\">");

            foreach (var scope in Texts(model.ServiceAccount, "scopes"))
            {
                body.Append("<code>").Append(Encode(scope)).Append("</code>");
            }

            body.Append("</span>");
        }

        body.Append("</summary><div class=\"service-body\">");

        // First inside it, because it is gone the moment this page is left and everything else here
        // can be read again later.
        if (secret is not null)
        {
            body.Append(SecretCard(model.ServiceAccount, secret));
        }

        var action = "/users/" + Uri.EscapeDataString(handle) + "/service-account";

        if (none)
        {
            return body
                .Append("<p class=\"field-note\">")
                .Append(_text[AdminText.ServiceAccountNone]).Append("</p>")
                .Append("<form method=\"post\" action=\"").Append(Encode(action)).Append("\">")
                .Append(hidden)
                .Append(ScopeField(model.ScopesSupported))
                .Append("<p class=\"field-note\">")
                .Append(_text[AdminText.ServiceAccountCeiling]).Append(' ')
                .Append(Encode(TextList(model.Account, "role"))).Append("</p>")
                .Append("<button type=\"submit\">")
                .Append(_text[AdminText.ServiceAccountCreate]).Append("</button></form>")
                .Append("</div></details>")
                .ToString();
        }

        var enabled = Flag(model.ServiceAccount, "enabled");

        return body
            .Append("<form method=\"post\" action=\"").Append(Encode(action)).Append("/enabled\">")
            .Append(hidden)
            .Append("<label><input type=\"checkbox\" name=\"enabled\" value=\"true\"")
            .Append(enabled ? " checked" : string.Empty)
            .Append("> ").Append(_text[AdminText.ServiceAccountEnabled]).Append("</label>")

            // Outside the label, like the two above it, so that reading the consequence does not
            // toggle the box.
            .Append("<p class=\"field-note\">")
            .Append(_text[AdminText.ServiceAccountEnabledNote]).Append("</p>")
            .Append("<button type=\"submit\">").Append(_text[AdminText.Apply]).Append("</button></form>")

            // Rotate above delete, and both in the same shape as the account's own operations. They
            // are the two ways a credential ends: one leaves a working service account behind and
            // one does not, so the recoverable one is offered first.
            .Append("<div class=\"ops\">")
            .Append(Op(handle, "service-account/rotate", hidden,
                _text[AdminText.ServiceAccountRotate], _text[AdminText.ServiceAccountRotateCaveat]))
            .Append(Op(handle, "service-account/delete", hidden,
                _text[AdminText.ServiceAccountDelete], _text[AdminText.ServiceAccountDeleteCaveat]))
            .Append("</div>")
            .Append("</div></details>")
            .ToString();
    }

    /// <summary>
    /// A secret that exists in this response and nowhere else, with the client id beside it.
    /// </summary>
    /// <param name="account">The service account, for the id and scopes — or a JSON null.</param>
    /// <param name="secret">The plaintext, which the server keeps only a digest of.</param>
    /// <remarks>
    /// <para>
    /// <b>The copy buttons are the one script in this app, and they are here rather than in the
    /// shell.</b> The shell is on every page and would then carry a script for a control that
    /// exists on one; putting the <c>&lt;script&gt;</c> beside the buttons keeps the two together,
    /// so a replacement layout cannot leave a dead button behind and the other six pages stay what
    /// the CSP header says they are. It is a same-origin file, which
    /// <c>default-src 'self'</c> already allows — nothing inline, and no change to the policy.
    /// </para>
    /// <para>
    /// <b>Without it the page still works</b>, which is why the value is in a
    /// <c>&lt;code&gt;</c> the sheet marks as <c>user-select: all</c>: one click selects the whole
    /// credential, which is what somebody with no JavaScript would otherwise be doing by hand
    /// across a string designed to be hard to read.
    /// </para>
    /// <para>
    /// The button carries both labels, because the second one is a sentence and sentences live in
    /// <see cref="AdminText"/>. A script composing "Copied" itself would be the one string on these
    /// pages a deployment could not translate.
    /// </para>
    /// </remarks>
    private string SecretCard(JsonElement account, string secret)
    {
        var body = new StringBuilder("<div class=\"secret-card\">")
            .Append("<p class=\"notice\" role=\"alert\">")
            .Append(_text[AdminText.ServiceAccountSecretOnce]).Append("</p>")
            .Append("<dl class=\"kv\">");

        if (account.ValueKind is JsonValueKind.Object)
        {
            body.Append("<dt>client_id</dt><dd>")
                .Append(Copyable("sa-client-id", Text(account, "client_id"), secret: false))
                .Append("</dd>");
        }

        body.Append("<dt>client_secret</dt><dd>")
            .Append(Copyable("sa-secret", secret, secret: true))
            .Append("</dd></dl>");

        if (account.ValueKind is JsonValueKind.Object)
        {
            body.Append("<p class=\"field-note\">scopes <code>")
                .Append(Encode(TextList(account, "scopes"))).Append("</code></p>");
        }

        // Once per card rather than once per button: the file is one listener over the document, so
        // a second tag would be a second listener on the same clicks.
        return body.Append("<script src=\"").Append(ClipboardScript).Append("\" defer></script>")
            .Append("</div>")
            .ToString();
    }

    /// <summary>One value, selectable in a click and copyable in a press.</summary>
    /// <param name="id">The element id the button points at. Fixed strings, never a handle.</param>
    /// <param name="value">The value itself.</param>
    /// <param name="secret">Whether this is the credential, for the styling that says so.</param>
    private string Copyable(string id, string value, bool secret) =>
        "<code class=\"copyable" + (secret ? " secret" : string.Empty) + "\" id=\"" + Encode(id)
        + "\">" + Encode(value) + "</code>"
        + "<button type=\"button\" class=\"copy\" data-copy=\"" + Encode(id)
        + "\" data-copied=\"" + _text[AdminText.CopyDone] + "\">"
        + _text[AdminText.Copy] + "</button>";

    /// <summary>
    /// How a role's permissions are edited: a box, or the deployment's vocabulary as checkboxes.
    /// </summary>
    /// <param name="id">The role id, for unique control ids — <c>new</c> on the create form.</param>
    /// <param name="held">The permissions the role holds now.</param>
    /// <remarks>
    /// <para>
    /// <b>Unlike the scopes picker, this list is not the server's rule.</b> <c>scopes_supported</c>
    /// is enforced at <c>/authorize</c>, so those checkboxes are a closed field. This list is
    /// <c>ADMIN_PERMISSIONS</c> — the deployment's hand-written copy of its resource server's
    /// vocabulary — and the server stores any string, so the field must not lose what the list
    /// does not name.
    /// </para>
    /// <para>
    /// <b>Hence the union, and it is the part of this method that must not regress:</b> a held
    /// permission outside the vocabulary renders as a checkbox too, ticked. It used to ride in a
    /// free-text box beside the list, which read as two controls for one field; a ticked box is
    /// the same guarantee — saving an unrelated edit cannot silently strip it — with one control.
    /// What was dropped with the box is typing a brand-new permission here, deliberately: the
    /// resource server ignores permission names it does not implement, so a word the vocabulary
    /// has never heard of grants nothing, and the day the resource server learns it is the day
    /// <c>ADMIN_PERMISSIONS</c> does. The CLI and the API still accept anything.
    /// </para>
    /// </remarks>
    private string PermissionsField(string id, IReadOnlyList<string> held)
    {
        if (_permissions is null)
        {
            return "<label for=\"permissions-" + Encode(id) + "\">"
                + _text[AdminText.RolePermissions] + "</label>"
                + "<input id=\"permissions-" + Encode(id) + "\" name=\"permissions\" value=\""
                + Encode(string.Join(' ', held)) + "\">";
        }

        var field = new StringBuilder("<fieldset class=\"scopes\"><legend>")
            .Append(_text[AdminText.RolePermissionsChoose]).Append("</legend>");

        // Ordinal, like every permission comparison: `Docs_Read` ticked as `docs_read` would be the
        // capitalised near-miss shipping through a form.
        var offered = _permissions
            .Concat(held.Where(p => !_permissions.Contains(p, StringComparer.Ordinal)))
            .ToArray();

        foreach (var permission in offered)
        {
            field.Append("<label><input type=\"checkbox\" name=\"permissions\" value=\"")
                .Append(Encode(permission)).Append('"')
                .Append(held.Contains(permission, StringComparer.Ordinal) ? " checked" : string.Empty)
                .Append("> <code>").Append(Encode(permission)).Append("</code></label>");
        }

        return field.Append("</fieldset>").ToString();
    }

    /// <summary>
    /// How the scopes for a new service account are chosen.
    /// </summary>
    /// <param name="supported">
    /// What the server publishes, or <see langword="null"/> when this app could not find out.
    /// </param>
    /// <remarks>
    /// <para>
    /// <b>Checkboxes, and this is the one place on the page where a closed list is right.</b> The
    /// role beside it is a free-text box with a <c>datalist</c> because the server treats a role as
    /// an opaque string and a dropdown would invent a rule it does not have. Scopes are the other
    /// case: <c>scopes_supported</c> is documented as every scope the server will issue, and the
    /// authorize pipeline refuses anything outside it. Offering a box to type into was offering a
    /// way to mint a credential that obtains a token and is then refused by every resource server —
    /// which is the empty-scope failure the server already refuses, arriving one typo later and
    /// looking like it worked.
    /// </para>
    /// <para>
    /// <b>Nothing is filtered out.</b> <c>openid</c> and <c>offline_access</c> do nothing for a
    /// grant that returns no id token and no refresh token, and dropping them would still be this
    /// app deciding what a service account may hold — the mistake the role field documents, made
    /// about scopes instead. They are inert rather than harmful, so they are offered.
    /// </para>
    /// <para>
    /// Falling back to the free-text box when the list is unknown is what keeps a discovery failure
    /// from taking the create form with it. An empty list renders the same way for the same reason:
    /// a document that omits <c>scopes_supported</c> has not said there are none.
    /// </para>
    /// </remarks>
    private string ScopeField(IReadOnlyList<string>? supported)
    {
        if (supported is not { Count: > 0 })
        {
            return "<label for=\"scopes\">" + _text[AdminText.ServiceAccountScopes] + "</label>"
                + "<input id=\"scopes\" name=\"scopes\" value=\"\">";
        }

        var field = new StringBuilder("<fieldset class=\"scopes\"><legend>")
            .Append(_text[AdminText.ServiceAccountScopesChoose]).Append("</legend>");

        foreach (var scope in supported)
        {
            // The value and the visible text are the same string, and it is shown as code rather
            // than prose: this is the literal an operator will later find in a service's
            // configuration, so it has to be readable as one.
            field.Append("<label><input type=\"checkbox\" name=\"scopes\" value=\"")
                .Append(Encode(scope)).Append("\"> <code>")
                .Append(Encode(scope)).Append("</code></label>");
        }

        // Inside the fieldset, because it is about the set rather than about the form, and outside
        // any label for the reason the note beside every other checkbox on this page is.
        return field
            .Append("<p class=\"field-note\">")
            .Append(_text[AdminText.ServiceAccountScopesRequired]).Append("</p>")
            .Append("</fieldset>")
            .ToString();
    }

    /// <inheritdoc />
    public string RenderNewAccount(NewAccountViewModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        var body = new StringBuilder("<h1>").Append(_text[AdminText.CreateAccount]).Append("</h1>");

        if (model.Error is { Length: > 0 })
        {
            body.Append("<p class=\"notice\" role=\"alert\">").Append(Encode(model.Error)).Append("</p>");
        }

        body.Append("<form method=\"post\" action=\"/users/new\">")
            .Append(Hidden(model.Antiforgery))
            .Append("<label for=\"handle\">").Append(_text[AdminText.ColumnHandle])
            .Append("</label><input id=\"handle\" name=\"handle\" required>")
            .Append("<label for=\"email\">").Append(_text[AdminText.ColumnEmail])
            .Append("</label><input id=\"email\" name=\"email\" type=\"email\">")
            .Append("<label for=\"role\">").Append(_text[AdminText.ColumnRole])
            .Append("</label><input id=\"role\" name=\"role\"")
            .Append(_adminRoles is not null ? " list=\"admin-roles\"" : string.Empty)
            .Append('>')
            // No password field, and its absence is the control: the API generates one and has no
            // parameter for anything else. A field here would be the first half of adding one there.
            .Append("<button type=\"submit\">").Append(_text[AdminText.Create]).Append("</button>")
            .Append("<p>").Append(_text[AdminText.CreateCaveat]).Append("</p></form>")
            .Append(RoleDatalist());

        return Wrap(
            AdminPageKind.NewAccount, _text.Plain(AdminText.CreateAccount), body.ToString(),
            model.OperatorName, model.Antiforgery);
    }

    /// <inheritdoc />
    public string RenderAudit(AuditViewModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        var body = new StringBuilder("<h1>").Append(_text[AdminText.NavAudit]).Append("</h1>")
            .Append("<table><thead><tr><th>").Append(_text[AdminText.ColumnWhen])
            .Append("</th><th>").Append(_text[AdminText.ColumnActor])
            .Append("</th><th>").Append(_text[AdminText.ColumnAction])
            .Append("</th><th>").Append(_text[AdminText.ColumnTarget])
            .Append("</th><th>").Append(_text[AdminText.ColumnOutcome])
            .Append("</th><th>").Append(_text[AdminText.ColumnDetail])
            .Append("</th></tr></thead><tbody>");

        if (model.Entries.ValueKind is JsonValueKind.Array)
        {
            foreach (var entry in model.Entries.EnumerateArray())
            {
                body.Append("<tr><td>").Append(Encode(Moment(Text(entry, "at"))))
                    .Append("</td><td>").Append(Encode(Text(entry, "actor_kind")))
                    .Append("</td><td>").Append(Encode(Text(entry, "action")))
                    .Append("</td><td>").Append(Encode(Text(entry, "target_handle")))
                    .Append("</td><td>").Append(Encode(Text(entry, "outcome")))
                    .Append("</td><td>").Append(Encode(Text(entry, "detail")))
                    .Append("</td></tr>");
            }
        }

        body.Append("</tbody></table>");

        return Wrap(
            AdminPageKind.Audit, _text.Plain(AdminText.NavAudit), body.ToString(),
            model.OperatorName, model.Antiforgery);
    }

    /// <inheritdoc />
    /// <remarks>
    /// <para>
    /// <b>Everything on one page, and every role editable in place.</b> A realm has a handful of
    /// roles and the reason to open this page is to compare what they stand for — which a list
    /// linking to a detail page each cannot do, and which is the question somebody is asking when
    /// they wonder why an account can do something.
    /// </para>
    /// <para>
    /// <b>The id has no box.</b> It is what every token carries and what a resource server matches
    /// on, so it is chosen once; the API offers no way to change it either. The page says so where
    /// the box would have been, because a field with nothing beside it reads as unfinished rather
    /// than as decided.
    /// </para>
    /// <para>
    /// <b>Permissions are typed, not ticked</b> — the opposite of the service account's scopes, and
    /// for the reason that made those checkboxes right. A scope is in <c>scopes_supported</c> and
    /// the authorize pipeline enforces it, so a closed list matches a real rule. A permission is the
    /// resource server's word, stored here and never interpreted, and this server publishes no list
    /// of them. Offering one would be inventing a vocabulary on the deployment's behalf.
    /// </para>
    /// </remarks>
    public string RenderRoles(RolesViewModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        var hidden = Hidden(model.Antiforgery);
        var body = new StringBuilder(Notice(model.Notice));

        body.Append("<h1>").Append(_text[AdminText.NavRoles]).Append("</h1>")

            // Once, at the top, rather than under every role. Both sentences are about how this
            // page works rather than about any one role, and repeating them per role turned a page
            // with three roles into the same paragraph three times — which is how a caveat stops
            // being read.
            .Append("<p class=\"field-note\">").Append(_text[AdminText.RoleIdFixed]).Append("</p>")

            // Which note depends on whether a vocabulary was configured: "this server cannot offer
            // a list" is the truth without ADMIN_PERMISSIONS and a lie beside a list of checkboxes.
            .Append("<p class=\"field-note\">")
            .Append(_text[_permissions is null
                ? AdminText.RolePermissionsNote
                : AdminText.RolePermissionsListedNote]).Append("</p>");

        if (model.HoldersTruncated)
        {
            body.Append("<p class=\"field-note\">")
                .Append(_text[AdminText.RoleHoldersTruncated]).Append("</p>");
        }

        var roles = model.Roles.TryGetProperty("roles", out var listed) ? listed
            : model.Roles.ValueKind is JsonValueKind.Array ? model.Roles
            : default;

        var any = false;

        if (roles.ValueKind is JsonValueKind.Array)
        {
            body.Append("<div class=\"roles\">");

            foreach (var role in roles.EnumerateArray())
            {
                any = true;
                body.Append(Role(role, hidden, model.Accounts));
            }

            body.Append("</div>");
        }

        if (!any)
        {
            body.Append("<p class=\"field-note\">").Append(_text[AdminText.RolesNone]).Append("</p>");
        }

        // Open when there is nothing to list, closed otherwise. A realm with roles opens on the
        // list it came to read; a realm with none opens on the only thing it can do.
        body.Append("<details class=\"role new\"").Append(any ? string.Empty : " open").Append('>')
            .Append("<summary><span class=\"role-title\">")
            .Append(_text[AdminText.RoleCreate]).Append("</span></summary>")
            .Append("<div class=\"role-body\">")
            .Append("<form method=\"post\" action=\"/roles\">")
            .Append(hidden)
            .Append("<label for=\"new-id\">").Append(_text[AdminText.RoleNewId]).Append("</label>")
            .Append("<input id=\"new-id\" name=\"id\" value=\"\" required>")
            .Append("<p class=\"field-note\">").Append(_text[AdminText.RoleNewIdNote]).Append("</p>")
            .Append("<label for=\"new-name\">").Append(_text[AdminText.RoleName]).Append("</label>")
            .Append("<input id=\"new-name\" name=\"name\" value=\"\">")
            .Append("<p class=\"field-note\">").Append(_text[AdminText.RoleNameNote]).Append("</p>")
            .Append(PermissionsField("new", []))
            .Append("<button type=\"submit\">").Append(_text[AdminText.RoleDefine]).Append("</button>")
            .Append("</form></div></details>");

        return Wrap(
            AdminPageKind.Roles, _text.Plain(AdminText.NavRoles), body.ToString(),
            model.OperatorName, model.Antiforgery);
    }

    /// <summary>One role: what it is, what it is called, who holds it, and how to remove it.</summary>
    /// <param name="role">The role, as the admin API returned it.</param>
    /// <param name="hidden">The antiforgery field, already rendered.</param>
    /// <param name="accounts">Every account, for the holder list — or undefined for silence.</param>
    private string Role(JsonElement role, string hidden, JsonElement accounts)
    {
        var id = Text(role, "id");
        var action = "/roles/" + Uri.EscapeDataString(id);

        // Ordinal, matching AdminRoleScopePolicy on the authorization server. A case-insensitive
        // match here would warn about a role the server does not privilege, or stay silent about one
        // it does — and this is the page with a delete button on it.
        var administers = _adminRoles is not null && _adminRoles.Contains(id, StringComparer.Ordinal);

        // Who holds this role, read with the same Texts(user, "role") the accounts list uses, so
        // the two pages cannot disagree about what an account holds. Null when the accounts were
        // not fetched — which renders as silence, never as "nobody".
        var holders = accounts.ValueKind is JsonValueKind.Array
            ? accounts.EnumerateArray()
                .Where(user => Texts(user, "role").Contains(id, StringComparer.Ordinal))
                .Select(user => Text(user, "handle"))
                .Where(handle => handle.Length > 0)
                .ToArray()
            : null;

        // ── the row, which is all most visits need ─────────────────────────────
        //
        // Everything an operator came to compare is here and nothing is behind a click: the id, what
        // it is called, and what it stands for. The forms are inside the disclosure because editing
        // is the rarer thing, and three expanded roles is a page nobody scrolls.
        var body = new StringBuilder("<details class=\"role\"><summary>")
            .Append("<code>").Append(Encode(id)).Append("</code>")
            .Append("<span class=\"role-title\">").Append(Encode(Text(role, "name"))).Append("</span>");

        // On the summary rather than only inside, because a warning behind a disclosure triangle is
        // a warning nobody reads. The badge is the accounts list's own — one term for one concept —
        // and the sentence it stands for is still in the body, next to the button it is about.
        if (administers)
        {
            body.Append("<span class=\"admin-badge\">").Append(_text[AdminText.AdminBadge]).Append("</span>");
        }

        // The count rides on the row — the groups question is "who is in what", asked across all
        // roles at once. Only when there is somebody: a zero here would be a claim, and the body
        // states the empty case in a full sentence instead.
        if (holders is { Length: > 0 })
        {
            body.Append("<span class=\"role-count\">")
                .Append(_text.Format(
                    AdminText.RoleHolderCount,
                    holders.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)))
                .Append("</span>");
        }

        body.Append("<span class=\"perms\">");

        foreach (var permission in Texts(role, "permissions"))
        {
            body.Append("<code>").Append(Encode(permission)).Append("</code>");
        }

        body.Append("</span></summary><div class=\"role-body\">");

        if (administers)
        {
            body.Append("<p class=\"field-note administers\">")
                .Append(_text[AdminText.RoleAdminWarning]).Append("</p>");
        }

        // Holders, spelled out where the buttons are. Absent accounts render nothing — "no account
        // holds this role" is only ever said when the walk actually saw the whole directory's page.
        if (holders is not null)
        {
            if (holders.Length == 0)
            {
                body.Append("<p class=\"field-note\">")
                    .Append(_text[AdminText.RoleHoldersNone]).Append("</p>");
            }
            else
            {
                body.Append("<p class=\"field-note\">").Append(_text[AdminText.RoleHolders]).Append(' ');

                for (var i = 0; i < holders.Length; i++)
                {
                    if (i > 0)
                    {
                        body.Append(", ");
                    }

                    body.Append("<a href=\"/users/").Append(Encode(Uri.EscapeDataString(holders[i])))
                        .Append("\">").Append(Encode(holders[i])).Append("</a>");
                }

                body.Append("</p>");
            }
        }

        return body
            .Append("<form method=\"post\" action=\"").Append(Encode(action)).Append("\">")
            .Append(hidden)
            .Append("<label for=\"name-").Append(Encode(id)).Append("\">")
            .Append(_text[AdminText.RoleName]).Append("</label>")
            .Append("<input id=\"name-").Append(Encode(id)).Append("\" name=\"name\" value=\"")
            .Append(Encode(Text(role, "name"))).Append("\">")
            .Append(PermissionsField(id, Texts(role, "permissions")))
            .Append("<button type=\"submit\">").Append(_text[AdminText.Apply]).Append("</button>")
            .Append("</form>")

            // `danger` rather than a stylesheet matching the action's suffix, which is how the one
            // irreversible operation on the account page is currently found. A renderer saying which
            // of its buttons destroys something is the durable half of that: a deployment restyling
            // this app should not have to know which URLs happen to end in a verb.
            .Append("<form method=\"post\" class=\"danger\" action=\"")
            .Append(Encode(action)).Append("/delete\">")
            .Append(hidden)
            .Append("<button type=\"submit\">").Append(_text[AdminText.RoleDelete]).Append("</button>")
            .Append("<p class=\"field-note\">")
            .Append(_text[AdminText.RoleDeleteCaveat]).Append("</p>")
            .Append("</form></div></details>")
            .ToString();
    }

    /// <inheritdoc />
    public string RenderPassword(PasswordViewModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        // The same card as a freshly minted client secret, because it is the same situation: a
        // credential that exists in one response, that nothing can produce again, and that the
        // reader is about to move somewhere else by hand. It was a bare <p> and the operator was
        // selecting a generated password across a line break.
        var body =
            $"""
             <h1>{_text.Format(AdminText.NewPasswordHeading, Encode(model.Handle))}</h1>
             <div class="secret-card">
               <p class="notice" role="alert">{_text[AdminText.NewPasswordOnlyTime]}</p>
               <p class="secret">{Copyable("new-password", model.Password, secret: true)}</p>
               <script src="{ClipboardScript}" defer></script>
             </div>
             <p><a href="/users/{Encode(Uri.EscapeDataString(model.Handle))}">{_text[AdminText.BackToAccount]}</a></p>
             """;

        return Wrap(
            AdminPageKind.Password, _text.Plain(AdminText.NewPasswordTitle), body,
            model.OperatorName, model.Antiforgery);
    }

    /// <summary>
    /// <inheritdoc cref="IAdminRenderer.RenderRefusal" path="/summary"/>
    /// </summary>
    /// <param name="model">The refusal, in the API's own words.</param>
    /// <remarks>
    /// <para>
    /// <b>The refusal itself is not translated here, and that is deliberate.</b> The API's own
    /// <c>error_description</c> is printed rather than a sentence composed in this app: those
    /// sentences were written to name the rule that was broken — "<c>users:write</c> is not one of
    /// this token's scopes" — and a friendlier paraphrase would lose the part an operator acts on. They
    /// belong to the authorization server, and it is the thing that should learn to say them in
    /// another language; a lookup table here could only ever cover the refusals that existed when it
    /// was written.
    /// </para>
    /// <para>
    /// So a Vietnamese deployment gets this page's own words in Vietnamese around a refusal that may
    /// still be English. That is the per-string fallback working rather than failing — the
    /// alternative is losing the sentence that says what to do next.
    /// </para>
    /// </remarks>
    public string RenderRefusal(RefusalViewModel model)
    {
        ArgumentNullException.ThrowIfNull(model);
        ArgumentNullException.ThrowIfNull(model.Result);

        var body = new StringBuilder("<h1>").Append(_text[AdminText.RefusedHeading]).Append("</h1>")
            .Append("<p class=\"notice\" role=\"alert\">")
            .Append(model.Result.Description is { Length: > 0 } said
                ? Encode(said)
                : _text[AdminText.RefusedUnexplained])
            .Append("</p><p><code>")
            .Append(Encode(model.Result.Error
                ?? ((int)model.Result.Status).ToString(CultureInfo.InvariantCulture)))
            .Append("</code></p><p><a href=\"/\">").Append(_text[AdminText.BackToAccounts])
            .Append("</a></p>");

        return Wrap(
            AdminPageKind.Refused, _text.Plain(AdminText.RefusedTitle), body.ToString(),
            model.OperatorName, model.Antiforgery);
    }

    /// <summary>
    /// Hand a page to the layout, and check the layout kept it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A layout has exactly one way to lose the page, which is to leave <see cref="AdminPage.Body"/>
    /// out — so unlike a renderer's many ways, that one is checkable, and checking it is cheap
    /// enough to do on every render. Serving an empty document is a page an operator reports as
    /// "the admin UI is broken" with nothing in any log; throwing names the layout and the page.
    /// </para>
    /// <para>
    /// A weaker guarantee than the same check on the authorization server, and worth saying so: there
    /// the body carries what <c>N-14</c> requires, so a dropped body is a security failure that looks
    /// like a working page. Here it is only ever a blank one.
    /// </para>
    /// </remarks>
    private string Wrap(
        AdminPageKind kind, string title, string body, string? operatorName, AntiforgeryTokens antiforgery)
    {
        var page = new AdminPage
        {
            Kind = kind,
            Title = title,
            Body = body,
            OperatorName = operatorName,
            Antiforgery = antiforgery,
        };

        var document = _layout.Wrap(page);

        return document is not null && document.Contains(body, StringComparison.Ordinal)
            ? document
            : throw new InvalidOperationException(
                $"{_layout.GetType().Name}.Wrap did not include the page body for {kind}. A layout must "
                + "write AdminPage.Body into the document verbatim — it is already-encoded markup, and "
                + "the page is empty without it.");
    }

    /// <summary>
    /// What just happened, as a banner — or nothing.
    /// </summary>
    /// <param name="key">
    /// One of <see cref="AdminText.NoticeKeys"/>, straight off the query string. Anything else,
    /// including <see langword="null"/>, is no banner.
    /// </param>
    /// <param name="value">
    /// The <c>{0}</c> of the two notices that have one — a count, or the handle an account used to
    /// have. Encoded here; it is query-string text like the key.
    /// </param>
    /// <remarks>
    /// <para>
    /// <b>The membership test is the security property, and it has to come first.</b> This argument
    /// arrives from a link, so before the change it was arbitrary text reflected into this app's own
    /// banner — encoded, so never an injection, and still a sentence a reader takes as their console
    /// speaking to them. Matching it against a closed set means a crafted link chooses which of six
    /// sentences appears and cannot write a seventh. Echoing an unrecognised key, or handing one to
    /// <see cref="AdminText"/> to see what comes back, hands the channel straight back.
    /// </para>
    /// <para>
    /// It is also what keeps a bad link from being a 500: <see cref="AdminText.Plain"/> throws for a
    /// key it does not know, on purpose, and asking it about a string somebody else wrote is exactly
    /// the misuse that documents. <see cref="AdminText.Keys"/> would answer the question and answer
    /// it too generously — every sentence on these pages is in it, so a link could hoist a
    /// credential warning over a page with no credential on it.
    /// </para>
    /// <para>
    /// A notice whose value did not arrive renders nothing rather than a sentence with a visible
    /// <c>{0}</c> in it. The placeholder is the tell: <see cref="AdminText.Format"/> always replaces
    /// it, so one still standing here means nobody supplied the count or the handle the sentence is
    /// about — a half-written notice, which is what a hand-typed URL produces.
    /// </para>
    /// </remarks>
    private string Notice(string? key, string? value = null)
    {
        if (key is not { Length: > 0 } || !AdminText.NoticeKeys.Contains(key))
        {
            return string.Empty;
        }

        var sentence = value is { Length: > 0 } ? _text.Format(key, Encode(value)) : _text[key];

        return sentence.Contains("{0}", StringComparison.Ordinal)
            ? string.Empty
            : "<p class=\"notice\">" + sentence + "</p>";
    }

    /// <summary>The antiforgery field, rendered.</summary>
    private static string Hidden(AntiforgeryTokens antiforgery) =>
        $"<input type=\"hidden\" name=\"{Encode(antiforgery.FieldName)}\" "
        + $"value=\"{Encode(antiforgery.Token)}\">";

    /// <summary>
    /// The roles that mean something, offered as suggestions.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A <c>datalist</c> rather than a <c>select</c>, which is the whole point: it suggests without
    /// constraining, so an operator can still type a role this app has never heard of — which the
    /// server allows and some deployment will want.
    /// </para>
    /// <para>
    /// It used to sit after <c>&lt;/main&gt;</c>, which put a form control in the shell and meant the
    /// shell had to be told the roles. It is content belonging to the inputs that reference it, so it
    /// moved inside. Measured rather than assumed, because <c>main</c> is a grid in the deployment's
    /// stylesheet and a new child could have taken a row: <c>grid-template-rows</c> is unchanged and
    /// every box on the page is at the same pixel, since a <c>datalist</c> is <c>display: none</c>
    /// and generates no box at all.
    /// </para>
    /// </remarks>
    private string RoleDatalist() =>
        _adminRoles is null
            ? string.Empty
            : "<datalist id=\"admin-roles\">"
              + string.Concat(_adminRoles.Select(r => $"<option value=\"{Encode(r)}\">"))
              + "</datalist>";

    /// <summary>
    /// What the role in the box currently means, said beside the box.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A sentence and a datalist, not a select.</b> The server treats the role as an opaque string
    /// it never compares to a constant — <c>AdminAuthorization</c> says so, and turning a role into
    /// an entitlement is the deployment's job through <c>IScopeEntitlementPolicy</c>. A dropdown here
    /// would invent a validation rule the server does not have, and a deployment using a role this
    /// app was never told about could no longer set it. So the input stays free text, the datalist
    /// offers the roles that mean something, and this line says what the current value does.
    /// </para>
    /// <para>
    /// <b>Why it is here at all.</b> Typing <c>foundeur</c> into that box saves cleanly, returns no
    /// error, and silently removes the account from <c>ADMIN_ROLES</c> — the one field on this page
    /// whose value is a privilege decision was also the one with no feedback at all. Nothing
    /// downstream refuses it, because nothing downstream is supposed to: an unknown role is a
    /// legitimate thing for a directory to hold.
    /// </para>
    /// </remarks>
    private string RoleConsequence(string role)
    {
        if (_adminRoles is null)
        {
            return string.Empty;
        }

        // Ordinal, matching AdminRoleScopePolicy. A case-insensitive hint here would say an account
        // administers when the server says it does not, which is worse than saying nothing.
        var administers = _adminRoles.Contains(role, StringComparer.Ordinal);

        var list = string.Join(", ", _adminRoles.Select(Encode));

        return administers
            ? "<p class=\"field-note administers\">" + _text.Format(AdminText.RoleAdministers, list) + "</p>"
            : "<p class=\"field-note\">" + _text.Format(AdminText.RoleDoesNot, list) + "</p>";
    }

    /// <param name="handle">Whose account the form acts on.</param>
    /// <param name="verb">The endpoint's verb, which is also what the danger styling matches on.</param>
    /// <param name="hidden">The antiforgery field, already rendered.</param>
    /// <param name="label">Already encoded — it comes from <see cref="AdminText"/>.</param>
    /// <param name="caveat">Already encoded, same reason.</param>
    /// <remarks>
    /// <b>No <see cref="AdminMarkup.Encode"/> on those two.</b> They arrive encoded from the text
    /// table, and encoding again is not harmless: the authorization server's renderer carries a
    /// comment about exactly this, where a second pass rendered `Café` as `Caf&amp;#233;`.
    /// Vietnamese is entirely made of characters that would go the same way.
    /// </remarks>
    private static string Op(string handle, string verb, string hidden, string label, string caveat) =>
        $"""
         <form method="post" action="/users/{Encode(Uri.EscapeDataString(handle))}/{Encode(verb)}">
           {hidden}<button type="submit">{label}</button><p>{caveat}</p>
         </form>
         """;
}
