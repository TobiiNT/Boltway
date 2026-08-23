using System.Net;

namespace Boltway.AdminBff.Tests;

/// <summary>The pages themselves, as opposed to the shell around them.</summary>
public sealed class RendererTests
{
    /// <summary>
    /// An audit timestamp is printed for a person, and still says which zone it is in.
    /// </summary>
    /// <remarks>
    /// The API sends <c>2026-08-13T08:00:31.0367474+00:00</c> and the page printed it verbatim,
    /// which made the widest column on the audit table seven digits of precision nobody uses. The
    /// <c>UTC</c> suffix stays because this app is never told the reader's zone — a local-looking
    /// time that is actually UTC is how an incident gets read an hour wrong.
    /// </remarks>
    [Fact]
    public void An_audit_timestamp_is_readable_and_still_says_utc()
    {
        var html = Render.With().RenderAudit(new AuditViewModel(
            Render.Json(
                """
                [{"at":"2026-08-13T08:00:31.0367474+00:00","actor_kind":"cli","action":"user.create",
                  "target_handle":"ada","outcome":"succeeded","detail":"role=founder"}]
                """),
            Render.Tokens, "ada"));

        Assert.Contains("2026-08-13 08:00:31 UTC", html, StringComparison.Ordinal);
        Assert.DoesNotContain("0367474", html, StringComparison.Ordinal);
        Assert.DoesNotContain("T08:00", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// A timestamp this app cannot parse is still shown.
    /// </summary>
    /// <remarks>
    /// An audit row is evidence. Dropping or blanking one because it did not match a format is the
    /// log losing a record to a presentation rule, which is worse than an ugly cell.
    /// </remarks>
    [Fact]
    public void An_unparseable_timestamp_is_passed_through_rather_than_swallowed()
    {
        var html = Render.With().RenderAudit(new AuditViewModel(
            Render.Json("""[{"at":"not a time","actor_kind":"cli","action":"user.create"}]"""),
            Render.Tokens, "ada"));

        Assert.Contains("not a time", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The formatter is public, so a replacement renderer need not re-derive the same answer.
    /// </summary>
    /// <remarks>
    /// It is the third of the three things a stylesheet could not supply, and the only one that is
    /// per-page rather than per-shell — so it is the piece a renderer written from scratch is most
    /// likely to want unchanged.
    /// </remarks>
    [Fact]
    public void The_timestamp_formatter_is_reachable_on_its_own()
    {
        Assert.Equal(
            "2026-08-13 08:00:31 UTC", DefaultAdminRenderer.Moment("2026-08-13T08:00:31.0367474+00:00"));

        Assert.Equal("not a time", DefaultAdminRenderer.Moment("not a time"));
    }

    /// <summary>
    /// A non-UTC instant is converted rather than relabelled.
    /// </summary>
    /// <remarks>
    /// The suffix is a claim about the number beside it. Printing <c>+07:00</c>'s wall clock with
    /// <c>UTC</c> after it would be the "read an incident an hour wrong" failure with the label
    /// making it worse rather than better.
    /// </remarks>
    [Fact]
    public void A_timestamp_in_another_offset_is_converted_to_utc() =>
        Assert.Equal("2026-08-13 01:00:31 UTC", DefaultAdminRenderer.Moment("2026-08-13T08:00:31+07:00"));

    /// <summary>
    /// The two pages that were declared translatable and were not.
    /// </summary>
    /// <remarks>
    /// <c>RefusedTitle</c> and <c>NewPasswordTitle</c> existed as keys, were translated in the
    /// deployment's file, and reached no page: neither the password page nor the refusal page took an
    /// <see cref="AdminText"/> at all, so both rendered English bodies under English titles on an
    /// otherwise Vietnamese deployment. Two dead keys is what that looked like from the outside; six
    /// missing ones is what it actually was.
    /// </remarks>
    [Fact]
    public void The_password_page_speaks_the_deployments_language()
    {
        var vi = Render.Text(
            (AdminText.LanguageKey, "vi"),
            (AdminText.NewPasswordTitle, "Mật khẩu mới"),
            (AdminText.NewPasswordHeading, "Mật khẩu mới cho {0}"),
            (AdminText.NewPasswordOnlyTime, "Đây là lần duy nhất mật khẩu được hiển thị."),
            (AdminText.BackToAccount, "Quay lại tài khoản"));

        var once = Render.Decoded(
            Render.With(vi).RenderPassword(new PasswordViewModel("ada", "generated-value", Render.Tokens, "ada")));

        Assert.Contains("<html lang=\"vi\">", once, StringComparison.Ordinal);
        Assert.Contains("Mật khẩu mới cho ada", once, StringComparison.Ordinal);
        Assert.Contains("Đây là lần duy nhất", once, StringComparison.Ordinal);
        Assert.Contains("Quay lại tài khoản", once, StringComparison.Ordinal);
        Assert.DoesNotContain("New password for", once, StringComparison.Ordinal);
    }

    /// <summary>The generated password still reaches the page, and reaches it encoded.</summary>
    [Fact]
    public void The_password_itself_is_rendered_and_encoded()
    {
        var html = Render.With().RenderPassword(new PasswordViewModel("ada", "a<b>&c", Render.Tokens, "ada"));

        Assert.Contains("a&lt;b&gt;&amp;c", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<b>", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The refusal page translates its own words and leaves the server's alone.
    /// </summary>
    /// <remarks>
    /// The <c>error_description</c> names the rule that was broken and is the authorization server's
    /// sentence to translate, not this app's — a table here could only cover the refusals that
    /// existed when it was written. So the surround is Vietnamese and the refusal may not be, which
    /// is the per-string fallback doing its job one level up.
    /// </remarks>
    [Fact]
    public void The_refusal_page_translates_its_own_words_only()
    {
        var vi = Render.Text(
            (AdminText.RefusedHeading, "Không thực hiện được"),
            (AdminText.BackToAccounts, "Quay lại danh sách tài khoản"));

        var once = Render.Decoded(Render.With(vi).RenderRefusal(new RefusalViewModel(
            Render.Refusal(
                HttpStatusCode.Forbidden, "forbidden", "`users:write` is not one of this token's scopes"),
            Render.Tokens, "ada")));

        Assert.Contains("Không thực hiện được", once, StringComparison.Ordinal);
        Assert.Contains("Quay lại danh sách tài khoản", once, StringComparison.Ordinal);
        Assert.Contains("`users:write` is not one of this token's scopes", once, StringComparison.Ordinal);
        Assert.DoesNotContain("That did not work", once, StringComparison.Ordinal);
    }

    /// <summary>A refusal with nothing to say falls back to the deployment's sentence.</summary>
    [Fact]
    public void A_refusal_with_no_description_uses_the_translated_fallback()
    {
        var vi = Render.Text((AdminText.RefusedUnexplained, "Máy chủ uỷ quyền đã từ chối yêu cầu này."));

        var once = Render.Decoded(Render.With(vi).RenderRefusal(new RefusalViewModel(
            Render.Refusal(HttpStatusCode.InternalServerError, null, null), Render.Tokens, "ada")));

        Assert.Contains("Máy chủ uỷ quyền đã từ chối", once, StringComparison.Ordinal);

        // No error code from the server, so the status stands in rather than nothing.
        Assert.Contains("500", once, StringComparison.Ordinal);
    }

    /// <summary>
    /// The deployment's file covers every key this build ships.
    /// </summary>
    /// <remarks>
    /// The check that would have caught the two dead keys the moment they were added. It asserts
    /// against <see cref="AdminText.Keys"/>, which is published for exactly this — a deployment
    /// comparing its file to the build.
    /// </remarks>
    [Fact]
    public void Every_key_is_reachable_from_a_page()
    {
        var everything = new AdminText(
            AdminText.Keys.ToDictionary(k => k, k => "[[" + k + "]]", StringComparer.Ordinal));

        var renderer = Render.With(everything, ["founder"]);

        // Both sides of every branch, because a key is only reachable on one of them. An account
        // with no password, one that cannot sign in, a role that does administer and one that does
        // not, a page with a cursor and a refusal with nothing to say — each of those is a sentence
        // that exists and that a one-fixture sweep would report as dead.
        var federatedAndDisabled = Render.Json(
            """
            {"handle":"mai","email":"l@v","email_verified":false,"role":"contractor",
             "subject":"01K","realm":"northwind","has_password":false,"disabled_at":"2026-08-13T00:00:00+00:00"}
            """);

        var rendered = string.Concat(
            renderer.RenderAccounts(new AccountsViewModel(
                Render.Json(
                    """
                    {"users":[{"handle":"ada","role":"founder","email_verified":true},
                              {"handle":"mai","role":"contractor","disabled_at":"2026-08-13T00:00:00+00:00"}],
                     "next":"01K"}
                    """),
                Render.Tokens, AdminText.NoticeApplied, "ada")),
            renderer.RenderAccount(new AccountViewModel(Render.Account("founder"), Render.Tokens, null, "ada")),
            renderer.RenderAccount(new AccountViewModel(federatedAndDisabled, Render.Tokens, null, "ada")),

            // Both service-account states, because they are two disjoint halves of the section and a
            // sweep over one of them reports the other's sentences as dead. The secret is rendered
            // here too — it has its own warning, and that warning is only ever on screen at the same
            // moment as a live credential.
            renderer.RenderAccount(new AccountViewModel(
                Render.Account("founder"), Render.Tokens, null, "ada")
            {
                ServiceAccount = Render.Json("null"),
            }),

            // The same half again with a scope list, because the two ways of asking for scopes are
            // disjoint branches with a caption each: the list has its own label and its own "tick
            // at least one", and the box above keeps the one that names the separator. A sweep over
            // either alone reports the other's sentences as dead.
            renderer.RenderAccount(new AccountViewModel(
                Render.Account("founder"), Render.Tokens, null, "ada")
            {
                ServiceAccount = Render.Json("null"),
                ScopesSupported = ["docs:read", "docs:write"],
            }),
            renderer.RenderAccount(new AccountViewModel(
                Render.Account("founder"), Render.Tokens, null, "ada")
            {
                ServiceAccount = Render.Json(
                    """{"client_id":"svc-grace","scopes":["docs:read"],"enabled":true}"""),
                NewSecret = "ck_cs_shown_once",
            }),
            renderer.RenderNewAccount(new NewAccountViewModel(Render.Tokens, null, "ada")),

            // Both halves again: a realm with roles carries every sentence about one, and a realm
            // with none carries the sentence that says so — which no fixture holding a role reaches.
            // Accounts and the truncation flag are on the populated call because the holder
            // sentences — held-by, nobody, and the truncated caveat — live only there.
            renderer.RenderRoles(new RolesViewModel(
                Render.Json(
                    """
                    {"roles":[{"id":"founder","name":"Founder","permissions":["docs:write","reports:read"]},
                              {"id":"member","name":"Member","permissions":[]}]}
                    """),
                Render.Tokens, AdminText.NoticeApplied, "ada")
            {
                Accounts = Render.Json("""[{"handle":"ada","role":["founder"]}]"""),
                HoldersTruncated = true,
            }),
            renderer.RenderRoles(new RolesViewModel(
                Render.Json("""{"roles":[]}"""), Render.Tokens, null, "ada")),

            // Once more through a renderer that was given a vocabulary, because the picker's label,
            // its extras box and its note render on no other path.
            Render.With(everything, ["founder"], ["docs_read"]).RenderRoles(new RolesViewModel(
                Render.Json("""{"roles":[{"id":"member","name":"Member","permissions":[]}]}"""),
                Render.Tokens, null, "ada")),
            renderer.RenderAudit(new AuditViewModel(
                Render.Json("""[{"at":"2026-08-13T08:00:00+00:00"}]"""), Render.Tokens, "ada")),
            renderer.RenderPassword(new PasswordViewModel("ada", "generated-value", Render.Tokens, "ada")),
            renderer.RenderRefusal(new RefusalViewModel(
                Render.Refusal(HttpStatusCode.Forbidden, "forbidden", "nope"), Render.Tokens,
                "ada")),
            renderer.RenderRefusal(new RefusalViewModel(
                Render.Refusal(HttpStatusCode.InternalServerError, null, null), Render.Tokens, "ada")),

            // Every notice, driven off the set the renderer matches against rather than a list
            // written out here — a notice added to that set and to no endpoint is still a sentence
            // this build ships, and it should be swept like the rest. Each gets a value, because two
            // of them are a sentence with a hole in it and render nothing without one.
            string.Concat(AdminText.NoticeKeys.Select(key => renderer.RenderAccounts(
                new AccountsViewModel(Render.Json("""{"users":[]}"""), Render.Tokens, key, "ada")
                {
                    NoticeValue = "1",
                }))));

        var missing = AdminText.Keys
            .Where(k => !rendered.Contains("[[" + k + "]]", StringComparison.Ordinal))
            .ToArray();

        Assert.True(missing.Length == 0, "unreachable keys: " + string.Join(", ", missing));
    }

    /// <summary>Roles arrive as an array, and every one of them is shown.</summary>
    /// <remarks>
    /// <para>
    /// <b>This is the shape the API actually returns, and no fixture in this file used it.</b>
    /// <c>AdminUserView</c> serialises roles under the key <c>role</c>, and the value became an
    /// array when an account started holding several. Every test here passed a string, so the whole
    /// suite agreed with itself and disagreed with the server.
    /// </para>
    /// <para>
    /// What that cost: <c>Text</c> answers empty for a non-string, so roles rendered blank, the
    /// admin badge matched nobody, and the account form's role box came up empty. The form posts
    /// every field it shows, so saving an unrelated change sent "clear the roles" — losing the
    /// account's permissions in the direction that raises no error and shows an almost-empty
    /// knowledge base at the next sign-in.
    /// </para>
    /// </remarks>
    [Fact]
    public void An_account_holding_several_roles_shows_all_of_them()
    {
        var account = Render.Json(
            """
            {"handle":"grace","email":"grace@example.com","email_verified":true,
             "role":["founder","editor"],
             "subject":"01JBK7Q2VN8XW4M0ZC3RTA9HDE","realm":"northwind","has_password":true}
            """);

        var page = Render.AccountPage(account, adminRoles: ["founder"]);

        Assert.Contains("founder editor", page, StringComparison.Ordinal);
    }

    /// <summary>The admin badge matches any held role, not the whole joined string.</summary>
    [Fact]
    public void An_admin_role_among_several_is_still_recognised()
    {
        var users = Render.Json(
            """{"users":[{"handle":"ada","role":["employee","founder"],"email_verified":true}]}""");

        var page = Render.With(null, ["founder"]).RenderAccounts(
            new AccountsViewModel(users, Render.Tokens, null, "ada"));

        Assert.Contains("admin-badge", page, StringComparison.Ordinal);
    }

    /// <summary>The field posts as `roles`, so the server takes the list rather than a scalar.</summary>
    /// <remarks>
    /// The name is the whole fix on the wire. Posting `role` with an empty box is what sent "-",
    /// which the admin API maps to null and applies as "this account holds nothing".
    /// </remarks>
    [Fact]
    public void The_role_field_posts_as_a_list()
    {
        var page = Render.AccountPage(Render.Account());

        Assert.Contains("name=\"roles\"", page, StringComparison.Ordinal);
        Assert.DoesNotContain("name=\"role\"", page, StringComparison.Ordinal);
    }

    /// <summary>An authorization server that has never heard of service accounts renders no section.</summary>
    /// <remarks>
    /// The BFF and the authorization server are separate images, so during any rollout one is older
    /// than the other. The older one answers 404 for the endpoint, the BFF leaves the property
    /// unset, and the account page has to be the page it was — a section rendered as an error would
    /// make an upgrade look like a fault, on the page an operator reaches for when something is
    /// already wrong.
    /// </remarks>
    [Fact]
    public void An_account_page_without_a_service_account_answer_shows_no_section()
    {
        var page = Render.AccountPage(Render.Account());

        Assert.DoesNotContain("Service account", page, StringComparison.Ordinal);
    }

    /// <summary>The secret is shown with its warning, and only when there is one.</summary>
    [Fact]
    public void A_new_secret_is_shown_once_and_says_so()
    {
        var withSecret = Render.With(null, null).RenderAccount(
            new AccountViewModel(Render.Account(), Render.Tokens, null, "ada")
            {
                ServiceAccount = Render.Json(
                    """{"client_id":"svc-grace","scopes":["docs:read"],"enabled":true}"""),
                NewSecret = "ck_cs_shown_once",
            });

        Assert.Contains("ck_cs_shown_once", withSecret, StringComparison.Ordinal);
        Assert.Contains("not stored", withSecret, StringComparison.Ordinal);

        // And the same page without one carries neither the value nor the warning: a standing
        // "copy this now" beside no secret teaches people to ignore it.
        var without = Render.With(null, null).RenderAccount(
            new AccountViewModel(Render.Account(), Render.Tokens, null, "ada")
            {
                ServiceAccount = Render.Json(
                    """{"client_id":"svc-grace","scopes":["docs:read"],"enabled":true}"""),
            });

        Assert.DoesNotContain("ck_cs_shown_once", without, StringComparison.Ordinal);
        Assert.DoesNotContain("not stored", without, StringComparison.Ordinal);
    }

    /// <summary>The scopes the server publishes are offered as checkboxes, not typed.</summary>
    /// <remarks>
    /// Every checkbox is <c>name="scopes"</c>, which is what makes the form post the field once per
    /// tick — and is the half the handler had to be taught to read.
    /// </remarks>
    [Fact]
    public void Published_scopes_are_offered_rather_than_typed()
    {
        var page = Render.With(null, null).RenderAccount(
            new AccountViewModel(Render.Account(), Render.Tokens, null, "ada")
            {
                ServiceAccount = Render.Json("null"),
                ScopesSupported = ["docs:read", "docs:write", "openid"],
            });

        foreach (var scope in new[] { "docs:read", "docs:write", "openid" })
        {
            Assert.Contains(
                $"<input type=\"checkbox\" name=\"scopes\" value=\"{scope}\">",
                page,
                StringComparison.Ordinal);
        }

        // And the box is gone, rather than sitting beside the list as a second way to say the same
        // thing — two controls posting one field is a form whose result depends on which one an
        // operator believed.
        Assert.DoesNotContain("<input id=\"scopes\"", page, StringComparison.Ordinal);
    }

    /// <summary>
    /// Nothing is ticked to begin with, and the page says an empty set is refused.
    /// </summary>
    /// <remarks>
    /// A pre-ticked scope is a permission granted by a default rather than by a decision, on a form
    /// whose entire subject is how much reach a credential gets.
    /// </remarks>
    [Fact]
    public void No_scope_is_ticked_by_default()
    {
        var page = Render.With(null, null).RenderAccount(
            new AccountViewModel(Render.Account(), Render.Tokens, null, "ada")
            {
                ServiceAccount = Render.Json("null"),
                ScopesSupported = ["docs:read", "docs:write"],
            });

        // Within the fieldset rather than the page: this account's address is verified and its
        // sign-in is allowed, so both of those boxes are `checked` and a sweep over the whole
        // document would pass on any markup at all.
        var start = page.IndexOf("<fieldset class=\"scopes\"", StringComparison.Ordinal);
        var end = page.IndexOf("</fieldset>", start, StringComparison.Ordinal);

        Assert.True(start >= 0 && end > start, "the scopes fieldset is not on the page");

        Assert.DoesNotContain("checked", page[start..end], StringComparison.Ordinal);
        Assert.Contains("tick at least one", page, StringComparison.Ordinal);
    }

    /// <summary>
    /// A server this app could not read falls back to the box, rather than to an empty list.
    /// </summary>
    /// <remarks>
    /// Both the unknown and the empty case, because they arrive differently and mean the same
    /// thing. Rendering zero checkboxes would state that the server issues no scopes at all, which
    /// is a claim neither a discovery failure nor an absent <c>scopes_supported</c> supports — and
    /// it would leave an operator with a form that cannot be completed.
    /// </remarks>
    [Fact]
    public void A_scope_list_that_could_not_be_read_falls_back_to_the_box() => AssertBox(null);

    /// <inheritdoc cref="A_scope_list_that_could_not_be_read_falls_back_to_the_box"/>
    [Fact]
    public void An_empty_scope_list_falls_back_to_the_box() => AssertBox([]);

    private static void AssertBox(IReadOnlyList<string>? supported)
    {
        var page = Render.With(null, null).RenderAccount(
            new AccountViewModel(Render.Account(), Render.Tokens, null, "ada")
            {
                ServiceAccount = Render.Json("null"),
                ScopesSupported = supported,
            });

        Assert.Contains("<input id=\"scopes\" name=\"scopes\"", page, StringComparison.Ordinal);
        Assert.Contains("space separated", page, StringComparison.Ordinal);
        Assert.DoesNotContain("type=\"checkbox\" name=\"scopes\"", page, StringComparison.Ordinal);
    }

    /// <summary>A role page offers no way to change an id.</summary>
    /// <remarks>
    /// The property this page is most likely to lose, because an editable id is the obvious shape
    /// and the API quietly does not have one. An id reaches every token the realm has issued and
    /// both halves of <c>ADMIN_ROLES</c>; a box here would be a control whose value is discarded, or
    /// worse, a second role nobody meant to define.
    /// </remarks>
    [Fact]
    public void The_role_id_has_no_input()
    {
        var page = Render.With(null, null).RenderRoles(new RolesViewModel(
            Render.Json("""{"roles":[{"id":"founder","name":"Founder","permissions":["docs:write"]}]}"""),
            Render.Tokens, null, "ada"));

        Assert.Contains("<code>founder</code>", page, StringComparison.Ordinal);
        Assert.Contains("name=\"name\"", page, StringComparison.Ordinal);
        Assert.Contains("name=\"permissions\"", page, StringComparison.Ordinal);

        // The create form has one, and it is the only one. `name="id"` appearing twice would mean
        // the edit form grew a box.
        var ids = page.Split("name=\"id\"", StringSplitOptions.None).Length - 1;

        Assert.Equal(1, ids);
        Assert.Contains("cannot be changed", page, StringComparison.Ordinal);
    }

    /// <summary>
    /// A role id is rendered as a literal, in the case it was given.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Found by looking at the page rather than by reasoning about it. The deployment's stylesheet
    /// makes <c>h2</c> a small uppercase section label, so <c>&lt;h2&gt;founder&lt;/h2&gt;</c> put
    /// <c>FOUNDER</c> on screen for a role whose id is <c>founder</c> — an ordinally matched string
    /// shown in a case that would not match it, on the one page where an operator reads an id to
    /// copy it.
    /// </para>
    /// <para>
    /// The fix is a stylesheet rule on <c>code</c>, so what this pins is the half that lives here:
    /// the id is marked as a literal. A renderer that stops doing that takes the rule with it.
    /// </para>
    /// </remarks>
    [Fact]
    public void A_role_id_is_marked_as_a_literal()
    {
        var page = Render.With(null, null).RenderRoles(new RolesViewModel(
            Render.Json("""{"roles":[{"id":"founder","name":"Founder","permissions":[]}]}"""),
            Render.Tokens, null, "ada"));

        Assert.Contains("<code>founder</code>", page, StringComparison.Ordinal);
        Assert.DoesNotContain("<code>FOUNDER</code>", page, StringComparison.Ordinal);
    }

    /// <summary>
    /// The page says the id is fixed once, not once per role.
    /// </summary>
    /// <remarks>
    /// A rule about the page rather than about any one role. Repeating it under each of three roles
    /// produced the same paragraph three times, which is how a caveat stops being read — and the
    /// caveats on this page are the ones that matter.
    /// </remarks>
    [Fact]
    public void The_page_level_notes_are_said_once()
    {
        var page = Render.With(null, null).RenderRoles(new RolesViewModel(
            Render.Json(
                """
                {"roles":[{"id":"founder","name":"Founder","permissions":[]},
                          {"id":"member","name":"Member","permissions":[]},
                          {"id":"monitor","name":"Monitor","permissions":[]}]}
                """),
            Render.Tokens, null, "ada"));

        Assert.Equal(1, page.Split("cannot be changed", StringSplitOptions.None).Length - 1);
        Assert.Equal(1, page.Split("cannot offer a list", StringSplitOptions.None).Length - 1);

        // The delete caveat is the opposite case and stays per role: it is about the button beside
        // it, and a destructive control with its consequence somewhere else up the page is one.
        Assert.Equal(3, page.Split("Every account holding this role", StringSplitOptions.None).Length - 1);
    }

    /// <summary>Deleting a role says what it does to the accounts holding it.</summary>
    /// <remarks>
    /// Both clauses, because the store removes the assignments along with the definition and an
    /// account left holding none does not keep what it had. A delete button whose caveat says only
    /// "this cannot be undone" would be true and useless.
    /// </remarks>
    [Fact]
    public void Deleting_a_role_says_what_happens_to_the_accounts_holding_it()
    {
        var page = Render.With(null, null).RenderRoles(new RolesViewModel(
            Render.Json("""{"roles":[{"id":"editor","name":"Editor","permissions":[]}]}"""),
            Render.Tokens, null, "ada"));

        Assert.Contains("/roles/editor/delete", page, StringComparison.Ordinal);
        Assert.Contains("Every account holding this role loses it", page, StringComparison.Ordinal);
        Assert.Contains("keeps nothing it had", page, StringComparison.Ordinal);
    }

    /// <summary>
    /// The role that administers the directory is marked, on the page with the delete button.
    /// </summary>
    /// <remarks>
    /// Deleting it is how a deployment locks itself out of its own admin UI — every holder loses
    /// <c>users:write</c> at once, including whoever pressed the button, and the page that could
    /// grant it back is the one they can no longer open.
    /// </remarks>
    [Fact]
    public void An_administering_role_is_marked_where_it_can_be_deleted()
    {
        var page = Render.With(null, ["founder"]).RenderRoles(new RolesViewModel(
            Render.Json(
                """
                {"roles":[{"id":"founder","name":"Founder","permissions":[]},
                          {"id":"member","name":"Member","permissions":[]}]}
                """),
            Render.Tokens, null, "ada"));

        var founder = page.IndexOf("<code>founder</code>", StringComparison.Ordinal);
        var member = page.IndexOf("<code>member</code>", StringComparison.Ordinal);
        var warning = page.IndexOf("administers the directory", StringComparison.Ordinal);

        Assert.True(warning > founder && warning < member, "the warning is not against founder");

        // Ordinal, matching AdminRoleScopePolicy. A near-miss must not be marked as privileged.
        var nearMiss = Render.With(null, ["Founder"]).RenderRoles(new RolesViewModel(
            Render.Json("""{"roles":[{"id":"founder","name":"Founder","permissions":[]}]}"""),
            Render.Tokens, null, "ada"));

        Assert.DoesNotContain("administers the directory", nearMiss, StringComparison.Ordinal);
    }

    /// <summary>
    /// A role's row says what it is and what it stands for without being opened.
    /// </summary>
    /// <remarks>
    /// The whole reason the rows collapse: an operator opens this page to compare permissions
    /// across roles, and a list that hides them behind three clicks has made the comparison
    /// harder than the page it replaced.
    /// </remarks>
    [Fact]
    public void A_collapsed_role_still_shows_its_permissions()
    {
        var page = Render.With(null, null).RenderRoles(new RolesViewModel(
            Render.Json("""{"roles":[{"id":"editor","name":"Editor","permissions":["docs:read","docs:write"]}]}"""),
            Render.Tokens, null, "ada"));

        var summary = page[page.IndexOf("<summary>", StringComparison.Ordinal)
            ..page.IndexOf("</summary>", StringComparison.Ordinal)];

        Assert.Contains("<code>editor</code>", summary, StringComparison.Ordinal);
        Assert.Contains("Editor", summary, StringComparison.Ordinal);
        Assert.Contains("<code>docs:read</code>", summary, StringComparison.Ordinal);
        Assert.Contains("<code>docs:write</code>", summary, StringComparison.Ordinal);

        // Closed, so the page opens on the list rather than on three forms.
        Assert.DoesNotContain("<details class=\"role\" open>", page, StringComparison.Ordinal);
    }

    /// <summary>
    /// The administers mark is on the row, not only inside it.
    /// </summary>
    /// <remarks>
    /// A warning behind a disclosure triangle is a warning nobody reads. The row carries the
    /// accounts list's own badge — one term for one concept — and the sentence it stands for is
    /// still in the body, beside the button it is about.
    /// </remarks>
    [Fact]
    public void The_administers_mark_survives_being_collapsed()
    {
        var page = Render.With(null, ["founder"]).RenderRoles(new RolesViewModel(
            Render.Json("""{"roles":[{"id":"founder","name":"Founder","permissions":[]}]}"""),
            Render.Tokens, null, "ada"));

        var summary = page[page.IndexOf("<summary>", StringComparison.Ordinal)
            ..page.IndexOf("</summary>", StringComparison.Ordinal)];

        Assert.Contains("admin-badge", summary, StringComparison.Ordinal);

        // And the full sentence is still there, further down, where the delete button is.
        Assert.Contains("administers the directory", page, StringComparison.Ordinal);
    }

    /// <summary>
    /// The create form opens itself when there is nothing to list.
    /// </summary>
    /// <remarks>
    /// A realm with roles opens on the list it came to read; a realm with none opens on the only
    /// thing it can do. A collapsed form beside "this directory defines no roles yet" is a page
    /// whose one useful control is hidden.
    /// </remarks>
    [Fact]
    public void The_create_form_is_open_only_when_there_is_nothing_else()
    {
        var empty = Render.With(null, null).RenderRoles(new RolesViewModel(
            Render.Json("""{"roles":[]}"""), Render.Tokens, null, "ada"));

        Assert.Contains("<details class=\"role new\" open>", empty, StringComparison.Ordinal);

        var populated = Render.With(null, null).RenderRoles(new RolesViewModel(
            Render.Json("""{"roles":[{"id":"founder","name":"Founder","permissions":[]}]}"""),
            Render.Tokens, null, "ada"));

        Assert.Contains("<details class=\"role new\">", populated, StringComparison.Ordinal);
    }

    /// <summary>
    /// Each role says who holds it — grouped with the same read the accounts list uses.
    /// </summary>
    [Fact]
    public void A_role_names_its_holders()
    {
        var page = Render.With(null, null).RenderRoles(new RolesViewModel(
            Render.Json(
                """
                {"roles":[{"id":"founder","name":"Founder","permissions":[]},
                          {"id":"employee","name":"Employee","permissions":[]}]}
                """),
            Render.Tokens, null, "ada")
        {
            // grace holds both roles, so they must appear under both — the union rule, on the
            // page that shows it.
            Accounts = Render.Json(
                """
                [{"handle":"ada","role":["founder"]},
                 {"handle":"grace","role":["founder","employee"]},
                 {"handle":"mai","role":[]}]
                """),
        });

        var founder = page[page.IndexOf("<code>founder</code>", StringComparison.Ordinal)
            ..page.IndexOf("<code>employee</code>", StringComparison.Ordinal)];
        var employee = page[page.IndexOf("<code>employee</code>", StringComparison.Ordinal)..];

        Assert.Contains("held by 2", founder, StringComparison.Ordinal);
        Assert.Contains("<a href=\"/users/ada\">ada</a>", founder, StringComparison.Ordinal);
        Assert.Contains("<a href=\"/users/grace\">grace</a>", founder, StringComparison.Ordinal);

        Assert.Contains("held by 1", employee, StringComparison.Ordinal);
        Assert.Contains("grace", employee, StringComparison.Ordinal);
        Assert.DoesNotContain(">ada</a>", employee, StringComparison.Ordinal);
    }

    /// <summary>
    /// A role nobody holds says so in a sentence, and shows no count.
    /// </summary>
    /// <remarks>
    /// The sentence sits in the body, next to the delete button — which is where "is this safe to
    /// remove" is being decided.
    /// </remarks>
    [Fact]
    public void A_role_with_no_holders_says_so_and_counts_nothing()
    {
        var page = Render.With(null, null).RenderRoles(new RolesViewModel(
            Render.Json("""{"roles":[{"id":"monitor","name":"Monitor","permissions":[]}]}"""),
            Render.Tokens, null, "ada")
        {
            Accounts = Render.Json("""[{"handle":"ada","role":["founder"]}]"""),
        });

        Assert.Contains("No account holds this role.", page, StringComparison.Ordinal);
        Assert.DoesNotContain("held by", page, StringComparison.Ordinal);
    }

    /// <summary>
    /// When the accounts could not be fetched, the page says nothing about holders.
    /// </summary>
    /// <remarks>
    /// Silence, not "nobody": "no account holds this role" computed from accounts that never
    /// loaded is a licence to delete a held role.
    /// </remarks>
    [Fact]
    public void Unknown_accounts_are_silence_not_nobody()
    {
        var page = Render.With(null, null).RenderRoles(new RolesViewModel(
            Render.Json("""{"roles":[{"id":"founder","name":"Founder","permissions":[]}]}"""),
            Render.Tokens, null, "ada"));

        Assert.DoesNotContain("No account holds this role.", page, StringComparison.Ordinal);
        Assert.DoesNotContain("held by", page, StringComparison.Ordinal);
    }

    /// <summary>A truncated walk says so, once, at page level.</summary>
    [Fact]
    public void A_truncated_walk_is_announced()
    {
        var page = Render.With(null, null).RenderRoles(new RolesViewModel(
            Render.Json("""{"roles":[{"id":"founder","name":"Founder","permissions":[]}]}"""),
            Render.Tokens, null, "ada")
        {
            Accounts = Render.Json("""[]"""),
            HoldersTruncated = true,
        });

        Assert.Contains("does not mean nobody", page, StringComparison.Ordinal);
    }

    /// <summary>
    /// With a vocabulary configured, permissions are ticked — and what the list does not name
    /// renders as a ticked checkbox too.
    /// </summary>
    /// <remarks>
    /// The union is the part that must never regress. If the checkboxes rendered only the
    /// vocabulary, a held permission outside it would be stripped by the next unrelated save —
    /// the roles-cleared-on-save defect with a different field name. It used to ride in a
    /// free-text box beside the list; the ticked box is the same guarantee with one control,
    /// which is also why no text input renders in this mode at all.
    /// </remarks>
    [Fact]
    public void A_configured_vocabulary_becomes_checkboxes_and_extras_survive()
    {
        var page = Render.With(null, null, ["docs_read", "docs_write"]).RenderRoles(new RolesViewModel(
            Render.Json(
                """{"roles":[{"id":"editor","name":"Editor","permissions":["docs_read","legacy_x"]}]}"""),
            Render.Tokens, null, "ada"));

        Assert.Contains(
            "<input type=\"checkbox\" name=\"permissions\" value=\"docs_read\" checked>",
            page, StringComparison.Ordinal);
        Assert.Contains(
            "<input type=\"checkbox\" name=\"permissions\" value=\"docs_write\">",
            page, StringComparison.Ordinal);

        // legacy_x is not in the vocabulary, so it is offered as a ticked box — not silently gone.
        Assert.Contains(
            "<input type=\"checkbox\" name=\"permissions\" value=\"legacy_x\" checked>",
            page, StringComparison.Ordinal);

        // One control type: the free-text permissions input does not render beside a vocabulary.
        Assert.DoesNotContain("<input id=\"permissions-", page, StringComparison.Ordinal);

        // And the note switched: "cannot offer a list" is a lie beside a list. Matched on the
        // env name rather than the prose, because the prose holds an apostrophe and the text
        // table HTML-encodes it.
        Assert.Contains("ADMIN_PERMISSIONS", page, StringComparison.Ordinal);
        Assert.DoesNotContain("cannot offer a list", page, StringComparison.Ordinal);
    }

    /// <summary>Without a vocabulary, the field is the box it always was.</summary>
    [Fact]
    public void No_vocabulary_keeps_the_box()
    {
        var page = Render.With(null, null).RenderRoles(new RolesViewModel(
            Render.Json("""{"roles":[{"id":"editor","name":"Editor","permissions":["docs_read"]}]}"""),
            Render.Tokens, null, "ada"));

        Assert.Contains("name=\"permissions\" value=\"docs_read\">", page, StringComparison.Ordinal);
        Assert.DoesNotContain("type=\"checkbox\" name=\"permissions\"", page, StringComparison.Ordinal);
        Assert.Contains("cannot offer a list", page, StringComparison.Ordinal);
    }

    /// <summary>A realm with no roles says so rather than showing an empty page.</summary>
    [Fact]
    public void No_roles_is_a_sentence()
    {
        var page = Render.With(null, null).RenderRoles(new RolesViewModel(
            Render.Json("""{"roles":[]}"""), Render.Tokens, null, "ada"));

        Assert.Contains("defines no roles yet", page, StringComparison.Ordinal);

        // And the form to fix that is still there, which is the point of saying it.
        Assert.Contains("action=\"/roles\"", page, StringComparison.Ordinal);
    }

    /// <summary>A scope carrying markup is encoded, in the value and in the text.</summary>
    /// <remarks>
    /// It reaches this page from another system's configuration, so it is not this app's to assume
    /// well-formed. The value lands inside an attribute and the text inside an element, which are
    /// two escapes rather than one.
    /// </remarks>
    [Fact]
    public void A_scope_is_encoded_wherever_it_lands()
    {
        var page = Render.With(null, null).RenderAccount(
            new AccountViewModel(Render.Account(), Render.Tokens, null, "ada")
            {
                ServiceAccount = Render.Json("null"),
                ScopesSupported = ["\"><script>alert(1)</script>"],
            });

        Assert.DoesNotContain("<script>", page, StringComparison.Ordinal);
    }

    // ── the banner a write lands on ─────────────────────────────────────────
    //
    // `?notice=` used to be the finished sentence: an endpoint composed it, the query string carried
    // it and the page printed it. That cost two things at once. Every write in a fully translated
    // console produced one English line, because a sentence written in Program.cs is the one string
    // on these pages an ADMIN_TEXT_FILE cannot reach. And the banner was whatever a link said it
    // was — encoded, so never an injection, and still this app's own voice saying somebody else's
    // words. It is a key now, matched against a closed set.

    /// <summary>A key becomes the sentence it names.</summary>
    [Fact]
    public void A_notice_key_is_rendered_as_its_sentence()
    {
        var html = Render.With().RenderAccounts(new AccountsViewModel(
            Render.Json("""{"users":[]}"""), Render.Tokens, AdminText.NoticeApplied, "ada"));

        Assert.Contains("Applied.", html, StringComparison.Ordinal);

        // The key is what travelled, and it is not what a person reads.
        Assert.DoesNotContain("NoticeApplied", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// And in the deployment's words, which is the whole reason it is a key.
    /// </summary>
    /// <remarks>
    /// The symptom this closes: a console translated end to end, and then a Vietnamese account page
    /// answering every save with "Applied." — which is the case AdminText's own remarks describe the
    /// table as existing to prevent, arriving through the one channel that had been left out of it.
    /// </remarks>
    [Fact]
    public void A_notice_is_said_in_the_deployment_s_words()
    {
        var vi = Render.Text((AdminText.NoticeApplied, "Đã lưu."));

        var once = Render.Decoded(Render.With(vi).RenderAccounts(new AccountsViewModel(
            Render.Json("""{"users":[]}"""), Render.Tokens, AdminText.NoticeApplied, "ada")));

        Assert.Contains("Đã lưu.", once, StringComparison.Ordinal);
        Assert.DoesNotContain("Applied.", once, StringComparison.Ordinal);
    }

    /// <summary>The roles page says its own three the same way.</summary>
    /// <remarks>
    /// A control on the sibling above rather than a repeat of it: the roles page is a second call
    /// site, and a helper wired into one page and not the other is the ordinary way this rots.
    /// </remarks>
    [Fact]
    public void A_roles_notice_is_rendered_too()
    {
        var html = Render.With().RenderRoles(new RolesViewModel(
            Render.Json("""{"roles":[]}"""), Render.Tokens, AdminText.NoticeDefined, "ada"));

        Assert.Contains("Defined.", html, StringComparison.Ordinal);
        Assert.DoesNotContain("NoticeDefined", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// Anything that is not a notice key renders no banner at all.
    /// </summary>
    /// <remarks>
    /// The property the rest of it rests on. A link is the only thing that puts a value in this
    /// parameter, so echoing an unrecognised one back hands anybody a sentence in this app's own
    /// voice, on the page an operator trusts most. Encoding it was never the answer to that — it
    /// stops the markup and keeps the sentence.
    /// </remarks>
    [Fact]
    public void An_unrecognised_notice_is_not_echoed()
    {
        var html = Render.With().RenderAccounts(new AccountsViewModel(
            Render.Json("""{"users":[]}"""), Render.Tokens,
            "Your session expired. Sign in again at admin.example.test.", "ada"));

        Assert.DoesNotContain("Sign in again", html, StringComparison.Ordinal);
        Assert.DoesNotContain("admin.example.test", html, StringComparison.Ordinal);
        Assert.DoesNotContain("class=\"notice\"", html, StringComparison.Ordinal);
    }

    /// <summary>Markup in that parameter is gone rather than escaped into the page.</summary>
    [Fact]
    public void A_notice_carrying_markup_renders_nothing()
    {
        var html = Render.With().RenderAccounts(new AccountsViewModel(
            Render.Json("""{"users":[]}"""), Render.Tokens, "<img src=x onerror=alert(1)>", "ada"));

        Assert.DoesNotContain("onerror", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// A sentence that belongs to a page is not a notice, even though it is a key.
    /// </summary>
    /// <remarks>
    /// Why the check is <c>AdminText.NoticeKeys</c> and not <c>AdminText.Keys</c>, which is the
    /// obvious one and is too generous by every sentence on these pages. With it, a link could hoist
    /// "this is the only time it is shown" over an account page with no credential on it — a warning
    /// about something that did not happen, in the console's own voice.
    /// </remarks>
    [Fact]
    public void A_page_sentence_is_not_a_notice()
    {
        var html = Render.With().RenderAccounts(new AccountsViewModel(
            Render.Json("""{"users":[]}"""), Render.Tokens, AdminText.NewPasswordOnlyTime, "ada"));

        Assert.DoesNotContain("only time it is shown", html, StringComparison.Ordinal);
        Assert.DoesNotContain("NewPasswordOnlyTime", html, StringComparison.Ordinal);
    }

    /// <summary>The two notices with a hole in them take the value beside the key.</summary>
    [Fact]
    public void A_notice_takes_its_value()
    {
        var html = Render.With().RenderAccount(new AccountViewModel(
            Render.Account(), Render.Tokens, AdminText.NoticeSessionsRevoked, "ada")
        {
            NoticeValue = "3",
        });

        Assert.Contains("3 grant(s) revoked.", html, StringComparison.Ordinal);

        // The clause an operator working an incident needs, which is why it is in the table rather
        // than composed at the endpoint: a translation that drops it is a translation to argue with.
        Assert.Contains("keep working until they expire", html, StringComparison.Ordinal);
    }

    /// <summary>That value is a string somebody else wrote, and it is escaped like one.</summary>
    [Fact]
    public void A_notice_value_is_encoded()
    {
        var html = Render.With().RenderAccounts(new AccountsViewModel(
            Render.Json("""{"users":[]}"""), Render.Tokens, AdminText.NoticeAnonymised, "ada")
        {
            NoticeValue = "<b>ada</b>",
        });

        Assert.Contains("&lt;b&gt;ada&lt;/b&gt;", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<b>ada</b>", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// A notice whose value did not arrive renders nothing, not a sentence with a hole in it.
    /// </summary>
    /// <remarks>
    /// Half a URL, typed or truncated. "{0} is anonymised" on the account list is worse than no
    /// banner: it says an account was anonymised and declines to say which.
    /// </remarks>
    [Fact]
    public void A_notice_missing_its_value_renders_nothing()
    {
        var html = Render.With().RenderAccounts(new AccountsViewModel(
            Render.Json("""{"users":[]}"""), Render.Tokens, AdminText.NoticeAnonymised, "ada"));

        Assert.DoesNotContain("is anonymised", html, StringComparison.Ordinal);
        Assert.DoesNotContain("{0}", html, StringComparison.Ordinal);
        Assert.DoesNotContain("class=\"notice\"", html, StringComparison.Ordinal);
    }
}
