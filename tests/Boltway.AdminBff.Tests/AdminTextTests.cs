using System.Net;
using System.Reflection;

using Boltway.AdminBff;

namespace Boltway.AdminBff.Tests;

/// <summary>
/// The words, and the fallback that makes a partial translation safe.
/// </summary>
/// <remarks>
/// The renderer used to say English only, on the grounds that a second localization mechanism for an
/// internal tool is a cost with no reader. The reader turned up: the deployment this ships to runs
/// every other page in Vietnamese and its operators are the two people who read these.
/// </remarks>
public sealed class AdminTextTests
{
    private static AdminText Vietnamese(params (string Key, string Value)[] pairs) => Render.Text(pairs);

    /// <summary>Configured words replace the English ones.</summary>
    [Fact]
    public void A_translated_key_is_used()
    {
        var html = Render.AccountPage(
            Render.Account(),
            Vietnamese((AdminText.Apply, "Lưu")));

        Assert.Contains("Lưu", WebUtility.HtmlDecode(html), StringComparison.Ordinal);
        Assert.DoesNotContain(">Apply<", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// A key left out is that one sentence in English, not a broken page.
    /// </summary>
    /// <remarks>
    /// The property the whole design rests on. One operator's own notes describe a founder meeting a
    /// Vietnamese page with "Change your password" in the middle of it - this working rather than
    /// failing, and the reason translating three sentences and leaving forty was not an option.
    /// </remarks>
    [Fact]
    public void A_missing_key_falls_back_to_English_alone()
    {
        var html = Render.AccountPage(
            Render.Account(),
            Vietnamese((AdminText.Apply, "Lưu")));

        Assert.Contains("Lưu", WebUtility.HtmlDecode(html), StringComparison.Ordinal);

        // Untranslated, and therefore still English rather than the key or an empty string.
        Assert.Contains("Operations", html, StringComparison.Ordinal);
        Assert.DoesNotContain("SectionOperations", html, StringComparison.Ordinal);
    }

    /// <summary>Told nothing at all, every page is English.</summary>
    [Fact]
    public void No_table_at_all_is_the_English_pages()
    {
        var html = Render.AccountPage(Render.Account());

        Assert.Contains("Operations", html, StringComparison.Ordinal);
        Assert.Contains("Apply", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// Vietnamese survives the round trip exactly once.
    /// </summary>
    /// <remarks>
    /// The table encodes, and anything that encoded again would render `Lưu` as its entities. The
    /// authorization server's renderer carries a comment about the same defect, found there as
    /// `Café` arriving as `Caf&amp;#233;`; Vietnamese is made almost entirely of characters that
    /// would go the same way, so the whole page would break rather than one word.
    /// </remarks>
    [Fact]
    public void Diacritics_are_encoded_exactly_once()
    {
        var html = Render.AccountPage(
            Render.Account(),
            Vietnamese(
                (AdminText.OpAnonymise, "Ẩn danh hoá"),
                (AdminText.OpAnonymiseCaveat, "Không hoàn tác được.")));

        // Decoded once, because HtmlEncode turns part of the Vietnamese range into numeric
        // entities - valid, and what a browser draws correctly. Asserting the literal appeared in
        // the raw HTML would be asserting the encoder did nothing. Surviving exactly one decode is
        // the property that matters, and it is what a second encoding pass would break.
        var once = WebUtility.HtmlDecode(html);

        Assert.Contains("Ẩn danh hoá", once, StringComparison.Ordinal);
        Assert.Contains("Không hoàn tác được.", once, StringComparison.Ordinal);
        Assert.DoesNotContain("&#", once, StringComparison.Ordinal);
    }

    /// <summary>A translation cannot introduce markup.</summary>
    /// <remarks>
    /// The file is supplied by a deployment and edited by hand. Encoding it is what makes it a
    /// source of sentences rather than a source of HTML.
    /// </remarks>
    [Fact]
    public void A_translation_containing_markup_renders_as_text()
    {
        var html = Render.AccountPage(
            Render.Account(),
            Vietnamese((AdminText.Apply, "<script>alert(1)</script>")));

        Assert.DoesNotContain("<script>", html, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
    }

    /// <summary>The role sentence keeps its placeholder through translation.</summary>
    /// <remarks>
    /// <c>{0}</c> is the list of privileged roles, spliced in after the sentence is encoded. A
    /// translation that kept the braces gets the list; the test is that word order is the
    /// translator's and the value is still the server's.
    /// </remarks>
    [Fact]
    public void A_translated_sentence_still_takes_its_value()
    {
        var html = Render.AccountPage(
            Render.Account(),
            Vietnamese((AdminText.RoleDoesNot, "Vai trò này không quản trị được. Chỉ {0} mới được.")),
            ["founder"]);

        var once = WebUtility.HtmlDecode(html);

        Assert.Contains("Vai trò này không quản trị được. Chỉ founder mới được.", once, StringComparison.Ordinal);
        Assert.DoesNotContain("{0}", once, StringComparison.Ordinal);
    }

    /// <summary>Every key the build ships is nameable, so a deployment can check its file.</summary>
    [Fact]
    public void Keys_are_published_for_a_deployment_to_check_against()
    {
        Assert.Contains(AdminText.Apply, AdminText.Keys);
        Assert.Contains(AdminText.SignInAllowedNote, AdminText.Keys);
        Assert.Equal(AdminText.Keys.Count, AdminText.Keys.Distinct(StringComparer.Ordinal).Count());
    }

    /// <summary>
    /// A key with no sentence behind it throws rather than rendering itself.
    /// </summary>
    /// <remarks>
    /// The direction <c>InteractionText.Default</c> in the library already takes, and the two must
    /// not disagree - a reader who learns the rule from one of them applies it to the other. What
    /// this replaces is quieter and worse: the table answered with the key, so
    /// <c>RoleHoldersTruncated</c> could reach an operator as though it were a sentence, with
    /// nothing in any log saying it had. English or a red test beats a page nobody can explain.
    /// </remarks>
    [Fact]
    public void A_key_this_build_does_not_ship_throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => AdminText.Default["RoleHoldersTruncatedd"]);
        Assert.Throws<ArgumentOutOfRangeException>(() => AdminText.Default.Plain("NotAKeyAtAll"));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => AdminText.Default.Format("NotAKeyAtAll", "value"));
    }

    /// <summary>
    /// A key a deployment left out is still English, which is the case that must not throw.
    /// </summary>
    /// <remarks>
    /// The control for the sibling above, and the property the whole table rests on: throwing is for
    /// a key this build never had, never for a key this build has and a translation has not.
    /// </remarks>
    [Fact]
    public void A_key_the_translation_left_out_still_falls_back()
    {
        var partial = Vietnamese((AdminText.Apply, "Lưu"));

        Assert.Equal("Operations", partial[AdminText.SectionOperations]);
        Assert.Equal("Operations", partial.Plain(AdminText.SectionOperations));
    }

    /// <summary>
    /// An entry that is not a sentence at all is not looked up, so it cannot throw.
    /// </summary>
    /// <remarks>
    /// <c>$language</c> is read straight off the table by <c>Language</c> and never goes through the
    /// key path. It is the one legal entry that is deliberately absent from <c>Keys</c>, which is
    /// also why the startup sweep excludes it rather than reporting it.
    /// </remarks>
    [Fact]
    public void The_language_entry_is_not_a_key()
    {
        Assert.DoesNotContain(AdminText.LanguageKey, AdminText.Keys);
        Assert.Equal("vi", Vietnamese((AdminText.LanguageKey, "vi")).Language);
    }

    /// <summary>
    /// Every constant on the class has an English sentence behind it.
    /// </summary>
    /// <remarks>
    /// What makes the throw above safe to ship. A constant added without a row in the table is a key
    /// no page can render and no deployment can translate - it was silently the key on the page
    /// before, and it would be an exception now, so it is worth catching here instead. The same
    /// reason the library keeps two deliberately empty strings in its own table rather than leaving
    /// them out.
    /// </remarks>
    [Fact]
    public void Every_constant_has_an_English_sentence()
    {
        var constants = typeof(AdminText)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(f => f is { IsLiteral: true, IsInitOnly: false } && f.FieldType == typeof(string))
            .Select(f => (string)f.GetValue(null)!)
            .Where(key => key != AdminText.LanguageKey)
            .ToArray();

        // A control on the sweep itself: a reflection filter that matches nothing passes every
        // assertion under it.
        Assert.Contains(AdminText.Apply, constants);

        var mute = constants.Where(key => !AdminText.Keys.Contains(key)).ToArray();

        Assert.True(mute.Length == 0, "constants with no English sentence: " + string.Join(", ", mute));
    }

    /// <summary>
    /// Every notice key is a key, and the two sets are not the same set.
    /// </summary>
    /// <remarks>
    /// <c>NoticeKeys</c> is what the renderer matches <c>?notice=</c> against, so it is the closed
    /// vocabulary a link may choose from. Both halves matter: one that is not in <c>Keys</c> has no
    /// sentence and would throw when a banner asked for it, and one that grew to cover <c>Keys</c>
    /// would put any sentence on these pages at the top of any page.
    /// </remarks>
    [Fact]
    public void Every_notice_key_is_a_key_and_not_every_key_is_a_notice()
    {
        Assert.NotEmpty(AdminText.NoticeKeys);
        Assert.DoesNotContain(AdminText.NewPasswordOnlyTime, AdminText.NoticeKeys);

        var mute = AdminText.NoticeKeys.Where(key => !AdminText.Keys.Contains(key)).ToArray();

        Assert.True(mute.Length == 0, "notice keys with no sentence: " + string.Join(", ", mute));
    }
}
