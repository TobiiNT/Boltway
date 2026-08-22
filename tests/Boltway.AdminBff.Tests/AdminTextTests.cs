using System.Net;

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
    /// Vietnamese page with "Change your password" in the middle of it — this working rather than
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
        // entities — valid, and what a browser draws correctly. Asserting the literal appeared in
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
}
