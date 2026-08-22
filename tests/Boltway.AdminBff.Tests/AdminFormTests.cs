using Microsoft.Extensions.Primitives;

namespace Boltway.AdminBff.Tests;

/// <summary>
/// Reading the fields the service-account form posts.
/// </summary>
/// <remarks>
/// The form is drawn two ways depending on what the authorization server publishes, and a handler
/// that reads only one of them is a button that refuses for a reason the operator cannot see. Both
/// shapes are asserted here because only one of them exists on any given deployment.
/// </remarks>
public sealed class AdminFormTests
{
    /// <summary>A list of checkboxes posts the field once per ticked box.</summary>
    [Fact]
    public void Several_ticked_boxes_are_several_scopes()
    {
        var scopes = AdminForm.Scopes(new StringValues(["kb:read", "kb:write", "openid"]));

        Assert.Equal(["kb:read", "kb:write", "openid"], scopes);
    }

    /// <summary>
    /// And they are not one scope with commas in it.
    /// </summary>
    /// <remarks>
    /// The assertion that fails if anybody rewrites this as <c>posted.ToString()</c>, which is the
    /// obvious reading and joins the values with commas. Stated separately from the test above
    /// because that one would still pass on a single element, and this is the whole defect.
    /// </remarks>
    [Fact]
    public void Ticked_boxes_are_never_joined_into_one_name()
    {
        var scopes = AdminForm.Scopes(new StringValues(["kb:read", "kb:write"]));

        Assert.DoesNotContain(scopes, scope => scope.Contains(',', StringComparison.Ordinal));
    }

    /// <summary>The typed box posts one value with spaces in it.</summary>
    [Fact]
    public void A_typed_box_is_split_on_spaces()
    {
        var scopes = AdminForm.Scopes(new StringValues("kb:read  kb:write "));

        Assert.Equal(["kb:read", "kb:write"], scopes);
    }

    /// <summary>A scope ticked and also typed is still one scope.</summary>
    [Fact]
    public void Repeats_collapse()
    {
        var scopes = AdminForm.Scopes(new StringValues(["kb:read", "kb:read kb:write"]));

        Assert.Equal(["kb:read", "kb:write"], scopes);
    }

    /// <summary>
    /// Nothing posted is no scopes, rather than one empty one.
    /// </summary>
    /// <remarks>
    /// A form submitted with no box ticked sends the field not at all. The server refuses an empty
    /// set with a sentence saying so, and that is the intended outcome — but only if what reaches it
    /// is empty rather than a set containing one nameless scope, which it would refuse as a parse
    /// error instead and say something else.
    /// </remarks>
    [Fact]
    public void Nothing_posted_is_no_scopes()
    {
        Assert.Empty(AdminForm.Scopes(StringValues.Empty));
        Assert.Empty(AdminForm.Scopes(new StringValues(string.Empty)));
        Assert.Empty(AdminForm.Scopes(new StringValues("   ")));
        Assert.Empty(AdminForm.Scopes(default));
    }

    /// <summary>A null among the values is skipped rather than thrown on.</summary>
    /// <remarks>
    /// <see cref="StringValues"/> holds <c>string?</c>, so this is representable and arrives from a
    /// request this app did not construct.
    /// </remarks>
    [Fact]
    public void A_null_value_is_skipped()
    {
        var scopes = AdminForm.Scopes(new StringValues([null, "kb:read"]));

        Assert.Equal(["kb:read"], scopes);
    }
}
