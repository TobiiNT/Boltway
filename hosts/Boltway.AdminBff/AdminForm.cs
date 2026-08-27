using Microsoft.Extensions.Primitives;

namespace Boltway.AdminBff;

/// <summary>
/// Reading what a form posted, where the shape a control sends is not the shape it looks like.
/// </summary>
/// <remarks>
/// Small enough to have lived inside the endpoint, and it did. It is here because the endpoints have
/// no tests - every test in this app renders a page - so a field read the wrong way is invisible
/// until an operator presses the button. Both defects this section has shipped were of that kind:
/// the code was right and the value never reached it.
/// </remarks>
public static class AdminForm
{
    /// <summary>The scopes a service-account form asked for, however it was drawn.</summary>
    /// <param name="posted">The <c>scopes</c> field, as the form sent it.</param>
    /// <returns>Each distinct scope, in the order it was posted.</returns>
    /// <remarks>
    /// <para>
    /// <b>One field, two shapes.</b> A list of checkboxes posts <c>scopes</c> once per tick; the box
    /// an operator types into posts it once with spaces in it. Which one arrives depends on whether
    /// the server published <c>scopes_supported</c>, so the handler cannot know and has to read
    /// both.
    /// </para>
    /// <para>
    /// <b>Why this is not <c>posted.ToString()</c>.</b> <see cref="StringValues"/> joins several
    /// values with <em>commas</em>, so three ticked scopes read as one scope named
    /// <c>a,b,c</c> - a single name, containing a character no scope may contain, which the
    /// authorization server then refuses. The failure is a refusal on a form that looked correct,
    /// which is the same shape as the roles field sending an array to a handler still reading one
    /// value.
    /// </para>
    /// <para>
    /// Distinct, because a scope ticked and also typed is still one scope, and the server treats a
    /// repeated name as a malformed set rather than as emphasis.
    /// </para>
    /// </remarks>
    public static string[] Scopes(StringValues posted) =>
        [.. posted
            .SelectMany(value => (value ?? string.Empty)
                .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Distinct(StringComparer.Ordinal)];

    /// <summary>The permissions a role form asked for.</summary>
    /// <param name="posted">The <c>permissions</c> field, as the form sent it.</param>
    /// <returns>Each distinct permission, in the order it was posted.</returns>
    /// <remarks>
    /// <para>
    /// The same reading as <see cref="Scopes"/> and deliberately the same code path, because the
    /// two fields have the same shape on the wire and the same trap in them. A permission carrying
    /// whitespace is refused by the store rather than silently becoming two, so splitting here is
    /// what the store expects rather than a guess about intent.
    /// </para>
    /// <para>
    /// This field is a box today and could become a list of checkboxes the moment anything publishes
    /// the vocabulary - at which point it would start posting several values, and reading it as one
    /// string would break exactly the way the roles field did. It is written for both now, so that
    /// change stays a renderer change.
    /// </para>
    /// </remarks>
    public static string[] Permissions(StringValues posted) => Scopes(posted);
}
