namespace Boltway.AuthorizationServer.Requests;

/// <summary>
/// The parameters of one OAuth request, read once and never re-read.
/// </summary>
/// <remarks>
/// <para>
/// Transport-neutral by design: a flat dictionary of name to values, produced before any stage
/// looks at a parameter. That is the PAR seam — adding pushed authorization requests later means
/// another implementation of the source, and none of the stages change, because none of them know
/// where their parameters came from. The same type serves <c>/authorize</c>'s query string and
/// <c>/token</c>'s form body, so the repeated-parameter rule below is enforced identically at both.
/// </para>
/// <para>
/// Values are a <b>list</b>, not a string, because the difference matters twice. A repeated
/// parameter is a protocol violation for everything except <c>resource</c> (RFC 8707 §2 explicitly
/// permits repetition), and binding to a single string would silently take one of them — which one
/// depends on the framework, and an attacker who can add a second <c>redirect_uri</c> would like to
/// know which.
/// </para>
/// </remarks>
public sealed class OAuthParameters
{
    private readonly IReadOnlyDictionary<string, IReadOnlyList<string>> _values;

    /// <summary>Wrap a parsed parameter set.</summary>
    public OAuthParameters(IReadOnlyDictionary<string, IReadOnlyList<string>> values) =>
        _values = values ?? throw new ArgumentNullException(nameof(values));

    /// <summary>
    /// A parameter that must appear at most once.
    /// </summary>
    /// <param name="name">The parameter name.</param>
    /// <param name="value">Its value, or <see langword="null"/> if absent.</param>
    /// <returns><see langword="false"/> if it appeared more than once.</returns>
    public bool TrySingle(string name, out string? value)
    {
        value = null;

        if (!_values.TryGetValue(name, out var found) || found.Count == 0)
        {
            return true;
        }

        if (found.Count > 1)
        {
            return false;
        }

        value = found[0];
        return true;
    }

    /// <summary>Every value of a repeatable parameter. Only <c>resource</c> is one.</summary>
    public IReadOnlyList<string> All(string name) =>
        _values.TryGetValue(name, out var found) ? found : [];

    /// <summary>
    /// Whether a parameter appears at all, <b>with a value</b>.
    /// </summary>
    /// <remarks>
    /// The "with a value" clause is why this is not a bare <c>ContainsKey</c>. A key mapped to an
    /// empty list is absent as far as <see cref="TrySingle"/> is concerned — it hands back
    /// <see langword="null"/> — and a <c>Contains</c> that answered <see langword="true"/> for the
    /// same input would make the two disagree about what "present" means. Nothing that ASP.NET
    /// query binding produces has that shape, but this type is deliberately transport-neutral and
    /// is the seam a pushed authorization request would arrive through.
    /// </remarks>
    public bool Contains(string name) => _values.TryGetValue(name, out var found) && found.Count > 0;
}
