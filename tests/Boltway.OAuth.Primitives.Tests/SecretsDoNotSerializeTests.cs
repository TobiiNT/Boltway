using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using Boltway.OAuth.Primitives.Pkce;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.OAuth.Primitives.Tests;

/// <summary>
/// A live secret must not come back out of a type by the routes a logger takes.
/// </summary>
/// <remarks>
/// <para>
/// <c>OpaqueSecret</c> has carried <c>[JsonIgnore]</c> and <c>[DebuggerBrowsable(Never)]</c> on its
/// wire value since it was written, under a comment explaining that overriding <c>ToString</c> is
/// not enough. Nothing tested any of it. Deleting either attribute left every suite green.
/// </para>
/// <para>
/// Writing these found two types with no defence at all. <c>CodeVerifier</c> reads as a request
/// parameter and is the secret PKCE turns on. <c>MintedToken</c> was worse: a positional record,
/// whose compiler-generated <c>ToString</c> prints every property, holding a signed and unexpired
/// access token - so <c>$"{token}"</c> emitted the credential itself. Both now carry what
/// <c>OpaqueSecret</c> carries.
/// </para>
/// <para>
/// The assertions are on the <em>value</em>, never on the shape. A test asserting "the JSON has no
/// <c>Wire</c> property" would pass on a type that renamed it.
/// </para>
/// </remarks>
public sealed class SecretsDoNotSerializeTests
{
    /// <summary>The two routes that are closed: JSON, and string interpolation.</summary>
    private static void AssertDoesNotSerialize(object value, string secret, string what)
    {
        Assert.DoesNotContain(secret, JsonSerializer.Serialize(value), StringComparison.Ordinal);

        Assert.DoesNotContain(
            secret,
            value.ToString() ?? string.Empty,
            StringComparison.Ordinal);

        Assert.False(
            $"{value}".Contains(secret, StringComparison.Ordinal),
            $"{what}: string interpolation prints the secret.");
    }

    [Fact]
    public void A_minted_secret_does_not_serialize()
    {
        var secret = OpaqueSecret.Generate(TokenPurpose.RefreshToken);

        AssertDoesNotSerialize(secret, secret.Wire, nameof(OpaqueSecret));
    }

    [Fact]
    public void A_pkce_verifier_does_not_serialize()
    {
        var verifier = CodeVerifier.Generate();

        AssertDoesNotSerialize(verifier, verifier.Value, nameof(CodeVerifier));
    }

    /// <summary>
    /// The challenge is not a secret and must stay readable - the inverse assertion, so that
    /// "hide everything" is not how the tests above get satisfied.
    /// </summary>
    /// <remarks>
    /// A code challenge is the SHA-256 of the verifier and travels in the authorization URL, in
    /// front of the user, in browser history and in this server's own logs. Hiding it would cost
    /// the diagnosis of every PKCE mismatch and buy nothing.
    /// </remarks>
    [Fact]
    public void A_pkce_challenge_stays_readable()
    {
        var challenge = CodeVerifier.Generate().ComputeS256Challenge();

        Assert.Contains(challenge, JsonSerializer.Serialize(new { challenge }), StringComparison.Ordinal);
    }

    /// <summary>
    /// The debugger is a leak surface with an audience of one, and it is the one that gets
    /// screenshotted into a chat.
    /// </summary>
    [Theory]
    [InlineData(typeof(OpaqueSecret), nameof(OpaqueSecret.Wire))]
    [InlineData(typeof(CodeVerifier), nameof(CodeVerifier.Value))]
    public void The_secret_is_hidden_from_the_debugger(Type type, string property)
    {
        var attribute = type.GetProperty(property)!.GetCustomAttribute<DebuggerBrowsableAttribute>();

        Assert.NotNull(attribute);
        Assert.Equal(DebuggerBrowsableState.Never, attribute.State);
    }

    /// <summary>
    /// <b>A logger that destructures over properties still reaches the value, and this test says
    /// so rather than pretending otherwise.</b>
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the route <c>OpaqueSecret</c>'s own comment names - Serilog's <c>{@secret}</c>, and
    /// any provider that "expands objects" - and it is the one <c>[JsonIgnore]</c> does not close,
    /// because reflection does not read attributes it was not told to. The only way to close it is
    /// to stop the value being a public property at all: a method, which destructuring does not
    /// call. That is a rename across roughly seventy call sites on the token path, and it has not
    /// been done.
    /// </para>
    /// <para>
    /// So this asserts the leak, deliberately. It is the reason Serilog is not a dependency of this
    /// repository and the reason <c>{@x}</c> must not appear in one: with
    /// <c>AddJsonConsole</c> the logger serialises the log <i>state</i> - the message and its named
    /// properties - which the attributes above do cover.
    /// </para>
    /// <para>
    /// It will fail the day somebody closes the route properly. That is the point: the failure is
    /// the prompt to delete this test and the paragraph explaining why Serilog is absent.
    /// </para>
    /// </remarks>
    [Fact]
    public void A_destructuring_logger_would_still_reach_the_value()
    {
        var secret = OpaqueSecret.Generate(TokenPurpose.RefreshToken);

        var reachable = typeof(OpaqueSecret)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.CanRead)
            .Select(p => p.GetValue(secret)?.ToString())
            .Any(v => v is not null && v.Contains(secret.Wire, StringComparison.Ordinal));

        Assert.True(
            reachable,
            "The destructuring route is closed. Delete this test and the note about Serilog that "
            + "cites it — both exist only to record that it was open.");
    }
}
