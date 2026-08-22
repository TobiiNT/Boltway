using System.Net;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.Identity.Subjects;
using Boltway.OAuth.Primitives.Ids;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// Signing in with the address, as well as with the handle.
/// </summary>
/// <remarks>
/// <para>
/// The asymmetry that produced this: <c>/forgot</c> accepted "tên đăng nhập hoặc email" and
/// <c>/login</c> accepted only the handle, so a founder asked for a reset with their address, set a
/// password, typed the same address to sign in, and was told <i>"that username and password did not
/// match"</i> — a true sentence about a question they had not asked. Reported after it happened.
/// </para>
/// <para>
/// The rule the tests below pin is narrow on purpose: <b>a verified address, and one account.</b>
/// An unverified address is a claim, not a proof, and the flow that may act on an unverified one is
/// <c>/forgot</c> — which <i>sends to</i> the address, and so establishes control rather than
/// assuming it.
/// </para>
/// </remarks>
public sealed partial class LoginFlowTests
{
    private const string AdaEmail = "ada@example.com";

    /// <summary>The address reaches the account, and the sign-in completes.</summary>
    [Fact]
    public async Task A_verified_address_signs_in()
    {
        await using var server = await StartAsync();

        var signedIn = await PostLoginAsync(server, AdaEmail, Password);

        Assert.Equal(HttpStatusCode.SeeOther, signedIn.StatusCode);
    }

    /// <summary>Case is not part of the address.</summary>
    [Theory]
    [InlineData("ADA@EXAMPLE.COM")]
    [InlineData("Ada@Example.Com")]
    public async Task The_address_is_accepted_in_any_case(string typed)
    {
        await using var server = await StartAsync();

        Assert.Equal(HttpStatusCode.SeeOther, (await PostLoginAsync(server, typed, Password)).StatusCode);
    }

    /// <summary>
    /// An unverified address signs nobody in, with the right password.
    /// </summary>
    /// <remarks>
    /// The security of the feature, stated as the case that must stay refused. Anybody who can
    /// create an account can type a colleague's address into it; only the round trip through the
    /// mailbox turns that claim into a fact, and until it does the address must authenticate
    /// nothing.
    /// </remarks>
    [Fact]
    public async Task An_unverified_address_does_not_sign_in()
    {
        await using var server = await StartAsync();

        await server.Users.SetEmailAsync(
            server.Subject, AdaEmail, verified: false, CancellationToken.None);

        var rejected = await PostLoginAsync(server, AdaEmail, Password);

        Assert.Equal(HttpStatusCode.OK, rejected.StatusCode);

        // And the handle still works, so what was refused is the address and not the account.
        Assert.Equal(HttpStatusCode.SeeOther, (await PostLoginAsync(server, Username, Password)).StatusCode);
    }

    /// <summary>
    /// A handle that looks like an address beats an address that matches it.
    /// </summary>
    /// <remarks>
    /// Order is the rule, not an implementation detail. If the address were asked first, registering
    /// an account whose <i>handle</i> is somebody else's address would shadow their sign-in — the
    /// caller would reach the shadowing account with the shadowing account's password, and the
    /// person whose address it is would find their own credentials refused.
    /// </remarks>
    [Fact]
    public async Task A_handle_shaped_like_an_address_wins()
    {
        await using var server = await StartAsync();
        var impostorPassword = "a different password entirely";

        await server.Users.StoreAsync(
            new UserAccount(
                new UlidSubjectIdFactory(TimeProvider.System).Mint(),
                AdaEmail,
                "impostor@example.com",
                EmailVerified: true,
                PasswordHash: server.Hasher.Hash(impostorPassword)),
            CancellationToken.None);

        // The handle owner's password reaches the handle owner.
        Assert.Equal(
            HttpStatusCode.SeeOther,
            (await PostLoginAsync(server, AdaEmail, impostorPassword)).StatusCode);

        // And Ada's own password no longer reaches Ada through that string, which is the cost of
        // the rule and is why it is the handle that wins: the collision is visible to whoever
        // registered it, and the alternative hands the account to whoever registers it second.
        Assert.Equal(HttpStatusCode.OK, (await PostLoginAsync(server, AdaEmail, Password)).StatusCode);
    }

    /// <summary>Two accounts sharing one verified address sign in as neither.</summary>
    [Fact]
    public async Task An_address_two_accounts_share_signs_in_as_neither()
    {
        await using var server = await StartAsync();

        await server.Users.SetEmailAsync(
            SubjectOf(server, FederatedOnlyUsername), AdaEmail, verified: true, CancellationToken.None);

        Assert.Equal(HttpStatusCode.OK, (await PostLoginAsync(server, AdaEmail, Password)).StatusCode);

        // The handle is unambiguous and still works: what became ambiguous is the address.
        Assert.Equal(HttpStatusCode.SeeOther, (await PostLoginAsync(server, Username, Password)).StatusCode);
    }

    /// <summary>
    /// An address nobody holds costs the same hash as one somebody does. S-48.
    /// </summary>
    /// <remarks>
    /// The enumeration guard, extended to the new lookup. Skipping the hash when the address matches
    /// nothing would answer faster for an unregistered address than for a registered one, which is
    /// the same oracle a distinct error message would be — measured in milliseconds instead of
    /// words. <c>CountingPasswordHasher</c> asks the question a stopwatch cannot answer on a shared
    /// CI machine: was the work done at all?
    /// </remarks>
    [Fact]
    public async Task An_unknown_address_still_pays_for_a_hash()
    {
        await using var server = await StartAsync();

        var before = server.Hasher.Verifications;

        await PostLoginAsync(server, "nobody@example.com", Password);

        Assert.Equal(before + 1, server.Hasher.Verifications);
    }

    private static SubjectId SubjectOf(Server server, string username) =>
        server.Users.FindByUsernameAsync(RealmId.Default, username, CancellationToken.None)
            .GetAwaiter().GetResult()!.Subject;
}
