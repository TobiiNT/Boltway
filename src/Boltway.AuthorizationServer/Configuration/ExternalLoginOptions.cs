namespace Boltway.AuthorizationServer.Configuration;

/// <summary>
/// What to do when an upstream asserts an identity no local account is linked to.
/// </summary>
/// <remarks>
/// <para>
/// <b>The member that is deliberately absent is the important one.</b> There is no
/// <c>MatchByEmail</c>. Auto-linking an upstream identity to an existing local account because the
/// email addresses agree is the classic federated account takeover: the attacker registers the
/// victim's address at an upstream that does not verify it, signs in, and inherits the local
/// account. The usual mitigation offered is to require <c>email_verified</c> - which is a claim
/// made by the upstream, in a token, about a check this server did not perform and cannot audit.
/// It is exactly as trustworthy as the upstream, and the whole point of adding a second provider
/// later is that not every upstream is equally trustworthy.
/// </para>
/// <para>
/// So the enum offers refusing and provisioning, and linking an upstream identity to an
/// <i>existing</i> account happens only through <c>POST /external/{scheme}/link</c>, which requires
/// a live authenticated session for the account being linked to.
/// </para>
/// <para>
/// The structural half of that argument used to be that <c>IUserStore</c> had no method finding an
/// account by email address <i>at all</i>, so there was no code path to add a "just this once"
/// exception to. That is no longer true and the sentence is kept because it is worth knowing what
/// replaced it: signing in with a verified address shipped, so
/// <c>FindByVerifiedEmailAsync</c> exists. The guard moved rather than went -
/// <c>StructuralRuleTests.Only_the_sign_in_form_resolves_an_account_by_address</c> reads the IL and
/// fails if anything outside the sign-in form calls it. Adding the exception here is still a diff
/// somebody has to write on purpose; it is no longer a method they would have to invent first.
/// </para>
/// </remarks>
public enum UnknownExternalIdentityPolicy
{
    /// <summary>
    /// Refuse, and say so. The default.
    /// </summary>
    /// <remarks>
    /// The strict posture, chosen as the default because the alternative is open registration: with
    /// <see cref="Provision"/>, anyone in the world with an account at the configured upstream has
    /// an account here. That may be exactly right - a deployment federating to its own corporate
    /// tenant wants it - and it is a decision somebody should make on purpose.
    /// </remarks>
    Refuse = 0,

    /// <summary>
    /// Create a new local account, linked to this upstream identity and to nothing else.
    /// </summary>
    /// <remarks>
    /// <b>New</b> is the operative word: the account is minted with a fresh ULID subject and is
    /// never an existing row. An upstream identity whose email matches an existing account gets its
    /// own separate account, and there is a test that measures exactly that.
    /// </remarks>
    Provision = 1,
}

/// <summary>Federated sign-in, as an operator configures it.</summary>
public sealed class ExternalLoginOptions
{
    /// <summary>What to do with an upstream identity no local account is linked to.</summary>
    public UnknownExternalIdentityPolicy UnknownIdentity { get; set; } = UnknownExternalIdentityPolicy.Refuse;

    /// <summary>
    /// How long a started federated sign-in may take before the pending request expires.
    /// </summary>
    /// <remarks>
    /// Ten minutes covers a user who has to type an upstream password and answer a second factor,
    /// and is short enough that a pending request left on a shared machine is not a standing
    /// invitation. It bounds the window in which a stolen <c>state</c> would be worth anything - and
    /// <c>state</c> is single-use besides, because the cookie is deleted when the callback reads it.
    /// </remarks>
    public TimeSpan PendingRequestLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Copy <c>email</c> and <c>email_verified</c> from the upstream onto a provisioned account.
    /// </summary>
    /// <remarks>
    /// On by default, and safe for one reason worth stating plainly: nothing in this server ever
    /// <i>reads</i> an account's email to decide which account something is. It reaches the
    /// <c>email</c> claim of an ID token, and the value there is the upstream's assertion rather
    /// than a check this server performed - which is the same thing OIDC Core says about
    /// <c>email_verified</c>, and the reason it is not an identity.
    /// </remarks>
    public bool CopyEmailOnProvision { get; set; } = true;

    /// <summary>Validate. Collects every problem rather than the first.</summary>
    /// <param name="errors">Every problem found.</param>
    public bool TryValidate(out IReadOnlyList<string> errors)
    {
        List<string> problems = [];

        if (PendingRequestLifetime <= TimeSpan.Zero || PendingRequestLifetime > TimeSpan.FromHours(1))
        {
            problems.Add(
                $"ExternalLoginOptions.PendingRequestLifetime is {PendingRequestLifetime}. It must be "
                + "positive and no more than an hour: it is the window in which a federated sign-in "
                + "that was started can be completed.");
        }

        errors = problems;
        return problems.Count == 0;
    }
}
