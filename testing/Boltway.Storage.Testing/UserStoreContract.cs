using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.OAuth.Primitives.Ids;

namespace Boltway.Storage.Testing;

/// <summary>
/// The <see cref="IUserStore"/> contract, run against every implementation.
/// </summary>
/// <remarks>
/// <para>
/// The sibling of <see cref="GrantStoreContract"/>, and it exists for the same reason: this suite is
/// what makes "point the server at your own directory" a tractable request rather than an invitation
/// to get a uniqueness rule subtly wrong. Its blind spots become customers' blind spots.
/// </para>
/// <para>
/// The rules under test are mostly about <b>uniqueness</b>, because that is where the interface's
/// prose makes demands a naive implementation will not meet. "Compare case-insensitively" and "do
/// not let two accounts differ only by case" are two separate requirements, and satisfying the first
/// with a case-folding lookup over a case-sensitive table satisfies neither reliably: which row a
/// login reaches then depends on the store's collation.
/// </para>
/// </remarks>
public abstract class UserStoreContract
{
    /// <summary>
    /// Both stores over one database, because they are one aggregate as far as this contract is
    /// concerned.
    /// </summary>
    /// <remarks>
    /// Two factories would hand back two databases for the relational implementations — each call to
    /// their fixture makes a fresh one — and every assignment test would then be defining a role in
    /// one and assigning it in another.
    /// </remarks>
    protected abstract (IUserStore Users, IRoleStore Roles) NewStores();

    /// <summary>A user store whose realm defines <c>founder</c> and <c>editor</c>.</summary>
    /// <remarks>
    /// Seeded, because assignment refuses an id nothing defines and most of what this contract
    /// covers is not about that rule. The tests that are about it define their own.
    /// </remarks>
    protected IUserStore NewUserStore()
    {
        var (users, roles) = NewStores();

        roles.StoreAsync(new RoleDefinition("founder", "founder", []), CancellationToken.None)
            .GetAwaiter().GetResult();
        roles.StoreAsync(new RoleDefinition("editor", "editor", []), CancellationToken.None)
            .GetAwaiter().GetResult();

        return users;
    }

    private const string Google = "https://accounts.google.com";

    private static SubjectId Subject(string suffix) =>
        SubjectId.FromStorage("01J8XKQ7M3N4P5R6S7T8V9W0" + suffix);

    private static UserAccount Account(
        string username = "ada",
        string subjectSuffix = "XY",
        string? passwordHash = "$argon2id$v=19$m=64,t=1,p=1$AAECAwQFBgcICQoLDA0ODw$AAECAwQFBgcICQoLDA0ODw") =>
        new(Subject(subjectSuffix), username, username + "@example.com", EmailVerified: true, passwordHash);

    // -------------------------------------------------- what an account holds

    /// <summary>The stamp round-trips, and an unknown account reports that it was not found.</summary>
    /// <remarks>
    /// <b>Null before anything writes it, and that is a value rather than an absence.</b> Every
    /// account predating this column has null, and the validator reads null as "these sessions are
    /// fine" — a backend defaulting it to the epoch would sign a whole deployment out on the
    /// migration that added it.
    /// </remarks>
    [Fact]
    public async Task Stamping_sessions_round_trips_and_reports_a_missing_account()
    {
        var store = NewUserStore();
        var subject = SubjectId.FromStorage("stamp-me");
        var at = new DateTimeOffset(2026, 8, 21, 3, 4, 5, TimeSpan.Zero);

        await store.StoreAsync(
            new UserAccount(subject, "stamped", null, EmailVerified: false, PasswordHash: null),
            CancellationToken.None);

        Assert.Null((await store.FindBySubjectAsync(subject, CancellationToken.None))!.SessionsValidFrom);

        Assert.True(await store.StampSessionsAsync(subject, at, CancellationToken.None));

        var stamped = await store.FindBySubjectAsync(subject, CancellationToken.None);

        // To the tick. The comparison this feeds is strictly-before, so a backend rounding to the
        // second would let a session that began in the same second outlive its own invalidation.
        Assert.Equal(at, stamped!.SessionsValidFrom);

        // False rather than throwing, the same contract SetPasswordHashAsync states: the caller's
        // next move is to report a handle that does not exist, not to have created one.
        Assert.False(
            await store.StampSessionsAsync(
                SubjectId.FromStorage("nobody-at-all"), at, CancellationToken.None));
    }

    /// <summary>
    /// Every link an account holds comes back, each keeping the issuer and upstream subject it was
    /// made with, and every one naming this account.
    /// </summary>
    /// <remarks>
    /// The reverse of <c>FindByExternalLoginAsync</c>, and the read a person makes about their own
    /// account. Without it a self-service page can offer to connect a provider and cannot say
    /// whether connecting already happened — measured on a running deployment, where a user linked
    /// an upstream account and got back an identical page.
    /// </remarks>
    [Fact]
    public async Task An_accounts_links_come_back()
    {
        var store = NewUserStore();
        var ada = Account();

        await store.StoreAsync(ada, CancellationToken.None);
        await store.LinkExternalLoginAsync(
            new ExternalLogin(Google, "google-subject", ada.Subject), CancellationToken.None);
        await store.LinkExternalLoginAsync(
            new ExternalLogin("https://okta.example", "okta-subject", ada.Subject), CancellationToken.None);

        var links = await store.ListExternalLoginsAsync(ada.Subject, CancellationToken.None);

        Assert.Equal(2, links.Count);
        Assert.Contains(links, l => l.UpstreamIssuer == Google && l.UpstreamSubject == "google-subject");
        Assert.Contains(links, l => l.UpstreamIssuer == "https://okta.example");
        Assert.All(links, l => Assert.Equal(ada.Subject.Value, l.Subject.Value));
    }

    /// <summary>Somebody else's links are not this account's.</summary>
    /// <remarks>
    /// The check that matters most, because the failure it catches is a page telling one user that
    /// another user's upstream account is connected to theirs.
    /// </remarks>
    [Fact]
    public async Task Another_accounts_links_are_not_returned()
    {
        var store = NewUserStore();
        var ada = Account(username: "ada", subjectSuffix: "XY");
        var grace = Account(username: "grace", subjectSuffix: "ZZ");

        await store.StoreAsync(ada, CancellationToken.None);
        await store.StoreAsync(grace, CancellationToken.None);

        await store.LinkExternalLoginAsync(
            new ExternalLogin(Google, "graces-google", grace.Subject), CancellationToken.None);

        Assert.Empty(await store.ListExternalLoginsAsync(ada.Subject, CancellationToken.None));
        Assert.Single(await store.ListExternalLoginsAsync(grace.Subject, CancellationToken.None));
    }

    /// <summary>An account with none gets an empty list, not an error.</summary>
    [Fact]
    public async Task An_account_with_no_links_is_empty()
    {
        var store = NewUserStore();
        var ada = Account();

        await store.StoreAsync(ada, CancellationToken.None);

        Assert.Empty(await store.ListExternalLoginsAsync(ada.Subject, CancellationToken.None));
    }

    /// <summary>And an account that does not exist is empty rather than a failure.</summary>
    /// <remarks>
    /// Reached with a subject taken from a session, so "the account was deleted a moment ago" is a
    /// real ordering rather than a bug — and a page that throws there is worse than one that shows
    /// no providers.
    /// </remarks>
    [Fact]
    public async Task An_unknown_subject_is_empty()
    {
        var store = NewUserStore();

        Assert.Empty(await store.ListExternalLoginsAsync(Subject("NONE"), CancellationToken.None));
    }

    // -------------------------------------------------- finding by address

    /// <summary>A verified address reaches its account.</summary>
    /// <remarks>
    /// The point of the method: <c>/forgot</c> accepted an address and <c>/login</c> did not, so a
    /// person who asked for a reset by email and then typed the same string to sign in was refused
    /// with "that username and password did not match" — a true sentence about the wrong question.
    /// </remarks>
    [Fact]
    public async Task A_verified_address_finds_the_account()
    {
        var store = NewUserStore();

        await store.StoreAsync(Account(), CancellationToken.None);

        var found = await store.FindByVerifiedEmailAsync(
            RealmId.Default, "ada@example.com", CancellationToken.None);

        Assert.Equal("ada", found?.Username);
    }

    /// <summary>Case does not matter, on either side of the comparison.</summary>
    /// <remarks>
    /// Both directions, because the fold has to happen on the stored value as well as the submitted
    /// one. A store that folds only what was typed passes the first of these and fails the second,
    /// and the second is the ordinary case — somebody registered with a capital letter.
    /// </remarks>
    [Theory]
    [InlineData("ada@example.com", "ADA@EXAMPLE.COM")]
    [InlineData("ADA@example.com", "ada@example.com")]
    [InlineData("Ada@Example.Com", "aDa@eXaMpLe.cOm")]
    public async Task The_address_is_matched_without_regard_to_case(string stored, string typed)
    {
        var store = NewUserStore();

        await store.StoreAsync(Account() with { Email = stored }, CancellationToken.None);

        Assert.NotNull(await store.FindByVerifiedEmailAsync(RealmId.Default, typed, CancellationToken.None));
    }

    /// <summary>
    /// An unverified address finds nothing.
    /// </summary>
    /// <remarks>
    /// The security of the whole feature. An unverified address is a string somebody typed about
    /// themselves; if it authenticated, anybody who can create an account could name a colleague's
    /// address and the address would prove nothing while looking like it proved something.
    /// </remarks>
    [Fact]
    public async Task An_unverified_address_finds_nothing()
    {
        var store = NewUserStore();

        await store.StoreAsync(
            Account() with { EmailVerified = false }, CancellationToken.None);

        Assert.Null(await store.FindByVerifiedEmailAsync(
            RealmId.Default, "ada@example.com", CancellationToken.None));
    }

    /// <summary>Verifying it later makes it work, without the address being written again.</summary>
    [Fact]
    public async Task Verifying_an_address_makes_it_usable()
    {
        var store = NewUserStore();
        var ada = Account() with { EmailVerified = false };

        await store.StoreAsync(ada, CancellationToken.None);

        Assert.True(await store.SetEmailAsync(
            ada.Subject, "ada@example.com", verified: true, CancellationToken.None));

        Assert.NotNull(await store.FindByVerifiedEmailAsync(
            RealmId.Default, "ada@example.com", CancellationToken.None));
    }

    /// <summary>
    /// Two accounts holding one verified address resolve to neither.
    /// </summary>
    /// <remarks>
    /// Nothing makes an address unique — a username has a unique index and an address has never had
    /// one — so this state is reachable, most plainly by an operator running <c>set-email … 
    /// --verified</c> twice. Returning either one would make which account a password reaches depend
    /// on the store's ordering, which is the same class of defect as two usernames differing only by
    /// case.
    /// </remarks>
    [Fact]
    public async Task An_address_two_accounts_share_finds_neither()
    {
        var store = NewUserStore();

        await store.StoreAsync(Account(username: "ada", subjectSuffix: "XY"), CancellationToken.None);
        await store.StoreAsync(
            Account(username: "grace", subjectSuffix: "ZZ") with { Email = "ada@example.com" },
            CancellationToken.None);

        Assert.Null(await store.FindByVerifiedEmailAsync(
            RealmId.Default, "ada@example.com", CancellationToken.None));

        // And the username lookup is unaffected: the ambiguity is the address's, not the account's.
        Assert.NotNull(await store.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None));
    }

    /// <summary>An address cleared by anonymisation stops finding the tombstone.</summary>
    /// <remarks>
    /// The write path most likely to be forgotten, because it clears the address with a literal
    /// rather than by calling the setter. A store that leaves the normalised copy behind keeps a
    /// deleted person's address pointing at their tombstone, which is the opposite of what
    /// anonymising is for.
    /// </remarks>
    [Fact]
    public async Task An_anonymised_account_is_no_longer_found_by_its_address()
    {
        var store = NewUserStore();
        var ada = Account();

        await store.StoreAsync(ada, CancellationToken.None);

        Assert.True(await store.AnonymiseAsync(
            ada.Subject, "anonymised-ada", DateTimeOffset.UnixEpoch, CancellationToken.None));

        Assert.Null(await store.FindByVerifiedEmailAsync(
            RealmId.Default, "ada@example.com", CancellationToken.None));
    }

    /// <summary>An address is a key within a realm, exactly as a username is.</summary>
    [Fact]
    public async Task The_address_lookup_is_scoped_to_one_realm()
    {
        var store = NewUserStore();

        await store.StoreAsync(Account(), CancellationToken.None);

        Assert.Null(await store.FindByVerifiedEmailAsync(
            RealmId.FromStorage("other"), "ada@example.com", CancellationToken.None));
    }

    /// <summary>Nothing submitted finds nothing, rather than every account with no address.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("not-an-address")]
    public async Task A_submission_that_matches_no_address_finds_nothing(string submitted)
    {
        var store = NewUserStore();

        await store.StoreAsync(Account(), CancellationToken.None);

        Assert.Null(await store.FindByVerifiedEmailAsync(
            RealmId.Default, submitted, CancellationToken.None));
    }

    // -------------------------------------------------- disabling and email

    /// <summary>
    /// An account can be disabled and enabled again, on both lookups.
    /// </summary>
    /// <remarks>
    /// The rule was enforced and unsettable: both sign-in paths refuse an account whose
    /// <c>DisabledAt</c> is set, and nothing could set it. Both lookups, because sign-in arrives by
    /// username and a store that updated only the subject index would refuse nobody.
    /// </remarks>
    [Fact]
    public async Task Disabling_and_enabling_show_on_both_lookups()
    {
        var store = NewUserStore();
        var ada = Account();
        var at = new DateTimeOffset(2026, 8, 10, 9, 0, 0, TimeSpan.Zero);

        await store.StoreAsync(ada, CancellationToken.None);

        Assert.True(await store.SetEnabledAsync(ada.Subject, at, CancellationToken.None));

        var disabledBySubject = await store.FindBySubjectAsync(ada.Subject, CancellationToken.None);
        var disabledByUsername = await store.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None);

        Assert.False(disabledBySubject!.IsActive);
        Assert.False(disabledByUsername!.IsActive);
        Assert.Equal(at, disabledBySubject.DisabledAt);

        Assert.True(await store.SetEnabledAsync(ada.Subject, null, CancellationToken.None));

        Assert.True((await store.FindBySubjectAsync(ada.Subject, CancellationToken.None))!.IsActive);
        Assert.True((await store.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None))!.IsActive);
    }

    /// <summary>
    /// Disabling leaves the credential and the role exactly as they were.
    /// </summary>
    /// <remarks>
    /// The same property the password and role setters have, from the third side: a load-modify-save
    /// implementation would write back every column it read, so disabling an account during an
    /// incident would silently undo a password reset done a moment earlier.
    /// </remarks>
    [Fact]
    public async Task Disabling_changes_nothing_else()
    {
        var store = NewUserStore();
        var ada = Account() with { Roles = ["founder"] };

        // Created holding none and assigned after, because creation does not assign.
        await store.StoreAsync(ada with { Roles = [] }, CancellationToken.None);
        await store.SetRolesAsync(ada.Subject, ada.Roles, CancellationToken.None);
        await store.SetEnabledAsync(ada.Subject, DateTimeOffset.UnixEpoch, CancellationToken.None);

        var stored = await store.FindBySubjectAsync(ada.Subject, CancellationToken.None);

        Assert.Equal(ada.PasswordHash, stored!.PasswordHash);
        Assert.Equal(["founder"], stored.Roles);
        Assert.Equal(ada.Email, stored.Email);
        Assert.Equal(ada.Username, stored.Username);
    }

    /// <summary>An address and its verified flag are one write, and both lookups show both.</summary>
    [Fact]
    public async Task An_email_and_its_verification_move_together()
    {
        var store = NewUserStore();
        var ada = Account();

        await store.StoreAsync(ada, CancellationToken.None);

        Assert.True(await store.SetEmailAsync(ada.Subject, "new@example.com", verified: true, CancellationToken.None));

        var bySubject = await store.FindBySubjectAsync(ada.Subject, CancellationToken.None);
        var byUsername = await store.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None);

        Assert.Equal("new@example.com", bySubject!.Email);
        Assert.True(bySubject.EmailVerified);

        // Both lookups, because a token is built from whichever one the flow reached — and
        // `email_verified` is the claim a resource server is most likely to trust without checking.
        Assert.Equal("new@example.com", byUsername!.Email);
        Assert.True(byUsername.EmailVerified);
    }

    /// <summary>Clearing the address clears the verified flag with it.</summary>
    /// <remarks>
    /// The flag is a claim about an address, so one left standing over a null one is a proof about an
    /// address the account no longer holds — and <c>email_verified</c> is the claim a resource server
    /// is most likely to trust without checking.
    /// </remarks>
    [Fact]
    public async Task Clearing_an_email_clears_its_verification()
    {
        var store = NewUserStore();
        var ada = Account();

        await store.StoreAsync(ada, CancellationToken.None);
        await store.SetEmailAsync(ada.Subject, "new@example.com", verified: true, CancellationToken.None);
        await store.SetEmailAsync(ada.Subject, null, verified: false, CancellationToken.None);

        var stored = await store.FindBySubjectAsync(ada.Subject, CancellationToken.None);

        Assert.Null(stored!.Email);
        Assert.False(stored.EmailVerified);
    }

    /// <summary>Disabling and setting an address both report false for an account nothing stored.</summary>
    /// <remarks>
    /// The same contract the password and role setters state, and the one the stamp test above
    /// records: false rather than an exception, because the caller's next move is to report a handle
    /// that does not exist.
    /// </remarks>
    [Fact]
    public async Task Setting_state_on_an_account_that_does_not_exist_says_so()
    {
        var store = NewUserStore();

        Assert.False(await store.SetEnabledAsync(Subject("ZZ"), null, CancellationToken.None));
        Assert.False(await store.SetEmailAsync(Subject("ZZ"), "x@example.com", true, CancellationToken.None));
    }

    // -------------------------------------------------------------------- list

    /// <summary>
    /// Paging walks every account exactly once, in creation order.
    /// </summary>
    /// <remarks>
    /// The property that <c>OFFSET</c> does not have. Subjects are ULIDs, so ordering by subject is
    /// ordering by creation and "after this one" is an index seek — but the reason to pin it is the
    /// other half: a keyset page cannot skip or repeat a row when the set changes underneath it,
    /// which on a directory means an account nobody reviewing it ever sees.
    ///
    /// <para>
    /// It asserts the walk, not an order. A relational store compares and orders in the column's
    /// collation, so the two agree with each other and need not agree with C#'s ordinal; pinning the
    /// ordinal order would be pinning a collation nobody configured.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Paging_returns_every_account_once_in_order()
    {
        var store = NewUserStore();
        var subjects = new List<string>();

        for (var i = 0; i < 7; i++)
        {
            var account = Account(username: "user" + i, subjectSuffix: i.ToString("D2", null));
            await store.StoreAsync(account, CancellationToken.None);
            subjects.Add(account.Subject.Value);
        }

        var walked = new List<string>();
        SubjectId? after = null;

        while (true)
        {
            var page = await store.ListAsync(RealmId.Default, after, 3, CancellationToken.None);

            if (page.Count == 0)
            {
                break;
            }

            walked.AddRange(page.Select(a => a.Subject.Value));
            after = page[^1].Subject;
        }

        // Set equality and no repeats, rather than a pinned order. Both the cursor comparison and
        // the ordering run in the column's collation on a relational store, so they agree with each
        // other — which is what makes paging sound — without being guaranteed to agree with C#'s
        // ordinal. Asserting the ordinal order here would be asserting a collation nobody has
        // configured; asserting this is asserting the property a caller depends on.
        Assert.Equal(subjects.Count, walked.Count);
        Assert.Equal(subjects.Count, walked.Distinct(StringComparer.Ordinal).Count());
        Assert.Empty(subjects.Except(walked, StringComparer.Ordinal));
    }

    /// <summary>The limit bounds the page: five accounts asked for two come back two.</summary>
    /// <remarks>
    /// The control for the walk above, which passes against a store that ignores the limit and returns
    /// the whole directory in one page — set equality and no repeats both survive that. Nothing else
    /// here would notice.
    /// </remarks>
    [Fact]
    public async Task A_page_is_no_longer_than_the_limit()
    {
        var store = NewUserStore();

        for (var i = 0; i < 5; i++)
        {
            await store.StoreAsync(
                Account(username: "user" + i, subjectSuffix: i.ToString("D2", null)), CancellationToken.None);
        }

        var page = await store.ListAsync(RealmId.Default, null, 2, CancellationToken.None);

        Assert.Equal(2, page.Count);
    }

    /// <summary>
    /// Listing one realm never returns another's accounts.
    /// </summary>
    /// <remarks>
    /// The realm filter on the one query that returns rows nobody named. A lookup by username that
    /// forgot the realm answers with one wrong account; a list that forgets it hands over the whole
    /// of somebody else's directory.
    /// </remarks>
    [Fact]
    public async Task Listing_is_scoped_to_one_realm()
    {
        var store = NewUserStore();

        await store.StoreAsync(
            Account(subjectSuffix: "A9") with { Realm = RealmId.FromStorage("acme") }, CancellationToken.None);
        await store.StoreAsync(
            Account(username: "grace", subjectSuffix: "G9") with { Realm = RealmId.FromStorage("globex") },
            CancellationToken.None);

        var acme = await store.ListAsync(RealmId.FromStorage("acme"), null, 50, CancellationToken.None);

        Assert.Equal(["ada"], acme.Select(a => a.Username));
        Assert.Empty(await store.ListAsync(RealmId.Default, null, 50, CancellationToken.None));
    }

    // ------------------------------------------------------------------- realms

    /// <summary>
    /// Two realms may hold the same username, and a lookup in one never returns the other's row.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This passes today with one realm configured, and that is the point of writing it now. A realm
    /// column that exists and is not part of the key reads as tenancy and is not — the <c>A-09</c>
    /// shape, where a document and a database describe different systems. Enforcing it from the
    /// first migration is what makes a second directory later a configuration change rather than an
    /// audit of every query in the repository.
    /// </para>
    /// <para>
    /// The username is deliberately identical <b>and differently cased</b>: the uniqueness rule
    /// folds case, so a store that scoped the lookup but not the constraint would refuse the second
    /// account, and one that scoped neither would return the wrong person to a login.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Two_realms_may_hold_the_same_username_and_never_see_each_others()
    {
        var store = NewUserStore();

        var acme = Account(subjectSuffix: "A1") with { Realm = RealmId.FromStorage("acme") };
        var globex = Account(username: "ADA", subjectSuffix: "G1") with { Realm = RealmId.FromStorage("globex") };

        await store.StoreAsync(acme, CancellationToken.None);
        await store.StoreAsync(globex, CancellationToken.None);

        var inAcme = await store.FindByUsernameAsync(RealmId.FromStorage("acme"), "ada", CancellationToken.None);
        var inGlobex = await store.FindByUsernameAsync(RealmId.FromStorage("globex"), "ada", CancellationToken.None);
        var inDefault = await store.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None);

        Assert.Equal(acme.Subject, inAcme!.Subject);
        Assert.Equal(globex.Subject, inGlobex!.Subject);

        // The realm nobody put an account in. A store filtering on nothing would answer with
        // whichever row its index happened to reach first, which is the failure that reads as
        // flakiness rather than as a missing WHERE clause.
        Assert.Null(inDefault);
    }

    /// <summary>
    /// The same upstream identity in two realms is two links, not a collision.
    /// </summary>
    /// <remarks>
    /// An upstream subject is chosen by the upstream provider, so one Google account presented to
    /// two directories is the same pair of strings both times. Without the realm in the key the
    /// second realm's link is refused as "already linked to a different local account" — and the
    /// person is told their Google account belongs to someone else.
    /// </remarks>
    [Fact]
    public async Task The_same_upstream_identity_can_be_linked_in_two_realms()
    {
        var store = NewUserStore();

        var acme = Account(subjectSuffix: "A2") with { Realm = RealmId.FromStorage("acme") };
        var globex = Account(username: "grace", subjectSuffix: "G2") with { Realm = RealmId.FromStorage("globex") };

        await store.StoreAsync(acme, CancellationToken.None);
        await store.StoreAsync(globex, CancellationToken.None);

        await store.LinkExternalLoginAsync(
            new ExternalLogin(Google, "upstream-1", acme.Subject) { Realm = RealmId.FromStorage("acme") },
            CancellationToken.None);

        await store.LinkExternalLoginAsync(
            new ExternalLogin(Google, "upstream-1", globex.Subject) { Realm = RealmId.FromStorage("globex") },
            CancellationToken.None);

        var fromAcme = await store.FindByExternalLoginAsync(
            RealmId.FromStorage("acme"), Google, "upstream-1", CancellationToken.None);
        var fromGlobex = await store.FindByExternalLoginAsync(
            RealmId.FromStorage("globex"), Google, "upstream-1", CancellationToken.None);

        Assert.Equal(acme.Subject, fromAcme!.Subject);
        Assert.Equal(globex.Subject, fromGlobex!.Subject);
    }

    /// <summary>
    /// An account stored without a realm is in the default one, on both lookups.
    /// </summary>
    /// <remarks>
    /// <c>UserAccount.Realm</c> defaults rather than being a constructor parameter, so that adding
    /// it broke nothing. This is what makes that claim true of the stores rather than only of the
    /// record: every existing caller keeps working and lands in one named realm, not in a null one.
    /// </remarks>
    [Fact]
    public async Task An_account_stored_without_a_realm_is_in_the_default_realm()
    {
        var store = NewUserStore();
        var ada = Account();

        await store.StoreAsync(ada, CancellationToken.None);

        var byUsername = await store.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None);
        var bySubject = await store.FindBySubjectAsync(ada.Subject, CancellationToken.None);

        Assert.NotNull(byUsername);
        Assert.Equal(RealmId.Default, bySubject!.Realm);
    }

    // -------------------------------------------------------------------- roles

    /// <summary>An assigned role comes back on both lookups, by subject and by username.</summary>
    /// <remarks>
    /// Assigned after creation rather than at it, which is the shape of every role test here:
    /// <c>StoreAsync</c> refuses an account carrying roles, so assignment is <c>SetRolesAsync</c>'s
    /// job and nothing else's.
    /// </remarks>
    [Fact]
    public async Task A_role_set_at_creation_comes_back_on_both_lookups()
    {
        // Both, because the two lookups are two code paths in every implementation here — one
        // keyed by subject, one by a normalized username — and a store that updated only the
        // index it was written through would answer differently depending on how it was asked.
        var store = NewUserStore();

        await store.StoreAsync(Account(), CancellationToken.None);
        await store.SetRolesAsync(Account().Subject, ["founder"], CancellationToken.None);

        Assert.Equal(["founder"], (await store.FindBySubjectAsync(Subject("XY"), CancellationToken.None))!.Roles);
        Assert.Equal(["founder"], (await store.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None))!.Roles);
    }

    /// <summary>An account created without a role holds none, and the store supplies no default.</summary>
    [Fact]
    public async Task An_account_created_without_a_role_has_none_rather_than_a_default()
    {
        // Empty, not "user" and not one supplied by the store. A store that chose a default would
        // be choosing a vocabulary, and the resource server's fallback for an account holding
        // nothing is the resource server's decision.
        var store = NewUserStore();

        await store.StoreAsync(Account(), CancellationToken.None);

        Assert.Empty((await store.FindBySubjectAsync(Subject("XY"), CancellationToken.None))!.Roles);
    }

    /// <summary>
    /// Setting roles replaces them on both lookups, and leaves the credential, the address and the
    /// handle exactly as they were.
    /// </summary>
    [Fact]
    public async Task Setting_a_role_changes_it_on_both_lookups_and_leaves_the_credential_alone()
    {
        var store = NewUserStore();
        var ada = Account() with { Roles = ["editor"] };

        // Created holding none and assigned after, because creation does not assign.
        await store.StoreAsync(ada with { Roles = [] }, CancellationToken.None);
        await store.SetRolesAsync(ada.Subject, ada.Roles, CancellationToken.None);

        Assert.True(await store.SetRolesAsync(ada.Subject, ["founder"], CancellationToken.None));

        var bySubject = await store.FindBySubjectAsync(ada.Subject, CancellationToken.None);
        var byUsername = await store.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None);

        // Replaced, not added to. `editor` is gone, which is what "set" has to mean if taking a
        // role away is expressible at all.
        Assert.Equal(["founder"], bySubject!.Roles);
        Assert.Equal(["founder"], byUsername!.Roles);

        // The reason this is a targeted setter rather than an update method. A promotion that
        // quietly rewrote the password hash would lock someone out, and the lockout would be
        // blamed on the password rather than on the promotion.
        Assert.Equal(ada.PasswordHash, bySubject.PasswordHash);
        Assert.Equal(ada.Email, bySubject.Email);
        Assert.Equal(ada.Username, bySubject.Username);
    }

    /// <summary>Setting an empty set clears every role, and reports that it did.</summary>
    /// <remarks>
    /// The direction a replace-everything setter has to keep open. Taking a role away is expressible
    /// only because the set the caller passes is the set the account ends with.
    /// </remarks>
    [Fact]
    public async Task A_role_can_be_cleared()
    {
        var store = NewUserStore();
        var ada = Account() with { Roles = ["founder"] };

        // Created holding none and assigned after, because creation does not assign.
        await store.StoreAsync(ada with { Roles = [] }, CancellationToken.None);
        await store.SetRolesAsync(ada.Subject, ada.Roles, CancellationToken.None);

        Assert.True(await store.SetRolesAsync(ada.Subject, [], CancellationToken.None));
        Assert.Empty((await store.FindBySubjectAsync(ada.Subject, CancellationToken.None))!.Roles);
    }

    /// <summary>
    /// Setting a password hash changes it on both lookups, and leaves the roles, the address and the
    /// handle exactly as they were.
    /// </summary>
    [Fact]
    public async Task Setting_a_password_changes_it_on_both_lookups_and_leaves_everything_else_alone()
    {
        var store = NewUserStore();
        var ada = Account() with { Roles = ["founder"] };

        // Created holding none and assigned after, because creation does not assign.
        await store.StoreAsync(ada with { Roles = [] }, CancellationToken.None);
        await store.SetRolesAsync(ada.Subject, ada.Roles, CancellationToken.None);

        Assert.True(await store.SetPasswordHashAsync(ada.Subject, "$argon2id$new", CancellationToken.None));

        var bySubject = await store.FindBySubjectAsync(ada.Subject, CancellationToken.None);
        var byUsername = await store.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None);

        // Both, because sign-in arrives by username. A store that updated only the subject lookup
        // would leave the old password working and the new one refused, and report success.
        Assert.Equal("$argon2id$new", bySubject!.PasswordHash);
        Assert.Equal("$argon2id$new", byUsername!.PasswordHash);

        // The mirror of the role test above: a password reset that quietly rewrote the role would
        // be an authorization change nobody asked for, and nobody would think to look for it there.
        Assert.Equal(ada.Roles, bySubject.Roles);
        Assert.Equal(ada.Email, bySubject.Email);
        Assert.Equal(ada.Username, bySubject.Username);
        Assert.Equal(ada.Subject, bySubject.Subject);
    }

    /// <summary>An unknown subject reports false, and no account is created by the attempt.</summary>
    /// <remarks>
    /// The second assertion is the one worth making: a store that upserted here would mint an account
    /// holding a password and nothing else, and report success for a handle somebody mistyped.
    /// </remarks>
    [Fact]
    public async Task Setting_a_password_on_an_account_that_does_not_exist_says_so_rather_than_creating_one()
    {
        var store = NewUserStore();

        Assert.False(await store.SetPasswordHashAsync(Subject("ZZ"), "$argon2id$new", CancellationToken.None));
        Assert.Null(await store.FindBySubjectAsync(Subject("ZZ"), CancellationToken.None));
    }

    /// <summary>Assigning a role to a subject nothing stored reports false and creates no row.</summary>
    [Fact]
    public async Task Setting_a_role_on_an_account_that_does_not_exist_says_so_rather_than_creating_one()
    {
        // False, not an exception and not a new row. The caller's next move is to report a typo in
        // a handle; a store that created the account would hand a role to nobody and report success.
        var store = NewUserStore();

        Assert.False(await store.SetRolesAsync(Subject("ZZ"), ["founder"], CancellationToken.None));
        Assert.Null(await store.FindBySubjectAsync(Subject("ZZ"), CancellationToken.None));
    }

    // ------------------------------------------------------------------ lookups

    /// <summary>A stored account comes back whole from either lookup, field for field.</summary>
    [Fact]
    public async Task An_account_is_found_by_subject_and_by_username()
    {
        var store = NewUserStore();
        var ada = Account();

        await store.StoreAsync(ada, CancellationToken.None);

        // Compared with the roles normalised away, because a record carrying a collection has
        // reference equality on that member: `string[]` and the compiler's read-only list are equal
        // accounts holding equal roles, and `Assert.Equal` on the whole record says they differ.
        // The roles are asserted on their own, which is also the only form that says which half was
        // wrong when it fails.
        var bySubject = await store.FindBySubjectAsync(ada.Subject, CancellationToken.None);
        var byUsername = await store.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None);

        Assert.NotNull(bySubject);
        Assert.NotNull(byUsername);
        Assert.Equal(ada with { Roles = [] }, bySubject with { Roles = [] });
        Assert.Equal(ada with { Roles = [] }, byUsername with { Roles = [] });
        Assert.Equal(ada.Roles, bySubject.Roles);
        Assert.Equal(ada.Roles, byUsername.Roles);
    }

    /// <summary>
    /// All three lookups answer null for something nothing stored: subject, username and upstream
    /// identity alike.
    /// </summary>
    [Fact]
    public async Task An_account_not_stored_is_not_found()
    {
        // "Not there" and "could not tell" must not be the same answer. A store that invented an
        // account here would authenticate someone who does not exist.
        var store = NewUserStore();

        Assert.Null(await store.FindBySubjectAsync(Subject("ZZ"), CancellationToken.None));
        Assert.Null(await store.FindByUsernameAsync(RealmId.Default, "nobody", CancellationToken.None));
        Assert.Null(await store.FindByExternalLoginAsync(RealmId.Default, Google, "unknown", CancellationToken.None));
    }

    /// <summary>A username reaches its account whatever case it was typed in.</summary>
    [Theory]
    [InlineData("ADA")]
    [InlineData("Ada")]
    [InlineData("aDa")]
    public async Task A_username_lookup_ignores_case(string typed)
    {
        // What a person types at a login form is not what they registered with. Requiring an exact
        // match makes "wrong password" the message for a correct one.
        var store = NewUserStore();
        await store.StoreAsync(Account("ada"), CancellationToken.None);

        Assert.NotNull(await store.FindByUsernameAsync(RealmId.Default, typed, CancellationToken.None));
    }

    /// <summary>An empty username answers null rather than throwing.</summary>
    [Fact]
    public async Task An_empty_username_is_not_found_rather_than_an_error()
    {
        // Reached straight from a form field. An exception here is a 500 that anyone can provoke by
        // posting an empty form, and its shape would distinguish it from a wrong password.
        var store = NewUserStore();
        await store.StoreAsync(Account(), CancellationToken.None);

        Assert.Null(await store.FindByUsernameAsync(RealmId.Default, string.Empty, CancellationToken.None));
    }

    // ------------------------------------------------------------------ uniqueness

    /// <summary>
    /// A second account whose username differs from an existing one only by case is refused, not
    /// stored beside it.
    /// </summary>
    [Fact]
    public async Task A_second_account_with_the_same_username_is_refused_even_in_a_different_case()
    {
        // The rule the interface states in prose. Two rows differing only by case means which one a
        // login reaches depends on the store's collation — so two implementations would disagree on
        // identical input, and one of them would let an attacker register "Admin" beside "admin".
        var store = NewUserStore();
        await store.StoreAsync(Account("ada", "AA"), CancellationToken.None);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => store.StoreAsync(Account("ADA", "BB"), CancellationToken.None));
    }

    /// <summary>
    /// Storing an account whose subject is already taken is refused, and the account already there
    /// keeps its username and its credential.
    /// </summary>
    [Fact]
    public async Task Storing_an_existing_subject_is_refused_rather_than_replacing_its_credentials()
    {
        // Add-only, like every other store here. An upsert would let whoever reaches the
        // registration path overwrite an existing account's password hash, which is account
        // takeover; a relational store's primary key would throw, so tolerating it here would make
        // two implementations disagree.
        var store = NewUserStore();
        await store.StoreAsync(Account("ada", "AA", "$argon2id$v=19$m=64,t=1,p=1$AAECAwQFBgcICQoLDA0ODw$AAECAwQFBgcICQoLDA0ODw"), CancellationToken.None);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => store.StoreAsync(Account("someone-else", "AA", "$argon2id$v=19$m=64,t=1,p=1$DwEBAQEBAQEBAQEBAQEBAQ$AAECAwQFBgcICQoLDA0ODw"), CancellationToken.None));

        var still = await store.FindBySubjectAsync(Subject("AA"), CancellationToken.None);

        Assert.Equal("ada", still!.Username);
    }

    /// <summary>A blank username and an empty subject are both refused.</summary>
    /// <remarks>
    /// <see cref="ArgumentException"/> rather than the <see cref="InvalidOperationException"/> the
    /// uniqueness rules throw, and the two say different things: one that the caller passed something
    /// that is not an account, the other that the directory already holds one.
    /// </remarks>
    [Fact]
    public async Task An_account_needs_a_username_and_a_subject()
    {
        var store = NewUserStore();

        await Assert.ThrowsAsync<ArgumentException>(
            () => store.StoreAsync(Account(username: " "), CancellationToken.None));

        await Assert.ThrowsAsync<ArgumentException>(
            () => store.StoreAsync(
                new UserAccount(SubjectId.FromStorage(string.Empty), "ada", null, false, null),
                CancellationToken.None));
    }

    // ------------------------------------------------------------------ D-10: external logins

    /// <summary>
    /// D-10: an upstream identity resolves through the link somebody made for it, and the local
    /// subject is what comes back.
    /// </summary>
    /// <remarks>
    /// The property underneath it is the one federation rests on: a local account is reached by the
    /// <c>(issuer, subject)</c> pair and by nothing looser — never by the address the upstream
    /// asserted, which is the classic federated takeover. This measures the positive half. That no
    /// caller resolves a federated sign-in by address is enforced where the callers are, not here.
    /// </remarks>
    [Fact]
    public async Task An_upstream_identity_resolves_to_the_local_account_it_is_linked_to()
    {
        // The table D-10 requires from day one. The point is that the local `sub` stays OURS: an
        // upstream subject is joined to it, never passed through into a token.
        var store = NewUserStore();
        var ada = Account();
        await store.StoreAsync(ada, CancellationToken.None);

        await store.LinkExternalLoginAsync(
            new ExternalLogin(Google, "108120124820391284", ada.Subject), CancellationToken.None);

        var found = await store.FindByExternalLoginAsync(RealmId.Default, Google, "108120124820391284", CancellationToken.None);

        Assert.Equal(ada.Subject, found!.Subject);
    }

    /// <summary>
    /// The upstream issuer and subject are matched ordinally, so a differently-cased pair resolves to
    /// nothing rather than to the account the exact pair reaches.
    /// </summary>
    [Fact]
    public async Task An_upstream_subject_is_matched_ordinally()
    {
        // An upstream issuer and subject are opaque values chosen by someone else. Case-folding them
        // would merge two identities the upstream considers distinct, and on a provider whose
        // subjects are case-sensitive that is account takeover by registration.
        var store = NewUserStore();
        var ada = Account();
        await store.StoreAsync(ada, CancellationToken.None);

        await store.LinkExternalLoginAsync(new ExternalLogin(Google, "abcDEF", ada.Subject), CancellationToken.None);

        Assert.NotNull(await store.FindByExternalLoginAsync(RealmId.Default, Google, "abcDEF", CancellationToken.None));
        Assert.Null(await store.FindByExternalLoginAsync(RealmId.Default, Google, "ABCdef", CancellationToken.None));
        Assert.Null(await store.FindByExternalLoginAsync(RealmId.Default, Google.ToUpperInvariant(), "abcDEF", CancellationToken.None));
    }

    /// <summary>
    /// One account may hold links from several upstream issuers, and each of them resolves back to
    /// it.
    /// </summary>
    [Fact]
    public async Task One_account_may_carry_links_from_several_upstream_issuers()
    {
        // The direction that must stay open, and the reason the table is keyed on the pair rather
        // than on the local subject. Without it, a user who signs in with Google and later with
        // Facebook ends up with two accounts and half their data in each.
        var store = NewUserStore();
        var ada = Account();
        await store.StoreAsync(ada, CancellationToken.None);

        await store.LinkExternalLoginAsync(new ExternalLogin(Google, "g-1", ada.Subject), CancellationToken.None);
        await store.LinkExternalLoginAsync(
            new ExternalLogin("https://www.facebook.com", "f-1", ada.Subject), CancellationToken.None);

        Assert.Equal(ada.Subject, (await store.FindByExternalLoginAsync(RealmId.Default, Google, "g-1", CancellationToken.None))!.Subject);
        Assert.Equal(
            ada.Subject,
            (await store.FindByExternalLoginAsync(RealmId.Default, "https://www.facebook.com", "f-1", CancellationToken.None))!.Subject);
    }

    /// <summary>
    /// A link already pointing at one account cannot be repointed at another: the second link is
    /// refused, and the identity still resolves to the account that holds it.
    /// </summary>
    [Fact]
    public async Task An_upstream_identity_cannot_be_moved_to_a_different_account()
    {
        // The direction that must stay closed. If a link could be repointed, whoever can replay a
        // link request aims someone else's Google identity at an account of their choosing, and the
        // next federated sign-in lands inside that account's data.
        var store = NewUserStore();
        await store.StoreAsync(Account("ada", "AA"), CancellationToken.None);
        await store.StoreAsync(Account("grace", "BB"), CancellationToken.None);

        await store.LinkExternalLoginAsync(new ExternalLogin(Google, "g-1", Subject("AA")), CancellationToken.None);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => store.LinkExternalLoginAsync(new ExternalLogin(Google, "g-1", Subject("BB")), CancellationToken.None));

        Assert.Equal(Subject("AA"), (await store.FindByExternalLoginAsync(RealmId.Default, Google, "g-1", CancellationToken.None))!.Subject);
    }

    /// <summary>
    /// Linking the same identity to the same account a second time is accepted, and the identity
    /// still resolves.
    /// </summary>
    [Fact]
    public async Task Linking_the_same_identity_to_the_same_account_twice_is_not_an_error()
    {
        // Signing in through the same upstream identity a second time must not fail. Only pointing
        // it somewhere new is an error.
        var store = NewUserStore();
        var ada = Account();
        await store.StoreAsync(ada, CancellationToken.None);

        await store.LinkExternalLoginAsync(new ExternalLogin(Google, "g-1", ada.Subject), CancellationToken.None);
        await store.LinkExternalLoginAsync(new ExternalLogin(Google, "g-1", ada.Subject), CancellationToken.None);

        Assert.NotNull(await store.FindByExternalLoginAsync(RealmId.Default, Google, "g-1", CancellationToken.None));
    }

    /// <summary>A link naming a local account nothing stored is refused rather than left dangling.</summary>
    [Fact]
    public async Task A_link_to_an_account_that_does_not_exist_is_refused()
    {
        // The foreign key. A dangling link resolves to nothing at sign-in time, and the failure
        // surfaces as "your Google account is not connected" long after the mistake was made.
        var store = NewUserStore();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => store.LinkExternalLoginAsync(new ExternalLogin(Google, "g-1", Subject("ZZ")), CancellationToken.None));
    }

    /// <summary>
    /// An account carrying no password hash can be stored and linked, and comes back active — the
    /// shape an account reachable only through an upstream provider has.
    /// </summary>
    [Fact]
    public async Task An_account_with_no_password_can_still_be_linked()
    {
        // The account shape federation produces: no local password, reachable only through an
        // upstream provider. A store that required a password hash would make that unrepresentable.
        var store = NewUserStore();
        var federated = Account(passwordHash: null);

        await store.StoreAsync(federated, CancellationToken.None);
        await store.LinkExternalLoginAsync(new ExternalLogin(Google, "g-1", federated.Subject), CancellationToken.None);

        var found = await store.FindByExternalLoginAsync(RealmId.Default, Google, "g-1", CancellationToken.None);

        Assert.Null(found!.PasswordHash);
        Assert.True(found.IsActive);
    }

    // ------------------------------------------------------------------ disabled accounts

    /// <summary>
    /// A disabled account is still returned by a lookup and reports itself inactive, rather than being
    /// hidden.
    /// </summary>
    [Fact]
    public async Task A_disabled_account_is_still_found_but_reports_itself_inactive()
    {
        // Found, deliberately. The login endpoint checks IsActive itself, and a store that hid
        // disabled accounts would turn "your account is suspended" into "no such user" — which also
        // makes the timing of the two differ, since one path skips the hash.
        var store = NewUserStore();
        var suspended = Account() with { DisabledAt = DateTimeOffset.UnixEpoch };

        await store.StoreAsync(suspended, CancellationToken.None);

        var found = await store.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None);

        Assert.NotNull(found);
        Assert.False(found.IsActive);
    }

    // ------------------------------------------------------------------ anonymise

    /// <summary>
    /// Anonymising replaces every identifying field and keeps the row.
    /// </summary>
    /// <remarks>
    /// The row staying is the design, not an implementation detail: deleting a user with
    /// outstanding grants leaves dangling references, and an audit trail that empties when the
    /// audited party asks is not one. What a person is owed is that the account stops naming them.
    /// </remarks>
    [Fact]
    public async Task Anonymising_replaces_every_identifying_field_and_keeps_the_row()
    {
        var store = NewUserStore();
        var account = Account() with { Roles = ["founder"] };
        var at = DateTimeOffset.UnixEpoch.AddDays(1);

        // Created holding none and assigned after, because creation does not assign.
        await store.StoreAsync(account with { Roles = [] }, CancellationToken.None);
        await store.SetRolesAsync(account.Subject, account.Roles, CancellationToken.None);

        Assert.True(await store.AnonymiseAsync(
            account.Subject, "anonymised-x", at, CancellationToken.None));

        var found = await store.FindBySubjectAsync(account.Subject, CancellationToken.None);

        Assert.NotNull(found);
        Assert.Equal("anonymised-x", found.Username);
        Assert.Null(found.Email);
        Assert.False(found.EmailVerified);
        Assert.Null(found.PasswordHash);
        Assert.Empty(found.Roles);
        Assert.Equal(at, found.DisabledAt);
    }

    /// <summary>
    /// The old username stops resolving, and the tombstone starts.
    /// </summary>
    /// <remarks>
    /// Sign-in arrives by username. A store that changed only the subject index would leave the
    /// person's own name resolving to the tombstone — with no password on it, so the failure would
    /// read as "wrong password" rather than as a half-applied operation.
    /// </remarks>
    [Fact]
    public async Task Anonymising_moves_the_username_index()
    {
        var store = NewUserStore();
        var account = Account();

        await store.StoreAsync(account, CancellationToken.None);
        await store.AnonymiseAsync(
            account.Subject, "anonymised-x", DateTimeOffset.UnixEpoch, CancellationToken.None);

        Assert.Null(await store.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None));
        Assert.NotNull(await store.FindByUsernameAsync(RealmId.Default, "anonymised-x", CancellationToken.None));
    }

    /// <summary>
    /// External links are removed, not repointed.
    /// </summary>
    /// <remarks>
    /// Two reasons and both matter. A surviving link is the person's upstream subject still in the
    /// database, which is one of the identifiers this removes; and it is a live route back in — the
    /// next federated sign-in would resolve to the tombstone and be let through, since federation
    /// never asks for a password.
    /// </remarks>
    [Fact]
    public async Task Anonymising_removes_every_external_link()
    {
        var store = NewUserStore();
        var account = Account(passwordHash: null);

        await store.StoreAsync(account, CancellationToken.None);
        await store.LinkExternalLoginAsync(
            new ExternalLogin(Google, "g-1", account.Subject), CancellationToken.None);

        await store.AnonymiseAsync(
            account.Subject, "anonymised-x", DateTimeOffset.UnixEpoch, CancellationToken.None);

        Assert.Null(await store.FindByExternalLoginAsync(
            RealmId.Default, Google, "g-1", CancellationToken.None));
    }

    /// <summary>
    /// Anonymising the same account twice is not an error.
    /// </summary>
    /// <remarks>
    /// The tombstone is derived from the subject, so a second run writes the same username — which
    /// would be a unique-index violation if the store did not tolerate a row keeping its own name.
    /// An operator rerunning a command that failed halfway is exactly when this happens.
    /// </remarks>
    [Fact]
    public async Task Anonymising_twice_is_idempotent()
    {
        var store = NewUserStore();
        var account = Account();

        await store.StoreAsync(account, CancellationToken.None);

        Assert.True(await store.AnonymiseAsync(
            account.Subject, "anonymised-x", DateTimeOffset.UnixEpoch, CancellationToken.None));
        Assert.True(await store.AnonymiseAsync(
            account.Subject, "anonymised-x", DateTimeOffset.UnixEpoch, CancellationToken.None));
    }

    /// <summary>Anonymising an account that is not there reports it rather than throwing.</summary>
    [Fact]
    public async Task Anonymising_an_unknown_subject_reports_false()
    {
        var store = NewUserStore();

        Assert.False(await store.AnonymiseAsync(
            Subject("ZZ"), "anonymised-x", DateTimeOffset.UnixEpoch, CancellationToken.None));
    }

    /// <summary>
    /// A tombstoned handle can be taken by a new account.
    /// </summary>
    /// <remarks>
    /// The point of the operation from the directory's side: the name a person used is free again.
    /// It fails if the store leaves the old normalized username on the row, which is the mistake a
    /// store that only sets <c>Username</c> makes — invisible until somebody re-uses a handle.
    /// </remarks>
    [Fact]
    public async Task The_freed_handle_can_be_used_again()
    {
        var store = NewUserStore();
        var account = Account();

        await store.StoreAsync(account, CancellationToken.None);
        await store.AnonymiseAsync(
            account.Subject, "anonymised-x", DateTimeOffset.UnixEpoch, CancellationToken.None);

        await store.StoreAsync(Account(subjectSuffix: "ZZ"), CancellationToken.None);

        var found = await store.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None);

        Assert.Equal(Subject("ZZ"), found!.Subject);
    }
}
