using System.Collections.Frozen;
using System.Net;

namespace Boltway.AdminBff;

/// <summary>
/// Every sentence the admin pages say, and how a deployment replaces one.
/// </summary>
/// <remarks>
/// <para>
/// <b>This file exists because its own predecessor's reasoning stopped being true.</b> Pages.cs
/// said English only, on the grounds that "a second localization mechanism for an internal tool is
/// a cost with no reader". That was right when it was written and is not right now: the deployment
/// this ships to runs every other page in Vietnamese, and its operators are the two people who read
/// these. The cost was always real; what changed is that the reader appeared.
/// </para>
/// <para>
/// <b>Constants with English defaults, not a resx</b> - the same shape as
/// <c>Boltway.AuthorizationServer.Interaction.InteractionText</c>, and for the same reason:
/// satellite assemblies belong to the assembly that owns the resource file, so a customer could
/// never add a language to ours. English lives here and a missing translation falls back to it, one
/// string at a time.
/// </para>
/// <para>
/// <b>Per-string fallback is the property that matters.</b> A half-finished translation is a
/// half-translated page rather than a broken one - the deployment's own notes describe a founder
/// meeting a Vietnamese page with "Change your password" in the middle of it, which is this working
/// rather than failing. It is also why translating three sentences and leaving forty was not an
/// option: that is the same page, produced on purpose.
/// </para>
/// <para>
/// <b>A translation can never introduce markup.</b> <see cref="Format"/> encodes what the table
/// returns and then splices already-safe HTML into the <c>{0}</c> placeholder, so a deployment
/// supplies sentences and this file supplies structure.
/// </para>
/// </remarks>
public sealed class AdminText
{
    /// <summary>
    /// The one key in a translation file that is not a sentence: the language its sentences are in.
    /// </summary>
    /// <remarks>
    /// <c>$</c>-prefixed so it cannot collide with a real key - every constant on this class is a
    /// <c>nameof</c>, and no C# identifier starts with <c>$</c>.
    /// </remarks>
    public const string LanguageKey = "$language";

    /// <summary>The English pages, which is what a deployment gets before it configures anything.</summary>
    public static AdminText Default { get; } = new(new Dictionary<string, string>(StringComparer.Ordinal));

    private readonly IReadOnlyDictionary<string, string> _strings;

    /// <summary>The pages in a deployment's own words.</summary>
    /// <param name="strings">
    /// Key to sentence. Anything missing falls back to the English below rather than rendering the
    /// key, so a partial file is a partial translation. <see cref="LanguageKey"/> is the exception:
    /// it names the language rather than saying anything.
    /// </param>
    public AdminText(IReadOnlyDictionary<string, string> strings)
    {
        ArgumentNullException.ThrowIfNull(strings);
        _strings = strings;
    }

    /// <summary>
    /// The BCP 47 tag for the <c>lang</c> attribute - <c>en</c> unless the file says otherwise.
    /// </summary>
    /// <remarks>
    /// <para>
    /// It lives in the translation file rather than in its own environment variable so that the
    /// page's <c>lang</c> cannot disagree with the words on it. Two settings that must be kept in
    /// step is how a Vietnamese page ends up declaring itself English - which is not cosmetic: a
    /// screen reader pronounces the page with the wrong phonology, and a browser offers to
    /// translate it from a language it is not in.
    /// </para>
    /// <para>
    /// A file that does not say gets <c>en</c>, which is what its untranslated keys fall back to.
    /// That is wrong for a file translated into something else and silent about it - but it is the
    /// same answer the sentences themselves give, so the page stays internally consistent rather
    /// than claiming a language on no evidence.
    /// </para>
    /// </remarks>
    public string Language =>
        _strings.TryGetValue(LanguageKey, out var tag) && tag.Length > 0 ? tag : "en";

    /// <summary>Every key this build knows, for a deployment checking its file against it.</summary>
    public static IReadOnlyCollection<string> Keys => English.Keys;

    /// <summary>The sentence for a key, HTML-encoded and ready for the page.</summary>
    /// <param name="key">One of the constants on this class.</param>
    /// <exception cref="ArgumentOutOfRangeException">No such key. See <see cref="Plain"/>.</exception>
    public string this[string key] => WebUtility.HtmlEncode(Plain(key));

    /// <summary>The sentence for a key, <b>unencoded</b>, for a caller that encodes on its own.</summary>
    /// <param name="key">One of the constants on this class.</param>
    /// <remarks>
    /// <para>
    /// The indexer is the safe path and this is not - anything from here that reaches HTML without
    /// being encoded is an injection. It exists for one context: a <c>&lt;title&gt;</c>, which
    /// <see cref="IAdminLayout"/> encodes itself because the other thing it renders there is a handle
    /// an operator typed. <see cref="AdminPage.Title"/> is plain text for that reason.
    /// </para>
    /// <para>
    /// It was written because the alternative was a page whose tab read <c>T&amp;#224;i khoản</c>.
    /// Passing the indexer's output into something that encodes again is the double-encoding defect
    /// the authorization server's renderer documents, and it landed here the moment the titles
    /// stopped being English literals.
    /// </para>
    /// <para>
    /// <b>A key with no English behind it throws instead of rendering itself</b>, which is what
    /// <c>InteractionText.Default</c> in the library does and is the direction chosen on purpose.
    /// Returning the key is the quieter of the two and the more expensive: it puts
    /// <c>RoleHoldersTruncated</c> on a page as though it were a sentence, in front of the operator,
    /// with nothing in any log saying so - the same defect the library's <c>Localized</c> records
    /// arriving from a localizer that answers with the key, and the reason its fallback is explicit
    /// there. Throwing costs nothing a deployment can trip over, because the only keys that reach
    /// here are the constants on this class: a deployment's file is data on the other side of
    /// <see cref="Keys"/>, its unknown entries are warned about at startup and never looked up, and
    /// a missing one falls back to English one string at a time. What is left is a key this build
    /// ships with no sentence behind it, and <c>Every_key_is_reachable_from_a_page</c> renders every
    /// page in the suite - so that becomes a red test rather than a page an operator screenshots.
    /// </para>
    /// <para>
    /// A caller holding a string that <i>might</i> not be a key - the <c>?notice=</c> query
    /// parameter is the one - asks <see cref="NoticeKeys"/> first rather than handing it here.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">No such key.</exception>
    public string Plain(string key) =>
        _strings.TryGetValue(key, out var translated) && translated.Length > 0
            ? translated
            : English.TryGetValue(key, out var fallback)
                ? fallback
                : throw new ArgumentOutOfRangeException(nameof(key), key, "No such admin string.");

    /// <summary>A sentence with one already-safe value spliced into its <c>{0}</c>.</summary>
    /// <param name="key">One of the constants on this class.</param>
    /// <param name="value">Already-encoded HTML.</param>
    /// <remarks>
    /// The order is the safety: the sentence is encoded first, so braces survive and markup in a
    /// translation renders as the characters somebody typed, then the safe value replaces the
    /// placeholder.
    /// </remarks>
    public string Format(string key, string value) => this[key].Replace("{0}", value, StringComparison.Ordinal);

    // ── navigation and shell ────────────────────────────────────────────────

    /// <summary>The accounts link, and the accounts page's heading.</summary>
    public const string NavAccounts = nameof(NavAccounts);

    /// <summary>The roles link, and the roles page's heading.</summary>
    public const string NavRoles = nameof(NavRoles);

    /// <summary>The audit link, and the audit page's heading.</summary>
    public const string NavAudit = nameof(NavAudit);

    /// <summary>The button that ends the operator's own session.</summary>
    public const string SignOut = nameof(SignOut);

    // ── the account list ────────────────────────────────────────────────────

    /// <summary>The link to the create form, and that form's heading.</summary>
    public const string CreateAccount = nameof(CreateAccount);

    /// <summary>Column: what somebody types at sign-in.</summary>
    public const string ColumnHandle = nameof(ColumnHandle);

    /// <summary>Column: the address.</summary>
    public const string ColumnEmail = nameof(ColumnEmail);

    /// <summary>Column: the role string.</summary>
    public const string ColumnRole = nameof(ColumnRole);

    /// <summary>Column: whether the account may sign in.</summary>
    public const string ColumnState = nameof(ColumnState);

    /// <summary>The marker on a role this deployment privileges.</summary>
    public const string AdminBadge = nameof(AdminBadge);

    /// <summary>State: the account may sign in.</summary>
    public const string StateActive = nameof(StateActive);

    /// <summary>State: the account may not.</summary>
    public const string StateDisabled = nameof(StateDisabled);

    /// <summary>The cursor link to the next page of accounts.</summary>
    public const string NextPage = nameof(NextPage);

    // ── one account ─────────────────────────────────────────────────────────

    /// <summary>Label: the account's stable identifier.</summary>
    public const string FieldSubject = nameof(FieldSubject);

    /// <summary>Label: which directory the account is in.</summary>
    public const string FieldRealm = nameof(FieldRealm);

    /// <summary>Label: whether a password exists here.</summary>
    public const string FieldPassword = nameof(FieldPassword);

    /// <summary>A password exists. Not what it is.</summary>
    public const string PasswordSet = nameof(PasswordSet);

    /// <summary>No password here, because this account arrives through a provider.</summary>
    public const string PasswordNone = nameof(PasswordNone);

    /// <summary>Heading over the fields an operator may edit.</summary>
    public const string SectionChange = nameof(SectionChange);

    /// <summary>Heading over the three irreversible-ish buttons.</summary>
    public const string SectionOperations = nameof(SectionOperations);

    /// <summary>What an empty box means, shown in the box.</summary>
    public const string PlaceholderClear = nameof(PlaceholderClear);

    /// <summary>The button that saves the fields above it.</summary>
    public const string Apply = nameof(Apply);

    // ── what a role means ───────────────────────────────────────────────────

    /// <summary>This role is privileged. <c>{0}</c> is the list of roles that are.</summary>
    public const string RoleAdministers = nameof(RoleAdministers);

    /// <summary>This role is not. <c>{0}</c> is the list of roles that are.</summary>
    public const string RoleDoesNot = nameof(RoleDoesNot);

    // ── the two checkboxes ──────────────────────────────────────────────────

    /// <summary>Checkbox: somebody has proven the address belongs to this person.</summary>
    public const string EmailVerified = nameof(EmailVerified);

    /// <summary>What an unverified address costs, which is narrower than it sounds.</summary>
    public const string EmailVerifiedNote = nameof(EmailVerifiedNote);

    /// <summary>Checkbox: this account may still sign in.</summary>
    public const string SignInAllowed = nameof(SignInAllowed);

    /// <summary>What disabling does and - the part people miss - what it does not.</summary>
    public const string SignInAllowedNote = nameof(SignInAllowedNote);

    /// <summary>Heading for the service-account section.</summary>
    public const string SectionServiceAccount = nameof(SectionServiceAccount);

    /// <summary>Said when the account has none.</summary>
    public const string ServiceAccountNone = nameof(ServiceAccountNone);

    /// <summary>
    /// Label for the scopes box, used only when this app could not learn which scopes exist.
    /// </summary>
    /// <remarks>
    /// It names the separator because on that path an operator is typing a set rather than
    /// choosing one. <see cref="ServiceAccountScopesChoose"/> is the label when there is a list to
    /// choose from, and says nothing about separators because there is nothing to separate.
    /// </remarks>
    public const string ServiceAccountScopes = nameof(ServiceAccountScopes);

    /// <summary>Label for the scopes list, when the server published one.</summary>
    public const string ServiceAccountScopesChoose = nameof(ServiceAccountScopesChoose);

    /// <summary>
    /// That the ticked set is the whole grant, and that an empty one is refused.
    /// </summary>
    /// <remarks>
    /// Said before the button rather than discovered after it. The server refuses an empty set -
    /// a credential that can never obtain a token is worse than a refusal - and this is the
    /// sentence that stops an operator meeting that refusal at all.
    /// </remarks>
    public const string ServiceAccountScopesRequired = nameof(ServiceAccountScopesRequired);

    /// <summary>What a service account can do, said before it is created.</summary>
    public const string ServiceAccountCeiling = nameof(ServiceAccountCeiling);

    /// <summary>The create button.</summary>
    public const string ServiceAccountCreate = nameof(ServiceAccountCreate);

    /// <summary>Shown beside a secret that will never appear again.</summary>
    public const string ServiceAccountSecretOnce = nameof(ServiceAccountSecretOnce);

    /// <summary>Label for the enabled checkbox.</summary>
    public const string ServiceAccountEnabled = nameof(ServiceAccountEnabled);

    /// <summary>What turning it off does, and does not do.</summary>
    public const string ServiceAccountEnabledNote = nameof(ServiceAccountEnabledNote);

    /// <summary>The button that mints a new secret for an existing service account.</summary>
    /// <remarks>
    /// The answer to "I lost it", and the reason the plaintext being unrecoverable is a decision
    /// rather than a gap. The button is not called "create" a second time: the client id and the
    /// scopes survive, so nothing a deployed service is configured with changes except the one
    /// value it was always going to have to be given.
    /// </remarks>
    public const string ServiceAccountRotate = nameof(ServiceAccountRotate);

    /// <summary>
    /// What rotating does - and the two halves of it people get wrong in opposite directions.
    /// </summary>
    /// <remarks>
    /// Both clauses are load-bearing. That the old secret dies <i>immediately</i> is the half an
    /// operator assumes is a grace period, and every service still holding it stops at the next
    /// token request. That tokens already issued keep working is the half they assume rotation
    /// fixes, and it is the same sentence <see cref="ServiceAccountDeleteCaveat"/> and
    /// <see cref="OpSessionsCaveat"/> carry, for the same reason.
    /// </remarks>
    public const string ServiceAccountRotateCaveat = nameof(ServiceAccountRotateCaveat);

    /// <summary>The delete button.</summary>
    public const string ServiceAccountDelete = nameof(ServiceAccountDelete);

    /// <summary>What deleting costs.</summary>
    public const string ServiceAccountDeleteCaveat = nameof(ServiceAccountDeleteCaveat);

    /// <summary>The button beside a value that is about to be pasted somewhere else.</summary>
    public const string Copy = nameof(Copy);

    /// <summary>
    /// What that button says once it has done it.
    /// </summary>
    /// <remarks>
    /// A key rather than a string the script composes, because a script composing it would be the
    /// one sentence on these pages a deployment could not translate. It travels to the button as a
    /// <c>data-</c> attribute, which is why it goes through the encoding indexer like every other.
    /// </remarks>
    public const string CopyDone = nameof(CopyDone);

    // ── operations ──────────────────────────────────────────────────────────

    /// <summary>Mint a password and show it once.</summary>
    public const string OpPassword = nameof(OpPassword);

    /// <inheritdoc cref="OpPassword"/>
    public const string OpPasswordCaveat = nameof(OpPasswordCaveat);

    /// <summary>End every session this account has open.</summary>
    public const string OpSessions = nameof(OpSessions);

    /// <inheritdoc cref="OpSessions"/>
    public const string OpSessionsCaveat = nameof(OpSessionsCaveat);

    /// <summary>Turn the account into a tombstone.</summary>
    public const string OpAnonymise = nameof(OpAnonymise);

    /// <inheritdoc cref="OpAnonymise"/>
    public const string OpAnonymiseCaveat = nameof(OpAnonymiseCaveat);

    // ── the create form ─────────────────────────────────────────────────────

    /// <summary>The button that creates the account.</summary>
    public const string Create = nameof(Create);

    /// <summary>What happens to the password on creation.</summary>
    public const string CreateCaveat = nameof(CreateCaveat);

    // ── the audit table ─────────────────────────────────────────────────────

    /// <summary>Column: when it happened.</summary>
    public const string ColumnWhen = nameof(ColumnWhen);

    /// <summary>Column: who did it.</summary>
    public const string ColumnActor = nameof(ColumnActor);

    /// <summary>Column: what they did.</summary>
    public const string ColumnAction = nameof(ColumnAction);

    /// <summary>Column: which account it was done to.</summary>
    public const string ColumnTarget = nameof(ColumnTarget);

    /// <summary>Column: whether it worked.</summary>
    public const string ColumnOutcome = nameof(ColumnOutcome);

    /// <summary>Column: anything else worth recording.</summary>
    public const string ColumnDetail = nameof(ColumnDetail);

    // ── roles ───────────────────────────────────────────────────────────────

    /// <summary>
    /// That an id is fixed once it exists, said where somebody would look for a way to change it.
    /// </summary>
    /// <remarks>
    /// The field with no edit box beside it is the one that most needs explaining, and the
    /// explanation is not "we did not build it": an id reaches every token this realm has issued and
    /// both halves of <c>ADMIN_ROLES</c>, so changing it in one place changes what a resource server
    /// matches on in another.
    /// </remarks>
    public const string RoleIdFixed = nameof(RoleIdFixed);

    /// <summary>Label for the permissions box.</summary>
    public const string RolePermissions = nameof(RolePermissions);

    /// <summary>
    /// That the permission vocabulary belongs to whatever reads it, not to this server.
    /// </summary>
    /// <remarks>
    /// Why this is a box rather than a list of checkboxes, said on the page for the operator who
    /// wonders. The authorization server publishes scopes and does not publish permissions - they
    /// are the resource server's words, and offering a closed list would invent a rule nothing
    /// enforces.
    /// </remarks>
    public const string RolePermissionsNote = nameof(RolePermissionsNote);

    /// <summary>Label over the permission checkboxes, when the deployment listed a vocabulary.</summary>
    public const string RolePermissionsChoose = nameof(RolePermissionsChoose);

    /// <summary>
    /// The note under the picker, when there is one - replacing <see cref="RolePermissionsNote"/>,
    /// which says the server cannot offer a list and stops being true the moment one is offered.
    /// </summary>
    /// <remarks>
    /// Both clauses are load-bearing: that the list is the deployment's own copy rather than the
    /// server's rule, and that a held permission outside it still renders, ticked - because the
    /// operator who cannot see where an unlisted permission went will conclude it was lost.
    /// </remarks>
    public const string RolePermissionsListedNote = nameof(RolePermissionsListedNote);

    /// <summary>Label over the accounts that hold a role.</summary>
    public const string RoleHolders = nameof(RoleHolders);

    /// <summary>Said when no account holds the role - next to the delete button, on purpose.</summary>
    public const string RoleHoldersNone = nameof(RoleHoldersNone);

    /// <summary>The count on a role's row, with <c>{0}</c> as the number.</summary>
    public const string RoleHolderCount = nameof(RoleHolderCount);

    /// <summary>
    /// That the holder lists were computed from a directory bigger than this page walked.
    /// </summary>
    /// <remarks>
    /// Shown page-level when the account walk hit its cap. Without it, a role whose holders are
    /// all beyond the cap reads as held by nobody - on the page with the delete button.
    /// </remarks>
    public const string RoleHoldersTruncated = nameof(RoleHoldersTruncated);

    /// <summary>The heading over the form that defines a new role.</summary>
    public const string RoleCreate = nameof(RoleCreate);

    /// <summary>Label for the id of a role being defined.</summary>
    public const string RoleNewId = nameof(RoleNewId);

    /// <summary>That the id is chosen once, said on the form that chooses it.</summary>
    public const string RoleNewIdNote = nameof(RoleNewIdNote);

    /// <summary>Label for the display name.</summary>
    public const string RoleName = nameof(RoleName);

    /// <summary>That the name is only ever read by a person.</summary>
    public const string RoleNameNote = nameof(RoleNameNote);

    /// <summary>The button that defines the role.</summary>
    public const string RoleDefine = nameof(RoleDefine);

    /// <summary>The button that removes a role.</summary>
    public const string RoleDelete = nameof(RoleDelete);

    /// <summary>
    /// What removing a role does to the accounts holding it.
    /// </summary>
    /// <remarks>
    /// Both clauses are load-bearing and neither may be dropped. The assignments go with the
    /// definition - that is the store's documented behaviour, chosen so no row names a definition
    /// nobody can read - and an account left holding no role does not keep what it had.
    /// </remarks>
    public const string RoleDeleteCaveat = nameof(RoleDeleteCaveat);

    /// <summary>Said beside a role that <c>ADMIN_ROLES</c> names.</summary>
    public const string RoleAdminWarning = nameof(RoleAdminWarning);

    /// <summary>Said when the realm defines no roles at all.</summary>
    public const string RolesNone = nameof(RolesNone);

    // ── what just happened ──────────────────────────────────────────────────
    //
    // The banner a write redirects to its page with. These are the sentences that were literals in
    // Program.cs - written straight into `?notice=` and printed by the renderer - so every write in
    // a fully translated console produced one English line, which is the exact symptom this table
    // was built to stop.
    //
    // **Redirecting with the key rather than the sentence closes a second thing.** `?notice=` was
    // text from the query string reflected into the page, so any link could make this app's own
    // banner say anything: encoded, so never an injection, and still a sentence an operator reads as
    // their own console speaking. Now the parameter is matched against NoticeKeys and anything else
    // renders nothing at all - a crafted link can choose which of six sentences appears, and cannot
    // compose one. That property only holds while an unknown key renders nothing; echoing it back,
    // or handing it to the table, gives the channel straight back.
    //
    // The API's own refusals do not travel this way and must not start: `error_description` names
    // the rule that was broken, it is the authorization server's sentence rather than this app's,
    // and a write the API refused renders RenderRefusal - where the sentence comes out of the
    // response body instead of a query string somebody else can write.

    /// <summary>A write landed, and there is nothing more to say about it.</summary>
    public const string NoticeApplied = nameof(NoticeApplied);

    /// <summary>A role now exists.</summary>
    public const string NoticeDefined = nameof(NoticeDefined);

    /// <summary>A role or a service account is gone.</summary>
    public const string NoticeDeleted = nameof(NoticeDeleted);

    /// <summary>
    /// This app stopped before calling the API, and can say so.
    /// </summary>
    /// <remarks>
    /// The only refusal that reaches a banner, because it is the only one with no server sentence
    /// behind it - rotating a secret on an account whose service account is already gone, from a
    /// page that was open while somebody deleted it. It claims nothing was changed, and the claim is
    /// sound rather than assumed: the check runs ahead of the call, so there is no write whose
    /// outcome is unknown. Everything the API refused keeps the API's own words on the refusal page.
    /// </remarks>
    public const string NoticeRefused = nameof(NoticeRefused);

    /// <summary>
    /// Sessions ended, with <c>{0}</c> as the count.
    /// </summary>
    /// <remarks>
    /// The second clause is the same one <see cref="OpSessionsCaveat"/> and
    /// <see cref="SignInAllowedNote"/> carry and may not be dropped in a translation. An operator
    /// pressing this is usually working an incident, and "signed out" overstates what happened by
    /// one access-token lifetime.
    /// </remarks>
    public const string NoticeSessionsRevoked = nameof(NoticeSessionsRevoked);

    /// <summary>
    /// An account became a tombstone, with <c>{0}</c> as the handle it had.
    /// </summary>
    /// <remarks>
    /// Said on the account list, because the account page it was sent from no longer names anybody.
    /// The second clause answers the question the first one raises - why the row is still there -
    /// before an operator concludes the deletion half-failed.
    /// </remarks>
    public const string NoticeAnonymised = nameof(NoticeAnonymised);

    /// <summary>
    /// The keys an endpoint may put in <c>?notice=</c>, and the only ones a banner will render.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A closed set rather than <see cref="Keys"/>, which would be the obvious check and the wrong
    /// one: every sentence on these pages is in <see cref="Keys"/>, so a link could raise
    /// <see cref="NewPasswordOnlyTime"/> as a banner over a page with no password on it. What
    /// belongs here is what a write actually says when it finishes.
    /// </para>
    /// <para>
    /// Public because the check is part of the seam: a deployment replacing
    /// <see cref="IAdminRenderer"/> takes on this page's escaping obligations, and this is the one
    /// it cannot see by reading its own markup.
    /// </para>
    /// </remarks>
    public static IReadOnlySet<string> NoticeKeys { get; } = FrozenSet.ToFrozenSet(
        [NoticeApplied, NoticeDefined, NoticeDeleted, NoticeRefused, NoticeSessionsRevoked, NoticeAnonymised],
        StringComparer.Ordinal);

    // ── the pages that report a failure ─────────────────────────────────────

    /// <summary>The title of the page a refused request lands on.</summary>
    public const string RefusedTitle = nameof(RefusedTitle);

    /// <summary>Its heading, which is not the same sentence as its title.</summary>
    public const string RefusedHeading = nameof(RefusedHeading);

    /// <summary>
    /// What is said when the API refused without saying why.
    /// </summary>
    /// <remarks>
    /// A fallback, and rarely the one shown: this page prints the server's own
    /// <c>error_description</c> when there is one, because those sentences name the rule that was
    /// broken and a paraphrase composed here would lose the part an operator acts on. They are the
    /// authorization server's to translate, not this app's.
    /// </remarks>
    public const string RefusedUnexplained = nameof(RefusedUnexplained);

    /// <summary>Back to the account list, from the refusal page.</summary>
    public const string BackToAccounts = nameof(BackToAccounts);

    /// <summary>The title of the page showing a freshly generated password.</summary>
    public const string NewPasswordTitle = nameof(NewPasswordTitle);

    /// <summary>Its heading. <c>{0}</c> is the handle.</summary>
    public const string NewPasswordHeading = nameof(NewPasswordHeading);

    /// <summary>The sentence that has to land, because it is the only warning there is.</summary>
    public const string NewPasswordOnlyTime = nameof(NewPasswordOnlyTime);

    /// <summary>Back to the account the password belongs to.</summary>
    public const string BackToAccount = nameof(BackToAccount);

    /// <summary>
    /// English, and what a missing translation falls back to one string at a time.
    /// </summary>
    private static readonly Dictionary<string, string> English = new(StringComparer.Ordinal)
    {
        [NavAccounts] = "Accounts",
        [NavAudit] = "Audit",
        [SignOut] = "Sign out",

        [CreateAccount] = "Create an account",
        [ColumnHandle] = "Handle",
        [ColumnEmail] = "Email",
        [ColumnRole] = "Role",
        [ColumnState] = "State",
        [AdminBadge] = "admin",
        [StateActive] = "active",
        [StateDisabled] = "disabled",
        [NextPage] = "Next page",

        [FieldSubject] = "Subject",
        [FieldRealm] = "Realm",
        [FieldPassword] = "Password",
        [PasswordSet] = "set",
        [PasswordNone] = "none — signs in through a provider",
        [SectionChange] = "Change",
        [SectionOperations] = "Operations",
        [PlaceholderClear] = "- to clear",
        [SectionServiceAccount] = "Service account",
        [ServiceAccountNone] = "This account has no service account. One is a client id and secret "
            + "that obtain tokens as this person, with no browser and no sign-in.",
        [ServiceAccountScopes] = "Scopes, space separated",
        [ServiceAccountScopesChoose] = "Scopes",
        [ServiceAccountScopesRequired] =
            "It is issued exactly what is ticked here, so tick at least one.",
        [ServiceAccountCeiling] = "It will be able to do whatever this account's roles allow:",
        [ServiceAccountCreate] = "Create service account",
        [ServiceAccountSecretOnce] = "Copy the secret now. It is not stored and will not be shown "
            + "again; creating the service account again replaces it.",
        [ServiceAccountEnabled] = "May obtain tokens",
        [ServiceAccountEnabledNote] = "Turning this off stops new tokens immediately. Tokens already "
            + "issued keep working until they expire.",
        [ServiceAccountRotate] = "Issue a new secret",
        [ServiceAccountRotateCaveat] = "The client id and the scopes stay as they are. The old "
            + "secret stops working the moment the new one is issued; tokens already issued keep "
            + "working until they expire.",
        [ServiceAccountDelete] = "Delete service account",
        [ServiceAccountDeleteCaveat] = "The client id and secret stop working. Tokens already issued "
            + "keep working until they expire.",
        [Copy] = "Copy",
        [CopyDone] = "Copied",
        [Apply] = "Apply",

        [RoleAdministers] =
            "This role administers the directory. Changing it to anything outside {0} takes that away.",
        [RoleDoesNot] = "This role does not administer the directory. Only {0} does.",

        [EmailVerified] = "Email is verified",
        [EmailVerifiedNote] =
            "Only a verified address can be typed at sign-in. The handle always works.",
        [SignInAllowed] = "Sign-in is allowed",
        // The last clause used to read "— end every session to cut those off", and it was false.
        // `RevokeSessionsAsync` stops refresh chains; an access token is a signed JWT that no
        // resource server checks against a denylist, and `IGrantStore.IsRevokedAsync` has no
        // production caller in either repository - a test in Boltway.OAuth.Tokens.Tests says
        // so in as many words. `UserAdministration` says it too: "Refresh chains stop immediately;
        // access tokens do not… an operator responding to a compromise should know which of the
        // two they just did." The caveat on the button seven lines below already said the true
        // thing, so the page contradicted itself, and the reader most likely to be on it is an
        // operator working an incident.
        //
        // So it says what the button does, and how long the exposure lasts. The window matches
        // what the account holder is told on /me/sessions, which is the other half of this being
        // one story rather than two.
        [SignInAllowedNote] =
            "Clearing this refuses new sign-ins. Tokens already issued keep working until they "
            + "expire — up to about an hour — and ending every session stops them being renewed "
            + "rather than cutting off the ones already out.",

        [OpPassword] = "Generate a new password",
        [OpPasswordCaveat] = "The new password is shown once and cannot be shown again.",
        [OpSessions] = "End every session",
        [OpSessionsCaveat] = "Access tokens already issued keep working until they expire.",
        [OpAnonymise] = "Anonymise",
        [OpAnonymiseCaveat] =
            "Irreversible. The handle and address become a tombstone and every session ends.",

        [Create] = "Create",
        [CreateCaveat] = "A password is generated and shown once.",

        [ColumnWhen] = "When",
        [ColumnActor] = "Actor",
        [ColumnAction] = "Action",
        [ColumnTarget] = "Target",
        [ColumnOutcome] = "Outcome",
        [ColumnDetail] = "Detail",

        [NavRoles] = "Roles",
        [RoleIdFixed] = "The id cannot be changed. It is what tokens carry and what a resource "
            + "server matches on, so renaming one means defining a second role and moving accounts "
            + "to it.",
        [RolePermissions] = "Permissions, space separated",
        [RolePermissionsNote] = "These are the words whatever reads the token understands. This "
            + "server stores them and never interprets them, so it cannot offer a list.",
        [RolePermissionsChoose] = "Permissions",
        [RolePermissionsListedNote] = "This list is the deployment's own (ADMIN_PERMISSIONS), not "
            + "a rule the server enforces. A permission outside it that a role already holds still "
            + "renders here, ticked; granting a brand-new one starts by adding it to that list.",
        [RoleHolders] = "Held by",
        [RoleHoldersNone] = "No account holds this role.",
        [RoleHolderCount] = "held by {0}",
        [RoleHoldersTruncated] = "The holder lists count only the first accounts in the directory; "
            + "it is larger than this page walks. An empty list here does not mean nobody.",
        [RoleCreate] = "Define a role",
        [RoleNewId] = "Id",
        [RoleNewIdNote] = "Chosen once. No spaces — it is compared character for character against "
            + "a claim.",
        [RoleName] = "Name",
        [RoleNameNote] = "What refusals and this page call it. Only ever read by a person, so it "
            + "can be reworded or translated later.",
        [RoleDefine] = "Define",
        [RoleDelete] = "Delete role",
        [RoleDeleteCaveat] = "Every account holding this role loses it. An account left holding no "
            + "role keeps nothing it had.",
        [RoleAdminWarning] = "This role administers the directory. Deleting it takes that from "
            + "everyone who holds it, including you.",
        [RolesNone] = "This directory defines no roles yet. An account can only hold a role that "
            + "exists here.",

        [NoticeApplied] = "Applied.",
        [NoticeDefined] = "Defined.",
        [NoticeDeleted] = "Deleted.",
        [NoticeRefused] = "Refused. Nothing was changed — reload the page and try again.",
        [NoticeSessionsRevoked] = "{0} grant(s) revoked. Access tokens already issued keep working "
            + "until they expire.",
        [NoticeAnonymised] = "{0} is anonymised. The account row stays so the audit trail keeps its "
            + "referent.",

        [RefusedTitle] = "Refused",
        [RefusedHeading] = "That did not work",
        [RefusedUnexplained] = "The authorization server refused this.",
        [BackToAccounts] = "Back to the accounts",

        [NewPasswordTitle] = "New password",
        [NewPasswordHeading] = "New password for {0}",
        [NewPasswordOnlyTime] =
            "This is the only time it is shown. It is not stored in this form anywhere, and no page "
            + "can show it again.",
        [BackToAccount] = "Back to the account",
    };
}
