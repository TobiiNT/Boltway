using System.Xml.Linq;
using Mono.Cecil;

namespace Boltway.Architecture.Tests;

/// <summary>
/// Rules that hold across assemblies, checked against compiled IL.
/// </summary>
/// <remarks>
/// Each of these encodes a claim made elsewhere in prose. The reason they are here rather than in a
/// comment is that every one of them was, at some point in this repository's history, true in the
/// comment and false in the code.
/// </remarks>
public sealed class StructuralRuleTests
{
    /// <summary>
    /// Nothing the redirect <b>decision</b> reaches touches <see cref="Uri"/>, except to reject.
    /// </summary>
    /// <remarks>
    /// <para>
    /// N-03. RFC 3986 §6.2.1 requires redirect URI comparison to be Simple String Comparison on the
    /// raw bytes, and <see cref="Uri"/> is a normalizing type: it lowercases hosts, elides default
    /// ports, resolves dot segments, percent-decodes unreserved characters, and trims control
    /// characters including CR and LF. Every one of those maps several distinct strings onto one,
    /// which <i>widens</i> the set of URIs that match — an open redirector that leaks <c>code</c>
    /// and <c>state</c>.
    /// </para>
    /// <para>
    /// <b>Rooted at the pipeline stage, not at the matcher, and that is a correction.</b> Rooting it
    /// at <c>RedirectUriMatcher.Match</c> looked stronger and proved almost nothing: parsing happens
    /// <i>before</i> Match, in <c>RequestedRedirectUri.TryParse</c>, which is not reachable from it
    /// at all. Measured — introducing the exact documented bug, taking the host from
    /// <c>Uri.Host</c> instead of the raw string, left this file 7/7 green. The rule scoped to the
    /// one sliver of the decision that structurally could not contain the violation.
    /// </para>
    /// <para>
    /// From the stage, the walk does reach the parser, so the rule needs an allowlist. It is four
    /// members and they have a property in common: every one is used only to <b>reject</b> a value,
    /// never to produce one that a later comparison sees. Nothing here can widen a match.
    /// </para>
    /// </remarks>
    [Fact]
    public void The_redirect_decision_only_reaches_System_Uri_to_reject()
    {
        var stage = Il.Method(
            "Boltway.AuthorizationServer.Authorize.AuthorizePipeline", "TryValidateRedirectUri");

        var reached = Il.ReachableFrom(stage);

        Assert.Equal(0, Il.UnresolvedCallTargets);

        // Only our own methods. The walk descends into System.Uri's internals, where every call is
        // by definition a member of System.Uri calling another — a fact about the BCL, not about
        // this codebase. The rule is about what Boltway code asks Uri for.
        var violations = reached
            .Where(m => m.DeclaringType.FullName.StartsWith("Boltway.", StringComparison.Ordinal))
            .SelectMany(m => Il.ReferencesTo(m, "System.Uri"))
            .Where(reference => !PermittedUriMembers.Any(allowed => reference.Contains(allowed, StringComparison.Ordinal)))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        Assert.True(
            violations.Count == 0,
            "The redirect matching decision reaches a normalizing member of System.Uri:" + Environment.NewLine
            + string.Join(Environment.NewLine, violations));

        // Non-vacuity: the walk must actually reach the parser, or the allowlist above is guarding
        // an empty set and the rule proves nothing.
        Assert.Contains(
            reached,
            m => string.Equals(m.DeclaringType.FullName, "Boltway.OAuth.Primitives.Redirects.RedirectUriParts", StringComparison.Ordinal));
    }

    /// <summary>
    /// The only <see cref="Uri"/> members the redirect path may touch.
    /// </summary>
    /// <remarks>
    /// <c>TryCreate</c> answers "is this even a URI"; <c>Fragment</c>, <c>UserInfo</c> and
    /// <c>Port</c> are each read to refuse a value RFC 8252 or RFC 6749 forbids. None of them
    /// returns a string that a matching decision later compares — that is the whole distinction
    /// between this list and the banned members, which all return normalized values.
    /// </remarks>
    private static readonly string[] PermittedUriMembers =
    [
        "System.Boolean System.Uri::TryCreate",
        "System.String System.Uri::get_Fragment",
        "System.String System.Uri::get_UserInfo",
        "System.Int32 System.Uri::get_Port",
    ];

    /// <summary>
    /// A redirect error is built in one place.
    /// </summary>
    /// <remarks>
    /// The sibling of the <c>RedirectMatch</c> rule below, and it was missing. <c>ValidatedRedirect</c>
    /// is now a class with a private constructor, so a forged capability is <see langword="null"/>
    /// and <c>Create</c> throws — but "only the pipeline delivers an error by redirect" is a claim
    /// about call sites, and only a call-site rule keeps it.
    /// </remarks>
    [Fact]
    public void Only_the_authorize_pipeline_builds_a_redirect_error()
    {
        var callers = Il.CallersOf(m =>
            string.Equals(
                m.DeclaringType?.FullName,
                "Boltway.AuthorizationServer.Authorize.AuthorizeRedirectError",
                StringComparison.Ordinal)
            && string.Equals(m.Name, "Create", StringComparison.Ordinal));

        var strangers = callers
            .Where(c => !PermittedRedirectErrorCallers.Contains(c.Type, StringComparer.Ordinal))
            .ToList();

        Assert.True(
            strangers.Count == 0,
            "An error is delivered by redirect from outside the authorize pipeline and endpoint:" + Environment.NewLine
            + string.Join(Environment.NewLine, strangers.Select(s => "  " + s)));

        Assert.NotEmpty(callers);
    }

    /// <summary>
    /// The types that may deliver an authorization error by redirect.
    /// </summary>
    /// <remarks>
    /// The pipeline builds the ones its stages produce. The endpoint builds three more that no stage
    /// can: the <c>server_error</c> of the exception boundary, and the <c>login_required</c> /
    /// <c>consent_required</c> of stages 9 and 10, which are decisions about interaction rather than
    /// about the request. Anything else appearing here is a third place that can redirect a user
    /// somewhere, which is the thing this rule exists to notice.
    /// </remarks>
    private static readonly string[] PermittedRedirectErrorCallers =
    [
        "Boltway.AuthorizationServer.Authorize.AuthorizePipeline",
        "Boltway.AuthorizationServer.Endpoints.AuthorizeEndpoint",

        // The third entry, added when /consent landed. The consent POST must answer `access_denied`,
        // and it does so through AuthorizeResumption — which also owns stages 11 and 12 — so both
        // routes to finishing an authorization run the same code. The alternative was letting
        // InteractionEndpoints build the error itself, which is the same capability spread over one
        // more type. This rule failing on that change is the mechanism working: widening the list is
        // a diff a reviewer sees.
        "Boltway.AuthorizationServer.Interaction.AuthorizeResumption",
    ];

    /// <summary>
    /// Only the matcher can produce a successful <c>RedirectMatch</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the rule N-11 actually rests on, and it needs an IL scan rather than the
    /// <see langword="internal"/> keyword. <c>InternalsVisibleTo</c> is granted per assembly, not
    /// per member: a grant added so one assembly could mint a <c>ResourceIdentifier</c> also handed
    /// it <c>RedirectMatch.Exact</c>, and with that it could construct a <c>ValidatedRedirect</c>
    /// pointing anywhere — which is precisely the capability the authorize pipeline's ordering
    /// exists to withhold from its early stages.
    /// </para>
    /// <para>
    /// Measured: that grant existed, and a probe compiled against it. It has been removed, and this
    /// test is what stops the next one from reopening it silently.
    /// </para>
    /// </remarks>
    [Fact]
    public void Only_the_matcher_constructs_a_successful_redirect_match()
    {
        var callers = Il.CallersOf(m =>
            string.Equals(m.DeclaringType?.FullName, "Boltway.OAuth.Primitives.Redirects.RedirectMatch", StringComparison.Ordinal)
            && m.Name is "Exact" or "LoopbackPortIgnored");

        var strangers = callers
            .Where(c => !string.Equals(c.Type, "Boltway.OAuth.Primitives.Redirects.RedirectUriMatcher", StringComparison.Ordinal))
            .ToList();

        Assert.True(
            strangers.Count == 0,
            "A successful RedirectMatch is minted outside RedirectUriMatcher, so a ValidatedRedirect "
            + "can be forged and an error can be redirected to an unvalidated address:" + Environment.NewLine
            + string.Join(Environment.NewLine, strangers.Select(s => "  " + s)));

        // The rule is vacuous if the matcher stopped calling them, which is how a renamed factory
        // turns a guarantee into a green test.
        Assert.NotEmpty(callers);
    }

    /// <summary>
    /// The issuer is never derived from the request.
    /// </summary>
    /// <remarks>
    /// Two distinct failures share this cause. Behind a reverse proxy <c>Request.Scheme</c> is
    /// <c>http</c>, so every token is issued under an issuer no client accepts. And with host-header
    /// injection the attacker picks <c>Request.Host</c>, so tokens are minted under a name they
    /// control — which is a signing oracle, not a configuration mistake.
    /// </remarks>
    [Fact]
    public void The_server_never_reads_the_request_host_or_scheme()
    {
        var violations = Il.CallersOf(m =>
                string.Equals(m.DeclaringType?.FullName, "Microsoft.AspNetCore.Http.HttpRequest", StringComparison.Ordinal)
                && m.Name is "get_Host" or "get_Scheme")
            .ToList();

        Assert.True(
            violations.Count == 0,
            "The issuer must come from configuration, never from the request:" + Environment.NewLine
            + string.Join(Environment.NewLine, violations.Select(v => "  " + v)));
    }

    /// <summary>
    /// Nothing spawns a process.
    /// </summary>
    /// <remarks>
    /// Not because anything here wants to, but because "the dangerous thing does not exist" is a
    /// property that can be demonstrated, while "the dangerous thing is fenced off" has to be
    /// believed. The scan looks at IL rather than at source text, so it also sees a call that
    /// arrives through a wrapper library.
    /// </remarks>
    [Fact]
    public void Nothing_starts_a_process()
    {
        var violations = Il.CallersOf(m =>
                string.Equals(m.DeclaringType?.FullName, "System.Diagnostics.Process", StringComparison.Ordinal))
            .ToList();

        Assert.True(
            violations.Count == 0,
            "Something starts a process:" + Environment.NewLine
            + string.Join(Environment.NewLine, violations.Select(v => "  " + v)));
    }

    /// <summary>
    /// No security-relevant value comes from <see cref="Random"/>.
    /// </summary>
    /// <remarks>
    /// CA5394 catches this at compile time and is set to error, so this is the backstop for the case
    /// CA5394 cannot see: a <c>#pragma warning disable</c>, or a call arriving from a referenced
    /// assembly compiled without the analyzer.
    /// </remarks>
    [Fact]
    public void Nothing_uses_the_non_cryptographic_random()
    {
        var violations = Il.CallersOf(m =>
                string.Equals(m.DeclaringType?.FullName, "System.Random", StringComparison.Ordinal))
            .ToList();

        Assert.True(
            violations.Count == 0,
            "System.Random is not a cryptographic source; use RandomNumberGenerator:" + Environment.NewLine
            + string.Join(Environment.NewLine, violations.Select(v => "  " + v)));
    }

    /// <summary>
    /// <c>TokenValidationParameters</c> is constructed in exactly one place.
    /// </summary>
    /// <remarks>
    /// N-09. The library leaves <c>ValidTypes</c> and <c>ValidAlgorithms</c> unset by default, so a
    /// second construction site is a validator that accepts an ID token where an access token was
    /// required, or a token signed with an algorithm this server never issues. One site means one
    /// place to read to know what is accepted.
    /// </remarks>
    [Fact]
    public void Token_validation_parameters_have_one_construction_site()
    {
        var callers = Il.CallersOf(m =>
                string.Equals(
                    m.DeclaringType?.FullName,
                    "Microsoft.IdentityModel.Tokens.TokenValidationParameters",
                    StringComparison.Ordinal)
                && string.Equals(m.Name, ".ctor", StringComparison.Ordinal))
            .ToList();

        var strangers = callers
            .Where(c => !c.Type.StartsWith("Boltway.OAuth.Tokens.Rfc9068ValidationParameters", StringComparison.Ordinal))
            .ToList();

        Assert.True(
            strangers.Count == 0,
            "TokenValidationParameters is built outside Rfc9068ValidationParameters, where ValidTypes "
            + "and ValidAlgorithms are pinned:" + Environment.NewLine
            + string.Join(Environment.NewLine, strangers.Select(s => "  " + s)));

        Assert.NotEmpty(callers);
    }

    /// <summary>
    /// No redirect preserves the request method. N-12.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 9700 §4.12 and OAuth 2.1 §7.5.3: a redirect after a request that carried credentials or a
    /// consent decision must be <c>303 See Other</c>, so the browser re-issues it as a GET. A 307 or
    /// 308 preserves the method <b>and the body</b> — so the username, the password or the consent
    /// form is re-sent to wherever the <c>Location</c> points, which on the error path is a URL the
    /// client chose.
    /// </para>
    /// <para>
    /// A rule over IL rather than over the one place that redirects today. Measured before this
    /// existed: emitting 307 from <c>AuthorizeResults</c> left the architecture suite 8/8 green — the
    /// flow tests went red, but only because every redirect happened to funnel through a single
    /// helper. The moment a second redirect site appears, for a consent page or a logout, the rule
    /// that was supposed to cover it is the one that does not exist.
    /// </para>
    /// </remarks>
    [Fact]
    public void No_redirect_preserves_the_request_method()
    {
        var offenders = new List<string>();

        foreach (var (assembly, type, method) in Il.AllMethods())
        {
            if (!method.HasBody)
            {
                continue;
            }

            foreach (var instruction in method.Body.Instructions)
            {
                // The status codes appear in IL as ldc.i4 operands. Reading them from the constant
                // pool catches `307`, `StatusCodes.Status307TemporaryRedirect` and anything else
                // that compiles down to the same number, which a source grep would not.
                if (instruction.Operand is int status and (307 or 308))
                {
                    offenders.Add($"  {type.FullName}.{method.Name} emits {status}  [{assembly.Name.Name}]");
                }
            }
        }

        Assert.True(
            offenders.Count == 0,
            "A method-preserving redirect re-sends the request body to the Location, which after a "
            + "credential or consent POST means re-sending the credential:" + Environment.NewLine
            + string.Join(Environment.NewLine, offenders));
    }

    /// <summary>
    /// The rule above can actually see a status code in IL.
    /// </summary>
    /// <remarks>
    /// Its control. A scan for integer operands finds nothing if the compiler stored the constants
    /// somewhere the walk does not reach, and "found no 307" would then be indistinguishable from
    /// "cannot see any status code at all". 303 is the one this server does emit.
    /// </remarks>
    [Fact]
    public void The_redirect_rule_can_see_a_status_code()
    {
        var found = Il.AllMethods()
            .Where(m => m.Method.HasBody)
            .SelectMany(m => m.Method.Body.Instructions)
            .Any(i => i.Operand is 303);

        Assert.True(found, "No 303 was visible in IL, so the 307/308 rule is scanning nothing.");
    }

    /// <summary>
    /// Only a resource registry mints a <c>ResourceIdentifier</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// N-01 says the server must never invent an audience. The chokepoint used to be the
    /// <see langword="internal"/> keyword on <c>ResourceIdentifier.TryRegister</c>, and that failed
    /// in both directions at once. It leaked, because <c>InternalsVisibleTo</c> is granted per
    /// assembly and the grant added for this method also exposed <c>RedirectMatch.Exact</c> — see
    /// <see cref="Only_the_matcher_constructs_a_successful_redirect_match"/>. And it over-tightened,
    /// because the server assembly was never on the grant list, so no assembly a customer could own
    /// could implement the public <c>IResourceRegistry</c> at all. Measured symptom:
    /// <c>CS0117: 'ResourceIdentifier' does not contain a definition for 'TryRegister'</c>.
    /// </para>
    /// <para>
    /// So the method is public and this rule is what constrains it: a call may only come from a type
    /// that implements <c>IResourceRegistry</c>. That is the honest shape of the guarantee — a build
    /// gate over this solution's own code, not a property of the type system. It stops the failure
    /// N-01 is actually about, which is <i>this library</i> stamping a house default audience on the
    /// customer's behalf where no client could ever detect it. It does not, and should not, constrain
    /// a customer's own registry: deciding which resources exist is that type's entire job.
    /// </para>
    /// </remarks>
    [Fact]
    public void Only_a_resource_registry_mints_a_resource_identifier()
    {
        const string Target = "Boltway.OAuth.Primitives.Ids.ResourceIdentifier";
        const string Registry = "Boltway.AuthorizationServer.Abstractions.Resources.IResourceRegistry";

        // The one type that mints a ResourceIdentifier without being a registry, and the reason it
        // is a different act.
        //
        // N-01 is about the *minting* path: an authorization server deciding, on a user's behalf and
        // undetectably, which resources a token it signs will be accepted at. A resource server
        // declaring which resource it *is* is the opposite direction — it is the assertion that
        // defines the role, it is read from that deployment's own configuration, and an RS-only
        // deployment holds no signing key and has no mint path to reach. Refusing it would mean a
        // resource server could not name itself.
        //
        // Listed rather than pattern-matched. This rule went red when the resource server landed,
        // which is the mechanism working: a new holder of the capability is a diff a reviewer sees,
        // and the argument for it has to be written down before the list grows.
        string[] permitted = ["Boltway.ResourceServer.Configuration.ProtectedResource"];

        List<string> callers = [];
        List<string> strangers = [];

        foreach (var (assembly, type, method) in Il.AllMethods())
        {
            if (!method.HasBody)
            {
                continue;
            }

            var mints = method.Body.Instructions.Any(i =>
                i.Operand is MethodReference called
                && string.Equals(called.DeclaringType?.FullName, Target, StringComparison.Ordinal)
                && string.Equals(called.Name, "TryRegister", StringComparison.Ordinal));

            if (!mints)
            {
                continue;
            }

            // The call is emitted into a closure or state machine for anything async or lambda-bound,
            // so the question "which type is this" has to be asked of the outermost declaring type —
            // and the interface check has to be asked of the definition that carries the interface.
            var owner = type;

            while (owner.DeclaringType is { } parent)
            {
                owner = parent;
            }

            var where = $"{owner.FullName}.{method.Name}  [{assembly.Name.Name}]";
            callers.Add(where);

            var isRegistry = owner.Interfaces.Any(
                i => string.Equals(i.InterfaceType.FullName, Registry, StringComparison.Ordinal));

            if (!isRegistry && !permitted.Contains(owner.FullName, StringComparer.Ordinal))
            {
                strangers.Add(where);
            }
        }

        Assert.True(
            strangers.Count == 0,
            "A ResourceIdentifier is minted outside an IResourceRegistry implementation. That is how "
            + "'accept the resource parameter and ignore it' and 'stamp a house default audience' get "
            + "back into the server — and RFC 8707 registers no metadata field, so no client can "
            + "detect it:" + Environment.NewLine
            + string.Join(Environment.NewLine, strangers.Select(s => "  " + s)));

        // The control. If TryRegister is renamed, or the shipped registry stops calling it, the
        // search above runs over nothing and reports success — which is the exact failure mode the
        // N-03 rule was caught in when it was rooted at the matcher instead of at the pipeline stage.
        Assert.NotEmpty(callers);
    }

    /// <summary>
    /// Only <c>Boltway.OAuth.Net</c> talks to the network.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>FetchOutcome.cs</c> has always said: <i>"An architecture test asserts that no assembly
    /// other than Boltway.OAuth.Net references System.Net.Http at all, and the exception list
    /// for that rule is empty — which is what makes 'every outbound fetch is guarded' checkable
    /// rather than a claim."</i> <c>DESIGN.md</c> says the same. The test did not exist, which made
    /// the guarantee exactly the claim it said it was not.
    /// </para>
    /// <para>
    /// It passes on the first run, so there is no live violation — the point is the next one. A
    /// review demonstrated it concretely: a <c>JwksFetcher</c> with a bare <c>new HttpClient()</c>,
    /// dereferencing the <c>jwks_uri</c> that the CIMD document parser already stores, was added to
    /// <c>Boltway.AuthorizationServer</c>. The full solution built green, every test passed,
    /// and pointed at two loopback listeners it followed a cross-address 302 and returned the
    /// internal body. That commit is half-written already: <c>private_key_jwt</c> needs a JWKS
    /// fetch, and C-03 marks it MUST for ChatGPT.
    /// </para>
    /// <para>
    /// The ban is on the whole namespace rather than on <c>HttpClient</c>, because
    /// <c>HttpMessageInvoker</c>, <c>SocketsHttpHandler</c> and <c>HttpRequestMessage</c> each reach
    /// the network without naming <c>HttpClient</c> once.
    /// </para>
    /// </remarks>
    [Fact]
    public void Only_the_guarded_fetcher_touches_system_net_http()
    {
        const string Guarded = "Boltway.OAuth.Net";

        var violations = Il.CallersOf(m =>
                m.DeclaringType?.FullName?.StartsWith("System.Net.Http.", StringComparison.Ordinal) is true)
            .Where(c => !string.Equals(c.Assembly, Guarded, StringComparison.Ordinal))
            .Where(c => !PermittedDirectHttpCallers.Contains(c.Type, StringComparer.Ordinal))
            .ToList();

        Assert.True(
            violations.Count == 0,
            "An assembly other than " + Guarded + " reaches System.Net.Http directly, so its request "
            + "is not subject to the redirect refusal, the address check, the byte cap or the "
            + "timeouts that make 'every outbound fetch is guarded' true:" + Environment.NewLine
            + string.Join(Environment.NewLine, violations.Select(v => "  " + v)));

        // The control. This rule is a search for absence, and an absence is also what a scan that
        // stopped looking reports — so assert the scanner can still see the one assembly that is
        // supposed to be full of these calls.
        var guarded = Il.CallersOf(m =>
                m.DeclaringType?.FullName?.StartsWith("System.Net.Http.", StringComparison.Ordinal) is true)
            .Where(c => string.Equals(c.Assembly, Guarded, StringComparison.Ordinal))
            .ToList();

        Assert.True(
            guarded.Count > 0,
            $"No System.Net.Http call was found in {Guarded} either, so this rule is scanning nothing.");
    }

    /// <summary>
    /// The one type that reaches <c>System.Net.Http</c> without going through the guarded fetcher.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This list was empty, and that was most of the rule's value, so widening it costs this
    /// comment.</b> The rule protects fetches of an <i>attacker-supplied</i> URL — a CIMD document,
    /// somebody else's JWKS — where redirect refusal, the special-use address check and the byte cap
    /// are what stand between a URL a stranger chose and a request to something internal.
    /// </para>
    /// <para>
    /// <b>Introspection is the other kind of outbound call, and the guards would break it rather
    /// than protect it.</b> The endpoint is configured by the operator, not carried in by a request;
    /// it is a POST with a body and a credential, which <c>ISafeHttpFetcher</c> has no shape for;
    /// and the address check would <i>refuse</i> the intended topology, where the resource server
    /// and the authorization server are two containers on one host and the endpoint is a private
    /// address. Routing it through the fetcher would be a security control applied to the wrong
    /// threat, and its only effect would be to make the correct deployment impossible.
    /// </para>
    /// <para>
    /// What keeps this narrow: it names a type rather than an assembly, so the rest of
    /// <c>Boltway.ResourceServer</c> is held to the ban exactly as before, and a second class
    /// there reaching the network is still a red test.
    /// </para>
    /// </remarks>
    private static readonly string[] PermittedDirectHttpCallers =
    [
        "Boltway.ResourceServer.Revocation.IntrospectionRevocationCheck",
    ];

    /// <summary>
    /// An error response can only be produced by the type that logs it. A-09.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>DESIGN.md</c> §1.2 said the <c>Rejection</c> type made A-09 structural, and §6 put it on
    /// the never-cut list. Neither the type nor the property existed. A review with a capturing
    /// <c>ILoggerProvider</c> at Trace level measured what was actually there: two
    /// <c>[LoggerMessage]</c> declarations in the whole of <c>src/</c>, both for abandoned or
    /// crashed requests, and <b>twenty-five rejection classes emitting nothing at all</b> — sixteen
    /// on the authorization server, nine on the resource server, with no correlation id anywhere in
    /// a resource-server response.
    /// </para>
    /// <para>
    /// The fix is a chokepoint, and a chokepoint is worth exactly as much as the rule that says it
    /// is the only one. Two searches, because there are two ways to write a 4xx:
    /// </para>
    /// <list type="number">
    /// <item><description>
    /// <b>Through the table.</b> Every OAuth error response needs its wire string, its status and
    /// its requirement id from <c>OAuthErrors.Resolve</c>. One caller per server assembly, and both
    /// of them log before they write.
    /// </description></item>
    /// <item><description>
    /// <b>Around the table.</b> A hand-written <c>Response.StatusCode = 400</c> would not call
    /// <c>Resolve</c> at all, so the first search cannot see it. Status codes reach IL as
    /// <c>ldc.i4</c> operands — <c>StatusCodes.Status400BadRequest</c> is a <c>const</c> and
    /// compiles to the same instruction as the literal — so a scan of the constant pool catches
    /// what a source grep would not. Same mechanism as the 307/308 rule above, which has its own
    /// control.
    /// </description></item>
    /// </list>
    /// <para>
    /// Scoped to the two server assemblies. <c>Primitives</c> holds the table itself, which is
    /// nothing but these constants, and <c>OAuth.Net</c> reads status codes off responses it fetched
    /// rather than writing them.
    /// </para>
    /// </remarks>
    [Fact]
    public void Only_the_rejection_writer_produces_an_error_response()
    {
        var resolvers = Il.CallersOf(m =>
                string.Equals(m.DeclaringType?.FullName, "Boltway.OAuth.Primitives.Errors.OAuthErrors", StringComparison.Ordinal)
                && string.Equals(m.Name, "Resolve", StringComparison.Ordinal))
            .ToList();

        var strangers = resolvers
            .Where(c => !PermittedRejectionWriters.Contains(c.Type, StringComparer.Ordinal))
            .ToList();

        Assert.True(
            strangers.Count == 0,
            "An OAuth error response is built outside the rejection writer, so it is delivered without "
            + "the structured log line and the X-Request-Id header that A-09 requires:" + Environment.NewLine
            + string.Join(Environment.NewLine, strangers.Select(s => "  " + s)));

        // The control for the first search. If Resolve is renamed or the writers stop calling it,
        // the scan above runs over nothing and reports success — the exact failure the N-03 rule was
        // caught in when it was rooted at the matcher instead of at the pipeline stage.
        Assert.Equal(
            PermittedRejectionWriters.Length,
            resolvers.Select(r => r.Type).Distinct(StringComparer.Ordinal).Count());

        var literals = new List<string>();
        var seen = 0;

        foreach (var (assembly, type, method) in Il.AllMethods())
        {
            if (!method.HasBody || !ServerAssemblies.Contains(assembly.Name.Name, StringComparer.Ordinal))
            {
                continue;
            }

            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.Operand is not int status || status is < 400 or > 599)
                {
                    continue;
                }

                seen++;

                var owner = Il.OutermostType(type);

                if (!PermittedRejectionWriters.Contains(owner, StringComparer.Ordinal)
                    && !PermittedStatusLiterals.Contains(owner, StringComparer.Ordinal))
                {
                    literals.Add($"  {owner}.{method.Name} carries {status}  [{assembly.Name.Name}]");
                }
            }
        }

        Assert.True(
            literals.Count == 0,
            "A 4xx or 5xx status is written outside the rejection writer. That response is not logged "
            + "and carries no correlation id, which is how A-09 was false for twenty-five rejection "
            + "classes while DESIGN.md said it was structural:" + Environment.NewLine
            + string.Join(Environment.NewLine, literals.Distinct(StringComparer.Ordinal)));

        // The control for the second search, and it is the one the 307/308 rule needed a separate
        // test for: a scan for integer operands finds nothing if the walk cannot see the constant
        // pool, and "found no stray 4xx" would then be indistinguishable from "cannot see a status
        // code at all".
        Assert.True(seen > 0, "No 4xx/5xx constant was visible in either server assembly, so this rule is scanning nothing.");
    }

    /// <summary>The assemblies that write protocol responses.</summary>
    private static readonly string[] ServerAssemblies =
    [
        "Boltway.AuthorizationServer",
        "Boltway.ResourceServer",
    ];

    /// <summary>
    /// The two types that may turn a rejection into a response.
    /// </summary>
    /// <remarks>
    /// One per server, because the two are separate deployables that share only a BCL-only assembly
    /// — see the note in <c>Boltway.ResourceServer/Diagnostics/RejectionLog.cs</c> for why the
    /// log declaration is duplicated rather than shared. Both emit the same event id, the same
    /// template and the same property names.
    /// </remarks>
    private static readonly string[] PermittedRejectionWriters =
    [
        "Boltway.AuthorizationServer.Diagnostics.RejectionResult",
        "Boltway.ResourceServer.Bearer.BearerChallenge",
    ];

    /// <summary>
    /// The methods that may carry a 4xx constant without being a rejection writer.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The first two are the same answer on the two servers: "this server publishes no document at
    /// this path". RFC 9728 §3.1 and RFC 8414 §3.1 make a client probe several well-known URLs in
    /// order, and a 404 is what tells it to try the next one. They carry no <c>error</c> member, no
    /// description and nothing derived from the request — there is no diagnostic content for a
    /// rejection to hold, and routing them through the writer would mean inventing error-table rows
    /// for a response that has no error code.
    /// </para>
    /// <para>
    /// Written down rather than pattern-matched on the status, so that the list is a diff a
    /// reviewer sees. That is the mechanism the <c>ResourceIdentifier</c> rule above describes:
    /// widening the allowlist should cost an argument in a comment.
    /// </para>
    /// </remarks>
    private static readonly string[] PermittedStatusLiterals =
    [
        "Boltway.AuthorizationServer.Endpoints.WellKnownNotFoundResult",
        "Boltway.ResourceServer.Endpoints.WellKnownNotFoundResult",

        // Added when rate limiting landed, and the distinction is real rather than a concession.
        // The rule looks for a status constant because writing one is how a response escapes the
        // rejection writer — but this type never writes a status. It *reads* one: a remote origin
        // answering 500 or 429 to a CIMD fetch is a transient failure worth serving a stale document
        // through, while a 404 is the origin saying the client is gone. Those two numbers describe
        // somebody else's response, not ours.
        //
        // The rule cannot tell the difference — an `ldc.i4` is an `ldc.i4` — so this is exactly the
        // kind of entry that has to carry its reasoning. If a future change makes this type write a
        // response, the allowlist will hide it, and that is the cost being accepted here.
        "Boltway.AuthorizationServer.Clients.CimdClientResolver",

        // The readiness probe's 503, and it meets the criterion in the first paragraph rather than
        // asking for an exception to it: no `error` member, no description, and — the part that
        // matters — nothing derived from the request. Every caller gets the same answer, because it
        // describes the server's store and not anything they sent.
        //
        // Routing it through the rejection writer would mean minting an OAuth error-table row for a
        // response that is not a protocol error, and it would log once per poll: a monitor at one
        // request a minute would write 1,440 correlation ids a day to say nothing changed. The line
        // worth having is the one StoreReadiness already writes — once per cache window, carrying
        // the exception the response deliberately does not.
        //
        // The status has to be the signal. 200 with `ok:false` is an uptime check that stays green
        // through the outage it exists to catch, which is the failure this endpoint was added to
        // remove.
        //
        // Accepted cost, stated because this list demands it: if this type is ever given a second
        // response that *is* a rejection, this entry hides it.
        "Boltway.AuthorizationServer.Diagnostics.AuthorizationServerReadinessEndpoint",

        // The administrative surface, and this entry is the one that has to argue hardest, because
        // an unlogged 401 on an admin API is precisely the shape A-09 exists to prevent.
        //
        // So it is not unlogged. `AdminEndpoints.Refuse` writes a warning carrying the failure kind,
        // the required scope, the path and the correlation id, for every refusal — the obligation is
        // met directly rather than by the shared writer. That matters most for the refusals that
        // never reach the service and therefore never reach the audit log: a cookie principal, or a
        // token minted for another resource, is somebody probing the directory, and the audit table
        // will never mention it.
        //
        // Why not the writer: these are not OAuth protocol errors. There is no row in the error
        // table for "no such account" or "handle taken", no `error` code a client branches on, and
        // no redirect. Minting rows would put administrative concerns in the shared OAuth error
        // surface, where every other endpoint would then have to reason about them.
        //
        // Accepted cost, stated because this list demands it: a response added to this type in
        // future is hidden by this entry, and the 401/403 logging is a line in a method rather than
        // a property of a type.
        "Boltway.AuthorizationServer.Endpoints.AdminEndpoints",

        // The self-service surface, on the same terms and with one difference worth naming rather
        // than inheriting.
        //
        // `AccountEndpoints.Refuse` writes the same warning for every refusal — failure kind, path,
        // correlation id — so the A-09 obligation is met directly here too. The difference is which
        // refusals matter: on `/admin` an unlogged 401 is somebody probing the directory, and here
        // it is somebody probing one account. Smaller, and not nothing — the one that has to be
        // visible is a run of `wrong_password` against a subject, which is a stolen token being
        // converted into a permanent credential. That one is not merely logged, it is audited:
        // `UserAdministration.ChangePasswordAsync` records it as a refusal, because no sign-in
        // happened and the sign-in log will never show it.
        //
        // Why not the writer, same as above: "no such session" and "no local password" are not
        // OAuth protocol errors and have no row in the error table.
        //
        // Accepted cost, stated because this list demands it: a response added to this type in
        // future is hidden by this entry.
        "Boltway.AuthorizationServer.Endpoints.AccountEndpoints",

        // OpenID Connect's UserInfo endpoint, and it argues from the two above rather than adding a
        // new direction: `UserInfoEndpoint` writes a warning on every refusal carrying the failure
        // kind and the correlation id, so the A-09 obligation is met directly rather than by the
        // shared writer.
        //
        // The refusal worth seeing here is narrower than either of theirs and worth naming. This
        // endpoint is reached with an access token the caller already holds, so a refusal is rarely
        // somebody probing — it is far more often a client configured against the wrong scopes, and
        // a run of `InsufficientScope` from one client_id is a misconfiguration that presents to a
        // person as "signing in works and I have no permissions". Without the line, the only
        // evidence is on the client's side, which is the side that does not know what it asked for.
        //
        // Why not the writer, same as the two above: `invalid_token` here is RFC 6750's, not a row
        // in the OAuth authorization error table, and there is no redirect and no `error` a client
        // branches on beyond retrying with a different grant.
        //
        // Accepted cost, stated because this list demands it: a response added to this type in
        // future is hidden by this entry.
        "Boltway.AuthorizationServer.Endpoints.UserInfoEndpoint",

        // The public recovery endpoints, and this entry argues from a different direction than the
        // two above: those refuse a caller who has authenticated wrongly, and these refuse one who
        // has not authenticated at all, because nobody on this surface can.
        //
        // A-09's obligation is that a refusal is visible and joinable. Here it is met by the audit
        // log rather than by a log line: `AccountRecovery` records every request and every
        // redemption, found or not — `user.password.forgot` with "no such account" is the entry that
        // makes a run of probes visible, and it exists precisely because the response deliberately
        // does not distinguish them.
        //
        // Why not the writer: `S-48` forbids it. The rejection writer produces an OAuth error
        // response with a code a caller can branch on, and the whole design of E-39 is that the
        // answer carries no information about what was found. A 404 for an unknown address is the
        // oracle this endpoint exists to close, so routing it through the shared writer would be
        // routing it into the defect.
        //
        // The 429 is the throttle's, and it is the one refusal here that is honest about why: it
        // describes the caller's own rate and nothing about any account.
        //
        // Accepted cost, stated because this list demands it: a response added to this type in
        // future is hidden by this entry.
        "Boltway.AuthorizationServer.Endpoints.RecoveryEndpoints",
    ];

    /// <summary>
    /// Every <c>src/</c> project that contains code is in the scan.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>Il.AssemblyNames</c> discovers what is beside the test binary, which is only what this test
    /// project references — so an unreferenced project is silently unscanned, and every rule in this
    /// file reports green over it. Measured before this test existed: an unguarded
    /// <c>new HttpClient()</c> planted in <c>Boltway.Storage.InMemory</c> broke nothing, because
    /// that assembly was not there to look at.
    /// </para>
    /// <para>
    /// Discovery replaced a hand-written list to stop it going stale; this is the other half, because
    /// discovery over an incomplete directory has exactly the same failure mode and is harder to see.
    /// The fix when this fails is a <c>ProjectReference</c> in this project's csproj — and that is
    /// deliberately a diff someone writes rather than something that happens quietly.
    /// </para>
    /// <para>
    /// Empty projects are skipped rather than required: four of the twelve <c>src/</c> projects are a
    /// <c>.csproj</c> and nothing else, and demanding a reference to an assembly with no code would
    /// be ceremony. They come into scope the moment they contain a single file.
    /// </para>
    /// </remarks>
    [Fact]
    public void Every_project_with_code_is_scanned()
    {
        var root = AuthRoot();
        var src = Path.Combine(root, "src");

        var withCode = Directory.EnumerateDirectories(src)
            .Where(d => Directory.EnumerateFiles(d, "*.cs", SearchOption.AllDirectories)
                .Any(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                       && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal)))
            .Select(Path.GetFileName)
            .Select(n => n!)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        // The control: if the walk found no projects at all — a moved directory, a changed layout —
        // the assertion below is vacuously true and this rule has stopped meaning anything.
        Assert.True(withCode.Count >= 5, $"Only {withCode.Count} src projects with code were found under {src}.");

        var missing = withCode.Except(Il.AssemblyNames, StringComparer.Ordinal).ToList();

        Assert.True(
            missing.Count == 0,
            "These src projects contain code and are not scanned by any architecture rule, so every "
            + "ban in this file passes over them silently. Add a ProjectReference in "
            + "Boltway.Architecture.Tests.csproj:" + Environment.NewLine
            + string.Join(Environment.NewLine, missing.Select(m => "  " + m)));
    }

    /// <summary>Walk up from the test binary to the <c>auth/</c> directory.</summary>
    /// <remarks>
    /// By shape rather than by a relative path with a fixed number of <c>..</c> segments, because
    /// that count changes with the target framework and the configuration in the output path — and a
    /// path that silently resolves to nothing turns the test above into a pass.
    /// </remarks>
    private static string AuthRoot()
    {
        var directory = new DirectoryInfo(Path.GetDirectoryName(typeof(StructuralRuleTests).Assembly.Location)!);

        while (directory is not null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, "src"))
                && Directory.Exists(Path.Combine(directory.FullName, "tests")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        Assert.Fail("Could not find the auth/ root above the test binary.");
        return null!;
    }

    /// <summary>
    /// Every project under <c>auth/</c> says whether it packs.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This rule exists because a number was counted off these files and came out wrong.</b> The
    /// version comment in <c>Directory.Build.props</c> said sixteen packages moved together from the
    /// day it was written; <c>dotnet pack</c> produces seventeen. Sixteen is exactly how many
    /// projects declared <c>IsPackable</c>, and the seventeenth — <c>Boltway.OAuth.Net</c> —
    /// packed by saying nothing at all, because packing is what the SDK does with a library unless
    /// told otherwise.
    /// </para>
    /// <para>
    /// So the rule is not "declare it because it is tidy". It is that <b>the set of things this
    /// repository publishes must be readable from the files</b>. A published package cannot be
    /// unpublished in any way that helps, which makes "what goes to the feed" a question that has to
    /// be answerable before the push rather than by reading the push's output afterwards.
    /// </para>
    /// <para>
    /// Both values satisfy it, and a test project writing <c>false</c> is not ceremony: two of them
    /// inherit <c>false</c> from <c>Microsoft.NET.Test.Sdk</c>, which is the same kind of invisible
    /// default that hid the seventeenth package, pointing the other way. A default nobody can see is
    /// the thing being banned, not a particular value.
    /// </para>
    /// </remarks>
    [Fact]
    public void Every_project_says_whether_it_packs()
    {
        var root = AuthRoot();

        var projects = Directory.EnumerateFiles(root, "*.csproj", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                     && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToList();

        // The control, on the same reasoning as the walk above: a rule that found no projects would
        // pass by looking at nothing, and it would keep passing after the layout moved under it.
        Assert.True(projects.Count >= 20, $"Only {projects.Count} projects were found under {root}.");

        var silent = projects
            .Where(f => XDocument.Load(f).Descendants("IsPackable").All(e => e.Value.Trim().Length == 0))
            .Select(f => Path.GetRelativePath(root, f))
            .ToList();

        Assert.True(
            silent.Count == 0,
            "These projects do not say whether they pack, so what this repository publishes cannot "
            + "be read off the files — only off the output of a pack that has already happened. Add "
            + "<IsPackable>true</IsPackable> or <IsPackable>false</IsPackable>:" + Environment.NewLine
            + string.Join(Environment.NewLine, silent.Select(s => "  " + s)));
    }


    /// <summary>
    /// Every assembly under test was actually loaded.
    /// </summary>
    /// <remarks>
    /// The control for this whole file. Every rule above is a search for violations, and a search
    /// over nothing finds nothing — so a build change that stopped copying an assembly beside the
    /// tests would turn all of them green at once.
    /// </remarks>
    [Fact]
    public void Every_assembly_under_test_is_loaded_and_has_code()
    {
        Assert.Equal(Il.AssemblyNames.Count, Il.Assemblies.Count);

        foreach (var assembly in Il.Assemblies)
        {
            var methods = Il.AllMethods().Count(m => m.Assembly == assembly);
            Assert.True(methods > 0, $"{assembly.Name.Name} contributed no methods to the scan.");
        }
    }

    /// <summary>
    /// The test assemblies that hold an <c>InternalsVisibleTo</c> grant, and no others.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Default-deny, which is the opposite of the list in <see cref="Il.AssemblyNames"/> and
    /// deliberately so.</b> That one was hand-maintained and a missing entry silently removed
    /// coverage; this one fails when an entry is missing, because the rule bans every
    /// <c>*.Tests</c> grant that is not named here. A new test project is therefore protected on
    /// the day it builds, without anyone remembering — and adding a grant to one is an edit to this
    /// list, made by someone who has to read the paragraph below first.
    /// </para>
    /// <para>
    /// Every name here is a test assembly that legitimately reaches inside the thing it tests. What
    /// must never join them is an assembly whose job is to prove a seam is reachable from outside:
    /// <c>Boltway.PublicApi.Tests</c>, which exists solely to compile against the public
    /// surface, and <c>Boltway.Interaction.Tests</c> and <c>Boltway.Storage.Tests</c>,
    /// which ship to customers as packages and must compile against exactly what a customer has. A
    /// grant to any of those three would not fail a test — it would make their compilation stop
    /// meaning anything, which is the failure mode the whole arrangement exists to prevent.
    /// </para>
    /// </remarks>
    private static readonly HashSet<string> TestAssembliesAllowedToSeeInternals = new(StringComparer.Ordinal)
    {
        "Boltway.AuthorizationServer.Tests",
        "Boltway.OAuth.Net.Tests",
        "Boltway.OAuth.Primitives.Tests",
        "Boltway.OAuth.Tokens.Tests",
        "Boltway.ResourceServer.Tests",
    };

    /// <summary>
    /// No shipped assembly hands its internals to a test assembly that is not on the list.
    /// </summary>
    /// <remarks>
    /// Read from compiled IL rather than from the <c>.csproj</c> files, because the grant that
    /// matters is the one in the assembly. A property group that sets it conditionally, or a
    /// <c>Directory.Build.props</c> that adds one for a whole folder, would be invisible to a scan
    /// of project files and completely visible here.
    /// </remarks>
    [Fact]
    public void No_unapproved_test_assembly_can_see_a_shipped_assemblys_internals()
    {
        List<string> unapproved = [];

        foreach (var assembly in Il.Assemblies)
        {
            foreach (var attribute in assembly.CustomAttributes.Where(IsInternalsVisibleTo))
            {
                if (attribute.ConstructorArguments.Count == 0
                    || attribute.ConstructorArguments[0].Value is not string granted)
                {
                    continue;
                }

                // The assembly name only: a grant on a signed assembly carries a PublicKey too.
                var name = granted.Split(',')[0].Trim();

                if (name.EndsWith(".Tests", StringComparison.Ordinal)
                    && !TestAssembliesAllowedToSeeInternals.Contains(name))
                {
                    unapproved.Add($"{assembly.Name.Name} -> {name}");
                }
            }
        }

        Assert.True(
            unapproved.Count == 0,
            "These grants let a test assembly see internals it is not approved for. If the target is "
            + "a customer's-eye assembly (PublicApi.Tests, Interaction.Tests, Storage.Tests), the "
            + "grant is the defect. Otherwise add it to TestAssembliesAllowedToSeeInternals:\n  "
            + string.Join("\n  ", unapproved));
    }

    /// <summary>
    /// The control for the rule above: the approved list describes grants that exist.
    /// </summary>
    /// <remarks>
    /// A default-deny list rots in the one direction its own rule cannot see. An entry for an
    /// assembly that no longer holds a grant is a standing permission nobody is using, and the next
    /// person to read it concludes the grant is required. This is what makes removing a grant also
    /// remove the permission for it.
    /// </remarks>
    [Fact]
    public void Every_approved_internals_grant_is_one_that_exists()
    {
        var granted = Il.Assemblies
            .SelectMany(assembly => assembly.CustomAttributes.Where(IsInternalsVisibleTo))
            .Where(attribute => attribute.ConstructorArguments.Count > 0)
            .Select(attribute => attribute.ConstructorArguments[0].Value as string)
            .Where(value => value is not null)
            .Select(value => value!.Split(',')[0].Trim())
            .ToHashSet(StringComparer.Ordinal);

        var stale = TestAssembliesAllowedToSeeInternals.Except(granted, StringComparer.Ordinal).ToList();

        Assert.True(
            stale.Count == 0,
            "These names are approved to see internals but no assembly grants it. Remove them: "
            + string.Join(", ", stale));
    }

    /// <summary>
    /// Only the sign-in form resolves an account by address. Never federation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The federation takeover this exists to keep impossible:</b> an attacker registers the
    /// victim's address at an upstream that does not verify addresses, signs in there, and — if the
    /// callback resolved the upstream identity to a local account by email — is handed the victim's
    /// account. <c>email_verified</c> in someone else's token is a claim about their own users, not
    /// a proof about ours.
    /// </para>
    /// <para>
    /// <b>This rule replaces a stronger-looking one that has stopped being available.</b>
    /// <c>ExternalLoginFlowTests</c> used to assert that <c>IUserStore</c> had no email lookup at
    /// all, on the reasoning that an absent method cannot be called from anywhere. That was the
    /// right guard while it held, and it stopped holding when signing in with a verified address
    /// became a feature — the sign-in form needs exactly the lookup federation must not have.
    /// </para>
    /// <para>
    /// So the guard moved from the interface's shape to the property that was always the point:
    /// <i>who calls it</i>. That is a narrower statement to make and a stronger one to keep — the
    /// old rule would have passed a federation callback that resolved by username, and this one
    /// names the callers. The allowlist is one type; anything else is a diff a reviewer sees, which
    /// is what the original rule said it was for.
    /// </para>
    /// </remarks>
    [Fact]
    public void Only_the_sign_in_form_resolves_an_account_by_address()
    {
        var callers = Il.CallersOf(m =>
            string.Equals(m.Name, "FindByVerifiedEmailAsync", StringComparison.Ordinal));

        var strangers = callers
            .Where(c => !PermittedAddressResolvers.Contains(c.Type, StringComparer.Ordinal))
            .ToList();

        Assert.True(
            strangers.Count == 0,
            "An account is resolved by email address outside the sign-in form. If this is a "
            + "federation path, it is the takeover described on this test: an attacker registers "
            + "the victim's address at an upstream that does not verify it and inherits the "
            + "account." + Environment.NewLine
            + string.Join(Environment.NewLine, strangers.Select(s => "  " + s)));

        // The control. A renamed method would empty the list and report a pass, which is the one
        // way an absence assertion fails silently — the same control the rule it replaces carried.
        Assert.NotEmpty(callers);
    }

    /// <summary>The types that may resolve an account from an address.</summary>
    /// <remarks>
    /// One entry, and adding a second is the decision this test exists to make deliberate. The
    /// storage implementations are not here because they <i>are</i> the method rather than callers
    /// of it; a store calling its own lookup is not a resolution path anybody reaches.
    /// </remarks>
    private static readonly string[] PermittedAddressResolvers =
    [
        "Boltway.AuthorizationServer.Endpoints.InteractionEndpoints",
    ];

    private static bool IsInternalsVisibleTo(CustomAttribute attribute) =>
        string.Equals(
            attribute.AttributeType.FullName,
            "System.Runtime.CompilerServices.InternalsVisibleToAttribute",
            StringComparison.Ordinal);
}
