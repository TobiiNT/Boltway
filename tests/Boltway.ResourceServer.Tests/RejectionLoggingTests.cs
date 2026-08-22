using System.Net;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Tokens;
using Boltway.ResourceServer.Diagnostics;
using Microsoft.Extensions.Logging;

namespace Boltway.ResourceServer.Tests;

/// <summary>
/// A-09 on the resource server, which is where it was furthest from true.
/// </summary>
/// <remarks>
/// <para>
/// Nine rejection classes, zero log lines, and no correlation id in any response at all. The worst
/// of it was <c>invalid_token</c>: an unparseable JWT, a signature that does not verify, a
/// <c>kid</c> naming no configured key, an <c>iss</c> mismatch and a <c>typ</c> that is not
/// <c>at+jwt</c> all rendered the same <c>"The access token is not valid."</c> — correctly, since
/// none of it is the client's business — while the discriminating
/// <c>SecurityTokenException</c> was computed inside the validator and dropped. A customer who
/// rotated a signing key and forgot <c>ProtectedResourceOptions.SigningKeys</c> got an undiagnosable
/// wall of 401s, with the library's own answer, <c>IDX10500: No security keys were provided</c>,
/// written nowhere.
/// </para>
/// <para>
/// So this file asserts two things that the authorization-server suite does not have to: that the
/// four failures which share one response are told apart in the log, and that the log names the
/// exception the client is deliberately not told about.
/// </para>
/// </remarks>
public sealed class RejectionLoggingTests
{
    /// <summary>One rejection class, and how to force it.</summary>
    private sealed record Scenario(
        ReasonCode Reason,
        Func<Task<ResourceServerFixture>> Fixture,
        Func<ResourceServerFixture, Task<HttpResponseMessage>> Act);

    private static Task<ResourceServerFixture> Plain() => ResourceServerFixture.StartAsync();

    private static Task<HttpResponseMessage> WithHeader(
        ResourceServerFixture fixture, string path, string authorization)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, new Uri(path, UriKind.Relative));
        request.Headers.TryAddWithoutValidation("Authorization", authorization);

        return fixture.Client.SendAsync(request);
    }

    private static IReadOnlyList<Scenario> Scenarios() =>
    [
        new(ReasonCode.BearerCredentialAbsent, Plain,
            f => f.Client.GetAsync(new Uri("/mcp", UriKind.Relative))),

        new(ReasonCode.BearerCredentialMalformed, Plain,
            f => WithHeader(f, "/mcp", "Bearer ")),

        new(ReasonCode.AccessTokenExpired, Plain,
            f => WithHeader(f, "/mcp", "Bearer " + Mint.AccessToken(
                lifetime: TimeSpan.FromMinutes(-30), issuedAt: DateTimeOffset.UtcNow.AddHours(-1)))),

        new(ReasonCode.AccessTokenWrongAudience, Plain,
            f => WithHeader(f, "/mcp", "Bearer " + Mint.AccessToken(Build.Resolve(Build.OtherResource)))),

        new(ReasonCode.AccessTokenRejected, Plain,
            f => WithHeader(f, "/mcp", "Bearer " + Mint.AccessToken(key: TestKeys.Stranger))),

        new(ReasonCode.InsufficientScope, Plain,
            f => WithHeader(f, "/mcp/write", "Bearer " + Mint.AccessToken())),
    ];

    /// <summary>
    /// Every rejection class: one line, the right reason, and the id on the response.
    /// </summary>
    /// <remarks>
    /// The same four properties the authorization-server suite checks, asserted the same way, so
    /// that "one query returns both halves of a failed connection" is something the tests hold
    /// rather than something the comments claim.
    /// </remarks>
    [Fact]
    public async Task Every_rejection_emits_one_line_carrying_the_id_that_is_in_the_response()
    {
        var failures = new List<string>();

        foreach (var scenario in Scenarios())
        {
            await using var fixture = await scenario.Fixture();
            using var response = await scenario.Act(fixture);

            var rejections = fixture.Logs.Rejections;

            if (rejections.Count != 1)
            {
                failures.Add(
                    $"  {scenario.Reason}: expected exactly one rejection line, got {rejections.Count} "
                    + $"for HTTP {(int)response.StatusCode}");
                continue;
            }

            var line = rejections[0];

            if (!string.Equals(line.Property("Reason"), scenario.Reason.ToString(), StringComparison.Ordinal))
            {
                failures.Add($"  {scenario.Reason}: the line says Reason={line.Property("Reason")}");
            }

            if (!string.Equals(line.Category, RejectionLog.LoggerCategory, StringComparison.Ordinal))
            {
                failures.Add($"  {scenario.Reason}: logged under category {line.Category}");
            }

            var correlationId = line.Property("CorrelationId");

            if (string.IsNullOrEmpty(correlationId))
            {
                failures.Add($"  {scenario.Reason}: the line carries no CorrelationId property");
                continue;
            }

            if (!response.Headers.TryGetValues(DiagnosticHeaders.RequestId, out var header))
            {
                failures.Add($"  {scenario.Reason}: the response carries no X-Request-Id header");
                continue;
            }

            var returned = header.Single();

            if (!string.Equals(returned, correlationId, StringComparison.Ordinal))
            {
                failures.Add(
                    $"  {scenario.Reason}: the response says X-Request-Id={returned} and the log says "
                    + $"CorrelationId={correlationId}, so they do not join");
            }

            // "Exactly one" measured the way an operator would measure it: grep the id and count.
            // The event-id filter above cannot see a second line about the same refusal written
            // under a different event, and that is not a hypothetical — the authorize endpoint used
            // to log X-10 itself, so restoring that line would produce two lines for one refusal and
            // leave the event-id count at one.
            var mentioning = fixture.Logs.Mentioning(correlationId);

            if (mentioning.Count != 1)
            {
                failures.Add(
                    $"  {scenario.Reason}: {mentioning.Count} log lines name the correlation id, not one: "
                    + string.Join(" | ", mentioning.Select(m => $"[{m.Category}/{m.EventId.Name}]")));
            }
        }

        Assert.True(
            failures.Count == 0,
            "A-09 is not satisfied on these rejection classes:" + Environment.NewLine
            + string.Join(Environment.NewLine, failures));
    }

    /// <summary>
    /// Every <see cref="ReasonCode"/> this server can emit is exercised above.
    /// </summary>
    /// <remarks>
    /// The resource server's six are all reachable over HTTP, so unlike the authorization server's
    /// list there is no excused set here — and saying so is the point: an empty escape hatch is
    /// worth more than a populated one.
    /// </remarks>
    [Fact]
    public void Every_reason_this_server_emits_is_covered()
    {
        var covered = Scenarios().Select(s => s.Reason).ToHashSet();

        ReasonCode[] emitted =
        [
            ReasonCode.BearerCredentialAbsent,
            ReasonCode.BearerCredentialMalformed,
            ReasonCode.AccessTokenExpired,
            ReasonCode.AccessTokenWrongAudience,
            ReasonCode.AccessTokenRejected,
            ReasonCode.InsufficientScope,
        ];

        Assert.Equal(emitted.Order(), covered.Order());
    }

    /// <summary>
    /// Four causes, one response, and three distinguishable log lines.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The measurement this whole file exists for, run in the direction that would have caught the
    /// original defect: force four distinct validation failures, check the client cannot tell them
    /// apart, and check the operator can.
    /// </para>
    /// <para>
    /// <b>Three, not four</b>, and the shortfall is recorded rather than rounded up — see the
    /// comment at the assertion. Two of the four are one message inside
    /// <c>Microsoft.IdentityModel</c> itself.
    /// </para>
    /// <para>
    /// The assertions are on the library's <c>IDXnnnnn</c> codes rather than on prose, because those
    /// codes are the stable, searchable part — <c>IDX10500</c> is what somebody types into a search
    /// box at 2am, and it is exactly what was being thrown away.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task One_invalid_token_response_covers_four_distinguishable_causes()
    {
        (string Name, Func<Task<ResourceServerFixture>> Fixture, string Token)[] cases =
        [
            ("not a JWT at all", Plain, "aaaa.bbbb.cccc"),
            ("signed by a stranger", Plain, Mint.AccessToken(key: TestKeys.Stranger)),
            ("an issuer this resource does not trust", Plain, Mint.AccessToken(issuer: "https://elsewhere.example")),

            // The customer's key rotation, reproduced: the resource server holds no key at all.
            ("no signing key is configured",
                () => ResourceServerFixture.StartAsync(o => o.SigningKeys.Clear()),
                Mint.AccessToken()),
        ];

        var descriptions = new HashSet<string>(StringComparer.Ordinal);
        var diagnoses = new List<string>();

        foreach (var (name, fixture, token) in cases)
        {
            await using var server = await fixture();
            using var response = await WithHeader(server, "/mcp", "Bearer " + token);

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal("invalid_token", BearerChallengeTests.Parameter(response, "error"));

            descriptions.Add(BearerChallengeTests.Parameter(response, "error_description")!);

            var line = Assert.Single(server.Logs.Rejections);

            Assert.Equal(nameof(ReasonCode.AccessTokenRejected), line.Property("Reason"));

            var detail = line.Property("Detail");

            Assert.False(string.IsNullOrEmpty(detail), $"{name}: the line carries no detail at all.");

            // `validator=` and not `validator=SecurityToken`, measured. "aaaa.bbbb.cccc" comes back
            // as an ArgumentException rather than a SecurityTokenException — the library does not
            // reach its own exception hierarchy for a string that is not a JWT — which is why
            // Classify's `_ => Rejected` default is doing real work rather than being a formality,
            // and why this assertion is about the shape of the field instead of about one type.
            Assert.Contains("validator=", detail, StringComparison.Ordinal);

            diagnoses.Add(detail!);
        }

        // The client cannot tell them apart, and must not be able to.
        Assert.Equal("The access token is not valid.", Assert.Single(descriptions));

        // The operator gets three, and the number is measured rather than assumed.
        //
        // Two of the four collapse, and it is worth being precise about where: a token whose `kid`
        // names no configured key and a server with no keys configured at all produce the SAME
        // message — "IDX10500: Signature validation failed. No security keys were provided to
        // validate the signature." — because the verifier runs with TryAllIssuerSigningKeys = false,
        // so an unmatched `kid` selects an empty key set and is indistinguishable from an empty
        // configuration. That is the library's message, not something this code drops; both cases
        // now reach the log, and the remedy for both is the same line of configuration.
        //
        // Asserting 3 rather than 4 is the honest number. Asserting 4 would have been a claim we
        // could not measure, which is the one mistake LESSONS.md is about.
        var distinct = diagnoses.Distinct(StringComparer.Ordinal).ToList();

        Assert.Equal(3, distinct.Count);

        // The one a rotated signing key produces — the field report this work started from.
        Assert.Contains(distinct, d => d.Contains("IDX10500", StringComparison.Ordinal));

        // And the one that names both issuers, which is the whole of that diagnosis.
        Assert.Contains(distinct, d =>
            d.Contains("IDX10205", StringComparison.Ordinal)
            && d.Contains("https://elsewhere.example", StringComparison.Ordinal)
            && d.Contains(Build.Issuer, StringComparison.Ordinal));
    }

    /// <summary>
    /// The line's property set, pinned. The other half of it is in the authorization-server suite.
    /// </summary>
    /// <remarks>
    /// The two servers declare the message template twice, because the only assembly they share is
    /// BCL-only by design and cannot take a logging dependency. This test and its twin assert the
    /// same literal set, so changing one without the other is a red build.
    /// </remarks>
    [Fact]
    public async Task The_rejection_event_declares_exactly_the_agreed_properties()
    {
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await fixture.Client.GetAsync(new Uri("/mcp", UriKind.Relative));

        var line = Assert.Single(fixture.Logs.Rejections);

        Assert.Equal(
            ["CorrelationId", "Description", "Detail", "Error", "Reason", "RequirementId", "Status", "Surface", "{OriginalFormat}"],
            line.Properties.Keys.OrderBy(k => k, StringComparer.Ordinal));

        Assert.Equal(
            "Rejected {Surface} request {CorrelationId}: {Reason} [{RequirementId}] -> {Status} {Error}: "
            + "{Description} {Detail}",
            line.Property("{OriginalFormat}"));

        Assert.Equal("ResourceServer", line.Property("Surface"));
        Assert.Equal("invalid_token", line.Property("Error"));
        Assert.Equal("X-32/X-33", line.Property("RequirementId"));
        Assert.Equal("401", line.Property("Status"));
        Assert.Equal(LogLevel.Warning, line.Level);
    }

    /// <summary>
    /// The access token the caller presented never appears in a log line.
    /// </summary>
    /// <remarks>
    /// The temptation is strongest on the branch where the token did not validate — "it is not a
    /// real token, so it is not a real secret" — and it is wrong for the commonest cause of that
    /// branch, which is a perfectly good token for the wrong audience or a stale one that is still
    /// live at the issuer. The sweep is over the whole captured event, at Trace, from every
    /// category.
    /// </remarks>
    [Fact]
    public async Task No_captured_log_line_contains_the_presented_token()
    {
        var token = Mint.AccessToken(Build.Resolve(Build.OtherResource));

        await using var fixture = await ResourceServerFixture.StartAsync();
        using var response = await WithHeader(fixture, "/mcp", "Bearer " + token);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        // The whole compact serialization, and each of its three segments separately: a log line
        // holding only the payload is still a log line holding the subject and the audience.
        var parts = token.Split('.');

        var needles = new List<string> { token };
        needles.AddRange(parts.Where(p => p.Length > 16));

        foreach (var line in fixture.Logs.Events)
        {
            var text = line.Message + "" + string.Join("", line.Properties.Values) + "" + line.Exception;

            foreach (var needle in needles)
            {
                Assert.DoesNotContain(needle, text, StringComparison.Ordinal);
            }
        }
    }
}
