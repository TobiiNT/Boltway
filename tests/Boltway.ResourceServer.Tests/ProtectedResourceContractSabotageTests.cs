using Boltway.ResourceServer.Testing;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Boltway.ResourceServer.Tests;

/// <summary>
/// That the shipped contract fails on the pipeline it was written from.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ProtectedResourceContractTests" /> proves the contract passes against correct wiring,
/// which on its own is also what a contract asserting nothing would do. This is the other half: a
/// deployment whose own authentication middleware does not know about the framework's anonymous
/// marker, which is exactly the defect measured on a real server on 2026-08-26 - RFC 9728 metadata
/// answering 401 at the URL that server's own challenges pointed clients at, with every unit test
/// in its suite green.
/// </para>
/// <para>
/// The contract methods are called directly rather than discovered by the runner, because what is
/// under test here is the assertion rather than the server. A derived class whose facts the runner
/// collected would report this repository's deliberate breakage as failures.
/// </para>
/// </remarks>
public sealed class ProtectedResourceContractSabotageTests
{
    [Fact]
    public async Task A_host_middleware_that_ignores_the_anonymous_marker_is_caught()
    {
        await using var sabotaged = await Sabotage();

        // The whole finding, in the exception message a consumer would read in their own runner.
        var failure = await Assert.ThrowsAnyAsync<Exception>(
            sabotaged.Both_well_known_forms_answer_without_a_credential);

        Assert.Contains("401", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task And_so_is_a_challenge_pointing_at_a_url_that_refuses()
    {
        // The same breakage seen from the other end, and the assertion that matters most: a client
        // reads the challenge, follows resource_metadata, and is refused there too.
        await using var sabotaged = await Sabotage();

        var failure = await Assert.ThrowsAnyAsync<Exception>(
            sabotaged.The_metadata_url_named_in_the_challenge_is_reachable);

        // The message names the URL the client was told to follow and what it answered, because
        // that pair is the finding: the challenge is correct and the destination is not.
        Assert.Contains(Build.MetadataUrl, failure.Message, StringComparison.Ordinal);
        Assert.Contains("401", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_control_is_that_correct_wiring_passes_both()
    {
        // Without this the two above pass against a contract that fails on everything, which is the
        // failure mode a sabotage suite is most able to hide.
        await using var wired = await Sabotage(sabotage: false);

        await wired.Both_well_known_forms_answer_without_a_credential();
        await wired.The_metadata_url_named_in_the_challenge_is_reachable();
    }

    private static async Task<Derivation> Sabotage(bool sabotage = true)
    {
        var fixture = await ResourceServerFixture.StartAsync(
            hostMiddleware: sabotage
                ? app => app.Use(async (context, next) =>
                {
                    // A second vocabulary for "no credential needed" that this middleware does not
                    // share. The library marks its metadata endpoints AllowAnonymous; this one has
                    // never heard of it, so it refuses them - and the deployment looks healthy.
                    if (context.Request.Path.StartsWithSegments("/.well-known"))
                    {
                        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        return;
                    }

                    await next(context);
                })
                : null);

        return new Derivation(fixture);
    }

    /// <summary>The contract, bound to a fixture, with its assertions callable by name.</summary>
    private sealed class Derivation(ResourceServerFixture fixture) : ProtectedResourceContract, IAsyncDisposable
    {
        protected override HttpClient Client => fixture.Client;

        protected override string Resource => Build.Resource;

        protected override string ProtectedPath => "/protected";

        public async ValueTask DisposeAsync() => await fixture.DisposeAsync();
    }
}
