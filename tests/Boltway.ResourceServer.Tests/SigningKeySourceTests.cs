using System.Net;
using System.Net.Http.Headers;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.ResourceServer.Tests;

/// <summary>
/// <c>SigningKeySource</c> — read on every validation, so a rotation can publish rather than mutate.
/// </summary>
/// <remarks>
/// <para>
/// The defect this closes was in the producer, not here: a <c>JwksRefresher</c> in
/// <c>Boltway.Mcp</c> called <c>Add</c> and <c>Remove</c> on <c>SigningKeys</c> from a background
/// timer, and that is the same list instance the validator hands to
/// <c>Rfc9068ValidationParameters</c> on every call. Nothing synchronised them. It could only be
/// fixed there by publishing a new list, and it could only publish a new list if something here
/// would read one. That type has since been deleted in favour of <c>JwksKeySource</c>, which
/// publishes a snapshot — but this seam is why it could.
/// </para>
/// <para>
/// So the property under test is not "a source works" but "the source is consulted again", which is
/// what a producer swapping a reference depends on. A validator that captured the result once would
/// pass a test that only checked the first request.
/// </para>
/// </remarks>
public sealed class SigningKeySourceTests
{
    [Fact]
    public async Task The_source_is_read_again_on_every_request()
    {
        IReadOnlyList<SecurityKey> keys = [];

        await using var fixture = await ResourceServerFixture.StartAsync(options =>
        {
            // Cleared, so a pass cannot come from the list the fixture seeded.
            options.SigningKeys.Clear();
            options.SigningKeySource = () => keys;
        });

        var token = Mint.AccessToken();

        var beforeAnyKeys = await Call(fixture, token);

        // The swap a producer makes: a whole new list, not an edit of the one just read.
        keys = [TestKeys.Handle.Key];

        var afterTheSwap = await Call(fixture, token);

        Assert.Equal(HttpStatusCode.Unauthorized, beforeAnyKeys);
        Assert.Equal(HttpStatusCode.OK, afterTheSwap);
    }

    /// <summary>
    /// With no source set, the list is still what verifies — so this is not a breaking change.
    /// </summary>
    [Fact]
    public async Task The_list_is_still_used_when_no_source_is_set()
    {
        await using var fixture = await ResourceServerFixture.StartAsync();

        Assert.Equal(HttpStatusCode.OK, await Call(fixture, Mint.AccessToken()));
    }

    /// <summary>
    /// A source, once set, is the only thing consulted.
    /// </summary>
    /// <remarks>
    /// Two sets of keys that both "work" would make the precedence unobservable, so the list here
    /// holds the real key and the source holds none: if the list were still being merged in, the
    /// request would succeed.
    /// </remarks>
    [Fact]
    public async Task A_source_replaces_the_list_rather_than_adding_to_it()
    {
        await using var fixture = await ResourceServerFixture.StartAsync(options =>
            options.SigningKeySource = () => []);

        Assert.Equal(HttpStatusCode.Unauthorized, await Call(fixture, Mint.AccessToken()));
    }

    private static async Task<HttpStatusCode> Call(ResourceServerFixture fixture, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri("/mcp", UriKind.Relative));

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await fixture.Client.SendAsync(request);

        return response.StatusCode;
    }
}
