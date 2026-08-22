using Boltway.OAuth.Primitives.Errors;

namespace Boltway.OAuth.Primitives.Tests.Errors;

/// <summary>The error table: X-01 through X-41.</summary>
public sealed class OAuthErrorsTests
{
    [Theory]
    // The wire strings clients branch on. RFC 6749 §4.1.2.1 and §5.2, RFC 8707 §2, OIDC Core
    // §3.1.2.6, RFC 6750 §3.1, RFC 7591 §3.2.2, RFC 7009 §2.2.1.
    [InlineData(OAuthSurface.Authorize, OAuthErrorCode.AccessDenied, "access_denied", 303)]
    [InlineData(OAuthSurface.Authorize, OAuthErrorCode.UnsupportedResponseType, "unsupported_response_type", 303)]
    [InlineData(OAuthSurface.Authorize, OAuthErrorCode.InvalidTarget, "invalid_target", 303)]
    [InlineData(OAuthSurface.Authorize, OAuthErrorCode.LoginRequired, "login_required", 303)]
    [InlineData(OAuthSurface.Token, OAuthErrorCode.InvalidGrant, "invalid_grant", 400)]
    [InlineData(OAuthSurface.Token, OAuthErrorCode.UnsupportedGrantType, "unsupported_grant_type", 400)]
    [InlineData(OAuthSurface.Token, OAuthErrorCode.InvalidTarget, "invalid_target", 400)]
    [InlineData(OAuthSurface.Registration, OAuthErrorCode.InvalidRedirectUri, "invalid_redirect_uri", 400)]
    [InlineData(OAuthSurface.ResourceServer, OAuthErrorCode.InsufficientScope, "insufficient_scope", 403)]
    [InlineData(OAuthSurface.ResourceServer, OAuthErrorCode.InvalidToken, "invalid_token", 401)]
    [InlineData(OAuthSurface.Revocation, OAuthErrorCode.UnsupportedTokenType, "unsupported_token_type", 400)]
    public void The_wire_string_and_status_are_what_the_rfc_says(
        OAuthSurface surface, OAuthErrorCode code, string wire, int status)
    {
        var spec = OAuthErrors.Resolve(surface, code);

        Assert.Equal(wire, spec.Wire);
        Assert.Equal(status, spec.Status);
    }

    [Theory]
    // Each of these is a real code that belongs to a different endpoint. Resolve throwing is what
    // makes "never emitted from /token" a property of the process rather than a sentence in a spec.
    [InlineData(OAuthErrorCode.AccessDenied)]
    [InlineData(OAuthErrorCode.UnsupportedResponseType)]
    [InlineData(OAuthErrorCode.ServerError)]
    [InlineData(OAuthErrorCode.TemporarilyUnavailable)]
    [InlineData(OAuthErrorCode.InvalidToken)]
    [InlineData(OAuthErrorCode.InsufficientScope)]
    [InlineData(OAuthErrorCode.LoginRequired)]
    [InlineData(OAuthErrorCode.ConsentRequired)]
    public void The_token_endpoint_cannot_emit_an_authorize_or_resource_code(OAuthErrorCode code)
    {
        Assert.False(OAuthErrors.CanEmit(OAuthSurface.Token, code));
        Assert.Throws<InvalidOperationException>(() => OAuthErrors.Resolve(OAuthSurface.Token, code));
    }

    [Theory]
    [InlineData(OAuthErrorCode.UnsupportedGrantType)]
    [InlineData(OAuthErrorCode.InvalidGrant)]
    [InlineData(OAuthErrorCode.UnsupportedTokenType)]
    public void The_authorize_endpoint_cannot_emit_a_token_code(OAuthErrorCode code)
    {
        Assert.False(OAuthErrors.CanEmit(OAuthSurface.Authorize, code));
    }

    [Fact]
    public void Nothing_before_redirect_validation_can_be_delivered_by_redirect()
    {
        // RFC 6749 §4.1.2.1: with no trustworthy redirect URI there is nowhere safe to send the
        // user, so the failure is rendered on our own origin. Redirecting anyway would make
        // /authorize an open redirector that also leaks `state`.
        foreach (var (key, spec) in OAuthErrors.All)
        {
            if (key.Surface != OAuthSurface.AuthorizePreRedirect)
            {
                continue;
            }

            Assert.Equal(ErrorDelivery.Html, spec.Delivery);

            // A status in the 3xx range would be a redirect however the delivery is labelled, so
            // this is the same property said again at the level the wire cares about.
            Assert.False(spec.Status is >= 300 and < 400, $"{key.Code} would redirect with {spec.Status}.");
        }
    }

    /// <summary>
    /// A pre-redirect failure carries 4xx for the client's mistakes and 5xx for ours.
    /// </summary>
    /// <remarks>
    /// This used to be folded into the test above as a flat "every row is 400", which was true only
    /// because every row was a client error. Adding <c>server_error</c> — the row the exception
    /// boundary needs, since there is no redirect available on this surface — made that assertion
    /// fail for the right reason: answering a server fault with 400 tells the caller their request
    /// was malformed and sends whoever is debugging it to the client.
    /// </remarks>
    [Fact]
    public void A_pre_redirect_status_says_which_side_failed()
    {
        foreach (var (key, spec) in OAuthErrors.All)
        {
            if (key.Surface != OAuthSurface.AuthorizePreRedirect)
            {
                continue;
            }

            var expected = key.Code is OAuthErrorCode.ServerError or OAuthErrorCode.TemporarilyUnavailable ? 5 : 4;

            Assert.Equal(expected, spec.Status / 100);
        }
    }

    [Fact]
    public void A_mismatched_redirect_uri_and_a_malformed_challenge_share_a_code_but_not_a_fate()
    {
        // The reason AuthorizePreRedirect is its own surface. `invalid_request` is the correct code
        // for both, and keyed on (endpoint, code) alone they collapse — resolving the
        // never-redirect case to a redirect.
        var beforeValidation = OAuthErrors.Resolve(OAuthSurface.AuthorizePreRedirect, OAuthErrorCode.InvalidRequest);
        var afterValidation = OAuthErrors.Resolve(OAuthSurface.Authorize, OAuthErrorCode.InvalidRequest);

        Assert.Equal(ErrorDelivery.Html, beforeValidation.Delivery);
        Assert.Equal(ErrorDelivery.Redirect, afterValidation.Delivery);
        Assert.Equal(beforeValidation.Wire, afterValidation.Wire);
    }

    [Fact]
    public void Every_authorize_redirect_is_303_never_302_or_307()
    {
        // OAuth 2.1 §7.5.3 and RFC 9700 §4.12: an authorization server redirecting a request that
        // may carry user credentials MUST NOT use 307 and SHOULD use 303. access_denied is by
        // definition the answer to a consent POST, so the rule is live here rather than theoretical.
        foreach (var (key, spec) in OAuthErrors.All)
        {
            if (key.Surface != OAuthSurface.Authorize)
            {
                continue;
            }

            Assert.Equal(ErrorDelivery.Redirect, spec.Delivery);
            Assert.Equal(303, spec.Status);
        }
    }

    [Fact]
    public void A_client_authentication_failure_is_400_unless_the_header_was_used()
    {
        // OAuth 2.1 §3.2.4: 400 in general; 401 MUST be used only when the client authenticated via
        // the Authorization header, and then a matching challenge is mandatory. A blanket 401 makes
        // a body-authenticating client see a Basic challenge and possibly switch schemes on retry.
        Assert.Equal(400, OAuthErrors.Resolve(OAuthSurface.Token, OAuthErrorCode.InvalidClient).Status);
        Assert.Equal(400, OAuthErrors.StatusForClientAuthFailure(usedAuthorizationHeader: false));
        Assert.Equal(401, OAuthErrors.StatusForClientAuthFailure(usedAuthorizationHeader: true));
    }

    [Fact]
    public void Every_client_authentication_failure_carries_a_challenge()
    {
        // RFC 6749 §5.2 makes the WWW-Authenticate header MUST, not SHOULD, for this case.
        foreach (var surface in new[] { OAuthSurface.Token, OAuthSurface.Introspection, OAuthSurface.Revocation })
        {
            Assert.Equal(
                ErrorDelivery.JsonWithChallenge,
                OAuthErrors.Resolve(surface, OAuthErrorCode.InvalidClient).Delivery);
        }
    }

    [Fact]
    public void Registration_management_can_reject_bad_metadata_on_a_put()
    {
        // RFC 7592 §2.2 defers to RFC 7591's error codes for an invalid metadata field. Without
        // these rows Resolve would throw on a legitimate rejection.
        Assert.True(OAuthErrors.CanEmit(OAuthSurface.RegistrationManagement, OAuthErrorCode.InvalidRedirectUri));
        Assert.True(OAuthErrors.CanEmit(OAuthSurface.RegistrationManagement, OAuthErrorCode.InvalidClientMetadata));
    }

    [Fact]
    public void An_inactive_token_has_no_row_because_it_is_not_an_error()
    {
        // RFC 7662 §2.3: "a properly formed and authorized query for an inactive or otherwise
        // invalid token ... is not considered an error response by this specification." It is a 200
        // on the success path, so there is deliberately nothing here to resolve.
        Assert.False(OAuthErrors.CanEmit(OAuthSurface.Introspection, OAuthErrorCode.InvalidToken));
    }

    [Fact]
    public void Server_error_is_a_redirect_because_a_500_cannot_be_one()
    {
        // The reason this code exists at all. An HTTP 500 from /authorize past the point where the
        // redirect URI is trusted is a defect, not a server condition.
        var spec = OAuthErrors.Resolve(OAuthSurface.Authorize, OAuthErrorCode.ServerError);

        Assert.Equal(ErrorDelivery.Redirect, spec.Delivery);
    }

    [Fact]
    public void Insufficient_scope_is_403_and_invalid_token_is_401()
    {
        // Both are challenges, and the split matters: 401 tells the client to refresh, 403 with
        // insufficient_scope tells it to ask for more scope. Collapsing them makes one of the two
        // recovery paths unreachable.
        Assert.Equal(401, OAuthErrors.Resolve(OAuthSurface.ResourceServer, OAuthErrorCode.InvalidToken).Status);
        Assert.Equal(403, OAuthErrors.Resolve(OAuthSurface.ResourceServer, OAuthErrorCode.InsufficientScope).Status);
    }

    [Fact]
    public void A_malformed_authorization_header_is_400_not_401()
    {
        // 401 would make the client refresh and resend the same malformed header, forever.
        Assert.Equal(400, OAuthErrors.Resolve(OAuthSurface.ResourceServer, OAuthErrorCode.InvalidRequest).Status);
    }

    [Fact]
    public void Registration_management_answers_401_and_never_404()
    {
        // Including for a client that does not exist — a 404 would make this endpoint a client-id
        // enumeration oracle.
        var spec = OAuthErrors.Resolve(OAuthSurface.RegistrationManagement, OAuthErrorCode.InvalidToken);

        Assert.Equal(401, spec.Status);
    }

    [Fact]
    public void Registration_has_no_invalid_request_because_rfc_7591_defines_none()
    {
        Assert.False(OAuthErrors.CanEmit(OAuthSurface.Registration, OAuthErrorCode.InvalidRequest));
    }

    [Fact]
    public void Every_spec_carries_the_requirement_row_it_implements()
    {
        // So a log line naming a rejection can be traced back to the row that demanded it.
        foreach (var (_, spec) in OAuthErrors.All)
        {
            Assert.StartsWith("X-", spec.RequirementId, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void No_two_codes_on_one_surface_share_a_wire_string()
    {
        foreach (var surface in Enum.GetValues<OAuthSurface>())
        {
            var wires = OAuthErrors.All
                .Where(e => e.Key.Surface == surface)
                .Select(e => e.Value.Wire)
                .ToList();

            Assert.Equal(wires.Count, wires.Distinct(StringComparer.Ordinal).Count());
        }
    }

    [Fact]
    public void Every_wire_string_is_lowercase_ascii_with_underscores()
    {
        // RFC 6749 §5.2 gives these as literal tokens. A capitalised or hyphenated variant is a
        // different string to every client that compares them.
        foreach (var (_, spec) in OAuthErrors.All)
        {
            Assert.Matches("^[a-z_]+$", spec.Wire);
        }
    }

    [Fact]
    public void The_none_code_is_not_in_the_table()
    {
        // None means "no error member in the response", which is a property of the response rather
        // than an error to look up.
        foreach (var surface in Enum.GetValues<OAuthSurface>())
        {
            Assert.False(OAuthErrors.CanEmit(surface, OAuthErrorCode.None));
        }
    }
}
