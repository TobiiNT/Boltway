using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Boltway.AdminBff;

/// <summary>
/// Sessions kept on the server, so the browser holds a key and never a token.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the whole reason the admin UI is a BFF rather than a single-page app.</b> §7.1 chose
/// this shape because the token stays server side; the default cookie handler would put the tokens
/// <i>in</i> the cookie — encrypted, so a script cannot read them, but still handed to the browser
/// on every response and sitting in whatever the browser writes to disk. An
/// <see cref="ITicketStore"/> is what makes "never sent to the browser" true rather than
/// approximately true.
/// </para>
/// <para>
/// <b>In memory, which is the honest limit of this implementation.</b> Signing everybody out on a
/// deploy is a real cost and an acceptable one here: the population is operators, the session is a
/// browser tab, and signing in again is one redirect. A deployment running more than one replica
/// needs a shared store — the operator would otherwise be signed out whenever the load balancer
/// moved them — and it is the same seam either way. Named rather than left to be discovered by the
/// second replica.
/// </para>
/// <para>
/// <b>Keys are 256 bits of CSPRNG output</b>, like every other secret in this repository. The key is
/// the whole credential: anybody holding it is that session, so a predictable one would be an
/// account takeover that never touches a password.
/// </para>
/// </remarks>
public sealed class InMemoryTicketStore : ITicketStore
{
    private readonly ConcurrentDictionary<string, AuthenticationTicket> _tickets = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        _tickets[key] = ticket;

        return Task.FromResult(key);
    }

    /// <inheritdoc />
    public Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        _tickets[key] = ticket;

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        // Expiry is checked here as well as by the cookie handler. The handler will not present an
        // expired ticket, but the entry would otherwise outlive it in memory — and a store that
        // keeps a session for longer than the session lasts is one whose contents are a bigger
        // target than they need to be.
        if (_tickets.TryGetValue(key, out var ticket)
            && ticket.Properties.ExpiresUtc is { } expires
            && expires <= DateTimeOffset.UtcNow)
        {
            _tickets.TryRemove(key, out _);

            return Task.FromResult<AuthenticationTicket?>(null);
        }

        return Task.FromResult(ticket);
    }

    /// <inheritdoc />
    public Task RemoveAsync(string key)
    {
        _tickets.TryRemove(key, out _);

        return Task.CompletedTask;
    }
}

/// <summary>Points the cookie handler at the ticket store.</summary>
/// <remarks>
/// A <c>PostConfigure</c> rather than a line in <c>AddCookie</c>, because the store has to come out
/// of the container and the options callback runs before it exists.
/// </remarks>
public sealed class UseTicketStore(ITicketStore store)
    : Microsoft.Extensions.Options.IPostConfigureOptions<CookieAuthenticationOptions>
{
    /// <inheritdoc />
    public void PostConfigure(string? name, CookieAuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        options.SessionStore = store;
    }
}
