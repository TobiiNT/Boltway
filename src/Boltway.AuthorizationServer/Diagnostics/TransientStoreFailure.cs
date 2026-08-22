using System.Data.Common;
using System.Net.Sockets;

namespace Boltway.AuthorizationServer.Diagnostics;

/// <summary>
/// Whether an exception means "the store could not be reached", as opposed to "the server is
/// broken".
/// </summary>
/// <remarks>
/// <para>
/// <b>The distinction is the whole value, and getting it wrong is worse in one direction than the
/// other.</b> Too narrow and a database outage still answers <c>500</c>, which is where this
/// started — no worse than before. Too broad and a genuine defect answers <c>503 Retry-After</c>,
/// which tells every client to keep trying and hides the bug behind a retry loop. So the test is
/// the framework's own contract for "retry me" rather than a guess at which messages look
/// infrastructural.
/// </para>
/// <para>
/// <b><see cref="DbException.IsTransient"/> is that contract</b>, and it is BCL rather than
/// provider surface: <c>System.Data.Common</c> ships in the shared framework, so this file compiles
/// with no dependency on Npgsql, SQLite or anything else. A provider sets the flag for the errors it
/// knows a caller may retry — connection failures, admission timeouts — and leaves it false for a
/// constraint violation or a syntax error, which is exactly the line that matters here.
/// </para>
/// <para>
/// <b>Two more types are checked, and neither is redundant.</b> <see cref="SocketException"/>
/// because a name-resolution failure can surface before any provider wraps it, and
/// <see cref="TimeoutException"/> because a store that never answers is unreachable as far as the
/// person signing in is concerned. Both are unambiguously about the connection rather than the
/// query, so neither widens this to cover a logic error.
/// </para>
/// <para>
/// <b>The chain is walked, because the exception that reaches an endpoint is not the one that
/// happened.</b> EF Core with <c>EnableRetryOnFailure</c> off — which <c>DESIGN.md</c> §1.2 requires
/// on <c>/token</c> — recognises a transient provider error and rethrows it wrapped in an
/// <see cref="InvalidOperationException"/> reading "An exception has been raised that is likely due
/// to a transient failure." The <see cref="DbException"/> is then the inner. Testing only the
/// outermost type would classify every real outage as a server fault, which is the production
/// behaviour this exists to correct.
/// </para>
/// </remarks>
internal static class TransientStoreFailure
{
    /// <summary>
    /// How many exceptions are examined before the walk gives up and says no.
    /// </summary>
    /// <remarks>
    /// A budget over the whole walk rather than a depth per chain, and iterative rather than
    /// recursive, because this runs on a failure path: a cyclic <c>InnerException</c> or a
    /// pathologically nested <see cref="AggregateException"/> must not turn one failed request into
    /// a hung one or a stack overflow. Thirty-two is far past anything EF Core, a provider and
    /// <see cref="AggregateException"/> nest in practice; a chain longer than that is not a
    /// transient store failure by any reading, and answering "no" sends it down the path it took
    /// before this existed.
    /// </remarks>
    private const int Budget = 32;

    /// <summary>Whether <paramref name="exception"/> or anything it wraps means the store is unreachable.</summary>
    /// <param name="exception">The exception an endpoint caught.</param>
    /// <returns>
    /// <see langword="true"/> when the request may be retried against the same server, which is what
    /// a <c>503</c> with a <c>Retry-After</c> promises the caller.
    /// </returns>
    internal static bool Describes(Exception? exception)
    {
        if (exception is null)
        {
            return false;
        }

        var pending = new Stack<Exception>();
        pending.Push(exception);

        for (var examined = 0; pending.Count > 0 && examined < Budget; examined++)
        {
            var current = pending.Pop();

            if (current is DbException { IsTransient: true } or SocketException or TimeoutException)
            {
                return true;
            }

            // AggregateException.InnerException is only the first of several and the transient one
            // is not reliably first, so every branch is queued rather than just the head.
            if (current is AggregateException aggregate)
            {
                foreach (var inner in aggregate.Flatten().InnerExceptions)
                {
                    pending.Push(inner);
                }
            }
            else if (current.InnerException is { } inner)
            {
                pending.Push(inner);
            }
        }

        return false;
    }
}
