using System.Text;
using Microsoft.AspNetCore.Http;

namespace Boltway.AuthorizationServer.Interaction;

/// <summary>
/// The browser a grant was approved from: how it is read, and how it is shown.
/// </summary>
/// <remarks>
/// <para>
/// <b>What this is for.</b> A person looking at their own sessions sees a list of client names, and
/// two grants for the same client are indistinguishable - which is exactly the moment somebody is
/// asking whether one of them is theirs. The <c>User-Agent</c> presented at <c>/authorize</c> is the
/// browser the consent screen was clicked in, so it names the machine that approved.
/// </para>
/// <para>
/// <b>No address is recorded, and that is the deployment's decision rather than an omission.</b> An
/// IP would say roughly where as well as roughly what, and it is the field that turns a session list
/// into a location history. What is here identifies a device to the person who owns it and says
/// nothing about where they were.
/// </para>
/// <para>
/// <b>Read once, at <c>/authorize</c>, and never updated.</b> A refresh does not touch it. The
/// alternative - restamping on every rotation - is a database write on the hot path of every
/// refresh, and it would answer a different question than the one the page asks: this says which
/// device <i>approved</i>, which is the decision a person is being asked to recognise.
/// </para>
/// <para>
/// <b>Stored raw and interpreted here.</b> The header is what was measured; a phrase like "Chrome on
/// macOS" is an interpretation of it, and interpretations improve. Freezing one into the store would
/// keep every old row at whatever the parser believed on the day it was written, and there would be
/// no way back to what the browser actually said.
/// </para>
/// </remarks>
public static class ApprovingDevice
{
    /// <summary>
    /// The most of a <c>User-Agent</c> that is kept.
    /// </summary>
    /// <remarks>
    /// A header is caller-controlled and has no length limit of its own, so something has to bound
    /// what reaches a column. 256 covers every real browser's header with room to spare - the
    /// longest in ordinary use run to about 180 - and the value is only ever displayed and compared
    /// by eye, so a truncated tail costs nothing that matters.
    /// </remarks>
    public const int MaxLength = 256;

    /// <summary>Read the header, or <see langword="null"/> when there is nothing usable.</summary>
    /// <param name="request">The request the consent screen was submitted from.</param>
    /// <remarks>
    /// Whitespace-only counts as absent. A header present and empty is a client saying nothing, and
    /// storing an empty string would put a row on the page that renders as a blank line.
    /// </remarks>
    internal static string? Read(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var header = request.Headers.UserAgent.ToString().Trim();

        return header.Length == 0
            ? null
            : header[..Math.Min(header.Length, MaxLength)];
    }

    /// <summary>
    /// A short phrase for a <c>User-Agent</c>, or the header itself when it cannot do better.
    /// </summary>
    /// <param name="userAgent">What was stored, or <see langword="null"/>.</param>
    /// <returns>
    /// A phrase like <c>Chrome on macOS</c>; the raw header when the pattern is unfamiliar; and
    /// <see langword="null"/> when nothing was recorded.
    /// </returns>
    /// <remarks>
    /// <para>
    /// <b>Deliberately small, and it falls back to the header rather than to a guess.</b> Every
    /// user-agent library in existence is a pile of heuristics over a string that has been lying
    /// about itself since 1994 - every browser still claims to be Mozilla - so this recognises the
    /// handful of families a person actually signs in from and gets out of the way otherwise. A raw
    /// header is ugly and true; "Unknown device" would be neither.
    /// </para>
    /// <para>
    /// <b>Order matters and is the whole trick.</b> Edge carries <c>Chrome</c> and <c>Safari</c> in
    /// its header, Chrome carries <c>Safari</c>, and every one of them carries <c>Mozilla</c>. So
    /// the most specific marker is tested first and the test stops at the first hit; reversing any
    /// two of these lines reports most of the fleet as Safari.
    /// </para>
    /// </remarks>
    public static string? Describe(string? userAgent)
    {
        if (string.IsNullOrWhiteSpace(userAgent))
        {
            return null;
        }

        var browser = Browser(userAgent);
        var platform = Platform(userAgent);

        return browser is null || platform is null ? userAgent : $"{browser} on {platform}";
    }

    /// <summary>
    /// The described device, flattened to one line, for somewhere with no markup to escape it.
    /// </summary>
    /// <param name="userAgent">What was stored, or <see langword="null"/>.</param>
    /// <returns>A single-line phrase, or <see langword="null"/> when nothing was recorded.</returns>
    /// <remarks>
    /// <para>
    /// <b>The sessions page needs nothing like this and that is the point.</b> There the value goes
    /// through HTML encoding, so a header full of angle brackets is four harmless characters. An
    /// email body has no such step: <c>RenderedNotification</c> is plain text unless a deployment
    /// says otherwise, and plain text is a format whose structure is made of newlines.
    /// </para>
    /// <para>
    /// <b>So what is removed is the structure, not the content.</b> A header carrying
    /// <c>\n\nThis was you, ignore this message.</c> would otherwise arrive looking like another
    /// paragraph of the sentence this deployment wrote, under this deployment's name - and the one
    /// party who can choose that header is the one the message is reporting on. Every control
    /// character goes, runs of whitespace collapse to one space, and what is left is a single line
    /// that can only ever be read as the value of the field it is printed beside.
    /// </para>
    /// <para>
    /// The text is otherwise untouched. Dropping unfamiliar headers would lose exactly the devices
    /// worth naming, and rewriting one would report something nobody sent.
    /// </para>
    /// </remarks>
    public static string? DescribeOnOneLine(string? userAgent)
    {
        if (Describe(userAgent) is not { } described)
        {
            return null;
        }

        var flattened = new StringBuilder(described.Length);
        var pendingSpace = false;

        foreach (var character in described)
        {
            // Control characters are removed rather than replaced by a space: a header padded with
            // them would otherwise become a wide gap that pushes the real text off the line.
            if (char.IsControl(character))
            {
                pendingSpace = true;
                continue;
            }

            if (char.IsWhiteSpace(character))
            {
                pendingSpace = true;
                continue;
            }

            if (pendingSpace && flattened.Length > 0)
            {
                flattened.Append(' ');
            }

            pendingSpace = false;
            flattened.Append(character);
        }

        // A header of nothing but control characters describes no device. Null rather than an empty
        // string, so the caller takes the same path as a grant that recorded nothing at all.
        return flattened.Length == 0 ? null : flattened.ToString();
    }

    private static string? Browser(string agent) =>
        // Edg before Chrome before Safari: each of those headers contains the ones below it.
        agent.Contains("Edg/", StringComparison.Ordinal) ? "Edge"
        : agent.Contains("OPR/", StringComparison.Ordinal) ? "Opera"
        : agent.Contains("Firefox/", StringComparison.Ordinal) ? "Firefox"
        : agent.Contains("Chrome/", StringComparison.Ordinal) ? "Chrome"
        : agent.Contains("Safari/", StringComparison.Ordinal) ? "Safari"
        : null;

    private static string? Platform(string agent) =>
        // iPhone and iPad before Mac: iOS headers name Mac OS X too.
        agent.Contains("iPhone", StringComparison.Ordinal) ? "iPhone"
        : agent.Contains("iPad", StringComparison.Ordinal) ? "iPad"
        : agent.Contains("Android", StringComparison.Ordinal) ? "Android"
        : agent.Contains("Macintosh", StringComparison.Ordinal) ? "macOS"
        : agent.Contains("Windows", StringComparison.Ordinal) ? "Windows"
        : agent.Contains("Linux", StringComparison.Ordinal) ? "Linux"
        : null;
}
