namespace Boltway.Notifications;

/// <summary>
/// Something this server needs to tell a person, by whatever means a deployment sends things.
/// </summary>
/// <remarks>
/// <para>
/// <b>Typed rather than a subject and a body, and it is the same decision
/// <c>IInteractionRenderer</c> records for the pages.</b> A library that composed "Reset your
/// password" would be putting one customer's voice in every other customer's inbox, in one
/// customer's language, over a signature nobody agreed to. What the library knows is <i>what
/// happened</i>; what to say about it is a deployment's.
/// </para>
/// <para>
/// <b>A closed hierarchy.</b> A sender written against these four handles every message this
/// server will send, and adding a fifth is a compile error in every implementation rather than a
/// message that silently goes nowhere - which is the failure mode of a string-keyed template lookup.
/// <see cref="NewDeviceAuthorized"/> was the fourth, and it arrived that way: the switch in
/// <c>NotificationText.Render</c> stopped compiling until it was handled.
/// </para>
/// </remarks>
public abstract record NotificationMessage
{
    /// <summary>Where to send it.</summary>
    /// <remarks>
    /// The address on the account at the moment the message was made. Passed rather than looked up
    /// so that a sender needs no directory access, and so that a message is a value that can be
    /// queued, logged with the address redacted, or replayed.
    /// </remarks>
    public required string To { get; init; }

    /// <summary>Whose account this is about.</summary>
    /// <remarks>
    /// The handle, not the subject: it is what the person recognises, and a ULID in an email is a
    /// support call. Never used to look anything up - a sender that resolved it would be a second
    /// path to the directory.
    /// </remarks>
    public required string Handle { get; init; }
}

/// <summary>Prove an address belongs to the person who gave it.</summary>
/// <param name="Link">The absolute URL to click. Carries the token and expires with it.</param>
/// <param name="ExpiresAt">When the link stops working.</param>
/// <remarks>
/// The link is composed by the server rather than by the sender, because it has to match a route
/// this server serves and a token this server minted. A sender that built it from a template would
/// be the second place the path is written down.
/// </remarks>
public sealed record VerifyEmail(string Link, DateTimeOffset ExpiresAt) : NotificationMessage;

/// <summary>Somebody asked to reset this account's password.</summary>
/// <param name="Link">The absolute URL to click.</param>
/// <param name="ExpiresAt">When the link stops working.</param>
/// <remarks>
/// <b>Sent only to an address that is on an account.</b> The endpoint that triggers it answers
/// identically whether or not one exists - <c>S-48</c> - so the absence of this message is the only
/// difference between the two cases, and it is a difference only the mailbox owner can observe.
/// </remarks>
public sealed record ResetPassword(string Link, DateTimeOffset ExpiresAt) : NotificationMessage;

/// <summary>This account's password has changed.</summary>
/// <param name="At">When.</param>
/// <param name="SessionsRevoked">How many sessions ended with it.</param>
/// <remarks>
/// <b>A notification, not a request, and the one message here that nobody asked for.</b> Telling
/// somebody their password changed is how they find out it was not them. It is therefore sent on
/// every route that changes a password - self-service, the reset link, and an operator's reset -
/// because the route that matters most is the one the account holder did not take.
/// </remarks>
public sealed record PasswordChanged(DateTimeOffset At, int SessionsRevoked) : NotificationMessage;

/// <summary>An application was authorized from a device this account has not approved from before.</summary>
/// <param name="At">When the approval happened.</param>
/// <param name="ClientName">
/// What to call the application. The client's display name, or its id when it has none - chosen by
/// the server, because a sender resolving a client id would be a second path to the client store.
/// </param>
/// <param name="Device">
/// The device, already described and already sanitised. See <c>ApprovingDevice</c>: this began as a
/// <c>User-Agent</c> header, which is to say a string the party being reported on chose.
/// </param>
/// <param name="Link">
/// Where to go about it: the sessions page, absolute.
/// </param>
/// <remarks>
/// <para>
/// <b><paramref name="Link"/> carries no token, unlike the other two messages here.</b> Theirs are
/// credentials - the link <i>is</i> the proof - so they expire and burn on use. This one addresses a
/// page that asks who you are on arrival, so it grants nothing and can expire never. It is here for
/// the plainer reason: this is the message read by somebody who has just learned they may be under
/// attack, and "your sessions page" is a step at which people stop.
/// </para>
/// </remarks>
/// <remarks>
/// <para>
/// <b>The second message nobody asked for, and it exists for the same reason as
/// <see cref="PasswordChanged"/>:</b> somebody reading it who did not do this has learned that
/// another party can complete a sign-in as them. That is the whole of it. Every other fact on the
/// page - which scopes, which resources - is available to a person who goes and looks, and a person
/// who has not been told has no reason to go and look.
/// </para>
/// <para>
/// <b>Sent on a new device rather than on every authorization, and the filter is the feature.</b>
/// Every completed <c>/authorize</c> writes a grant, so a message per grant would arrive whenever
/// somebody reconnected an application they use daily. A notice that arrives for the ordinary case
/// is one that gets filtered into a folder, and then it is not there on the day it matters. What
/// makes the filter affordable is that approving is rare and approving from somewhere new is rarer.
/// </para>
/// <para>
/// <b>The cost of that filter, stated rather than left to be discovered:</b> "new" is judged on the
/// described device - <c>Chrome on macOS</c> - and not on the raw header, so a second machine
/// running the same browser and operating system as one already approved from produces no message.
/// The alternative loses more: a raw header changes with every browser update, which would send a
/// notice naming a device the reader recognises, and a notice that cries wolf about the reader's own
/// laptop is worse than none, because it teaches them what to do with the next one.
/// </para>
/// </remarks>
public sealed record NewDeviceAuthorized(
    DateTimeOffset At, string ClientName, string Device, string Link) : NotificationMessage;

/// <summary>Where a deployment's messages go.</summary>
/// <remarks>
/// <para>
/// <b>Failure is the implementation's to define, and the caller's to survive.</b> Every call site in
/// this server sends after the write it describes has committed, and treats a throw as something to
/// log rather than to fail the operation on: a password reset that succeeded and could not be
/// announced is better than one rolled back because a mail server was busy.
/// </para>
/// <para>
/// That means a sender that queues is the better shape, and a sender that blocks on a remote SMTP
/// conversation is holding a request thread while it does. <c>SmtpNotificationSender</c> says so.
/// </para>
/// </remarks>
public interface INotificationSender
{
    /// <summary>Send one message.</summary>
    /// <param name="message">What happened, and to whom.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    Task SendAsync(NotificationMessage message, CancellationToken cancellationToken);
}

/// <summary>The words. Separate from the sending, for the reason messages are typed at all.</summary>
/// <remarks>
/// A deployment overrides this to write its own subjects and bodies, in its own language, without
/// also having to reimplement a transport. The shipped implementation is English and plain text -
/// enough to be correct, obviously not enough to be a product's voice, which is the signal to
/// replace it.
/// </remarks>
public interface INotificationRenderer
{
    /// <summary>Turn a message into what a person reads.</summary>
    /// <param name="message">What happened.</param>
    RenderedNotification Render(NotificationMessage message);
}

/// <summary>A message, as a person will read it.</summary>
/// <param name="Subject">The subject line.</param>
/// <param name="Body">The body.</param>
/// <param name="IsHtml">Whether <paramref name="Body"/> is HTML rather than plain text.</param>
public sealed record RenderedNotification(string Subject, string Body, bool IsHtml = false);
