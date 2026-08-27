# Localization

Boltway ships English, and every sentence a person reads is replaceable by a deployment - no
rebuild, no fork, no satellite assembly. A deployment that configures none of this serves the
English pages and English mail it always did.

There are **three surfaces**, and they do not share a mechanism. Saying that plainly is more use
than pretending they are uniform, because the differences are what a translator trips over.

| | interaction pages | admin BFF | notifications |
|---|---|---|---|
| what it covers | sign-in, consent, logout, error, `/me/*` | the accounts, roles and audit pages | the mail this server sends |
| where the English lives | `InteractionText` in `Boltway.AuthorizationServer` | `AdminText` in `Boltway.AdminBff` | `NotificationText` in `Boltway.Notifications` |
| shape of the file | culture → key → sentence | key → sentence | property → sentence |
| what a host reads it from | `UI_TRANSLATIONS_FILE`, or `UI_TRANSLATIONS` | `ADMIN_TEXT_FILE` | `NOTIFICATION_TEXT_FILE`, or `NOTIFICATION_TEXT` |
| language chosen per request | **yes**, from `ui_locales` | no - one language per deployment | no - one per deployment, [on purpose](#notifications) |
| a key you left out | English, one string at a time | English, one string at a time | English, one property at a time |
| a key you spelled wrong | **named on stderr at startup**, then ignored | **named on stderr at startup**, then ignored | silently ignored |
| a `{0}` you dropped | **refused at startup** | silently renders without the value | silently renders without the value |
| a `{9}` you invented | **refused at startup** | renders as the literal `{9}` | **refused at startup** |

Everything below is either one of those cells with its reason attached, or a hazard that belongs to
all three.

## What all three have in common

**Fallback is per string, not per file.** A file with four sentences in it is a page with four
translated sentences and the rest in English. That is the property to design around rather than
work around: it is what lets a translation land in pieces, and it is why "translate three sentences
and leave forty" is not a way to break anything. The visible cost is a mixed-language page, which
is the shape of a job half done rather than of a defect.

**Whole sentences, never fragments.** *"The application at {0} is asking to access your account"* is
one key rather than three, because word order is not a property every language shares and a page
assembled from fragments in English order reads as machine output in most of them. Where a value is
spliced in, it goes in through a `{0}` placeholder - move the placeholder wherever the sentence
needs it.

**A translation cannot introduce markup.** The page text is HTML-encoded first and the safe values
are spliced into the placeholders afterwards, so a translation containing `<script>` renders as the
characters somebody typed. Braces survive encoding, which is what makes that order work. Notification
text is the exception and for the opposite reason: it becomes the body of a plain-text mail, where
there is no markup to escape and escaping would put `&amp;` in front of a reader.

**A dropped placeholder deletes what it was carrying, and the rendered page still looks finished.**
Substitution is a replace: no `{0}` means no substitution and a sentence that reads perfectly well.
A `ConsentClientAsking` translated without its `{0}` is a consent page with no client hostname on
it - the field `N-14` makes a MUST, deleted by editing a JSON file, on a page that still renders and
still passes the renderer contract. Where the library can catch that it does, at startup; where it
cannot, count the placeholders in the English string yourself and put the same ones in yours. Which
is which is the last two rows of the table above.

## The interaction pages

The keys are the `public const string` fields on
[`InteractionText`](../src/Boltway.AuthorizationServer/Interaction/InteractionText.cs), and each one
carries an XML doc saying what it labels and what its `{0}` is. `InteractionText.Keys` is public so
that *"did we translate all of them"* has a mechanical answer rather than an opinion -
see [Checking a file before it ships](#checking-a-file-before-it-ships).

The file is a JSON object of **culture name → key → sentence**:

```json
{
  "vi": { "LoginTitle": "Đăng nhập", "LoginPassword": "Mật khẩu" },
  "fr": { "LoginTitle": "Connexion" }
}
```

Three settings on `Boltway.AuthorizationServer.Host` read it:

| | |
| --- | --- |
| `UI_TRANSLATIONS_FILE` | a path to that JSON. **Prefer this.** A translation is a document - written by whoever writes the words, reviewed in a diff - and a table this size on one line of a `.env` is a thing nobody proofreads |
| `UI_TRANSLATIONS` | the same JSON inline, for a deployment with nowhere to mount a file |
| `UI_DEFAULT_LOCALE` | the language the pages are in when nothing else applies. `en` if unset |

Setting both `UI_TRANSLATIONS` and `UI_TRANSLATIONS_FILE` is **refused at startup**, rather than one
of them winning: there is no reading of it where the answer is obvious, and picking one silently is
how a deployment comes to serve the copy nobody edited.

Consuming the library directly rather than through the host, the same thing is one call:

```csharp
services.AddBoltwayInteractionLocalization("vi", translations);
app.UseRequestLocalization();   // the host places this; it must be upstream of the endpoints
```

Order relative to `AddBoltwayAuthorizationServer` does not matter for these two: the renderer is
registered as a delegate and resolves the localizer when it is first built rather than when it is
registered, and the advertised-versus-served check below is a comparison rather than an assignment.

.NET has no first-class way for an application to override a *library's* resources - satellite
assemblies belong to the assembly that owns the `.resx`, so a consumer cannot add a language to
ours. So the text comes from a dictionary instead, and `DictionaryStringLocalizer` is an
implementation of the framework's interface over it rather than a replacement for the framework.

**The seam is `IStringLocalizer` itself - the bare, non-generic one - registered before
`AddBoltwayInteractionLocalization`,** which registers its own with `TryAdd` and stands aside for
yours. That is worth stating precisely because the precise version is load-bearing: this was
documented for a while as a replaced `IStringLocalizerFactory`, the way OrchardCore and ABP do it,
and nothing here has ever resolved a factory. `AddLocalization()` does not register the bare
`IStringLocalizer` at all, so a consumer who followed that got English pages and no error.

### A worked example

[`docs/examples/translations.vi.json`](examples/translations.vi.json) is a real file - valid JSON,
real key names, part of the table translated and the rest deliberately absent so that the
per-string fallback is visible rather than described. Copy it, mount it, point the setting at it:

```bash
UI_DEFAULT_LOCALE=vi
UI_TRANSLATIONS_FILE=/etc/boltway/ui/translations.json
```

```yaml
# docker compose
services:
  auth:
    environment:
      UI_DEFAULT_LOCALE: vi
      UI_TRANSLATIONS_FILE: /etc/boltway/ui/translations.json
    volumes:
      - ./translations.vi.json:/etc/boltway/ui/translations.json:ro
```

The pages then come up in Vietnamese, and everything the file leaves out - the session list, the
password pages, the recovery flow - comes up in English until somebody adds it.

Two things in that file are worth pointing at:

- **`"en": {}` is not an incantation.** A culture translates as many keys as it has and the rest
  fall back; an empty table is that rule's zero case. It is how a deployment whose default is
  Vietnamese *also offers English*, because English is the per-string fallback and being a fallback
  is not being a registered culture. Without that line, `?ui_locales=en` on a `vi` deployment serves
  the Vietnamese page - correctly, and it looks like a defect for about ten minutes.
- **`ShellTagline` and `ShellDomain` are empty in the shipped English and omitted when empty.** They
  are the two lines in the default layout's brand panel: a tagline is a deployment's own claim about
  itself, and the domain is a second copy of *which server this is* for a reader whose app hid the
  address bar. They live in the translation file because everything that is text on the page lives
  in one file; a deployment writes the same domain into each of its languages, which is the cost of
  that rule and a small one for one line.

### JSON, strictly

The parser is `System.Text.Json` with web defaults. **No comments and no trailing commas** - both are
rejected, and the startup error names the file. Key names inside the tables are matched
**ordinally and exactly**: `logintitle` is not `LoginTitle`, and it will be reported as unknown and
ignored. Culture names are matched case-insensitively.

A key this build does not have is named on stderr and then ignored, rather than being fatal:

```
/etc/boltway/ui/translations.json['vi'] has 1 key(s) this build does not know,
which will be ignored: LoginUserName
```

That is the trade on purpose - a translation written against a newer version of the library must not
stop an older one from starting - but it is the only signal you get, so read the boot log the first
time a file lands.

### Placeholders are refused at startup

`AddBoltwayInteractionLocalization` runs `InteractionText.Problems` over the whole table before it
registers anything, and throws when a translated string's `{n}` set differs from the English one's
in either direction:

```
These translations would render a page missing something the caller supplied:
  vi/ConsentClientAsking drops {0}, so the value it carried is silently absent from the rendered page.
  vi/ErrorReference adds {1}, which no caller supplies, so it reaches the page as literal text.
```

The arity is not a rule the check invents - it is read off the English table, which is what the
call sites are written against. Every problem is reported at once, so a translator fixes one file in
one pass rather than earning one restart per key. An unknown key is not reported here; it has no
English arity to be compared with, and the host that loaded the file has already named it on stderr.

A refusal to start is the right trade for this specific mistake and not for every mistake: a page
that silently lost a security field is worse than a host that did not come up, and unlike a missing
translation there is no later moment at which anybody finds out.

## Per-request culture

`ui_locales` is OIDC Core §3.1.2.1: a space-separated list of BCP 47 tags, most preferred first,
sent by the client on `/authorize`. Boltway reads it, and the supported set is exactly what
`ui_locales_supported` advertises in the discovery document.

```
GET /authorize?...&ui_locales=vi
→ 303 /login?returnUrl=%2Fauthorize%3F...&ui-culture=vi
```

Four things about that redirect are the design rather than the implementation:

- **The parameter is never turned into a `CultureInfo`.** The provider hands the requested names to
  `RequestLocalizationMiddleware`, which matches them against `SupportedUICultures`. That matching is
  the framework's, which is what makes the resolved culture something the server chose rather than
  something a caller sent. At most eight tags are read; the rest are dropped, because a long list is
  attacker-controlled wasted work.
- **The choice is carried on the URL, and it has to be carried by something.** `/authorize`, `/login`
  and `/consent` are three requests, and `/authorize` puts its whole query inside one
  percent-encoded `returnUrl` - so nothing named `ui_locales` survives to the page on its own. The
  endpoint appends the **resolved** culture as `ui-culture`, which the framework's own query-string
  provider reads back. This was believed for a while to be handled by a cookie provider; nothing
  wrote that cookie, and a deployment serving `vi` answered `/authorize?…&ui_locales=vi` with an
  English sign-in page while advertising otherwise. A deployment that would rather use a cookie can
  still write one - the framework's provider is registered and will read it.
- **`<html lang>` is the resolved culture, never the requested one.** Reflecting the request would
  tell a screen reader to pronounce an English page with Vietnamese phonology. `dir="rtl"` comes off
  the same string for nine primary subtags (`ar`, `he`, `fa`, `ur`, `ps`, `sd`, `yi`, `ckb`, `dv`) -
  a list rather than `TextInfo.IsRightToLeft`, because that property reads ICU data and this build
  has none. **The admin BFF emits `lang` and no `dir`**, so its pages are not mirrored.
- **An unsupported `ui_locales` is not an error.** OIDC makes it a hint. Refusing would be a client
  that cannot connect because of a language, which is a much larger failure than being served the
  default one.

### Advertised must equal served

`ui_locales_supported` is generated from the same function that configures the middleware, and
`MapBoltwayAuthorizationServer` compares the two anyway and **refuses to start on a mismatch in
either direction**:

```
ui_locales_supported and the request-localization middleware disagree.
Advertised and not served: ja. The document has to describe the server: a client that
respects the list will ask for a language it cannot be given, and neither side sees an error.
```

Advertising a language nobody serves is `N-06` - never advertise a capability you do not have - and
serving one nobody advertises is a capability no client will ever ask for. The check does not care
which of the two configuration calls ran first.

One shape it cannot catch: **`UI_DEFAULT_LOCALE=vi` with no translations at all is internally
consistent and completely English.** The middleware serves `vi`, the document advertises `vi`, the
pages declare `lang="vi"`, and every sentence on them falls back. Set the default to a language you
have actually written.

### Region subtags: list the exact tags your clients send

A `vi-VN` request does **not** fall back to a `vi` table in this library's own configuration, and
this is the one place the framework's ordinary behaviour does not apply.

Measured 2026-08-23 on .NET SDK 10.0.111, a minimal app with `SupportedUICultures = [en, vi]`,
asking for `vi-VN`:

| | `vi-VN` resolves to |
| --- | --- |
| ICU present (a normal app) | `vi` - `CultureInfo.GetCultureInfo("vi-VN").Parent.Name` is `"vi"` |
| `InvariantGlobalization=true` (this repository's hosts) | `en`, the default - `Parent.Name` is `""` |

Every culture created in globalization-invariant mode has the invariant culture as its parent, so
the language-from-region chain that normally makes `vi-VN` find `vi` does not exist. Both the
middleware's matching and `DictionaryStringLocalizer`'s own parent walk stop immediately.

So: **the table key has to be the tag the client actually sends.** If clients send `vi-VN`, a `vi`
table does not serve them - there is no parent walk to reach it - and a deployment that must serve
both needs both entries, with the strings in each. See
[the hazard below](#1-a-consumer-that-sets-invariantglobalization-refuses-to-start) for why the
build is configured this way and what else it costs.

## The admin BFF

`Boltway.AdminBff` has its own table, `AdminText`, and its own single setting:

```bash
ADMIN_TEXT_FILE=/etc/boltway/admin/text.json
```

```json
{
  "$language": "vi",
  "NavAccounts": "Tài khoản",
  "NavRoles": "Vai trò",
  "SignOut": "Đăng xuất"
}
```

Three differences from the interaction pages, all of them things a translator needs to know:

- **Flat, not keyed by culture.** One language per deployment. There is no `ui_locales` here and no
  request localization at all - an admin surface has few readers and no client sending it a language
  hint, so a per-request mechanism would be a second one with no second reader.
- **`$language` sets `<html lang>`,** and it lives in the file rather than in a variable of its own
  so that the declared language cannot disagree with the words. A file that does not say gets `en`,
  which is what its untranslated keys fall back to - wrong for a file translated into something else
  and silent about it, but internally consistent rather than claiming a language on no evidence. It
  is `$`-prefixed because every other key is a C# `nameof` and no identifier starts with `$`.
- **There is no inline variable.** File or nothing.

There used to be a fourth, and closing it is worth reading as a warning about the other two tables.
A key this build does not know is now named on stderr at startup and then ignored, exactly as
`UI_TRANSLATIONS_FILE` handles one. What made it worth doing is how it failed: per-string fallback
means a mistyped key renders correct English, so the only signal a translator got was a sentence
that did not change - which reads as "the file is not being loaded" rather than "line 12 is
misspelled".

## Notifications

`NotificationText` is a record with an English default on every property, and a deployment replaces
whichever ones it wants:

```bash
NOTIFICATION_TEXT_FILE=/etc/boltway/mail/text.json
```

```json
{
  "resetPasswordSubjectText": "Đặt lại mật khẩu",
  "resetPasswordBodyText": "Chào {0},\n\nMở liên kết này để chọn mật khẩu mới:\n\n{1}\n\nLiên kết hết hạn lúc {2} và chỉ dùng được một lần."
}
```

Property names bind case-insensitively, so `ResetPasswordSubjectText` works as well as the camelCase
form. An unset property keeps its English; a **mis**spelled one is silently ignored, which looks
identical. `NOTIFICATION_TEXT` holds the same JSON inline, and setting both it and
`NOTIFICATION_TEXT_FILE` is refused for the same reason the UI pair is.

**One set of sentences per deployment, not one per recipient, and that is a decision rather than a
gap.** A page is rendered for the person reading it and the request says who that is. A notification
is not: the culture in scope when a password-changed notice is sent belongs to whoever *caused* it,
which for an operator-driven reset is a different person from the recipient, and no account in this
library carries a language preference. Per-request culture would therefore be right about as often
as it was wrong, silently - and it would be wrong on the message somebody reads while they are
locked out and least able to work past a language they do not use. A deployment whose people share a
language says so once. A deployment whose people do not needs a per-recipient preference this
library does not have, and should replace `INotificationRenderer`.

**A record rather than a dictionary, for the same reason.** A dictionary can be half-filled by a
deploy; a password-reset mail with an empty body is worse than an English one. Binding leaves an
unset property alone, so a partial translation is partial rather than blank.

**Whole messages, not fragments** - more so than on the pages. A letter is not assembled from
sentences in English order, and a translator needs to be able to move a paragraph. The one exception
is the sessions line in the password-changed notice, which is a whole sentence that is sometimes
absent, and it carries its own leading newline because zero is the ordinary case.

Two paragraphs are load-bearing and a rewrite should keep what they do rather than what they say:

- The last paragraph of `resetPasswordBodyText` tells somebody who did **not** ask for this that they
  need do nothing, and says *why* that is safe rather than only asserting it. A reset mail that says
  "if this was not you, contact support" turns every phishing simulation into a support ticket.
- `newDeviceAuthorizedBodyText` gives two instructions in one order: end the access first, then
  change the password. A reader told only the second changes their password while the grant keeps
  working.

### The startup check

A configured sentence with a placeholder the message does not supply - a stray `{3}`, or a `{0}` in
a subject that takes none - throws `FormatException` inside `string.Format`. Left to the sender that
surfaces as a caught-and-logged failure at the moment somebody is waiting for a reset link, and the
message they needed silently does not arrive. So the host calls `NotificationText.Problems()` at
startup and refuses to run instead:

```
/etc/boltway/mail/text.json has 1 sentence(s) that will not render:
ResetPasswordBodyText: Index (zero based) must be greater than or equal to zero and less than
the size of the argument list.
```

It renders every property against the arguments its message actually supplies, so what it catches is
a placeholder with no argument behind it. The mirror-image mistake - **dropping** a placeholder - it
cannot catch, because `string.Format` is perfectly happy to ignore an argument. A
`resetPasswordBodyText` with no `{1}` is a reset mail with no link in it, and the only check for
that is reading the string.

## Two things that will surprise you

### 1. A consumer that sets `InvariantGlobalization` refuses to start

This is the one that costs an afternoon, and it is documented nowhere a consumer reads, because it
lives in this repository's `Directory.Build.props`.

`InvariantGlobalization=true` is the ordinary thing to set on a container image that carries no ICU -
Alpine-based .NET images do not, and this repository's own `Dockerfile` says so in as many words.
**It implies `PredefinedCulturesOnly=true`**, under which only the invariant culture exists. Boltway needs a
culture *named* - as a dictionary key, as the value of `<html lang>`, and as something the
middleware can match `ui_locales` against - so `AddBoltwayInteractionLocalization` calls
`CultureInfo.GetCultureInfo` on every configured tag, and in that mode it throws.

Measured 2026-08-23, .NET SDK 10.0.111:

```
System.Globalization.CultureNotFoundException
Only the invariant culture is supported in globalization-invariant mode.
See https://aka.ms/GlobalizationInvariantMode for more information. (Parameter 'name')
vi is an invalid culture identifier.
```

The fix is one line, and it is what this repository's own hosts do:

```xml
<InvariantGlobalization>true</InvariantGlobalization>
<PredefinedCulturesOnly>false</PredefinedCulturesOnly>   <!-- required, and it is not implied -->
```

That is culture *identity* without culture *data*, and the split is the point. `InvariantGlobalization`
stays on - an authorization server has no business calling unmanaged code, and every comparison in
this library is ordinal by rule - while a culture that carries invariant data is exactly enough to be
a dictionary key, a `lang` value and a matching target. ICU stays out of the image. Both hosts in
this repository are built this way - their generated `runtimeconfig.json` carries
`System.Globalization.Invariant: true` beside `System.Globalization.PredefinedCulturesOnly: false`.

The cost is the region-subtag behaviour above, and the one below.

### 2. No date, time or number on any surface is ever localized

A Vietnamese reader sees `2026-08-12 07:37:00Z` on the session list and `2026-08-12 07:37 UTC` in
their mail. This is not an oversight to be filed; it is a consequence of the paragraph above, and
every formatting site in the tree passes `CultureInfo.InvariantCulture` deliberately.

| what | rendered as | where |
| --- | --- | --- |
| a moment on an interaction page | `<time datetime="2026-08-12T07:37:00.0000000+00:00">2026-08-12 07:37:00Z</time>` | session list, approvals list |
| a moment in mail | `2026-08-12 07:37 UTC` | every notification |
| a moment on an admin page | `2026-08-12 07:37:00 UTC` | the audit table |
| a count, a lifetime in minutes | `12` - no grouping separator | *"{0} session(s) were ended"*, `SessionsTokens` |

Three reasons, and only the first is about ICU:

1. **There is no culture data to format with.** Under invariant globalization, a `vi` culture formats
   exactly as the invariant one does - so a culture-sensitive call here would not be unavailable, it
   would be a silent wrong answer that looked like a right one.
2. **UTC, and it says so.** Converting to the reader's zone means knowing it, and this server is not
   told. Printing a local-looking time that is actually UTC is how somebody reads an incident an
   hour wrong.
3. **The digits are the deployment's configuration, not the reader's prose.** A timestamp is not a
   sentence, and a translation should not be able to change what a date means - which is why the
   formatting lives in the renderer rather than in the string table, and why `{2}` in a mail body is
   handed to you already formatted.

Right-to-left is handled (`dir` on the interaction pages, from the nine subtags listed above).
Localized calendars, localized number grouping and per-reader time zones are not, and there is no
setting that turns them on.

## What stays English on purpose

Not everything on a page or in a header is prose, and translating the wrong half breaks a protocol.

| | why |
| --- | --- |
| `error_description` on `/authorize` failures and in `WWW-Authenticate` | OAuth 2.1 §4.1.2.1 restricts it to `%x20-21 / %x23-5B / %x5D-7E`. A Vietnamese sentence put there arrives as its ASCII fragments - the diacritics are dropped, not escaped. `A-12` requires the code and a safe description in the body so that `curl -D-` is a sufficient debugging tool, and it is written for whoever integrates the client |
| every other `WWW-Authenticate` parameter | a stray `"` terminates the quoted string early and takes `resource_metadata` - the client's only route to discovery - with it |
| scope names, claim names, header and form field names, enum values, id prefixes | matched character-for-character by two implementations. Two implementations that diverge on a translation enforce different contracts while both believe they are right |
| the keys in every file on this page | they are `nameof` constants in C#. See below |

The error page carries **two** sentences with two jobs, and this is the shape to copy anywhere else
the same problem appears: `ErrorStartAgain` (and its four siblings) is the reader's sentence, chosen
by what they can *do* about the refusal, and it is translated. The `error_description` under it is
the developer's and is not. `ErrorDeveloperDetail` is the label above it, and **it is translated** -
without a label, unlabelled English on a translated page reads as a string somebody forgot rather
than as a deliberate audience change.

## Key names are frozen on purpose

A key can outlive the sentence it was named for. `LoginUsername` labels a field that now accepts a
handle *or* an address, and its English text says so - the constant keeps its name anyway, and the
remark on it says why.

The constant's **value is the lookup key**. Renaming `LoginUsername` to `LoginIdentifier` would not
migrate anybody's file - it would silently drop every deployment's translation of that line back to
English, producing a page that goes half-English on upgrade. That is the failure a translated
deployment is least able to see, because the page still renders, still validates and still passes
every test.

So: your file is keyed on something deliberately stable, the name may not describe the sentence, and
the XML doc on the constant is where the current meaning is written down. Read the doc, not the
name.

The same rule cuts the other way - a key is added when a sentence needs to be *separately*
translatable, not when a new sentence appears. `AccountSignOut` and `LogoutSubmit` are the same word
in English and two keys, because one is a link to a page that asks and the other is the button on
that page that does it; several languages distinguish them, and a deployment translating the button
would otherwise have silently retitled the link.

## Checking a file before it ships

Every table exposes its key set, so *"did we translate all of them"* is mechanical:

```csharp
var mine = JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, string>>>(
    File.ReadAllText("translations.vi.json"), JsonSerializerOptions.Web)!;

var unknown = mine["vi"].Keys.Except(InteractionText.Keys, StringComparer.Ordinal).ToList();
var missing = InteractionText.Keys.Except(mine["vi"].Keys, StringComparer.Ordinal).ToList();
```

`unknown` is a typo or a key from another version - both hosts warn about these on stderr and then
ignore them. `missing` is not an error at all: those are the strings that will render in English,
and seeing the list is the point. `AdminText.Keys` answers the same question for the admin pages.

The other two questions have their own APIs, and both of them are already wired into startup:

| | |
| --- | --- |
| `InteractionText.Problems(translations)` | every `{n}` mismatch in the whole table, named by culture and key. `AddBoltwayInteractionLocalization` turns the list into a refusal to start |
| `NotificationText.Problems()` | every mail sentence that will not render. The host turns it into a refusal to start |

What is left is the part no API can answer, because it is about meaning rather than shape:

- **A dropped placeholder in the admin table or in the mail.** Neither is checked - `AdminText`
  substitutes with a replace, and `string.Format` ignores an argument nobody asked for. The English
  to compare against is `AdminText.Default.Plain(key)` and `new NotificationText()`, and
  `InteractionText.Default(key)` is the same door for the pages.
- **The sentences that carry a caveat.** `SessionsTokens`, `LogoutDoneTokens` and `ConsentsNotSessions`
  each exist because their absence produced somebody who believed the opposite - that ending a
  session cuts access already granted, that signing out revokes tokens, that withdrawing consent
  ends access an application already holds. `LoginRejected` is one sentence and not two on purpose:
  two would say whether the account exists, and *"wrong password"* rendered in a language the
  reviewer of the English text cannot read turns the form into a directory of who has an account.
  A rewrite keeps every clause, or it is not a rewrite.

## Further reading

- [`InteractionText.cs`](../src/Boltway.AuthorizationServer/Interaction/InteractionText.cs) - every key, with the reason for each on the constant
- [`InteractionLocalization.cs`](../src/Boltway.AuthorizationServer/Interaction/InteractionLocalization.cs) - the localizer, the `ui_locales` provider, `SupportedCultures`
- [`NotificationText.cs`](../src/Boltway.Notifications/NotificationText.cs) - the mail, and the per-deployment argument in full
- [`AdminText.cs`](../hosts/Boltway.AdminBff/AdminText.cs) - the admin table and `$language`
- [`hosts/Boltway.AuthorizationServer.Host/README.md`](../hosts/Boltway.AuthorizationServer.Host/README.md) - every environment variable this page names
- [`README.md`](INTERACTION-PAGES.md) - the three UI tiers: theme, layout, renderer. Language is orthogonal to all three
