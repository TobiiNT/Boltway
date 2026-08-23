# Changing the sign-in and consent pages

Everything a deployment can do to the pages this server renders: theme them, wrap them in your own
document, or replace the markup. Split out of the root README, which was giving ninety-six lines to
a subject most readers do not reach on their first day and every reader who does needs in full.

[`LOCALIZATION.md`](LOCALIZATION.md) is the language axis, and is orthogonal to all of this — the
last section here says how the two meet.

---

Three tiers. **Take the lowest one that does what you need**, because each step up hands you a
requirement you then own.

The consent page is governed by N-14, which is a MUST in the MCP specification: the host of the
`client_id` URL leads, the self-asserted `client_name` is subordinate to it and marked unverified,
the requested redirect host is shown, and a redirect landing on the user's own machine carries an
explicit warning. A page missing any of that looks finished.

**Tier 1 — theme.** No code.

```csharp
o.Interaction.ProductName = "Northwind";              // goes in <title>, never in a heading
o.Interaction.LogoPath = "/img/northwind.svg";
o.Interaction.StylesheetPaths.Add("/css/authorization.css");
```

Serve the files yourself — `app.UseStaticFiles()` and a folder under `wwwroot`. Every path must be
an absolute path **on this origin**; a CDN URL is refused at startup, because these pages send
`default-src 'self'` and the browser would refuse it silently at render time instead. Nothing here
can reach the part of the page N-14 governs.

**Tier 2 — layout.** Your document, the server's page inside it.

```csharp
services.AddSingleton<IInteractionLayout, NorthwindLayout>();   // BEFORE AddBoltwayAuthorizationServer
```

`Wrap(InteractionPage page)` returns the whole document and must contain `page.Body` **verbatim and
unencoded**. That body is the server's markup, with every N-14 field already in the required order,
so a layout has exactly one way to lose a requirement — and the renderer checks that one condition
on every render and throws rather than serving a consent page with no consent on it. Header, footer,
navigation, classes and language are all yours.

**Inline script or style in a layout** needs a nonce, which is off by default because the shipped
pages have none:

```csharp
o.Interaction.UseContentSecurityPolicyNonce = true;
```

Then branch on it — never assume it, or the page breaks when someone turns it off:

```csharp
if (page.Nonce is not null) sb.Append($"<script nonce=\"{page.Nonce}\">…</script>");
```

The policy gains `script-src 'self' 'nonce-…'` and `style-src 'self' 'nonce-…'` — `'self'` stays in
both, so your stylesheet keeps loading. `frame-ancestors`, `base-uri`, `object-src` and
`form-action` are untouched, and nothing anywhere adds `'unsafe-inline'` or `'unsafe-eval'`. Two
things a nonce cannot rescue: a `style="…"` attribute and an `onclick=` handler. Those need
`'unsafe-hashes'`, which is not offered — use a class and an external file.

Most dynamic UI needs none of this. `default-src 'self'` already allows `<script src="/js/app.js">`
from your own origin, so a compiled bundle or a self-hosted htmx works with the policy unchanged.

**Tier 3 — renderer.** The markup itself.

```csharp
services.AddSingleton<IInteractionRenderer, NorthwindRenderer>();
```

Total control, and you now own N-14, A-11 and A-14 in full. Two things that are easy to miss and
break silently: `POST /consent` reads `form["decision"]` and compares it to `"approve"` ordinally,
so a control named anything else ships a page whose Approve button denies; and `POST /login` reads
`username` and `password`.

**Whichever of the last two you take, run the contract.** `Boltway.Interaction.Testing` ships as
a package for this — derive `InteractionLayoutContract` or `InteractionRendererContract`, override
one factory method, and get the requirements asserted against your own output, including that
nothing on the page is something the CSP will refuse.

```csharp
public sealed class NorthwindRendererTests : InteractionRendererContract
{
    protected override IInteractionRenderer NewRenderer() => new NorthwindRenderer();
}
```

Both seams use `TryAdd`, so a registration made **before** `AddBoltwayAuthorizationServer`
wins. Registering after it does nothing, silently.

**Language is a fourth axis, orthogonal to all three tiers.** Every sentence these pages say is a key
in `InteractionText`, and a deployment replaces any subset of them with a JSON file — untranslated
keys fall back to English one string at a time, so a partial translation is a partial translation
rather than a broken page. `ui_locales` (OIDC Core §3.1.2.1) picks the language per request, and
`ui_locales_supported` advertises exactly what the middleware will honour, because startup refuses
the two disagreeing. The admin pages and the mail have their own tables and their own failure modes.
One thing to know before you reference this from a container image: this library needs a culture to
be *nameable*, so `InvariantGlobalization=true` on its own — which implies
`PredefinedCulturesOnly=true` — throws `CultureNotFoundException` at startup.
[`LOCALIZATION.md`](LOCALIZATION.md) is the whole of it, with an example translation file.
