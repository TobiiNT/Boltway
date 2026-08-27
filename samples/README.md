# Samples

Two hosts that together perform the handshake Claude actually performs against an MCP connector.
`Boltway.Sample.AuthorizationServer` runs the authorization server on `https://localhost:7443`
and also serves a Client ID Metadata Document for a demo client, so the pair is self-contained and
needs no internet; `Boltway.Sample.ResourceServer` runs the MCP-side resource server on
`https://localhost:7444`, protects `/mcp/stories` with `RequireScope`, and publishes the RFC 9728
document that a `401` challenge points at. They are **two projects rather than one** because that is
the deployment shape - the resource server references only `Boltway.ResourceServer` and has no
compile-time knowledge of the authorization server, which is the property a single combined host
would quietly destroy. Everything about them that is not production-shaped - the signing key
generated at startup, the in-memory stores, the per-process refresh derivation key, the loopback
exemption that lets the CIMD fetcher reach `localhost`, and the seeded `demo` user - is marked `DEV:`
in the source with what a real deployment does instead.

## Running them

```bash
dotnet dev-certs https --trust                          # once
export SSL_CERT_DIR="$HOME/.aspnet/dev-certs/trust:/usr/lib/ssl/certs"   # Linux, see below

dotnet run --project samples/Boltway.Sample.AuthorizationServer     # terminal 1
dotnet run --project samples/Boltway.Sample.ResourceServer          # terminal 2
./samples/drive-flow.sh                                                  # terminal 3
```

`drive-flow.sh` needs `curl` and `python3`. It needs **no `jq`** - every piece of parsing in it is a
python3 one-liner, because python3 is on every machine that can build this repository and `jq` is
not.

**`--trust` is load-bearing, and the flag was missing here for a while.** `dotnet dev-certs https`
on its own only ensures a certificate exists in .NET's own store. It does not write
`~/.aspnet/dev-certs/trust` - only `--trust` does - so the very next line exported `SSL_CERT_DIR`
pointing at a directory that was never created, the certificate was trusted by nothing, and the
resource server died at startup on its JWKS warm-up. Measured as written, 2026-08; what was measured
is the crash and the absent directory, not which of the two `SSL_CERT_DIR` entries OpenSSL ended up
using. The failure reads as an authentication problem, which is the one thing it is not. The
paragraph two below this one already named the right command while the block above did not.

Start order matters. The resource server refreshes the authorization server's JWKS once before it
serves anything and **fails to start** if it cannot, deliberately: a resource server that comes up
with no keys answers `401` to every caller holding a perfectly good token, and that reads as an
authentication failure rather than as the ordering problem it is. So the authorization server goes
first.

Restarting the authorization server on its own then breaks the pair, and the cause is the one named
at the top of this file rather than a missing feature: **its dev signing key is generated per
process**, so a restart does not rotate a key, it destroys one. Every token already issued fails
validation, and every new token is signed by a key the resource server has never seen. Restart both
together.

There is nothing to work around there. `Boltway.OAuth.Net.JwksKeySource` - which the resource server
uses - holds a fetched key set for five minutes and refreshes in the background as the snapshot
ages, so an authorization server that *rotates* a key is picked up without anybody restarting
anything. That is the case it exists for, and the number is derived rather than chosen: five minutes
sits inside the ten-minute floor a signing key ring is allowed to publish a key ahead of using it.
What no refresher can recover is a key that no longer exists anywhere, which is what a per-process
key becomes at every restart. (This paragraph used to blame "the missing JWKS refresher, listed in
the root README under what is not built yet". The refresher is built, the resource server calls it,
and the root README lists no such gap - measured against both, 2026-08.)

`SSL_CERT_DIR` is needed on Linux only, and only because both hosts make .NET-to-.NET HTTPS calls to
each other over the ASP.NET Core development certificate: the authorization server fetches the
client metadata document from itself, and the resource server fetches JWKS. `dotnet dev-certs https
--trust` prints this same instruction. `drive-flow.sh` uses `curl -k` for the same reason.

## What the script shows

`drive-flow.sh` walks the whole flow and prints the headers rather than a summary: the unauthenticated
`401` with its `resource_metadata` pointer, the RFC 9728 document, the authorization server metadata,
`/authorize` for a client that has never been registered anywhere, `/login`, `/consent`, the code, the
token exchange, the decoded access token (`typ: at+jwt`, `aud` equal to the MCP server's URL), the
protected resource answering `200`, a `403 insufficient_scope` for an endpoint the token cannot
reach, and a refresh.

The step worth watching is `/authorize`. The demo client's `client_id` is
`https://localhost:7443/clients/demo-cli`, and there is no registration step anywhere: the server
fetches that URL, validates the document it finds, and proceeds. Nothing is written to any client
table.

Both ports are fixed in the two `Program.cs` files and the script matches them, with no environment
override - the script used to offer one and it could not work. `7443` is baked into the issuer and
into that `client_id`, `7444` into the resource every token's `aud` is compared against, and neither
project's `launchSettings.json` carries an `applicationUrl`. Moving them is an edit to both programs
in one commit, because the two constants name each other.

## Deploying rather than sampling

These two hosts are the smallest thing that completes a flow, and every part of them that is not
production-shaped is marked `DEV:` in the source. What a deployment does instead is
`hosts/Boltway.AuthorizationServer.Host` - the same server with everything arriving as configuration -
and `docker-compose.yml` in the repository root stands one up beside PostgreSQL and the admin UI.
