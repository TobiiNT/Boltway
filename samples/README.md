# Samples

Two hosts that together perform the handshake Claude actually performs against an MCP connector.
`Boltway.Sample.AuthorizationServer` runs the authorization server on `https://localhost:7443`
and also serves a Client ID Metadata Document for a demo client, so the pair is self-contained and
needs no internet; `Boltway.Sample.ResourceServer` runs the MCP-side resource server on
`https://localhost:7444`, protects `/mcp/stories` with `RequireScope`, and publishes the RFC 9728
document that a `401` challenge points at. They are **two projects rather than one** because that is
the deployment shape — the resource server references only `Boltway.ResourceServer` and has no
compile-time knowledge of the authorization server, which is the property a single combined host
would quietly destroy. Everything about them that is not production-shaped — the signing key
generated at startup, the in-memory stores, the per-process refresh derivation key, the loopback
exemption that lets the CIMD fetcher reach `localhost`, and the seeded `demo` user — is marked `DEV:`
in the source with what a real deployment does instead.

## Running them

```bash
dotnet dev-certs https                                  # once
export SSL_CERT_DIR="$HOME/.aspnet/dev-certs/trust:/usr/lib/ssl/certs"   # Linux, see below

dotnet run --project samples/Boltway.Sample.AuthorizationServer     # terminal 1
dotnet run --project samples/Boltway.Sample.ResourceServer          # terminal 2
./samples/drive-flow.sh                                                  # terminal 3
```

Start order matters, twice over. The resource server fetches the authorization server's JWKS at
startup, so the authorization server has to be up first. And the authorization server's dev signing
key is generated per process — so **restarting it invalidates the keys the resource server is
holding**, and every token then fails validation with `invalid_token`. Restart both together. (That
is not a sample defect to work around; it is the missing JWKS refresher, listed in the root README
under what is not built yet.)

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
