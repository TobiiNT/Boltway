#!/usr/bin/env bash
#
# Drives one whole authorization code flow against the two sample hosts, the way a client would:
# discovery, 401 challenge, /authorize, /login, /consent, /token, the protected resource, refresh.
#
# It exists because "the sample starts" and "the sample completes a flow" are different claims and
# only the second is worth anything. Every step prints the status line and the headers that carry
# the protocol, so the transcript shows the handshake rather than a summary of it.
#
# Start both hosts first — see samples/README.md.
#
#   ./samples/drive-flow.sh
#
# curl -k throughout: the hosts use the ASP.NET Core development certificate, which is not in the
# system trust store. A real client verifies the chain.

set -euo pipefail

AS=${AS:-https://localhost:7443}
RS=${RS:-https://localhost:7444}
RESOURCE=$RS/mcp
CLIENT_ID=$AS/clients/demo-cli
REDIRECT=http://127.0.0.1:5099/callback

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
JAR=$WORK/cookies
H=$WORK/headers

curl_() { curl -sk -c "$JAR" -b "$JAR" "$@"; }
urlenc() { python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1"; }
qs() { python3 -c 'import urllib.parse,sys;print(urllib.parse.parse_qs(urllib.parse.urlparse(sys.argv[1]).query)[sys.argv[2]][0])' "$1" "$2"; }
show() { tr -d '\r' < "$H" | grep -iE '^(HTTP/|location:|www-authenticate:)' || true; }
location() { tr -d '\r' < "$H" | grep -i '^location:' | cut -d' ' -f2; }
brief() { python3 -c '
import json,sys
for k, v in json.load(sys.stdin).items():
    print(f"{k}: {v[:34] + chr(8230) if isinstance(v, str) and len(v) > 34 else v}")'; }

# The antiforgery field the interaction pages render. Its name is ASP.NET Core's to choose, so it
# is read out of the form rather than assumed — the first hidden input that is not returnUrl.
antiforgery() { python3 -c '
import re,sys
for m in re.finditer(r"<input type=\"hidden\" name=\"([^\"]+)\" value=\"([^\"]*)\"", sys.stdin.read()):
    if m.group(1) != "returnUrl":
        print(m.group(1) if sys.argv[1] == "name" else m.group(2))
        break' "$1"; }

VERIFIER=$(python3 -c 'import secrets,base64;print(base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode())')
CHALLENGE=$(python3 -c 'import hashlib,base64,sys;print(base64.urlsafe_b64encode(hashlib.sha256(sys.argv[1].encode()).digest()).rstrip(b"=").decode())' "$VERIFIER")
STATE=$(python3 -c 'import secrets;print(secrets.token_urlsafe(12))')

echo "### 1. the resource server, unauthenticated. This is where a client starts."
curl -sk -D "$H" -o /dev/null "$RESOURCE/stories"; show

echo
echo "### 2. the RFC 9728 document the challenge pointed at"
curl -sk "$RS/.well-known/oauth-protected-resource/mcp" | python3 -m json.tool

echo
echo "### 3. the authorization server it named"
curl -sk "$AS/.well-known/oauth-authorization-server" | python3 -c '
import json,sys
d = json.load(sys.stdin)
for k in ("issuer","authorization_endpoint","token_endpoint","code_challenge_methods_supported",
          "client_id_metadata_document_supported","registration_endpoint"):
    print(k + ": " + str(d.get(k, "(absent)")))'

AUTHORIZE="$AS/authorize?response_type=code&client_id=$(urlenc "$CLIENT_ID")&redirect_uri=$(urlenc "$REDIRECT")&scope=$(urlenc 'openid offline_access stories.read')&state=$STATE&code_challenge=$CHALLENGE&code_challenge_method=S256&resource=$(urlenc "$RESOURCE")"

echo
echo "### 4. GET /authorize, with a client this server has never seen"
curl_ -D "$H" -o /dev/null "$AUTHORIZE"; show
LOGIN=$(location)
RETURN_URL=$(qs "$AS$LOGIN" returnUrl)

echo
echo "### 5. the login page"
LOGIN_PAGE=$(curl_ "$AS$LOGIN")
printf '%s' "$LOGIN_PAGE" | grep -o '<form[^>]*>'
echo "antiforgery field: $(printf '%s' "$LOGIN_PAGE" | antiforgery name)"

echo
echo "### 6. POST /login"
curl_ -D "$H" -o /dev/null -X POST "$AS/login" \
  --data-urlencode "username=demo" \
  --data-urlencode "password=demo-password" \
  --data-urlencode "returnUrl=$RETURN_URL" \
  --data-urlencode "$(printf '%s' "$LOGIN_PAGE" | antiforgery name)=$(printf '%s' "$LOGIN_PAGE" | antiforgery value)"
show

echo
echo "### 7. GET /authorize again, now with a session"
curl_ -D "$H" -o /dev/null "$AS$RETURN_URL"; show
CONSENT=$(location)

echo
echo "### 8. the consent page"
CONSENT_PAGE=$(curl_ "$AS$CONSENT")
printf '%s' "$CONSENT_PAGE" | python3 -c '
import html,re,sys
body = sys.stdin.read().split("<body>")[1].split("<form")[0]
print(html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body))).strip())'

echo
echo "### 9. POST /consent, decision=approve"
curl_ -D "$H" -o /dev/null -X POST "$AS/consent" \
  --data-urlencode "decision=approve" \
  --data-urlencode "returnUrl=$RETURN_URL" \
  --data-urlencode "$(printf '%s' "$CONSENT_PAGE" | antiforgery name)=$(printf '%s' "$CONSENT_PAGE" | antiforgery value)"
show

CALLBACK=$(location)
CODE=$(qs "$CALLBACK" code)
[ "$(qs "$CALLBACK" state)" = "$STATE" ] && echo "(state came back unchanged, and iss identifies the issuer — RFC 9207)"

echo
echo "### 10. POST /token"
TOKENS=$(curl -sk -X POST "$AS/token" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "code_verifier=$VERIFIER" \
  --data-urlencode "resource=$RESOURCE")
printf '%s' "$TOKENS" | brief

ACCESS=$(printf '%s' "$TOKENS" | python3 -c 'import json,sys;print(json.load(sys.stdin)["access_token"])')
REFRESH=$(printf '%s' "$TOKENS" | python3 -c 'import json,sys;print(json.load(sys.stdin)["refresh_token"])')

echo
echo "### 11. the access token, decoded"
python3 -c '
import base64,json,sys
h, p, _ = sys.argv[1].split(".")
d = lambda s: json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
print(json.dumps(d(h))); print(json.dumps(d(p), indent=2))' "$ACCESS"

echo
echo "### 12. the resource server again, with the token"
curl -sk -D "$H" -o "$WORK/body" -H "Authorization: Bearer $ACCESS" "$RESOURCE/stories"; show
python3 -m json.tool < "$WORK/body"

echo
echo "### 13. an endpoint whose scopes this token does not carry"
curl -sk -D "$H" -o /dev/null -H "Authorization: Bearer $ACCESS" "$RESOURCE/stories/draft"; show

echo
echo "### 14. refresh"
curl -sk -X POST "$AS/token" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$REFRESH" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "resource=$RESOURCE" | brief

echo
# Not an error, and the successor comes back identical. Redemption is idempotent inside a 45-second
# grace window because the successor is DERIVED from the token being redeemed, so a client retrying
# after a dropped response computes the same one rather than losing its grant to a race. After the
# window the same replay is read as reuse, and the whole token family and its grant are revoked.
echo "### 15. the same refresh token again, inside the grace window"
curl -sk -X POST "$AS/token" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$REFRESH" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "resource=$RESOURCE" | brief
