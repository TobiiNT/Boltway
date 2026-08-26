#!/usr/bin/env python3
"""Go red when a vendor's client-id metadata document stops matching the capture in `spec/`.

    python3 scripts/check-vendor-cimd.py [spec-dir]

`spec/REQUIREMENTS.md` section 6 is nineteen `C-*` rows describing how two vendors' MCP clients
actually behave — including their defects, which is the half that makes it valuable. `C-04` is a
field-name bug in a document somebody else publishes. `C-06` is a redirect URI declared without a
port. `C-03` is which client authentication method one of them offers at `/token`.

**Every one of those rows is a measurement of somebody else's system, and somebody else fixes
bugs.** `LESSONS.md` is thirteen entries about recording an unmeasured thing as a known one; a
dated capture is the answer to that, and it stays the answer for exactly as long as the capture is
current. After that it is a claim wearing a date.

`pinned-drafts.py` next door watches the IETF for the same reason and is the model for this file,
down to the exit codes. The difference is what moves: a working group publishes a revision every
few months, and a vendor ships whenever it likes. The two captures already in `spec/` are fourteen
days apart and one of them exists *because* something changed — ChatGPT's documents grew the RFC
7591 singular spelling beside the RFC 8414 plural — which was found by hand, at whatever moment
somebody happened to look.

**What it compares.** The newest `cimd-live-*.json` in the spec directory names a set of URLs and
what each answered on that date. This fetches each URL and compares the parsed JSON. Parsed, not
byte-for-byte: key order and whitespace are not what `C-01`..`C-19` are about, and a check that
fires on them teaches its reader to skip it.

**An unreachable vendor fails and is retried; it does not file anything.** Not being able to ask is
not evidence that nothing changed. Same rule as the drafts check and as `check-published-versions.py`
against an unreadable feed: a check that passes when it could not look is worse than no check,
because it is believed.

**A document that has changed is not a defect in this repository.** It is a measurement that is now
owed: re-capture, re-read the `C-*` rows the change touches, and fix anything that stopped being
true. Nothing on `main` is broken by it.

**Exit codes, and they are a contract `vendor-cimd.yml` reads:**

    0  every captured document still answers what it answered
    1  at least one has changed, or the capture named nothing to check — work owed, and the
       workflow opens a tracking issue
    2  at least one URL could not be fetched — nothing was measured about it, so the run is red
       and the workflow retries rather than filing

Standard library only, deliberately. A check whose own dependencies can break is a check that goes
red for reasons that have nothing to do with what it watches.
"""

import json
import pathlib
import sys
import urllib.error
import urllib.request

# Long enough for a slow TLS handshake over a proxy, short enough that three attempts plus the
# workflow's own waits stay inside its timeout.
TIMEOUT_SECONDS = 20

# A User-Agent, because a document published for OAuth clients is served by infrastructure that may
# treat a library default as a scraper. Naming the check means whoever reads their access log can
# tell what this is.
USER_AGENT = "boltway-cimd-check (+https://github.com/TobiiNT/Boltway)"


def captures(spec_dir: pathlib.Path) -> pathlib.Path | None:
    """The newest `cimd-live-*.json`, chosen by the date in its name.

    By name rather than by mtime: a checkout writes every file at the same moment, so mtime here
    orders nothing. The name carries the measurement date, which is the thing that actually orders
    them.
    """
    found = sorted(spec_dir.glob("cimd-live-*.json"))
    return found[-1] if found else None


def parse(text: str) -> dict[str, object]:
    """Read a capture into `{url: document}`.

    The format is a `// <url>` line followed by that URL's document on the next line, and a leading
    block of `//` prose describing what the re-measurement found. Written by hand, so this reads it
    forgivingly: any `//` line that is a URL names the document that follows.
    """
    documents: dict[str, object] = {}
    url: str | None = None

    for line in text.splitlines():
        stripped = line.strip()

        if not stripped:
            continue

        if stripped.startswith("//"):
            comment = stripped[2:].strip()
            url = comment if comment.startswith("https://") else url
            continue

        if url is not None:
            documents[url] = json.loads(stripped)
            url = None

    return documents


def fetch(url: str) -> object:
    """The document as the vendor serves it today."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})

    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


def differences(captured: object, live: object, path: str = "") -> list[str]:
    """What changed, named field by field.

    A diff rather than a boolean, because "something moved" sends a person to read two documents
    side by side and "`token_endpoint_auth_method` appeared" sends them to `C-03`. The second is the
    whole value of the `C-*` table.
    """
    if isinstance(captured, dict) and isinstance(live, dict):
        found: list[str] = []

        for key in sorted(set(captured) | set(live)):
            here = f"{path}.{key}" if path else key

            if key not in live:
                found.append(f"{here}: gone (was {json.dumps(captured[key])})")
            elif key not in captured:
                found.append(f"{here}: new ({json.dumps(live[key])})")
            else:
                found.extend(differences(captured[key], live[key], here))

        return found

    # Lists compared in order, because order is meaningful in some of these members and this check
    # cannot tell which. Reporting a reordering the reader then dismisses costs less than hiding one
    # that mattered.
    if captured != live:
        return [f"{path or '(document)'}: {json.dumps(captured)} -> {json.dumps(live)}"]

    return []


def main(argv: list[str]) -> int:
    spec_dir = pathlib.Path(argv[1] if len(argv) > 1 else "spec")

    capture = captures(spec_dir)

    if capture is None:
        print(f"no cimd-live-*.json in {spec_dir}: there is nothing to check against.")
        return 1

    documents = parse(capture.read_text(encoding="utf-8"))

    if not documents:
        print(f"{capture.name} named no documents: the capture format may have changed.")
        return 1

    print(f"comparing {len(documents)} document(s) against {capture.name}")

    changed: list[str] = []
    unreachable: list[str] = []

    for url, captured in sorted(documents.items()):
        try:
            live = fetch(url)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as failure:
            unreachable.append(f"{url}: {type(failure).__name__}: {failure}")
            print(f"  ?  {url} — could not be asked")
            continue

        found = differences(captured, live)

        if found:
            changed.append(url)
            print(f"  !  {url} — changed since {capture.name}")
            for line in found:
                print(f"       {line}")
        else:
            print(f"  ok {url}")

    if unreachable:
        print()
        print("Nothing was measured for:")
        for line in unreachable:
            print(f"  {line}")

        # Ahead of the changed check on purpose. A run that could not ask every question has not
        # established the answer to the ones it did — reporting "one changed, one unknown" as work
        # owed would file an issue whose list is incomplete, and the retry costs one minute.
        return 2

    if changed:
        print()
        print(
            f"{len(changed)} document(s) moved. Re-capture into "
            f"spec/cimd-live-<today>.json, then re-read the C-* rows the change touches in "
            "spec/REQUIREMENTS.md section 6 and fix anything that stopped being true."
        )
        return 1

    print()
    print(f"every captured document still answers what it did on {capture.stem.removeprefix('cimd-live-')}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
