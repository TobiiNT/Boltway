#!/usr/bin/env python3
"""Go red when an Internet-Draft this repository pins has been revised.

    python3 scripts/check-pinned-drafts.py [spec-dir]

`auth/spec/REQUIREMENTS.md` records U-15: OAuth 2.1 is a draft, not an RFC, its normative text
may still move, and the mitigation written down there is three sentences long. Two of them were
done and stay done: cite the exact revision, pin a copy in the repo. The third, *"re-diff on each
new revision"*, is an instruction to a person with nothing to tell them the day it applies.

That is the shape of failure this repository keeps finding. `contract-check.mjs` existed, passed
when run by hand, and nothing ran it for a day. `--skip-duplicate` was green while dropping the
build that mattered. An instruction nobody is prompted to follow is indistinguishable from an
instruction nobody follows, and the way you find out is that the pinned copy and the working text
have disagreed for months.

**What it compares.** The revision in each pinned filename against the revision the IETF
datatracker reports for that draft today. `draft-ietf-oauth-v2-1-15.txt` says we are working from
revision 15; if the datatracker says 16, the diff described in U-15 is now owed and this goes red.

**Where the list of drafts comes from: the directory, not a list in this file.** Pinning a new
draft is `cp` into `auth/spec/` and nothing else. A second place to name them is a second place
for them to be wrong, and the one that goes stale is always the one no build reads.

**An unreachable datatracker fails.** It is not evidence that nothing changed, and this check is
worth having only if its green means something. That is the same rule
`check-published-versions.py` applies to an unreadable feed, and the reason is identical: a check
that passes when it could not look is worse than no check, because it is believed.

**An expired draft is reported and does not fail.** An I-D expires six months after publication
whether or not anyone intends to revise it, so expiry on its own is not work. It is printed
because U-15 exists to keep the moving target in view, and a citation to an expired draft is worth
knowing about before somebody quotes it to a client.
"""

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

DATATRACKER = 'https://datatracker.ietf.org/api/v1/doc/document/'

# IETF revisions are always two digits, and a draft name may itself end in a digit:
# `draft-ietf-oauth-v2-1-15` is revision 15 of `draft-ietf-oauth-v2-1`, not revision 1 of
# something. Anchoring on exactly two trailing digits is what keeps those apart.
PINNED = re.compile(r'^(draft-.+)-(\d{2})$')


def pinned_drafts(spec_dir):
    """Every draft pinned in `spec_dir`, as (name, revision, filename)."""
    found = []

    for entry in sorted(os.listdir(spec_dir)):
        if not entry.endswith('.txt'):
            continue

        match = PINNED.match(entry[: -len('.txt')])

        if match:
            found.append((match.group(1), match.group(2), entry))

    return found


def current_revision(name):
    """What the datatracker says about `name` today: (revision, expiry, title)."""
    url = f'{DATATRACKER}?name={urllib.parse.quote(name)}&format=json'

    with urllib.request.urlopen(url, timeout=30) as response:
        payload = json.load(response)

    objects = payload.get('objects') or []

    # A name that resolves to nothing is a failure rather than a pass. It means the pinned file is
    # named something the datatracker does not know, so this check has never been checking it.
    if not objects:
        raise LookupError(f'the datatracker has no document named {name}')

    document = objects[0]

    return document.get('rev'), document.get('expires'), document.get('title', '')


def main(argv):
    spec_dir = argv[1] if len(argv) > 1 else 'auth/spec'

    if not os.path.isdir(spec_dir):
        print(f'::error::{spec_dir} is not a directory, so no pinned draft was checked.')
        return 1

    drafts = pinned_drafts(spec_dir)

    # Nothing pinned is not a pass either: this check is wired to a directory, and a directory that
    # has moved or been emptied would otherwise report success having done nothing.
    if not drafts:
        print(f'::error::no pinned draft-*.txt found in {spec_dir}. Either none is pinned, in')
        print('::error::which case U-15 has lost its mitigation, or this check is pointed at the')
        print('::error::wrong directory. Neither is a pass.')
        return 1

    stale = []
    unreachable = []
    now = datetime.now(timezone.utc)

    for name, revision, filename in drafts:
        try:
            latest, expires, title = current_revision(name)
        except (urllib.error.URLError, LookupError, json.JSONDecodeError, TimeoutError) as failure:
            unreachable.append((filename, failure))
            print(f'  UNREACHABLE {filename}: {failure}')
            continue

        if latest != revision:
            stale.append((filename, name, revision, latest, title))
            print(f'  REVISED     {filename}: pinned {revision}, datatracker says {latest}')
        else:
            print(f'  current     {filename}: revision {revision}')

        if expires:
            when = datetime.fromisoformat(expires.replace('Z', '+00:00'))
            days = (when - now).days

            # Labelled with `latest`, not with what is pinned: the datatracker reports the expiry
            # of the revision it is currently serving. Printing that date beside an older pinned
            # number would state an expiry for a revision nobody asked about.
            if days < 0:
                print(f'::notice::{name}-{latest} expired {-days} day(s) ago ({when.date()}). '
                      f'An I-D expires whether or not a revision is intended, so on its own '
                      f'there is nothing to re-diff; cite it as the expired draft it is.')
            elif days <= 30:
                print(f'::notice::{name}-{latest} expires in {days} day(s) ({when.date()}).')

    print()

    for filename, name, revision, latest, title in stale:
        print(f'::error::{title or name} has moved from {revision} to {latest}.')
        print(f'::error::  U-15 in auth/spec/REQUIREMENTS.md asks for a re-diff on each new')
        print(f'::error::  revision. Fetch {name}-{latest}.txt, diff it against the pinned')
        print(f'::error::  {filename}, act on anything normative that moved, then replace the')
        print(f'::error::  pinned copy and update every citation of the revision number.')

    for filename, failure in unreachable:
        print(f'::error::could not ask the datatracker about {filename}: {failure}.')
        print('::error::  That is not evidence the pinned revision is current, so this check')
        print('::error::  fails rather than reporting a green it did not establish.')

    if stale or unreachable:
        return 1

    print(f'Every pinned draft is the current revision ({len(drafts)} checked).')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
