#!/usr/bin/env python3
"""Go red when an em-dash reaches this repository's prose.

    python3 scripts/check-dashes.py

`CLAUDE.md` bans U+2014 in what this repository *writes* - documents and comments - and leaves it
where the software *speaks* - string literals, which are output. That split is why `grep` alone
cannot check it: grep cannot tell a comment from a string.

**This file exists so the rule does not have to carry numbers.** It used to state its own counts,
which meant editing any string literal made `CLAUDE.md` stale, and `CLAUDE.md` is read at the start
of every session. A number in there is a number somebody has to keep true forever, and one that was
already written down wrong once. Here it is computed instead, so it cannot rot.

**Three trees are out of scope, and the reason differs for each.** `spec/` holds vendored IETF
drafts and dated captures of live surfaces, where rewriting punctuation falsifies somebody else's
document or a recorded measurement. `docs/archive/` is a dated measurement kept because it is wrong
on purpose. `docs/examples/translations.vi.json` is user-facing copy a deployment edits, and how a
deployment punctuates its own pages is not this repository's business.

**Exit codes, and they are a contract:**

    0  no em-dash in any document or comment
    1  at least one found - the report names file and line
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

# By codepoint, so this file does not contain the character it bans. Written as a literal, the
# constant counted itself: every run reported one more string-literal em-dash than the repository
# has, forever, and the one extra was this line. A checker that cannot come up clean about itself
# is a checker whose number nobody can reconcile.
DASH = chr(0x2014)

SKIP_PREFIX = ("spec/", "docs/archive/")
SKIP_FILE = ("docs/examples/translations.vi.json",)

HASH_NAMES = ("Dockerfile", "CODEOWNERS", ".editorconfig", ".gitignore", ".dockerignore", ".env.example")


def tracked() -> list[str]:
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout
    return [f for f in out.split("\n") if f and not f.startswith(SKIP_PREFIX) and f not in SKIP_FILE]


def prose_only(path: str, text: str) -> str:
    """Everything a *reader of this repository* wrote, with what the software says removed.

    Blanked rather than deleted, so a line number in the report still matches the file.
    """
    blank = lambda m: re.sub(r"[^\n]", " ", m.group())  # noqa: E731 - one expression, used twice

    if path.endswith(".md"):
        return text
    if path.endswith(".cs"):
        return re.sub(r'"""(?:.|\n)*?"""|@?"(?:[^"\\\n]|\\.|"")*"', blank, text)
    if path.endswith((".props", ".csproj", ".slnx", ".targets")):
        # Only the comments are ours; element and attribute text is what MSBuild or an IDE shows.
        # Keeping the comments and blanking the rest, rather than the other way round, because the
        # first draft collected the comments into a new string and every line number it reported was
        # wrong - which costs more time on a red build than the check saves.
        return "".join(m.group() if m.lastindex is None and m.group().startswith("<!--")
                       else re.sub(r"[^\n]", " ", m.group())
                       for m in re.finditer(r"<!--(?:.|\n)*?-->|(?:(?!<!--).|\n)+", text))
    if path.endswith((".css", ".js")):
        text = re.sub(r"/\*(?:.|\n)*?\*/", lambda m: "\x00" + m.group()[1:], text)
        out = []
        for line in text.split("\n"):
            keep = "\x00" in line or line.lstrip().startswith("//") or line.lstrip().startswith("*")
            out.append(line.replace("\x00", "/") if keep else "")
        return "\n".join(out)
    if path.endswith((".yml", ".yaml", ".sh", ".py")) or pathlib.Path(path).name in HASH_NAMES:
        lines = [l if l.lstrip().startswith("#") else "" for l in text.split("\n")]
        return "\n".join(lines)
    return ""


def main() -> int:
    found = []
    spoken = 0

    for f in tracked():
        p = pathlib.Path(f)
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if DASH not in text:
            continue

        prose = prose_only(f, text)
        spoken += text.count(DASH) - prose.count(DASH)

        for i, line in enumerate(prose.split("\n"), 1):
            if DASH in line:
                found.append((f, i, text.split("\n")[i - 1].strip()[:100]))

    for f, i, line in found:
        print(f"{f}:{i}: {line}")

    # Reported rather than failed. A literal is output, and changing one is a change to what this
    # software says: that belongs in a commit about the message, not in a punctuation sweep.
    print(f"\n{len(found)} in prose or comments (must be 0), {spoken} inside string literals (left alone).")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
