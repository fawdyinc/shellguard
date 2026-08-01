#!/usr/bin/env python3
"""Extract the commands Fawdy's skills recommend, for validation against the registry.

A skill that tells the agent to run a command the guard rail refuses is worse
than a skill that says nothing: the agent burns turns discovering the refusal.
This produces the corpus that validator/testdata/skill-commands.txt is built
from, so that mismatch fails a test instead of a support call.

Usage:
    scripts/extract-skill-commands.py <fawdy-legacy>/src/lib/skills \\
        > validator/testdata/skill-commands.txt

Only fenced blocks tagged bash/sh/powershell are read -- untagged fences in
these skills hold sample output, config file excerpts, and log lines, none of
which are commands. Lines using shell constructs the guard rail does not model
(loops, conditionals, command substitution) are dropped with a note rather than
silently, so the corpus never looks more complete than it is.
"""

import pathlib
import re
import sys

SHELL_FENCES = {
    "bash": "bash",
    "sh": "bash",
    "shell": "bash",
    "console": "bash",
    "powershell": "powershell",
    "ps1": "powershell",
    "pwsh": "powershell",
}

# Constructs shellguard deliberately does not model. A skill line using one is
# not a single validatable command.
SHELL_CONSTRUCTS = re.compile(
    r"(^\s*(for|while|if|then|else|fi|do|done|case|esac|function)\b)"
    r"|(\$\()|(`)|(\|\|)|(&&)|(^\s*\w+=)"
)

# Placeholders the skills use for values the reader supplies. These must be
# substituted before parsing: `<pid>` would otherwise read as a redirect.
PLACEHOLDER = re.compile(r"<[^>]{1,40}>")


def extract(path: pathlib.Path):
    """Yield (line_number, shell, command) for each recommended command in path.

    shell is "bash" or "powershell", taken from the fence tag: the two use
    different parsers and different halves of the registry.
    """
    fence_lang = None
    pending = ""
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        fence = re.match(r"^\s*```\s*([A-Za-z0-9_+-]*)\s*$", raw)
        if fence:
            fence_lang = fence.group(1).lower() if fence_lang is None else None
            pending = ""
            continue
        shell = SHELL_FENCES.get(fence_lang) if fence_lang else None
        if shell is None:
            continue

        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        # Join backslash continuations before doing anything else.
        if line.endswith("\\"):
            pending += line[:-1].strip() + " "
            continue
        line = (pending + line).strip()
        pending = ""

        # Strip a trailing comment, but not a '#' inside quotes.
        if "#" in line and line.count('"') % 2 == 0 and line.count("'") % 2 == 0:
            line = re.sub(r"\s+#\s.*$", "", line).strip()
        if not line:
            continue

        if SHELL_CONSTRUCTS.search(line):
            yield lineno, shell, None  # dropped: reported, never silent
            continue

        yield lineno, shell, PLACEHOLDER.sub("PLACEHOLDER", line)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    root = pathlib.Path(sys.argv[1])
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2

    seen = set()
    rows, dropped = [], 0
    for md in sorted(root.rglob("*.md")):
        rel = md.relative_to(root)
        for lineno, shell, command in extract(md):
            if command is None:
                dropped += 1
                continue
            if (shell, command) in seen:
                continue
            seen.add((shell, command))
            rows.append((f"{rel}:{lineno}", shell, command))

    print("# Commands Fawdy's skills recommend, extracted from their fenced")
    print("# bash/powershell blocks. Regenerate with:")
    print("#   scripts/extract-skill-commands.py <fawdy-legacy>/src/lib/skills \\")
    print("#     > validator/testdata/skill-commands.txt")
    print(f"# {len(rows)} unique commands; {dropped} lines dropped as shell constructs.")
    print("# Format: <source>\\t<shell>\\t<command>")
    for source, shell, command in rows:
        print(f"{source}\t{shell}\t{command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
