#!/usr/bin/env python3
"""Extract the commands Fawdy's skills recommend, for validation against the registry.

A skill that tells the agent to run a command the guard rail refuses is worse
than a skill that says nothing: the agent burns turns discovering the refusal.
This produces the corpus that validator/testdata/skill-commands.txt is built
from, so that mismatch fails a test instead of a support call.

Usage:
    scripts/extract-skill-commands.py <fawdy-legacy>/src/lib/skills \\
        > validator/testdata/skill-commands.txt

Two sources are read.

Fenced blocks tagged bash/sh/powershell. Untagged fences in these skills hold
operator actions, sample output, config excerpts, and log lines -- none of them
commands the agent should run -- so they are deliberately ignored. That
convention is documented in the skills' own README.md.

Inline code spans, outside any fence. These are invisible to a reader auditing
fenced blocks, and commands do end up in them. To keep prose out of the corpus,
a span is taken only when its first token names a command already in the
registry: that admits `lmstat -a` and rejects `Cannot`, `Invalid`, and the log
fragments that make up most backticked text. The cost of this filter is stated
plainly -- it cannot catch an inline command whose tool is absent from the
registry entirely. Fenced blocks still cover that direction.

Spans holding a Unicode dash before a letter (`-F`) are counted and skipped.
That dash is a PDF extraction artefact, never a working flag, and at least one
appears inside a deliberate verbatim quotation of a vendor document.
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

# An inline span: `like this`. Requires two tokens, so a bare tool name used as
# a noun ("the `docker` daemon") is not mistaken for a recommendation.
INLINE_SPAN = re.compile(r"`([A-Za-z][A-Za-z0-9_.\-]*\s+[^`]{1,110})`")

# En dash or em dash immediately before a letter. Always a PDF artefact.
UNICODE_DASH_FLAG = re.compile(r"[–—][A-Za-z]")

# A line that tells the reader NOT to run something. The skills are required to
# name denied commands and refused flags -- an anti-pattern table, a "the vendor
# recommends X, the guard rail refuses it" note -- and those mentions are
# textually identical to a recommendation. Without this test the corpus reports
# the skills' most careful writing as defects.
NEGATION_CUE = re.compile(
    r"\b(no|not|never|don't|do not|cannot|can't|avoid|instead|rather than|"
    r"denied|denies|deny|blocked|blocks|refused|refuses|refuse|wrong|"
    r"anti-pattern|unavailable|is retained|legacy|deprecated|"
    r"disables?|disabled|switched off|turns? off)\b"
    r"|^\s*\|",  # a table row: the Wrong/Right tables are pure counter-example
    re.IGNORECASE,
)


def load_registry(manifests: pathlib.Path) -> dict:
    """Map lowercased command name -> "bash" | "powershell" for allowed commands.

    Denied manifests are excluded on purpose. The skills name denied commands
    constantly, and correctly: recording why a tool is refused, and what to use
    instead, is required of them. Treating each of those mentions as a
    recommendation would report the skills' best behaviour as a defect. A denied
    command inside a *fenced* block is still caught, which is the case that
    matters.
    """
    names = {}
    for yaml in sorted(manifests.rglob("*.yaml")):
        if yaml.name.startswith("_"):
            continue
        name = shell = None
        denied = False
        for line in yaml.read_text(encoding="utf-8").splitlines():
            if name is None:
                m = re.match(r"^name:\s*(.+?)\s*$", line)
                if m:
                    name = m.group(1).strip().strip("\"'")
            if shell is None:
                m = re.match(r"^shell:\s*(.+?)\s*$", line)
                if m:
                    shell = m.group(1).strip().strip("\"'")
            if re.match(r"^deny:\s*true\s*$", line):
                denied = True
        if not name or denied:
            continue
        if shell is None and "powershell" in yaml.parts:
            shell = "powershell"
        names[name.lower()] = "powershell" if shell == "powershell" else "bash"
    return names


def clean(line: str) -> str:
    """Strip a trailing comment, but not a '#' inside quotes."""
    if "#" in line and line.count('"') % 2 == 0 and line.count("'") % 2 == 0:
        line = re.sub(r"\s+#\s.*$", "", line).strip()
    return line


def extract(path: pathlib.Path, registry: dict):
    """Yield (line_number, shell, command, origin) for each recommended command.

    shell is "bash" or "powershell": the two use different parsers and different
    halves of the registry. For a fenced block it comes from the fence tag; for
    an inline span it comes from the matched manifest's own scoping.

    origin is "fence", "inline", or one of the skip reasons, so the header can
    report what was left out instead of silently shrinking the corpus.
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
            # Outside a shell fence. Inline spans only count outside every
            # fence -- an untagged fence holds operator content by convention.
            if fence_lang is not None:
                continue
            if NEGATION_CUE.search(raw):
                for _ in INLINE_SPAN.findall(raw):
                    yield lineno, None, None, "counter-example"
                continue
            for span in INLINE_SPAN.findall(raw):
                candidate = clean(span.strip())
                if not candidate:
                    continue
                if UNICODE_DASH_FLAG.search(candidate):
                    yield lineno, None, None, "unicode-dash"
                    continue
                tokens = candidate.split()
                head = tokens[0].lower()
                if head not in registry:
                    continue
                # Require a flag. An inline span worth validating carries one;
                # without that test, log-catalogue entries and syntax templates
                # whose first word happens to name a tool ("File version ver
                # cannot be read", "lmutil command") enter the corpus as
                # commands and fail for reasons that are not defects.
                if not any(t.startswith("-") for t in tokens[1:]):
                    yield lineno, None, None, "no-flag"
                    continue
                # Three tokens minimum. Prose names a flag without its value
                # constantly -- "use `journalctl -u` for one unit", "`sar -n`
                # takes a keyword" -- and those fail for a missing argument that
                # the sentence around them supplies. A real inline command
                # carries a flag AND something to act on.
                if len(tokens) < 3:
                    yield lineno, None, None, "flag-mention"
                    continue
                if SHELL_CONSTRUCTS.search(candidate):
                    yield lineno, None, None, "construct"
                    continue
                yield (
                    lineno,
                    registry[head],
                    PLACEHOLDER.sub("PLACEHOLDER", candidate),
                    "inline",
                )
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

        line = clean(line)
        if not line:
            continue

        if SHELL_CONSTRUCTS.search(line):
            yield lineno, None, None, "construct"
            continue

        yield lineno, shell, PLACEHOLDER.sub("PLACEHOLDER", line), "fence"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    root = pathlib.Path(sys.argv[1])
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2

    manifests = pathlib.Path(__file__).resolve().parent.parent / "manifest" / "manifests"
    if not manifests.is_dir():
        print(f"registry not found: {manifests}", file=sys.stderr)
        return 2
    registry = load_registry(manifests)

    seen = set()
    rows = []
    counts = {"fence": 0, "inline": 0, "construct": 0, "unicode-dash": 0, "no-flag": 0, "counter-example": 0, "flag-mention": 0}
    for md in sorted(root.rglob("*.md")):
        rel = md.relative_to(root)
        for lineno, shell, command, origin in extract(md, registry):
            counts[origin] = counts.get(origin, 0) + 1
            if command is None:
                continue
            if (shell, command) in seen:
                continue
            seen.add((shell, command))
            rows.append((f"{rel}:{lineno}", shell, command))

    print("# Commands Fawdy's skills recommend, extracted from their fenced")
    print("# bash/powershell blocks and from inline code spans. Regenerate with:")
    print("#   scripts/extract-skill-commands.py <fawdy-legacy>/src/lib/skills \\")
    print("#     > validator/testdata/skill-commands.txt")
    print(
        f"# {len(rows)} unique commands "
        f"({counts['fence']} from fences, {counts['inline']} from inline spans); "
        f"{counts['construct']} dropped as shell constructs, "
        f"{counts["unicode-dash"]} skipped for a Unicode dash before a flag, "
        f"{counts["counter-example"]} skipped as counter-examples."
    )
    print("# Format: <source>\\t<shell>\\t<command>")
    for source, shell, command in rows:
        print(f"{source}\t{shell}\t{command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
