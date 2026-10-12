#!/usr/bin/env python3
"""Check that every ACTIVE target records where its findings will be delivered.

For each target that has a SCOPE.md, require BOTH `Platform:` and `Program URL:` to be filled in --
or the canonical Target page (`01 - Targets/<t>/Target - <t>.md`) to carry a non-empty `platform:` or
`channel:` in its frontmatter.

Why: a target can sit in hunting for months with findings labelled for a platform, and only when you are
ready to submit do you find out the program is private and you are not in it. Fill the channel BEFORE you
start hunting, not before you submit. A rule nobody runs does not exist, so this check runs it.

Design rules (each guards against a known failure mode):
  * Only targets that are already being worked (or about to be submitted) need a channel. `planned`, `closed`
    and `parked` are exempt: a gate that fires on nearly every target carries no signal -- it just turns the
    runner red and drowns the warnings that matter.
  * Read the lifecycle status from the CANONICAL Target page, not from the workshop copy of SCOPE.md.
    A status looked up in the wrong place filters nothing while still looking normal.
  * When both exist, the canonical copy wins. The workshop SCOPE.md is a hand-kept copy; a gate must not
    judge a copy that is not the source of truth.
  * A target that exists ONLY in the workshop (no canonical Target page) cannot be fixed by filling SCOPE.md;
    it is reported separately and does not fail the check.
  * Field values are read within ONE line. A blank `- Platform:` followed by `- Program URL:` on the next line
    must not read as Platform = "- Program URL:" (an unanchored `\\s*(.*)` crosses the newline and turns an
    empty file into a "filled" one).

Usage:
  python3 automation/check_scope_channel.py           # human-readable; exit 1 if any real gap
  python3 automation/check_scope_channel.py --json    # machine-readable

Overrides (tests use these): WORKSHOP_ROOT=<dir with <target>/SCOPE.md>  TARGETS_DIR=<dir with <target>/Target - <target>.md>
"""
import glob
import json
import os
import re
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
CANONICAL = os.environ.get("TARGETS_DIR") or os.path.join(REPO, "01 - Targets")

INACTIVE = {"planned", "closed", "parked"}
EMPTY_VALUES = {"", "-", "—", "–", "tbd", "unknown", "n/a", "none"}


def workshop_root() -> str:
    """WORKSHOP_ROOT env wins; otherwise ask workspace_layout.sh (the single source of layout truth)."""
    env = os.environ.get("WORKSHOP_ROOT")
    if env:
        return env
    layout = os.path.join(REPO, "automation", "workspace_layout.sh")
    try:
        out = subprocess.run(["bash", layout, "--shell"], capture_output=True, text=True, timeout=10).stdout
        m = re.search(r"^WORKSHOP_ROOT='([^']*)'", out, re.M)
        if m:
            return m.group(1)
    except (OSError, subprocess.SubprocessError):
        pass
    return os.path.join(REPO, "workspace", "workshop")


def _frontmatter(path: str) -> str:
    head = open(path, encoding="utf-8", errors="replace").read()[:3000]
    m = re.match(r"---\n(.*?)\n---", head, re.S)
    return m.group(1) if m else ""


def target_status(target_dir: str) -> str:
    """Lifecycle status from the canonical Target page; empty string if unknown (= do not filter, be conservative)."""
    tgt = os.path.basename(target_dir)
    for base in (os.path.join(CANONICAL, tgt), target_dir):
        p = os.path.join(base, "Target - %s.md" % tgt)
        if os.path.isfile(p):
            m = re.search(r'^status:\s*"?([\w-]+)', _frontmatter(p), re.M)
            return m.group(1).strip().lower() if m else ""
    return ""


def canonical_channel(tgt: str) -> str:
    """Non-empty `platform:` / `channel:` from the canonical Target page frontmatter, else ''."""
    for p in sorted(glob.glob(os.path.join(CANONICAL, tgt, "Target - *.md"))):
        fm = _frontmatter(p)
        for key in ("platform", "channel"):
            m = re.search(r'^%s:[ \t]*"?([^"#\n]*)' % key, fm, re.M)
            if m and m.group(1).strip().lower() not in EMPTY_VALUES:
                return m.group(1).strip()
    return ""


def active_scopes(root: str = None):
    """SCOPE.md files of targets whose status is not planned/closed/parked. The canonical copy wins on name clashes."""
    root = root or workshop_root()
    by_name = {}
    for f in sorted(glob.glob(os.path.join(root, "*", "SCOPE.md"))):
        by_name[os.path.basename(os.path.dirname(f))] = f
    for f in sorted(glob.glob(os.path.join(CANONICAL, "*", "SCOPE.md"))):
        by_name[os.path.basename(os.path.dirname(f))] = f
    return [f for _, f in sorted(by_name.items())
            if target_status(os.path.dirname(f)) not in INACTIVE]


# Values are matched within a single line: [ \t]* and [^\n]* never cross a newline.
_PLATFORM_RE = re.compile(r"^[-* \t]*\**[ \t]*Platform:?\**:?[ \t]*([^\n]*)$", re.M)
_URL_RE = re.compile(r"^[-* \t]*\**[ \t]*(?:Program )?URL:?\**:?[ \t]*([^\n]*)$", re.M)


def _value(regex, text) -> str:
    m = regex.search(text)
    return re.sub(r"\*", "", m.group(1)).strip() if m else ""


def missing(root: str = None):
    out = []
    for f in active_scopes(root):
        text = open(f, encoding="utf-8", errors="replace").read()
        tgt = os.path.basename(os.path.dirname(f))
        pv, uv = _value(_PLATFORM_RE, text), _value(_URL_RE, text)
        # The "(Fill in from program page)" hint from the template can still be present while the channel
        # fields are filled, so its presence alone does not mean a gap; it is only reported as a hint.
        template_left = "fill in from program page" in text.lower()
        if (pv.lower() in EMPTY_VALUES or uv.lower() in EMPTY_VALUES) and not canonical_channel(tgt):
            workspace_only = not os.path.isdir(os.path.join(CANONICAL, tgt))
            out.append({"target": tgt, "platform": pv, "url": uv, "workspace_only": workspace_only,
                        "reason": "fields empty" + (" (template not cleaned up)" if template_left else "")})
    return out


def main() -> int:
    rows = missing()
    real = [r for r in rows if not r["workspace_only"]]
    ws_only = [r for r in rows if r["workspace_only"]]
    total = len(active_scopes())
    if "--json" in sys.argv:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 1 if real else 0
    print("## Delivery channel unconfirmed — %d / %d targets\n" % (len(real), total))
    for r in real:
        print("  %-24s %s" % (r["target"], r["reason"]))
    if real:
        print("\nA target with no confirmed channel may have nowhere to deliver what you find -- fill it in "
              "before you start hunting, not before you submit.")
    if ws_only:
        print("\n(%d more exist only in the workshop with no canonical Target page; not counted as failures -- "
              "either adopt them into the vault or confirm they are no longer being worked):" % len(ws_only))
        print("  " + ", ".join(r["target"] for r in ws_only))
    return 1 if real else 0


if __name__ == "__main__":
    sys.exit(main())
