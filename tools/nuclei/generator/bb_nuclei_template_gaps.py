#!/usr/bin/env python3
"""Detect KB patterns that lack a nuclei template — MECHANICAL inventory only.

Division of labour (same as deepdive handoff):
  * THIS script (cheap/mechanical, OK on VPS/Hermes): inventory which KB patterns
    have HTTP-checkable signals but no custom-safe nuclei template yet, and queue
    them.
  * Template GENERATION is a LOCAL strong-model (Opus) job — converting prose
    patterns into correct, catch-all-aware nuclei YAML needs precision/judgement
    that the cheap VPS model cannot do reliably (malformed templates waste scans
    or false-positive). A Hermes agent MUST NOT generate templates.

Output -> ~/.hermes/workspace/nuclei_template_queue.jsonl (gaps for local Opus).
Local picks up via automation/pull_nuclei_gaps.sh, then runs/extends
scripts/bb_kb_to_nuclei.py.
"""
import json
import os
import re
from pathlib import Path

HERMES_HOME = Path(os.environ.get("HERMES_HOME", os.path.expanduser("~/.hermes")))
KB_DIR = HERMES_HOME / "kb"
AGENT = HERMES_HOME / "hermes-agent"
TPL_DIR = AGENT / "templates" / "nuclei" / "custom-safe"
QUEUE = HERMES_HOME / "workspace" / "nuclei_template_queue.jsonl"

# Signals that a KB pattern describes a concrete HTTP-checkable exposure.
PATH_RE = re.compile(r"`?(/[A-Za-z0-9._\-/]{2,})`?")
# Logic / interaction classes that nuclei GET-matchers cannot reliably template
# (need active payloads, oracles, or auth flows) — excluded.
EXCLUDE_CLASSES = (
    "ssrf", "sqli", "sql injection", "cors", "enumerat", "injection", "race",
    "captcha", "idor", "oauth", "oidc", "saml", "jwt", "smuggl", "cache",
    "clickjack", "csrf", "prototype", "deserial", "xxe", "ssti", "business logic",
    "blind", "oracle", "takeover", "dependency confusion", "host header",
    "open redirect", "websocket", "graphql", "ai llm", "mcp", "memory api",
)
# A pattern is GET-templatable only if it names a concrete fixed exposure path.
FIXED_PATH_RE = __import__("re").compile(
    r"`?(/(?:\.[a-z]|actuator|_ignition|swagger|api-docs|server-status|phpinfo|"
    r"server-info|debug|config\.|env|metrics|health|wp-json|\.well-known|"
    r"\.git|\.svn|\.npmrc|\.aws|backup|web\.config|appsettings)[A-Za-z0-9._\-/]*)`?",
    __import__("re").IGNORECASE)


def _existing_template_keys():
    keys = set()
    if TPL_DIR.exists():
        for f in TPL_DIR.glob("*.yaml"):
            txt = f.read_text(encoding="utf-8", errors="ignore").lower()
            keys.add(f.stem.lower())
            for m in PATH_RE.findall(txt):
                keys.add(m.lower())
    return keys


def main():
    if not KB_DIR.exists():
        print("no KB dir"); return
    existing = _existing_template_keys()
    gaps = []
    for f in sorted(KB_DIR.glob("Pattern - *.md")):
        txt = f.read_text(encoding="utf-8", errors="ignore")
        low = txt.lower()
        name = f.stem.replace("Pattern - ", "")
        # skip logic/interaction classes (not GET-templatable)
        if any(c in name.lower() or c in low[:400] for c in EXCLUDE_CLASSES):
            continue
        # require a concrete fixed exposure path
        paths = sorted(set(FIXED_PATH_RE.findall(txt)))[:8]
        if not paths:
            continue
        # already covered? (template filename or any of its paths overlap)
        covered = name.lower().replace(" ", "-") in " ".join(existing)
        if not covered and paths:
            covered = any(p.lower() in existing for p in paths)
        if covered:
            continue
        gaps.append({"pattern": name, "file": f.name,
                     "candidate_paths": paths,
                     "hint": "convert to catch-all-aware GET nuclei template (LOCAL Opus only)"})

    QUEUE.parent.mkdir(parents=True, exist_ok=True)
    QUEUE.write_text("\n".join(json.dumps(g, ensure_ascii=False) for g in gaps)
                     + ("\n" if gaps else ""), encoding="utf-8")
    print(f"KB patterns lacking nuclei template: {len(gaps)} -> {QUEUE}")
    for g in gaps[:12]:
        print(f"  - {g['pattern']}  paths={g['candidate_paths'][:3]}")
    if gaps:
        print("\n  → 本地 Opus: automation/pull_nuclei_gaps.sh 後用 bb_kb_to_nuclei.py 生成。"
              "\n  → 切勿讓 Hermes(minimax) agent 生成模板。")


if __name__ == "__main__":
    main()
