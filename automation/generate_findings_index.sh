#!/usr/bin/env bash
# generate_findings_index.sh — generate FINDINGS_QUICK_REF.md for a target: a scannable table of every
# finding, attempt and submission, so you can check "is this really new?" BEFORE claiming a discovery.
#
# Usage:  bash automation/generate_findings_index.sh <target>
# Output: workspace/workshop/<target>/FINDINGS_QUICK_REF.md      (read by dedup_hints.sh, audit_workspace.sh,
#                                                                 start_session.py and end_session.py)
#     AND 01 - Targets/<target>/FINDINGS_QUICK_REF.md             (read by humans in the vault)
#
# Why BOTH copies: automation reads the workshop copy, humans read the vault copy. Writing only one lets the
# other rot — a vault copy that is months stale means every dedup check reads months-old state. Keep them
# in lockstep.
#
# Hand-written content survives regeneration if you wrap it in
#     <!-- MANUAL:BEGIN -->  ...  <!-- MANUAL:END -->
# Everything outside those markers is regenerated and overwritten.
#
# What gets indexed (from 01 - Targets/<target>/):
#   Findings/*.md, Attempts/*.md, Submissions/**/*.md   (files starting with "_" are skipped)
# What does NOT get indexed:
#   * files with `fileClass: form`
#   * anything under a `Forms/` directory — those are copies of documents that were sent out; the Submission
#     file is the record, and indexing both produces duplicate rows with blank fields
#
# Overrides (tests use these): TARGETS_DIR=<dir with <target>/>   WORKSHOP_ROOT=<dir>
set -euo pipefail

if [[ $# -lt 1 ]]; then
  cat <<'USAGE'
Usage: bash automation/generate_findings_index.sh <target>

Generates FINDINGS_QUICK_REF.md for a target — a quick-scan table of all Findings, Attempts and
Submissions — into both the workshop folder and the vault target folder.

Example:
  bash automation/generate_findings_index.sh acme
USAGE
  exit 1
fi

TARGET="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Explicit overrides win over the layout (they let tests run against a synthetic tree), so remember
# them before the layout script assigns its own values.
_ws_override="${WORKSHOP_ROOT:-}"
# shellcheck source=automation/workspace_layout.sh
eval "$("$SCRIPT_DIR/workspace_layout.sh" --shell)"
[[ -n "$_ws_override" ]] && WORKSHOP_ROOT="$_ws_override"
VAULT_TARGETS="${TARGETS_DIR:-$VAULT_ROOT/01 - Targets}"
VAULT_TARGET_DIR="$VAULT_TARGETS/$TARGET"
WORKSHOP_DIR="$WORKSHOP_ROOT/$TARGET"
OUT_FILE="$WORKSHOP_DIR/FINDINGS_QUICK_REF.md"
VAULT_OUT_FILE="$VAULT_TARGET_DIR/FINDINGS_QUICK_REF.md"

if [[ ! -d "$VAULT_TARGET_DIR" ]]; then
  echo "[!] Vault target not found: $VAULT_TARGET_DIR" >&2
  exit 2
fi

mkdir -p "$WORKSHOP_DIR"

python3 - "$VAULT_TARGET_DIR" "$TARGET" "$OUT_FILE" "$VAULT_OUT_FILE" <<'PYEOF'
import re
import sys
from datetime import date
from pathlib import Path

vault_dir = Path(sys.argv[1])
target = sys.argv[2]
out_file = Path(sys.argv[3])
vault_out_file = Path(sys.argv[4])

MANUAL_BEGIN = "<!-- MANUAL:BEGIN -->"
MANUAL_END = "<!-- MANUAL:END -->"
LIST_KEYS = {"artifacts"}


def extract_manual_block(*paths):
    """Carry hand-written content across regenerations.

    Returns the first MANUAL block found (markers included), or ''. Without this, regenerating would
    silently destroy notes people added to the quick-ref — the file everyone reads first.
    """
    for path in paths:
        if path is None or not path.is_file():
            continue
        text = path.read_text(errors="replace")
        start = text.find(MANUAL_BEGIN)
        if start == -1:
            continue
        end = text.find(MANUAL_END, start)
        if end == -1:
            continue
        return text[start:end + len(MANUAL_END)].strip()
    return ""


def extract_frontmatter(path):
    """Tiny YAML-subset reader: scalar keys plus the list key `artifacts`."""
    text = path.read_text(errors="replace")
    empty_lists = {k: [] for k in LIST_KEYS}
    if not text.startswith("---"):
        return {}, empty_lists, text
    end = text.find("\n---", 3)
    if end == -1:
        return {}, empty_lists, text
    fm_text, body = text[3:end], text[end + 4:]
    fm, fm_lists = {}, {k: [] for k in LIST_KEYS}
    current_list = None  # the LIST_KEYS key we are accumulating into
    for line in fm_text.splitlines():
        matched_list = False
        for lk in LIST_KEYS:
            if re.match(rf"^{lk}\s*:", line):
                m = re.match(rf"^{lk}\s*:\s*\[(.+)\]", line)  # inline list: key: [a, b]
                if m:
                    items = [x.strip().strip('"').strip("'") for x in m.group(1).split(",")]
                    fm_lists[lk].extend(x for x in items if x and x != "{{identifier_1}}")
                    current_list = None
                else:
                    current_list = lk
                matched_list = True
                break
        if matched_list:
            continue
        if current_list:
            if re.match(r"^\s+-\s+", line):
                item = re.sub(r"^\s+-\s+", "", line).strip().strip('"').strip("'")
                if item and item != "{{identifier_1}}":
                    fm_lists[current_list].append(item)
                continue
            if re.match(r"^\w", line):
                current_list = None
        m = re.match(r"^(\w[\w_-]*):\s*(.*)", line)
        if m:
            key, val = m.group(1), m.group(2).strip().strip('"').strip("'")
            fm.setdefault(key, val)
    return fm, fm_lists, body


def host_from_filename(fname):
    m = re.search(r"([\w-]+\.[a-z]{2,6}(?:\.[a-z]{2})?)", fname)
    return m.group(1) if m else ""


def id_from_filename(fname):
    """Fallback ID when the frontmatter has none: `ABC-012` style codes or a CVE number."""
    m = re.search(r"(CVE-\d{4}-\d+|\b[A-Z][A-Z0-9]{1,9}-[A-Z]?\d+[-v\d]*)", fname)
    return m.group(1) if m else ""


rows_findings, rows_attempts, rows_submissions = [], [], []
known_identifiers = {}              # identifier -> [report ids that declared it]
submissions_missing_artifacts = []  # ids of Submissions with no `artifacts:`

for section, folder_name, rows in (
    ("Finding", "Findings", rows_findings),
    ("Attempt", "Attempts", rows_attempts),
    ("Submission", "Submissions", rows_submissions),
):
    folder = vault_dir / folder_name
    if not folder.exists():
        continue
    for f in sorted(folder.glob("**/*.md")):
        if f.stem.startswith("_"):
            continue
        # Documents that were sent out live under Forms/; the Submission file is the record. Indexing both
        # produces duplicate rows with blank fields and counts cover emails as submissions.
        if "Forms" in f.parts:
            continue
        fm, fm_lists, _body = extract_frontmatter(f)
        if fm.get("fileClass", "").lower() == "form":
            continue
        fname = f.stem

        finding_id = fm.get("finding_id", "") or fm.get("case_id", "") or fm.get("advisory", "") or id_from_filename(fname)
        title = fm.get("title", "") or re.sub(r"^(?:Finding|Attempt|Submission)\s*-\s*\S+\s*-\s*", "", fname)
        status = fm.get("status", fm.get("triage_status", ""))
        severity = fm.get("severity", fm.get("risk", ""))
        host = fm.get("host", fm.get("endpoint", fm.get("affected_host", "")))
        if section == "Attempt":
            finding_id = finding_id or fname
            status = status or fm.get("result", "")
        host = host or host_from_filename(fname)

        row = {
            "id": finding_id,
            "title": title[:70] + ("…" if len(title) > 70 else ""),
            "status": status, "severity": severity, "host": host,
            "file": f.name,
        }
        # Findings are de-duplicated by finding_id. A bad merge can leave two files with the same ID
        # (an old name and a new one); one row per file would silently inflate the total.
        # First file wins; the clash is reported on stderr and does not abort.
        if section == "Finding" and finding_id:
            dup = next((r for r in rows if r["id"] == finding_id), None)
            if dup is not None:
                sys.stderr.write(
                    f"[generate_findings_index] WARN duplicate finding_id {finding_id}: "
                    f"'{f.name}' and '{dup['file']}' both exist -> keeping the first; check for a bad merge\n")
                continue
        rows.append(row)

        if section == "Submission":
            artifacts = fm_lists.get("artifacts", [])
            if artifacts:
                for item in artifacts:
                    ids = known_identifiers.setdefault(item, [])
                    if finding_id not in ids:
                        ids.append(finding_id)
            else:
                submissions_missing_artifacts.append(finding_id or fname)


def render_table(rows, id_col="ID"):
    if not rows:
        return "_(no data)_\n"
    lines = [f"| {id_col} | Title | Status | Severity | Host |",
             "|-----|-------|--------|----------|------|"]
    for r in rows:
        lines.append(f"| `{r['id']}` | {r['title']} | {r['status']} | {r['severity']} | `{r['host']}` |")
    return "\n".join(lines) + "\n"


def render_known_identifiers(known, missing):
    lines = []
    if known:
        lines += ["| Identifier | Report |", "|-----------|--------|"]
        for identifier, ids in sorted(known.items()):
            id_str = ", ".join(f"#{i}" if not i.startswith("#") else i for i in ids)
            lines.append(f"| `{identifier}` | {id_str} |")
    else:
        lines.append("_(no data — add an `artifacts:` field to your Submission frontmatter)_")
    if missing:
        missing_str = ", ".join(f"`#{m}`" if not m.startswith("#") else f"`{m}`" for m in missing[:20])
        if len(missing) > 20:
            missing_str += f" ... and {len(missing) - 20} more"
        lines += ["",
                  f"> ⚠️ **{len(missing)} Submission(s) have no `artifacts:` field** "
                  f"(their identifiers cannot be looked up in the table above): {missing_str}",
                  "> Fix: add `artifacts: [identifier1, identifier2]` to the Submission frontmatter and re-run this script."]
    return "\n".join(lines) + "\n"


total = len(rows_findings) + len(rows_attempts) + len(rows_submissions)
today = date.today().isoformat()
_manual = extract_manual_block(vault_out_file, out_file)
manual_block = f"\n{_manual}\n" if _manual else ""

out = f"""# {target} — Findings Quick Reference

> **Auto-generated {today}** — read this before scanning, to avoid re-discovering known issues.
> Regenerate: `bash automation/generate_findings_index.sh {target}`

**Total: {len(rows_findings)} Findings | {len(rows_attempts)} Attempts | {len(rows_submissions)} Submissions = {total} entries**
{manual_block}
---

## Submissions ({len(rows_submissions)})

{render_table(rows_submissions, id_col='Report')}

## Findings ({len(rows_findings)})

{render_table(rows_findings)}

## Attempts ({len(rows_attempts)})

{render_table(rows_attempts)}

---

## 🔍 Known Identifiers (look here before claiming something is new)

> Auto-extracted from the Submission `artifacts:` field. `automation/dedup_hints.sh` reads this file too.
> An identifier listed here is already confirmed to exist — it is not a new finding.

{render_known_identifiers(known_identifiers, submissions_missing_artifacts)}
---

> Keyword + host search across the vault (a separate tool; it does not read this file):
> `bash automation/vault_precheck.sh {target} "<keyword>" "<host>"`
"""

written = []
for dest in (out_file, vault_out_file):
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(out)
    written.append(dest)

suffix = " [manual block preserved]" if _manual else ""
for dest in written:
    print(f"[ok] Written {dest} ({total} entries, {len(known_identifiers)} identifiers, "
          f"{len(submissions_missing_artifacts)} missing artifacts){suffix}")
PYEOF
