#!/usr/bin/env bash
# check_workspace_boundary.sh — keep working material (and binaries) out of git.
#
# In this layout the workspace lives INSIDE the repo at workspace/ and is kept out of git by .gitignore.
# That is easy to get wrong silently: one `git add -f`, one missing ignore line for a new target, and an
# unpacked firmware image or a vendor binary is in history — where it cannot be taken back without rewriting
# the repository. Adding another .gitignore line per new target is whack-a-mole: the rule is always one target
# behind. The invariant worth checking is structural, not "did I remember an ignore entry":
#
#   1. Only workspace SCAFFOLDING may be tracked under workspace/ (README.md, .gitignore, .gitkeep files).
#   2. No process directory (workshop/, firmware_analysis/, extractions/, reports/, logs/) sits at the repo
#      root — they belong under workspace/.
#   3. No file with a common archive / binary / disk-image EXTENSION is tracked anywhere (zip, tar, gz, apk, ipa,
#      jar, so, dll, bin, ...). Extension-less binaries and formats not in that list are NOT detected: this is a
#      guard against the usual accidents, not a malware scanner.
#      If you deliberately track a tiny fixture, allow it with BOUNDARY_ALLOW_REGEX='^tests/fixtures/'.
#
# Exit code: 0 = boundary intact; 1 = violation(s) listed with a fix.
#
# Usage:  bash automation/check_workspace_boundary.sh
# Env:    BOUNDARY_ROOT=<repo>              check another repository (tests use this)
#         BOUNDARY_ALLOW_REGEX=<ERE>        tracked paths matching this are exempt from rule 3
set -uo pipefail

ROOT="${BOUNDARY_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ALLOW="${BOUNDARY_ALLOW_REGEX:-}"
issues=0

echo "-- workspace boundary --"
echo "   repo: $ROOT"
echo ""

if ! git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "SKIP: $ROOT is not a git repository"; exit 0
fi

# core.quotePath=false: without it git prints non-ASCII paths as "\346\226..." wrapped in quotes, the closing
# quote defeats the `\.zip$` style patterns below, and a non-ASCII-named archive would slip through.
gitls() { git -c core.quotePath=false -C "$ROOT" ls-files "$@" 2>/dev/null; }

# 1 — only scaffolding is tracked under workspace/
tracked_ws=$(gitls workspace \
  | grep -vE '^workspace/(README\.md|\.gitignore)$' \
  | grep -vE '(^|/)\.gitkeep$' || true)
if [ -n "$tracked_ws" ]; then
  echo "FAIL: working material is tracked under workspace/ (only README.md, .gitignore and .gitkeep may be):"
  printf '%s\n' "$tracked_ws" | head -20 | sed 's/^/   /'
  echo "   Fix: git rm --cached <file>, and make sure the path is covered by workspace/.gitignore."
  issues=$((issues+1)); echo ""
fi

# 2 — no process directory at the repo root
stray=""
for d in workshop firmware_analysis extractions reports logs; do
  [ -e "$ROOT/$d" ] || continue
  # -type f: a directory that only holds .gitkeep files (scaffolding) is not working material.
  n=$(find "$ROOT/$d" -mindepth 1 -type f ! -name '.gitkeep' 2>/dev/null | head -1 | wc -l | tr -d ' ')
  [ "$n" = 0 ] && continue
  stray="$stray $d/"
done
if [ -n "$stray" ]; then
  echo "FAIL: process directories at the repo root (they belong under workspace/):$stray"
  echo "   Fix: move their contents under workspace/<name>/ (git-ignored)."
  issues=$((issues+1)); echo ""
fi

# 3 — tracked archives / binaries / disk images
bad=$(gitls \
  | grep -iE '\.(exe|msi|dmg|zip|7z|tar|tar\.gz|tgz|gz|bz2|xz|iso|img|bin|squashfs|apk|apkm|ipa|jar|class|so|dll|dylib)$' || true)
if [ -n "$ALLOW" ] && [ -n "$bad" ]; then
  bad=$(printf '%s\n' "$bad" | grep -vE "$ALLOW" || true)
fi
if [ -n "$bad" ]; then
  echo "FAIL: archive / binary files are tracked:"
  printf '%s\n' "$bad" | head -20 | sed 's/^/   /'
  echo "   Fix: git rm --cached <file>, and keep the source URL and the command that fetches it in the target's notes"
  echo "        (for example its README or RECON_DB) so the file can be re-downloaded instead of versioned."
  echo "   (a deliberate small fixture can be allowed with BOUNDARY_ALLOW_REGEX)"
  issues=$((issues+1)); echo ""
fi

if [ "$issues" -eq 0 ]; then
  echo "OK: workspace boundary intact — no working material or binaries tracked."
  exit 0
fi
echo "-- workspace boundary: $issues violation(s) --"
exit 1
