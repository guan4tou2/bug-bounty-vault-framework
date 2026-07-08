#!/usr/bin/env bash
# preflight_sync.sh — one-shot pre-commit gate bundle for the Vault OR the public
# framework repo. Bundles the "regen mirrors → forbidden-string scan → leak-test →
# harness invariants" dance that otherwise gets hand-run every time skills/agents/
# governance change. Auto-detects which repo it is in. Run from the repo root.
#
#   bash automation/preflight_sync.sh
#
# Exit 0 = all gates green (safe to commit). Non-zero = a gate failed (see output).
set -uo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; YEL='\033[1;33m'; CY='\033[0;36m'; NC='\033[0m'
ok(){ echo -e "${GREEN}  ✓${NC} $*"; }
bad(){ echo -e "${RED}  ✗${NC} $*"; }
warn(){ echo -e "${YEL}  ⚠${NC} $*"; }
hdr(){ echo -e "\n${CY}▶ $*${NC}"; }

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT" || exit 2
fails=0

# ── detect repo flavour ──────────────────────────────────────────────
# framework (public) ships the leak-test + a gemini mirror; the vault does not.
IS_FRAMEWORK=0
[ -f tests/test_public_skeleton.py ] && IS_FRAMEWORK=1
echo -e "${CY}preflight_sync${NC} — repo: $([ "$IS_FRAMEWORK" = 1 ] && echo 'framework (public)' || echo 'vault (private)') @ $ROOT"

# ── 1. regen mirrors (skill edits drift .codex / .gemini) ────────────
hdr "1. mirror regen"
if [ -f automation/sync_codex_skills.py ]; then
  if python3 automation/sync_codex_skills.py >/dev/null 2>&1; then ok "codex mirror synced"; else bad "sync_codex_skills.py failed"; fails=$((fails+1)); fi
else warn "no sync_codex_skills.py (skipped)"; fi
if [ -f automation/install_gemini_skills.sh ]; then
  if bash automation/install_gemini_skills.sh >/dev/null 2>&1; then ok "gemini mirror synced"; else warn "install_gemini_skills.sh non-zero (check manually)"; fi
fi

# NOTE: the public forbidden-string / leak check is the leak-test itself
# (tests/test_public_skeleton.py, step 2 below) — the authoritative gate. We do
# NOT hardcode the forbidden-string list here: a script that lists those literals
# would itself trip the leak-test when it lives in the public repo.

# ── 2. leak-test / skeleton test ─────────────────────────────────────
hdr "2. skeleton / skill test (public repo: this IS the forbidden-string gate)"
if [ "$IS_FRAMEWORK" = 1 ] && [ -f tests/test_public_skeleton.py ]; then
  if python3 -m pytest tests/test_public_skeleton.py -q >/tmp/preflight_leak.txt 2>&1; then ok "leak-test green ($(grep -oE '[0-9]+ passed' /tmp/preflight_leak.txt | head -1))"; else bad "leak-test FAILED"; tail -8 /tmp/preflight_leak.txt | sed 's/^/      /'; fails=$((fails+1)); fi
elif [ -f tests/test_workspace_skills.py ]; then
  if python3 -m pytest tests/test_workspace_skills.py -q >/tmp/preflight_skill.txt 2>&1; then ok "workspace-skills test green"; else bad "workspace-skills test FAILED"; tail -8 /tmp/preflight_skill.txt | sed 's/^/      /'; fails=$((fails+1)); fi
else warn "no skeleton/skill test found (skipped)"; fi

# ── 3. harness invariants ────────────────────────────────────────────
hdr "3. harness invariants"
if [ -f automation/check_harness_invariants.sh ]; then
  if bash automation/check_harness_invariants.sh >/tmp/preflight_inv.txt 2>&1; then ok "all invariants hold"; else bad "invariant(s) violated"; grep -E '❌|✗' /tmp/preflight_inv.txt | head -8 | sed 's/^/      /'; fails=$((fails+1)); fi
else warn "no check_harness_invariants.sh (skipped)"; fi

# ── verdict ──────────────────────────────────────────────────────────
echo ""
if [ "$fails" -eq 0 ]; then echo -e "${GREEN}✅ preflight green — safe to commit${NC}"; exit 0
else echo -e "${RED}❌ preflight: $fails gate(s) failed — fix before commit${NC}"; exit 1; fi
