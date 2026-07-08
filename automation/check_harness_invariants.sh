#!/usr/bin/env bash
# Single harness-invariant gate for the public framework (harness-engineering
# pillar 3: mechanical enforcement). One command, each failure carrying its fix.
# Rules: golden-rules.md. Run before structural changes / at session end.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"
fails=0
pass() { echo "✅ $1"; }
fail() { echo "❌ $1"; echo "   fix: $2"; fails=$((fails+1)); }

echo "── harness invariants (see golden-rules.md) ──"

# S1/S2/A1/S3/R1/R2 — the authoritative public-skeleton test suite
if python3 -m pytest tests/test_public_skeleton.py -q >/tmp/fw_hinv_test.txt 2>&1; then
  pass "S1/S2/A1/S3/R1/R2 public-skeleton suite (skills · agents · mirrors · nuclei shape-only · platform-neutral)"
else
  fail "public-skeleton suite failed" "python3 -m pytest tests/test_public_skeleton.py -q   (detail: /tmp/fw_hinv_test.txt)"
fi

# S3 — mirror parity (explicit, fast)
if python3 "$SCRIPT_DIR/sync_codex_skills.py" --check >/tmp/fw_hinv_sync.txt 2>&1; then
  pass "S3 codex/gemini mirror parity"
else
  fail "S3 mirror drift" "python3 automation/sync_codex_skills.py"
fi

# vault skeleton health
if python3 "$SCRIPT_DIR/check_vault.py" >/tmp/fw_hinv_vault.txt 2>&1; then
  pass "vault skeleton health (check_vault.py)"
else
  fail "vault health check failed" "python3 automation/check_vault.py   (detail: /tmp/fw_hinv_vault.txt)"
fi

# S4 — skill count agreement across the three sources of truth
sk_dirs=$(ls -d .claude/skills/bb-*/ 2>/dev/null | wc -l | tr -d ' ')
sk_readme=$(grep -cE '^\| `bb-' .claude/skills/README.md 2>/dev/null | tr -d ' ')
sk_claude=$(grep -cE '^\| \*\*bb-' CLAUDE.md 2>/dev/null | tr -d ' ')
if [ "$sk_dirs" = "$sk_readme" ] && [ "$sk_dirs" = "$sk_claude" ]; then
  pass "S4 skill counts agree (dirs=$sk_dirs · README=$sk_readme · CLAUDE=$sk_claude)"
else
  fail "S4 skill count drift: dirs=$sk_dirs README=$sk_readme CLAUDE=$sk_claude" \
       "align .claude/skills/README.md + CLAUDE.md skill table with .claude/skills/bb-*/"
fi

# A gate counts as "wired" if referenced directly in settings.json, OR routed
# through the low-frequency wrapper (which delegates to the expensive gates only
# on commit/session-close/verify commands).
gate_wired() {
  local gate="$1"
  grep -q "$gate" .claude/settings.json 2>/dev/null && return 0
  grep -q low_frequency_gates.sh .claude/settings.json 2>/dev/null \
    && grep -q "$gate" automation/low_frequency_gates.sh 2>/dev/null
}

# F1 — surface-map scan-time gate installed + wired
if [ -x automation/surface_map_gate.sh ] && gate_wired surface_map_gate.sh; then
  pass "F1 surface-map scan-time gate wired (PreToolUse Bash, direct or via low_frequency_gates.sh)"
else
  fail "F1 surface-map gate missing/unwired" "ensure automation/surface_map_gate.sh exists + referenced in .claude/settings.json PreToolUse (directly or via low_frequency_gates.sh)"
fi

# F2 — lifecycle hooks present
if python3 - <<'PY' 2>/dev/null
import json,sys
h=json.load(open(".claude/settings.json")).get("hooks",{})
sys.exit(0 if ("Stop" in h and "SessionStart" in h) else 1)
PY
then
  pass "F2 Stop + SessionStart hooks present"
else
  fail "F2 lifecycle hooks missing" "add Stop + SessionStart hooks to .claude/settings.json"
fi

# F4 — static-only gate installed + wired
if [ -x automation/static_only_gate.sh ] && gate_wired static_only_gate.sh; then
  pass "F4 static-only gate wired (PreToolUse Bash, direct or via low_frequency_gates.sh)"
else
  fail "F4 static-only gate missing/unwired" "ensure automation/static_only_gate.sh exists + referenced in .claude/settings.json PreToolUse Bash (directly or via low_frequency_gates.sh)"
fi

echo "──"
if [ "$fails" -eq 0 ]; then
  echo "✅ all harness invariants hold"
  exit 0
fi
echo "❌ $fails invariant(s) violated — see golden-rules.md"
exit 1
