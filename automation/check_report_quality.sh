#!/usr/bin/env bash
# Report-quality gate (TEMPLATE/REPORT loop) — mechanical pre-submission check on a
# FORM / Submission file. Turns the "三題檢驗 / 反誇大 / 通報前清單" conventions into a
# real gate. Hard-fails on the "never" rules (exaggeration words, internal IDs);
# warns on completeness (impact / PoC / severity) since field layout varies.
#
# Usage: bash automation/check_report_quality.sh <path-to-FORM-or-Submission.md>
set -uo pipefail
f="${1:-}"
if [ -z "$f" ] || [ ! -f "$f" ]; then
  echo "usage: $0 <path-to-FORM-or-Submission.md>"; exit 2
fi
fails=0; warns=0
ok()   { echo "✅ $1"; }
bad()  { echo "❌ $1"; fails=$((fails+1)); }
warn() { echo "⚠️  $1"; warns=$((warns+1)); }

body=$(cat "$f")

echo "── report quality: $(basename "$f") ──"

# HARD 1 — anti-exaggeration: no unproven hedging presented as impact
exag=$(echo "$body" | grep -niE "could potentially|potentially could|理論上(可|能)|推測(可|能)|應該可以|可能可以|maybe exploitable|might allow" | head -5)
if [ -n "$exag" ]; then
  bad "exaggeration / unproven hedging — prove it or drop it (反誇大):"
  echo "$exag" | sed 's/^/     /'
else
  ok "no exaggeration hedging"
fi

# HARD 2 — no internal IDs in report body (exclude CVE/CWE/CVSS)
ids=$(echo "$body" | grep -noE "[A-Z]{2,5}-[0-9]{2,4}" | grep -viE "CVE-|CWE-|CVSS|SHA-|RFC-|ISO-|AES-|RSA-|TLS-|SSL-|MD5-|UTF-|HMAC-" | head -5)
if [ -n "$ids" ]; then
  bad "internal IDs in report body — strip them (報告禁用內部編號):"
  echo "$ids" | sed 's/^/     /'
else
  ok "no internal IDs in body"
fi

# WARN — completeness signals (layout varies; advisory)
echo "$body" | grep -qiE "impact|影響|衝擊" || warn "no Impact section/keyword found — state concrete impact, not just 'exposed'"
echo "$body" | grep -qiE "poc|proof of concept|重現|reproduc|步驟|steps to" || warn "no PoC / reproduction steps found"
echo "$body" | grep -qiE "severity|嚴重|cvss|critical|high|medium|low" || warn "no severity/CVSS found"

echo "──"
if [ "$fails" -gt 0 ]; then
  echo "❌ $fails hard issue(s), $warns warning(s) — fix the ❌ before submitting."
  exit 1
fi
echo "✅ no hard issues ($warns warning(s) to review). Still run the 7-question gate by hand."
exit 0
