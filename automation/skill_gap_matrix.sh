#!/usr/bin/env bash
# skill_gap_matrix.sh — produce skill × surface gap matrix for a target.
#
# Implements Step 3 of `Playbook - Trigger Chain Dry-Run`. Reads everything
# we know about the target + lists every available skill, then emits a
# markdown matrix showing which skills are applicable, which need
# fingerprinting, and which to skip — based on simple keyword heuristics
# against the target's known tech stack.
#
# Usage:
#   bash automation/skill_gap_matrix.sh <target> [> matrix.md]
#
# Output: markdown to stdout.
#
# Heuristics (matched against Target page + RECON_DB + memory):
#   "laravel|php|phpsessid"  → PHP-specific skills relevant (type-juggling, ...)
#   "spring|java|jsessionid|actuator" → Java-specific skills
#   "graphql"                → graphql-and-hidden-parameters relevant
#   "react|vue|spa|next.js"  → SPA-relevant warnings (LL-120)
#   "wordpress|wp-"          → WP-specific
#   "android|apk"            → android-pentesting-tricks, mobile-ssl-pinning
#   "electron"               → desktop hunt patterns
#   "firmware|cgi|router"    → firmware patterns
#   "competition|hackthe"    → Disclosed Pre-Read mandatory
#
# Limitations: cannot infer everything; output is a draft for human triage,
# not a final verdict. Caller should refine per their judgment.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
eval "$("$SCRIPT_DIR/workspace_layout.sh" --shell)" 2>/dev/null || {
  echo "⛔ workspace_layout.sh failed" >&2
  exit 2
}

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
  echo "Usage: bash automation/skill_gap_matrix.sh <target>" >&2
  exit 2
fi

TARGET_PAGE="$VAULT_ROOT/01 - Targets/$TARGET/Target - $TARGET.md"
RECON_DB="$WORKSHOP_ROOT/$TARGET/RECON_DB.md"
FQR="$WORKSHOP_ROOT/$TARGET/FINDINGS_QUICK_REF.md"
MEMORY_FILE=""
for f in $MEMORY_DIR/project_*"$TARGET"*.md; do
  [ -f "$f" ] && MEMORY_FILE="$f" && break
done

# Aggregate searchable text for stack detection.
HAYSTACK=""
for f in "$TARGET_PAGE" "$RECON_DB" "$FQR" "$MEMORY_FILE"; do
  [ -f "$f" ] && HAYSTACK+="$(cat "$f") "
done

has() { printf '%s' "$HAYSTACK" | grep -qiE "$1"; }

# Stack signals
SIG_PHP=$(has 'laravel|\bphp\b|phpsessid' && echo 1 || echo 0)
SIG_JAVA=$(has 'spring|jsessionid|tomcat|actuator|servlet' && echo 1 || echo 0)
SIG_NODE=$(has 'node\.?js|express|next\.?js' && echo 1 || echo 0)
SIG_DOTNET=$(has 'asp\.net|iis|aspx|customerrors' && echo 1 || echo 0)
SIG_GRAPHQL=$(has 'graphql|__typename|introspection' && echo 1 || echo 0)
SIG_SPA=$(has 'spa|react|vue|catch.all' && echo 1 || echo 0)
SIG_WP=$(has 'wordpress|wp-|wp_' && echo 1 || echo 0)
SIG_ANDROID=$(has 'android|\.apk|frida|jadx' && echo 1 || echo 0)
SIG_ELECTRON=$(has 'electron|asar|chromium' && echo 1 || echo 0)
SIG_FIRMWARE=$(has 'firmware|router|cgi|busybox|binwalk' && echo 1 || echo 0)
SIG_COMPETITION=$(has 'example competition|example-competition|red.?blue|red-blue|competition' && echo 1 || echo 0)
SIG_AUTH=$(has 'oauth|jwt|saml|sso|login|password.?reset|otp' && echo 1 || echo 0)
SIG_UPLOAD=$(has 'upload|multipart|attach' && echo 1 || echo 0)
SIG_API=$(has '\bapi\b|swagger|openapi|/v1/|/v2/' && echo 1 || echo 0)

# Verdict for one skill: applicable / needs-fingerprint / skip
verdict() {
  local name="$1" should="$2" reason="$3"
  case "$should" in
    yes) printf "| %s | ✅ | %s |\n" "$name" "$reason" ;;
    maybe) printf "| %s | 🟡 | %s |\n" "$name" "$reason" ;;
    no) printf "| %s | ❌ | %s |\n" "$name" "$reason" ;;
  esac
}

cat <<HEADER
---
type: dry-run-matrix
target: $TARGET
generated_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)
---

# Skill × Surface Gap Matrix — $TARGET

> Auto-generated draft per [[Playbook - Trigger Chain Dry-Run]] Step 3.
> Heuristic-based; **human must triage** the 🟡 and verify ✅ before action.

## Detected stack signals
- PHP/Laravel: $([ "$SIG_PHP" = 1 ] && echo "✅" || echo "—")
- Java/Spring: $([ "$SIG_JAVA" = 1 ] && echo "✅" || echo "—")
- Node.js: $([ "$SIG_NODE" = 1 ] && echo "✅" || echo "—")
- ASP.NET: $([ "$SIG_DOTNET" = 1 ] && echo "✅" || echo "—")
- GraphQL: $([ "$SIG_GRAPHQL" = 1 ] && echo "✅" || echo "—")
- SPA: $([ "$SIG_SPA" = 1 ] && echo "✅" || echo "—")
- WordPress: $([ "$SIG_WP" = 1 ] && echo "✅" || echo "—")
- Android: $([ "$SIG_ANDROID" = 1 ] && echo "✅" || echo "—")
- Electron: $([ "$SIG_ELECTRON" = 1 ] && echo "✅" || echo "—")
- Firmware/IoT: $([ "$SIG_FIRMWARE" = 1 ] && echo "✅" || echo "—")
- Competition/prior-disclosure: $([ "$SIG_COMPETITION" = 1 ] && echo "⚠️ Pre-Read Gate mandatory" || echo "—")
- Auth surfaces: $([ "$SIG_AUTH" = 1 ] && echo "✅" || echo "—")
- Upload surfaces: $([ "$SIG_UPLOAD" = 1 ] && echo "✅" || echo "—")
- API surfaces: $([ "$SIG_API" = 1 ] && echo "✅" || echo "—")

## Matrix — yaklang external skills (22)

| Skill | Verdict | Reason |
|---|---|---|
HEADER

# yaklang skills with heuristics
[ "$SIG_PHP" = 1 ] && verdict "type-juggling" yes "Laravel/PHP detected — OTP / hash 弱比較 / magic hash" || verdict "type-juggling" no "no PHP detected"
[ "$SIG_AUTH" = 1 ] && verdict "http-host-header-attacks" yes "auth surface present → password reset poisoning candidate" || verdict "http-host-header-attacks" maybe "no auth surface noted; check anyway"
[ "$SIG_AUTH" = 1 ] && verdict "authbypass-authentication-flaws" yes "auth surfaces detected — pw reset / MFA / token predictability" || verdict "authbypass-authentication-flaws" maybe "verify auth surfaces"
[ "$SIG_AUTH" = 1 ] && verdict "jwt-oauth-token-attacks" maybe "auth detected — check if JWT/OAuth specifically" || verdict "jwt-oauth-token-attacks" no "no auth detected"
[ "$SIG_GRAPHQL" = 1 ] && verdict "graphql-and-hidden-parameters" yes "GraphQL detected — introspection + batching" || verdict "graphql-and-hidden-parameters" maybe "probe /graphql first"
[ "$SIG_NODE" = 1 ] && verdict "prototype-pollution" yes "Node.js detected" || verdict "prototype-pollution" no "no Node detected"
[ "$SIG_NODE" = 1 ] && verdict "prototype-pollution-advanced" yes "Node.js — PP→RCE gadgets relevant" || verdict "prototype-pollution-advanced" no "no Node detected"
verdict "business-logic-vulnerabilities" yes "always-applicable to any form/workflow"
[ "$SIG_API" = 1 ] && verdict "http-parameter-pollution" yes "API surface — CDN/WAF/app 解析差異" || verdict "http-parameter-pollution" maybe "any param-taking endpoint"
verdict "crlf-injection" maybe "test any redirect/Location/Set-Cookie endpoint"
[ "$SIG_PHP" = 1 ] && verdict "nosql-injection" maybe "PHP stack — MongoDB possible but uncommon" || verdict "nosql-injection" maybe "fingerprint backend DB first"
[ "$SIG_UPLOAD" = 1 ] && verdict "upload-insecure-files" yes "upload surface present — IIS/Nginx/Apache parser CVEs" || verdict "upload-insecure-files" no "no upload surface noted"
verdict "csp-bypass-advanced" maybe "useful if XSS chain found and CSP encountered"
verdict "401-403-bypass-techniques" maybe "see LL-148: only run if baseline 401/403 (not 404) + non-SPA + non-Apache+PHP"
verdict "dependency-confusion" maybe "low yield unless target uses internal npm/pypi packages"
verdict "waf-bypass-techniques" maybe "useful when hitting a WAF — Ghost Bits + encoding chain"
[ "$SIG_ANDROID" = 1 ] && verdict "android-pentesting-tricks" yes "Android target detected — Frida + WebView + intent" || verdict "android-pentesting-tricks" no "no Android target"
[ "$SIG_ANDROID" = 1 ] && verdict "mobile-ssl-pinning-bypass" yes "Android target — pinning bypass for traffic interception" || verdict "mobile-ssl-pinning-bypass" no "no mobile target"
verdict "xss-cross-site-scripting" yes "broad XSS framework — context matrix / Blind XSS / CSP bypass"
verdict "ssrf-server-side-request-forgery" yes "broad SSRF framework — cloud metadata / IP bypass / gopher"
verdict "idor-broken-object-authorization" yes "broad IDOR/BOLA/BFLA framework — A/B replay + ORM filter injection"
verdict "recon-and-methodology" yes "Zseano method + GitHub recon + Java middleware fingerprint"

cat <<MID

## Matrix — canonical bb-* skills (16)

| Skill | Verdict | Reason |
|---|---|---|
MID

[ "$SIG_COMPETITION" = 1 ] && verdict "Disclosed Pre-Read Gate" yes "**MANDATORY** — competition target" || verdict "Disclosed Pre-Read Gate" yes "always required;低成本"
verdict "bb-surface-mapping" yes "first gate — required before any pattern/hunter"
verdict "bb-scope-safety-check" yes "before any active scan"
verdict "bb-web-vuln-scan" yes "main OWASP coverage skill"
verdict "bb-exploit-chain" yes "after any finding — 6-Q gate before moving system"
verdict "bb-dedup-finding" yes "before opening new Finding"
verdict "bb-attack-chain-review" yes "for any info-leak / auth bug candidate"
verdict "bb-evidence-readiness" yes "before Finding finalize"
verdict "bb-submission-readiness" yes "before FORM creation"
[ "$SIG_FIRMWARE" = 1 ] || [ "$SIG_ANDROID" = 1 ] || [ "$SIG_ELECTRON" = 1 ] && verdict "bb-version-cve-precheck" yes "binary/firmware/native — CVE pre-check mandatory" || verdict "bb-version-cve-precheck" maybe "if any software version detected"
verdict "bb-cve-citation" maybe "when report references CVE"
verdict "bb-platform-form" maybe "when submitting via platform-form ZeroDay"
verdict "bb-triage-response" maybe "after platform reply"
verdict "bb-incident-response" maybe "if scan causes service impact"
verdict "bb-knowledge-capture" yes "session-end — abstract any new learning to KB"
verdict "bb-attempt-recorder" yes "any negative result worth recording"

cat <<FOOTER

## Notes

- Verdicts are **draft heuristics**. Refine 🟡 by sampling 1-2 endpoints.
- ✅ + ❌ rows: act on / skip directly.
- 🟡 rows: needs fingerprint or scope decision.
- If many ❌ — recon may be thin. Run more tools (gau / katana / nuclei) and re-generate.

## Sources read
- Target page: $([ -f "$TARGET_PAGE" ] && echo "✅" || echo "❌ missing — run init_target.sh")
- RECON_DB: $([ -f "$RECON_DB" ] && echo "✅" || echo "❌ missing")
- FINDINGS_QUICK_REF: $([ -f "$FQR" ] && echo "✅" || echo "❌ missing")
- memory file: $([ -n "$MEMORY_FILE" ] && echo "✅ $MEMORY_FILE" || echo "—")

## Next

1. Save this matrix to \`\$WORKSHOP_ROOT/$TARGET/dry_run_matrix.md\`(or memory for competition)
2. Follow [[Playbook - Trigger Chain Dry-Run]] Step 4: pick top 5 by hit-rate × severity
3. Action item 1 → run → record results → update matrix if new info

> Auto-generated via \`bash automation/skill_gap_matrix.sh $TARGET\` — re-run anytime to refresh.
FOOTER
