#!/usr/bin/env bash
# precheck_version_cve.sh — AGENTS.md §0g.11 accelerator
#
# Uses the NVD CVE API 2.0 (public, no API key needed) to search <vendor> <product>,
# printing the matching CVE list + a markdown snippet you can paste into the RECON_DB
# `## 🛡️ Pre-flight Checks` section.
#
# Notes:
# - NVD keyword search does not automatically filter by version. You must manually verify each CVE's affected version range.
# - This script does **not** parse individual vendor advisories (page structures vary too much); advisories still require a manual WebFetch.
# - It is an accelerator for the mandatory §0g.5 NVD check, not a replacement; the mandatory vendor advisory + changelog checks still need to be done.
#
# Usage:
#   automation/precheck_version_cve.sh <vendor> <product> [version]
#
# Examples:
#   automation/precheck_version_cve.sh qnap qts 5.0.1.2425
#   automation/precheck_version_cve.sh netgear wax620 1.0.5
#   automation/precheck_version_cve.sh dlink dcs-4614ek
#
# Exit codes:
#   0  Success (including 0 hits)
#   1  Usage error
#   2  Network / API error

set -euo pipefail

usage() {
  sed -n '2,/^set -euo pipefail/p' "$0" | sed 's/^# \?//; /^set -euo/d'
  exit 1
}

[[ $# -lt 2 ]] && usage

command -v jq >/dev/null 2>&1 || { echo "[err] jq not installed (brew install jq)"; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "[err] curl not installed"; exit 2; }

VENDOR="$1"
PRODUCT="$2"
VERSION="${3:-N/A}"
DATE="$(date +%Y-%m-%d)"
KEY="${VENDOR} ${PRODUCT}"
KEY_ENC=$(printf '%s' "$KEY" | jq -sRr @uri)

NVD_API="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${KEY_ENC}&resultsPerPage=20"
NVD_WEB="https://nvd.nist.gov/vuln/search/results?form_type=Basic&search_type=all&query=${KEY_ENC}"
GHSA_WEB="https://github.com/advisories?query=${KEY_ENC}"
BB_PLATFORM_HACKTIVITY="https://<bb-platform>/hacktivity?q=$(printf '%s' "$PRODUCT" | jq -sRr @uri)"

echo "## §0g Pre-flight Query — ${VENDOR}/${PRODUCT} (version: ${VERSION})"
echo ""
echo "Query date: ${DATE}"
echo "NVD API:    ${NVD_API}"
echo "NVD web:    ${NVD_WEB}"
echo "GHSA web:   ${GHSA_WEB}"
echo "BB platform hacktivity: ${BB_PLATFORM_HACKTIVITY}"
echo ""
echo "[info] Vendor advisory + changelog still needs manual WebFetch (see AGENTS.md §0g.5)."
echo ""

JSON=$(curl -fsSL -A "BB-precheck/1.0 (+§0g)" --max-time 15 "${NVD_API}" 2>&1) || {
  echo "[err] NVD API request failed:"
  echo "${JSON}" | head -3
  echo ""
  echo "Fallback: open ${NVD_WEB} in browser."
  exit 2
}

TOTAL=$(echo "$JSON" | jq -r '.totalResults // 0')
echo "## NVD result: ${TOTAL} hits"
echo ""

if [[ "${TOTAL}" -gt 0 ]]; then
  # ── CISA KEV check (2026-06-04 added) ────────────────────────────────
  # Known Exploited Vulnerabilities catalog — flag any CVE in the result
  # set as 🔥 actively exploited. Cached for 24h to avoid hammering CISA.
  KEV_CACHE="/tmp/cisa_kev_cache.json"
  KEV_AGE=999999
  if [[ -f "$KEV_CACHE" ]]; then
    KEV_AGE=$(( $(date +%s) - $(stat -f %m "$KEV_CACHE" 2>/dev/null || stat -c %Y "$KEV_CACHE" 2>/dev/null || echo 0) ))
  fi
  if [[ "$KEV_AGE" -gt 86400 ]]; then
    curl -fsSL --max-time 10 \
      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
      > "$KEV_CACHE.tmp" 2>/dev/null && mv "$KEV_CACHE.tmp" "$KEV_CACHE" || true
  fi
  KEV_CVES=""
  if [[ -s "$KEV_CACHE" ]]; then
    KEV_CVES=$(jq -r '.vulnerabilities[]?.cveID' "$KEV_CACHE" 2>/dev/null || echo "")
  fi

  echo "| CVE | KEV | Published | CVSS | Summary (first 110 chars) |"
  echo "|---|---|---|---|---|"
  echo "$JSON" | jq -r --arg kev "$KEV_CVES" '
    .vulnerabilities[]? |
    .cve as $c |
    ($c.id) as $cveid |
    [
      $cveid,
      (if ($kev | contains($cveid + "\n")) or ($kev | endswith($cveid)) then "🔥" else "" end),
      (($c.published // "")[:10]),
      (($c.metrics.cvssMetricV31[0].cvssData.baseScore
        // $c.metrics.cvssMetricV30[0].cvssData.baseScore
        // $c.metrics.cvssMetricV2[0].cvssData.baseScore
        // "n/a") | tostring),
      (($c.descriptions[]? | select(.lang=="en") | .value)[:110]
        | gsub("\\|"; "\\\\|") | gsub("\n"; " ") | gsub("\r"; ""))
    ] | "| " + join(" | ") + " |"
  '
  # Count KEV hits from the printed table itself (avoids second jq pass).
  KEV_HITS=$(echo "$JSON" | jq -r --arg kev "$KEV_CVES" '
    .vulnerabilities[]? | .cve.id as $id |
    if ($kev | contains($id + "\n")) or ($kev | endswith($id)) then "1" else empty end
  ' | wc -l | tr -d ' ')
  if [[ "${TOTAL}" -gt 20 ]]; then
    echo ""
    echo "_Only 20 results shown. Open NVD web view for full list._"
  fi
  if [[ "$KEV_HITS" -gt 0 ]]; then
    echo ""
    echo "🔥 **${KEV_HITS} CVE(s) in CISA KEV** (Known Exploited Vulnerabilities) — high-priority chain candidate; if the target version is affected, it is **almost certainly exploitable** (in-the-wild exploitation confirmed)."
  fi
  echo ""
  echo "### Other CVE sources (manual follow-up)"
  echo "- Exploit-DB search: https://www.exploit-db.com/search?q=$(printf '%s' "$KEY" | jq -sRr @uri)"
  echo "- searchsploit local:  \`searchsploit ${VENDOR} ${PRODUCT}\` (if installed)"
  echo "- packetstormsecurity:  https://packetstormsecurity.com/search/?q=$(printf '%s' "$KEY" | jq -sRr @uri)"
else
  echo "_No NVD hits via keyword search. Still verify via vendor advisory + GHSA + H1 manually._"
fi

cat <<EOF

---

## Paste-ready RECON_DB snippet (per the §0g.9 template; commit only after filling in the manual verification results)

\`\`\`
### Target Pre-flight - ${DATE} - ${VENDOR}/${PRODUCT}/${VERSION}
- Category: <firmware | native | mobile | library | OS | SaaS>
- Version on hand: ${VERSION} (<release date YYYY-MM-DD>)
- Latest stable: <fill> (<release date>) — source: <vendor release URL>
- Supported branch: <yes / no / EOL — source: <vendor lifecycle URL>>
- Version gap: <0 (latest) | minor-N | major-N | EOL>
- CVE search: ${NVD_WEB} → ${TOTAL} hits (verify affected versions manually)
- Vendor advisory: <URL> → <0 / N hits>
- GHSA / 3rd-party: ${GHSA_WEB} → <0 / N hits>
- <Platform> disclosed: ${BB_PLATFORM_HACKTIVITY} → <skipped or N hits>
- Decision: <proceed | proceed - exception (<reason>) | abort - too old | abort - known CVE <CVE-ID> | abort - EOL>
\`\`\`

> Mandatory: after filling in Decision, if it is abort, run the five-step stop-loss SOP in AGENTS.md §0g.7.
EOF
