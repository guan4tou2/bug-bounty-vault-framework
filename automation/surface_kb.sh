#!/usr/bin/env bash
# surface_kb.sh — point-of-need KB retrieval (let the right KB surface itself)
#
# The problem: the KB has 96 Patterns / 27 Playbooks / 23 Checklists / 209 LL, and
# bb_kb_search is a manual "remember to look it up" pull. This script inverts that:
# detect the target's tech fingerprints → automatically surface the relevant KB.
# Turns "remember to look it up" into "it surfaces automatically". Run it after recon
# output / at the start of a session.
#
# Mechanical detection + LLM judgment: it only lists candidate KB — it doesn't decide
# relevance for you and doesn't auto-apply anything.
#
# Usage:
#   bash automation/surface_kb.sh <target>          # read the target's RECON_DB and extract fingerprints
#   bash automation/surface_kb.sh --tech laravel,nacos,graphql   # provide fingerprints directly
#
# bash 3.2 compatible (macOS)
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
eval "$("$SCRIPT_DIR/workspace_layout.sh" --shell)"

KB="$VAULT_ROOT/09 - Knowledge Base"
TARGETS="$VAULT_ROOT/01 - Targets"

# Known tech-fingerprint dictionary (lowercase; extendable). Surface KB only on a hit, to avoid noise.
TECH_TOKENS="laravel wordpress drupal joomla nacos spring actuator graphql electron \
jenkins confluence jira citrix gitlab ignition horizon clockwork whoops struts \
nginx apache tomcat node express django flask rails s3 bucket azure firebase \
oauth saml jwt cors ssrf idor lfi rce ssti xxe redis mongodb elasticsearch \
kibana grafana prometheus harbor exchange proxyshell hikvision nvr rtsp upnp \
soap cgi firmware websocket cswsh swagger openapi keycloak wso2"

TECHS=""
case "${1:-}" in
  --tech)
    TECHS="$(echo "${2:-}" | tr ',' ' ' | tr 'A-Z' 'a-z')"
    ;;
  "" )
    echo "Usage: surface_kb.sh <target>  |  surface_kb.sh --tech a,b,c"; exit 2 ;;
  * )
    target="$1"
    # Find the target's recon source (RECON_DB / Recon note)
    src="$(find "$TARGETS" -ipath "*${target}*" \( -iname 'RECON_DB*.md' -o -iname '*recon*.md' \) 2>/dev/null)"
    if [ -z "$src" ]; then
      echo "⚠️  No RECON_DB found for $target; use --tech to provide fingerprints manually."; exit 1
    fi
    blob="$(cat $src 2>/dev/null | tr 'A-Z' 'a-z')"
    for t in $TECH_TOKENS; do
      echo "$blob" | grep -qF "$t" && TECHS="$TECHS $t"
    done
    ;;
esac

TECHS="$(echo "$TECHS" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ')"
if [ -z "$TECHS" ]; then
  echo "No tech fingerprints from the dictionary detected. Use --tech manually, or bb_kb_search for full-text search."
  exit 0
fi

echo "# Point-of-need KB — detected fingerprints: $TECHS"
echo "# Mechanically surfaced candidates; LLM decides which are actually relevant. Open each with Read."
echo
for t in $TECHS; do
  hits="$(grep -rilF "$t" "$KB" --include='Pattern -*.md' --include='Playbook -*.md' --include='Checklist -*.md' 2>/dev/null | sed 's#.*/##; s#\.md$##' | sort -u)"
  [ -z "$hits" ] && continue
  echo "## [$t]"
  echo "$hits" | sed 's/^/  - /'
  echo
done
echo "→ Full-text / semantic search (incl. LL/Writeups): bb_kb_search '<keyword>'"
