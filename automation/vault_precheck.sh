#!/usr/bin/env bash
# Minimal public-safe dedup helper.
set -euo pipefail

target="${1:-}"
keyword="${2:-}"
host="${3:-}"

if [[ -z "$target" || -z "$keyword" ]]; then
  cat >&2 <<'USAGE'
Usage: bash automation/vault_precheck.sh <target> <keyword> [host_or_endpoint]
USAGE
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target_dir="$ROOT/01 - Targets/$target"
workspace_dir="$ROOT/workspace/workshop/$target"

echo "# Vault Precheck — $target"
echo ""
echo "- keyword: $keyword"
[[ -n "$host" ]] && echo "- host: $host"
echo ""

if [[ ! -d "$target_dir" ]]; then
  echo "[warn] No Vault target directory found: 01 - Targets/$target"
  exit 0
fi

echo "## Matches"
matches=0
while IFS= read -r file; do
  [[ -f "$file" ]] || continue
  if grep -qi -- "$keyword" "$file"; then
    rel="${file#$ROOT/}"
    echo "- $rel"
    matches=$((matches + 1))
  fi
done < <(find "$target_dir" "$workspace_dir" -type f \( -name '*.md' -o -name '*.txt' -o -name '*.json' \) 2>/dev/null)

if [[ "$matches" -eq 0 ]]; then
  echo "- No obvious matches."
fi
