#!/usr/bin/env bash
# Link repo-managed Gemini skill wrappers into the local Gemini CLI skill directory.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC="$ROOT/.gemini/skills"
DEST="${GEMINI_HOME:-$HOME/.gemini}/skills"
MODE="link"

usage() {
  cat <<'USAGE'
Usage: bash automation/install_gemini_skills.sh [--check] [--copy]

Default mode creates symlinks from ~/.gemini/skills/<skill> to this repo's
.gemini/skills/<skill>. Existing non-matching skill directories are not overwritten.

Options:
  --check   Verify install state only.
  --copy    Copy wrappers instead of symlinking; existing destinations still fail.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --check) MODE="check" ;;
    --copy) MODE="copy" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

if [ ! -d "$SRC" ]; then
  echo "Missing repo Gemini skills: $SRC" >&2
  exit 1
fi

mkdir -p "$DEST"
fail=0

for skill_dir in "$SRC"/*; do
  [ -d "$skill_dir" ] || continue
  name="$(basename "$skill_dir")"
  dest="$DEST/$name"

  if [ "$MODE" = "check" ]; then
    if [ -L "$dest" ] && [ "$(readlink "$dest")" = "$skill_dir" ]; then
      echo "[ok] linked $name"
    elif [ -f "$dest/SKILL.md" ]; then
      echo "[ok] installed $name"
    else
      echo "[missing] $name"
      fail=$((fail+1))
    fi
    continue
  fi

  if [ -e "$dest" ] || [ -L "$dest" ]; then
    if [ -L "$dest" ] && [ "$(readlink "$dest")" = "$skill_dir" ]; then
      echo "[ok] already linked $name"
      continue
    fi
    echo "[skip] $dest already exists and is not this repo mirror" >&2
    fail=$((fail+1))
    continue
  fi

  if [ "$MODE" = "copy" ]; then
    cp -R "$skill_dir" "$dest"
    echo "[ok] copied $name"
  else
    ln -s "$skill_dir" "$dest"
    echo "[ok] linked $name"
  fi
done

exit "$fail"
