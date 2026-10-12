#!/usr/bin/env bash
# vault_backup_config.sh — back up USER-LEVEL Claude Code config that lives outside this repo.
#
# Usage:  bash automation/vault_backup_config.sh
# Run it after you change anything under ~/.claude, and at environment-rebuild checkpoints.
#
# Why: everything inside the repo is already under git. The user-level config
# (~/.claude/CLAUDE.md, custom slash commands, settings) is not, so losing the machine loses it.
# This script copies only those files into "10 - Meta/Environment/user-claude/" so they can be tracked
# in YOUR PRIVATE vault.
#
# Backed up (from ~/.claude):
#   CLAUDE.md, docs/*.md, commands/*.md, statusline-command.sh, hooks/*.sh,
#   settings.json  -> settings.sanitized.json   (see "settings mode" in the scanner below)
#
# Deliberately NOT backed up:
#   - these keys of settings.json: hooks (often generated and rewritten by other tools; versioning them only
#     produces noise), sandbox (machine-specific paths), env, apiKeyHelper and mcpServers (the places
#     credentials most commonly live)
#   - ~/.claude.json (OAuth / account state), projects/*/memory (meant to be disposable),
#     skills/ and plugins/ (reinstallable), transcripts / history / caches
#
# SAFETY — every file is scanned BEFORE it is copied:
#   * a source file that contains a secret-shaped string is NOT copied and the script exits 1. Detected shapes:
#     private-key blocks, JWTs, provider tokens (sk-, ghp_/gho_/ghu_/ghs_/ghr_, github_pat_, glpat-, npm_, hf_,
#     sk_live_/rk_live_, AKIA…, xox…, AIza…), Slack/Discord webhook URLs, Telegram bot tokens, `Bearer <token>`
#     headers and aws_secret_access_key assignments. The message names the pattern that matched.
#   * if the scan itself fails (unreadable file, interpreter error) the file is treated as UNSAFE and not copied
#   * settings.json is scanned more strictly: it additionally refuses long opaque values and IPv4 addresses
#     (permission rules can name hosts), apart from loopback addresses and version-like strings
#   The scan is a safety net, not a guarantee: it cannot recognize a short, prefix-less secret. Read what you
#   are about to commit.
#
# PUBLIC-FORK WARNING: the destination is git-ignored by default (see .gitignore) because this is YOUR personal
# configuration. Remove that ignore line only if your vault is a PRIVATE repository and you want it versioned.
#
# Optional: EXCLUDE_COMMANDS="foo-*" skips commands that come from a plugin you do not want versioned.
# BACKUP_OUT_DIR overrides the destination (the tests use it so they never touch your real config).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${BACKUP_OUT_DIR:-$ROOT_DIR/10 - Meta/Environment/user-claude}"
CLAUDE_DIR="$HOME/.claude"
DATE=$(date '+%Y-%m-%d %H:%M')
COPIED=0
FAILED=0
EXCLUDE_COMMANDS="${EXCLUDE_COMMANDS:-}"

G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; N='\033[0m'
ok()   { echo -e "${G}[ok]${N}  $*"; COPIED=$((COPIED+1)); }
warn() { echo -e "${Y}[skip]${N} $*"; }
err()  { echo -e "${R}[err]${N}  $*"; FAILED=$((FAILED+1)); }

# The scanner lives in ONE place so the file scan and the settings scan cannot drift apart.
#   python3 -c "$SCAN_PY" scan <file>                       exit 0 clean | 10 secret-shaped string found | other = scan failed
#   python3 -c "$SCAN_PY" settings <src> <dst> <home>       writes the sanitized settings, exit 0 | 3 refused
read -r -d '' SCAN_PY <<'PYEOF' || true
import json, re, sys

# Left boundary (?<![A-Za-z0-9]) on the prefixed tokens: without it ordinary hyphenated words such as
# "risk-based-..." or "desk-only-..." contain "sk-" and are mistaken for a key.
HIGH_CONFIDENCE = {
    "private key block": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "JWT": r"eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}",
    "provider token": (r"(?<![A-Za-z0-9])(sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
                       r"|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{30,}|hf_[A-Za-z0-9]{30,}|[rs]k_live_[A-Za-z0-9]{20,}"
                       r"|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,})"),
    "webhook URL": r"(hooks\.slack\.com/services/[A-Za-z0-9/]{20,}|discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{20,})",
    "Telegram bot token": r"\b\d{8,10}:AA[A-Za-z0-9_-]{30,}",
    "Bearer credential": r"Bearer\s+(?=[A-Za-z0-9._~+/-]*\d)[A-Za-z0-9._~+/-]{24,}",
    "AWS secret key assignment": r"aws_secret_access_key\s*[=:]\s*\S{20,}",
}
# Extra checks for settings.json only (it is JSON, so these shapes are far less likely to be prose).
SETTINGS_ONLY = {
    "long opaque value": r'["\s=:](?!/)[A-Za-z0-9+/_\-]{40,}["\s]',          # values starting with / are paths
    "IPv4 address": r"(?<![\d.=<>~])(?!127\.0\.0\.)(?:\d{1,3}\.){3}\d{1,3}\b",  # not loopback, not "==1.2.3.4"
}


def first_match(text, patterns):
    for name, pattern in patterns.items():
        if re.search(pattern, text):
            return name
    return None


mode = sys.argv[1]
if mode == "scan":
    text = open(sys.argv[2], encoding="utf-8", errors="replace").read()
    hit = first_match(text, HIGH_CONFIDENCE)
    if hit:
        sys.stderr.write("secret-shaped string (%s)" % hit)
        sys.exit(10)
    sys.exit(0)

if mode == "settings":
    src, dst, home = sys.argv[2:5]
    data = json.load(open(src, encoding="utf-8"))
    DROP = ("hooks", "sandbox", "env", "apiKeyHelper", "mcpServers")
    dropped = [k for k in DROP if data.pop(k, None) is not None]
    text = json.dumps(data, indent=2, ensure_ascii=False).replace(home, "$HOME")
    hit = first_match(text, dict(HIGH_CONFIDENCE, **SETTINGS_ONLY))
    if hit:
        sys.stderr.write("settings.json still contains a secret-shaped string or address (%s); refusing to write\n" % hit)
        sys.exit(3)
    open(dst, "w", encoding="utf-8").write(text + "\n")
    print("dropped keys:", ", ".join(dropped) or "(none)")
    sys.exit(0)

sys.exit(2)
PYEOF

copy_file() {
  local src="$1" dst_dir="$2" label="$3" rc=0 msg
  if [[ ! -f "$src" ]]; then
    warn "$label — source not found: $src"
    return
  fi
  msg="$(python3 -c "$SCAN_PY" scan "$src" 2>&1)" || rc=$?
  if [[ $rc -eq 10 ]]; then
    err "$label — ${msg}; NOT copied. Remove the secret from the source file, then re-run."
    return
  elif [[ $rc -ne 0 ]]; then
    err "$label — secret scan failed (exit $rc): ${msg}; NOT copied (an unscanned file is treated as unsafe)."
    return
  fi
  mkdir -p "$dst_dir"
  cp "$src" "$dst_dir/"
  ok "$label"
}

# Replace the home directory with $HOME so the backup restores on another machine or user.
# surrogateescape: a file that is not valid UTF-8 must not abort the whole run; its bytes are preserved.
rewrite_home() {
  local f="$1"
  python3 - "$f" "$HOME" <<'PYEOF'
import sys
path, home = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8", errors="surrogateescape").read()
open(path, "w", encoding="utf-8", errors="surrogateescape").write(text.replace(home, "$HOME"))
PYEOF
}

sanitize_settings() {
  local src="$CLAUDE_DIR/settings.json" dst="$OUT_DIR/settings.sanitized.json" msg
  if [[ ! -f "$src" ]]; then warn "settings.json — source not found"; return; fi
  mkdir -p "$OUT_DIR"
  if msg="$(python3 -c "$SCAN_PY" settings "$src" "$dst" "$HOME" 2>&1)"; then
    ok "settings.json -> settings.sanitized.json (${msg}; home path -> \$HOME)"
  else
    err "settings.json — ${msg:-sanitizing failed}; nothing written"; rm -f "$dst"
  fi
}

echo "==================================================="
echo "  User-level Claude config backup — ${DATE}"
echo "  -> $OUT_DIR"
echo "==================================================="
echo ""

echo "-- 1. CLAUDE.md / docs --"
copy_file "$CLAUDE_DIR/CLAUDE.md" "$OUT_DIR" "CLAUDE.md"
for f in "$CLAUDE_DIR"/docs/*.md; do
  [[ -f "$f" ]] && copy_file "$f" "$OUT_DIR/docs" "docs/$(basename "$f")"
done
echo ""

echo "-- 2. commands/ (EXCLUDE_COMMANDS='${EXCLUDE_COMMANDS}') --"
for f in "$CLAUDE_DIR"/commands/*.md; do
  [[ -f "$f" ]] || continue
  name="$(basename "$f")"
  # shellcheck disable=SC2053
  if [[ -n "$EXCLUDE_COMMANDS" && "$name" == $EXCLUDE_COMMANDS ]]; then continue; fi
  copy_file "$f" "$OUT_DIR/commands" "commands/$name"
done
echo ""

echo "-- 3. statusline / hook scripts --"
copy_file "$CLAUDE_DIR/statusline-command.sh" "$OUT_DIR" "statusline-command.sh"
for f in "$CLAUDE_DIR"/hooks/*.sh; do
  [[ -f "$f" ]] && copy_file "$f" "$OUT_DIR/hooks" "hooks/$(basename "$f")"
done
echo ""

echo "-- 4. settings.json (sanitized) --"
sanitize_settings
echo ""

# Home path -> $HOME in text files (the JSON was handled during sanitizing).
for f in "$OUT_DIR"/CLAUDE.md "$OUT_DIR"/docs/*.md "$OUT_DIR"/commands/*.md "$OUT_DIR"/statusline-command.sh "$OUT_DIR"/hooks/*.sh; do
  [[ -f "$f" ]] && rewrite_home "$f"
done

echo "-- 5. backup log --"
# NOTE: write ${DATE} with braces — a multibyte character right after a bare $DATE can be parsed as part of the
# variable name under some locales, which aborts the script under `set -u`.
cat > "$OUT_DIR/_backup_log.md" <<LOGEOF
# User-level Claude config backup

> Last backup: ${DATE} (\`bash automation/vault_backup_config.sh\`)

## What is backed up (source: \`~/.claude/\`)

| File | Notes |
|------|-------|
| \`CLAUDE.md\`, \`docs/\` | user-level instructions and the rule documents they reference |
| \`commands/\` | custom slash commands |
| \`statusline-command.sh\`, \`hooks/\` | your own scripts (every file is scanned for secret-shaped strings before it is copied) |
| \`settings.sanitized.json\` | settings.json minus \`hooks\`, \`sandbox\`, \`env\`, \`apiKeyHelper\`, \`mcpServers\`; home directory replaced by \`\$HOME\` |

## Deliberately not backed up

The dropped settings keys above, \`~/.claude.json\` (OAuth), \`projects/*/memory\` (disposable),
\`skills/\` and \`plugins/\` (reinstallable), transcripts / history / caches.

## Restore

\`\`\`bash
B="10 - Meta/Environment/user-claude"
cp "\$B/CLAUDE.md" "\$B/statusline-command.sh" ~/.claude/
mkdir -p ~/.claude/{docs,commands,hooks}
cp "\$B"/docs/*.md ~/.claude/docs/; cp "\$B"/commands/*.md ~/.claude/commands/; cp "\$B"/hooks/*.sh ~/.claude/hooks/
# the backup holds the literal string \$HOME; substitute it on restore:
sed -i.bak 's|\\\$HOME|'"\$HOME"'|g' ~/.claude/CLAUDE.md ~/.claude/docs/*.md ~/.claude/commands/*.md
# settings.sanitized.json is for reference / manual merge only: re-create the dropped keys yourself.
\`\`\`
LOGEOF
ok "_backup_log.md updated"
echo ""

echo "==================================================="
if [[ $FAILED -gt 0 ]]; then
  echo -e "${R}  Done: $COPIED files backed up, $FAILED errors${N}"
else
  echo -e "${G}  Done: $COPIED files backed up${N}"
fi
echo "  Location: $OUT_DIR"
echo "==================================================="
echo ""
# Only suggest a commit when the destination is NOT git-ignored: a plain `git add` on an ignored path fails,
# and the usual workaround (`git add -f`) would publish personal config to a public fork.
if [[ "$OUT_DIR" != "$ROOT_DIR"/* ]]; then
  echo "  The destination is outside this repository, so there is nothing to commit."
elif git -C "$ROOT_DIR" check-ignore -q "$OUT_DIR" 2>/dev/null; then
  echo "  The destination is git-ignored, so nothing is staged. To version it in a PRIVATE vault, remove the"
  echo "  ignore line for it from .gitignore first."
else
  echo "  Suggested commit:"
  echo "  git -C \"$ROOT_DIR\" add \"$OUT_DIR\""
  echo "  git -C \"$ROOT_DIR\" commit --only -m \"[meta] user-level config backup: ${DATE}\" -- \"$OUT_DIR\""
fi
exit $(( FAILED > 0 ? 1 : 0 ))
