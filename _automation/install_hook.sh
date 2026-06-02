#!/usr/bin/env bash
# Install the frontmatter-lint pre-commit hook.
# Symlinks .git/hooks/pre-commit to run lint_frontmatter.py --staged on every commit.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOK_DIR="$REPO_ROOT/.git/hooks"
HOOK="$HOOK_DIR/pre-commit"

if [ ! -d "$REPO_ROOT/.git" ]; then
  echo "error: not a git repository ($REPO_ROOT/.git missing)" >&2
  exit 1
fi

mkdir -p "$HOOK_DIR"

cat > "$HOOK" <<'EOF'
#!/usr/bin/env bash
# Auto-installed by _automation/install_hook.sh
# Reject commits that introduce frontmatter violations.
exec python3 "$(git rev-parse --show-toplevel)/_automation/lint_frontmatter.py" --staged
EOF

chmod +x "$HOOK"
echo "Installed pre-commit hook -> $HOOK"
echo "It runs: python3 _automation/lint_frontmatter.py --staged"
echo "Bypass once with: git commit --no-verify"
