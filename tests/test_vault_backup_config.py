"""Tests for automation/vault_backup_config.sh using a synthetic HOME (never touches real config).

The script copies user-level Claude config (~/.claude) into a folder that may end up under version control.
The properties that matter, and that these tests pin down:
  * hooks / sandbox / env / apiKeyHelper / mcpServers are dropped from settings, and the home directory
    becomes the literal string $HOME
  * a secret-shaped string in ANY copied file (not only settings.json) stops that file from being copied and
    makes the script exit 1, and the message names the pattern that matched
  * ordinary hyphenated prose is NOT mistaken for a key (a scanner that refuses normal CLAUDE.md files is useless)
  * if the scan itself fails, the file is treated as unsafe
  * the restore command documented in the generated log really restores the home path
  * the "suggested commit" hint is not printed for a git-ignored or external destination
"""
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "automation" / "vault_backup_config.sh"

# Built by concatenation so this file itself contains no literal secret-shaped marker.
PRIVATE_KEY_LINE = "# -----BEGIN OPENSSH " + "PRIVATE KEY-----"


def _make_home(tmp_path: Path, settings: dict) -> Path:
    home = tmp_path / "home"
    claude = home / ".claude"
    (claude / "docs").mkdir(parents=True)
    (claude / "commands").mkdir()
    (claude / "hooks").mkdir()
    (claude / "CLAUDE.md").write_text(f"# Global\nwork under {home}/proj\n", encoding="utf-8")
    (claude / "docs" / "a.md").write_text(f"doc {home}\n", encoding="utf-8")
    (claude / "commands" / "hello.md").write_text("cmd\n", encoding="utf-8")
    (claude / "commands" / "plug-x.md").write_text("cmd\n", encoding="utf-8")
    (claude / "statusline-command.sh").write_text(f"#!/bin/sh\necho {home}\n", encoding="utf-8")
    (claude / "hooks" / "h.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (claude / "settings.json").write_text(json.dumps(settings, indent=2), encoding="utf-8")
    return home


def _run(home: Path, out: Path, script: Path = SCRIPT, **extra_env):
    env = dict(os.environ, HOME=str(home), LC_ALL="en_US.UTF-8", **extra_env)
    if out is not None:
        env["BACKUP_OUT_DIR"] = str(out)
    return subprocess.run(["bash", str(script)], capture_output=True, text=True, env=env)


def _text(result):
    return result.stdout + result.stderr


# ── settings sanitizing ────────────────────────────────────────────────────

def test_sanitizes_settings_and_rewrites_home(tmp_path):
    home = tmp_path / "home"
    home = _make_home(tmp_path, {
        "model": "sonnet",
        "permissions": {"allow": ["WebSearch"]},
        "hooks": {"Stop": [{"hooks": [{"command": "x"}]}]},
        "sandbox": {"path": f"{home}/x"},
        "env": {"SOME_SETTING": "value"},
        "apiKeyHelper": "get-key.sh",
        "mcpServers": {"s": {"command": "run", "env": {"K": "v"}}},
        "statusLine": {"command": f"{home}/s.sh"},
    })
    out = tmp_path / "out"
    result = _run(home, out, EXCLUDE_COMMANDS="plug-*")
    assert result.returncode == 0, _text(result)

    settings = json.loads((out / "settings.sanitized.json").read_text(encoding="utf-8"))
    for dropped in ("hooks", "sandbox", "env", "apiKeyHelper", "mcpServers"):
        assert dropped not in settings, dropped
    assert settings["statusLine"]["command"] == "$HOME/s.sh"
    assert not [p for p in out.rglob("*") if p.is_file() and str(home) in p.read_text(encoding="utf-8")]
    assert (out / "commands" / "hello.md").exists()
    assert not (out / "commands" / "plug-x.md").exists()


def test_refuses_settings_with_secret_shaped_string_and_names_the_pattern(tmp_path):
    home = _make_home(tmp_path, {"model": "sonnet", "note": "ghp_" + "A" * 30})
    out = tmp_path / "out"
    result = _run(home, out)
    assert result.returncode == 1
    assert not (out / "settings.sanitized.json").exists()
    assert "provider token" in _text(result) and "refusing to write" in _text(result)
    assert (out / "CLAUDE.md").exists()   # the rest of the backup still happens


def test_refuses_settings_that_name_an_ip_address(tmp_path):
    home = _make_home(tmp_path, {"model": "sonnet", "permissions": {"allow": ["Bash(ssh user@10.20.30.40 ls)"]}})
    out = tmp_path / "out"
    result = _run(home, out)
    assert result.returncode == 1 and not (out / "settings.sanitized.json").exists()
    assert "IPv4 address" in _text(result)


def test_settings_with_loopback_versions_and_long_paths_are_accepted(tmp_path):
    """Fail-closed must not mean fail-always: loopback, version pins and long filesystem paths are ordinary."""
    home = _make_home(tmp_path, {
        "model": "sonnet",
        "permissions": {"allow": ["Bash(curl http://127.0.0.1:8080/health)", "Bash(pip install pkg==1.2.3.4)"]},
        "additionalDirectories": ["/Volumes/external-disk/my-very-long-project-name-that-goes-on/and-on/subdir"],
    })
    out = tmp_path / "out"
    result = _run(home, out)
    assert result.returncode == 0, _text(result)
    assert (out / "settings.sanitized.json").exists()


# ── per-file secret scan ───────────────────────────────────────────────────

@pytest.mark.parametrize("name,content", [
    ("openai_style", "curl -H 'Authorization: Bearer sk-" + "a" * 30 + "' https://example.test\n"),
    ("private_key", PRIVATE_KEY_LINE + "\n"),
    ("slack_webhook", "curl -X POST https://hooks.slack.com/services/T0000000/B0000000/" + "X" * 24 + "\n"),
    ("discord_webhook", "curl https://discord.com/api/webhooks/123456789012345678/" + "a" * 30 + "\n"),
    ("github_oauth", "token=gho_" + "A" * 30 + "\n"),
    ("gitlab_pat", "token=glpat-" + "a" * 22 + "\n"),
    ("bearer_header", "curl -H 'Authorization: Bearer abc123def456ghi789jkl012mno345' x\n"),
    ("aws_secret", "aws_secret_access_key = " + "A1b2C3d4" * 5 + "\n"),
])
def test_secret_in_a_hook_script_is_not_copied(tmp_path, name, content):
    """Hook and statusline scripts are where webhook URLs and API keys usually live; they get scanned too."""
    home = _make_home(tmp_path, {"model": "sonnet"})
    (home / ".claude" / "hooks" / "notify.sh").write_text("#!/bin/sh\n" + content, encoding="utf-8")
    out = tmp_path / "out"
    result = _run(home, out)
    assert result.returncode == 1, _text(result)
    assert not (out / "hooks" / "notify.sh").exists()
    assert (out / "hooks" / "h.sh").exists()   # clean files are still backed up
    assert "NOT copied" in _text(result) and "secret-shaped string (" in _text(result)


def test_secret_in_claude_md_is_not_copied(tmp_path):
    home = _make_home(tmp_path, {"model": "sonnet"})
    (home / ".claude" / "CLAUDE.md").write_text("token: AKIA" + "A" * 16 + "\n", encoding="utf-8")
    out = tmp_path / "out"
    assert _run(home, out).returncode == 1
    assert not (out / "CLAUDE.md").exists()


def test_ordinary_hyphenated_prose_is_not_mistaken_for_a_key(tmp_path):
    """'risk-based-...' / 'desk-only-...' contain 'sk-'; without a left boundary the scanner refuses normal docs."""
    home = _make_home(tmp_path, {"model": "sonnet"})
    (home / ".claude" / "CLAUDE.md").write_text(
        "Use a risk-based-prioritization-framework and task-specific-instructions-for-agents.\n"
        "See desk-only-guardrails-for-poc-generation and Bearer token-based-authentication-mechanism-notes.\n",
        encoding="utf-8")
    out = tmp_path / "out"
    result = _run(home, out)
    assert result.returncode == 0, _text(result)
    assert (out / "CLAUDE.md").exists()


def test_unreadable_file_is_treated_as_unsafe_not_as_clean(tmp_path):
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root can read anything")
    home = _make_home(tmp_path, {"model": "sonnet"})
    hook = home / ".claude" / "hooks" / "locked.sh"
    hook.write_text("#!/bin/sh\n", encoding="utf-8")
    hook.chmod(0)
    try:
        out = tmp_path / "out"
        result = _run(home, out)
        assert result.returncode == 1
        assert not (out / "hooks" / "locked.sh").exists()
        assert "secret scan failed" in _text(result)
    finally:
        hook.chmod(stat.S_IRUSR | stat.S_IWUSR)


def test_non_utf8_hook_does_not_abort_the_run(tmp_path):
    home = _make_home(tmp_path, {"model": "sonnet"})
    (home / ".claude" / "hooks" / "latin1.sh").write_bytes(b"#!/bin/sh\n# caf\xe9 note\n")
    out = tmp_path / "out"
    result = _run(home, out)
    assert result.returncode == 0, _text(result)
    assert b"caf\xe9" in (out / "hooks" / "latin1.sh").read_bytes()


# ── restore and commit hint ────────────────────────────────────────────────

def test_documented_restore_command_restores_home(tmp_path):
    home = _make_home(tmp_path, {"model": "sonnet"})
    out = tmp_path / "out"
    assert _run(home, out).returncode == 0
    backed_up = (out / "CLAUDE.md").read_text(encoding="utf-8")
    assert "$HOME" in backed_up and str(home) not in backed_up

    log = (out / "_backup_log.md").read_text(encoding="utf-8")
    restore_line = next(line for line in log.splitlines() if line.startswith("sed -i.bak "))
    target = tmp_path / "restore" / "CLAUDE.md"
    target.parent.mkdir()
    target.write_text(backed_up, encoding="utf-8")
    cmd = restore_line.replace("~/.claude/CLAUDE.md ~/.claude/docs/*.md ~/.claude/commands/*.md", str(target))
    subprocess.run(["bash", "-c", cmd], check=True, env=dict(os.environ, HOME=str(home)))
    restored = target.read_text(encoding="utf-8")
    assert str(home) in restored and "$HOME" not in restored


def test_no_commit_suggestion_for_an_external_destination(tmp_path):
    home = _make_home(tmp_path, {"model": "sonnet"})
    result = _run(home, tmp_path / "out")           # destination outside the repo
    assert result.returncode == 0
    assert "Suggested commit" not in result.stdout and "outside this repository" in result.stdout


def _copy_script_into_temp_repo(tmp_path: Path, gitignore: str) -> Path:
    """The script resolves its repo from its own location, so run a COPY of it inside a throw-away git repo."""
    repo = tmp_path / "repo"
    (repo / "automation").mkdir(parents=True)
    shutil.copy(SCRIPT, repo / "automation" / "vault_backup_config.sh")
    (repo / ".gitignore").write_text(gitignore, encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True, capture_output=True)
    return repo / "automation" / "vault_backup_config.sh"


def test_no_commit_suggestion_when_the_destination_is_git_ignored(tmp_path):
    script = _copy_script_into_temp_repo(tmp_path, "10 - Meta/Environment/user-claude/\n")
    home = _make_home(tmp_path, {"model": "sonnet"})
    result = _run(home, None, script=script)          # default destination = inside the temp repo, ignored
    assert result.returncode == 0, _text(result)
    assert "git-ignored" in result.stdout and "Suggested commit" not in result.stdout


def test_commit_suggestion_is_shown_when_the_destination_is_not_ignored(tmp_path):
    script = _copy_script_into_temp_repo(tmp_path, "# nothing ignored\n")
    home = _make_home(tmp_path, {"model": "sonnet"})
    result = _run(home, None, script=script)
    assert result.returncode == 0, _text(result)
    assert "Suggested commit" in result.stdout
