"""Tests for automation/check_workspace_boundary.sh against throw-away git repositories."""
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "automation" / "check_workspace_boundary.sh"


def _git(repo: Path, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                   env=dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t",
                            GIT_COMMITTER_EMAIL="t@t"))


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q")
    (r / "workspace").mkdir()
    (r / "workspace" / "README.md").write_text("scaffold\n", encoding="utf-8")
    (r / "workspace" / ".gitignore").write_text("*\n", encoding="utf-8")
    (r / "workspace" / "workshop").mkdir()
    (r / "workspace" / "workshop" / ".gitkeep").write_text("", encoding="utf-8")
    (r / "notes.md").write_text("hello\n", encoding="utf-8")
    _git(r, "add", "-f", "-A")
    _git(r, "commit", "-q", "-m", "init")
    return r


def _run(repo: Path, **env):
    return subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True,
                          env=dict(os.environ, BOUNDARY_ROOT=str(repo), **env))


def test_clean_repo_passes(repo):
    r = _run(repo)
    assert r.returncode == 0, r.stdout
    assert "boundary intact" in r.stdout


def test_tracked_working_material_under_workspace_fails(repo):
    (repo / "workspace" / "workshop" / "acme").mkdir()
    (repo / "workspace" / "workshop" / "acme" / "RECON_DB.md").write_text("secret recon\n", encoding="utf-8")
    _git(repo, "add", "-f", "workspace/workshop/acme/RECON_DB.md")
    r = _run(repo)
    assert r.returncode == 1
    assert "workspace/workshop/acme/RECON_DB.md" in r.stdout


def test_scaffolding_gitkeep_is_allowed(repo):
    (repo / "workspace" / "logs").mkdir()
    (repo / "workspace" / "logs" / ".gitkeep").write_text("", encoding="utf-8")
    _git(repo, "add", "-f", "workspace/logs/.gitkeep")
    assert _run(repo).returncode == 0


def test_process_directory_at_repo_root_fails(repo):
    (repo / "extractions").mkdir()
    (repo / "extractions" / "dump.txt").write_text("x\n", encoding="utf-8")
    r = _run(repo)
    assert r.returncode == 1 and "extractions/" in r.stdout


def test_empty_process_directory_is_tolerated(repo):
    (repo / "logs").mkdir()
    (repo / "logs" / ".gitkeep").write_text("", encoding="utf-8")
    assert _run(repo).returncode == 0


def test_tracked_binary_fails_and_allow_regex_exempts_it(repo):
    (repo / "tests").mkdir()
    (repo / "tests" / "seed.tgz").write_bytes(b"\x1f\x8b" + b"0" * 10)
    _git(repo, "add", "-f", "tests/seed.tgz")
    assert _run(repo).returncode == 1
    assert "tests/seed.tgz" in _run(repo).stdout
    assert _run(repo, BOUNDARY_ALLOW_REGEX="^tests/").returncode == 0


def test_non_ascii_archive_name_is_still_caught(repo):
    """git quotes non-ASCII paths unless core.quotePath=false; the closing quote used to defeat the `.zip$` pattern."""
    (repo / "tests").mkdir()
    (repo / "tests" / "résumé.zip").write_bytes(b"PK" + b"0" * 10)
    _git(repo, "add", "-f", "tests/résumé.zip")
    r = _run(repo)
    assert r.returncode == 1 and "résumé.zip" in r.stdout


def test_directory_holding_only_gitkeep_files_is_not_a_stray_process_directory(repo):
    (repo / "logs" / "sub").mkdir(parents=True)
    (repo / "logs" / "sub" / ".gitkeep").write_text("", encoding="utf-8")
    assert _run(repo).returncode == 0


def test_not_a_git_repo_is_skipped(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    r = _run(plain)
    assert r.returncode == 0 and "SKIP" in r.stdout
