"""Validate the public Obsidian vault framework structure.

Tests verify:
- Required files and directories exist
- No private/target-specific data leaks
- Obsidian numbered folders present
- LLM skill/agent parity across platforms
- Templates use placeholder values
- Scanner configs are seed-only
"""
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def all_text() -> str:
    """Collect all non-git text for forbidden-string scanning."""
    chunks = []
    skip_parts = {".git", ".pytest_cache", "__pycache__", "tests"}
    for path in ROOT.rglob("*"):
        if path.is_file() and not skip_parts.intersection(path.parts):
            try:
                chunks.append(path.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                pass
    return "\n".join(chunks)


# ── Structure ────────────────────────────────────────────────────────────────


def test_obsidian_numbered_folders_exist():
    """Vault must have the Obsidian numbered folder convention."""
    required_dirs = [
        "00 - Dashboard",
        "01 - Targets",
        "01 - Dorks",
        "05 - Tools",
        "07 - Templates",
        "09 - Knowledge Base",
        "10 - Meta",
    ]
    for d in required_dirs:
        assert (ROOT / d).is_dir(), f"Missing Obsidian folder: {d}"


def test_target_example_structure():
    """The _example target must have the full subfolder tree."""
    example = ROOT / "01 - Targets" / "_example"
    assert example.is_dir(), "Missing _example target"
    for sub in ("Findings", "Submissions", "Attempts", "Recon", "Services", "Attack Chains"):
        assert (example / sub).is_dir(), f"Missing _example/{sub}"


def test_required_top_level_files_exist():
    required = [
        "README.md",
        "LICENSE",
        ".gitignore",
        "AGENTS.md",
        "AGENTS_QUICK.md",
        "STRUCTURE.md",
        "CLAUDE.md",
        "CODEX.md",
        "GEMINI.md",
    ]
    for path in required:
        assert (ROOT / path).exists(), f"Missing: {path}"


def test_obsidian_config_exists():
    assert (ROOT / ".obsidian" / "app.json").exists()
    assert (ROOT / ".obsidian" / "community-plugins.json").exists()


# ── LLM Integration ─────────────────────────────────────────────────────────


def test_claude_agents_exist():
    agents_dir = ROOT / ".claude" / "agents"
    assert agents_dir.is_dir()
    expected = ["bbflow-runner.md", "cvss-auto-scorer.md", "pre-recon.md", "submit-form.md", "vault-sync.md"]
    for name in expected:
        assert (agents_dir / name).exists(), f"Missing agent: {name}"


def test_claude_skills_exist():
    skills_dir = ROOT / ".claude" / "skills"
    assert skills_dir.is_dir()
    expected = [
        "bb-version-cve-precheck",
        "bb-dedup-finding",
        "bb-cve-citation",
        "bb-hitcon-form",
        "bb-context-handoff",
        "bb-triage-response",
        "bb-incident-response",
    ]
    for name in expected:
        assert (skills_dir / name / "SKILL.md").exists(), f"Missing skill: {name}"


def test_codex_skills_mirror_claude():
    codex_dir = ROOT / ".codex" / "skills"
    assert codex_dir.is_dir()
    claude_skills = {p.parent.name for p in (ROOT / ".claude" / "skills").glob("*/SKILL.md")}
    codex_skills = {p.parent.name for p in codex_dir.glob("*/SKILL.md")}
    # Codex may have extra (bb-agent-prompts router), but must cover all Claude skills
    assert claude_skills.issubset(codex_skills), f"Codex missing: {claude_skills - codex_skills}"


def test_gemini_skills_mirror_claude():
    gemini_dir = ROOT / ".gemini" / "skills"
    assert gemini_dir.is_dir()
    claude_skills = {p.parent.name for p in (ROOT / ".claude" / "skills").glob("*/SKILL.md")}
    gemini_skills = {p.parent.name for p in gemini_dir.glob("*/SKILL.md")}
    assert claude_skills.issubset(gemini_skills), f"Gemini missing: {claude_skills - gemini_skills}"


# ── Templates ────────────────────────────────────────────────────────────────


def test_obsidian_templates_exist():
    templates_dir = ROOT / "07 - Templates"
    assert templates_dir.is_dir()
    expected = [
        "Template - Finding.md",
        "Template - Submission.md",
        "Template - Target.md",
    ]
    for name in expected:
        assert (templates_dir / name).exists(), f"Missing template: {name}"


def test_non_obsidian_templates_exist():
    for name in ("handoff.md", "operation-log.md"):
        assert (ROOT / "templates" / name).exists(), f"Missing template: {name}"


# ── Knowledge Base ───────────────────────────────────────────────────────────


def test_seed_kb_patterns_exist():
    kb_dir = ROOT / "09 - Knowledge Base"
    assert kb_dir.is_dir()
    expected = [
        "Pattern - IDOR.md",
        "Pattern - CORS Misconfiguration.md",
        "Pattern - OAuth Misconfiguration.md",
        "Lessons Learned.md",
    ]
    for name in expected:
        assert (kb_dir / name).exists(), f"Missing KB seed: {name}"


def test_kb_patterns_have_frontmatter():
    kb_dir = ROOT / "09 - Knowledge Base"
    for pattern in kb_dir.glob("Pattern - *.md"):
        content = pattern.read_text(encoding="utf-8")
        assert content.startswith("---"), f"Missing frontmatter: {pattern.name}"
        assert "type: pattern" in content, f"Wrong type in: {pattern.name}"


def test_llm_wiki_framework_maps_to_full_obsidian_vault_layers():
    framework = read("docs/llm-wiki-framework.md")
    architecture = read("docs/architecture.md")

    for required in (
        "Obsidian Vault",
        "LLM Wiki is not the whole Obsidian vault",
        "00 - Dashboard",
        "01 - Targets",
        "07 - Templates",
        "09 - Knowledge Base",
        "10 - Meta",
        "Current state",
        "Templates",
        "Meta",
    ):
        assert required in framework, f"LLM Wiki framework missing layer: {required}"

    for required in (
        "00 - Dashboard",
        "01 - Targets",
        "07 - Templates",
        "09 - Knowledge Base",
        "10 - Meta",
        "LLM Wiki",
    ):
        assert required in architecture, f"Architecture doc missing layer: {required}"


# ── Scanner Configs ──────────────────────────────────────────────────────────


def test_tool_configs_exist():
    tools_dir = ROOT / "tools"
    assert tools_dir.is_dir()
    expected = [
        "tools/nuclei/templates/misconfig-headers.yaml",
        "tools/nuclei/templates/oauth-misconfig.yaml",
        "tools/osmedeus/profiles/light-recon.yaml",
        "tools/bbot/presets/subdomain-enum.yml",
    ]
    for path in expected:
        assert (ROOT / path).exists(), f"Missing tool config: {path}"


# ── Automation ───────────────────────────────────────────────────────────────


def test_automation_scripts_exist():
    automation_dir = ROOT / "automation"
    assert automation_dir.is_dir()
    expected = [
        "start_session.py",
        "end_session.py",
        "check_vault.py",
        "audit_workspace.sh",
        "init_target.sh",
        "setup_workspace.sh",
        "workspace_layout.sh",
        "check_active_sessions.sh",
        "claim.sh",
        "release.sh",
        "session_start_brief.sh",
        "session_end_checklist.sh",
        "session_end_brief.sh",
        "vault_precheck.sh",
    ]
    for name in expected:
        assert (automation_dir / name).exists(), f"Missing automation: {name}"


def test_documented_automation_commands_have_scripts():
    content = "\n".join(
        read(path)
        for path in (
            "AGENTS.md",
            "AGENTS_QUICK.md",
            "CODEX.md",
            "CLAUDE.md",
            "GEMINI.md",
            "docs/session-lifecycle.md",
        )
    )
    for match in __import__("re").finditer(r"automation/([A-Za-z0-9_.-]+\.(?:sh|py))", content):
        assert (ROOT / "automation" / match.group(1)).exists(), f"Documented missing script: {match.group(1)}"


def test_python_automation_commands_are_not_documented_as_bash():
    content = all_text()

    assert not __import__("re").search(r"bash\s+automation/[A-Za-z0-9_.-]+\.py", content)


def test_session_start_brief_wrapper_is_brief_only():
    wrapper = read("automation/session_start_brief.sh")
    start = read("automation/start_session.py")

    assert "--brief-only" in wrapper
    assert "--brief-only" in start


def test_automation_active_sessions_dir():
    sessions_dir = ROOT / "automation" / "active_sessions"
    assert sessions_dir.is_dir()
    assert (sessions_dir / "README.md").exists()


# ── Workspace ────────────────────────────────────────────────────────────────


def test_workspace_scaffold_exists():
    assert (ROOT / "workspace" / "README.md").exists()
    assert (ROOT / "workspace" / ".gitignore").exists()


# ── Docs & bbflow ────────────────────────────────────────────────────────────


def test_docs_exist():
    docs_dir = ROOT / "docs"
    assert docs_dir.is_dir()
    expected = [
        "session-lifecycle.md",
        "architecture.md",
        "workflow.md",
        "post-clone-checklist.md",
    ]
    for name in expected:
        assert (docs_dir / name).exists(), f"Missing doc: {name}"


def test_public_seed_positioning_and_post_clone_checklist():
    readme = read("README.md")
    checklist = read("docs/post-clone-checklist.md")

    for required in (
        "public seed",
        "private vault",
        "self-updating",
        "docs/post-clone-checklist.md",
    ):
        assert required in readme, f"README missing public positioning: {required}"

    for required in (
        "Optional LLM setup",
        "Claude Code",
        "Codex",
        "Gemini",
        "No LLM",
        "Optional scanner setup",
        "VPS is recommended",
        "not required",
        "Pearclean / AppCleaner / CleanMyMac",
        "bash automation/setup_workspace.sh",
        "bash automation/init_target.sh <target>",
    ):
        assert required in checklist, f"Post-clone checklist missing: {required}"


def test_public_safety_documents_local_cleaner_exclusions():
    safety = read("docs/public-safety.md")

    for required in (
        "Pearclean / AppCleaner / CleanMyMac",
        "exclusion",
        "workspace/",
        "01 - Targets/",
    ):
        assert required in safety, f"public-safety missing cleaner guidance: {required}"


def test_public_workflow_forbids_auto_deleting_canonical_target_data():
    agents = read("AGENTS.md")
    vault_sync = read(".claude/agents/vault-sync.md")

    for required in (
        "Never auto-delete Vault target directories",
        "01 - Targets/<target>/",
        "canonical",
        "quarantine/manual-review",
        "explicit user confirmation",
    ):
        assert required in agents, f"AGENTS.md missing no-auto-delete rule: {required}"

    for required in (
        "Never auto-delete Vault target directories",
        "orphan",
        "empty shell",
        "explicit user confirmation",
    ):
        assert required in vault_sync, f"vault-sync missing no-auto-delete rule: {required}"


def test_protect_critical_writes_hook_covers_workflow_control_files():
    hook = read("automation/protect_critical_writes.sh")
    settings = read(".claude/settings.json")

    for required in (
        "AGENTS.md",
        "CLAUDE.md",
        "CODEX.md",
        "GEMINI.md",
        "STRUCTURE.md",
        "RECON_DB.md",
        "FINDINGS_QUICK_REF.md",
        "SCOPE.md",
        "HANDOFF.md",
    ):
        assert required in hook, f"protect hook missing: {required}"

    assert '"PreToolUse"' in settings
    assert "protect_critical_writes.sh" in settings
    assert '"PostToolUse"' in settings
    assert "audit_workspace.sh" in settings


def test_public_docs_do_not_force_specific_llm_or_vps():
    content = "\n".join(
        read(path)
        for path in (
            "README.md",
            "AGENTS.md",
            "AGENTS_QUICK.md",
            "CODEX.md",
            "CLAUDE.md",
            "GEMINI.md",
            "docs/session-lifecycle.md",
            "docs/post-clone-checklist.md",
        )
    )

    assert "VPS only" not in content
    assert "VPS required" not in content
    assert "must use claude" not in content.lower()
    assert "must use codex" not in content.lower()


def test_changelog_tracks_public_seed_release():
    changelog = read("CHANGELOG.md")

    assert "## v0.1.0" in changelog
    assert "public seed" in changelog


def test_session_lifecycle_covers_phases():
    lifecycle = read("docs/session-lifecycle.md")
    lifecycle_lower = lifecycle.lower()
    for required in ("claim", "closeout", "handoff", "knowledge capture"):
        assert required in lifecycle_lower, f"Missing in session-lifecycle: {required}"


def test_bbflow_framework_exists():
    bbflow_dir = ROOT / "bbflow"
    assert bbflow_dir.is_dir()
    expected = ["README.md", "flow.md", "output-contract.md", "safety-boundary.md", "scope.example.yaml"]
    for name in expected:
        assert (bbflow_dir / name).exists(), f"Missing bbflow: {name}"


# ── Safety ───────────────────────────────────────────────────────────────────


def test_no_private_or_target_specific_data():
    content = all_text()
    content_lower = content.lower()
    # Case-insensitive checks (private target names, usernames)
    ci_forbidden = [
        "guantou",
        "teamplus",
        "juiker",
        "digiwin",
        "openfind",
        "watsons",
        "every8d",
        "e8d.tw",
        "safesay",
    ]
    for needle in ci_forbidden:
        assert needle not in content_lower, f"Private data leak (ci): {needle}"
    # Case-sensitive checks (IPs, hostnames, paths)
    cs_forbidden = [
        "/Users/guantou",
        "oracle-a1",
        "oracle-e2",
        "138.2.59.206",
        "138.2.37.19",
        "64.110.106.138",
        "younglee.tw5",
        "t112c53033",
    ]
    for needle in cs_forbidden:
        assert needle not in content, f"Private data leak: {needle}"


def test_agents_md_references_automation_not_scripts():
    agents = read("AGENTS.md")
    assert "automation/" in agents, "AGENTS.md should reference automation/"


def test_docs_do_not_reference_removed_scripts_directory():
    """Active docs should not reference old flat-layout scripts/ directory.
    CHANGELOG is excluded since it documents the migration history."""
    chunks = []
    skip_parts = {".git", ".pytest_cache", "__pycache__", "tests"}
    skip_files = {"CHANGELOG.md"}
    for path in ROOT.rglob("*"):
        if path.is_file() and not skip_parts.intersection(path.parts) and path.name not in skip_files:
            try:
                chunks.append(path.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                pass
    content = "\n".join(chunks)
    assert "scripts/" not in content
    assert "verify_public_skeleton.py" not in content
    assert "bootstrap_private_vault.py" not in content


def test_structure_md_describes_obsidian_layout():
    structure = read("STRUCTURE.md")
    for required in ("00 - Dashboard", "01 - Targets", "05 - Tools", "07 - Templates", "09 - Knowledge Base"):
        assert required in structure, f"STRUCTURE.md missing: {required}"


def test_public_docs_define_05_tools_as_vault_layer_not_runtime_toolchain():
    """Public framework should match the private vault's active Obsidian layers."""
    for path in ("README.md", "STRUCTURE.md", "docs/architecture.md", "docs/llm-wiki-framework.md"):
        doc = read(path)
        assert "05 - Tools" in doc, f"{path} missing 05 - Tools layer"
        assert "runtime" in doc.lower(), f"{path} should separate vault notes from runtime tooling"
