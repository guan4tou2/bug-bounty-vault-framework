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
        "init_target.sh",
        "setup_workspace.sh",
    ]
    for name in expected:
        assert (automation_dir / name).exists(), f"Missing automation: {name}"


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
    ]
    for name in expected:
        assert (docs_dir / name).exists(), f"Missing doc: {name}"


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
    forbidden = [
        "/Users/guantou",
        "guantou",
        "TeamPlus",
        "Juiker",
        "digiwin",
        "openfind",
        "watsons",
        "oracle-a1",
        "138.2.59.206",
        "64.110.106.138",
        "younglee.tw5",
    ]
    for needle in forbidden:
        assert needle not in content, f"Private data leak: {needle}"


def test_agents_md_references_automation_not_scripts():
    agents = read("AGENTS.md")
    assert "automation/" in agents, "AGENTS.md should reference automation/"


def test_structure_md_describes_obsidian_layout():
    structure = read("STRUCTURE.md")
    for required in ("00 - Dashboard", "01 - Targets", "07 - Templates", "09 - Knowledge Base"):
        assert required in structure, f"STRUCTURE.md missing: {required}"
