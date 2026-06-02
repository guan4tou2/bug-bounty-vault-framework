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
    expected = ["attack-chain-deep-dive.md", "bbflow-runner.md", "cvss-auto-scorer.md", "pre-recon.md", "report-writer.md", "vault-sync.md"]
    for name in expected:
        assert (agents_dir / name).exists(), f"Missing agent: {name}"
    assert not (agents_dir / "submit-form.md").exists(), "Public framework should use generic report-writer agent"


def test_claude_skills_exist():
    skills_dir = ROOT / ".claude" / "skills"
    assert skills_dir.is_dir()
    expected = [
        "bb-version-cve-precheck",
        "bb-dedup-finding",
        "bb-cve-citation",
        "bb-form-writer",
        "bb-context-handoff",
        "bb-triage-response",
        "bb-incident-response",
        "bb-scope-safety-check",
        "bb-attack-chain-review",
        "bb-evidence-readiness",
        "bb-attempt-recorder",
        "bb-submission-readiness",
        "bb-knowledge-capture",
    ]
    for name in expected:
        assert (skills_dir / name / "SKILL.md").exists(), f"Missing skill: {name}"
    assert not (skills_dir / "bb-hitcon-form").exists(), "Public framework should not ship platform-specific form skills"


def test_public_framework_uses_platform_neutral_report_writing():
    """Public seed must provide generic report/form writing, not platform-specific templates."""
    text = all_text()
    forbidden = [
        "bb-hitcon-form",
        "HITCON ZeroDay",
        "TWCERT",
        "HackerOne",
        "Bugcrowd",
        "Intigriti",
        "ZD-2026",
        "FORM - HITCON",
        "reports/hitcon",
        "reports/twcert",
        "reports/hackerone",
        "reports/bugcrowd",
        "reports/intigriti",
    ]
    for token in forbidden:
        assert token.lower() not in text.lower(), f"Platform-specific public content leaked: {token}"

    for required in (
        "bb-form-writer",
        "report-writer",
        "platform-neutral",
        "templates/form.md",
        "templates/submission.md",
    ):
        assert required in text, f"Missing generic report/form workflow marker: {required}"


def test_private_adapter_docs_define_public_private_boundary():
    """Public seed must document how users add private downstream adapters."""
    readme = read("README.md")
    private_adapters = read("docs/private-adapters.md")
    public_vs_private = read("docs/public-vs-private.md")

    for path in ("docs/private-adapters.md", "docs/public-vs-private.md"):
        assert path in readme, f"README must link {path}"

    for required in (
        "Private Adapter Pattern",
        "public seed",
        "private vault",
        "generic FORM",
        "do not upstream",
        "downstream channel",
    ):
        assert required in private_adapters, f"Missing adapter guidance: {required}"

    for required in (
        "Public Seed",
        "Private Vault",
        "workspace",
        "platform-neutral",
        "target-specific",
        "bbflow",
        "LLM Wiki",
    ):
        assert required in public_vs_private, f"Missing boundary marker: {required}"


# The mirrors carry exactly the Claude skills plus one CLI-only router.
MIRROR_EXTRA = {"bb-agent-prompts"}


def test_codex_skills_mirror_claude():
    codex_dir = ROOT / ".codex" / "skills"
    assert codex_dir.is_dir()
    claude_skills = {p.parent.name for p in (ROOT / ".claude" / "skills").glob("*/SKILL.md")}
    codex_skills = {p.parent.name for p in codex_dir.glob("*/SKILL.md")}
    # Exact set-equality (minus the known router) catches Claude-side renames
    # that would otherwise leave orphaned mirror skills behind.
    assert codex_skills == claude_skills | MIRROR_EXTRA, (
        f"Codex drift — missing: {claude_skills - codex_skills}, "
        f"orphaned: {codex_skills - claude_skills - MIRROR_EXTRA}"
    )


def test_gemini_skills_mirror_claude():
    gemini_dir = ROOT / ".gemini" / "skills"
    assert gemini_dir.is_dir()
    claude_skills = {p.parent.name for p in (ROOT / ".claude" / "skills").glob("*/SKILL.md")}
    gemini_skills = {p.parent.name for p in gemini_dir.glob("*/SKILL.md")}
    assert gemini_skills == claude_skills | MIRROR_EXTRA, (
        f"Gemini drift — missing: {claude_skills - gemini_skills}, "
        f"orphaned: {gemini_skills - claude_skills - MIRROR_EXTRA}"
    )


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
    for name in ("handoff.md", "operation-log.md", "candidate-review.md"):
        assert (ROOT / "templates" / name).exists(), f"Missing template: {name}"


def test_candidate_lifecycle_is_available_in_public_framework():
    quick = read("AGENTS_QUICK.md")
    candidate = read("templates/candidate-review.md")
    contract = read("bbflow/output-contract.md")

    for required in (
        "bb-scope-safety-check",
        "bb-attack-chain-review",
        "bb-evidence-readiness",
        "bb-attempt-recorder",
        "bb-submission-readiness",
        "bb-knowledge-capture",
    ):
        assert required in quick

    for required in (
        "candidate found",
        "Scope Safety Check",
        "Attack Chain Review",
        "Evidence Readiness",
        "Candidate Decision",
    ):
        assert required in candidate

    for required in (
        "candidate_type",
        "evidence_hint",
        "chain_potential",
        "requires_scope_safety",
        "suggested_skill",
    ):
        assert required in contract


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


def test_no_private_infrastructure_path_patterns():
    """Catch incomplete neutralization of the private vault's own infra.

    The public repo IS the vault root, so the literal 'Bug Bounty Vault/'
    path prefix, private auto-memory files, private tooling names, and the
    wrong '09 - KB/' folder abbreviation must never appear.
    """
    content = all_text()
    forbidden_patterns = [
        "Bug Bounty Vault/",   # repo root is the vault — no nested prefix
        "09 - KB/",            # wrong abbreviation; folder is '09 - Knowledge Base/'
        "memory/MEMORY",       # private auto-memory file
        "memory/project_",     # private auto-memory file
        "memory `feedback_",   # private auto-memory citation (backtick form)
        "memory `project_",    # private auto-memory citation (backtick form)
        "bbops",               # private tooling
        "graphify",            # author's private tooling — keep KB indexing tool-agnostic
        "Master Kanban.md",    # dangling private file path (public board is "Kanban Board.md")
    ]
    for needle in forbidden_patterns:
        assert needle not in content, f"Private infra leak: {needle}"


# ── CI & deeper integrity ────────────────────────────────────────────────────


def test_ci_workflow_runs_the_test_suite():
    ci = ROOT / ".github" / "workflows" / "test.yml"
    assert ci.exists(), "Missing CI workflow .github/workflows/test.yml"
    text = ci.read_text(encoding="utf-8")
    assert "pytest" in text, "CI workflow must run pytest"


def test_frontmatter_blocks_are_valid_yaml():
    """Every .md with a leading frontmatter block must parse as YAML and close."""
    import re as _re
    import pytest
    yaml = pytest.importorskip("yaml")  # PyYAML is a test dependency (see CI)
    scan_dirs = ["07 - Templates", "09 - Knowledge Base", "01 - Targets/_example", "templates"]
    fm_re = _re.compile(r"\A---\n(.*?)\n---\n", _re.DOTALL)
    for d in scan_dirs:
        for md in (ROOT / d).rglob("*.md"):
            text = md.read_text(encoding="utf-8")
            if not text.startswith("---"):
                continue
            m = fm_re.match(text)
            assert m, f"Frontmatter not closed with --- in {md.relative_to(ROOT)}"
            # Templater/placeholder tokens aren't valid YAML scalars on their own;
            # only assert parse-ability when there are no unescaped template tokens.
            block = m.group(1)
            if "<%" in block or "{{" in block:
                continue
            try:
                yaml.safe_load(block)
            except Exception as e:  # noqa: BLE001
                raise AssertionError(f"Invalid YAML frontmatter in {md.relative_to(ROOT)}: {e}")


def test_relative_markdown_links_resolve():
    """In-repo relative [text](path.md) links must point at existing files."""
    import re as _re
    link_re = _re.compile(r"\]\(([^)]+\.md)(#[^)]*)?\)")
    skip_parts = {".git", ".pytest_cache", "__pycache__"}
    missing = []
    for md in ROOT.rglob("*.md"):
        if skip_parts.intersection(md.parts):
            continue
        text = md.read_text(encoding="utf-8", errors="ignore")
        for m in link_re.finditer(text):
            target = m.group(1)
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            if "<" in target or ">" in target:  # placeholder like <target>.md
                continue
            resolved = (md.parent / target).resolve()
            if not resolved.exists():
                missing.append(f"{md.relative_to(ROOT)} -> {target}")
    assert not missing, "Broken relative markdown links:\n" + "\n".join(missing)


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
