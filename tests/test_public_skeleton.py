import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def all_text() -> str:
    chunks = []
    for path in ROOT.rglob("*"):
        ignored_parts = {".git", ".pytest_cache", "__pycache__", "tests"}
        if path == ROOT / "scripts/verify_public_skeleton.py":
            continue
        if path.is_file() and not ignored_parts.intersection(path.parts):
            chunks.append(path.read_text(encoding="utf-8", errors="ignore"))
    return "\n".join(chunks)


def test_required_public_framework_files_exist():
    required = [
        "README.md",
        "LICENSE",
        ".gitignore",
        ".obsidian/app.json",
        ".obsidian/appearance.json",
        ".obsidian/community-plugins.json",
        ".obsidian/core-plugins.json",
        ".obsidian/graph.json",
        ".obsidian/plugins/README.md",
        ".obsidian/templates.json",
        "agents/README.md",
        "agents/authorized-security-researcher.md",
        "agents/recon-analyst.md",
        "agents/triage-reviewer.md",
        "bbflow/README.md",
        "bbflow/flow.md",
        "bbflow/knowledge-capture-hook.md",
        "bbflow/output-contract.md",
        "bbflow/scope.example.yaml",
        "bbflow/safety-boundary.md",
        "docs/architecture.md",
        "docs/adoption-model.md",
        "docs/prompting-model.md",
        "docs/workflow.md",
        "docs/sop.md",
        "docs/llm-wiki-framework.md",
        "docs/obsidian-setup.md",
        "docs/public-safety.md",
        "docs/fresh-start.md",
        "hooks/README.md",
        "hooks/preflight-scope-guard.md",
        "hooks/post-run-knowledge-capture.md",
        "hooks/pre-public-sync.md",
        "templates/target.md",
        "templates/recon-note.md",
        "templates/finding.md",
        "templates/review-note.md",
        "templates/submission.md",
        "templates/form.md",
        "templates/scope.yaml",
        "prompts/README.md",
        "prompts/authorized-security-researcher.md",
        "prompts/recon-analyst.md",
        "prompts/triage-reviewer.md",
        "prompts/report-writer.md",
        "prompts/knowledge-curator.md",
        "prompts/vault-maintainer.md",
        "prompts/automation-runner.md",
        "prompts/workflow-coach.md",
        "scripts/verify_public_skeleton.py",
        "skills/README.md",
        "skills/authorized-workflow/SKILL.md",
        "skills/knowledge-capture/SKILL.md",
    ]

    for path in required:
        assert (ROOT / path).exists(), path


def test_repository_is_architecture_only_and_empty_of_operational_data():
    forbidden_dirs = [
        "01 - Targets",
        "09 - Knowledge Base",
        "workspace",
        ".vault-workspace",
        "graphify-out",
        "memory",
        "reports",
        "firmware_analysis",
        "extractions",
    ]

    for path in forbidden_dirs:
        assert not (ROOT / path).exists(), path


def test_public_docs_define_generic_architecture_and_flow():
    readme = read("README.md")
    architecture = read("docs/architecture.md")
    workflow = read("docs/workflow.md")
    llm_wiki = read("docs/llm-wiki-framework.md")
    obsidian_setup = read("docs/obsidian-setup.md")

    for required in (
        "architecture-only",
        "No target data",
        "Vault",
        "Workspace",
        "Automation",
        "LLM Wiki",
    ):
        assert required in readme

    for required in (
        "Vault as canonical source",
        "External workspace",
        "Automation as control plane",
        "Tooling as optional runtime",
        "```mermaid",
        "Public Seed",
        "Private Vault",
        "Workspace",
        "Knowledge Capture",
    ):
        assert required in architecture

    for required in (
        "Target -> Recon -> Finding -> Review -> Knowledge Capture",
        "Safety gate",
        "Dedupe gate",
        "Evidence gate",
        "Knowledge capture gate",
    ):
        assert required in workflow

    for required in (
        "Pattern",
        "Playbook",
        "Reference Card",
        "historical status log",
        "source of truth",
    ):
        assert required in llm_wiki

    for required in (
        "Recommended core plugins",
        "Recommended community plugins",
        "Dataview",
        "Templater",
        "QuickAdd",
        "Git",
        "Bases",
        "Canvas",
    ):
        assert required in obsidian_setup


def test_readme_links_usage_and_obsidian_setup():
    readme = read("README.md")

    for required in (
        "How to Use This Framework",
        "Obsidian Setup",
        "docs/fresh-start.md",
        "docs/obsidian-setup.md",
    ):
        assert required in readme


def test_public_repo_is_starter_only_not_runtime_store():
    readme = read("README.md")
    fresh_start = read("docs/fresh-start.md")
    adoption_model = read("docs/adoption-model.md")
    public_safety = read("docs/public-safety.md")

    for required in (
        "starter kit",
        "seed framework",
        "not a runtime workspace",
    ):
        assert required in readme

    for required in (
        "fork-or-copy boundary",
        "private runtime",
        "do not sync back",
        "owned by the adopter",
    ):
        assert required in adoption_model

    assert "After adoption" in fresh_start
    assert "out of scope for this public repository" in fresh_start
    assert "The verifier protects this public skeleton" in public_safety


def test_obsidian_preset_is_committed_without_plugin_binaries():
    community_plugins = json.loads(read(".obsidian/community-plugins.json"))
    core_plugins = json.loads(read(".obsidian/core-plugins.json"))
    templates_config = json.loads(read(".obsidian/templates.json"))
    plugin_readme = read(".obsidian/plugins/README.md")

    for plugin_id in (
        "dataview",
        "templater-obsidian",
        "quickadd",
        "obsidian-git",
        "obsidian-tasks-plugin",
        "omnisearch",
        "obsidian-linter",
        "table-editor-obsidian",
    ):
        assert plugin_id in community_plugins

    for core_id in (
        "bases",
        "canvas",
        "graph",
        "backlink",
        "properties",
        "templates",
        "switcher",
        "global-search",
    ):
        assert core_id in core_plugins

    assert templates_config["folder"] == "templates"
    assert "plugin binaries are not vendored" in plugin_readme
    assert "Install plugins from Obsidian Community Plugins" in plugin_readme


def test_public_prompt_agent_skill_pack_is_safe_and_generic():
    prompting_model = read("docs/prompting-model.md")
    agents_readme = read("agents/README.md")
    skills_readme = read("skills/README.md")

    for required in (
        "public-safe",
        "private implementation prompts",
        "No exploit payloads",
        "scope guard",
    ):
        assert required in prompting_model

    for required in (
        "tool-neutral",
        "Authorized scope",
        "Stop conditions",
    ):
        assert required in agents_readme

    for required in (
        "skill skeletons",
        "allowed inputs",
        "refuse out-of-scope",
    ):
        assert required in skills_readme

    for path in (
        "prompts/authorized-security-researcher.md",
        "prompts/recon-analyst.md",
        "prompts/triage-reviewer.md",
        "prompts/report-writer.md",
        "prompts/knowledge-curator.md",
        "prompts/vault-maintainer.md",
        "prompts/automation-runner.md",
        "prompts/workflow-coach.md",
        "agents/authorized-security-researcher.md",
        "agents/recon-analyst.md",
        "agents/triage-reviewer.md",
        "skills/authorized-workflow/SKILL.md",
        "skills/knowledge-capture/SKILL.md",
    ):
        content = read(path)
        assert "Authorized scope" in content, path
        assert "Stop conditions" in content, path
        assert "Output" in content, path


def test_public_hook_skeletons_exist_without_runtime_commands():
    hooks_readme = read("hooks/README.md")

    for required in (
        "hook skeletons",
        "private implementation",
        "no runtime commands",
    ):
        assert required in hooks_readme

    for path in (
        "hooks/preflight-scope-guard.md",
        "hooks/post-run-knowledge-capture.md",
        "hooks/pre-public-sync.md",
    ):
        content = read(path)
        assert "Purpose" in content, path
        assert "Trigger" in content, path
        assert "Stop conditions" in content, path
        assert "Output" in content, path


def test_public_bbflow_layer_is_framework_only():
    readme = read("bbflow/README.md")
    flow = read("bbflow/flow.md")
    output_contract = read("bbflow/output-contract.md")
    capture_hook = read("bbflow/knowledge-capture-hook.md")
    scope_example = read("bbflow/scope.example.yaml")
    safety_boundary = read("bbflow/safety-boundary.md")

    for required in (
        "framework-only",
        "bring your own tools",
        "scope guard",
        "no hunters",
        "no payloads",
    ):
        assert required in readme

    for required in (
        "Gate 0",
        "Gate 1",
        "Gate 2",
        "Gate 3",
        "Gate 4",
        "Knowledge Capture",
    ):
        assert required in flow

    for required in (
        "run_manifest.json",
        "candidates.jsonl",
        "schema version",
        "review_status",
    ):
        assert required in output_contract

    for required in (
        "Pattern",
        "Playbook",
        "Checklist",
        "do not copy raw output",
    ):
        assert required in capture_hook

    for required in (
        "version: 1",
        "allowed_assets:",
        "disallowed_assets:",
        "safety_level:",
        "output_dir:",
    ):
        assert required in scope_example

    for required in (
        "No bundled scanners",
        "No evasion guidance",
        "No target-specific templates",
    ):
        assert required in safety_boundary


def test_templates_are_placeholders_not_real_reports():
    for path in (
        "templates/target.md",
        "templates/recon-note.md",
        "templates/finding.md",
        "templates/review-note.md",
        "templates/submission.md",
        "templates/form.md",
        "templates/scope.yaml",
    ):
        content = read(path)
        assert "<" in content and ">" in content, path
        assert "example.com" in content or "<target>" in content or "<program>" in content


def test_no_private_or_target_specific_data_is_present():
    content = all_text()
    forbidden = [
        "/Users/guantou",
        "guantou",
        "TeamPlus",
        "Juiker",
        "digiwin",
        "openfind",
        "watsons",
        "HITCON",
        "TWCERT",
        "Bugcrowd",
        "HackerOne",
        "Intigriti",
        "YesWeHack",
        "ZeroDay",
        "oracle-a1",
        "bug-bounty-vault",
        "cookie:",
        "Authorization:",
        "Bearer ",
        "通報平台",
        "nuclei",
        "osmedeus",
        "bbot",
    ]

    for needle in forbidden:
        assert needle not in content, needle


def test_verify_script_mentions_public_safety_contract():
    script = read("scripts/verify_public_skeleton.py")

    for required in (
        "architecture-only",
        "forbidden_dirs",
        "forbidden_strings",
        "No target data",
    ):
        assert required in script
