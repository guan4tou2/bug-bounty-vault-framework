from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def all_text() -> str:
    chunks = []
    for path in ROOT.rglob("*"):
        ignored_parts = {".git", ".pytest_cache", "__pycache__", "tests"}
        if path.is_file() and not ignored_parts.intersection(path.parts):
            chunks.append(path.read_text(encoding="utf-8", errors="ignore"))
    return "\n".join(chunks)


def test_required_public_framework_files_exist():
    required = [
        "README.md",
        "LICENSE",
        ".gitignore",
        "docs/architecture.md",
        "docs/workflow.md",
        "docs/sop.md",
        "docs/llm-wiki-framework.md",
        "docs/public-safety.md",
        "docs/fresh-start.md",
        "templates/target.md",
        "templates/recon-note.md",
        "templates/finding.md",
        "templates/submission.md",
        "templates/form.md",
        "templates/scope.yaml",
        "scripts/verify_public_skeleton.py",
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
    ):
        assert required in architecture

    for required in (
        "Target -> Recon -> Finding -> Submission -> Triage -> Knowledge Capture",
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


def test_templates_are_placeholders_not_real_reports():
    for path in (
        "templates/target.md",
        "templates/recon-note.md",
        "templates/finding.md",
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
        "oracle-a1",
        "bug-bounty-vault",
        "cookie:",
        "Authorization:",
        "Bearer ",
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
