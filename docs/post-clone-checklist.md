# Post-Clone Checklist

This checklist is optional. The framework is an Obsidian vault first; use the parts that fit your workflow.

## 1. Verify the Skeleton

```bash
python3 automation/check_vault.py
python3 -m pytest tests/test_public_skeleton.py -q
```

These checks verify the public framework shape. They do not validate your future private targets, reports, or runtime data.

## 2. Create Local Workspace Folders

```bash
bash automation/setup_workspace.sh
```

`workspace/` is ignored by git and is intended for local scratch files, scan output, logs, and proof-of-concept material.

## 3. Open in Obsidian

Open the repository root as an Obsidian vault. The `.obsidian/` directory ships the **settings and a recommended plugin enable-list** — but **not** the plugin binaries. On first open, install the community plugins via **Settings → Community plugins**. **Templater**, **Dataview**, and **Kanban** are required for the templates, dashboards, and boards to render; the rest are optional. The full step-by-step (including how to verify the dashboards render and how to point Templater at `07 - Templates`) is in [obsidian-setup.md](obsidian-setup.md).

## 4. LLM setup (primary operating mode)

This vault is built to be driven by an LLM agent. Pick one entrypoint:

- **Claude Code**: read `CLAUDE.md`; the agent uses `.claude/skills/` and `.claude/agents/`.
- **Codex**: read `CODEX.md`; run `bash automation/install_codex_skills.sh` to mirror skills into your Codex skill directory.
- **Gemini**: read `GEMINI.md`; run `bash automation/install_gemini_skills.sh` to mirror skills into your Gemini skill directory.
- **Fallback — no LLM**: operate by hand with Obsidian templates, `AGENTS.md`, `STRUCTURE.md`, and the `automation/` scripts.

## 5. Tool layer setup (bbflow)

The tool layer (Ring 2) is the standalone **bbflow** CLI — a separate install, not bundled. Establish it once with `bb-tool-setup` ([../bbflow/setup.md](../bbflow/setup.md)): Docker (`ghcr.io/guan4tou2/bbflow`) or `./install.sh --all`. A contract-conforming scanner is a fallback.

- Run noisy/aggressive scanning (bbflow `hunt`/`flow`, Osmedeus, BBOT, Nuclei at scale, fuzzers) on a VPS or isolated runner.
- Local-only use is enough for note-taking, report drafting, template use, and low-risk validation.
- Bring your own authorization, scope file, and rate limits.

## 6. Initialize Your First Target

```bash
bash automation/init_target.sh <target>
bash automation/claim.sh <target>
```

Then keep operational notes in `workspace/workshop/<target>/` and canonical writeups in `01 - Targets/<target>/`.

## 7. Local Safety

- Keep real operational data in a private repository or under ignored workspace paths.
- Add the vault root, `workspace/`, and `01 - Targets/` to Pearclean / AppCleaner / CleanMyMac exclusion lists.
- Do not publish real target data, screenshots, tokens, cookies, payload bundles, scan output, or report drafts.

## 8. Before Publishing Your Own Fork

```bash
python3 automation/check_vault.py
python3 -m pytest tests/test_public_skeleton.py -q
```

Review `docs/public-safety.md` before making any fork or derived repository public.
