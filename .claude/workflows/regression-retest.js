export const meta = {
  name: 'regression-retest',
  description: 'Deterministic batch re-test of parked/waiting findings across targets. One safe-probe agent per target re-runs ONLY documented non-destructive checks, classifies still-vulnerable/patched/endpoint-gone/inconclusive, then one agent synthesizes prioritized status-update proposals. REPORTS only — never mutates the vault, never re-runs destructive PoCs.',
  phases: [
    { title: 'Retest', detail: 'one safe-probe agent per target: re-run documented GET-equivalent checks, classify each parked finding' },
    { title: 'Synthesize', detail: 'aggregate verdicts across all targets -> prioritized status-update proposals' },
  ],
}

// Adaptive hunting stays on sub-agents; mechanical batch (re-test N targets) goes to a workflow.
// Sub-agents do NOT inherit CLAUDE.md/AGENTS.md, so the safety contract is carried inline.
// Pass target names as args: Workflow({ name: 'regression-retest', args: ['acme', 'globex'] }).
// Each agent reads paths RELATIVE to the repo root (its cwd) — no hard-coded paths in this script.

const targets = (args || []).map(t => (typeof t === 'string' ? t : t && t.name)).filter(Boolean)
if (targets.length === 0) {
  return { error: "Pass target names as args, e.g. args: ['acme','globex']." }
}

// Hard safety contract — injected into every retest agent.
const RULES = [
  'HARD RULES (you are re-testing live third-party targets you are authorized to test):',
  '(1) SAFE-ONLY. Re-run ONLY the documented non-destructive / GET-equivalent probe. NEVER re-run a destructive PoC',
  '    (POST/PUT/PATCH/DELETE, anything that writes/changes/deletes state, sends payloads, or could disrupt service).',
  "    If a finding's only documented PoC is destructive, DO NOT execute it — classify it \"inconclusive\" and say why.",
  '(2) IN-SCOPE ONLY. Probe only the exact host/endpoint the finding already documents. Do not enumerate new hosts.',
  '(3) EVIDENCE. Every verdict cites the finding file:line AND the concrete probe result (status / body signal).',
  '(4) HOST-GONE is a non-destructive 3-signal check only (DNS/NXDOMAIN + connect + cert) — never a takeover attempt.',
  '(5) Route outbound probes through your configured proxy/VPS if the target requires it, and honor static-only mode.',
  '(6) READ-ONLY on the vault: do not edit, write, commit, or move any file. Report verdicts back only.',
].join('\n')

const VERDICT_SCHEMA = {
  type: 'object',
  properties: {
    target: { type: 'string' },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          finding_id: { type: 'string' },
          endpoint: { type: 'string' },
          verdict: { type: 'string', enum: ['still-vulnerable', 'patched', 'endpoint-gone', 'inconclusive'] },
          evidence: { type: 'string' },
          proposed_status: { type: 'string' },
        },
        required: ['finding_id', 'verdict', 'evidence'],
      },
    },
    notes: { type: 'string' },
  },
  required: ['target', 'findings'],
}

function retestPrompt(target) {
  return [
    `Re-test the PARKED / waiting-triage / resolved findings for target "${target}".`,
    '',
    RULES,
    '',
    'STEPS (read paths relative to the repo root — your cwd):',
    `1. Read "01 - Targets/${target}/FINDINGS_QUICK_REF.md" and "01 - Targets/${target}/RECON_DB.md" to list findings whose`,
    '   status is parked / waiting-triage / resolved / needs-verification, with their documented endpoint + PoC.',
    '2. For each, run ONLY the safe documented probe (a GET, or the 3-signal HOST-GONE check). Classify:',
    '   still-vulnerable | patched | endpoint-gone | inconclusive.',
    '',
    'Return the structured verdict list. Do NOT paste raw HTTP bodies — one-line evidence per finding (status + signal + file:line).',
  ].join('\n')
}

phase('Retest')
// Barrier: synthesis needs ALL targets' verdicts together, so collect them before synthesizing.
const perTarget = (await parallel(
  targets.map(t => () => agent(retestPrompt(t), { label: `retest:${t}`, phase: 'Retest', schema: VERDICT_SCHEMA, agentType: 'general-purpose' })),
)).filter(Boolean)

const flat = perTarget.flatMap(r => (r.findings || []).map(f => ({ ...f, target: r.target })))
log(`retested ${flat.length} finding(s) across ${perTarget.length}/${targets.length} target(s)`)
if (flat.length === 0) {
  return { retested: 0, targets, note: 'No parked/waiting findings found, or all agents returned empty. Check the FINDINGS_QUICK_REF paths.' }
}

phase('Synthesize')
const synthesis = await agent(
  [
    'You are the regression synthesis step. Below are re-test verdicts across several targets (JSON).',
    'Produce a PRIORITIZED, human-readable status-update proposal. REPORT ONLY — propose, do not mutate anything.',
    '',
    'Group by action, most urgent first:',
    '- still-vulnerable -> propose re-notify / escalate (vendor never fixed); flag if a submitted report should be bumped.',
    '- endpoint-gone -> propose HOST-GONE close (cite the 3-signal evidence).',
    '- patched -> propose close-as-resolved (verify the fix held; note any variant/bypass worth a follow-up test).',
    '- inconclusive -> say exactly what blocked it (destructive-only PoC, needs account, needs VPS) and the next safe step.',
    '',
    'For each item: `target - finding_id - verdict - one-line evidence - proposed status/action`.',
    'End with a 3-line summary: counts per verdict + the single highest-priority action.',
    '',
    'VERDICTS:',
    JSON.stringify(flat, null, 2),
  ].join('\n'),
  { label: 'synthesize', phase: 'Synthesize' },
)

return { retested: flat.length, targets: perTarget.map(r => r.target), report: synthesis }
