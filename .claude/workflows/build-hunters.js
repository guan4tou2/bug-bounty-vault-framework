export const meta = {
  name: 'build-hunters',
  description: 'Drain the Experience→Tool backlog: read the not-yet-drafted entries, author each into its target format (nuclei template → your scanner repo, e.g. 05 - Tools/hunters/nuclei/; RE/recon script → hunters/re/), then run the local lifecycle gates it can (nuclei -validate + example.com null-case). Output is a DRAFT — canary + FP-review + promote need a live target and stay manual. Grows a living scanner from hunting experience. Portable artifacts, no infra coupling.',
  phases: [
    { title: 'Read', detail: 'parse the backlog → entries not yet drafted/promoted' },
    { title: 'Author', detail: 'one agent per entry: dedup check → author → nuclei -validate → example.com null-case' },
    { title: 'Report', detail: 'summary + which drafts passed validate+null-case (ready for a human canary)' },
  ],
}

// Drains 05 - Tools/Backlog - Experience to Tool.md. Only mechanizable patterns become tools;
// judgment-needed ones stay in KB/DT. Home = your scanner repo (this seed uses 05 - Tools/hunters/;
// point it at a standalone nuclei-templates/hunters repo if you keep one). Sub-agents don't inherit
// CLAUDE.md, so rules are injected inline. Args (optional): { only: ['H-002', ...] }.
const only = (args && Array.isArray(args.only)) ? args.only : null
const HOME = 'the scanner repo (this seed: 05 - Tools/hunters/nuclei/ for templates, 05 - Tools/hunters/re/ for scripts)'

const RULES = [
  'HARD RULES (authoring a portable detection artifact from a learned pattern):',
  '(1) PORTABLE, NO INFRA COUPLING: the artifact must run locally (nuclei / a plain script). No environment-specific paths or services.',
  '(2) SANITIZE: no target-specific host, token, cookie, customer name, or private endpoint in the artifact.',
  '(3) SPLIT: only mechanizable (rule-detectable) patterns become tools. If the entry really needs semantic judgment, do NOT author — flag it to stay in KB/DT.',
  '(4) LIFECYCLE: for a nuclei template run BOTH `nuclei -validate -t <file>` AND a null-case `nuclei -t <file> -u https://example.com` (must yield NO hit). Pass only if validate ok AND null-case clean. Prefer a matcher specific enough to avoid false positives (a discriminating signature, not a generic word). This is a DRAFT: do NOT canary against real targets, do NOT mark promoted — that stays manual.',
  `(5) HOME + NAMING: write into ${HOME}. slug = kebab-case tied to the source pattern. Set metadata.source-pattern + metadata.lifecycle "validate+null-case OK; canary+FP pending" (nuclei) / a header comment (script) pointing back to the KB pattern.`,
  '(6) DEDUP FIRST: before authoring, check for an equivalent detection so you do not dilute the set. (a) grep your existing templates for the same signature/tags; (b) check the nuclei community set (`nuclei -tl -tags <tag>`). If an equivalent exists, do NOT author — set authored=false with skip_reason="already covered by <template>".',
].join('\n')

// ---------------------------------------------------------------- Read
phase('Read')
const READ_SCHEMA = {
  type: 'object',
  properties: {
    entries: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          catches: { type: 'string' },
          domain: { type: 'string' },
          signal: { type: 'string' },
          format: { type: 'string' },
          source: { type: 'string' },
          status: { type: 'string' },
        },
        required: ['id', 'catches', 'domain', 'format'],
      },
    },
  },
  required: ['entries'],
}
const parsed = await agent(
  [
    'Read the file "05 - Tools/Backlog - Experience to Tool.md" (use Read/grep).',
    'Return every backlog table row whose status is NOT already promoted/deployed (i.e. idea / draft / authored).',
    only ? `Restrict to these ids only: ${only.join(', ')}.` : 'Return all not-yet-promoted rows.',
    'REPORT ONLY — do not modify the file. Parse id / what-it-catches / domain / signal / target-format / source / status.',
  ].join('\n'),
  { label: 'read-backlog', phase: 'Read', schema: READ_SCHEMA, agentType: 'general-purpose' },
)
const entries = (parsed && parsed.entries || []).filter(e => !/promot|deploy/i.test(e.status || ''))
log(`${entries.length} backlog entr(ies) to drain`)
if (entries.length === 0) return { drained: 0, note: 'Backlog has no not-yet-promoted entries. Nothing to build.' }

// ---------------------------------------------------------------- Author
const AUTHOR_SCHEMA = {
  type: 'object',
  properties: {
    id: { type: 'string' },
    slug: { type: 'string' },
    path: { type: 'string' },
    validated: { type: 'boolean' },              // validate + null-case both passed
    authored: { type: 'boolean' },
    skip_reason: { type: 'string' },
    note: { type: 'string' },
  },
  required: ['id', 'authored'],
}
function authorPrompt(e) {
  return [
    `Author a detection artifact for backlog entry ${e.id}.`,
    `Catches: ${e.catches}`,
    `Domain: ${e.domain} · target format: ${e.format} · signal: ${e.signal || '(see source)'} · source: ${e.source || ''}`,
    '',
    'Read the source KB pattern first (grep 09 - Knowledge Base) so the artifact is faithful to the real technique.',
    'Then run the DEDUP check (rule 6) — if an equivalent detection already exists, skip instead of duplicating.',
    '',
    RULES,
    '',
    'Then: write the artifact to the correct path, run `nuclei -validate` AND the example.com null-case,',
    'and report validated=true only if both pass. If the entry actually needs semantic judgment, do NOT author:',
    'set authored=false with a skip_reason. Return the structured result.',
  ].join('\n')
}
phase('Author')
const built = (await parallel(
  entries.map(e => () => agent(authorPrompt(e), { label: `author:${e.id}`, phase: 'Author', schema: AUTHOR_SCHEMA, agentType: 'general-purpose' })),
)).filter(Boolean)

const ready = built.filter(b => b.authored && b.validated)
const skipped = built.filter(b => !b.authored)
log(`authored ${built.filter(b => b.authored).length} · validate+null-case ${ready.length} · skipped ${skipped.length}`)

// ---------------------------------------------------------------- Report
phase('Report')
const report = await agent(
  [
    'You are the drain-report step. Below are the results of authoring detection artifacts from the backlog (JSON).',
    'Produce a concise operator report. REPORT ONLY — do NOT edit the backlog file yourself.',
    '',
    '1. DRAFTS READY FOR CANARY: written + validate + null-case passed → propose status "validate+null-case OK, canary pending" (id → path). Do NOT call these deployed/promoted — a human runs the scoped canary + FP-review before promote.',
    '2. AUTHORED BUT FAILED validate/null-case → what to fix.',
    '3. SKIPPED (needs judgment / already covered): with the reason.',
    'End with one line: "draft-ready N · needs-fix M · skipped K". Promotion into the default auto-run set stays manual.',
    '',
    'RESULTS:',
    JSON.stringify(built, null, 2),
  ].join('\n'),
  { label: 'drain-report', phase: 'Report' },
)

return {
  drained: entries.length,
  draft_ready_for_canary: ready.map(b => ({ id: b.id, path: b.path })),
  skipped: skipped.map(b => ({ id: b.id, reason: b.skip_reason || 'unspecified' })),
  report,
}
