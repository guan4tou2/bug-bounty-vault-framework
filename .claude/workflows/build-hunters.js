export const meta = {
  name: 'build-hunters',
  description: 'Drain the Experience→Tool backlog: read the non-deployed entries, author each into its target format (nuclei template / RE script), validate locally (nuclei -validate), write it under 05 - Tools/hunters/, and report which entries are ready to flip to deployed. Grows the living scanner from hunting experience. Portable artifacts, no VPS.',
  phases: [
    { title: 'Read', detail: 'parse the backlog → non-deployed entries (idea/authored)' },
    { title: 'Author', detail: 'one agent per entry: author artifact in its format + validate locally + write to hunters/' },
    { title: 'Report', detail: 'summary + proposed backlog status flips (idea→deployed) for operator to confirm' },
  ],
}

// Drains 05 - Tools/Backlog - Experience to Tool.md. Only mechanizable patterns become tools;
// judgment-needed ones stay in KB/DT (the backlog already excludes them). Sub-agents don't inherit
// CLAUDE.md, so rules are injected inline. Args (optional): { only: ['H-002', ...] } to drain
// specific ids; otherwise all non-deployed entries.
const only = (args && Array.isArray(args.only)) ? args.only : null

const RULES = [
  'HARD RULES (authoring a portable detection artifact from a learned pattern):',
  '(1) PORTABLE, NO VPS: the artifact must run locally (nuclei / a plain script). No VPS-specific paths or services.',
  '(2) SANITIZE: no target-specific host, token, cookie, customer name, or private endpoint in the artifact.',
  '(3) SPLIT: only mechanizable (rule-detectable) patterns become tools. If the entry really needs semantic judgment, do NOT author — flag it to stay in KB/DT.',
  '(4) TEST: for a nuclei template, run `nuclei -validate -t <file>` and only pass if it validates. Prefer a matcher specific enough to avoid false positives (a discriminating signature, not a generic word).',
  '(5) NAMING: slug = kebab-case tied to the source pattern; nuclei → 05 - Tools/hunters/nuclei/<slug>.yaml ; RE/script → 05 - Tools/hunters/re/<slug>.<ext>. Set metadata.source-pattern (nuclei) / a header comment (script) pointing back to the KB pattern.',
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
          catches: { type: 'string' },          // what the pattern detects
          domain: { type: 'string' },            // web|firmware|mobile|infra
          signal: { type: 'string' },            // the mechanizable signal
          format: { type: 'string' },            // nuclei-template | bbflow-hunter | re-script | ...
          source: { type: 'string' },            // KB pattern / finding / LL
          status: { type: 'string' },            // idea | authored (never deployed here)
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
    'Return every backlog table row whose status is NOT already "deployed" (i.e. status idea or authored).',
    only ? `Restrict to these ids only: ${only.join(', ')}.` : 'Return all non-deployed rows.',
    'REPORT ONLY — do not modify the file. Parse the id / what-it-catches / domain / signal / target-format / source / status columns.',
  ].join('\n'),
  { label: 'read-backlog', phase: 'Read', schema: READ_SCHEMA, agentType: 'general-purpose' },
)
const entries = (parsed && parsed.entries || []).filter(e => (e.status || 'idea') !== 'deployed')
log(`${entries.length} non-deployed backlog entr(ies) to drain`)
if (entries.length === 0) return { drained: 0, note: 'Backlog has no non-deployed entries. Nothing to build.' }

// ---------------------------------------------------------------- Author (pipeline: author → self-check)
const AUTHOR_SCHEMA = {
  type: 'object',
  properties: {
    id: { type: 'string' },
    slug: { type: 'string' },
    path: { type: 'string' },                    // where the artifact was written
    validated: { type: 'boolean' },              // nuclei -validate passed (or n/a script self-check ok)
    authored: { type: 'boolean' },               // file written
    skip_reason: { type: 'string' },             // set if NOT authored (e.g. needs-judgment)
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
    'Read the source KB pattern first (grep 09 - Knowledge Base for it) so the artifact is faithful to the real technique.',
    '',
    RULES,
    '',
    'Then: write the artifact to the correct hunters/ path, and (for a nuclei template) run',
    '`nuclei -validate -t "<the file>"` — report validated=true only if it passes. If the entry actually needs',
    'semantic judgment and cannot be a sound mechanical rule, do NOT author it: set authored=false with a skip_reason.',
    'Return the structured result.',
  ].join('\n')
}
phase('Author')
const built = (await parallel(
  entries.map(e => () => agent(authorPrompt(e), { label: `author:${e.id}`, phase: 'Author', schema: AUTHOR_SCHEMA, agentType: 'general-purpose' })),
)).filter(Boolean)

const ready = built.filter(b => b.authored && b.validated)
const skipped = built.filter(b => !b.authored)
log(`authored ${built.filter(b => b.authored).length} · validated ${ready.length} · skipped ${skipped.length}`)

// ---------------------------------------------------------------- Report
phase('Report')
const report = await agent(
  [
    'You are the drain-report step. Below are the results of authoring detection artifacts from the backlog (JSON).',
    'Produce a concise operator report. REPORT ONLY — do NOT edit the backlog file yourself.',
    '',
    '1. READY TO DEPLOY: artifacts written + validated → propose flipping their backlog status idea→deployed (list id → path).',
    '2. AUTHORED BUT NOT VALIDATED: written but failed validation → what to fix.',
    '3. SKIPPED (needs judgment): entries that should stay in KB/DT, with the reason.',
    'End with one line: "ready N · needs-fix M · skipped K". The operator confirms the status flips.',
    '',
    'RESULTS:',
    JSON.stringify(built, null, 2),
  ].join('\n'),
  { label: 'drain-report', phase: 'Report' },
)

return {
  drained: entries.length,
  ready_to_deploy: ready.map(b => ({ id: b.id, path: b.path })),
  skipped: skipped.map(b => ({ id: b.id, reason: b.skip_reason || 'unspecified' })),
  report,
}
