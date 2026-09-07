export const meta = {
  name: 'subdomain-sweep',
  description: 'Sift a large subdomain set: fan out safe mechanical sweeps in batches (live/tech fingerprint + interest score + known-leak checks), then synthesize a ranked shortlist of the few worth deep-hunting. REPORT-only; safe GET-equivalent probes; never deep-hunts everything.',
  phases: [
    { title: 'Sweep', detail: 'one agent per batch of subdomains: live + fingerprint + interest score + known-leak checks' },
    { title: 'Rank', detail: 'aggregate → ranked shortlist + disposition suggestions' },
  ],
}

// Many subdomains = a SIFT problem, not a fleet problem. Batch mechanical sweep (this workflow)
// → then deep-hunt the top few interactively. Sub-agents do NOT inherit CLAUDE.md; safety inline.
// Args: a list of subdomains, e.g. Workflow({ name: 'subdomain-sweep', args: ['a.x.com','b.x.com', ...] }).

const subs = (args || []).map(s => (typeof s === 'string' ? s : s && s.host)).filter(Boolean)
if (subs.length === 0) {
  return { error: "Pass subdomains as args, e.g. args: ['a.x.com','b.x.com',...] (from recon: httpx/dnsx output)." }
}

// batch so we spawn ~a handful of agents, not one per subdomain
const BATCH = Math.max(8, Math.ceil(subs.length / 12))
const batches = []
for (let i = 0; i < subs.length; i += BATCH) batches.push(subs.slice(i, i + BATCH))
log(`${subs.length} subdomains → ${batches.length} batch(es) of ~${BATCH}`)

const RULES = [
  'HARD RULES (authorized recon sift over a subdomain set):',
  '(1) SAFE-ONLY: GET / HEAD-equivalent probes only. No payloads, no POST/PUT/DELETE, no fuzzing, no exploitation.',
  '(2) IN-SCOPE: only the subdomains listed in this prompt. Do not pivot to new hosts.',
  '(3) Route outbound probes through the configured proxy/VPS if required; honor static-only mode.',
  '(4) This is a SIFT, not a hunt: fingerprint + score + known-leak surface only; do NOT deep-test.',
].join('\n')

const SWEEP_SCHEMA = {
  type: 'object',
  properties: {
    results: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          host: { type: 'string' },
          live: { type: 'boolean' },
          status: { type: 'string' },
          tech: { type: 'string' },
          interest: { type: 'integer' },   // 0-100
          signals: { type: 'string' },       // e.g. "actuator exposed; login page; .git 404"
          verdict: { type: 'string', enum: ['deep-hunt', 'quick-look', 'noise', 'dead'] },
        },
        required: ['host', 'interest', 'verdict'],
      },
    },
  },
  required: ['results'],
}

function sweepPrompt(batch) {
  return [
    `Sweep this batch of subdomains (safe recon sift only):`,
    batch.map(h => `  - ${h}`).join('\n'),
    '',
    RULES,
    '',
    'For EACH host: httpx-style probe (live? status? server/tech fingerprint); a quick interest score 0-100',
    '(admin/api/oauth/graphql/upload/staging/dev signals raise it; CDN/redirect/parked lower it); and cheap',
    'known-leak surface checks (actuator / .git / .env / debug page / login) via safe GET only.',
    'Classify each: deep-hunt (high interest) | quick-look | noise (CDN/dup/parked) | dead (no resolve).',
    'Return the structured results. One-line `signals` per host; do NOT paste raw bodies.',
  ].join('\n')
}

phase('Sweep')
const swept = (await parallel(
  batches.map((b, i) => () => agent(sweepPrompt(b), { label: `sweep:batch-${i + 1}`, phase: 'Sweep', schema: SWEEP_SCHEMA, agentType: 'general-purpose' })),
)).filter(Boolean)

const all = swept.flatMap(r => r.results || [])
const deep = all.filter(r => r.verdict === 'deep-hunt').sort((a, b) => (b.interest || 0) - (a.interest || 0))
log(`swept ${all.length} hosts · ${deep.length} flagged deep-hunt`)
if (all.length === 0) return { swept: 0, note: 'No results — check the subdomain list / probe reachability.' }

phase('Rank')
const shortlist = await agent(
  [
    'You are the sift synthesis step. Below are mechanical sweep results over a subdomain set (JSON).',
    'Produce a PRIORITIZED shortlist for interactive deep-hunting. REPORT ONLY.',
    '',
    '1. Top deep-hunt targets (highest interest + interesting signals) — the few worth a human deep pass, with why.',
    '2. Quick-look bucket (worth a 5-min check).',
    '3. Noise/dead counts (so coverage is accounted for — do NOT silently drop them).',
    '4. Disposition suggestions: which hosts to mark covered/blocked/untested in the Attack Surface Graph.',
    'End with: "deep-hunt N · quick-look M · noise K · dead J" and the single highest-priority host.',
    '',
    'SWEEP RESULTS:',
    JSON.stringify(all, null, 2),
  ].join('\n'),
  { label: 'rank', phase: 'Rank' },
)

return { swept: all.length, deep_hunt: deep.map(r => r.host), report: shortlist }
