#!/usr/bin/env bash
# check_hunter_quality.sh — bbflow self-evolution BACKWARD edge (advisory).
#
# Forward edge (KB pattern → new nuclei template) already exists via
# pull_nuclei_gaps.sh. This is the missing backward edge: aggregate the persisted
# HUNTERS_REPORT corpus and surface per-hunter HIT-RATE + YIELD so low-value /
# noisy hunters can be tuned or retired — by human judgement, in the standalone
# bbflow repo. It NEVER mutates hunters (a miss can be environmental, not bad).
#
# Corpus: $WORKSHOP_ROOT/*/HUNTERS_REPORT_*.md  (format: `## <hunter>` sections,
#         `- (no hits ...)` = miss, `- <candidate>` lines = hits).
#
# Usage:
#   bash automation/check_hunter_quality.sh            # full report
#   bash automation/check_hunter_quality.sh --json     # machine-readable
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
eval "$("$SCRIPT_DIR/workspace_layout.sh" --shell)"
BBFLOW_HUNTERS="${BBFLOW_DIR:-$PROJECT_ROOT/../bbflow}/hunters"

JSON=0; [ "${1:-}" = "--json" ] && JSON=1

python3 - "$WORKSHOP_ROOT" "$BBFLOW_HUNTERS" "$JSON" <<'PY'
import os, re, sys, glob, json

workshop, hunters_dir, as_json = sys.argv[1], sys.argv[2], sys.argv[3] == "1"

reports = glob.glob(os.path.join(workshop, "*", "HUNTERS_REPORT_*.md"))
stats = {}   # hunter -> {runs, hits, cands}
MISS = re.compile(r"^\-\s*\(no hits", re.I)

for rp in reports:
    try:
        txt = open(rp, encoding="utf-8", errors="replace").read()
    except Exception:
        continue
    # split into `## <hunter>` sections
    parts = re.split(r"^##\s+([a-z0-9\-]+)\s*$", txt, flags=re.M)
    # parts = [preamble, name1, body1, name2, body2, ...]
    for i in range(1, len(parts), 2):
        name = parts[i].strip()
        body = parts[i + 1] if i + 1 < len(parts) else ""
        lines = [l for l in body.splitlines() if l.strip().startswith("- ")]
        miss = (not lines) or any(MISS.match(l.strip()) for l in lines)
        cand = 0 if miss else len(lines)
        s = stats.setdefault(name, {"runs": 0, "hits": 0, "cands": 0})
        s["runs"] += 1
        if cand:
            s["hits"] += 1
            s["cands"] += cand

# canonical hunters that never appear in any report (never run / alias drift)
canon = set()
if os.path.isdir(hunters_dir):
    for f in glob.glob(os.path.join(hunters_dir, "hunt-*.sh")):
        canon.add(os.path.basename(f)[5:-3])  # strip hunt- / .sh

rows = []
for name, s in stats.items():
    hr = s["hits"] / s["runs"] if s["runs"] else 0.0
    avg = s["cands"] / s["hits"] if s["hits"] else 0.0
    rows.append((name, s["runs"], s["hits"], hr, s["cands"], avg))
rows.sort(key=lambda r: (r[3], r[4]))   # worst hit-rate first

if as_json:
    print(json.dumps({
        "reports": len(reports),
        "hunters": [
            {"hunter": n, "runs": ru, "runs_with_hits": h,
             "hit_rate": round(hr, 3), "total_candidates": c, "avg_per_hit": round(av, 1)}
            for (n, ru, h, hr, c, av) in rows
        ],
    }, ensure_ascii=False, indent=2))
    sys.exit(0)

print(f"── bbflow hunter quality (backward edge) ──")
print(f"   corpus: {len(reports)} HUNTERS_REPORT across {len(set(os.path.basename(os.path.dirname(r)) for r in reports))} targets\n")

DEAD = [r for r in rows if r[1] >= 5 and r[2] == 0]          # >=5 runs, 0 hits
# noisy: high total yield AND high avg-per-hit (mass output = FP-prone, needs ownership/catch-all scrutiny)
NOISY = sorted([r for r in rows if r[4] >= 30 and r[5] >= 8], key=lambda r: -r[4])

print(f"{'hunter':<26} {'runs':>4} {'hit%':>5} {'cands':>6} {'avg/hit':>8}")
for (n, ru, h, hr, c, av) in rows:
    print(f"{n:<26} {ru:>4} {int(hr*100):>4}% {c:>6} {av:>8.1f}")

if DEAD:
    print(f"\n⚠ DEAD WEIGHT (≥5 runs, 0 hits — retire/tune candidate in bbflow):")
    for (n, ru, *_ ) in DEAD:
        print(f"   - {n} ({ru} runs, never hit)")
if NOISY:
    print(f"\n⚠ NOISY (mass output — verify not catch-all / unowned before trusting):")
    for (n, ru, h, hr, c, av) in NOISY:
        print(f"   - {n}: {c} candidates over {h} hitting runs (avg {av:.0f}/run)")
    print("     (mass-output hunters are FP-prone: e.g. cloud-bucket LISTABLE≠owned,")
    print("      email-security = SPF/DMARC info, open-redirect = unverified reflections)")

# alias drift / never-run: canonical hunters whose label never appears
seen = set(stats.keys())
ALIAS = {"cors-reflect":"cors","user-enum":"userenum","hardcoded-js-secrets":"js-secrets",
         "wayback-endpoints":"wayback","sourcemap-secrets":"sourcemap","graphql-idor":"graphql",
         "sourcemap-endpoint-family":"sourcemap-family"}
never = [c for c in sorted(canon) if c not in seen and ALIAS.get(c) not in seen]
if never:
    print(f"\nℹ canonical hunters never seen in corpus ({len(never)} — never run, or alias drift):")
    print("   " + ", ".join(never))

print(f"\nAdvisory only — tune/retire in the standalone bbflow repo (human judgement;")
print(f"a miss may be environmental). Forward edge: bash automation/pull_nuclei_gaps.sh")
PY
