#!/usr/bin/env bash
# measure_context_intake.sh — quantify what enters MAIN context in real Claude Code sessions.
#
# The instrument for "measure -> converge -> refactor": re-run it to check whether your
# context-discipline mechanisms (delegation, the F5 inline-scan / F6 big-read gates, thin
# skills, sub-agent report contracts) actually move the numbers over time. Read-only; parses
# Claude Code transcript JSONL, prints a report. No private paths — resolves the transcript
# directory generically from the current repo (or BB_TRANSCRIPT_DIR).
#
# Reports, for the analysed sessions (main line only, via isSidechain):
#   - context composition: raw tool output % vs assistant text % vs thinking %
#   - by-tool breakdown of main-line tool_result chars (which tools flood context)
#   - DELEGATION RATIO = sub-agent-absorbed tool output / all tool output (higher = better)
#   - context bombs: single tool_results over the bomb threshold
#
# Usage:
#   bash automation/measure_context_intake.sh                 # 5 most-recent sessions
#   bash automation/measure_context_intake.sh --recent 10     # 10 most-recent (by mtime)
#   bash automation/measure_context_intake.sh --top 6         # 6 largest (by size)
#   bash automation/measure_context_intake.sh <file.jsonl>    # one specific transcript
# Env: BB_TRANSCRIPT_DIR  (override the transcript dir; default derives it from the repo path)
#      BB_BOMB_CHARS       (context-bomb threshold, default 40000)
set -uo pipefail

# Claude Code stores transcripts at ~/.claude/projects/<cwd-with-nonalnum-replaced-by-dash>/
if [ -n "${BB_TRANSCRIPT_DIR:-}" ]; then
  PROJ_DIR="$BB_TRANSCRIPT_DIR"
else
  PROJ_DIR="$HOME/.claude/projects/$(pwd | sed 's#[^a-zA-Z0-9]#-#g')"
fi
if [ ! -d "$PROJ_DIR" ]; then
  echo "measure_context_intake: transcript dir not found: $PROJ_DIR" >&2
  echo "  set BB_TRANSCRIPT_DIR to your Claude Code project transcript folder (~/.claude/projects/<...>)." >&2
  exit 1
fi

MODE="recent"; N=5; ONEFILE=""
case "${1:-}" in
  --recent) MODE="recent"; N="${2:-5}";;
  --top)    MODE="top";    N="${2:-5}";;
  "" )      : ;;
  * )       ONEFILE="$1";;
esac

export PROJ_DIR MODE N ONEFILE
python3 - <<'PY'
import json, glob, os, collections
PROJ = os.environ["PROJ_DIR"]; MODE = os.environ["MODE"]; N = int(os.environ["N"])
ONE = os.environ.get("ONEFILE") or ""
BOMB = int(os.environ.get("BB_BOMB_CHARS", "40000"))

if ONE:
    files = [ONE if os.path.isabs(ONE) else os.path.join(PROJ, ONE)]
else:
    allf = glob.glob(f"{PROJ}/*.jsonl")
    key = (os.path.getsize if MODE == "top" else os.path.getmtime)
    files = sorted(allf, key=lambda f: -key(f))[:N]
files = [f for f in files if os.path.isfile(f)]
if not files:
    print("no transcript files found under", PROJ); raise SystemExit(1)

def blk_len(b):
    if isinstance(b, str): return len(b)
    if isinstance(b, dict):
        c = b.get("content", b.get("text", ""))
        if isinstance(c, str): return len(c)
        if isinstance(c, list): return sum(blk_len(x) for x in c)
        return len(json.dumps(b, ensure_ascii=False))
    return 0

g_tool = collections.Counter(); g_txt = g_think = g_side = g_main = 0; bombs = []
for f in files:
    id2tool = {}
    with open(f, errors="replace") as fh:
        for line in fh:
            try: d = json.loads(line)
            except Exception: continue
            msg = d.get("message") or {}; content = msg.get("content"); side = d.get("isSidechain", False)
            if not isinstance(content, list): continue
            for b in content:
                if not isinstance(b, dict): continue
                bt = b.get("type")
                if bt == "tool_use": id2tool[b.get("id")] = b.get("name", "?")
                elif bt == "tool_result":
                    L = blk_len(b); tool = id2tool.get(b.get("tool_use_id"), "?")
                    if side: g_side += L
                    else:
                        g_tool[tool] += L; g_main += L
                        if L > BOMB: bombs.append((L, tool, os.path.basename(f)[:8]))
                elif bt == "text" and not side: g_txt += blk_len(b)
                elif bt == "thinking" and not side: g_think += blk_len(b)

tot = g_main + g_txt + g_think or 1
pct = lambda x: 100 * x // tot
print(f"=== Context Intake — {len(files)} session ({MODE} {N if not ONE else ''}) ===")
print(f"main-line tool output : {g_main:>12,}  ({pct(g_main)}%)")
print(f"main-line assistant   : {g_txt:>12,}  ({pct(g_txt)}%)")
print(f"main-line thinking    : {g_think:>12,}  ({pct(g_think)}%)")
deleg = 100 * g_side // max(g_side + g_main, 1)
bar = "#" * (deleg // 5)
print(f"\n* delegation ratio = sub-agent-absorbed / all tool = {deleg:>3}%  [{bar:<20}]  (higher = better)")
print(f"   sub-agent tool output (never hits main line): {g_side:,}")
print("\nmain-line tool output by tool (biggest flood sources):")
for tool, c in g_tool.most_common(10):
    print(f"  {c:>12,}  {100 * c // max(g_main, 1):>3}%  {tool}")
print(f"\ncontext bombs (single tool_result > {BOMB:,} chars): {len(bombs)}")
for L, tool, s in sorted(bombs, reverse=True)[:8]:
    print(f"  {L:>10,}  {tool:<26} [{s}]")
PY
