---
type: checklist
title: Checklist - Screenshot Pipeline Last Mile
tags: [checklist, workflow, screenshot, evidence, chrome-headless, submission, bb-checklist]
status: verified
first_seen: 2026-05-18
last_updated: 2026-05-18
category: Checklist
precedents: 8 HITCON FORMs — all went from HARD BLOCK to ready in single session
---

# Checklist - Screenshot Pipeline Last Mile

## TL;DR

Screenshot preparation is the #1 submission bottleneck. Use **Chrome headless batch pipeline** to convert verification commands into styled evidence PNGs in minutes, not hours.

## The bottleneck

| Phase | Time spent | Value added |
|-------|-----------|-------------|
| Finding the vulnerability | Hours | High |
| Writing the FORM | 30-60 min | Medium |
| **Getting screenshot evidence** | **Often blocks for days** | **Gate to submission** |

HITCON ZeroDay enforces mandatory image upload — no screenshot = cannot submit. A finding sitting "ready" for weeks because of missing screenshots is lost bounty velocity.

## Pipeline: Command → HTML → PNG

### Step 1: Run verification commands, capture output

```bash
# Run curl/dig/nmap and save raw output
curl -sD- "https://TARGET/endpoint" > /tmp/evidence-raw.txt
```

### Step 2: Build styled HTML evidence page

```html
<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>
  body { background: #1a1a2e; color: #e0e0e0; font-family: 'SF Mono', monospace;
         padding: 40px; max-width: 1100px; margin: auto; }
  h1 { color: #ff6b6b; border-bottom: 2px solid #ff6b6b; padding-bottom: 10px; }
  h2 { color: #4ecdc4; margin-top: 30px; }
  .cmd { color: #ffd93d; }           /* command = yellow */
  .pass { color: #6bcb77; }          /* pass = green */
  .fail { color: #ff6b6b; }          /* fail = red */
  .info { color: #4ecdc4; }          /* info = cyan */
  pre { background: #16213e; padding: 15px; border-radius: 8px;
        overflow-x: auto; line-height: 1.5; }
  table { border-collapse: collapse; width: 100%; margin: 20px 0; }
  th, td { border: 1px solid #333; padding: 8px 12px; text-align: left; }
  th { background: #16213e; color: #4ecdc4; }
  .summary { background: #16213e; padding: 20px; border-radius: 8px;
             border-left: 4px solid #ff6b6b; margin: 20px 0; }
</style></head>
<body>
<h1>Finding-ID — Title</h1>
<p>Verified: 2026-XX-XX | Target: example.com | Platform: macOS</p>

<h2>1. Verification Command</h2>
<pre><span class="cmd">$ curl -sD- https://target/endpoint</span>

<span class="fail">HTTP/1.1 200 OK
Access-Control-Allow-Origin: *</span></pre>

<h2>Summary</h2>
<div class="summary">
  <span class="fail">&#x274C;</span> Vulnerability confirmed — CORS wildcard allows cross-origin access
</div>
</body></html>
```

### Step 3: Serve and capture

```bash
# Serve HTML (background)
cd /tmp/evidence-screenshots && python3 -m http.server 8889 &

# Chrome headless screenshot
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --headless=new \
  --screenshot="/tmp/output.png" \
  --window-size=1200,900 \
  "http://localhost:8889/evidence.html"

# Copy to Vault
cp /tmp/output.png "01 - Targets/<target>/Screenshots/FINDING-ID-evidence-macOS.png"
```

### Step 4: Update FORM

```markdown
# In FORM frontmatter:
needs_screenshots: false   # was: true

# In screenshot section:
| # | 檔名 | 內容 |
|---|------|------|
| 1 | FINDING-ID-evidence-macOS.png | 驗證結果摘要 |
```

## Batch processing (8+ findings)

```bash
# Generate all HTML files first
for id in 002 003 008 009 017 018 019 020; do
  # Build HTML for each finding (script or manual)
  generate_evidence_html "JK-${id}" > "/tmp/screenshots/jk${id}-evidence.html"
done

# Start server once
cd /tmp/screenshots && python3 -m http.server 8889 &

# Batch screenshot
for id in 002 003 008 009 017 018 019 020; do
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
    --headless=new \
    --screenshot="/tmp/screenshots/JK-${id}-evidence-macOS.png" \
    --window-size=1200,900 \
    "http://localhost:8889/jk${id}-evidence.html"
done

# Batch copy to Vault
cp /tmp/screenshots/JK-*-evidence-macOS.png \
   "01 - Targets/<target>/Screenshots/"
```

## Key lessons

1. **HTML > raw terminal screenshot**: Styled HTML with color coding is clearer than a terminal screenshot with wall-of-text
2. **Re-verification built in**: Building the evidence page forces you to re-run commands, confirming the vuln is still live
3. **Batch = multiplicative**: 8 findings × 30min each = 4 hours individually; batch pipeline = 45 minutes total
4. **Dark theme**: Matches security audience expectations, high contrast, professional
5. **Chrome headless reliability**: Unlike MCP screenshot tools, `--headless=new --screenshot=path` writes directly to disk — no intermediate ID resolution needed

## Anti-patterns

| Don't | Do |
|-------|-----|
| Take OS-level terminal screenshots | Build styled HTML evidence pages |
| Screenshot one finding, then context-switch | Batch all findings in one pass |
| Leave `needs_screenshots: true` for "later" | Pipeline immediately after verification |
| Use browser MCP save_to_disk (unreliable path) | Use Chrome CLI `--screenshot=path` |

## Related

- [[Reference Card - HITCON ZeroDay Form]] — screenshot is mandatory field
- AGENTS.md §5 — verification grade definitions
