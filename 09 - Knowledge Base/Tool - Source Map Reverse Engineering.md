---
type: reference
title: Tool - Source Map Reverse Engineering
tags: [source-map, javascript, reverse-engineering, recon, webpack, vue, info-disclosure]
status: validated
last_updated: 2026-04-07
---

# Source Map Reverse Engineering -- Complete Tool Guide

> Source maps are mapping files that restore minified/bundled code back to original source.
> Correct attack flow: **Discover .map exposure -> Download -> Reverse restore -> Audit source code -> Find exploitable vulnerabilities -> Report only the vulnerability itself (not the source map)**

---

## Source Map Basics

### What is a Source Map

```
app.min.js          <- Production (obfuscated/minified)
app.min.js.map      <- Source Map (contains original source paths + mapping)
```

A source map contains:
- `sources`: Original file paths (e.g., `src/api/auth.js`)
- `sourcesContent`: Original source code content
- `mappings`: VLQ mapping from minified positions to original positions

### How to Confirm Source Map Existence

```bash
# Method 1: Directly try the .map path
curl -I https://target.com/static/js/app.xxx.js.map

# Method 2: Check if JS file has sourceMappingURL comment at the end
curl -s https://target.com/static/js/app.xxx.js | tail -5
# If //# sourceMappingURL=app.xxx.js.map -> confirmed exposed

# Method 3: Browser DevTools
# F12 -> Sources -> check if webpack:// directory tree appears on the left

# Method 4: Chrome Extension
# SourceDetector (auto-detect and download)
```

---

## Reverse Engineering Tool Comparison

| Tool | Install | Features | Best for |
|------|---------|----------|----------|
| **reverse-sourcemap** | `npm i -g reverse-sourcemap` | Simplest, restores directory structure | Quick batch restoration |
| **@sugarat/source-map-cli** | `npm i -g @sugarat/source-map-cli` | Supports HTTP direct reading, error location | Precise analysis of specific lines |
| **SourceDetector** | Chrome Extension | Auto-detect + download | Discovery phase |
| **source-map-tools** | npm | Programmatic API | Automation scripts |

---

## Tool 1: reverse-sourcemap (Most Common)

```bash
# Install
npm install --global reverse-sourcemap

# Restore entire source map
reverse-sourcemap -v app.xxx.js.map -o ./output

# Result: output/ directory with fully restored project structure
# src/
# +-- api/
# |   +-- auth.js       <- Contains API endpoints
# |   +-- user.js
# +-- components/
# +-- store/
#     +-- index.js      <- Contains token/state logic
```

---

## Tool 2: @sugarat/source-map-cli (Advanced)

```bash
# Install
npm i -g @sugarat/source-map-cli

# === parse command: locate error original position ===

# From HTTP JS file + line:column
smt parse https://target.com/static/js/app.js:24:17596

# Directly specify .map file
smt parse https://target.com/static/js/app.js.map:24:17596 -s

# Local file
smt parse /path/to/app.js -l 24 -c 17596

# Export results to directory
smt parse https://target.com/js/app.js:10:500 -o ./parsed_output

# === sources command: restore all original files ===

# From HTTP URL (auto-find .map)
smt sources https://target.com/static/js/app.js

# Directly specify .map
smt sources https://target.com/static/js/app.js.map -s

# Specify output directory
smt sources https://target.com/static/js/app.js -o ./src_output
```

**Option reference:**

| Option | Description |
|--------|-------------|
| `-s, --source-map` | Input is .map file rather than .js file |
| `-l, --line` | Specify line number |
| `-c, --column` | Specify column number |
| `-o, --output` | Output directory |
| `-n, --show-num` | Number of context lines to display (default 5) |

---

## Complete Attack Flow

### Step 1: Discover Source Maps

```bash
# Try from known JS files
for js in $(curl -s https://target.com | grep -oP 'src="[^"]+\.js"' | grep -oP '[^"]+\.js'); do
  curl -s -o /dev/null -w "%{http_code} $js.map\n" "https://target.com/$js.map"
done

# Use Burp intercept: check Network tab JS requests, right-click -> try .map path
# Use waybackurls to find historical .map files
echo "target.com" | waybackurls | grep "\.map$"
```

### Step 2: Download Source Maps

```bash
mkdir target_sourcemap && cd target_sourcemap
curl -O https://target.com/static/js/app.abc123.js.map
curl -O https://target.com/static/js/chunk-vendors.abc123.js.map
```

### Step 3: Reverse Restore

```bash
# Batch restore all .map files
for f in *.map; do
  reverse-sourcemap -v "$f" -o "./output/${f%.map}"
done
```

### Step 4: Audit Source Code (Key Step)

```bash
cd output

# Find API endpoints
grep -r "api\|endpoint\|http\|fetch\|axios" . | grep -v node_modules

# Find hardcoded keys/tokens
grep -rE "(api_key|apikey|secret|token|password|credential)" . --include="*.js" --include="*.ts"

# Find authentication logic
grep -r "auth\|login\|jwt\|bearer\|oauth" . --include="*.js" --include="*.ts"

# Find internal URLs / paths
grep -rE "https?://[a-z0-9.-]+(internal|dev|staging|admin)" .

# Find encryption logic
grep -r "encrypt\|decrypt\|AES\|RSA\|ECDH\|crypto" . --include="*.js"

# Find GraphQL schema
grep -r "query\|mutation\|gql\|graphql" . --include="*.js"

# Find email / accounts
grep -rE "[a-zA-Z0-9.]+@[a-zA-Z0-9.]+" .
```

### Step 5: Escalate to Exploitable Vulnerabilities

Findings from source maps -> attempt escalation:

| Discovery | Escalation Direction |
|-----------|---------------------|
| API endpoint | Test IDOR / unauthorized access |
| Hardcoded API key | Verify if active -> financial impact |
| Auth logic | Find bypass conditions (JWT alg:none, token format) |
| Internal URL | SSRF testing |
| GraphQL schema | Introspection + mutation testing |
| Email addresses | Account enumeration starting point |

**Only report the escalated vulnerability, not the source map itself (major programs will mark N/A)**

---

## Vue / Webpack Specific Techniques

Vue CLI projects generate source maps when not properly configured:

```bash
# Confirm if it's a Vue project (look at chunk naming pattern)
# chunk-vendors.xxx.js + app.xxx.js -> typical Vue CLI

# Restored directory typically has
src/
+-- main.js          <- entry point, contains router/store references
+-- router/index.js  <- all routes (including admin routes)
+-- store/index.js   <- Vuex state (contains token storage logic)
+-- api/             <- all API calls (endpoint goldmine)
+-- utils/crypto.js  <- encryption utilities (often has hardcoded keys)
```

**Find admin routes:**
```bash
grep -r "admin\|dashboard\|manage\|backend" output/src/router/
```

---

## Defenses (for remediation recommendations)

### Vue CLI / Create React App
```javascript
// .env.production
GENERATE_SOURCEMAP=false

// vue.config.js
module.exports = {
  productionSourceMap: false
}
```

### Webpack
```javascript
// webpack.config.js
module.exports = {
  devtool: false  // or 'hidden-source-map' (generates but doesn't expose URL)
}
```

### Nginx (Emergency Block)
```nginx
location ~* \.map$ {
    deny all;
    return 404;
}
```

---

## Related Notes

- [[Pattern - Source Map Exposure]]
- [[Resource - Client-Side Bugs]]
- [[Checklist - XSS Rat 2026]]
- [[Playbook - Recon Methodology]]
- [[Pattern - Git Exposure]]
