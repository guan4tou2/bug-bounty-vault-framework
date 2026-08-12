---
type: wiki
category: tool
tool: burp,caido
status: active
last-updated: 2026-04-21
---

# Tool: Burp Suite + Caido (Manual Proxy)

> **Purpose:** The **final manual mile** after all the automated tools are done. Burp is the industry standard; Caido is an open-source alternative (free, lightweight).

## Comparison

| Feature | Burp Community | Burp Pro | Caido |
|------|---------------|----------|-------|
| Price | Free | ~$500/year | Free + optional pro tier |
| Repeater | Yes | Yes | Yes (Replay) |
| Intruder | Rate-limited | Yes, unlimited | Yes (Automate) |
| Scanner | No | Yes | No (use an external tool) |
| Extensions | Yes (BApp Store) | Yes | Yes (Plugins) |
| Platform | Java (slow) | Java | Native (fast) |
| Team collaboration | No | No | Yes (Collab) |

**Recommendation:** Use Caido for solo work (fast, free); use Burp Pro at a company.

## Burp basic setup

### 1. Download + install

```bash
# Burp Community
# https://portswigger.net/burp/communitydownload

# macOS brew cask
brew install --cask burp-suite
```

### 2. Start the proxy (default 127.0.0.1:8080)

### 3. Browser proxy

- Firefox: Options → Network Settings → Manual Proxy → 127.0.0.1:8080
- Or use the FoxyProxy extension

### 4. Install the Burp CA certificate

```bash
# Download the CA from http://burp
# Import it into the browser as a trusted CA
```

### 5. Recommended extensions (BApp Store)

| Extension | Purpose |
|-----------|------|
| Logger++ | Better logging |
| Turbo Intruder | Very high-speed attacks |
| Autorize | Automated IDOR testing |
| Hackvertor | Payload encoding |
| Copy as Python-Requests | Convert a request into Python |
| Param Miner | Hidden param fuzzing |
| Collaborator Everywhere | Automatic OAST injection |
| Active Scan++ | Enhanced scanning |
| Backslash Powered Scanner | Finds anomalies |
| J2EE Scan | J2EE-specific |

## Caido basic setup

### 1. Download + install

```bash
# https://caido.io/download
# Linux AppImage / macOS dmg / Windows msi
```

### 2. Start

```bash
caido server  # CLI mode
# or open the GUI app
```

### 3. Point browser proxy to 127.0.0.1:8080 (default)

### 4. Import the Burp CA (Caido uses the same format)

## Core workflows

### Workflow 1: Manually verify a nuclei finding

```
1. nuclei finds XSS at https://target/search?q=...
2. Locate this request in Burp Proxy history (or browse to it manually once)
3. Send to Repeater
4. Manually tune the payload:
   - Try different encodings
   - Try CSP bypasses
   - Try WAF bypasses
5. Confirm it actually executes in a real browser (screenshot)
```

### Workflow 2: Intruder brute force

```
1. Grab a POST login request
2. Send to Intruder
3. Mark the password field as a position
4. Payload → wordlist
5. Start attack → check the Length column for differences
6. A response with a different length = likely correct password
```

### Workflow 3: Batch IDOR testing

```
1. Log in as user A, send a request to /api/user/:id
2. Send to Repeater
3. Swap the Cookie for user B's
4. Try the same id and see if you can view A's data
5. Use Intruder to fuzz a range of ids
```

### Workflow 4: GraphQL introspection

```
1. Find the /graphql endpoint
2. Send an introspection query via Repeater
3. Find sensitive mutations in the schema
4. Try unauthorized mutations
5. Integrate with Param Miner / a CODE plugin
```

## Recommended shortcuts

### Burp

| Action | Shortcut |
|------|------|
| Send to Repeater | `Ctrl+R` / `Cmd+R` |
| Send to Intruder | `Ctrl+I` |
| Copy URL | `Ctrl+U` |
| Forward request | `Ctrl+F` |
| Drop | `Ctrl+D` |

### Caido

| Action | Shortcut |
|------|------|
| Send to Replay | `Ctrl+R` |
| Send to Automate | `Ctrl+I` |
| Forward | `F` |

## Integration with bbflow

bbflow handles automation; Burp/Caido is for manual verification:

```bash
# 1. bbflow runs its hunters and produces candidates
bbflow hunt target

# 2. Open the candidate URLs in Burp (or import directly into Burp)
# 3. Manually confirm via Repeater
# 4. Grab a curl command and write it up in the report
```

### Converting curl to a Burp request

Burp has "Copy as curl command"; the reverse direction is manual:

```bash
# Say nuclei found this URL
URL="https://target.com/api/v1/secret?id=1"
curl -v "$URL" -H "Authorization: Bearer xxx" > out.txt 2>&1

# Paste the request portion of the -v output into Burp Repeater
```

### Routing Burp's proxy as a relay (bbflow tool → Burp → target)

```bash
# Route nuclei's traffic through Burp for visibility
nuclei -u target -proxy http://127.0.0.1:8080

# Route sqlmap through Burp
sqlmap -u target --proxy=http://127.0.0.1:8080

# Route ffuf through Burp
ffuf -u target/FUZZ -w words.txt -replay-proxy http://127.0.0.1:8080
```

## Common scenarios

### Scenario A: Found an endpoint only accessible after login

1. Log in once via Burp (capture the entire flow)
2. Save Item on a particular request as a request file
3. `sqlmap -r request.txt --batch`

### Scenario B: JWT testing

1. Burp extension: **JWT Editor**
2. Decode the JWT
3. Try `alg=none` / change `role=admin`
4. Modify the token directly in Repeater and send

### Scenario C: CORS testing

```
Add Origin: https://evil.com to the request
Check the response's Access-Control-Allow-Origin

If it echoes https://evil.com → reflective CORS
If it returns null → usable via a sandboxed iframe / data: URL
```

### Scenario D: Open Redirect testing

```
Use Repeater to modify the redirect param:
?redirect=https://evil.com
?redirect=//evil.com
?redirect=/\evil.com
?redirect=javascript:alert(1)
?redirect=%2f%2fevil.com
```

## Payload dictionaries (built into Burp Intruder)

Intruder → Payloads → Type:

- Simple list
- Runtime file (external wordlist)
- Numbers (numeric ranges, for IDOR)
- Dates
- Brute forcer (combinatorial)
- Null payloads (test empty values)
- **Recursive grep** (extract a value from the response and feed it back in)

## Notes

### Burp Community rate limiting

- Intruder is limited to 1 thread, roughly 1 req/s
- Not practical for brute forcing → use ffuf / hydra instead

### Burp Scanner is Pro-only

- Use external nuclei instead
- Or manually run Burp's Active Scan (Pro)

### Caido Automate as the Intruder equivalent

- No speed limit on the free tier
- But a smaller extension ecosystem

## Related documents

- [00-bbflow-complete-flow.md](00-bbflow-complete-flow.md)
- [40-checklist-new-target.md](40-checklist-new-target.md)
- [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md)
