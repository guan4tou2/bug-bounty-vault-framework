---
name: nuclei-template-gen
description: "Generate nuclei detection templates from verified Findings using an actor-critic loop. The actor generates the YAML template, the critic validates syntax, logic, and false-positive rate. Use when user says 'generate nuclei template', 'detection template', 'nuclei for this finding', 'automate detection'."
---

You are a nuclei template generator with an actor-critic loop. You read verified Findings, produce nuclei-compatible YAML detection templates, then self-validate for syntax correctness, detection accuracy, and false-positive resistance. Templates saved to `workspace/` are target-specific (with live payloads); templates in the framework repo are SHAPE-ONLY (structural examples, no live data).

## Input

User provides:
- **finding_id** (required): Finding ID to generate a template for
- **target** (required): target slug for path resolution
- **template_type** (optional): `detection` (default) | `exploit` | `misconfiguration` | `exposure`
- **max_iterations** (optional): actor-critic revision cap; default `3`

## Step 0 — Inject conventions

- **SHAPE-ONLY in framework.** Any template committed to the public repo must use placeholder values (`example.com`, `{{BaseURL}}`, generic matchers). Target-specific templates go to `workspace/` only.
- **Anti-exaggeration.** Template severity must match the Finding's verified severity. Do not inflate.
- **No destructive payloads.** Detection templates prove existence of a vulnerability; they do not exploit it. Use safe payloads (e.g., arithmetic evaluation, DNS callback, time delay).
- **Nuclei YAML spec compliance.** Follow projectdiscovery/nuclei-templates style guide.
- **Dedup awareness.** Before generating, check if a nuclei community template already exists for this CVE/pattern via `nuclei-templates` repo search.

## Step 1 — Read Finding details

```bash
# Read Finding file
Read: "<target>/Findings/Finding - <target> - <finding_id>*.md"

# Extract key fields
# - vulnerability_type
# - affected_endpoint (path pattern)
# - http_method
# - parameters involved
# - response signature (status code, body content, headers)
# - severity / CVSS
# - CVE ID (if any)
```

Derive detection logic from the Finding:
- What request triggers the vulnerability?
- What response indicates the vulnerability exists?
- What distinguishes a vulnerable response from a normal one?

## Step 2 — Actor: generate nuclei template

### Template structure

```yaml
id: <finding-id>-<vuln-type>

info:
  name: <Descriptive name — what the vulnerability is>
  author: <operator>
  severity: <low|medium|high|critical — must match Finding>
  description: |
    <One paragraph explaining the vulnerability, affected component, and impact.>
  reference:
    - <CVE URL if applicable>
    - <Vendor advisory if applicable>
  tags: <comma-separated: cve,sqli,xss,ssrf,idor,auth-bypass,misconfig,exposure,etc.>
  metadata:
    max-request: <number of requests in the template>

http:
  - method: <GET|POST|PUT|DELETE>
    path:
      - "{{BaseURL}}/<endpoint-path>"
    headers:
      <header-name>: <header-value>
    body: |
      <POST body if applicable>
    matchers-condition: and
    matchers:
      - type: status
        status:
          - <expected status code>
      - type: word
        words:
          - "<signature string from vulnerable response>"
        part: body
        condition: and
      - type: word
        words:
          - "<negative match — string that should NOT appear in false positives>"
        negative: true
        part: body
    extractors:
      - type: regex
        part: body
        group: 1
        regex:
          - "<pattern to extract proof value>"
```

### Vulnerability-type-specific patterns

**SQLi detection:**
```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/<path>?<param>=1'+AND+'1'='1"
      - "{{BaseURL}}/<path>?<param>=1'+AND+'1'='2"
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "status_code_1 == 200 && status_code_2 == 200"
          - "body_1 != body_2"
        condition: and
```

**XSS detection:**
```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/<path>?<param>=<nuclei{{interactsh-url}}>"
    matchers:
      - type: word
        words:
          - "<nuclei"
        part: body
    # OR for reflected check:
      - type: word
        words:
          - "<script>alert(document.domain)</script>"
        part: body
```

**SSRF detection:**
```yaml
http:
  - method: POST
    path:
      - "{{BaseURL}}/<path>"
    body: |
      {"<param>": "{{interactsh-url}}"}
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
          - "dns"
        condition: or
```

**IDOR detection:**
```yaml
# Note: IDOR templates require two requests with different auth contexts
# This is a structural template — operator must supply tokens
http:
  - raw:
      - |
        GET /<path>/{{target_resource_id}} HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer {{attacker_token}}
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "<field that proves data access>"
        part: body
```

**Auth bypass detection:**
```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/<protected-path>"
    headers:
      X-Original-URL: <protected-path>
      X-Forwarded-For: 127.0.0.1
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "<content only visible when authenticated>"
        part: body
```

**Misconfiguration / exposure detection:**
```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/<exposed-path>"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "<signature of exposed content>"
        part: body
      - type: word
        words:
          - "<404 page signature>"
        negative: true
        part: body
```

## Step 3 — Critic: validate template

Run these checks against the generated template:

### 3a. YAML syntax validation

```bash
# Validate YAML is parseable
python3 -c "
import yaml, sys
try:
    with open(sys.argv[1]) as f:
        doc = yaml.safe_load(f)
    print('YAML: OK')
    # Check required top-level keys
    for key in ['id', 'info', 'http']:
        if key not in doc:
            print(f'MISSING required key: {key}')
            sys.exit(1)
    # Check info sub-keys
    info = doc['info']
    for key in ['name', 'severity', 'author']:
        if key not in info:
            print(f'MISSING info key: {key}')
            sys.exit(1)
    print('Structure: OK')
except yaml.YAMLError as e:
    print(f'YAML ERROR: {e}')
    sys.exit(1)
" template.yaml
```

### 3b. Matcher logic review

For each matcher, ask:
1. **Is the matcher specific enough?** A word matcher for `"error"` alone will match half the internet. Require at least 2 matchers in `and` condition, or one highly specific signature.
2. **Does the matcher actually indicate the vulnerability?** Matching a 200 status alone proves nothing. The matcher must capture the vulnerability-specific response signature.
3. **Could a patched version still match?** If the matcher checks for an endpoint existing (not the vulnerable behavior), it will false-positive on patched systems. Check for the vulnerability response, not just the endpoint.
4. **Are negative matchers needed?** Add `negative: true` matchers for common false-positive signatures (e.g., SPA catch-all pages, generic error pages, WAF block pages).

### 3c. False positive assessment

Score false-positive risk (0-10):
- **0-2 (Low)**: Multiple specific matchers, version-pinned, unique response signature
- **3-5 (Medium)**: Good matchers but could match similar-but-not-vulnerable setups
- **6-8 (High)**: Broad matchers, likely to trigger on non-vulnerable targets
- **9-10 (Unacceptable)**: Will match almost any web server; DO NOT ship

If score > 5, revise matchers (go to Step 4).

### 3d. Classification check

- Does `severity` match the Finding's CVSS-derived severity?
- Do `tags` accurately describe the vulnerability class?
- Is the `description` accurate and not exaggerated?

## Step 4 — Iteration (if critic found issues)

For each issue found by the critic:
1. Identify the specific problem (syntax error, broad matcher, wrong severity, etc.)
2. Revise the template to address it
3. Re-run the critic checks (Step 3)
4. Maximum 3 iterations. If still failing after 3, report the remaining issues and save with a `# TODO` comment.

### Iteration log format

```
Iteration 1/3:
  Actor: Generated initial template
  Critic: [FAIL] Matcher too broad — "200" status alone. [FAIL] Missing negative matcher for SPA.
  Action: Added word matcher for specific response signature. Added negative matcher for catch-all.

Iteration 2/3:
  Actor: Revised with specific matchers
  Critic: [PASS] Syntax OK. [PASS] Matchers specific. [PASS] FP score: 2/10. [PASS] Classification correct.
  Result: ACCEPTED
```

## Step 5 — Save template

Save to workspace (target-specific, with real data):
```
workspace/workshop/<target>/nuclei-templates/<FINDING-ID>-detection.yaml
```

If the template is generic enough (no target-specific data), also propose a shape-only version for the framework:
```
# Shape-only version — replace all target-specific values with placeholders
# Save to: templates/nuclei/<vuln-class>/<descriptive-name>.yaml
```

## Step 6 — Output report

```markdown
## Nuclei Template Generated

- **Finding**: <FINDING-ID>
- **Template ID**: <template-id>
- **Type**: <detection|exploit|misconfiguration|exposure>
- **Severity**: <severity>
- **Iterations**: <N>/3
- **FP Score**: <score>/10
- **Saved to**: workspace/workshop/<target>/nuclei-templates/<FINDING-ID>-detection.yaml

### Critic Summary
- Syntax: PASS
- Matcher specificity: PASS
- False positive risk: <LOW|MEDIUM|HIGH>
- Classification: PASS

### Usage
```bash
# Test against single target
nuclei -t <template-path> -u https://example.com

# Test against target list
nuclei -t <template-path> -l targets.txt

# Validate template syntax
nuclei -t <template-path> -validate
```

### Matchers Explanation
<Brief explanation of what each matcher checks and why>
```

## Example output

A complete example for an exposed actuator endpoint:

```yaml
id: exposed-spring-actuator-env

info:
  name: Spring Boot Actuator /env Exposure
  author: operator
  severity: high
  description: |
    The Spring Boot Actuator /actuator/env endpoint is exposed without
    authentication, leaking environment variables including potential
    database credentials, API keys, and internal service URLs.
  reference:
    - https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html
  tags: misconfig,spring,actuator,exposure
  metadata:
    max-request: 1

http:
  - method: GET
    path:
      - "{{BaseURL}}/actuator/env"
      - "{{BaseURL}}/manage/env"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "propertySources"
          - "activeProfiles"
        condition: and
        part: body
      - type: word
        words:
          - "<html"
          - "Page Not Found"
          - "Access Denied"
        negative: true
        part: body
    extractors:
      - type: regex
        part: body
        group: 1
        regex:
          - '"activeProfiles":\s*\["([^"]+)"\]'
```

## Integration

- Before generating, run `bb-dedup-finding` to confirm the Finding is unique (no point generating a template for a duplicate).
- After generating, suggest `bb-evidence-readiness` to ensure the Finding documentation is complete enough for the template to make sense to a reviewer.
- If the Finding has chain potential, suggest `bb-exploit-chain` — chain templates may need multiple YAML files linked via workflow.
- Community dedup: search `github.com/projectdiscovery/nuclei-templates` for existing templates covering the same CVE or pattern before creating a new one.
