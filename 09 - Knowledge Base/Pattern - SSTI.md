---
fileClass: KB
type: pattern
tags: [pattern, ssti, injection, rce, template]
added: 2026-01-01
---

# Pattern — SSTI (Server-Side Template Injection)

## Summary

User input is passed unsanitized into a server-side template engine, allowing an attacker to inject template syntax that is evaluated server-side. Successful exploitation can range from information disclosure (engine version, environment variables) to full Remote Code Execution (RCE) by escaping the template sandbox and accessing underlying language runtime objects.

## Detection Signals

- Input is reflected in a response that resembles rendered template output (e.g., `{{7*7}}` returns `49`)
- Error messages referencing a template engine: Jinja2, Twig, Freemarker, Velocity, ERB, Handlebars, Pebble, Smarty, Mako
- User-controlled values appear in email bodies, PDF reports, notification messages, or custom view templates
- Application allows user-defined "templates" for documents, dashboards, or email subjects/bodies
- `500 Internal Server Error` triggered by `${`, `{{`, or `<%` syntax in an input field

## Grep Signatures

```bash
# Python Jinja2 / Mako — render with user input
grep -rn 'render_template_string(\|Template(.*request\.\|from_string(' --include='*.py'

# Python format-string template (also injectable)
grep -rn '\.format(\*\*request\.\|\.format(\*\*params' --include='*.py'

# PHP Twig — createTemplate or render with user var
grep -rn 'createTemplate(\|->render(\s*\$\(request\|->render(\s*\$_' --include='*.php'

# Java Freemarker — user-controlled template string
grep -rn 'new Template(\|cfg\.getTemplate(\|template\.process(' --include='*.java'

# Java Velocity — Velocity.evaluate
grep -rn 'Velocity\.evaluate(\|VelocityEngine.*evaluate(' --include='*.java'

# Ruby ERB — ERB.new with user input
grep -rn 'ERB\.new(\s*params\|ERB\.new(\s*request\.' --include='*.rb'

# Node.js — Handlebars / EJS compile with user input
grep -rn 'Handlebars\.compile(\|ejs\.render(\|\.render(\s*req\.' --include='*.js' --include='*.ts'
```

## Test Methodology

1. Identify input fields where user content is reflected in a rendered context: names, labels, email subjects, report templates, custom messages
2. Inject the polyglot detection probe: `${{<%[%'"}}%\`` — an error or partial reflection indicates a template engine is processing input
3. Inject arithmetic probes per engine to fingerprint (see table below):
   - `{{7*7}}` → `49`: Jinja2 or Twig
   - `${7*7}` → `49`: Freemarker, Velocity, or EL expression
   - `<%= 7*7 %>` → `49`: ERB
   - `{{7*'7'}}` → `7777777`: Jinja2 (Python str * int behavior); Twig would error
4. Once engine is identified, escalate to information disclosure: read environment variables or config values (e.g., `{{config}}` in Jinja2)
5. Attempt sandbox escape using published engine-specific chains (see engine references); use `example.com` collaborator to confirm OOB callback before claiming RCE
6. Document: exact input field, reflected output, engine version if exposed, and the minimal PoC that demonstrates code execution or data leakage

## Common Bypass Techniques

| Defense / Engine | Bypass |
|------------------|--------|
| Jinja2 sandbox (no `__class__`) | Use `request`, `config`, `lipsum`, `cycler` globals; MRO traversal via `__mro_entries__` |
| Twig sandbox | Abuse allowed functions (`filter`, `map`); check if `_self` or `app` globals are exposed |
| Freemarker sandbox (`BeansWrapper`) | `freemarker.template.utility.Execute` class if `exposureLevel` is permissive |
| Velocity sandbox | `$class.inspect` or runtime reflection if `SecureUberspector` is absent |
| Input length limit | Use template inheritance or macro definitions to split payload |
| Keyword filtering (`__class__`, `import`) | Attribute access via `|attr('__class__')`, string concatenation (`'__cl'+'ass__'`) |
| Output encoding after render | SSTI still executes; use OOB DNS/HTTP callback to confirm RCE without needing visible output |

## Severity Guide

| Impact | Severity |
|--------|----------|
| Remote Code Execution (sandbox escape confirmed, OS command executed) | P1 |
| Arbitrary file read on server (e.g., `/etc/passwd`, app config) | P1-P2 |
| Sandboxed RCE with significant runtime access (env vars, secrets) | P2 |
| Template engine information disclosure (version, config, stack trace) | P2-P3 |
| Reflected template expression evaluated but sandboxed with no data leak | P3 |

## Related

- [[Pattern - IDOR]]
- [[Pattern - SSRF]]
- [[Lessons Learned]]
- [[Checklist - Pre-Submission Validation]]
- [[Playbook - Recon]]
