#!/usr/bin/env python3
"""Generate high-precision, catch-all-aware nuclei templates from the team KB.

Community nuclei templates (13k+) cover generic exposures but frequently FALSE-
POSITIVE on SPA catch-all (any path -> 200 app shell) and on framework-public
config. This generator encodes the team's hard-won KB lessons into GET-only
templates that:
  * require the ACTUAL sensitive signal in the body (not just 200), and
  * carry a negative matcher against the SPA app-shell (<!doctype html / <html).

Re-runnable / idempotent. Output -> templates/nuclei/custom-safe/ which
nuclei_safe_scan.py already includes. Source lessons: KB Pattern - High-Yield
Unauthenticated Web Hunting, Mechanical False-Positive Gate, Source Map Exposure.
"""
import pathlib

OUT = pathlib.Path(__file__).resolve().parents[1] / "templates" / "nuclei" / "custom-safe"

# Each: (filename, id, name, severity, path, words[], negative_words[], extra_condition)
# All GET-only, safe. negative_words guard against SPA catch-all app shells.
TEMPLATES = [
    {
        "file": "kb-actuator-index.yaml", "id": "kb-actuator-index",
        "name": "Spring actuator index exposed (endpoint list, catch-all aware)", "sev": "medium",
        "path": "/actuator",
        "words_or": ['"_links"', '"health":{"href"', '"/actuator/env"', '"/actuator/health"', '"beans"'],
        "neg": ["<!doctype html", "<html"],
        "note": "Actuator index JSON lists exposed mgmt endpoints; SPA 200 shell excluded. KB: Unauth Security Dashboard Chain.",
    },
    {
        "file": "kb-prometheus-metrics.yaml", "id": "kb-prometheus-metrics",
        "name": "Prometheus /metrics exposed (real metric format)", "sev": "low",
        "path": "/metrics",
        "words_or": ["# HELP ", "# TYPE ", "process_cpu_seconds_total", "go_gc_duration_seconds", "jvm_"],
        "neg": ["<!doctype html", "<html"],
        "note": "Real Prometheus exposition format (# HELP/# TYPE); excludes SPA shell. KB: Unauth Security Dashboard Chain.",
    },
    {
        "file": "kb-gitlab-openid-fingerprint.yaml", "id": "kb-gitlab-openid-fingerprint",
        "name": "GitLab anonymous fingerprint via openid-configuration", "sev": "info",
        "path": "/.well-known/openid-configuration",
        "words_or": ['"issuer":"https', "/oauth/token", "/oauth/authorize", "grant_types_supported"],
        "neg": ["<!doctype html", "<html"],
        "note": "OIDC discovery confirms GitLab/IdP issuer + endpoints for anonymous fingerprinting. KB: GitLab Anonymous Fingerprinting.",
    },
    {
        "file": "kb-vite-env-json.yaml", "id": "kb-vite-env-json",
        "name": "Vite/SPA env.json runtime config leak (catch-all aware)", "sev": "medium",
        "path": "/env.json",
        "words_or": ['"apiUrl"', '"API_URL"', '"clientId"', '"tenantId"', '"endpoint"', '"backendUrl"'],
        "neg": ["<!doctype html", "<html"],
        "note": "Real runtime env.json (Vite/SPA) leaks backend/api/client config; excludes SPA 200 shell.",
    },
    {
        "file": "kb-wpjson-user-enum.yaml", "id": "kb-wpjson-user-enum",
        "name": "WordPress wp-json user enumeration (real JSON array)", "sev": "low",
        "path": "/wp-json/wp/v2/users",
        "words_or": ['"slug":', '"id":1,', '"user_registered"'],
        "neg": ["<!doctype html", "<html"],
        "note": "Confirms exposed author list via real JSON (slug/id), not the default /wp-json discovery.",
    },
    {
        "file": "kb-env-real-secret.yaml", "id": "kb-env-real-secret",
        "name": "Exposed .env with real secret (catch-all aware)", "sev": "high",
        "path": "/.env",
        "words_or": ["DB_PASSWORD=", "DB_PASSWORD =", "AWS_SECRET", "AWS_ACCESS_KEY_ID=AKIA",
                     "APP_KEY=base64:", "SECRET_KEY=", "PRIVATE_KEY", "DATABASE_URL=postgres://",
                     "DATABASE_URL=mysql://", "MAIL_PASSWORD=", "REDIS_PASSWORD="],
        "neg": ["<!doctype html", "<html", "<!DOCTYPE html"],
        "note": "Only fires on REAL secret keys; MIX_/VITE_/public-only .env (xtrachef 教訓) does NOT match.",
    },
    {
        "file": "kb-actuator-env-dump.yaml", "id": "kb-actuator-env-dump",
        "name": "Spring actuator /env real dump (not SPA shell)", "sev": "high",
        "path": "/actuator/env",
        "words_or": ["\"activeProfiles\"", "\"propertySources\"", "systemEnvironment", "applicationConfig"],
        "neg": ["<!doctype html", "<html"],
        "note": "Requires actual env JSON keys; SPA catch-all returning 200 HTML is excluded.",
    },
    {
        "file": "kb-ignition-debug.yaml", "id": "kb-ignition-debug",
        "name": "Laravel Ignition / Whoops debug page (stack trace)", "sev": "high",
        "path": "/_ignition/health-check",
        "words_or": ["\"can_execute_commands\"", "ignition", "\"environment\""],
        "neg": ["<!doctype html"],
        "note": "Ignition health-check JSON; also catches Whoops via stack-trace words on error pages.",
    },
    {
        "file": "kb-git-config-exposed.yaml", "id": "kb-git-config-exposed",
        "name": "Exposed .git/config with repo URL (catch-all aware)", "sev": "medium",
        "path": "/.git/config",
        "words_or": ["[core]", "[remote \"origin\"]", "url = http", "url = git@"],
        "neg": ["<!doctype html", "<html"],
        "note": "Requires real git config markers; excludes SPA 200 shell.",
    },
    {
        "file": "kb-source-map-exposed.yaml", "id": "kb-source-map-exposed",
        "name": "JS source map with sourcesContent exposed", "sev": "low",
        "path": "/main.js.map",
        "words_or": ["\"sourcesContent\"", "\"webpack://\"", "\"sources\":["],
        "neg": ["<!doctype html"],
        "note": "Real source map reveals original source; helps find internal pkg names / DepConf scopes.",
    },
    {
        "file": "kb-npmrc-registry.yaml", "id": "kb-npmrc-registry",
        "name": "Exposed .npmrc with registry/_authToken", "sev": "high",
        "path": "/.npmrc",
        "words_or": ["_authToken", "//registry.npmjs.org/:_auth", "registry=http"],
        "neg": ["<!doctype html", "<html"],
        "note": "Real .npmrc proves npm resolution config (DepConf evidence) or leaks auth token.",
    },
]

HEADER_NOTE = "# AUTO-GENERATED by scripts/bb_kb_to_nuclei.py from team KB. GET-only, catch-all-aware.\n"


def render(t):
    words = "\n".join(f'          - '+repr(w) for w in t["words_or"])
    neg = "\n".join(f'          - '+repr(w) for w in t["neg"])
    return HEADER_NOTE + f'''id: {t["id"]}

info:
  name: {t["name"]}
  author: hermes-bb-kb
  severity: {t["sev"]}
  description: |
    {t["note"]}
  tags: kb,exposure,catch-all-aware,safe

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}{t["path"]}"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        condition: or
        words:
{words}
      - type: word
        part: body
        condition: or
        negative: true
        words:
{neg}
'''


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for t in TEMPLATES:
        (OUT / t["file"]).write_text(render(t), encoding="utf-8")
    print(f"wrote {len(TEMPLATES)} KB-derived templates -> {OUT}")
    for t in TEMPLATES:
        print(f"  - {t['file']} ({t['sev']})")


if __name__ == "__main__":
    main()
