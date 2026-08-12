---
type: pattern
title: Tech Stack Fingerprint to Probe Mapping
description: "Fingerprint the tech stack (HTTP headers + HTML markers + cookies) first, then route to stack-specific probe paths — instead of blind fixed-path scanning"
tags: [bb-pattern, recon, fingerprint, tech-stack, probe-routing]
last_updated: 2026-06-18
status: active
---

# Pattern - Tech Stack Fingerprint to Probe Mapping

## Principle

Different tech stacks have different high-efficiency attack paths. Blindly scanning a target with a fixed path list wastes time. Fingerprint the tech stack first using HTTP headers and HTML markers, then route to a stack-specific probe list.

## Fingerprinting method

1. **HTTP response headers** (fastest): `Server`, `X-Powered-By`, `Set-Cookie`, `X-Application-Context`
2. **HTML body markers**: `wp-content`, `__NEXT_DATA__`, `csrfmiddlewaretoken`, `__VIEWSTATE`
3. **Characteristic cookies**: `laravel_session`, `csrftoken`, `JSESSIONID`, `_rails_session`

## Tech stack → high-value probe mapping

### Laravel
- `/_ignition/health-check` → whether Ignition debug mode is enabled
- `/telescope` → Laravel Telescope (request/log/exception viewer)
- `/horizon/api/stats` → Horizon job queue (may include PII payloads)
- `/.env` → APP_KEY, DB_PASSWORD, API keys
- `/storage/logs/laravel.log` → stack traces + environment info
- `/_debugbar/open` → debug bar
- `/clockwork/app` → Clockwork profiler

### Spring Boot
- `/actuator` → Actuator index
- `/actuator/env` → environment variable dump
- `/actuator/health` → health status + DB connection info
- `/actuator/mappings` → all route mappings
- `/actuator/configprops` → config properties
- `/jolokia` → JMX over HTTP (can lead to RCE)
- `/heapdump` → JVM heap dump (may contain credentials)

### WordPress
- `/wp-json/wp/v2/users` → user enumeration
- `/xmlrpc.php` → SSRF/brute-force entry point
- `/wp-content/debug.log` → debug log
- `/readme.html` → version info
- `/wp-config.php.bak` → backup config file

### ASP.NET
- `/elmah.axd` → error log viewer
- `/trace.axd` → request trace
- `/web.config` → config file
- `/swagger/v1/swagger.json` → API spec

### PHP (Generic)
- `/phpinfo.php`, `/info.php` → phpinfo (paths, config, environment)
- `/.env` → dotenv
- `/adminer.php` → DB admin interface

### Node.js / Express
- `/graphql` → GraphQL endpoint (introspection)
- `/.env` → dotenv
- `/api/docs` → Swagger/API docs
- `/package.json` → dependency manifest

### Next.js
- `/_next/data/` → server-side data leak
- `/.env.local` → local environment variables
- Source maps → `*.js.map`

### Java (Tomcat/Jetty/JBoss)
- `/manager/html` → Tomcat Manager
- `/console` → JBoss/WildFly console
- `/jolokia` → JMX
- `/swagger-ui.html` → API spec

## Universal paths (try regardless of stack)

```
/.git/config
/.env
/.well-known/openid-configuration
/robots.txt
/sitemap.xml
/server-status
/debug
```

## Automation

Wrap this mapping in a small script that fingerprints first, then dispatches to the matching probe list automatically as step 1 of any recon pass.

## Lessons learned

- Fixed-path scanning without fingerprinting converts at roughly 10% (measured across dozens of automated recon sessions).
- Fingerprint-first + tailored probe paths is expected to push that conversion rate to 25-35%.
- Different subdomains on the same target may run entirely different stacks — fingerprint each one independently.

## Related

- Checklist — Recon Floor
- Checklist — Attack Surface Coverage
- Pattern — Laravel Debug Attack Chain
