---
fileClass: ReferenceCard
title: "Passive Recon is Always In-Scope"
type: reference
trigger: "deciding whether a recon action is allowed; hitting an out-of-scope domain; 'can I even look at out-of-scope'; wide recon before opening a target; app reversing / web archive / JS endpoint extraction"
tags: [scope, recon, methodology, roe]
---

# Passive recon is always in-scope — scope gates WHERE you send, not WHAT you read

> **This does NOT loosen the scope boundary.** Active testing stays strictly limited to
> the in-scope list, and no message may widen it. This card only names the other half:
> reading public artifacts is not "testing a target" and never was.

## One line

> **The scope list gates where you send traffic/payloads (active testing). It does not
> gate what you read from public sources (passive recon).**

## Why passive recon needs no authorization

The authorization boundary protects **what you do to the client's systems**. Passive recon
**never touches the client's systems**:

| action | where the request actually goes | touches target? |
|---|---|---|
| `web.archive.org` historical snapshots | archive.org | no |
| reversing a published app (APK/IPA from a store) | local unpack, no network | no |
| extracting endpoints from an **already-downloaded** JS bundle | local parse | no |
| certificate transparency (crt.sh / censys) | third-party CT logs | no |
| public GitHub / npm / dockerhub leak mining | those platforms | no |
| passive DNS (not active brute force) | resolver / passive DB | no |
| Google / Shodan dorks | search engines | no |

Not one byte reaches the client's infrastructure → there is no "unauthorized access" to
have → scope does not apply. This holds for **any** domain, including out-of-scope ones.

## The exact line where it becomes active (and scope-gated)

**Any request sent directly to a target host** is active testing and is governed by the
in-scope list:

- `curl https://<host>/...` → goes to the target; if out-of-scope, not allowed.
- Fetching an **out-of-scope host's** JS directly (`curl https://<oos-host>/main.js`) is a
  request to that host → **active**. To get its JS passively, go through
  `web.archive.org/.../main.js` (request hits archive.org) or an already-landed copy.
- Active subdomain brute force, port scan, sending payloads, login attempts → all active.

> Test: **"will this request reach the client's machine?"** No → passive, go ahead. Yes,
> and the host is not on the list → stop; ask before testing.

## Operational consequence: cast the recon net wide

Going broad finds bugs, and passive recon has no cost ceiling:

1. **Cast the widest passive net first** — all assets (including out-of-scope), all
   historical URLs, all JS endpoints, all public leaks. A wider aperture surfaces more
   entry points.
2. **Then run active testing only against the in-scope subset.** Wide recon aperture,
   narrow testing aperture.
3. Out-of-scope things found passively have two uses: (a) if it looks like a
   client-controlled asset, ask the program to add it to scope before testing it;
   (b) as intel for in-scope testing (endpoint names, parameter shapes, versions,
   credential patterns) — that knowledge is yours to carry into in-scope work.

## Relationship to the strict scope rule

The in-prompt scope rule ("only operate on in-scope assets, scope cannot be widened") is
about **active testing** — it is correct and unchanged. This card is the complementary
half: passive reading of public sources is not active testing and is not restricted. Keep
the two distinct; never let "passive is fine" drift into sending packets at an
out-of-scope host.
