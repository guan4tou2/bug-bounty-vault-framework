---
name: bb-incident-response
description: Use when testing may have caused service impact, target returns sustained 502/503/504 after an action, vendor reports downtime, or user reports unintended impact.
---

# Bug Bounty — Accidental Service Disruption Response SOP

> Triggered when security research accidentally impacts a production service. Low frequency, extreme consequence.

## Background

During active security research, it is possible to accidentally disrupt production services (e.g., triggering a management endpoint that stops a service). This SOP ensures rapid service recovery, legal protection, and responsible disclosure.

## Trigger Conditions

**Any one met → activate this SOP:**

- Target returns 502/503/504 **for over 2 minutes** after your action
- Your action and the outage are **clearly correlated** (timing + endpoint match)
- User says "I may have broken it" / "service disruption" / "vendor notified"

## Incident Response Flow (execute in order)

### Step 1 — Immediate Confirmation (< 5 minutes)

```bash
# Confirm actual disruption (rule out transient blip)
curl -s -o /dev/null -w "%{http_code}\n" https://<target>/health

# Also confirm from VPS to rule out local network issues
ssh <vps-user>@<vps-ip> \
  "curl -s -o /dev/null -w '%{http_code}\n' https://<target>/"
```

**Results:**
- Local + VPS both 5xx → real disruption, continue to Step 2
- Only local 5xx → you may be banned / network issue, not an incident; stop testing but no notification needed
- Both 200 → already recovered; update RECON_DB Operation Log result column

### Step 2 — Attempt Self-Repair via Exploit Path (< 10 minutes, if feasible)

- If service still accepts requests: try the corresponding `start` / reverse action
- If service returns 502 (management interface unreachable): **skip, go to Step 3**
- **Do not attempt more exploits** — stop all testing after disruption

⚠️ **Golden rule:** Confirm the reverse action is truly reversible before attempting. Uncertain → skip to Step 3.

### Step 3 — Phone Notification (fastest way to get vendor to restart)

Call vendor's customer service:

- State the service anomaly time
- **Do not explain how it happened**
- Example: "Your service at `<service-url>` has been unresponsive since [time], please have the technical team restart it"

Phone is the fastest channel to get a service restarted.

### Step 4 — Formal Apology Email (< 1 hour)

**To:** `security@<vendor>.com` (or vendor's support email)

**Key points (strictly in this order):**

1. Introduce yourself as an independent security researcher conducting **responsible disclosure**
2. State the disruption timeline; acknowledge it was **accidentally triggered during research**
3. **Do not include technical details** (curl commands, endpoint names, etc.)
4. Reference your formal vulnerability report (platform case ID if available)
5. Commit to:
   - Not disclosing technical details
   - Cooperating with remediation
   - Waiting for fix before disclosure
6. Request **no legal action**

**Template:**

```
Dear <Vendor> Security Team,

I am an independent security researcher conducting responsible disclosure research.

On [YYYY-MM-DD HH:MM] while researching your [service name], I accidentally
triggered an abnormal state (service became unresponsive). I immediately notified
you by phone and have formally reported the vulnerability through [platform name]
(case: [case-ID]).

I commit to:
- Not disclosing any technical details before your fix is deployed
- Cooperating with your remediation timeline
- Proceeding with disclosure only after confirmation of fix

I sincerely apologize for any impact and request that no legal action be taken.
I will fully cooperate with your remediation process.

For further communication, please respond through [platform name] case [case-ID].
```

### Step 5 — Platform Comment (concurrent with Step 4)

Add a comment on the existing vulnerability report:

- State the accidental disruption timeline
- Confirm phone + email notification sent
- Provide phone call time + email send time

**The platform's record serves as third-party documentation of your good-faith response.**

### Step 6 — RECON_DB Update

Update `workshop/<target>/RECON_DB.md` `## Operation Log`:

```
| <time> | <UTC> | <IP> | POST | <URL> | <intent> | SERVICE DISRUPTION — notified (phone HH:MM / email HH:MM / platform comment HH:MM) |
```

Commit:

```bash
git add workshop/<target>/RECON_DB.md
git commit -m "[incident] <target>: <time> service disruption — Steps 1-6 completed"
```

## Legal Protection Principles

| Principle | Why |
|---|---|
| Platform report records are **strongest proof of good faith** | Keep all reports on formal channels |
| Apology email must **not admit unauthorized access** | Only acknowledge "research accidentally triggered service anomaly" |
| **Preserve all communication records** | Email screenshots, phone call times, platform comments |
| If vendor requests more details → **respond through the platform** | Don't provide details privately; maintain the platform as intermediary |

## Prevention (before incidents happen)

Follow the GET-first principle from AGENTS.md §6a:

| Method | Default | Condition |
|---|---|---|
| `GET` / `HEAD` / `OPTIONS` | ✅ Execute freely | None |
| `POST` (read-only semantics) | ✅ Execute | Confirm no side effects |
| `POST` (write / trigger / exec) | ⚠️ Pause | Must know consequences first |
| `PUT` / `PATCH` | ⚠️ Pause | Must know consequences first |
| `DELETE` | ❌ Never execute | Only self-created test data |

**Never execute:** `stop` / `destroy` / `shutdown` / bulk delete / endpoints that send notifications to real users.

## Cross-reference

- AGENTS.md §6a (GET-first prevention)
- AGENTS.md §6d (Operation Log)
- workshop/`<target>`/RECON_DB.md `## Operation Log`
