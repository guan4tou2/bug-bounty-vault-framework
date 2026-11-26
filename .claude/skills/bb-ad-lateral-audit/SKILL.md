---
name: bb-ad-lateral-audit
description: "Use when an Active Directory, Windows domain, LDAP, or Kerberos environment is in scope — structured lateral movement audit adapted from DreadGOAD methodology. Triggers: AD target, domain controller found, LDAP exposed, Kerberos tickets, 'lateral movement', 'AD audit', 'domain enum'."
---

# Bug Bounty — Active Directory Lateral Movement Audit

Structured AD audit checklist for bug bounty engagements. Covers enumeration, credential access, lateral movement, and privilege escalation with safety gates at each phase.

## Trigger

Run when:

- An Active Directory / Windows domain environment is in scope
- A domain controller (DC) is discovered during recon
- LDAP (389/636), SMB (445), Kerberos (88) ports are exposed on in-scope hosts
- Domain-joined hosts are found during surface mapping
- User says "AD audit", "lateral movement", "domain enum", "kerberos", "ldap enum"

## Environment Isolation Rule (DreadGOAD)

Each AD scenario is tested independently. No cross-scenario state pollution.

- Document the specific domain and forest under test before any action
- Record the domain functional level and trust topology
- Keep credentials, tickets, and hashes isolated per engagement
- Do not reuse credentials obtained in one domain against another domain unless both are explicitly in scope and the trust relationship is documented

## Phase 1: Enumeration (reconnaissance → discovery)

Kill chain stages: `reconnaissance`, `discovery`

### Domain Information

| Check | Command / Tool | What it reveals |
|-------|---------------|-----------------|
| Current context | `whoami /all` | Current user, groups, privileges |
| Domain SID | `Get-ADDomain` / `rpcclient` | Domain identifier |
| Functional level | `Get-ADDomain` / LDAP query | Available attack surface (older = more vulns) |
| Password policy | `Get-ADDefaultDomainPasswordPolicy` / `crackmapexec smb <dc> --pass-pol` | Lockout threshold, complexity, min length |
| Fine-grained policies | `Get-ADFineGrainedPasswordPolicy` | Per-group overrides |

**Password policy is mandatory before any credential attack.** Record lockout threshold and observation window.

### User Enumeration

| Target group | Why it matters |
|-------------|---------------|
| Domain Admins | Full domain control |
| Enterprise Admins | Forest-wide control |
| Schema Admins | AD schema modification |
| Backup Operators | Can extract ntds.dit |
| Account Operators | Can modify non-admin accounts |
| Server Operators | Local admin on DCs |
| DnsAdmins | DLL injection on DC via DNS service |
| Group Policy Creator Owners | GPO creation/modification |

### Computer Enumeration

Identify high-value targets: domain controllers, file servers, SQL servers, Exchange, SCCM/MECM, ADCS (certificate authority), WSUS, LAPS-managed hosts.

### Trust Relationships

| Trust type | Direction | Attack potential |
|-----------|-----------|-----------------|
| Forest trust | Bidirectional / One-way | SID history injection, cross-forest Kerberoast |
| Domain trust | Parent-child / External | Trust key extraction, SID filtering bypass |
| Shortcut trust | Bidirectional | Lateral movement path |

**Scope gate**: a trusted domain is NOT automatically in scope. Verify before crossing any trust boundary.

### Service Accounts and SPNs

Enumerate all SPN-bearing accounts. Flag:
- Service accounts in privileged groups
- Accounts with `DONT_REQ_PREAUTH` set
- Managed Service Accounts (MSA) and Group Managed Service Accounts (gMSA)
- Accounts with `TRUSTED_FOR_DELEGATION` (unconstrained delegation)

### ACL Analysis

Dangerous permissions to flag:

| Permission | Attack path |
|-----------|------------|
| GenericAll | Full control — reset password, modify membership |
| WriteDACL | Grant yourself any permission |
| WriteOwner | Take ownership, then WriteDACL |
| ForceChangePassword | Reset target's password without knowing current |
| AddMember | Add yourself to privileged group |
| GenericWrite | Modify attributes (e.g., set SPN for Kerberoasting) |
| AllExtendedRights | Includes ForceChangePassword + read LAPS |

## Phase 2: Credential Access

Kill chain stage: `credential-access`

### Kerberoasting

1. Enumerate SPN-bearing service accounts
2. Request TGS tickets for those SPNs
3. Extract ticket hashes
4. Crack offline (does NOT touch the target)

**Cost gate**: estimate crack time. If service account uses 25+ char random password, skip — not cost-effective.

### AS-REP Roasting

1. Enumerate accounts with `DONT_REQ_PREAUTH`
2. Request AS-REP without pre-authentication
3. Crack the encrypted timestamp offline

### Password Spraying

**Safety-critical operation. Mandatory pre-checks:**

1. Read the lockout policy (Phase 1 — mandatory)
2. Calculate safe spray rate: `threshold - 1` attempts per `observation_window`
3. **Smoke test first**: try top-3 passwords against 3 test accounts
4. **Go/no-go gate**: if smoke test yields nothing, assess cost/benefit before full spray
5. Use `--jitter` and respect inter-request delay
6. Monitor for lockout indicators after each round

### NTLM Relay

Identify relay opportunities: SMB signing disabled, LDAP signing not required, HTTP→LDAP coercion paths. Tools: Responder (passive), ntlmrelayx.

### Credential Dumping (requires explicit authorization + admin access)

- LSASS dump (Mimikatz / pypykatz / nanodump)
- SAM/SYSTEM registry hive extraction
- ntds.dit extraction (DCSync if Domain Admin or replication rights)
- DPAPI master key extraction → saved credentials, browser passwords

## Phase 3: Lateral Movement

Kill chain stage: `lateral-movement`

| Technique | Requires | Detection risk |
|-----------|----------|---------------|
| Pass-the-Hash (PTH) | NTLM hash | Medium — event 4624 type 3 |
| Pass-the-Ticket (PTT) | Kerberos TGT/TGS | Low — normal Kerberos traffic |
| PSExec | Admin + SMB | High — creates service, writes to ADMIN$ |
| WMI | Admin + DCOM | Medium — event 4688 |
| WinRM | Admin + WinRM enabled | Medium — event 4688, PowerShell logging |
| DCOM | Admin + DCOM | Low — varied event signatures |
| RDP | Valid creds + RDP enabled | High — event 4624 type 10 |
| SMB share access | Valid creds | Low — event 5140 |

### Delegation Abuse

| Type | Attack | Impact |
|------|--------|--------|
| Unconstrained | Capture TGT of any user authenticating to the host | Domain compromise if DC authenticates |
| Constrained | S4U2Self + S4U2Proxy to impersonate any user to target service | Service-level compromise |
| Resource-based (RBCD) | Write msDS-AllowedToActOnBehalfOfOtherIdentity | Impersonate any user to target host |

### Ticket Attacks (requires KDC compromise or specific keys)

- Silver ticket: forge TGS for a specific service (needs service NTLM hash)
- Golden ticket: forge TGT for any user (needs krbtgt NTLM hash — **explicit authorization required**)

## Phase 4: Privilege Escalation

Kill chain stage: `privilege-escalation`

### ACL-Based Attacks

WriteDACL on domain object → grant DCSync rights → extract all hashes. This is the most common AD privesc path.

### ADCS (Active Directory Certificate Services) — ESC1 through ESC8

| ESC | Condition | Impact |
|-----|-----------|--------|
| ESC1 | Template allows SAN, enrollee-supplies-subject, low-priv enrollment | Impersonate any user |
| ESC2 | Template has Any Purpose or no EKU | Impersonate any user |
| ESC3 | Enrollment agent template + vulnerable target template | Enroll certificates on behalf of others |
| ESC4 | Write access to template object | Modify template to become ESC1 |
| ESC5 | Write access to CA's AD object | Modify CA configuration |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA | SAN override on any template |
| ESC7 | ManageCA + ManageCertificates permissions | Approve pending requests |
| ESC8 | HTTP enrollment endpoint without EPA | NTLM relay to certificate enrollment |

### Other Escalation Paths

- GPO abuse: modify GPO linked to DC OU → scheduled task / startup script
- Print Spooler (PrintNightmare): CVE-2021-1675 / CVE-2021-34527
- PetitPotam: coerce DC authentication → relay to ADCS
- Shadow Credentials: write msDS-KeyCredentialLink → PKINIT authentication
- LAPS: read ms-Mcs-AdmPwd attribute if granted

## Safety Rules (Bug Bounty Specific)

- **NEVER** spray passwords without reading the lockout policy first
- **NEVER** attempt Golden Ticket in production without explicit written authorization
- **NEVER** modify AD objects (users, groups, GPOs, ACLs) without explicit authorization
- **NEVER** use destructive techniques (delete accounts, disable services, modify schemas)
- **NEVER** cross trust boundaries without verifying scope covers the target domain
- Document every credential obtained and every lateral movement action in the Operation Log
- Run `python3 -I automation/scope_check.py --target <host> --scope $WORKSHOP_ROOT/<target>/SCOPE.md` before each new host
- If a lockout occurs, immediately stop all credential attacks and run `bb-incident-response`
- Prefer read-only enumeration over active exploitation when both prove the same point
- Use VPS/isolated runner for noisy operations (spray, relay, coercion)

## Cost Awareness (ExploitBench)

Before expensive operations, estimate cost and apply a go/no-go gate:

| Operation | Typical cost/time | Smoke test |
|-----------|------------------|------------|
| Full Kerberoast crack | Hours–days GPU time | Crack top-3 hashes with rockyou first |
| Password spray (full domain) | 10–60 min depending on user count | 3 passwords × 3 accounts |
| Full LDAP enumeration | 1–5 min | Quick `ldapsearch` for domain root |
| BloodHound collection | 2–10 min, generates traffic | SharpHound with `--CollectionMethod Session,LoggedOn` only |
| ntds.dit extraction + crack | Hours | Check if DCSync is possible first (less noisy) |

**Rule**: if the smoke test fails and no other evidence suggests the full operation will succeed, document the negative result (`bb-attempt-recorder`) and move on.

## Output Format

```markdown
## AD Lateral Movement Audit
- Target domain:
- Domain functional level:
- Scope source:
- Kill chain stages covered: [reconnaissance, discovery, credential-access, lateral-movement, privilege-escalation]

### Enumeration Summary
- Privileged users: <count by group>
- High-value targets: <DCs, ADCS, SCCM, etc.>
- Delegation hosts: <unconstrained/constrained/RBCD>
- Dangerous ACLs: <list>
- Trust relationships: <list with scope status>

### Credential Access Results
- Kerberoastable accounts: <count, cracked count>
- AS-REP roastable: <count, cracked count>
- Password spray: <attempted/skipped, reason>
- Other credentials obtained: <list>

### Lateral Movement Paths
- Verified paths: <list with technique>
- Theoretical paths: <list>
- Blocked paths: <list with reason>

### Privilege Escalation
- ACL paths: <list>
- ADCS findings: <ESC#, impact>
- Other escalation: <list>

### Kill chain progression: reconnaissance → discovery → credential-access → lateral-movement → privilege-escalation
### Safety incidents: none / <describe>
### Chain extensions: <recommendations for bb-exploit-chain>
```

## Cross-References

- `bb-scope-safety-check` — before each new host
- `bb-exploit-chain` — chain credential/access findings immediately
- `chain-tracker` agent — persist AD chain state in CHAIN_GRAPH.md
- `Reference Card - Severity Calibration Anchors` — calibrate AD finding severity
- `bb-counterevidence` — mandatory before promoting AD findings
- `bb-incident-response` — if lockout or service impact occurs
