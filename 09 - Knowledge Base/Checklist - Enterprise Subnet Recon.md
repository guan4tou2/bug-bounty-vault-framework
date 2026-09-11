---
type: checklist
title: "Enterprise Subnet Recon Checklist"
tags: [checklist, recon, subnet, enterprise, snmp]
status: active
last_updated: 2026-06-25
---

# Checklist — Enterprise /24 Subnet Recon

> Expanding from a single known IP to a full subnet, across one or more /24 subnets.

## Phase 0: Intelligence Gathering

- [ ] Reverse DNS on the known IP → `dig +short -x <ip>` → confirm the ISP (some national telecom ISPs assign fixed IPs to enterprise customers)
- [ ] WHOIS lookup → confirm IP range ownership
- [ ] **Subdomain enumeration** (do this in Session 1!) → subfinder / crt.sh / ip.thc.org
- [ ] Resolve all subdomains → compile an IP list → identify which /24s have multiple IPs in them

## Phase 1: Subnet Scanning

```bash
for i in $(seq 1 254); do
  ip="<prefix>.${i}"
  https=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}_%{size_download}" "https://${ip}/" 2>/dev/null)
  http=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}_%{size_download}" "http://${ip}/" 2>/dev/null)
  [ "$https" != "000_0" ] || [ "$http" != "000_0" ] && echo "${ip} HTTPS:${https} HTTP:${http}"
done
```

## Phase 1b: UDP Protocol Scanning (do not skip this!)

```bash
# SNMP is mandatory on network equipment (firewall/router/AP/NVR)
sudo nmap -sU -p 161 --script snmp-info,snmp-sysdescr,snmp-interfaces,snmp-netstat,snmp-processes -Pn <ip-list>

# Test SNMP community strings (try at least public/private)
snmpwalk -v2c -c public <ip> 1.3.6.1.2.1.1
snmpwalk -v2c -c private <ip> 1.3.6.1.2.1.1

# Write test (read-only sysContact check to confirm RW, do not change the value)
snmpget -v2c -c private <ip> 1.3.6.1.2.1.1.4.0
```

- [ ] SNMP UDP 161 scan (every live IP, especially network equipment)
- [ ] Test SNMP community strings `public`/`private`
- [ ] If SNMP is open → run a full walk (system/interface/routing/process)
- [ ] If a write succeeds → **Critical**, record it but do not modify anything

## Phase 2: Per Live IP

- [ ] Extract SSL cert intelligence (model/MAC/serial/domain/organization)
- [ ] HTTP headers (Server/X-Powered-By/X-AspNet-Version)
- [ ] Home page title + favicon hash
- [ ] Known product fingerprints (FortiGate = jade theme / ZyXEL = zld_product_spec.js / Synology = SYNO.API)

## Phase 3: Categorize and Act

| Category | Action |
|------|------|
| Firewall/VPN (FortiGate/ZyXEL/Cisco) | CVE endpoint probing, version fingerprinting, SSL cert serial, **SNMP default community** |
| NAS/storage (Synology/QNAP) | API registry, CVE pre-check, Docker API |
| Mail (Exchange) | OWA version (via CSS path), NTLM domain, ProxyShell |
| ERP/business systems | Framework fingerprinting, SQLi, default credentials |
| IoT/cameras (Hikvision/NVR) | CVE-2021-36260, ONVIF, default passwords |
| Containers (Harbor/Docker) | Pre-auth API, project enumeration, Token Service |
| Digital signage/embedded | CGI enumeration, presence/absence of CAPTCHA, firmware CVEs |
| Access control/attendance systems | Default passwords, legacy codebase |

## Phase 4: Cross-Validation (credential reuse)

- [ ] For every login endpoint, **GET first to confirm field names**, then POST (avoids false negatives from a 200 with an empty body)
  ```bash
  curl -sk http://TARGET/login.php | grep -oP 'name="[^"]+"'
  ```
- [ ] Update the recon notes' "Known Login Endpoints" section (format: `| URL | user_field | pass_field |`)
- [ ] Test credential reuse (extracted credentials × all login interfaces)
  ```bash
  bash automation/credential_reuse_tester.sh <target>
  ```
- [ ] Distinguish vendor bugs from config issues: for empty passwords / default credentials, determine whether the endpoint is genuinely unauthenticated (vendor bug) or simply never had a password set (config issue)
- [ ] Correlate certs across the same organization (same issuer/O = same deployment batch)
- [ ] Connect attack chains (RCE on host A → lateral movement → system B)

## Key Takeaways

- Subnet scanning is a **Session 1 activity**, not something to defer to Session 5
- Enterprises with fixed IP allocations often have an entire /24 assigned to the same customer
- SSL certs are the safest (GET-only) source of intelligence
- SPA catch-all detection: compare `home page size` vs `random path size` — identical sizes indicate a false positive
