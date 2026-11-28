"""mitm_record.py — always-on recording addon for mitmdump.

Run it as the recording layer:

    BB_MITM_SCOPE="app.example.com,api.example.com" \
    BB_TRAFFIC_DB="$VAULT_ROOT/mitm_mcp_traffic.db" \
    mitmdump -q -s automation/mitm_record.py --listen-host 127.0.0.1 --listen-port 8788

Point your tools (and, for manual work, Burp's upstream proxy) at
127.0.0.1:8788. Every in-scope exchange lands in the `flows` table that
`traffic_bind.py` reads and binds to Findings — one queryable store for both
agent and manual traffic.

Why this exists alongside mitmproxy-mcp: the MCP recorder
(mitmproxy_mcp/core/recorder.py) writes the SAME `flows` schema but only while
the MCP server runs, and it stores response text with no size cap. This addon
is a standalone always-on writer with the same schema PLUS three disk guards:

1. Scope gate. Records only hosts in BB_MITM_SCOPE (substring match). Empty
   scope records NOTHING — same fail-safe as the MCP recorder's empty
   allowed_domains. This is the main reason the store does not explode: it is
   never a firehose of all browsing.
2. Bodies are stored only for texty content types (TEXTY_CT) whose first bytes
   carry no NUL. Everything else — images, fonts, video, archives, wasm,
   application/octet-stream and other downloads — keeps only its metadata row,
   not its bytes. This is a content-type ALLOWLIST plus a NUL sniff, NOT
   get_text(): mitmproxy's get_text(strict=False) latin-1-decodes octet-stream
   into garbage text, so relying on it would still store binary. The `size`
   column always records the real byte length.
3. Text-body cap. Response/request text over BB_MITM_BODY_CAP bytes is stored
   truncated with a marker, so one large JS bundle or JSON dump cannot alone
   balloon a row. Default 512 KiB.

Env:
  BB_MITM_SCOPE      comma-separated host substrings; empty = record nothing
  BB_TRAFFIC_DB      sqlite path (default ./mitm_mcp_traffic.db)
  BB_MITM_BODY_CAP   max stored body bytes per side (default 524288)
  BB_MITM_TEXTY_CT   comma CT prefixes whose body IS stored (overrides default
                     allowlist: text/, application/json, application/xml,
                     application/javascript, application/x-www-form-urlencoded,
                     application/graphql)
"""
from __future__ import annotations

import json
import os
import sqlite3

from mitmproxy import http


def _env_list(name: str) -> list[str]:
    return [s.strip() for s in os.environ.get(name, "").split(",") if s.strip()]


# Content types whose body is worth storing. Anything else (images, fonts,
# video, octet-stream, downloads, wasm) keeps only metadata. A "+json"/"+xml"
# suffix (e.g. application/vnd.api+json) is treated as texty too.
DEFAULT_TEXTY_CT = (
    "text/", "application/json", "application/xml", "application/javascript",
    "application/x-www-form-urlencoded", "application/graphql",
)


class Recorder:
    def __init__(self) -> None:
        self.db_path = os.environ.get("BB_TRAFFIC_DB", "mitm_mcp_traffic.db")
        self.scope = _env_list("BB_MITM_SCOPE")
        self.body_cap = int(os.environ.get("BB_MITM_BODY_CAP", str(512 * 1024)))
        self.texty_ct = tuple(_env_list("BB_MITM_TEXTY_CT")) or DEFAULT_TEXTY_CT
        self._init_db()

    def _conn(self):
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self) -> None:
        with self._conn() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS flows (
                    id TEXT PRIMARY KEY, url TEXT, method TEXT, status_code INTEGER,
                    request_headers TEXT, request_body TEXT,
                    response_headers TEXT, response_body TEXT,
                    timestamp REAL, size INTEGER
                )""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON flows(timestamp)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_url ON flows(url)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_method ON flows(method)")

    def _in_scope(self, host: str) -> bool:
        # Empty scope records nothing — fail safe, never a firehose.
        return bool(self.scope) and any(d in host for d in self.scope)

    def _headers_json(self, msg: http.Message) -> str:
        return json.dumps([[k.decode("latin-1"), v.decode("latin-1")]
                           for k, v in msg.headers.fields])

    def _is_texty(self, content_type: str) -> bool:
        ct = content_type.split(";", 1)[0].strip().lower()
        if ct.endswith(("+json", "+xml")):
            return True
        return any(ct.startswith(p) for p in self.texty_ct)

    def _body(self, msg: http.Message, content_type: str) -> str | None:
        if not msg.content:
            return None
        # Allowlist, not get_text: get_text(strict=False) latin-1-decodes
        # octet-stream into garbage, so a CT allowlist + NUL sniff is the only
        # reliable binary gate.
        if not self._is_texty(content_type):
            return None
        if b"\x00" in msg.content[:1024]:
            return None  # binary despite a texty content-type
        text = msg.get_text(strict=False)
        if text is None:
            return None
        if len(text) > self.body_cap:
            return text[:self.body_cap] + f"\n…[truncated {len(text) - self.body_cap} bytes]"
        return text

    def response(self, flow: http.HTTPFlow) -> None:
        if not self._in_scope(flow.request.host):
            return
        resp = flow.response
        resp_ct = resp.headers.get("content-type", "") if resp else ""
        req_ct = flow.request.headers.get("content-type", "")
        size = len(resp.content) if resp and resp.content else 0
        with self._conn() as c:
            c.execute("""
                INSERT INTO flows (id, url, method, status_code,
                    request_headers, request_body, response_headers, response_body,
                    timestamp, size)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    url=excluded.url, method=excluded.method,
                    status_code=excluded.status_code,
                    request_headers=excluded.request_headers,
                    request_body=excluded.request_body,
                    response_headers=excluded.response_headers,
                    response_body=excluded.response_body, size=excluded.size
            """, (
                flow.id, flow.request.url, flow.request.method,
                resp.status_code if resp else None,
                self._headers_json(flow.request), self._body(flow.request, req_ct),
                self._headers_json(resp) if resp else None,
                self._body(resp, resp_ct) if resp else None,
                flow.request.timestamp_start, size,
            ))


addons = [Recorder()]
