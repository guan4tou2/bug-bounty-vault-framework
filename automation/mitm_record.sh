#!/usr/bin/env bash
# Always-on recording layer for bug-bounty traceability.
#
# Launches mitmdump with automation/mitm_record.py, writing in-scope exchanges
# into the `flows` table that traffic_bind.py reads. Point your tools — and, for
# manual work, Burp's UPSTREAM proxy — at this listener, so agent and manual
# traffic land in one bindable store.
#
# Must run under a CPython that has sqlite3: the Homebrew `mitmdump` binary ships
# a frozen Python WITHOUT sqlite3, so we launch via `uv run --with mitmproxy`.
#
# Required:
#   BB_MITM_SCOPE   comma-separated in-scope host substrings. REQUIRED on purpose
#                   — an empty scope would record nothing, a wildcard would record
#                   everything; neither is a safe default, so you must state it.
# Optional:
#   BB_TRAFFIC_DB   sqlite path (default: <vault>/mitm_mcp_traffic.db)
#   BB_MITM_HOST    listen host (default 127.0.0.1)
#   BB_MITM_PORT    listen port (default 8788)
#   BB_MITM_BODY_CAP  max stored body bytes per side (default 524288)
#
# HTTPS: first run generates a CA at ~/.mitmproxy/mitmproxy-ca-cert.pem; trust it
# so the proxy can record TLS. Untrusted = plaintext HTTP recorded, HTTPS tunneled.
set -euo pipefail

: "${BB_MITM_SCOPE:?set BB_MITM_SCOPE to in-scope hosts (comma-separated); refusing to record an unbounded scope}"

HERE="$(cd "$(dirname "$0")" && pwd)"
export BB_TRAFFIC_DB="${BB_TRAFFIC_DB:-$HERE/../mitm_mcp_traffic.db}"

echo "recording scope=[$BB_MITM_SCOPE] -> $BB_TRAFFIC_DB on ${BB_MITM_HOST:-127.0.0.1}:${BB_MITM_PORT:-8788}" >&2
exec uv run --with mitmproxy mitmdump -q -s "$HERE/mitm_record.py" \
  --listen-host "${BB_MITM_HOST:-127.0.0.1}" --listen-port "${BB_MITM_PORT:-8788}"
