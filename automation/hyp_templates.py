#!/usr/bin/env python3
"""hyp_templates.py — deterministic surface->hypothesis and capability->hypothesis
generation. Closes the three ASG coverage gaps found in the effectiveness review:

  Gap 1  surface->hypothesis auto-derivation was never used (30/33 hyps hand-authored)
  Gap 2  74% of surfaces sat `untested` but never entered the work queue
  Gap 3  the capability layer span idle (capabilities held, nothing depended on them)

All three reduce to one mechanism: a TEMPLATE REGISTRY that maps a trigger — a surface
of type X, or a held capability of type Y — to the standard, DEPTH-PRIMED hypotheses for
it, and SEEDS them onto the ledger so they enter `ready_hypotheses` and get worked round
by round. Deterministic and free; the LLM `propose` becomes the fallback for what the
templates do not cover, not the only path onto a surface.

Depth, not checklist noise: each template carries the invariant + a control action for
the oracle, and bakes in the refute patterns from the KB (e.g. a subdomain-takeover
template's control is served-content verification, per LL-299; API write templates carry
the WRITE-5 mass-assign/boundary/cross-entity angles, not just "GET returns 200").

Two CG layers, kept separate (the cross-target review corrected an earlier "just delete
CG" call — the concept is fine, ADOPTION was the problem: 9/10 targets never filled R:/P:
because nothing seeded them):
  (a) INFORMATION RETENTION — surface templates PRE-FILL `requires` per template (not per
      surface type: an unauth probe requires nothing and runs now; the IDOR/WRITE/upload
      probes carry requires=["R:auth=session"] and are seeded BLOCKED). So the ledger
      records "this hypothesis is blocked on an account" WITHOUT the operator hand-thinking
      it — the R: layer grows on its own, and a provisioned session auto-readies them.
  (b) AUTO-CHAIN COMPUTATION — CAP_TEMPLATES leverages a HELD capability (P: provides ->
      downstream requires). This layer is DORMANT until adoption produces a capability;
      it is deliberately not invested in further (building chain automation before R:/P:
      are populated is idle spinning). It fires for free if/when a capability lands.
"""
from __future__ import annotations

import re
import uuid
from typing import Callable, Optional

from hunt_loop import HuntLoop
from logic_vuln_loop import Env, LogicHypothesis

# ── surface classification (heuristic over the descriptive node_id) ──────────
_SURFACE_RULES: list[tuple[str, str]] = [
    (r"graphql", "graphql"),
    (r"oauth|openid|/authorize|\bsso\b|saml", "oauth"),
    (r"upload|file-?write|attachment", "upload"),
    (r"\bipc\b|\brpc\b|websocket|web-?socket|named-?pipe|unix-?socket", "ipc"),
    (r"protocol|scheme|openexternal|blocklist|allowlist|deeplink|deep-?link", "protocol"),
    (r"subdomain|cname|takeover|\bdns\b|dangling", "dns"),
    (r"redirect|return-?url|\bnext=|callback-?url", "redirect"),
    (r"cors|access-control", "cors"),
    (r"admin|dashboard|manage(ment)?|console", "admin"),
    (r"config|\.env|disclosure|manifest|\.json|settings", "config"),
    (r"\bapi\b|/v[0-9]|endpoint|/rest|/graph", "api"),
]


def classify_surface(node_id: str) -> str:
    n = (node_id or "").lower()
    for pat, kind in _SURFACE_RULES:
        if re.search(pat, n):
            return kind
    return "generic"


def _t(dimension, invariant, test_action, control_action, violation_outcome,
       expected_normal, provides=None, requires=None):
    return {
        "dimension": dimension, "invariant": invariant, "test_action": test_action,
        "control_action": control_action, "violation_outcome": violation_outcome,
        "expected_normal": expected_normal, "provides": provides or [], "requires": requires or [],
    }


# ── surface_type -> depth-primed hypothesis templates ────────────────────────
# {surface} is substituted with the surface node id so the action is concrete.
SURFACE_TEMPLATES: dict[str, list[dict]] = {
    "graphql": [
        _t("trust", "GraphQL introspection must be gated when the API is auth-gated",
           "GET introspection {__schema{types{name}}} on {surface}",
           "GET {surface} without a token (baseline)",
           "schema_returned", "401/403 before introspection is reachable"),   # unauth -> requires []
        _t("roles", "a node/edge id must not be readable across tenants (IDOR)",
           "query node(id: <other-tenant-id>) on {surface}",
           "query node(id: <own-id>) on {surface}",
           "cross_tenant_object", "own object only / 403 on foreign id",
           requires=["R:auth=session"]),                                      # needs a login to test
    ],
    "oauth": [
        _t("trust", "redirect_uri must be validated against a strict allowlist",
           "start auth on {surface} with redirect_uri=attacker.example",
           "start auth on {surface} with the registered redirect_uri",
           "code_to_attacker", "rejected / only registered uri honored"),
        _t("state", "the state parameter must bind the callback to the initiator (CSRF)",
           "replay {surface} callback with a foreign/absent state",
           "complete {surface} with the matching state",
           "session_fixated", "callback rejected without matching state"),
    ],
    "upload": [
        _t("trust", "upload must restrict type and never place files in a served/exec path",
           "upload a .html/.svg/.phtml to {surface}",
           "upload an allowed .png to {surface}",
           "active_content_stored", "type rejected / stored inert & off-origin",
           requires=["R:auth=session"]),                                      # upload usually needs a login
    ],
    "ipc": [
        _t("trust", "a local IPC/RPC command surface must authenticate the caller/origin",
           "invoke a privileged command on {surface} from an unauthorized origin",
           "invoke the same command with an authorized origin/token",
           "command_executed_unauth", "INVALID_PERMISSIONS / origin rejected"),
    ],
    "protocol": [
        _t("trust", "external-scheme handling must be an allowlist, not a denylist",
           "drive {surface} with smb:/ftp:/tel:/search-ms: (UNC-auth schemes)",
           "drive {surface} with https: (the intended scheme)",
           "dangerous_scheme_reached_sink", "non-allowlisted scheme dropped/inert"),
    ],
    "dns": [
        # depth-primed with LL-299: a takeover needs served-content verification, not a CNAME string
        _t("trust", "a dangling CNAME to an unclaimed provider resource is takeover-able",
           "resolve {surface} and fetch the CNAME target's content",
           "compare vs a live control host serving real content",
           "unclaimed_provider_fingerprint",
           "live-200 to canonical / NXDOMAIN / NODATA all REFUTE takeover"),
    ],
    "redirect": [
        _t("trust", "a redirect target must be same-site / allowlisted",
           "request {surface} with an external/attacker redirect target",
           "request {surface} with an internal target",
           "external_location_honored", "host hardcoded/allowlisted -> rewritten"),
    ],
    "cors": [
        _t("trust", "ACAO must not reflect an arbitrary Origin with credentials",
           "send {surface} with Origin: https://evil.example",
           "send {surface} with a legitimate Origin",
           "acao_reflects_evil_with_creds",
           "no ACAO reflected / not script-readable (see LL-245: 302 ACAO is inert)"),
    ],
    "admin": [
        _t("roles", "an admin/management surface must reject unauthenticated access",
           "GET {surface} unauthenticated",
           "GET a known-public path (baseline catch-all discriminator)",
           "admin_data_or_action", "401/403, and not a SPA catch-all shell (byte-compare)"),
    ],
    "config": [
        # depth-primed with LL-299 public-by-design: a token in client config is often not a secret
        _t("trust", "a served config/manifest must not expose a usable server-side secret",
           "GET {surface} and classify each exposed value",
           "diff vs a nonexistent path (catch-all discriminator)",
           "server_secret_or_pii",
           "only public-by-design tokens (RUM/Intercom/OAuth client id) -> not a finding"),
    ],
    "api": [
        # an unauth-read probe runs immediately (requires []); the authed IDOR/WRITE
        # probes are seeded BLOCKED on R:auth=session -> the ledger records "these need
        # an account" (CG info-retention layer) and they auto-ready when one is provisioned
        _t("roles", "an auth-gated API resource must reject unauthenticated reads",
           "GET {surface} unauthenticated",
           "GET a known-nonexistent path (catch-all discriminator)",
           "unauth_data_returned", "401/403, not a SPA catch-all shell (byte-compare)"),
        _t("roles", "an object must not be readable/writable across owners (IDOR)",
           "GET/PUT {surface} with another owner's id",
           "GET/PUT {surface} with the caller's own id",
           "cross_owner_access", "own object only / 403 on foreign id",
           requires=["R:auth=session"]),
        # depth-primed with WRITE-5 (feedback_unauth_write_write5_checklist)
        _t("trust", "a write endpoint must enforce mass-assignment / field boundaries",
           "POST/PUT {surface} with extra privileged fields (role/owner/price/state)",
           "POST/PUT {surface} with only the intended fields",
           "privileged_field_accepted", "extra fields ignored/rejected (WRITE-5)",
           requires=["R:auth=session"]),
    ],
    "generic": [
        _t("invariant", "the surface enforces its intended trust boundary",
           "exercise {surface} from the unauthorized/adversarial side",
           "exercise {surface} on the normal/baseline path",
           "boundary_crossed", "boundary holds (control differs from test)"),
    ],
}

# ── capability_type -> downstream leverage templates (Gap 3) ─────────────────
# keyed by a prefix of the capability tag P:<domain>=<value>; when such a capability
# is CONFIRMED, seed a hypothesis that LEVERAGES it (requires=[cap]) so the capsule's
# ready set grows and the chain actually advances.
def _cap_kind(cap: str) -> str:
    m = re.match(r"P:([a-z]+)=", cap or "")
    return m.group(1) if m else "generic"


CAP_TEMPLATES: dict[str, list[dict]] = {
    "cred": [_t("trust", "a leaked credential must not unlock a privileged endpoint",
                "authenticate to a privileged endpoint using {cap}",
                "hit the same endpoint anonymously",
                "privileged_access_with_leaked_cred", "401/403 even with the leaked value")],
    "token": [_t("trust", "a leaked token must be scoped/expired, not a master key",
                 "replay {cap} against sibling/admin endpoints in the ecosystem",
                 "replay a random/invalid token",
                 "token_honored_broadly", "token rejected off its intended scope")],
    "read": [_t("trust", "a disclosed internal value must not pivot to a further asset",
                "use the value from {cap} to reach the referenced internal asset",
                "attempt the same reach without it",
                "internal_asset_reached", "asset still gated independently")],
    "ssrf": [_t("trust", "server-side fetch must not reach internal/metadata endpoints",
                "drive {cap} at cloud metadata / an internal-only host",
                "drive it at an external control URL",
                "internal_response_returned", "internal targets blocked/filtered")],
}


def _mk(env: Env, spec: dict, subst: dict) -> LogicHypothesis:
    def s(v: str) -> str:
        for k, val in subst.items():
            v = v.replace("{" + k + "}", val)
        return v
    return LogicHypothesis(
        hyp_id="tpl:" + uuid.uuid4().hex[:12],
        dimension=spec["dimension"], invariant=s(spec["invariant"]), applies_env=env,
        precondition="", expected_normal=s(spec["expected_normal"]),
        test_action=s(spec["test_action"]), control_action=s(spec["control_action"]),
        violation_outcome=spec["violation_outcome"],
        provides=list(spec.get("provides") or []),
        requires=list(spec.get("requires") or []),
        surface_id=subst.get("surface"))


def hypotheses_for_surface(env: Env, node_id: str) -> list[LogicHypothesis]:
    kind = classify_surface(node_id)
    return [_mk(env, spec, {"surface": node_id}) for spec in SURFACE_TEMPLATES.get(kind, SURFACE_TEMPLATES["generic"])]


def hypotheses_for_capability(env: Env, cap: str) -> list[LogicHypothesis]:
    specs = CAP_TEMPLATES.get(_cap_kind(cap), [])
    out = []
    for spec in specs:
        h = _mk(env, spec, {"cap": cap})
        if cap not in h.requires:
            h.requires.append(cap)          # leverage => depends on the held capability
        out.append(h)
    return out


def make_templater(env: Env, registry: dict) -> Callable[[HuntLoop, dict], Optional[LogicHypothesis]]:
    """A `templater(loop, cap)` for autodrive's replan slot. Priority: leverage a newly
    held capability (Gap 3), else cover the next untested surface (Gap 1/2). It SEEDS all
    generated hypotheses onto the ledger (add_hypothesis) + the shared registry so they
    enter `ready_hypotheses` and get worked round by round, and returns one to run now.
    Returns None when nothing is left to template -> autodrive falls back to LLM propose."""
    done_surfaces: set[str] = set()
    done_caps: set[str] = set()

    def _seed(loop: HuntLoop, hyps: list[LogicHypothesis]) -> Optional[LogicHypothesis]:
        first = None
        for h in hyps:
            registry[h.hyp_id] = h
            loop.add_hypothesis(h.hyp_id, requires=h.requires)   # enters the capsule
            if first is None:
                first = h
        return first

    def templater(loop: HuntLoop, cap: dict) -> Optional[LogicHypothesis]:
        # Gap 3: a held capability nothing has leveraged yet
        for c in cap.get("capabilities", []):
            if c not in done_caps and CAP_TEMPLATES.get(_cap_kind(c)):
                done_caps.add(c)
                seeded = _seed(loop, hypotheses_for_capability(env, c))
                if seeded is not None:
                    return seeded
        # Gap 1/2: the next untested surface with no templated hypotheses yet
        for node_id in cap.get("untested_surface", []):
            if node_id not in done_surfaces:
                done_surfaces.add(node_id)
                seeded = _seed(loop, hypotheses_for_surface(env, node_id))
                if seeded is not None:
                    return seeded
        return None

    return templater
