"""Scope failed paths and explicitly propose a new comparison after changed facts.

Old verdicts and authorization decisions remain intact. This creates no execution,
never grants a capability, and cannot reopen declined authorization by a new ID.
"""
from __future__ import annotations

from command_lifecycle import unresolved_actions
from evidence_applicability import latest_context
from evidence_refs import evidence_resolves, normalize_evidence


def environment_scope(hyp):
    return {"version": hyp.applies_env.version, "role": hyp.applies_env.role, "host": hyp.applies_env.host}


def same_failure_scope(record, hyp):
    old, new = record.get("scope", {}), environment_scope(hyp)
    # Unknown history cannot assert this exact comparison was already tried.
    return all(old.get(key) not in (None, "", "*", "unknown") and old[key] == new[key] for key in new)


def reopen_dead_end(loop, previous_hyp_id, new_hyp, *, reason, condition_evidence):
    """Explicit new-context comparison; caller persists using its existing lock.

    Requires a pinned artifact plus a matching explicit current-context event or
    a capability that was actually acquired since the old failed attempt. The
    existing risk/authorization gate still applies when this new hypothesis runs.
    """
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("changed-condition retry requires a reason")
    old = next((event for event in reversed(loop.events)
                if event.get("type") == "dead_end" and event.get("hyp_id") == previous_hyp_id), None)
    if not old or old.get("cause") == "declined":
        raise ValueError("no reopenable failure; declined authorization needs its original authorization path")
    if new_hyp.hyp_id == previous_hyp_id or any(event.get("type") == "hypothesis"
                                               and event.get("id") == new_hyp.hyp_id for event in loop.events):
        raise ValueError("changed conditions require a fresh comparison identity")
    if unresolved_actions(loop.events, previous_hyp_id):
        raise ValueError("previous execution or effects require reconciliation before another comparison")
    proof = normalize_evidence(condition_evidence, loop.base_path, events=loop.events)
    if not isinstance(proof, dict) or proof.get("kind") != "artifact" or not proof.get("sha256"):
        raise ValueError("changed conditions require a pinned evidence artifact")
    if not evidence_resolves(proof, loop.base_path, loop.events):
        raise ValueError("changed-condition evidence is unavailable")
    old_scope, new_scope = old.get("scope", {}), environment_scope(new_hyp)
    changed = [key for key, value in new_scope.items()
               if old_scope.get(key) not in (None, "", "*", "unknown")
               and value not in (None, "", "*", "unknown") and old_scope[key] != value]
    context = latest_context(loop.events) or {}
    environment = context.get("environment")
    current_scope = {"version": context.get("version"), "role": context.get("role"),
                     "host": environment.get("host") if isinstance(environment, dict) else environment}
    current_matches = bool(changed) and all(
        value not in (None, "", "*", "unknown") and current_scope.get(key) == value
        for key, value in new_scope.items())
    capabilities = set(loop.capsule()["capabilities"])
    acquired = set(new_hyp.requires) & capabilities - set(old.get("available_capabilities", []))
    capability_change = "available_capabilities" in old and bool(acquired)
    if not set(new_hyp.requires).issubset(capabilities) or not (current_matches or capability_change):
        raise ValueError("no evidenced current-condition or acquired-capability change")
    loop.append("failure_path_reopened", previous_hyp_id=previous_hyp_id, hyp_id=new_hyp.hyp_id,
                reason=reason.strip(), old_scope=old_scope, new_scope=new_scope,
                changed_fields=changed, acquired_capabilities=sorted(acquired), evidence=proof)
    loop.add_hypothesis(new_hyp.hyp_id, requires=list(new_hyp.requires))
    return new_hyp.hyp_id
