"""Policy Administrator dispatches policy decisions to enforcement actions."""

from typing import Any, Dict

import httpx

from shared.policy_models import PolicyDecision
from shared.profile_manager import profile_manager

ACTION_API_URL = "http://localhost:8002"
ISOLATION_SECURITY_EVENT_ID = "13000003"


async def _execute_isolate(client: httpx.AsyncClient, request_id: str, target_ip: str, reason: str) -> None:
    response = await client.post(
        f"{ACTION_API_URL}/actions/isolate",
        json={
            "agent_ip": target_ip,
            "security_event_id": ISOLATION_SECURITY_EVENT_ID,
            "reason": reason,
            "request_id": request_id,
        },
    )
    response.raise_for_status()


async def _execute_change_role(client: httpx.AsyncClient, request_id: str, mac: str, target_role: str, reason: str) -> None:
    response = await client.post(
        f"{ACTION_API_URL}/actions/change-role",
        json={
            "mac": mac,
            "target_role": target_role,
            "reason": reason,
            "request_id": request_id,
        },
    )
    response.raise_for_status()


def _copy_decision(decision: PolicyDecision, **metadata: Any) -> PolicyDecision:
    return PolicyDecision(
        decision.allowed,
        decision.action,
        decision.reason,
        target_role=decision.target_role,
        risk_delta=decision.risk_delta,
        risk_level=decision.risk_level,
        metadata={**decision.metadata, **metadata},
    )


async def dispatch_alert_decision(decision: PolicyDecision, context: Dict[str, Any]) -> PolicyDecision:
    request_id = context["request_id"]
    mac = context["mac"]
    ip_address = context["ip_address"]

    async with httpx.AsyncClient(timeout=60.0) as client:
        if decision.action == "isolate":
            await _execute_isolate(client, request_id, ip_address, decision.reason)
            profile_manager.update_state(mac, "ISOLATED")
            return _copy_decision(decision, agent_ip=ip_address)

        if decision.action == "restrict":
            target_role = decision.target_role or "restricted"
            await _execute_change_role(client, request_id, mac, target_role, decision.reason)
            profile_manager.update_state(mac, "NON_COMPLIANT")
            return _copy_decision(decision, mac=mac, target_role=target_role)

    return decision


async def dispatch_device_decision(decision: PolicyDecision, context: Dict[str, Any]) -> PolicyDecision:
    request_id = context["request_id"]
    mac = context["mac"]
    previous_role = context["previous_role"]
    sca_score = context["sca_score"]

    if decision.action == "keep_uncheck":
        target_role = "uncheck"
        async with httpx.AsyncClient(timeout=60.0) as client:
            if previous_role != target_role:
                await _execute_change_role(client, request_id, mac, target_role, decision.reason)
        profile_manager.update_state(mac, "NON_COMPLIANT")
        return PolicyDecision(
            False,
            "keep_uncheck",
            decision.reason,
            target_role=target_role,
            metadata={"mac": mac, "target_role": target_role, "reason": "Posture checks failed"},
        )

    target_role = decision.target_role or "uncheck"
    async with httpx.AsyncClient(timeout=60.0) as client:
        if target_role != previous_role:
            await _execute_change_role(client, request_id, mac, target_role, decision.reason)

    profile_manager.update_state(mac, "COMPLIANT")
    return PolicyDecision(
        True,
        "allow_role",
        f"SCA score {sca_score} → {target_role}",
        target_role=target_role,
        metadata={"mac": mac, "target_role": target_role, "reason": decision.reason},
    )
