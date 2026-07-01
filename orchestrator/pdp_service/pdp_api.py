"""PDP (Policy Decision Point) API"""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import httpx
import sys
import os
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.audit_utils import format_audit_reason
from shared.logger import get_logger, setup_logging
from shared.policy_engine import evaluate_alert_risk, evaluate_posture_access, resolve_role_from_groups
from shared.policy_models import PolicyDecision as SharedPolicyDecision
from shared.profile_manager import profile_manager
from pdp_service.policy_admin import ACTION_API_URL, dispatch_alert_decision, dispatch_device_decision

setup_logging("INFO", service_name="pdp")
logger = get_logger(__name__)

app = FastAPI(
    title="Policy Decision Point API",
    version="1.0.0",
    description="Policy engine for Zero Trust NAC - evaluates alerts and device assessments to determine actions",
)

class PdpApiDecision(BaseModel):
    decision: str
    action_params: Dict[str, Any]
    reason: str
    policy_matched: str


def _to_api_decision(decision: SharedPolicyDecision, policy_matched: str) -> PdpApiDecision:
    api_decision = {
        "allow_role": "change_role",
        "keep_uncheck": "none",
        "restrict": "change_role",
        "isolate": "isolate",
        "allow_jit": "allow_jit",
        "deny_jit": "deny_jit",
        "no_action": "none",
    }[decision.action]
    return PdpApiDecision(
        decision=api_decision,
        action_params=decision.metadata,
        reason=decision.reason,
        policy_matched=policy_matched,
    )


class WazuhAlertRequest(BaseModel):
    request_id: Optional[str] = None
    rule_id: str
    rule_level: int
    rule_groups: List[str]
    rule_description: str
    agent_ip: Optional[str] = None
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    data: Dict[str, Any] = {}
    full_log: Optional[str] = None
    previous_output: Optional[str] = None
    raw_event: Dict[str, Any] = {}


class DeviceAssessmentRequest(BaseModel):
    ip: str
    mac: str
    user_pid: str
    user_category: str
    firewall_enabled: Optional[bool] = None
    antivirus_enabled: Optional[bool] = None
    trigger_source: Optional[str] = None
    request_id: str


RULE_TARGET_FIELD_MAP: Dict[str, str] = {
    "100051": "data.srcip",
    "100081": "data.srcip",
    "100091": "data.srcip",
    "100003": "agent.ip",
    "100020": "agent.ip",
    "62152": "agent.ip",
    "110094": "agent.ip",
    "63104": "agent.ip",
    "200110": "data.netflow.ipv4_src_addr",
    "DLP_PII_EXFIL": "agent.ip",
}


def _get_nested_value(data: Dict[str, Any], path: str) -> Optional[Any]:
    current: Any = data
    for key in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(key)
        if current is None:
            return None
    return current


def _resolve_target_ip(request: WazuhAlertRequest) -> Optional[str]:
    if request.agent_ip and profile_manager.get_profile_by_ip(request.agent_ip):
        return request.agent_ip
    path = RULE_TARGET_FIELD_MAP.get(request.rule_id, "agent.ip")
    raw_target = _get_nested_value(request.raw_event, path)
    if isinstance(raw_target, str) and raw_target.strip():
        return raw_target.strip()
    return request.agent_ip


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "pdp-api"}


@app.post("/pdp/evaluate-alert", response_model=PdpApiDecision)
async def evaluate_wazuh_alert(request: WazuhAlertRequest):
    request_id = request.request_id or str(uuid.uuid4())
    logger.info(
        "pdp_evaluate_alert_start",
        request_id=request_id,
        rule_id=request.rule_id,
        rule_level=request.rule_level,
        agent_ip=request.agent_ip,
    )

    target_ip = _resolve_target_ip(request)
    if not target_ip:
        decision = SharedPolicyDecision(False, "no_action", "Target not resolved")
        return _to_api_decision(decision, "target_not_resolved")

    profile = profile_manager.get_profile_by_ip(target_ip)
    if not profile:
        decision = SharedPolicyDecision(False, "no_action", "Profile not found for target", metadata={"target_ip": target_ip})
        return _to_api_decision(decision, "profile_not_found")

    old_total = profile.risk_score.get("total_score", 0)
    decision = evaluate_alert_risk(
        current_score=old_total,
        rule_id=request.rule_id,
        rule_level=request.rule_level,
        rule_description=request.rule_description,
        current_posture=profile.posture_security,
        raw_event=request.raw_event,
    )

    if decision.risk_delta <= 0:
        policy_matched = "risk_not_configured" if decision.reason == "Rule has no configured penalty" else "risk_not_applicable"
        decision = SharedPolicyDecision(
            decision.allowed,
            decision.action,
            decision.reason,
            target_role=decision.target_role,
            risk_delta=decision.risk_delta,
            risk_level=decision.risk_level,
            metadata={**decision.metadata, "target_ip": target_ip},
        )
        profile_manager.add_system_event(
            mac=profile.device_id,
            action="Policy evaluated",
            reason=format_audit_reason(
                policy_name=policy_matched,
                decision=decision.action,
                reason=decision.reason,
                rule_id=request.rule_id,
                risk_delta=decision.risk_delta,
            ),
            event_id=request.rule_id,
            event_source="PDP",
        )
        return _to_api_decision(decision, policy_matched)

    new_total = decision.metadata["risk_score"]
    profile_manager.update_risk_score(profile.device_id, new_total, decision.risk_level)
    event_source = "DLP_PROXY" if request.raw_event.get("source") == "dlp_proxy" else "WAZUH_ALERT"
    profile_manager.add_system_event(
        mac=profile.device_id,
        event_id=request.rule_id,
        level=request.rule_level,
        action=f"Risk penalty +{decision.risk_delta}: {request.rule_description}",
        reason=format_audit_reason(
            policy_name="alert_risk_evaluation",
            decision=decision.action,
            reason=decision.reason,
            rule_id=request.rule_id,
            risk_delta=decision.risk_delta,
            risk_score=new_total,
            risk_level=decision.risk_level,
            target_role=decision.target_role,
        ),
        event_source=event_source,
    )

    logger.info("risk_score_updated", request_id=request_id, rule_id=request.rule_id, mac=profile.device_id, old_total=old_total, penalty=decision.risk_delta, new_total=new_total)

    if decision.action in {"isolate", "restrict"}:
        decision = await dispatch_alert_decision(
            decision,
            {
                "request_id": request_id,
                "mac": profile.device_id,
                "ip_address": profile.ip_address,
            },
        )
        policy_matched = "risk_score_isolation_threshold" if decision.action == "isolate" else "risk_score_downgrade_threshold"
        return _to_api_decision(decision, policy_matched)

    return _to_api_decision(decision, "risk_score_updated")


@app.post("/pdp/evaluate-device", response_model=PdpApiDecision)
async def evaluate_device_assessment(request: DeviceAssessmentRequest):
    logger.info("pdp_evaluate_device_start", request_id=request.request_id, ip=request.ip, mac=request.mac, user_pid=request.user_pid, user_category=request.user_category)

    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            sca_response = await client.post(f"{ACTION_API_URL}/actions/get-sca", json={"ip": request.ip})
            sca_response.raise_for_status()
            sca_data = sca_response.json()
            if not sca_data.get("success"):
                decision = SharedPolicyDecision(False, "no_action", "Could not retrieve SCA data", metadata={"reason": "Failed to get SCA score"})
                return _to_api_decision(decision, "error_no_sca")
            sca_score = sca_data.get("sca_score", 0)
            profile_manager.update_posture_security(mac=request.mac, sca_score=sca_score, firewall_enabled=request.firewall_enabled, antivirus_enabled=request.antivirus_enabled)
        except Exception as e:
            decision = SharedPolicyDecision(False, "no_action", "Failed to communicate with Action API", metadata={"reason": f"Action API error: {str(e)}"})
            return _to_api_decision(decision, "error_api_call")

        actual_role = None
        role_lookup_ok = False
        try:
            groups_response = await client.post(f"{ACTION_API_URL}/actions/get-user-groups", json={"username": request.user_pid})
            groups_response.raise_for_status()
            groups_data = groups_response.json()
            if groups_data.get("success"):
                actual_role = resolve_role_from_groups(groups_data.get("groups", []))
                role_lookup_ok = actual_role is not None
                if actual_role:
                    profile_manager.update_actual_role(request.mac, actual_role)
        except Exception:
            pass

        profile = profile_manager.get_profile(request.mac)
        if profile:
            profile_manager.update_user_info(mac=request.mac, username=profile.identity.get("username") or request.user_pid, auth_type=profile.identity.get("auth_type") or "802.1x-User", current_role=profile.identity.get("current_role") or "uncheck")

        previous_role = profile.identity.get("current_role") if profile else (request.user_category or "uncheck")
        decision = evaluate_posture_access(
            sca_score=sca_score,
            firewall_enabled=request.firewall_enabled,
            antivirus_enabled=request.antivirus_enabled,
            user_role=actual_role if role_lookup_ok else None,
            previous_role=previous_role,
        )

        policy_matched = "non_compliant_posture_keep_uncheck" if decision.action == "keep_uncheck" else "compliant_user_role_with_health"
        profile_manager.add_system_event(
            mac=request.mac,
            action="Policy evaluated",
            reason=format_audit_reason(
                policy_name=policy_matched,
                decision=decision.action,
                reason=decision.reason,
                target_role=decision.target_role,
                sca_score=sca_score,
                firewall_enabled=request.firewall_enabled,
                antivirus_enabled=request.antivirus_enabled,
            ),
            role=decision.target_role,
            event_source="PDP",
        )
        decision = await dispatch_device_decision(
            decision,
            {
                "request_id": request.request_id,
                "mac": request.mac,
                "previous_role": previous_role,
                "sca_score": sca_score,
            },
        )
        return _to_api_decision(decision, policy_matched)


if __name__ == "__main__":
    import uvicorn
    logger.info("Starting PDP API on port 8001")
    uvicorn.run("pdp_api:app", host="0.0.0.0", port=8001, reload=True)
