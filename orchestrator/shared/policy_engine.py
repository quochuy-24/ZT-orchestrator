"""Pure Policy Engine for Zero Trust decisions."""

from typing import Any, Dict, Optional, Tuple

from shared.policy_config import (
    GROUP_TO_ROLE,
    JIT_RESOURCES,
    JIT_ROLE_PERMISSIONS,
    POSTURE_POLICY,
    RISK_LEVEL_SCORE_MAP,
    RISK_SCORE_OVERRIDES,
    RISK_THRESHOLDS,
    ROLE_TO_CATEGORY_ID,
)
from shared.policy_models import PolicyDecision


def calculate_risk_penalty(rule_level: int, rule_id: str) -> int:
    if rule_id in RISK_SCORE_OVERRIDES:
        return RISK_SCORE_OVERRIDES[rule_id]
    return RISK_LEVEL_SCORE_MAP.get(rule_level, 0)


def calculate_risk_level(total_score: int) -> str:
    if total_score >= RISK_THRESHOLDS["isolate"]:
        return "CRITICAL"
    if total_score >= RISK_THRESHOLDS["restrict"]:
        return "HIGH"
    if total_score >= RISK_THRESHOLDS["medium"]:
        return "MEDIUM"
    if total_score > 0:
        return "LOW"
    return "UNKNOWN"


def resolve_role_from_groups(groups: list[str]) -> Optional[str]:
    for group in groups:
        if group in GROUP_TO_ROLE:
            return GROUP_TO_ROLE[group]
    return None


def resolve_category_id(role: str) -> Optional[int]:
    return ROLE_TO_CATEGORY_ID.get(role)


def _is_health_status_off(rule_id: str, raw_event: Dict[str, Any]) -> Tuple[bool, bool, bool]:
    if rule_id != "100020":
        return False, False, False
    win = raw_event.get("data", {}).get("win", {}) if isinstance(raw_event, dict) else {}
    win_system = win.get("system", {}) if isinstance(win, dict) else {}
    message = win_system.get("message") if isinstance(win_system, dict) else None
    text = str(message).lower() if message is not None else ""
    fw_off = '"firewall":"off"' in text
    av_off = '"antivirus":"off"' in text
    return fw_off or av_off, fw_off, av_off


def _is_bad_transition(rule_id: str, current_posture: Dict[str, Any], raw_event: Dict[str, Any]) -> bool:
    if rule_id == "62152":
        return current_posture.get("antivirus_enabled") is True
    if rule_id == "62151":
        return False
    is_health, fw_off, av_off = _is_health_status_off(rule_id, raw_event)
    if not is_health:
        return False
    fw_bad = fw_off and current_posture.get("firewall_enabled") is True
    av_bad = av_off and current_posture.get("antivirus_enabled") is True
    return fw_bad or av_bad


def should_apply_risk(rule_id: str, rule_level: int, current_posture: Dict[str, Any], raw_event: Dict[str, Any]) -> bool:
    if rule_id in {"100020", "62151", "62152"}:
        return _is_bad_transition(rule_id, current_posture, raw_event)
    return 7 <= rule_level <= 12


def evaluate_alert_risk(
    current_score: int,
    rule_id: str,
    rule_level: int,
    rule_description: str,
    current_posture: Dict[str, Any],
    raw_event: Dict[str, Any],
) -> PolicyDecision:
    if not should_apply_risk(rule_id, rule_level, current_posture, raw_event):
        return PolicyDecision(False, "no_action", "No risk penalty for this event/transition")

    penalty = calculate_risk_penalty(rule_level, rule_id)
    if penalty <= 0:
        return PolicyDecision(False, "no_action", "Rule has no configured penalty")

    new_total = current_score + penalty
    new_level = calculate_risk_level(new_total)
    reason = f"Risk score {new_total} from rule {rule_id}"
    metadata = {
        "risk_score": new_total,
        "rule_id": rule_id,
        "rule_level": rule_level,
        "rule_description": rule_description,
    }

    if new_total > RISK_THRESHOLDS["isolate"]:
        return PolicyDecision(False, "isolate", reason, risk_delta=penalty, risk_level=new_level, metadata=metadata)
    if new_total > RISK_THRESHOLDS["restrict"]:
        return PolicyDecision(False, "restrict", reason, target_role="restricted", risk_delta=penalty, risk_level=new_level, metadata={**metadata, "target_role": "restricted"})
    return PolicyDecision(True, "no_action", f"Risk score updated to {new_total} (below threshold)", risk_delta=penalty, risk_level=new_level, metadata=metadata)


def evaluate_posture_access(
    sca_score: int,
    firewall_enabled: Optional[bool],
    antivirus_enabled: Optional[bool],
    user_role: Optional[str],
    previous_role: str,
) -> PolicyDecision:
    sca_pass = sca_score >= POSTURE_POLICY["sca_min_score"]
    firewall_pass = (not POSTURE_POLICY["firewall_required"]) or firewall_enabled is True
    antivirus_pass = (not POSTURE_POLICY["antivirus_required"]) or antivirus_enabled is True

    if sca_pass and firewall_pass and antivirus_pass and user_role:
        reason = f"SCA pass + firewall ON + antivirus ON, assign role {user_role}"
        return PolicyDecision(True, "allow_role", reason, target_role=user_role)

    reason = f"SCA score {sca_score} posture not compliant; assign role uncheck"
    return PolicyDecision(False, "keep_uncheck", reason, target_role="uncheck")


def evaluate_jit_access(role: Optional[str], risk_score: int, resource_id: Optional[str] = None) -> PolicyDecision:
    if not role or role not in JIT_ROLE_PERMISSIONS:
        return PolicyDecision(False, "deny_jit", f"Role {role} has no JIT permissions")
    if risk_score > RISK_THRESHOLDS["jit_max"]:
        return PolicyDecision(False, "deny_jit", f"Risk score {risk_score} blocks JIT access")

    allowed_resources = JIT_ROLE_PERMISSIONS.get(role, [])
    visible_resources = [res_id for res_id in allowed_resources if res_id in JIT_RESOURCES]

    if resource_id is None:
        if not visible_resources:
            return PolicyDecision(False, "deny_jit", f"Role {role} has no JIT resources", metadata={"allowed_resources": []})
        return PolicyDecision(True, "allow_jit", "JIT resources allowed", metadata={"allowed_resources": visible_resources})

    if resource_id not in allowed_resources or resource_id not in JIT_RESOURCES:
        return PolicyDecision(False, "deny_jit", f"Role {role} denied JIT resource {resource_id}")
    return PolicyDecision(True, "allow_jit", f"JIT resource {resource_id} allowed", metadata={"resource_id": resource_id})
