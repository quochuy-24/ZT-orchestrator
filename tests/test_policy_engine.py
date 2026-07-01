import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "orchestrator"))

from shared.policy_engine import (
    calculate_risk_penalty,
    calculate_risk_level,
    evaluate_alert_risk,
    evaluate_jit_access,
    evaluate_posture_access,
)


def test_calculate_risk_penalty_uses_level_map():
    assert calculate_risk_penalty(7, "unknown") == 15


def test_calculate_risk_level_thresholds():
    assert calculate_risk_level(0) == "UNKNOWN"
    assert calculate_risk_level(1) == "LOW"
    assert calculate_risk_level(31) == "MEDIUM"
    assert calculate_risk_level(61) == "HIGH"
    assert calculate_risk_level(81) == "CRITICAL"


def test_evaluate_posture_access_allows_role_when_posture_passes():
    decision = evaluate_posture_access(
        sca_score=30,
        firewall_enabled=True,
        antivirus_enabled=True,
        user_role="IT",
        previous_role="uncheck",
    )

    assert decision.allowed is True
    assert decision.action == "allow_role"
    assert decision.target_role == "IT"


def test_evaluate_posture_access_keeps_uncheck_when_firewall_off():
    decision = evaluate_posture_access(
        sca_score=30,
        firewall_enabled=False,
        antivirus_enabled=True,
        user_role="IT",
        previous_role="uncheck",
    )

    assert decision.allowed is False
    assert decision.action == "keep_uncheck"
    assert decision.target_role == "uncheck"


def test_evaluate_alert_risk_level_7_adds_penalty():
    decision = evaluate_alert_risk(
        current_score=0,
        rule_id="100001",
        rule_level=7,
        rule_description="User logon",
        current_posture={},
        raw_event={},
    )

    assert decision.risk_delta == 15
    assert decision.risk_level == "LOW"
    assert decision.metadata["risk_score"] == 15


def test_evaluate_alert_risk_isolates_when_over_threshold():
    decision = evaluate_alert_risk(
        current_score=80,
        rule_id="100001",
        rule_level=12,
        rule_description="Critical alert",
        current_posture={},
        raw_event={},
    )

    assert decision.action == "isolate"
    assert decision.allowed is False
    assert decision.risk_level == "CRITICAL"


def test_evaluate_jit_access_allows_it_role_resource():
    decision = evaluate_jit_access("IT", 10, "linux_ssh")

    assert decision.allowed is True
    assert decision.action == "allow_jit"
    assert decision.metadata["resource_id"] == "linux_ssh"


def test_evaluate_jit_access_denies_high_risk():
    decision = evaluate_jit_access("IT", 31, "linux_ssh")

    assert decision.allowed is False
    assert decision.action == "deny_jit"


def test_evaluate_jit_access_denies_unknown_role():
    decision = evaluate_jit_access("guest", 10, "linux_ssh")

    assert decision.allowed is False
    assert decision.action == "deny_jit"
