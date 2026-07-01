"""JIT Access Router - API Endpoints"""

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from typing import Dict, Optional
import asyncio
import random
import sys
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "orchestrator"))

from shared.audit_utils import format_audit_reason
from shared.policy_config import JIT_ACCESS_DURATION_MINUTES, JIT_OTP_TTL_SECONDS, JIT_RESOURCES
from shared.policy_engine import evaluate_jit_access
from shared.profile_manager import profile_manager
from services.telegram import send_otp_telegram
from services.vyos import add_firewall_rule, remove_firewall_rule

router = APIRouter()

# In-memory storage
otp_cache: Dict[str, Dict] = {}
active_sessions: Dict[str, Dict] = {}

# User to Telegram chat_id mapping
USER_TELEGRAM_MAPPING = {
    "quochuy": "5372788511",
    "LAB\\quochuy": "5372788511",
    "LAB\\minhtam": "7940121851",
    "minhtam":"7940121851"
}


def _get_forwarded_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if not forwarded_for:
        raise HTTPException(status_code=400, detail="Missing X-Forwarded-For header")
    return forwarded_for.split(",")[0].strip()


def get_profile_by_ip(ip: str) -> Optional[Dict]:
    """Get device profile by IP from ProfileManager"""
    for mac, profile in profile_manager.list_profiles().items():
        if profile.ip_address == ip:
            username = profile.identity.get("username")
            role = profile.identity.get("current_role")
            risk_score = profile.risk_score.get("total_score", 0)

            telegram_chat_id = USER_TELEGRAM_MAPPING.get(username)

            return {
                "ip": ip,
                "mac": mac,
                "username": username,
                "role": role,
                "risk_score": risk_score,
                "telegram_chat_id": telegram_chat_id
            }
    return None


def _audit_jit_event(profile: Optional[Dict], action: str, reason: str, event_id: Optional[str] = None):
    if not profile:
        return
    profile_manager.add_system_event(
        mac=profile["mac"],
        action=action,
        reason=reason,
        role=profile.get("role"),
        event_id=event_id,
        event_source="JIT_PORTAL",
    )


class RequestOTPPayload(BaseModel):
    resource_id: str


class GrantAccessPayload(BaseModel):
    resource_id: str
    otp_code: str
    duration_minutes: int = JIT_ACCESS_DURATION_MINUTES


@router.get("/resources")
async def get_resources(request: Request):
    """Get list of available resources for JIT access"""
    client_ip = _get_forwarded_client_ip(request)

    profile = get_profile_by_ip(client_ip)

    if not profile:
        raise HTTPException(status_code=403, detail="Device not found in system")

    decision = evaluate_jit_access(profile["role"], profile["risk_score"])
    if not decision.allowed:
        _audit_jit_event(
            profile,
            "JIT resources denied",
            f"{decision.reason} from {client_ip}",
        )
        detail = "Access denied: Device has high risk score" if "Risk score" in decision.reason else "Access denied: Your role does not have JIT access permissions"
        raise HTTPException(status_code=403, detail=detail)

    resources_list = [
        {"id": res_id, **JIT_RESOURCES[res_id]}
        for res_id in decision.metadata["allowed_resources"]
    ]

    _audit_jit_event(
        profile,
        "JIT resources viewed",
        f"User {profile['username']} viewed {len(resources_list)} JIT resources from {client_ip}",
    )

    return {
        "username": profile["username"],
        "role": profile["role"],
        "resources": resources_list
    }


@router.post("/request-otp")
async def request_otp(payload: RequestOTPPayload, request: Request):
    """Request OTP for resource access"""
    client_ip = _get_forwarded_client_ip(request)

    profile = get_profile_by_ip(client_ip)

    if not profile:
        raise HTTPException(status_code=403, detail="Device not found")

    decision = evaluate_jit_access(profile["role"], profile["risk_score"], payload.resource_id)
    if not decision.allowed:
        _audit_jit_event(
            profile,
            "JIT OTP denied",
            f"{decision.reason} from {client_ip}",
            event_id=payload.resource_id,
        )
        detail = "Risk score too high" if "Risk score" in decision.reason else "Access denied to this resource"
        raise HTTPException(status_code=403, detail=detail)

    resource = JIT_RESOURCES[payload.resource_id]

    if not profile["telegram_chat_id"]:
        _audit_jit_event(
            profile,
            "JIT OTP denied",
            f"Telegram chat ID missing for {profile['username']} requesting {resource['name']}",
            event_id=payload.resource_id,
        )
        raise HTTPException(
            status_code=400,
            detail="Telegram chat ID not configured for this user"
        )

    otp_code = str(random.randint(100000, 999999))

    otp_cache[client_ip] = {
        "otp": otp_code,
        "resource_id": payload.resource_id,
        "expires_at": time.time() + JIT_OTP_TTL_SECONDS,
        "username": profile["username"]
    }

    sent = await send_otp_telegram(
        chat_id=profile["telegram_chat_id"],
        username=profile["username"],
        resource_name=resource["name"],
        otp_code=otp_code
    )

    if not sent:
        otp_cache.pop(client_ip, None)
        _audit_jit_event(
            profile,
            "JIT OTP send failed",
            format_audit_reason(
                policy_name="jit_otp_send",
                decision="deny_jit",
                reason="Failed to send OTP",
                resource=payload.resource_id,
                source_ip=client_ip,
            ),
            event_id=payload.resource_id,
        )
        raise HTTPException(status_code=502, detail="Failed to send OTP")

    _audit_jit_event(
        profile,
        "JIT OTP requested",
        format_audit_reason(
            policy_name="jit_otp_request",
            decision="allow_jit",
            reason="OTP sent",
            resource=payload.resource_id,
            source_ip=client_ip,
        ),
        event_id=payload.resource_id,
    )

    return {
        "status": "success",
        "message": "OTP sent to your Telegram",
        "expires_in_seconds": JIT_OTP_TTL_SECONDS
    }


@router.post("/grant-access")
async def grant_access(payload: GrantAccessPayload, request: Request):
    """Grant JIT access after OTP verification"""
    client_ip = _get_forwarded_client_ip(request)

    profile = get_profile_by_ip(client_ip)

    if client_ip not in otp_cache:
        _audit_jit_event(
            profile,
            "JIT OTP denied",
            f"No OTP request found for {payload.resource_id} from {client_ip}",
            event_id=payload.resource_id,
        )
        raise HTTPException(status_code=400, detail="No OTP request found")

    cached = otp_cache[client_ip]

    if time.time() > cached["expires_at"]:
        del otp_cache[client_ip]
        _audit_jit_event(
            profile,
            "JIT OTP denied",
            f"Expired OTP for {payload.resource_id} from {client_ip}",
            event_id=payload.resource_id,
        )
        raise HTTPException(status_code=400, detail="OTP expired")

    if cached["otp"] != payload.otp_code:
        _audit_jit_event(
            profile,
            "JIT OTP denied",
            f"Invalid OTP for {payload.resource_id} from {client_ip}",
            event_id=payload.resource_id,
        )
        raise HTTPException(status_code=400, detail="Invalid OTP")

    if cached["resource_id"] != payload.resource_id:
        _audit_jit_event(
            profile,
            "JIT OTP denied",
            f"Resource mismatch cached={cached['resource_id']} requested={payload.resource_id} from {client_ip}",
            event_id=payload.resource_id,
        )
        raise HTTPException(status_code=400, detail="Resource mismatch")

    if not profile:
        raise HTTPException(status_code=403, detail="Device not found")

    decision = evaluate_jit_access(profile["role"], profile["risk_score"], payload.resource_id)
    if not decision.allowed:
        _audit_jit_event(
            profile,
            "JIT access denied",
            f"{decision.reason} during grant from {client_ip}",
            event_id=payload.resource_id,
        )
        detail = "Risk score changed, access denied" if "Risk score" in decision.reason else "Access denied to this resource"
        raise HTTPException(status_code=403, detail=detail)

    resource = JIT_RESOURCES[payload.resource_id]

    try:
        rule_id = await add_firewall_rule(
            source_ip=client_ip,
            dest_ip=resource["ip"],
            dest_port=resource["port"],
            username=profile["username"]
        )
    except Exception as e:
        _audit_jit_event(
            profile,
            "JIT access failed",
            format_audit_reason(
                policy_name="jit_access_grant",
                decision="no_action",
                reason=f"VyOS rule creation failed: {e}",
                resource=payload.resource_id,
                source_ip=client_ip,
                destination=f"{resource['ip']}:{resource['port']}",
            ),
            event_id=payload.resource_id,
        )
        raise HTTPException(status_code=502, detail="Failed to create temporary firewall rule") from e

    del otp_cache[client_ip]

    session_id = f"{client_ip}_{payload.resource_id}_{int(time.time())}"
    active_sessions[session_id] = {
        "client_ip": client_ip,
        "resource_id": payload.resource_id,
        "rule_id": rule_id,
        "granted_at": time.time(),
        "expires_at": time.time() + (payload.duration_minutes * 60)
    }

    _audit_jit_event(
        profile,
        "JIT access granted",
        format_audit_reason(
            policy_name="jit_access_grant",
            decision="allow_jit",
            reason="Access granted",
            resource=payload.resource_id,
            source_ip=client_ip,
            destination=f"{resource['ip']}:{resource['port']}",
            duration_minutes=payload.duration_minutes,
            rule_id=rule_id,
        ),
        event_id=session_id,
    )

    async def revoke_access():
        print(f"[JIT] Scheduled revoke for session {session_id} in {payload.duration_minutes} minutes")
        await asyncio.sleep(payload.duration_minutes * 60)
        print(f"[JIT] Revoking access for session {session_id}, rule {rule_id}")
        try:
            await remove_firewall_rule(rule_id)
            _audit_jit_event(
                profile,
                "JIT access revoked",
                format_audit_reason(
                    policy_name="jit_access_revoke",
                    decision="deny_jit",
                    reason="Access revoked",
                    resource=payload.resource_id,
                    source_ip=client_ip,
                    destination=f"{resource['ip']}:{resource['port']}",
                    rule_id=rule_id,
                ),
                event_id=session_id,
            )
            print(f"[JIT] Successfully revoked access for session {session_id}")
        except Exception as e:
            _audit_jit_event(
                profile,
                "JIT revoke failed",
                format_audit_reason(
                    policy_name="jit_revoke_failure",
                    decision="no_action",
                    reason=f"Revoke failed: {e}",
                    resource=payload.resource_id,
                    source_ip=client_ip,
                    destination=f"{resource['ip']}:{resource['port']}",
                    rule_id=rule_id,
                ),
                event_id=session_id,
            )
            print(f"[JIT] Failed to revoke access for session {session_id}: {e}")
        if session_id in active_sessions:
            del active_sessions[session_id]

    threading.Thread(target=lambda: asyncio.run(revoke_access()), daemon=True).start()

    return {
        "status": "success",
        "message": f"Access granted for {payload.duration_minutes} minutes",
        "resource": resource["name"],
        "expires_in_minutes": payload.duration_minutes
    }
