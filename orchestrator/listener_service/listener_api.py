"""Listener Service - Receive PacketFence webhooks and poll for user login"""

from fastapi import FastAPI, BackgroundTasks, Query, Request, HTTPException
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional
import httpx
import asyncio
import re
import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.audit_utils import format_audit_reason
from shared.logger import get_logger, setup_logging
from shared.profile_manager import profile_manager
from action_service.clients.packetfence_client import PacketFenceClient

setup_logging("INFO", service_name="listener")
logger = get_logger(__name__)

app = FastAPI(title="Listener Service", version="1.0.0")
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

PACKETFENCE_URL = "https://192.168.29.91:9999"
PACKETFENCE_USER = "admin"
PACKETFENCE_PASSWORD = "123"
PDP_URL = "http://localhost:8001/pdp/evaluate-device"
PDP_ALERT_URL = "http://localhost:8001/pdp/evaluate-alert"
ACTION_API_URL = "http://localhost:8002"

ALERT_TARGET_FIELD_MAP = {
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


class DeviceDiscoveredEvent(BaseModel):
    mac: str
    ip: str
    hostname: Optional[str] = None
    event: Optional[str] = None
    timestamp: Optional[str] = None


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "listener"}


@app.get("/ui/devices")
async def device_management_ui(request: Request):
    return templates.TemplateResponse("device_management.html", {"request": request})


@app.get("/devices")
async def get_devices(
    q: Optional[str] = None,
    state: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    return profile_manager.list_devices_paginated(q=q, state=state, limit=limit, offset=offset)




async def _post_action(endpoint: str, payload: dict, request_id: str):
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(f"{ACTION_API_URL}{endpoint}", json={**payload, "request_id": request_id})
            response.raise_for_status()
            result = response.json()
    except httpx.HTTPError as e:
        logger.error("action_proxy_failed", request_id=request_id, endpoint=endpoint, error=str(e))
        raise HTTPException(status_code=502, detail=str(e)) from e

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error") or "Action failed")
    return result


@app.post("/devices/{mac}/release")
async def release_device(mac: str):
    import uuid
    request_id = str(uuid.uuid4())
    logger.info("device_release_requested", request_id=request_id, mac=mac)
    return await _post_action(
        "/actions/restore-actual-role",
        {"mac": mac, "reason": "Manual release from device management UI"},
        request_id,
    )


@app.post("/devices/{mac}/restrict")
async def restrict_device(mac: str):
    import uuid
    request_id = str(uuid.uuid4())
    logger.info("device_restrict_requested", request_id=request_id, mac=mac)
    return await _post_action(
        "/actions/change-role",
        {"mac": mac, "target_role": "restricted", "reason": "Manual restrict from device management UI"},
        request_id,
    )


@app.post("/devices/{mac}/isolate")
async def isolate_device(mac: str):
    import uuid
    request_id = str(uuid.uuid4())
    logger.info("device_isolate_requested", request_id=request_id, mac=mac)

    profile = profile_manager.get_profile(mac)
    if not profile or not profile.ip_address:
        raise HTTPException(status_code=400, detail="Device IP not found in profile")

    return await _post_action(
        "/actions/isolate",
        {
            "agent_ip": profile.ip_address,
            "security_event_id": str(13000003),
            "reason": "Manual isolate from device management UI",
        },
        request_id,
    )


@app.get("/devices/{mac}/netflow")
async def get_device_netflow(mac: str, minutes: int = Query(default=5, ge=1, le=60)):
    import uuid
    request_id = str(uuid.uuid4())
    logger.info("device_netflow_requested", request_id=request_id, mac=mac, minutes=minutes)

    profile = profile_manager.get_profile(mac)
    if not profile or not profile.ip_address:
        raise HTTPException(status_code=400, detail="Device IP not found in profile")

    return await _post_action(
        "/actions/get-netflow",
        {"ip": profile.ip_address, "minutes": minutes},
        request_id,
    )


@app.get("/devices/{mac}/audit-logs")
async def get_device_audit_logs(
    mac: str,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    return profile_manager.get_audit_logs_paginated(mac=mac, limit=limit, offset=offset)


@app.post("/webhook/test/")
async def webhook_test(payload: dict):
    """Test endpoint - receive and log raw webhook data"""
    import uuid
    request_id = str(uuid.uuid4())

    logger.info("webhook_test_received",
                request_id=request_id,
                payload=payload)

    return {
        "status": "received",
        "request_id": request_id,
        "message": "Test webhook received successfully",
        "received_data": payload
    }


def _is_valid_dlp_client_ip(value: object) -> bool:
    if not isinstance(value, str):
        return False
    ip = value.strip()
    return bool(ip) and ip not in {"127.0.0.1", "::1", "0.0.0.0", "localhost"}


def _first_forwarded_ip(value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    first_ip = value.split(",")[0].strip()
    return first_ip if _is_valid_dlp_client_ip(first_ip) else None


def _resolve_dlp_client_ip(payload: dict, request: Request) -> Optional[str]:
    agent = payload.get("agent", {}) if isinstance(payload, dict) else {}
    network = payload.get("network", {}) if isinstance(payload, dict) else {}

    candidates = [
        agent.get("ip") if isinstance(agent, dict) else None,
        network.get("src_ip") if isinstance(network, dict) else None,
        _first_forwarded_ip(request.headers.get("x-forwarded-for")),
        _first_forwarded_ip(request.headers.get("x-client-ip")),
        _first_forwarded_ip(request.headers.get("x-real-ip")),
    ]

    for candidate in candidates:
        if _is_valid_dlp_client_ip(candidate):
            return str(candidate).strip()
    return None


def _normalize_dlp_alert(payload: dict, client_ip: str) -> dict:
    normalized = dict(payload)
    rule = normalized.get("rule", {}) if isinstance(normalized.get("rule"), dict) else {}
    agent = normalized.get("agent", {}) if isinstance(normalized.get("agent"), dict) else {}
    network = normalized.get("network", {}) if isinstance(normalized.get("network"), dict) else {}
    dlp = normalized.get("dlp", {}) if isinstance(normalized.get("dlp"), dict) else {}

    normalized["source"] = normalized.get("source") or "dlp_proxy"
    normalized["rule"] = {
        "id": str(rule.get("id") or "DLP_PII_EXFIL"),
        "level": int(rule.get("level", 10) or 10),
        "description": str(rule.get("description") or "DLP alert received"),
    }
    normalized["agent"] = {
        **agent,
        "ip": client_ip,
    }
    normalized["data"] = {
        "dlp": dlp,
        "network": network,
        "source": normalized["source"],
        "event_id": normalized.get("event_id"),
        "timestamp": normalized.get("timestamp"),
    }
    normalized["full_log"] = format_audit_reason(
        policy_name="dlp_proxy_alert",
        decision="alert_received",
        reason=normalized["rule"]["description"],
        action=dlp.get("action"),
        data_type=dlp.get("data_type"),
        match_count=dlp.get("match_count"),
        destination=f"{network.get('dst_ip')}:{network.get('dst_port')}",
        url=network.get("url"),
    )
    return normalized


@app.post("/webhook/dlp-alert")
async def dlp_alert(payload: dict, request: Request, background_tasks: BackgroundTasks):
    import uuid
    request_id = str(uuid.uuid4())
    client_ip = _resolve_dlp_client_ip(payload, request)
    rule = payload.get("rule", {}) if isinstance(payload.get("rule"), dict) else {}
    dlp = payload.get("dlp", {}) if isinstance(payload.get("dlp"), dict) else {}

    logger.info(
        "dlp_alert_received",
        request_id=request_id,
        event_id=payload.get("event_id"),
        rule_id=rule.get("id"),
        rule_level=rule.get("level"),
        client_ip=client_ip,
        action=dlp.get("action"),
        match_count=dlp.get("match_count"),
    )

    if not client_ip:
        logger.warning(
            "dlp_client_ip_unresolved",
            request_id=request_id,
            event_id=payload.get("event_id"),
            agent_ip=(payload.get("agent") or {}).get("ip") if isinstance(payload.get("agent"), dict) else None,
        )
        raise HTTPException(status_code=400, detail="DLP client IP not resolved")

    normalized_payload = _normalize_dlp_alert(payload, client_ip)
    background_tasks.add_task(forward_alert_to_pdp, normalized_payload, request_id)

    return {
        "status": "received",
        "request_id": request_id,
        "message": "DLP alert forwarded to PDP",
        "client_ip": client_ip,
    }


@app.post("/webhook/wazuh-alert/")
async def wazuh_alert(payload: dict, background_tasks: BackgroundTasks):
    """Receive Wazuh alert webhook - route based on rule ID"""
    import uuid
    request_id = str(uuid.uuid4())

    # Support both direct Wazuh webhook payload and OpenSearch document format with _source wrapper
    event_payload = payload.get("_source", payload)

    rule = event_payload.get("rule", {})
    rule_id = str(rule.get("id", ""))

    logger.info("wazuh_alert_received",
                request_id=request_id,
                rule_id=rule_id,
                rule_description=rule.get("description"))

    # Route based on rule ID
    if rule_id == "100001":  # User logon
        background_tasks.add_task(handle_user_logon, event_payload, request_id)
        return {
            "status": "received",
            "request_id": request_id,
            "message": "User logon event forwarded to handler"
        }

    elif rule_id == "100010":  # User logoff (interactive, user-initiated)
        background_tasks.add_task(handle_user_logoff, event_payload, request_id)
        return {
            "status": "received",
            "request_id": request_id,
            "message": "User logoff event forwarded to handler"
        }

    elif rule_id == "100020":  # Endpoint health status
        background_tasks.add_task(handle_endpoint_health_status, event_payload, request_id)
        return {
            "status": "received",
            "request_id": request_id,
            "message": "Endpoint health status updated and forwarded to PDP"
        }

    elif rule_id == "62152":  # Defender real-time protection disabled
        background_tasks.add_task(handle_windows_defender_status, event_payload, request_id, False)
        return {
            "status": "received",
            "request_id": request_id,
            "message": "Windows Defender disabled status updated and forwarded to PDP"
        }

    elif rule_id == "62151":  # Defender real-time protection enabled
        background_tasks.add_task(handle_windows_defender_status, event_payload, request_id, True)
        return {
            "status": "received",
            "request_id": request_id,
            "message": "Windows Defender enabled status updated and forwarded to PDP"
        }

    else:  # Generic alert (malware, etc.)
        background_tasks.add_task(
            forward_alert_to_pdp,
            event_payload,
            request_id
        )

        return {
            "status": "received",
            "request_id": request_id,
            "message": "Wazuh alert forwarded to PDP"
        }


@app.post("/webhook/device-discovered")
async def device_discovered(event: DeviceDiscoveredEvent, background_tasks: BackgroundTasks):
    """Receive device discovered webhook from PacketFence"""
    import uuid
    request_id = str(uuid.uuid4())

    logger.info("device_discovered",
                request_id=request_id,
                mac=event.mac,
                ip=event.ip,
                hostname=event.hostname,
                event_type=event.event,
                webhook_timestamp=event.timestamp)

    # Create device profile
    profile = profile_manager.create_profile(event.mac, event.ip, event.hostname)
    logger.info("profile_created",
                request_id=request_id,
                device_id=profile.device_id,
                state=profile.state)

    background_tasks.add_task(enrich_profile_operating_system, event.mac, request_id)
    background_tasks.add_task(enrich_profile_sca, event.mac, event.ip, request_id)

    # NOTE: Polling disabled - now using Wazuh logon events (rule 100001)
    # Uncomment below to re-enable polling as fallback:
    # background_tasks.add_task(process_device, event.mac, event.ip, event.hostname, request_id)

    return {"status": "received", "request_id": request_id}


def _resolve_operating_system(device_type: object, dhcp_vendor: object) -> Optional[str]:
    if isinstance(device_type, str) and device_type.strip():
        return device_type.strip()
    if isinstance(dhcp_vendor, str) and "msft" in dhcp_vendor.lower():
        return "Windows"
    return None


def _resolve_hostname(primary_hostname: object, computername: object) -> Optional[str]:
    if isinstance(primary_hostname, str) and primary_hostname.strip():
        return primary_hostname.strip()
    if isinstance(computername, str) and computername.strip():
        return computername.strip()
    return None


async def enrich_profile_operating_system(mac: str, request_id: str, max_retries: int = 6, delay_seconds: int = 5):
    last_operating_system = None
    last_hostname = None
    last_switch_ip = None
    last_switch_port = None

    for attempt in range(1, max_retries + 1):
        try:
            async with PacketFenceClient() as pf:
                node = await pf.get_node_by_mac(mac)
                if not node:
                    logger.warning("discovery_enrichment_node_not_found", request_id=request_id, mac=mac, attempt=attempt)
                    if attempt < max_retries:
                        await asyncio.sleep(delay_seconds)
                    continue

                operating_system = _resolve_operating_system(node.get("device_type"), node.get("dhcp_vendor"))
                hostname = _resolve_hostname(node.get("hostname"), node.get("computername"))
                switch_ip = node.get("last_switch")
                switch_port = node.get("last_ifDesc")

                if not operating_system and not hostname and not switch_ip and not switch_port:
                    logger.info("discovery_enrichment_no_signal", request_id=request_id, mac=mac, attempt=attempt)
                    if attempt < max_retries:
                        await asyncio.sleep(delay_seconds)
                    continue

                profile_manager.update_discovery_metadata(
                    mac=mac,
                    operating_system=operating_system,
                    hostname=hostname,
                    switch_ip=switch_ip,
                    switch_port=switch_port,
                    topology_source="packetfence",
                )

                last_operating_system = operating_system or last_operating_system
                last_hostname = hostname or last_hostname
                last_switch_ip = switch_ip or last_switch_ip
                last_switch_port = switch_port or last_switch_port

                logger.info(
                    "discovery_enrichment_updated",
                    request_id=request_id,
                    mac=mac,
                    attempt=attempt,
                    operating_system=operating_system,
                    hostname=hostname,
                    switch_ip=switch_ip,
                    switch_port=switch_port,
                    source="packetfence",
                )

                if last_operating_system and last_hostname:
                    logger.info(
                        "discovery_enrichment_completed",
                        request_id=request_id,
                        mac=mac,
                        attempt=attempt,
                        operating_system=last_operating_system,
                        hostname=last_hostname,
                        switch_ip=last_switch_ip,
                        switch_port=last_switch_port,
                    )
                    return
        except Exception as e:
            logger.warning("discovery_enrichment_failed", request_id=request_id, mac=mac, attempt=attempt, error=str(e))

        if attempt < max_retries:
            await asyncio.sleep(delay_seconds)

    logger.warning(
        "discovery_enrichment_partial",
        request_id=request_id,
        mac=mac,
        max_retries=max_retries,
        operating_system=last_operating_system,
        hostname=last_hostname,
        switch_ip=last_switch_ip,
        switch_port=last_switch_port,
    )


async def enrich_profile_sca(mac: str, ip: str, request_id: str, max_retries: int = 6, delay_seconds: int = 10):
    for attempt in range(1, max_retries + 1):
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(f"{ACTION_API_URL}/actions/get-sca", json={"ip": ip, "request_id": request_id})
                response.raise_for_status()
                result = response.json()

            if not result.get("success"):
                logger.info(
                    "pre_login_sca_not_ready",
                    request_id=request_id,
                    mac=mac,
                    ip=ip,
                    attempt=attempt,
                    error=result.get("error"),
                )
                if attempt < max_retries:
                    await asyncio.sleep(delay_seconds)
                continue

            sca_score = result.get("sca_score", 0)
            profile_manager.update_posture_security(mac=mac, sca_score=sca_score)
            profile_manager.add_system_event(
                mac=mac,
                action="Pre-login SCA updated",
                reason=format_audit_reason(
                    policy_name="pre_login_sca_enrichment",
                    decision="no_action",
                    reason="SCA enriched before user login",
                    sca_score=sca_score,
                    agent_id=result.get("agent_id"),
                ),
                event_id=result.get("agent_id"),
                event_source="LISTENER",
            )
            logger.info(
                "pre_login_sca_updated",
                request_id=request_id,
                mac=mac,
                ip=ip,
                attempt=attempt,
                sca_score=sca_score,
                agent_id=result.get("agent_id"),
            )
            return
        except Exception as e:
            logger.warning("pre_login_sca_failed", request_id=request_id, mac=mac, ip=ip, attempt=attempt, error=str(e))

        if attempt < max_retries:
            await asyncio.sleep(delay_seconds)

    profile_manager.add_system_event(
        mac=mac,
        action="Pre-login SCA unavailable",
        reason=format_audit_reason(
            policy_name="pre_login_sca_enrichment",
            decision="no_action",
            reason="SCA unavailable before user login",
            attempts=max_retries,
        ),
        event_source="LISTENER",
    )
    logger.warning("pre_login_sca_unavailable", request_id=request_id, mac=mac, ip=ip, max_retries=max_retries)


async def process_device(mac: str, ip: str, hostname: Optional[str], request_id: str):
    """Poll for user login then forward to PDP"""

    logger.info("polling_start", request_id=request_id, mac=mac)

    async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
        token = await authenticate_packetfence(client)

        if not token:
            logger.error("auth_failed", request_id=request_id)
            return

        user_info = await poll_for_user_login(client, token, mac, request_id)

        if not user_info:
            logger.warning("user_login_timeout", request_id=request_id, mac=mac)
            return

        logger.info("user_logged_in",
                   request_id=request_id,
                   mac=mac,
                   pid=user_info["pid"],
                   category=user_info["category"])

        # Update profile with user info
        profile = profile_manager.get_profile(mac)
        if profile:
            profile_manager.update_user_info(
                mac=mac,
                username=user_info["pid"],
                auth_type="802.1x-User",
                current_role=user_info["category"]
            )
            session = profile_manager.Session()
            try:
                from shared.db_models import Device
                device_row = session.query(Device).filter_by(device_id=mac).first()
                if device_row:
                    device_row.nas_ip = user_info.get("last_switch")
                    device_row.switch_port = user_info.get("last_port")
                    session.commit()
            finally:
                session.close()

            # Additional legacy fields are no longer persisted in SQLite schema:
            # stripped_user_name, last_dot1x_username, last_connection_type

            profile = profile_manager.get_profile(mac)
            if profile:
                profile.identity["nas_ip"] = user_info.get("last_switch")
                profile.identity["switch_port"] = user_info.get("last_port")
                if user_info.get("stripped_user_name"):
                    profile.identity["stripped_user_name"] = user_info["stripped_user_name"]
                if user_info.get("last_dot1x_username"):
                    profile.identity["last_dot1x_username"] = user_info["last_dot1x_username"]
                if user_info.get("last_connection_type"):
                    profile.identity["last_connection_type"] = user_info["last_connection_type"]

        logger.info("profile_updated_user_info",
                   request_id=request_id,
                   mac=mac,
                   username=user_info["pid"],
                   nas_ip=user_info.get("last_switch"),
                   switch_port=user_info.get("last_port"))

        await forward_to_pdp(client, ip, mac, user_info, request_id)




async def authenticate_packetfence(client: httpx.AsyncClient) -> Optional[str]:
    """Authenticate with PacketFence and get token"""
    try:
        response = await client.post(
            f"{PACKETFENCE_URL}/api/v1/login",
            json={"username": PACKETFENCE_USER, "password": PACKETFENCE_PASSWORD}
        )
        response.raise_for_status()
        token = response.json().get("token")
        logger.info("packetfence_authenticated")
        return token
    except Exception as e:
        logger.error("packetfence_auth_error", error=str(e))
        return None


async def poll_for_user_login(client: httpx.AsyncClient, token: str, mac: str, request_id: str, max_retries: int = 10, delay: int = 10):
    """Poll PacketFence until user logs in (category == uncheck)"""

    for attempt in range(1, max_retries + 1):
        logger.info("polling_attempt",
                   request_id=request_id,
                   mac=mac,
                   attempt=attempt,
                   max_retries=max_retries)

        try:
            response = await client.get(
                f"{PACKETFENCE_URL}/api/v1/node/{mac}",
                headers={"Authorization": f"Bearer {token}"}
            )
            response.raise_for_status()
            data = response.json()
            item = data.get("item", {})

            category = item.get("category", "")
            pid = item.get("pid", "default")

            if category == "uncheck":
                logger.info("user_found",
                           request_id=request_id,
                           mac=mac,
                           pid=pid,
                           category=category,
                           attempt=attempt)
                return {
                    "pid": pid,
                    "category": category,
                    "stripped_user_name": item.get("stripped_user_name"),
                    "last_dot1x_username": item.get("last_dot1x_username"),
                    "last_switch": item.get("last_switch"),
                    "last_port": item.get("last_port"),
                    "last_connection_type": item.get("last_connection_type")
                }

            logger.info("user_not_ready",
                       request_id=request_id,
                       mac=mac,
                       category=category,
                       pid=pid)

            if attempt < max_retries:
                await asyncio.sleep(delay)

        except Exception as e:
            logger.error("polling_error",
                        request_id=request_id,
                        attempt=attempt,
                        error=str(e))
            if attempt < max_retries:
                await asyncio.sleep(delay)

    return None


async def forward_to_pdp(client: httpx.AsyncClient, ip: str, mac: str, user_info: dict, request_id: str):
    """Forward device info to PDP for evaluation"""

    payload = {
        "ip": ip,
        "mac": mac,
        "user_pid": user_info["pid"],
        "user_category": user_info["category"],
        "request_id": request_id
    }

    logger.info("forwarding_to_pdp", request_id=request_id, payload=payload)

    try:
        response = await client.post(PDP_URL, json=payload, timeout=60.0)
        response.raise_for_status()
        result = response.json()
        logger.info("pdp_response", request_id=request_id, result=result)
    except Exception as e:
        logger.error("pdp_forward_failed", request_id=request_id, error=str(e))


async def _resolve_mac_by_ip_from_packetfence(client: httpx.AsyncClient, ip: str, request_id: str) -> Optional[str]:
    """Resolve latest MAC from PacketFence ip4logs by IP."""
    try:
        token = await authenticate_packetfence(client)
        if not token:
            logger.warning("packetfence_token_unavailable",
                           request_id=request_id,
                           ip=ip)
            return None

        payload = {
            "cursor": 0,
            "fields": ["end_time", "ip", "mac", "start_time"],
            "limit": 1,
            "query": {
                "op": "and",
                "values": [
                    {
                        "field": "ip",
                        "op": "equals",
                        "value": ip
                    }
                ]
            },
            "sort": ["start_time DESC"]
        }

        response = await client.post(
            f"{PACKETFENCE_URL}/api/v1/ip4logs/search",
            headers={"Authorization": f"Bearer {token}"},
            json=payload
        )
        response.raise_for_status()
        data = response.json()
        items = data.get("items", [])
        if not items:
            logger.warning("packetfence_ip_lookup_empty",
                           request_id=request_id,
                           ip=ip)
            return None

        mac = items[0].get("mac")
        logger.info("packetfence_ip_lookup_success",
                    request_id=request_id,
                    ip=ip,
                    mac=mac,
                    start_time=items[0].get("start_time"),
                    end_time=items[0].get("end_time"))
        return mac
    except Exception as e:
        logger.error("packetfence_ip_lookup_failed",
                     request_id=request_id,
                     ip=ip,
                     error=str(e))
        return None


async def handle_user_logon(payload: dict, request_id: str):
    """Handle user logon event from Wazuh (rule 100001)"""

    agent = payload.get("agent", {})
    data = payload.get("data", {})
    win_eventdata = data.get("win", {}).get("eventdata", {})

    agent_ip = agent.get("ip", "")
    target_user = win_eventdata.get("targetUserName", "")
    target_domain = win_eventdata.get("targetDomainName", "")

    username = f"{target_domain}\\{target_user}" if target_domain else target_user

    logger.info("user_logon_detected",
                request_id=request_id,
                agent_ip=agent_ip,
                username=username)

    profile = profile_manager.get_profile_by_ip(agent_ip)

    # Fallback: if IP miss, resolve MAC from PacketFence ip4logs and reconcile profile IP
    if not profile and agent_ip:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as pf_client:
            mac = await _resolve_mac_by_ip_from_packetfence(pf_client, agent_ip, request_id)
            if mac:
                profile_by_mac = profile_manager.get_profile(mac)
                if profile_by_mac:
                    profile_manager.create_profile(mac=mac, ip=agent_ip, hostname=profile_by_mac.hostname)
                    profile = profile_manager.get_profile(mac)
                    logger.info("profile_reconciled_by_packetfence_ip",
                                request_id=request_id,
                                mac=mac,
                                new_ip=agent_ip)

    if not profile:
        logger.warning("profile_not_found_for_logon",
                      request_id=request_id,
                      agent_ip=agent_ip)
        return

    previous_role = profile.identity.get("current_role") or "Machine"

    profile_manager.update_user_info(
        mac=profile.device_id,
        username=username,
        auth_type="802.1x-User",
        current_role=previous_role
    )

    profile = profile_manager.get_profile(profile.device_id)

    logger.info("profile_updated_logon",
                request_id=request_id,
                mac=profile.device_id,
                username=username)

    async with httpx.AsyncClient(timeout=60.0) as client:
        eval_payload = {
            "ip": agent_ip,
            "mac": profile.device_id,
            "user_pid": username,
            "user_category": previous_role,
            "firewall_enabled": profile.posture_security.get("firewall_enabled"),
            "antivirus_enabled": profile.posture_security.get("antivirus_enabled"),
            "trigger_source": "wazuh_rule_100001",
            "request_id": request_id
        }

        try:
            response = await client.post(PDP_URL, json=eval_payload)
            response.raise_for_status()
            result = response.json()
            logger.info("pdp_response_logon", request_id=request_id, result=result)
        except Exception as e:
            logger.error("pdp_forward_failed_logon", request_id=request_id, error=str(e))


def _parse_status_to_bool(value: object) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if value is None:
        return None

    text = str(value).strip().lower()
    if text in {"on", "true", "1", "enabled", "enable", "yes", "running", "up", "active"}:
        return True
    if text in {"off", "false", "0", "disabled", "disable", "no", "stopped", "down", "inactive"}:
        return False
    return None


def _extract_status_from_message(raw_message: object) -> tuple[Optional[str], Optional[str]]:
    if not isinstance(raw_message, str):
        return None, None

    firewall_match = re.search(r'"firewall"\s*:\s*"([^"]+)"', raw_message, re.IGNORECASE)
    antivirus_match = re.search(r'"antivirus"\s*:\s*"([^"]+)"', raw_message, re.IGNORECASE)

    firewall = firewall_match.group(1) if firewall_match else None
    antivirus = antivirus_match.group(1) if antivirus_match else None
    return firewall, antivirus


def _extract_health_status(payload: dict) -> tuple[Optional[bool], Optional[bool], str, str]:
    """Extract firewall/antivirus status; prioritize win.system.message parsing."""
    data = payload.get("data", {}) if isinstance(payload, dict) else {}
    win = data.get("win", {}) if isinstance(data, dict) else {}
    win_system = win.get("system", {}) if isinstance(win, dict) else {}
    win_eventdata = win.get("eventdata", {}) if isinstance(win, dict) else {}

    firewall_raw = None
    antivirus_raw = None

    if isinstance(win_system, dict):
        firewall_raw, antivirus_raw = _extract_status_from_message(win_system.get("message"))

    if firewall_raw is None or antivirus_raw is None:
        if isinstance(win_eventdata, dict):
            nested = win_eventdata.get("data")
            if isinstance(nested, str):
                fw_msg, av_msg = _extract_status_from_message(nested)
                firewall_raw = firewall_raw if firewall_raw is not None else fw_msg
                antivirus_raw = antivirus_raw if antivirus_raw is not None else av_msg

    if firewall_raw is None or antivirus_raw is None:
        full_log = payload.get("full_log") if isinstance(payload, dict) else None
        if isinstance(full_log, str):
            fw_msg, av_msg = _extract_status_from_message(full_log)
            firewall_raw = firewall_raw if firewall_raw is not None else fw_msg
            antivirus_raw = antivirus_raw if antivirus_raw is not None else av_msg

    firewall_enabled = _parse_status_to_bool(firewall_raw)
    antivirus_enabled = _parse_status_to_bool(antivirus_raw)

    firewall_status = str(firewall_raw) if firewall_raw is not None else "UNKNOWN"
    antivirus_status = str(antivirus_raw) if antivirus_raw is not None else "UNKNOWN"

    return firewall_enabled, antivirus_enabled, firewall_status, antivirus_status


async def handle_endpoint_health_status(payload: dict, request_id: str):
    """Update posture from health status (100020) then forward to PDP alert path."""
    agent = payload.get("agent", {})
    agent_ip = agent.get("ip", "")

    firewall_enabled, antivirus_enabled, firewall_status, antivirus_status = _extract_health_status(payload)

    profile = profile_manager.get_profile_by_ip(agent_ip)
    if not profile:
        logger.warning("profile_not_found_for_health_status",
                      request_id=request_id,
                      agent_ip=agent_ip)
        await forward_alert_to_pdp(payload, request_id)
        return

    posture_went_bad = firewall_enabled is False or antivirus_enabled is False
    if posture_went_bad:
        await forward_alert_to_pdp(payload, request_id)

    profile_manager.update_posture_security(
        mac=profile.device_id,
        firewall_enabled=firewall_enabled,
        antivirus_enabled=antivirus_enabled
    )

    profile_manager.add_system_event(
        mac=profile.device_id,
        action="Endpoint health status updated",
        reason=format_audit_reason(
            policy_name="wazuh_health_status",
            decision="no_action",
            reason="Wazuh endpoint health update received",
            rule_id="100020",
            firewall_status=firewall_status,
            antivirus_status=antivirus_status,
            firewall_enabled=firewall_enabled,
            antivirus_enabled=antivirus_enabled,
        ),
        event_id=str(100020),
        event_source="LISTENER",
    )

    logger.info("profile_updated_health_status",
                request_id=request_id,
                mac=profile.device_id,
                firewall=firewall_status,
                antivirus=antivirus_status,
                firewall_enabled=firewall_enabled,
                antivirus_enabled=antivirus_enabled)

    refreshed_profile = profile_manager.get_profile(profile.device_id)
    username = refreshed_profile.identity.get("username") if refreshed_profile else None
    current_role = refreshed_profile.identity.get("current_role") if refreshed_profile else None

    should_recover = (
        firewall_enabled is True
        and antivirus_enabled is True
        and isinstance(username, str)
        and bool(username.strip())
        and current_role == "uncheck"
    )

    if should_recover:
        async with httpx.AsyncClient(timeout=60.0) as client:
            eval_payload = {
                "ip": agent_ip,
                "mac": profile.device_id,
                "user_pid": username,
                "user_category": current_role,
                "firewall_enabled": firewall_enabled,
                "antivirus_enabled": antivirus_enabled,
                "trigger_source": "wazuh_rule_100020_recovery",
                "request_id": request_id
            }
            try:
                response = await client.post(PDP_URL, json=eval_payload)
                response.raise_for_status()
                result = response.json()
                logger.info("pdp_recovery_response_health_status", request_id=request_id, result=result)
            except Exception as e:
                logger.error("pdp_recovery_failed_health_status", request_id=request_id, error=str(e))

    if not posture_went_bad:
        await forward_alert_to_pdp(payload, request_id)


async def handle_windows_defender_status(payload: dict, request_id: str, enabled: bool):
    """Update defender posture (62151/62152) then forward to PDP alert path."""
    agent = payload.get("agent", {})
    agent_ip = agent.get("ip", "")

    profile = profile_manager.get_profile_by_ip(agent_ip)
    if not profile:
        logger.warning("profile_not_found_for_defender_status",
                      request_id=request_id,
                      agent_ip=agent_ip,
                      antivirus_enabled=enabled)
        await forward_alert_to_pdp(payload, request_id)
        return

    if enabled is False:
        await forward_alert_to_pdp(payload, request_id)

    profile_manager.update_posture_security(
        mac=profile.device_id,
        antivirus_enabled=enabled
    )

    profile_manager.add_system_event(
        mac=profile.device_id,
        action="Windows Defender status updated",
        reason=format_audit_reason(
            policy_name="wazuh_defender_status",
            decision="no_action",
            reason="Wazuh Defender status update received",
            rule_id=str(payload.get("rule", {}).get("id", "")),
            antivirus_enabled=enabled,
        ),
        event_id=str(payload.get("rule", {}).get("id", "")),
        event_source="LISTENER",
    )

    logger.info("profile_updated_defender_status",
                request_id=request_id,
                mac=profile.device_id,
                antivirus_enabled=enabled)

    if enabled is True:
        await forward_alert_to_pdp(payload, request_id)


async def handle_user_logoff(payload: dict, request_id: str):
    """Handle user logoff event from Wazuh (rule 100010)"""

    agent = payload.get("agent", {})
    data = payload.get("data", {})
    win_eventdata = data.get("win", {}).get("eventdata", {})

    agent_ip = agent.get("ip", "")
    agent_id = agent.get("id", "")
    target_user = win_eventdata.get("targetUserName", "")
    target_domain = win_eventdata.get("targetDomainName", "")

    username = f"{target_domain}\\{target_user}" if target_domain else target_user

    logger.info("user_logoff_detected",
                request_id=request_id,
                agent_ip=agent_ip,
                username=username)

    # Find device profile by IP
    profile = profile_manager.get_profile_by_ip(agent_ip)

    if not profile:
        logger.warning("profile_not_found_for_logoff",
                      request_id=request_id,
                      agent_ip=agent_ip)
        return

    mac = profile.device_id

    # Call Action API to revert to uncheck
    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            response = await client.post(
                "http://localhost:8002/actions/revert-to-uncheck",
                json={
                    "mac": mac,
                    "reason": f"User {username} logged off",
                    "request_id": request_id
                }
            )
            response.raise_for_status()
            result = response.json()

            logger.info("revert_to_uncheck_success",
                       request_id=request_id,
                       mac=mac,
                       result=result)

            # Update profile state and role history
            profile_manager.add_role_change(
                mac=mac,
                new_role="uncheck",
                reason=format_audit_reason(
                    policy_name="user_logoff",
                    decision="keep_uncheck",
                    reason=f"User {username} logged off",
                    rule_id="100010",
                    target_role="uncheck",
                )
            )
            profile_manager.update_state(mac, "LOGGED_OFF")

            logger.info("profile_updated_logoff",
                       request_id=request_id,
                       mac=mac,
                       state="LOGGED_OFF")

        except Exception as e:
            logger.error("revert_to_uncheck_failed",
                        request_id=request_id,
                        mac=mac,
                        error=str(e))


def _get_nested_value(data: dict, path: str) -> Optional[object]:
    current = data
    for key in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(key)
        if current is None:
            return None
    return current


def _resolve_alert_target_ip(event_payload: dict) -> Optional[str]:
    rule = event_payload.get("rule", {})
    agent = event_payload.get("agent", {})
    rule_id = str(rule.get("id", ""))
    path = ALERT_TARGET_FIELD_MAP.get(rule_id, "agent.ip")
    raw_target = _get_nested_value(event_payload, path)
    if isinstance(raw_target, str) and raw_target.strip():
        return raw_target.strip()
    agent_ip = agent.get("ip")
    if isinstance(agent_ip, str) and agent_ip.strip():
        return agent_ip.strip()
    return None


async def _ensure_profile_for_alert(event_payload: dict, request_id: str) -> Optional[str]:
    target_ip = _resolve_alert_target_ip(event_payload)
    if not target_ip:
        return None

    profile = profile_manager.get_profile_by_ip(target_ip)
    if profile:
        return target_ip

    async with httpx.AsyncClient(verify=False, timeout=30.0) as pf_client:
        mac = await _resolve_mac_by_ip_from_packetfence(pf_client, target_ip, request_id)

    if not mac:
        return target_ip

    profile_by_mac = profile_manager.get_profile(mac)
    if profile_by_mac:
        profile_manager.create_profile(mac=mac, ip=target_ip, hostname=profile_by_mac.hostname)
        logger.info("alert_profile_reconciled_by_packetfence_ip", request_id=request_id, mac=mac, target_ip=target_ip)
        return target_ip

    logger.warning("alert_profile_mac_found_but_profile_missing", request_id=request_id, mac=mac, target_ip=target_ip)
    return target_ip


async def forward_alert_to_pdp(
    event_payload: dict,
    request_id: str
):
    """Forward Wazuh alert to PDP for policy evaluation"""

    rule = event_payload.get("rule", {})
    agent = event_payload.get("agent", {})
    target_ip = await _ensure_profile_for_alert(event_payload, request_id)
    payload = {
        "request_id": request_id,
        "rule_id": str(rule.get("id", "")),
        "rule_level": int(rule.get("level", 0) or 0),
        "rule_groups": rule.get("groups", []),
        "rule_description": rule.get("description", ""),
        "agent_ip": target_ip or agent.get("ip"),
        "agent_id": agent.get("id"),
        "agent_name": agent.get("name"),
        "data": event_payload.get("data", {}),
        "full_log": event_payload.get("full_log"),
        "previous_output": event_payload.get("previous_output"),
        "raw_event": event_payload,
    }

    logger.info(
        "forwarding_alert_to_pdp",
        request_id=request_id,
        rule_id=payload["rule_id"],
        rule_level=payload["rule_level"],
        agent_ip=payload["agent_ip"],
        agent_id=payload["agent_id"],
        has_data=bool(payload.get("data")),
        has_full_log=bool(payload.get("full_log")),
        has_previous_output=bool(payload.get("previous_output")),
    )

    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            response = await client.post(PDP_ALERT_URL, json=payload)
            response.raise_for_status()
            result = response.json()

            logger.info("pdp_alert_response",
                       request_id=request_id,
                       decision=result.get("decision"),
                       policy_matched=result.get("policy_matched"),
                       reason=result.get("reason"))

            # If PDP decided to isolate, execute action
            if result.get("decision") == "isolate":
                action_params = result.get("action_params", {})
                logger.info("pdp_decided_isolate",
                           request_id=request_id,
                           action_params=action_params)

        except Exception as e:
            logger.error("pdp_alert_forward_failed",
                        request_id=request_id,
                        error=str(e))


if __name__ == "__main__":
    import uvicorn
    logger.info("Starting Listener Service on port 8000")
    uvicorn.run("listener_api:app", host="0.0.0.0", port=8000, reload=True)