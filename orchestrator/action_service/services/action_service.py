"""Action Service - Business Logic"""

from typing import Dict, Any
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from action_service.clients.packetfence_client import PacketFenceClient
from action_service.clients.wazuh_client import WazuhClient, WazuhError
from action_service.clients.ldap_client import LDAPClient, LDAPError
from action_service.clients.elasticsearch_client import ElasticsearchClient
from shared.audit_utils import format_audit_reason
from shared.logger import get_logger
from shared.policy_engine import resolve_category_id, resolve_role_from_groups
from shared.profile_manager import profile_manager

ISOLATION_SECURITY_EVENT_ID = 13000003

logger = get_logger(__name__)


async def isolate_device(agent_ip: str, security_event_id: str, reason: str, request_id: str) -> Dict[str, Any]:
    """Isolate device by applying security event"""

    logger.info("isolate_device_start", request_id=request_id, agent_ip=agent_ip)

    if not agent_ip:
        logger.error("missing_agent_ip", request_id=request_id)
        return {"success": False, "error": "Missing agent IP"}

    try:
        async with PacketFenceClient() as pf:
            node = await pf.get_node_by_ip(agent_ip)

            if not node:
                logger.warning("no_mac_found", request_id=request_id, ip=agent_ip)
                return {"success": False, "error": f"No MAC found for IP {agent_ip}"}

            mac = node["mac"]
            logger.info("mac_found", request_id=request_id, mac=mac, ip=agent_ip)

            result = await pf.apply_security_event(mac, security_event_id)

        profile_manager.update_state(mac, "ISOLATED")
        profile_manager.add_system_event(
            mac=mac,
            action="Manual isolate",
            reason=format_audit_reason(
                policy_name="manual_isolate",
                decision="isolate",
                reason=reason,
                rule_id=security_event_id,
            ),
            role="isolation",
            event_id=str(result.get("id")) if result.get("id") is not None else None,
        )

        logger.info("device_isolated", request_id=request_id, mac=mac, event_id=result.get("id"))

        return {
            "success": True,
            "action": "isolate",
            "mac": mac,
            "ip": agent_ip,
            "security_event_id": security_event_id,
            "event_id": result.get("id"),
            "reason": reason
        }

    except Exception as e:
        logger.error("isolate_failed", request_id=request_id, error=str(e), exc_info=True)
        return {"success": False, "error": str(e)}


async def change_device_role(mac: str, target_role: str, reason: str, request_id: str) -> Dict[str, Any]:
    """Change device role in PacketFence"""

    logger.info("change_role_start",
                request_id=request_id,
                mac=mac,
                target_role=target_role,
                reason=reason)

    if not mac:
        logger.error("missing_mac", request_id=request_id)
        return {"success": False, "error": "Missing MAC address"}

    try:
        async with PacketFenceClient() as pf:
            node = await pf.get_node_by_mac(mac)

            if not node:
                logger.warning("node_not_found", request_id=request_id, mac=mac)
                return {"success": False, "error": f"Node {mac} not found"}

            old_role = node.get("category", "unknown")

            await pf.change_node_role(mac, target_role)
            profile_manager.add_role_change(
                mac=mac,
                new_role=target_role,
                reason=format_audit_reason(
                    policy_name="role_change_enforcement",
                    decision="allow_role",
                    reason=reason,
                    target_role=target_role,
                ),
            )

            logger.info("role_changed",
                       request_id=request_id,
                       mac=mac,
                       old_role=old_role,
                       new_role=target_role)

            return {
                "success": True,
                "action": "change_role",
                "mac": mac,
                "old_role": old_role,
                "new_role": target_role,
                "reason": reason
            }

    except Exception as e:
        logger.error("change_role_failed", request_id=request_id, error=str(e), exc_info=True)
        return {"success": False, "error": str(e)}


async def get_device_sca(ip: str, request_id: str) -> Dict[str, Any]:
    """Get Wazuh agent info and SCA score"""

    logger.info("get_sca_start",
                request_id=request_id,
                ip=ip)

    try:
        async with WazuhClient() as wazuh:
            agent = await retry_get_agent_by_ip(wazuh, ip, request_id)

            if not agent:
                logger.warning("agent_not_found",
                              request_id=request_id,
                              ip=ip)
                return {
                    "success": False,
                    "agent_id": None,
                    "agent_name": None,
                    "agent_status": None,
                    "sca_score": 0,
                    "sca_pass": 0,
                    "sca_fail": 0,
                    "sca_total": 0,
                    "sca_policy_name": None
                }

            agent_id = agent["id"]
            agent_name = agent["name"]
            agent_status = agent.get("status", "unknown")

            sca = await wazuh.get_sca_summary(agent_id)

            if not sca:
                logger.warning("sca_not_found",
                              request_id=request_id,
                              agent_id=agent_id)
                return {
                    "success": True,
                    "agent_id": agent_id,
                    "agent_name": agent_name,
                    "agent_status": agent_status,
                    "sca_score": 0,
                    "sca_pass": 0,
                    "sca_fail": 0,
                    "sca_total": 0,
                    "sca_policy_name": None
                }

            logger.info("sca_retrieved",
                       request_id=request_id,
                       agent_id=agent_id,
                       agent_name=agent_name,
                       sca_score=sca.get("score"),
                       sca_pass=sca.get("pass"),
                       sca_fail=sca.get("fail"))

            return {
                "success": True,
                "agent_id": agent_id,
                "agent_name": agent_name,
                "agent_status": agent_status,
                "sca_score": sca.get("score", 0),
                "sca_pass": sca.get("pass", 0),
                "sca_fail": sca.get("fail", 0),
                "sca_total": sca.get("total_checks", 0),
                "sca_policy_name": sca.get("name")
            }

    except WazuhError as e:
        logger.error("get_sca_error",
                    request_id=request_id,
                    error=str(e))
        return {
            "success": False,
            "error": str(e),
            "agent_id": None,
            "agent_name": None,
            "agent_status": None,
            "sca_score": 0,
            "sca_pass": 0,
            "sca_fail": 0,
            "sca_total": 0,
            "sca_policy_name": None
        }


async def get_device_netflow(ip: str, minutes: int, request_id: str) -> Dict[str, Any]:
    """Get recent netflow connections for device IP."""

    logger.info("get_netflow_start",
                request_id=request_id,
                ip=ip,
                minutes=minutes)

    if not ip:
        logger.error("missing_ip_for_netflow", request_id=request_id)
        return {"success": False, "error": "Missing device IP", "connections": []}

    try:
        async with ElasticsearchClient() as es:
            connections = await es.query_netflow(ip, minutes)

        logger.info("netflow_retrieved",
                    request_id=request_id,
                    ip=ip,
                    minutes=minutes,
                    count=len(connections))

        return {
            "success": True,
            "ip": ip,
            "minutes": minutes,
            "connections": connections,
            "total": len(connections)
        }

    except Exception as e:
        logger.error("get_netflow_failed",
                    request_id=request_id,
                    ip=ip,
                    minutes=minutes,
                    error=str(e),
                    exc_info=True)
        return {"success": False, "error": str(e), "connections": []}


async def retry_get_agent_by_ip(wazuh: WazuhClient, ip: str, request_id: str, max_retries: int = 3, delay: int = 5):
    """Retry getting agent with delay"""

    for attempt in range(1, max_retries + 1):
        logger.info("agent_lookup_attempt",
                   request_id=request_id,
                   ip=ip,
                   attempt=attempt,
                   max_retries=max_retries)

        try:
            agent = await wazuh.get_agent_by_ip(ip)

            if agent:
                logger.info("agent_found",
                           request_id=request_id,
                           agent_id=agent["id"],
                           agent_name=agent["name"],
                           attempt=attempt)
                return agent

            if attempt < max_retries:
                logger.info("agent_not_found_retry",
                           request_id=request_id,
                           delay_seconds=delay,
                           next_attempt=attempt + 1)
                await asyncio.sleep(delay)

        except WazuhError as e:
            logger.error("agent_lookup_error",
                        request_id=request_id,
                        attempt=attempt,
                        error=str(e))

            if attempt < max_retries:
                await asyncio.sleep(delay)

    logger.warning("agent_lookup_failed",
                  request_id=request_id,
                  total_attempts=max_retries)
    return None


async def get_user_groups(username: str, request_id: str) -> Dict[str, Any]:
    """Get user groups from LDAP without making an access decision."""

    logger.info("get_user_groups_start",
                request_id=request_id,
                username=username)

    try:
        ldap_client = LDAPClient()
        groups = ldap_client.get_user_groups(username)

        if not groups:
            logger.warning("no_groups_found",
                          request_id=request_id,
                          username=username)
            return {
                "success": False,
                "error": "No groups found for user",
                "username": username,
                "groups": []
            }

        logger.info("user_groups_found",
                   request_id=request_id,
                   username=username,
                   groups=groups)

        return {
            "success": True,
            "username": username,
            "groups": groups
        }

    except LDAPError as e:
        logger.error("ldap_query_failed",
                    request_id=request_id,
                    username=username,
                    error=str(e))
        return {
            "success": False,
            "error": str(e),
            "username": username,
            "groups": []
        }


async def get_user_role(username: str, request_id: str) -> Dict[str, Any]:
    """Resolve user role from LDAP groups for backward-compatible callers."""

    logger.info("get_user_role_start",
                request_id=request_id,
                username=username)

    groups_result = await get_user_groups(username, request_id)
    if not groups_result.get("success"):
        return {
            "success": False,
            "error": groups_result.get("error"),
            "role": None,
            "category_id": None
        }

    groups = groups_result["groups"]
    role = resolve_role_from_groups(groups)

    if not role:
        logger.warning("no_role_mapping",
                      request_id=request_id,
                      username=username,
                      groups=groups)
        return {
            "success": False,
            "error": f"No role mapping for groups: {groups}",
            "role": None,
            "category_id": None
        }

    category_id = resolve_category_id(role)

    logger.info("user_role_found",
               request_id=request_id,
               username=username,
               groups=groups,
               role=role,
               category_id=category_id)

    return {
        "success": True,
        "username": username,
        "groups": groups,
        "role": role,
        "category_id": category_id
    }


async def revert_device_to_uncheck(mac: str, reason: str, request_id: str) -> Dict[str, Any]:
    """Revert device to uncheck state (for logoff)"""

    logger.info("revert_to_uncheck_start",
                request_id=request_id,
                mac=mac,
                reason=reason)

    try:
        async with PacketFenceClient() as pf:
            node = await pf.get_node_by_mac(mac)

            if not node:
                return {"success": False, "error": f"Node {mac} not found"}

            old_role = node.get("category", "unknown")

            await pf.revert_node_to_uncheck(mac)

            logger.info("reverted_to_uncheck",
                       request_id=request_id,
                       mac=mac,
                       old_role=old_role)

            return {
                "success": True,
                "action": "revert_to_uncheck",
                "mac": mac,
                "old_role": old_role,
                "new_role": "uncheck",
                "reason": reason
            }

    except Exception as e:
        logger.error("revert_failed", request_id=request_id, error=str(e), exc_info=True)
        return {"success": False, "error": str(e)}


async def restore_device_to_actual_role(mac: str, reason: str, request_id: str) -> Dict[str, Any]:
    """Restore device role to actual role, reset risk score, and mark COMPLIANT."""

    logger.info("restore_actual_role_start",
                request_id=request_id,
                mac=mac,
                reason=reason)

    profile = profile_manager.get_profile(mac)
    if not profile:
        logger.warning("restore_profile_not_found", request_id=request_id, mac=mac)
        return {"success": False, "error": f"Profile {mac} not found"}

    username = profile.identity.get("username")
    target_role = None

    if username:
        role_result = await get_user_role(username, request_id)
        if not role_result.get("success"):
            return {"success": False, "error": role_result.get("error") or "Failed to resolve actual role"}
        target_role = role_result.get("role")
    else:
        target_role = profile.identity.get("actual_role") or "Machine"

    if not target_role:
        return {"success": False, "error": "Actual role not found"}

    try:
        async with PacketFenceClient() as pf:
            node = await pf.get_node_by_mac(mac)
            if not node:
                return {"success": False, "error": f"Node {mac} not found"}

            old_role = node.get("category", "unknown")
            closed_event_ids = []
            for event in await pf.get_open_security_events(mac):
                if event.get("security_event_id") != ISOLATION_SECURITY_EVENT_ID:
                    continue
                event_id = event.get("id")
                if event_id is None:
                    continue
                await pf.close_security_event(mac, event_id)
                closed_event_ids.append(event_id)

            await pf.change_node_role(mac, target_role)

        profile_manager.add_role_change(
            mac=mac,
            new_role=target_role,
            reason=format_audit_reason(
                policy_name="restore_actual_role",
                decision="allow_role",
                reason=reason,
                target_role=target_role,
                closed_event_ids=closed_event_ids,
            ),
        )
        profile_manager.update_risk_score(mac=mac, total_score=0, risk_level="UNKNOWN")
        profile_manager.update_state(mac=mac, state="COMPLIANT")

        logger.info("restore_actual_role_success",
                    request_id=request_id,
                    mac=mac,
                    old_role=old_role,
                    new_role=target_role,
                    closed_event_ids=closed_event_ids)

        return {
            "success": True,
            "action": "restore_actual_role",
            "mac": mac,
            "old_role": old_role,
            "new_role": target_role,
            "risk_score": 0,
            "state": "COMPLIANT",
            "closed_event_ids": closed_event_ids,
            "reason": reason
        }

    except Exception as e:
        logger.error("restore_actual_role_failed", request_id=request_id, mac=mac, error=str(e), exc_info=True)
        return {"success": False, "error": str(e)}
