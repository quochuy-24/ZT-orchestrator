"""PacketFence API Client - Layer 1"""

from typing import Optional, Dict, Any
import httpx
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from shared.logger import get_logger
from shared.policy_config import ROLE_TO_CATEGORY_ID

logger = get_logger(__name__)


class PacketFenceError(Exception):
    pass


class PacketFenceClient:
    """PacketFence API client"""

    def __init__(self):
        self.base_url = "https://192.168.29.91:9999"
        self.username = "admin"
        self.password = "123"
        self._client: Optional[httpx.AsyncClient] = None
        self._token: Optional[str] = None

    async def __aenter__(self):
        await self._ensure_client()
        await self._authenticate()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def _ensure_client(self):
        if self._client is None:
            self._client = httpx.AsyncClient(verify=False, timeout=30.0)

    async def _authenticate(self):
        """Login and get token"""
        await self._ensure_client()
        try:
            response = await self._client.post(f"{self.base_url}/api/v1/login", json={"username": self.username, "password": self.password})
            if response.status_code == 401:
                raise PacketFenceError("Invalid credentials")
            response.raise_for_status()

            # Try header first
            self._token = response.headers.get('X-PacketFence-Token')

            # If not in header, try response body
            if not self._token:
                data = response.json()
                self._token = data.get('token')

            if not self._token:
                raise PacketFenceError("No token received")

            logger.info("packetfence_authenticated")
        except httpx.ConnectError as e:
            raise PacketFenceError(f"Connection failed: {e}")

    def _get_headers(self) -> Dict[str, str]:
        if not self._token:
            raise PacketFenceError("Not authenticated")
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    async def get_node_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get MAC address from IP using ip4log"""
        await self._ensure_client()
        try:
            search_payload = {
                "cursor": 0,
                "limit": 1,
                "fields": ["mac", "ip"],
                "query": {"op": "and", "values": [{"field": "ip", "op": "equals", "value": ip}]},
                "sort": ["start_time DESC"]
            }
            response = await self._client.post(f"{self.base_url}/api/v1/ip4logs/search", headers=self._get_headers(), json=search_payload)
            response.raise_for_status()
            items = response.json().get('items', [])
            if not items or not items[0].get('mac'):
                logger.warning("packetfence_mac_not_found", ip=ip)
                return None
            mac = items[0]['mac']
            logger.info("packetfence_mac_found", mac=mac, ip=ip)
            return {"mac": mac, "ip": ip}
        except httpx.HTTPStatusError as e:
            raise PacketFenceError(f"Failed to search IP: {e}")

    async def apply_security_event(self, mac: str, security_event_id: str) -> Dict[str, Any]:
        """Apply security event to isolate device"""
        await self._ensure_client()
        try:
            response = await self._client.post(f"{self.base_url}/api/v1/node/{mac}/apply_security_event", headers=self._get_headers(), json={"security_event_id": security_event_id})
            response.raise_for_status()
            result = response.json()
            logger.info("packetfence_security_event_applied", mac=mac, security_event_id=security_event_id, event_id=result.get("id"))
            return result
        except httpx.HTTPStatusError as e:
            raise PacketFenceError(f"Failed to apply security event: {e}")

    async def get_node_by_mac(self, mac: str) -> Optional[Dict[str, Any]]:
        """Get node info by MAC address"""
        await self._ensure_client()
        try:
            response = await self._client.get(f"{self.base_url}/api/v1/node/{mac}", headers=self._get_headers())
            if response.status_code == 404:
                return None
            response.raise_for_status()
            data = response.json()
            node = data.get("item", {})
            logger.info("packetfence_node_found", mac=mac, category=node.get("category"), status="success")
            return node
        except httpx.HTTPStatusError as e:
            raise PacketFenceError(f"Failed to get node: {e}")

    async def get_open_security_events(self, mac: str) -> list[Dict[str, Any]]:
        """Get open security events for a node"""
        await self._ensure_client()
        try:
            response = await self._client.get(
                f"{self.base_url}/api/v1/node/{mac}/security_events",
                headers=self._get_headers(),
            )
            response.raise_for_status()
            items = response.json().get("items", [])
            open_events = [item for item in items if item.get("status") == "open"]
            logger.info("packetfence_security_events_found", mac=mac, open_events=len(open_events), status="success")
            return open_events
        except httpx.HTTPStatusError as e:
            raise PacketFenceError(f"Failed to get security events: {e}")

    async def close_security_event(self, mac: str, event_id: int) -> Dict[str, Any]:
        """Close an open security event on a node"""
        await self._ensure_client()
        try:
            response = await self._client.put(
                f"{self.base_url}/api/v1/node/{mac}/close_security_event/",
                headers=self._get_headers(),
                json={"security_event_id": str(event_id)},
            )
            response.raise_for_status()
            result = response.json()
            logger.info("packetfence_security_event_closed", mac=mac, event_id=event_id, status="success")
            return result
        except httpx.HTTPStatusError as e:
            raise PacketFenceError(f"Failed to close security event: {e}")

    async def change_node_role(self, mac: str, role: str) -> Dict[str, Any]:
        """Change node role/category"""
        await self._ensure_client()

        category_id = ROLE_TO_CATEGORY_ID.get(role)
        if not category_id:
            raise PacketFenceError(f"Unknown role: {role}")

        try:
            response = await self._client.patch(
                f"{self.base_url}/api/v1/node/{mac}",
                headers=self._get_headers(),
                json={
                    "category_id": category_id,
                    "bypass_role_id": category_id
                }
            )
            response.raise_for_status()
            result = response.json()
            logger.info("packetfence_role_changed", mac=mac, role=role, category_id=category_id, status="success")
            return result
        except httpx.HTTPStatusError as e:
            raise PacketFenceError(f"Failed to change role: {e}")

    async def revert_node_to_uncheck(self, mac: str) -> Dict[str, Any]:
        """Revert node to uncheck with bypass_role_id=0"""
        await self._ensure_client()

        try:
            response = await self._client.patch(
                f"{self.base_url}/api/v1/node/{mac}",
                headers=self._get_headers(),
                json={
                    "category_id": 125,  # uncheck
                    "bypass_role_id": 0   # no bypass
                }
            )
            response.raise_for_status()
            result = response.json()
            logger.info("packetfence_reverted_to_uncheck", mac=mac, category_id=125, bypass_role_id=0, status="success")
            return result
        except httpx.HTTPStatusError as e:
            raise PacketFenceError(f"Failed to revert node: {e}")

    async def close(self):
        """Close HTTP client"""
        if self._client:
            await self._client.aclose()
            self._client = None
            self._token = None
