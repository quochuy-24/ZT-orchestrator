"""Wazuh API Client - Layer 1"""

from typing import Optional, Dict, Any
import httpx
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from shared.logger import get_logger

logger = get_logger(__name__)


class WazuhError(Exception):
    pass


class WazuhClient:
    """Wazuh API client"""

    def __init__(self):
        self.base_url = "https://192.168.29.103:55000"
        self.username = "python_api"
        self.password = "Doipassxaichung0-"
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
        """Login and get JWT token"""
        await self._ensure_client()
        try:
            response = await self._client.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.username, self.password)
            )
            response.raise_for_status()
            self._token = response.json().get("data", {}).get("token")
            if not self._token:
                raise WazuhError("No token received")
            logger.info("wazuh_authenticated")
        except httpx.ConnectError as e:
            raise WazuhError(f"Connection failed: {e}")

    def _get_headers(self) -> Dict[str, str]:
        if not self._token:
            raise WazuhError("Not authenticated")
        return {"Authorization": f"Bearer {self._token}"}

    async def get_agent_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get agent info by IP"""
        await self._ensure_client()
        try:
            response = await self._client.get(
                f"{self.base_url}/agents",
                headers=self._get_headers(),
                params={"ip": ip}
            )
            response.raise_for_status()
            data = response.json()
            items = data.get("data", {}).get("affected_items", [])
            if not items:
                logger.warning("wazuh_agent_not_found", ip=ip)
                return None
            agent = items[0]
            logger.info("wazuh_agent_found", ip=ip, agent_id=agent.get("id"), agent_name=agent.get("name"), status="success")
            return agent
        except httpx.HTTPStatusError as e:
            raise WazuhError(f"Failed to get agent: {e}")

    async def get_sca_summary(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get SCA summary for agent"""
        await self._ensure_client()
        try:
            response = await self._client.get(
                f"{self.base_url}/sca/{agent_id}",
                headers=self._get_headers()
            )
            response.raise_for_status()
            data = response.json()
            items = data.get("data", {}).get("affected_items", [])
            if not items:
                logger.warning("wazuh_sca_not_found", agent_id=agent_id)
                return None
            sca = items[0]
            logger.info("wazuh_sca_retrieved", agent_id=agent_id, sca_score=sca.get("score"), sca_pass=sca.get("pass"), sca_fail=sca.get("fail"), status="success")
            return sca
        except httpx.HTTPStatusError as e:
            raise WazuhError(f"Failed to get SCA: {e}")

    async def close(self):
        """Close HTTP client"""
        if self._client:
            await self._client.aclose()
            self._client = None
            self._token = None
