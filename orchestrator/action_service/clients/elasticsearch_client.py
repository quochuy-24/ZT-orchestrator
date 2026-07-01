"""Elasticsearch/OpenSearch Client - Netflow queries"""

from typing import Optional, Dict, Any, List
import httpx
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from shared.logger import get_logger

logger = get_logger(__name__)


class ElasticsearchError(Exception):
    pass


class ElasticsearchClient:
    """Elasticsearch/OpenSearch client for netflow queries."""

    def __init__(self):
        self.base_url = "https://192.168.29.103:9200"
        self.username = "admin"
        self.password = "Doipassxaichung0-"
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        await self._ensure_client()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def _ensure_client(self):
        if self._client is None:
            self._client = httpx.AsyncClient(verify=False, timeout=30.0, auth=(self.username, self.password))

    @staticmethod
    def _protocol_name(protocol: Any) -> str:
        mapping = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
        }
        try:
            proto_num = int(protocol)
        except (TypeError, ValueError):
            return f"PROTO_{protocol}"
        return mapping.get(proto_num, f"PROTO_{proto_num}")

    @staticmethod
    def _format_bytes(byte_count: float) -> str:
        if byte_count < 1024:
            return f"{int(byte_count)} B"
        if byte_count < 1024 * 1024:
            return f"{byte_count / 1024:.1f} KB"
        if byte_count < 1024 * 1024 * 1024:
            return f"{byte_count / (1024 * 1024):.1f} MB"
        return f"{byte_count / (1024 * 1024 * 1024):.1f} GB"

    def _build_netflow_query(self, device_ip: str, minutes: int) -> Dict[str, Any]:
        return {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": f"now-{minutes}m",
                                    "lte": "now",
                                }
                            }
                        },
                        {
                            "bool": {
                                "should": [
                                    {"match": {"netflow.ipv4_src_addr": device_ip}},
                                    {"match": {"netflow.ipv4_dst_addr": device_ip}},
                                ],
                                "minimum_should_match": 1,
                            }
                        },
                    ]
                }
            },
            "aggs": {
                "group_by_ip": {
                    "terms": {
                        "field": "netflow.ipv4_dst_addr.keyword",
                        "size": 20,
                        "order": {"tong_bytes_ip": "desc"},
                    },
                    "aggs": {
                        "tong_bytes_ip": {"sum": {"field": "netflow.in_bytes"}},
                        "group_by_port": {
                            "terms": {
                                "field": "netflow.l4_dst_port",
                                "size": 10,
                                "order": {"tong_bytes_port": "desc"},
                            },
                            "aggs": {
                                "tong_bytes_port": {"sum": {"field": "netflow.in_bytes"}},
                                "group_by_proto": {
                                    "terms": {
                                        "field": "netflow.protocol",
                                        "size": 5,
                                        "order": {"tong_bytes_proto": "desc"},
                                    },
                                    "aggs": {
                                        "tong_bytes_proto": {"sum": {"field": "netflow.in_bytes"}},
                                    },
                                },
                            },
                        },
                    },
                }
            },
        }

    def _parse_netflow_response(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        buckets = payload.get("aggregations", {}).get("group_by_ip", {}).get("buckets", [])
        connections: List[Dict[str, Any]] = []

        for ip_bucket in buckets:
            dst_ip = ip_bucket.get("key")
            for port_bucket in ip_bucket.get("group_by_port", {}).get("buckets", []):
                dst_port = port_bucket.get("key")
                for proto_bucket in port_bucket.get("group_by_proto", {}).get("buckets", []):
                    bytes_value = float(proto_bucket.get("tong_bytes_proto", {}).get("value", 0) or 0)
                    connections.append(
                        {
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "protocol": self._protocol_name(proto_bucket.get("key")),
                            "bytes": int(bytes_value),
                            "bytes_formatted": self._format_bytes(bytes_value),
                        }
                    )

        connections.sort(key=lambda item: item["bytes"], reverse=True)
        return connections

    async def query_netflow(self, device_ip: str, minutes: int = 5) -> List[Dict[str, Any]]:
        await self._ensure_client()
        try:
            response = await self._client.post(
                f"{self.base_url}/netflow-*/_search",
                headers={"Content-Type": "application/json"},
                json=self._build_netflow_query(device_ip, minutes),
            )
            response.raise_for_status()
            data = response.json()
            connections = self._parse_netflow_response(data)
            logger.info("elasticsearch_netflow_retrieved", ip=device_ip, minutes=minutes, count=len(connections))
            return connections
        except httpx.HTTPStatusError as e:
            raise ElasticsearchError(f"Failed to query netflow: {e}")
        except httpx.HTTPError as e:
            raise ElasticsearchError(f"Netflow query error: {e}")

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None
