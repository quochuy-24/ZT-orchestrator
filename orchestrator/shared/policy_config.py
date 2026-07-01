"""Central policy configuration for Zero Trust decisions."""

from typing import Dict, List, Any

GROUP_TO_ROLE: Dict[str, str] = {
    "Accounting": "accounting",
    "IT": "IT",
}

ROLE_TO_CATEGORY_ID: Dict[str, int] = {
    "default": 1,
    "guest": 2,
    "gaming": 3,
    "voice": 4,
    "REJECT": 5,
    "Machine": 6,
    "accounting": 9,
    "User": 13,
    "user": 13,
    "quarantine": 5,
    "uncheck": 125,
    "IT": 242,
    "restricted": 246,
}

RISK_LEVEL_SCORE_MAP: Dict[int, int] = {
    7: 15,
    8: 20,
    9: 25,
    10: 35,
    11: 50,
    12: 100,
}

RISK_SCORE_OVERRIDES: Dict[str, int] = {
    "100020": 35,
    "62152": 35,
}

RISK_THRESHOLDS: Dict[str, int] = {
    "jit_max": 30,
    "medium": 30,
    "restrict": 60,
    "isolate": 80,
}

POSTURE_POLICY: Dict[str, Any] = {
    "sca_min_score": 30,
    "firewall_required": True,
    "antivirus_required": True,
}

JIT_ACCESS_DURATION_MINUTES = 5
JIT_OTP_TTL_SECONDS = 300

JIT_RESOURCES: Dict[str, Dict[str, Any]] = {
    "linux_ssh": {"name": "Linux Server (SSH)", "ip": "10.0.40.100", "port": 22},
    "linux_sql": {"name": "Linux Server (SQL Database)", "ip": "10.0.40.100", "port": 3306},
    "win_rdp": {"name": "Windows Server (Remote Desktop)", "ip": "192.168.29.17", "port": 3389},
    "pf_admin": {"name": "PacketFence Web Admin", "ip": "192.168.29.91", "port": 1443},
    "wazuh_admin": {"name": "Wazuh Security Dashboard", "ip": "192.168.29.103", "port": 443},
}

JIT_ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "IT": ["linux_ssh", "linux_sql", "win_rdp", "pf_admin", "wazuh_admin"],
    "accounting": [],
}
