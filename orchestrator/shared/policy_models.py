"""Shared policy decision models for Zero Trust evaluation."""

from dataclasses import dataclass, field
from typing import Any, Dict, Literal, Optional

PolicyAction = Literal[
    "allow_role",
    "keep_uncheck",
    "restrict",
    "isolate",
    "allow_jit",
    "deny_jit",
    "no_action",
]


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    action: PolicyAction
    reason: str
    target_role: Optional[str] = None
    risk_delta: int = 0
    risk_level: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
