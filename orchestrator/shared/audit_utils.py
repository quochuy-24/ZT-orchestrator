"""Audit reason formatting helpers."""

from typing import Any


def format_audit_reason(**fields: Any) -> str:
    parts = []
    for key, value in fields.items():
        if value is None:
            continue
        parts.append(f"{key}={value}")
    return " | ".join(parts)
