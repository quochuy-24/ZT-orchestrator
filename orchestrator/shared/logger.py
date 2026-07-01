"""Shared logger utility"""

import json
import logging
import os
import sys
from typing import Any

import structlog


class ConsoleRenderer:
    """Render structured logs in readable one-line console format."""

    def __call__(self, _: Any, __: str, event_dict: dict) -> str:
        timestamp = str(event_dict.pop("timestamp", "-"))
        level = str(event_dict.pop("level", "INFO")).upper()
        service = str(event_dict.pop("service", "-"))
        event = str(event_dict.pop("event", "log"))
        request_id = event_dict.pop("request_id", None)

        main = f"[{timestamp}] {level:<5} {service} | {event}"
        if request_id:
            main += f" | request_id={request_id}"

        details = []
        for key, value in event_dict.items():
            if value is None:
                continue
            if isinstance(value, (dict, list)):
                value = json.dumps(value, ensure_ascii=False)
            details.append(f"{key}={value}")

        return f"{main} | {' '.join(details)}" if details else main


def setup_logging(level: str = "INFO", service_name: str | None = None, log_format: str | None = None):
    """Setup structured logging with console/json output."""
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper())
    )

    resolved_format = (log_format or os.getenv("LOG_FORMAT") or "console").strip().lower()
    renderer = ConsoleRenderer() if resolved_format == "console" else structlog.processors.JSONRenderer()

    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso", key="timestamp"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    processors.append(structlog.processors.EventRenamer(to="event"))

    if service_name:
        def _add_service(_: Any, __: str, event_dict: dict) -> dict:
            event_dict.setdefault("service", service_name)
            return event_dict

        processors.append(_add_service)

    processors.append(renderer)

    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str):
    """Get a structured logger."""
    return structlog.get_logger(name)
