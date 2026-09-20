"""Structured logging with credential masking.

Two rules this file enforces:

  * logs are JSON, so they can be shipped into the SIEM this tool feeds;
  * an API key never reaches a log line, whatever code path produced it.

The masking filter works on the formatted message *and* on the arguments, and
it masks by value (the configured keys) and by pattern (anything that looks
like a key in a URL query string or an auth header), because the failure mode
worth designing for is the one nobody predicted — an exception repr that
happens to carry the header dict.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import UTC, datetime

_SECRET_ENV_KEYS = (
    "ABUSEIPDB_API_KEY",
    "OTX_API_KEY",
    "GREYNOISE_API_KEY",
    "ABUSECH_AUTH_KEY",
    "VIRUSTOTAL_API_KEY",
    "POSTGRES_PASSWORD",
)

_PATTERNS = (
    # name = value / "name": "value" / name: value, with or without quotes
    re.compile(
        r"(?i)\b(api[_-]?key|auth[_-]?key|apikey|key|token|password|passwd|secret)\b"
        r"(['\"]?\s*[=:]\s*['\"]?)([^\s,;&'\"}\)]+)"
    ),
    re.compile(r"(?i)([?&](?:key|apikey|api_key|token|auth)=)([^&\s]+)"),
    re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+)(\S+)"),
    re.compile(r"(?i)(postgresql(?:\+\w+)?://[^:]+:)([^@]+)(@)"),
)

REDACTED = "***REDACTED***"


def _configured_secrets() -> list[str]:
    values = []
    for key in _SECRET_ENV_KEYS:
        value = os.environ.get(key, "").strip()
        if len(value) >= 8:          # short/blank values would over-redact
            values.append(value)
    return values


def mask(text: str) -> str:
    """Redact configured secret values and anything shaped like a credential."""
    if not text:
        return text
    for secret in _configured_secrets():
        text = text.replace(secret, REDACTED)
    for pattern in _PATTERNS:
        if pattern.groups == 3 and pattern.pattern.startswith("(?i)(postgresql"):
            text = pattern.sub(r"\1" + REDACTED + r"\3", text)
        elif pattern.groups == 3:
            text = pattern.sub(r"\1\2" + REDACTED, text)
        else:
            text = pattern.sub(r"\1" + REDACTED, text)
    return text


def _mask_arg(value: object) -> object:
    """Mask string arguments only.

    Coercing every argument to str would corrupt the format string — a
    `logger.info("imported %d rows", count)` call would start raising inside
    logging. Masking must be invisible to everything except secrets.
    """
    return mask(value) if isinstance(value, str) else value


class SecretMaskingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = mask(record.msg)
            if record.args:
                if isinstance(record.args, dict):
                    record.args = {k: _mask_arg(v) for k, v in record.args.items()}
                else:
                    record.args = tuple(_mask_arg(arg) for arg in record.args)
        except Exception:  # logging must never raise
            record.msg = "log record suppressed: masking failed"
            record.args = ()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": mask(record.getMessage()),
        }
        for attr in ("request_id", "client_ip", "method", "path", "status", "duration_ms"):
            value = getattr(record, attr, None)
            if value is not None:
                payload[attr] = value
        if record.exc_info:
            payload["exception"] = mask(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", json_logs: bool = True) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(SecretMaskingFilter())
    handler.setFormatter(
        JsonFormatter()
        if json_logs
        else logging.Formatter("%(asctime)s %(levelname)-8s %(name)s :: %(message)s")
    )
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    # uvicorn duplicates access logs through its own handlers; ours already
    # carry the request context, so silence the duplicate.
    for name in ("uvicorn.access",):
        logging.getLogger(name).handlers = []
        logging.getLogger(name).propagate = False
