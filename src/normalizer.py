"""
normalizer.py — Normalize raw SIEM alerts and threat intel entries into a
unified NormalizedAlert schema.

Supported source_type values:
  "siem_alert"   — standard EDR/SIEM event
  "threat_intel" — threat intelligence feed indicator

Public API:
  normalize(raw_events: list[dict]) -> list[NormalizedAlert]
  normalize_file(path: str)         -> list[NormalizedAlert]
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class NormalizedAlert:
    id: str                          # deterministic short hash
    source_type: str                 # "siem_alert" | "threat_intel" | "unknown"
    timestamp: datetime | None       # parsed to aware UTC datetime
    src_ip: str | None
    dst_ip: str | None
    hostname: str | None
    description: str | None
    severity: str | None             # critical | high | medium | low | info
    raw: dict[str, Any] = field(repr=False)  # original event, preserved for report output


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEVERITY_VALID = {"critical", "high", "medium", "low", "info"}


def _parse_timestamp(value: str | None) -> datetime | None:
    """Parse an ISO 8601 string to an aware UTC datetime.  Returns None on
    failure rather than raising so a bad timestamp never drops an alert.
    """
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        logger.warning("Could not parse timestamp %r — setting to None", value)
        return None


def _make_id(*parts: Any) -> str:
    """Return the first 12 hex chars of a SHA-256 over the joined parts."""
    key = "|".join(str(p) for p in parts)
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def _clean_severity(value: str | None, default: str = "info") -> str:
    if value and value.lower() in _SEVERITY_VALID:
        return value.lower()
    return default


# ---------------------------------------------------------------------------
# Source-specific parsers
# ---------------------------------------------------------------------------

def _from_siem(raw: dict) -> NormalizedAlert:
    ts_raw = raw.get("timestamp")
    src_ip = raw.get("src_ip") or None
    desc   = raw.get("description") or None

    return NormalizedAlert(
        id          = _make_id("siem", ts_raw, src_ip, desc),
        source_type = "siem_alert",
        timestamp   = _parse_timestamp(ts_raw),
        src_ip      = src_ip,
        dst_ip      = raw.get("dst_ip") or None,
        hostname    = raw.get("hostname") or None,
        description = desc,
        severity    = _clean_severity(raw.get("severity")),
        raw         = raw,
    )


def _from_intel(raw: dict) -> NormalizedAlert:
    ts_raw         = raw.get("timestamp")
    indicator_type = (raw.get("indicator_type") or "").lower()
    indicator_val  = raw.get("indicator_value") or None
    feed_name      = raw.get("feed_name") or "unknown feed"

    # Map indicator value to the appropriate IP field
    if indicator_type == "ip":
        src_ip = indicator_val
        dst_ip = raw.get("dst_ip") or None
    elif indicator_type in ("domain", "url", "hash"):
        src_ip = None
        dst_ip = raw.get("dst_ip") or None
    else:
        src_ip = None
        dst_ip = raw.get("dst_ip") or None

    # Fall back to a generated description if none provided
    description = raw.get("description") or f"{feed_name}: {indicator_type} indicator ({indicator_val})"

    return NormalizedAlert(
        id          = _make_id("intel", ts_raw, indicator_val, description),
        source_type = "threat_intel",
        timestamp   = _parse_timestamp(ts_raw),
        src_ip      = src_ip,
        dst_ip      = dst_ip,
        hostname    = raw.get("hostname") or None,
        description = description,
        severity    = _clean_severity(raw.get("severity")),
        raw         = raw,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def normalize(raw_events: list[dict]) -> list[NormalizedAlert]:
    """Normalize a list of raw event dicts into NormalizedAlert objects.

    Unknown source_type values produce a best-effort NormalizedAlert using
    the siem parser so no event is silently dropped.
    """
    alerts: list[NormalizedAlert] = []
    for raw in raw_events:
        source_type = (raw.get("source_type") or "").lower()
        try:
            if source_type == "siem_alert":
                alert = _from_siem(raw)
            elif source_type == "threat_intel":
                alert = _from_intel(raw)
            else:
                logger.warning("Unknown source_type %r — applying siem parser", source_type)
                alert = _from_siem(raw)
            alerts.append(alert)
        except Exception:
            logger.exception("Failed to normalize event: %r", raw)
    return alerts


def normalize_file(path: str) -> list[NormalizedAlert]:
    """Load a JSON file and return normalized alerts."""
    with open(path, encoding="utf-8") as fh:
        raw_events = json.load(fh)
    if not isinstance(raw_events, list):
        raise ValueError(f"Expected a JSON array at top level, got {type(raw_events).__name__}")
    return normalize(raw_events)
