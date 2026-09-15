"""
correlator.py — Group NormalizedAlert objects into CorrelationClusters.

Two alerts are correlated when they share the same values on all
match_fields of a CorrelationRule AND the candidate alert's timestamp
falls within time_window_seconds of the cluster's last_seen timestamp.

Algorithm: greedy, deterministic (alerts sorted by timestamp ascending).
First matching rule wins.  Alerts whose match fields are all None are
never merged (each becomes a singleton cluster).

Public API:
  correlate(alerts, rules) -> list[CorrelationCluster]
  DEFAULT_RULES            — two pre-built CorrelationRule objects
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from normalizer import NormalizedAlert

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

_SEVERITY_RANK: dict[str, int] = {
    "critical": 5,
    "high":     4,
    "medium":   3,
    "low":      2,
    "info":     1,
}

_BASE_SCORE: dict[str, float] = {
    "critical": 10.0,
    "high":      7.0,
    "medium":    4.0,
    "low":       2.0,
    "info":      1.0,
}


def _max_severity(severities: list[str | None]) -> str:
    best = "info"
    for s in severities:
        if s and _SEVERITY_RANK.get(s, 0) > _SEVERITY_RANK.get(best, 0):
            best = s
    return best


def risk_score(severity: str, alert_count: int) -> float:
    """base_score x min(alert_count / 3, 3.0), rounded to 2 dp."""
    base       = _BASE_SCORE.get(severity, 1.0)
    multiplier = min(alert_count / 3.0, 3.0)
    return round(base * multiplier, 2)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class CorrelationRule:
    name: str
    match_fields: list[str]
    time_window_seconds: int


@dataclass
class CorrelationCluster:
    cluster_id: str
    alerts: list["NormalizedAlert"] = field(default_factory=list)
    severity: str = "info"
    risk_score: float = 0.0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    matched_rule: str | None = None   # name of the first rule that caused a merge


# ---------------------------------------------------------------------------
# Default rules
# ---------------------------------------------------------------------------

DEFAULT_RULES: list[CorrelationRule] = [
    CorrelationRule(
        name                = "ip-pair",
        match_fields        = ["src_ip", "dst_ip"],
        time_window_seconds = 300,
    ),
    CorrelationRule(
        name                = "src-host",
        match_fields        = ["src_ip", "hostname"],
        time_window_seconds = 300,
    ),
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _all_none(alert: "NormalizedAlert", fields: list[str]) -> bool:
    """Return True if every field in *fields* is None on *alert*."""
    return all(getattr(alert, f, None) is None for f in fields)


def _fields_match(anchor: "NormalizedAlert", candidate: "NormalizedAlert", fields: list[str]) -> bool:
    """Return True if *anchor* and *candidate* share the same non-None value
    on every field in *fields*.
    """
    for f in fields:
        av = getattr(anchor, f, None)
        cv = getattr(candidate, f, None)
        if av is None or cv is None or av != cv:
            return False
    return True


def _within_window(cluster: CorrelationCluster, alert: "NormalizedAlert", window_seconds: int) -> bool:
    """Return True if *alert*.timestamp is within *window_seconds* of
    *cluster*.last_seen (in either direction, to tolerate slight clock skew).
    """
    if cluster.last_seen is None or alert.timestamp is None:
        return True   # no timestamp data → optimistically allow merge
    delta = abs((alert.timestamp - cluster.last_seen).total_seconds())
    return delta <= window_seconds


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def correlate(
    alerts: list["NormalizedAlert"],
    rules: list[CorrelationRule] | None = None,
) -> list[CorrelationCluster]:
    """Group *alerts* into CorrelationClusters using *rules*.

    Returns clusters sorted by risk_score descending so the caller gets the
    most significant cluster first.
    """
    if rules is None:
        rules = DEFAULT_RULES

    # Deterministic processing order
    sorted_alerts = sorted(
        alerts,
        key=lambda a: a.timestamp or datetime.min.replace(tzinfo=None),
    )

    clusters: list[CorrelationCluster] = []
    cluster_counter = 0

    for alert in sorted_alerts:
        merged = False

        for cluster in clusters:
            anchor = cluster.alerts[0]   # representative / anchor alert

            for rule in rules:
                # Skip if all match fields are None on either side
                if _all_none(alert, rule.match_fields) or _all_none(anchor, rule.match_fields):
                    continue

                if (
                    _fields_match(anchor, alert, rule.match_fields)
                    and _within_window(cluster, alert, rule.time_window_seconds)
                ):
                    cluster.alerts.append(alert)

                    # Update time boundaries
                    if alert.timestamp is not None:
                        if cluster.last_seen is None or alert.timestamp > cluster.last_seen:
                            cluster.last_seen = alert.timestamp
                        if cluster.first_seen is None or alert.timestamp < cluster.first_seen:
                            cluster.first_seen = alert.timestamp

                    # Record the rule name only on the first merge
                    if cluster.matched_rule is None:
                        cluster.matched_rule = rule.name

                    merged = True
                    break   # first matching rule wins

            if merged:
                break   # alert assigned; stop scanning clusters

        if not merged:
            cluster_counter += 1
            ts = alert.timestamp
            clusters.append(
                CorrelationCluster(
                    cluster_id   = f"C{cluster_counter:03d}",
                    alerts       = [alert],
                    first_seen   = ts,
                    last_seen    = ts,
                    matched_rule = None,
                )
            )

    # Finalise severity and risk_score now that all alerts are assigned
    for cluster in clusters:
        cluster.severity   = _max_severity([a.severity for a in cluster.alerts])
        cluster.risk_score = risk_score(cluster.severity, len(cluster.alerts))

    # Return highest-risk first
    return sorted(clusters, key=lambda c: c.risk_score, reverse=True)
