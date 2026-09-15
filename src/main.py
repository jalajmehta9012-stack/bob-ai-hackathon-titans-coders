"""
main.py - Threat Correlation System entry point.

Usage:
  python main.py <input_file> [--output PATH] [--time-window SECONDS]
                              [--match-fields FIELD,FIELD]

Produces:
  - report.json          -- machine-readable full report
  - stdout               -- BLUF paragraph + 4-section structured summary
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import correlator as cor
import mitre_mapper as mm
import normalizer as nrm

# ---------------------------------------------------------------------------
# JSON serialisation
# ---------------------------------------------------------------------------

class _DatetimeEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            return o.isoformat()
        return super().default(o)


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _severity_badge(severity: str) -> str:
    return f"[{severity.upper()}]"


def _build_cluster_dict(cluster: cor.CorrelationCluster, techniques: list[mm.MitreTechnique]) -> dict:
    src_ips      = sorted({a.src_ip   for a in cluster.alerts if a.src_ip})
    hostnames    = sorted({a.hostname for a in cluster.alerts if a.hostname})
    source_types = sorted({a.source_type for a in cluster.alerts})

    # T1566 severity floor: any cluster containing Phishing is at least HIGH
    severity = cluster.severity
    tech_ids = {t.technique_id for t in techniques}
    if "T1566" in tech_ids and severity not in ("critical", "high"):
        severity = "high"

    final_risk = cor.risk_score(severity, len(cluster.alerts))

    return {
        "cluster_id":   cluster.cluster_id,
        "severity":     severity,
        "risk_score":   final_risk,
        "matched_rule": cluster.matched_rule,
        "first_seen":   cluster.first_seen,
        "last_seen":    cluster.last_seen,
        "alert_count":  len(cluster.alerts),
        "source_types": source_types,
        "src_ips":      src_ips,
        "hostnames":    hostnames,
        "techniques": [
            {
                "id":               t.technique_id,
                "name":             t.technique_name,
                "tactic":           t.tactic,
                "matched_keywords": t.matched_keywords,
            }
            for t in techniques
        ],
        "alerts": [a.raw for a in cluster.alerts],
    }


def _build_report(
    raw_count: int,
    cluster_dicts: list[dict],
) -> dict:
    severity_counts = {s: 0 for s in _SEVERITY_ORDER}
    technique_freq: Counter = Counter()

    for cd in cluster_dicts:
        sev = cd["severity"]
        if sev in severity_counts:
            severity_counts[sev] += 1
        for t in cd["techniques"]:
            technique_freq[(t["id"], t["name"])] += 1

    top_techniques = [
        {"id": tid, "name": tname, "cluster_count": count}
        for (tid, tname), count in technique_freq.most_common(5)
    ]

    return {
        "generated_at":    datetime.now(timezone.utc),
        "total_raw_alerts": raw_count,
        "total_clusters":  len(cluster_dicts),
        "severity_counts": severity_counts,
        "top_techniques":  top_techniques,
        "clusters":        cluster_dicts,
    }


# ---------------------------------------------------------------------------
# BLUF generator
# ---------------------------------------------------------------------------

def _build_bluf(
    raw_count: int,
    cluster_dicts: list[dict],
    top: dict,
) -> tuple[str, str]:
    unique_ips = {ip for cd in cluster_dicts for ip in cd["src_ips"]}
    total_clusters = len(cluster_dicts)
    high_or_critical = [cd for cd in cluster_dicts if cd["severity"] in ("critical", "high")]
    mixed_clusters   = [
        cd for cd in cluster_dicts
        if "siem_alert" in cd["source_types"] and "threat_intel" in cd["source_types"]
    ]

    # Sentence 1 — bottom line
    s1 = (
        f"Analysis of {raw_count} raw alerts produced {total_clusters} correlated "
        f"cluster{'s' if total_clusters != 1 else ''} across {len(unique_ips)} unique source IP"
        f"{'s' if len(unique_ips) != 1 else ''}."
    )

    # Sentence 2 — why it matters (name the top cluster)
    top_techniques = top.get("techniques", [])
    tech_str = (
        ", ".join(f"{t['id']} ({t['name']})" for t in top_techniques[:2])
        if top_techniques else "unknown technique"
    )
    top_ips   = top.get("src_ips", [])
    top_hosts = top.get("hostnames", [])
    top_asset = top_ips[0] if top_ips else (top_hosts[0] if top_hosts else "unknown asset")

    if high_or_critical:
        s2 = (
            f"The highest-risk cluster ({top['cluster_id']}, {_severity_badge(top['severity'])}, "
            f"risk score {top['risk_score']}) originates from {top_asset} and maps to {tech_str}."
        )
    else:
        s2 = (
            f"No critical or high severity clusters were identified; "
            f"the top cluster ({top['cluster_id']}) has severity {top['severity']} "
            f"and maps to {tech_str}."
        )

    # Sentence 3 — what to do
    if high_or_critical:
        s3 = (
            f"Immediate investigation is recommended for "
            f"{len(high_or_critical)} critical/high cluster"
            f"{'s' if len(high_or_critical) != 1 else ''}; "
            f"review report.json for full detail."
        )
    else:
        s3 = "No critical or high severity clusters were identified; standard monitoring is sufficient."

    notes = ""
    if mixed_clusters:
        ids = ", ".join(cd["cluster_id"] for cd in mixed_clusters)
        notes = (
            f"NOTES: Threat intelligence corroborates SIEM activity in "
            f"{len(mixed_clusters)} cluster{'s' if len(mixed_clusters) != 1 else ''} "
            f"({ids}), increasing confidence in these findings."
        )

    return f"{s1} {s2} {s3}", notes


# ---------------------------------------------------------------------------
# Stdout printer
# ---------------------------------------------------------------------------

_SEP  = "-" * 72
_SEP2 = "=" * 72


def _print_report(bluf: str, notes: str, cluster_dicts: list[dict], report: dict) -> None:
    # BLUF
    print()
    print(_SEP2)
    print("  BOTTOM LINE UP FRONT (BLUF)")
    print(_SEP2)
    # Word-wrap at ~70 chars for readability
    words, line = bluf.split(), ""
    for word in words:
        if len(line) + len(word) + 1 > 70 and line:
            print(f"  {line}")
            line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        print(f"  {line}")
    if notes:
        print()
        # Word-wrap the NOTES line the same way
        words, line = notes.split(), ""
        for word in words:
            if len(line) + len(word) + 1 > 70 and line:
                print(f"  {line}")
                line = word
            else:
                line = f"{line} {word}".strip()
        if line:
            print(f"  {line}")
    print(_SEP2)

    # Section 1 -- Alert counts by severity
    print()
    print("  SECTION 1 -- ALERT COUNTS BY SEVERITY")
    print(_SEP)
    for sev in _SEVERITY_ORDER:
        count = report["severity_counts"].get(sev, 0)
        bar   = "#" * count
        print(f"  {sev:<10}  {count:>3}  {bar}")

    # Section 2 -- Top 5 ATT&CK techniques
    print()
    print("  SECTION 2 -- TOP 5 ATT&CK TECHNIQUES (by cluster frequency)")
    print(_SEP)
    if report["top_techniques"]:
        for i, t in enumerate(report["top_techniques"], 1):
            print(f"  {i}. [{t['id']}] {t['name']}  -- {t['cluster_count']} cluster(s)")
    else:
        print("  (no techniques mapped)")

    # Section 3 -- Affected hosts / IPs
    print()
    print("  SECTION 3 -- AFFECTED HOSTS / IPs")
    print(_SEP)
    all_ips   = sorted({ip   for cd in cluster_dicts for ip   in cd["src_ips"]})
    all_hosts = sorted({h    for cd in cluster_dicts for h    in cd["hostnames"]})
    print(f"  Source IPs  : {', '.join(all_ips)  or '(none)'}")
    print(f"  Hostnames   : {', '.join(all_hosts) or '(none)'}")

    # Section 4 -- Cluster detail
    print()
    print("  SECTION 4 -- CLUSTER DETAIL  (sorted by risk score desc)")
    for cd in cluster_dicts:   # already sorted by risk_score desc
        print()
        print(_SEP)
        badge = _severity_badge(cd["severity"])
        rule  = cd["matched_rule"] or "singleton"
        print(
            f"  {badge:<12} {cd['cluster_id']}  "
            f"risk={cd['risk_score']:.2f}  rule={rule}  alerts={cd['alert_count']}"
        )
        # Time range
        fs = cd["first_seen"].isoformat() if isinstance(cd["first_seen"], datetime) else str(cd["first_seen"])
        ls = cd["last_seen"].isoformat()  if isinstance(cd["last_seen"],  datetime) else str(cd["last_seen"])
        print(f"  Time        : {fs}  ->  {ls}")
        # Assets
        print(f"  Src IPs     : {', '.join(cd['src_ips'])  or '(none)'}")
        print(f"  Hostnames   : {', '.join(cd['hostnames']) or '(none)'}")
        # Source types
        print(f"  Sources     : {', '.join(cd['source_types'])}")
        # Techniques
        if cd["techniques"]:
            techs = "  |  ".join(
                f"{t['id']} {t['name']} [{t['tactic']}]"
                for t in cd["techniques"]
            )
            print(f"  Techniques  : {techs}")
        else:
            print("  Techniques  : (none mapped)")

    print()
    print(_SEP)
    print(
        f"  {report['total_clusters']} cluster(s) from {report['total_raw_alerts']} raw alerts  "
        f"| generated {report['generated_at'].isoformat()}"
    )
    print(_SEP)
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="main.py",
        description="Ingest SIEM alerts + threat intel, correlate, map to MITRE ATT&CK, report.",
    )
    p.add_argument(
        "input_file",
        nargs="?",
        default="sample.json",
        help="Path to JSON file containing raw alert/intel events (default: sample.json).",
    )
    p.add_argument(
        "--output", "-o",
        default=None,
        help="Path for the JSON report output (default: report.json next to input).",
    )
    p.add_argument(
        "--time-window",
        type=int,
        default=300,
        metavar="SECONDS",
        help="Correlation time window in seconds (default: 300).",
    )
    p.add_argument(
        "--match-fields",
        default=None,
        metavar="FIELD,FIELD",
        help=(
            "Comma-separated field names to match on, e.g. src_ip,dst_ip. "
            "Overrides DEFAULT_RULES with a single custom rule."
        ),
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    args = _parse_args(argv)

    # ── Load & normalise ─────────────────────────────────────────────────
    input_path = Path(args.input_file)
    if not input_path.exists():
        print(f"ERROR: input file not found: {input_path}", file=sys.stderr)
        return 1

    try:
        alerts = nrm.normalize_file(str(input_path))
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: could not parse input file: {exc}", file=sys.stderr)
        return 1

    if not alerts:
        print("WARNING: no alerts produced from input -- nothing to report.", file=sys.stderr)
        return 0

    # ── Correlation rules ────────────────────────────────────────────────
    if args.match_fields:
        fields = [f.strip() for f in args.match_fields.split(",") if f.strip()]
        rules = [
            cor.CorrelationRule(
                name                = "custom",
                match_fields        = fields,
                time_window_seconds = args.time_window,
            )
        ]
    else:
        rules = [
            cor.CorrelationRule(
                name                = r.name,
                match_fields        = r.match_fields,
                time_window_seconds = args.time_window,
            )
            for r in cor.DEFAULT_RULES
        ]

    # ── Correlate ────────────────────────────────────────────────────────
    clusters = cor.correlate(alerts, rules)   # sorted by risk_score desc

    # ── MITRE mapping ────────────────────────────────────────────────────
    cluster_techniques: dict[str, list[mm.MitreTechnique]] = {
        c.cluster_id: mm.map_cluster(c) for c in clusters
    }

    # ── Build report dicts ───────────────────────────────────────────────
    cluster_dicts = [
        _build_cluster_dict(c, cluster_techniques[c.cluster_id])
        for c in clusters
    ]
    report = _build_report(len(alerts), cluster_dicts)

    # ── Write JSON report ─────────────────────────────────────────────────
    if args.output:
        out_path = Path(args.output)
    else:
        out_path = input_path.parent / "report.json"

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, cls=_DatetimeEncoder, indent=2)

    # ── Print to stdout ───────────────────────────────────────────────────
    bluf, notes = _build_bluf(len(alerts), cluster_dicts, cluster_dicts[0])
    _print_report(bluf, notes, cluster_dicts, report)

    print(f"Report written to: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
