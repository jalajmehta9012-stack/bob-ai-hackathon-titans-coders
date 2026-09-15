"""
mitre_mapper.py — Map NormalizedAlert clusters to MITRE ATT&CK techniques.

Matching strategy:
  - Whole-word regex: re.search(r'\b<keyword>\b', text, re.IGNORECASE)
  - re.escape() applied to every keyword, so multi-word phrases work correctly
  - negate_keywords: if any negation term matches the same text, the technique
    is suppressed for that alert and a debug log entry is emitted
  - matched_keywords on the returned MitreTechnique is the audit trail

Public API:
  map_cluster(cluster) -> list[MitreTechnique]
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from correlator import CorrelationCluster

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class MitreTechnique:
    technique_id: str
    technique_name: str
    tactic: str
    matched_keywords: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Technique lookup table
# ---------------------------------------------------------------------------
# Each entry:
#   technique_id   : ATT&CK ID string
#   technique_name : human-readable name
#   tactic         : ATT&CK tactic name
#   keywords       : list of whole-word trigger terms (any match → candidate)
#   negate_keywords: list of whole-word suppression terms (any match → skip)
# ---------------------------------------------------------------------------

TECHNIQUE_MAP: list[dict] = [
    {
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "keywords": ["credential", "lsass", "mimikatz", "ntds", "hashdump"],
        "negate_keywords": ["test", "simulation"],
    },
    {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
        "keywords": ["lateral", "psexec", "smb", "wmi", "remote exec"],
        "negate_keywords": ["backup", "scheduled"],
    },
    {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "keywords": ["beacon", "c2", "command and control", "exfil", "cobaltstrike"],
        "negate_keywords": [],
    },
    {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "keywords": ["powershell", "cmd", "bash", "script exec", "shellcode"],
        "negate_keywords": ["help", "documentation"],
    },
    {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "keywords": ["valid account", "stolen cred", "account abuse", "privilege escalation"],
        "negate_keywords": [],
    },
    {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "keywords": ["brute force", "password spray", "login attempt", "auth failure"],
        "negate_keywords": ["lockout policy", "test"],
    },
    {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "Defense Evasion",
        "keywords": ["inject", "dll injection", "process hollow", "reflective"],
        "negate_keywords": [],
    },
    {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "keywords": ["file discovery", "directory enum", "ls -r", "dir /s"],
        "negate_keywords": [],
    },
    {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "keywords": ["tool transfer", "wget", "curl", "bitsadmin", "certutil"],
        "negate_keywords": [],
    },
    {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "Initial Access",
        "keywords": ["phish", "spearphish", "malicious attachment", "credential harvest"],
        "negate_keywords": ["ntds", "cached credential"],
    },
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _whole_word_pattern(term: str) -> re.Pattern:
    """Compile a whole-word, case-insensitive regex for *term*.

    re.escape handles multi-word phrases (e.g. 'remote exec') and special
    characters safely.  The \\b anchors apply around the full escaped phrase.
    """
    return re.compile(r"\b" + re.escape(term) + r"\b", re.IGNORECASE)


def _match_alert(alert) -> list[MitreTechnique]:
    """Return a list of MitreTechnique objects matched against *alert*.

    Search text is built from description + rule_name so both prose and
    structured rule labels are checked.
    """
    description = alert.description or ""
    rule_name = alert.raw.get("rule_name", "") or ""
    search_text = f"{description} {rule_name}"

    matched: list[MitreTechnique] = []

    for entry in TECHNIQUE_MAP:
        tid = entry["technique_id"]

        # ── Step 1: find any triggering keyword ──────────────────────────
        fired_keywords: list[str] = []
        for kw in entry["keywords"]:
            if _whole_word_pattern(kw).search(search_text):
                fired_keywords.append(kw)

        if not fired_keywords:
            continue  # no positive signal — skip

        # ── Step 2: check negation keywords ──────────────────────────────
        negated_by: list[str] = []
        for nkw in entry["negate_keywords"]:
            if _whole_word_pattern(nkw).search(search_text):
                negated_by.append(nkw)

        if negated_by:
            logger.debug(
                "Technique %s suppressed for alert %s — negation keyword(s) matched: %s",
                tid,
                alert.id,
                negated_by,
            )
            continue  # suppressed

        logger.debug(
            "Technique %s matched alert %s via keyword(s): %s",
            tid,
            alert.id,
            fired_keywords,
        )
        matched.append(
            MitreTechnique(
                technique_id=tid,
                technique_name=entry["technique_name"],
                tactic=entry["tactic"],
                matched_keywords=fired_keywords,
            )
        )

    return matched


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def map_cluster(cluster: "CorrelationCluster") -> list[MitreTechnique]:
    """Map all alerts in *cluster* to MITRE ATT&CK techniques.

    Returns a deduplicated list sorted by technique_id.  When the same
    technique is matched by multiple member alerts, their matched_keywords
    lists are merged and deduplicated.
    """
    # technique_id → merged MitreTechnique
    seen: dict[str, MitreTechnique] = {}

    for alert in cluster.alerts:
        for technique in _match_alert(alert):
            tid = technique.technique_id
            if tid not in seen:
                seen[tid] = technique
            else:
                # Merge keyword lists — preserve insertion order, no duplicates
                existing_kws = seen[tid].matched_keywords
                for kw in technique.matched_keywords:
                    if kw not in existing_kws:
                        existing_kws.append(kw)

    return sorted(seen.values(), key=lambda t: t.technique_id)


# ---------------------------------------------------------------------------
# Inline test — run with: python mitre_mapper.py
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    import pathlib
    from dataclasses import dataclass as _dc

    # Minimal stand-in for NormalizedAlert — only the fields _match_alert needs
    @_dc
    class _Alert:
        id: str
        description: str
        raw: dict

    sample_path = pathlib.Path(__file__).parent / "sample.json"
    raw_events = json.loads(sample_path.read_text(encoding="utf-8"))

    print(f"Loaded {len(raw_events)} entries from {sample_path.name}\n")
    print(f"{'#':<4}  {'SOURCE':<12}  {'DESCRIPTION':<55}  TECHNIQUES")
    print("-" * 110)

    no_match_count = 0
    for idx, entry in enumerate(raw_events, start=1):
        description = entry.get("description") or ""
        rule_name   = entry.get("rule_name") or ""
        source      = entry.get("source_type", "unknown")
        alert       = _Alert(id=str(idx), description=description, raw=entry)

        techniques  = _match_alert(alert)

        if techniques:
            for i, t in enumerate(techniques):
                prefix = f"{idx:<4}  {source:<12}  {description[:55]:<55}" if i == 0 else f"{'':4}  {'':12}  {'':55}"
                kws    = ", ".join(t.matched_keywords)
                print(f"{prefix}  [{t.technique_id}] {t.technique_name} (via: {kws})")
        else:
            no_match_count += 1
            print(f"{idx:<4}  {source:<12}  {description[:55]:<55}  (no match)")

    print("-" * 110)
    print(f"\nTotal entries: {len(raw_events)}  |  Matched: {len(raw_events) - no_match_count}  |  No match: {no_match_count}")
