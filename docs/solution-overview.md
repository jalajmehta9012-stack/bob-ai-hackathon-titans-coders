# Solution Overview

## What We Built

The Threat Correlation & ATT&CK Mapper is a command-line pipeline written in pure Python 3. It accepts a JSON file containing raw security events from SIEM systems and threat intelligence feeds, groups them into correlated attack clusters, maps each cluster to MITRE ATT&CK techniques, scores the clusters by risk, and produces two outputs simultaneously: a machine-readable `report.json` and a human-readable BLUF (Bottom Line Up Front) on stdout.

The entire tool requires no installation — there are no third-party dependencies. It runs on any system with Python 3.10+.

---

## How It Works

1. **Ingest.** `main.py` reads a flat JSON array of raw alert/indicator objects from the input file. Each object is a SIEM alert (`"source_type": "siem_alert"`) or a threat intelligence entry (`"source_type": "threat_intel"`).

2. **Normalise.** `normalizer.py` converts each raw event into a `NormalizedAlert` dataclass with a consistent schema: `id`, `source_type`, `timestamp` (UTC-aware `datetime`), `src_ip`, `dst_ip`, `hostname`, `description`, `severity`, and the original `raw` dict. SIEM events and threat-intel indicators are parsed by separate dedicated parsers. For threat-intel, the `indicator_value` field is mapped to `src_ip` when the `indicator_type` is `"ip"`; domain, URL, and hash indicators leave `src_ip` as `None`. Every event is assigned a deterministic 12-character SHA-256 ID; unknown `source_type` values fall back to the SIEM parser so no event is silently dropped.

3. **Correlate.** `correlator.py` groups normalised alerts into `CorrelationCluster` objects using configurable `CorrelationRule` definitions. Two built-in rules run by default:
   - **`ip-pair`** — groups alerts that share the same `src_ip` and `dst_ip` within a 300-second window.
   - **`src-host`** — groups alerts that share the same `src_ip` and `hostname` within a 300-second window.

   The algorithm is greedy and deterministic: alerts are processed in timestamp order, and the first cluster and rule that match win. Alerts whose relevant fields are all `None` are never merged; they become singleton clusters. Each cluster's `matched_rule` records which rule caused the first merge, providing a complete attribution trail.

4. **Score.** Each cluster's severity is set to the maximum severity across its member alerts (`critical > high > medium > low > info`). The risk score is computed as `base_score × min(alert_count / 3, 3.0)`, where `base_score` is 10.0 / 7.0 / 4.0 / 2.0 / 1.0 for critical / high / medium / low / info. Clusters are sorted by risk score descending so the most dangerous activity is always first. A special T1566 (Phishing) severity floor is applied: any cluster containing a Phishing technique match is promoted to at least `high`.

5. **Map to MITRE ATT&CK.** `mitre_mapper.py` runs each alert's `description` and `rule_name` text through a two-stage matching process against a 10-technique lookup table:
   - **Stage 1 (positive match):** A whole-word, case-insensitive regex checks whether any of the technique's `keywords` appear in the text. Multi-word phrases such as `"remote exec"` and `"password spray"` are supported via `re.escape()`.
   - **Stage 2 (negation suppression):** If any `negate_keywords` also match, the technique is suppressed for that alert. This prevents, for example, the `"credential"` keyword from falsely matching T1003 on test or simulation descriptions.
   
   When the same technique is matched by multiple alerts in a cluster, their `matched_keywords` lists are merged and deduplicated. The final `MitreTechnique` objects carry the full `matched_keywords` list as an audit trail.

6. **Report.** `main.py` assembles the cluster data and technique mappings into a structured report dict, serialises it to `report.json` (datetimes are ISO 8601 strings), and prints four sections to stdout: severity bar chart, top-5 ATT&CK techniques by cluster frequency, affected source IPs and hostnames, and per-cluster detail with time range, assets, sources, and mapped techniques.

7. **BLUF.** A three-sentence executive summary is printed first:
   - Sentence 1 — total raw alerts, cluster count, and unique source IP count.
   - Sentence 2 — the highest-risk cluster's ID, severity badge, risk score, source IP, and top ATT&CK techniques.
   - Sentence 3 — recommended action (immediate investigation, or standard monitoring if no critical/high clusters).
   
   An additional NOTES line is appended when any cluster contains both SIEM and threat-intel data, calling out the corroborated findings.

---

## What Makes It Different from Naive Keyword Alerting

A naive keyword-based SIEM rule fires once per alert. This system is different in three ways:

1. **Cluster-level attribution, not alert-level.** A credential-dumping attack generates five separate alerts (LSASS read, Mimikatz, NTDS access, hashdump, cached credential extraction). A naive rule fires five separate warnings. This system produces one cluster with a `critical` severity, a risk score of `10.0`, the full list of matched techniques, and one BLUF sentence naming the source asset. The analyst sees the attack, not the noise.

2. **Negation suppression prevents false positives.** The T1566 (Phishing) matcher suppresses on `"ntds"` and `"cached credential"` — both of which could trigger `"credential harvest"` in other contexts. The T1003 (Credential Dumping) matcher suppresses on `"test"` and `"simulation"`. This two-stage approach reduces false positive burden without requiring analyst tuning.

3. **Every match is explainable.** The `matched_rule` field on every cluster and the `matched_keywords` field on every technique mean the output can be reproduced, challenged, and defended. There are no probability scores or black-box decisions — every attribution traces back to a specific field value and a specific keyword in the lookup table.

---

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Configurable `CorrelationRule` objects over similarity scoring | Deterministic field-matching rules produce reproducible, auditable clusters. Similarity scoring (e.g., cosine distance on embeddings) would introduce non-determinism and require a model dependency — unacceptable for a defence/SOC context where every decision must be explainable. |
| Dual output: `report.json` + stdout BLUF | Machine-readable JSON can be ingested by downstream SOAR platforms, ticketing systems, or dashboards. The stdout BLUF serves the human analyst or commander who needs an answer in under 30 seconds. Both are produced in a single run. |
| CTID BLUF format (3 sentences: bottom line, top cluster, action) | Adopted from the Centre for Threat-Informed Defence's recommendation for intelligence product formatting. Ensures the output is immediately useful to a reader with no SIEM background. |
| `matched_rule` attribution on every cluster | Analysts need to know *why* two alerts were grouped. Recording the first matching rule name on the cluster provides a concise, human-readable explanation without requiring the analyst to re-run the correlation logic. |
| Python 3 standard library only | Zero-dependency deployment is a hard requirement for many defence and government environments where outbound package installation is restricted or requires a security review. Every module used (`argparse`, `hashlib`, `json`, `re`, `dataclasses`, `datetime`, `pathlib`, `logging`, `collections`) ships with CPython. |
| T1566 severity floor | Phishing is the leading initial access vector in enterprise breaches. A single phishing alert should never be reported as `medium` and lost in the noise. The floor ensures any cluster with a phishing match is at minimum `high`, regardless of the raw severity of the underlying alerts. |

---

## IBM Technologies Used

- **IBM Bob:** Used as the primary AI coding assistant throughout the development of this project. Bob was used for code generation, architecture review, iterative refinement of the correlation and mapping logic, and authoring all documentation. The entire pipeline was developed interactively with Bob in Agent mode, with Bob reading the source files and generating accurate, grounded documentation from the actual code rather than from templates.
