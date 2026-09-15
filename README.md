# Threat Correlation & ATT&CK Mapper

> Ingest SIEM alerts and threat intelligence, correlate them into clusters, map every cluster to MITRE ATT&CK techniques, and produce a machine-readable JSON report plus a command-line BLUF (Bottom Line Up Front) summary — zero external dependencies.

---

## 👥 Team

| Field | Value |
|---|---|
| **Team Name** | Titans Coders |
| **Track** | AI |
| **Members** | Titans Coders |

---

## 🎯 Problem Statement

Security Operations Centre (SOC) analysts and defence teams are buried in thousands of individual SIEM alerts per shift, with no fast way to group related events, attribute them to known adversary techniques, or surface an executive-ready summary. Existing tooling either requires expensive platform licences, produces alert fatigue through poor signal-to-noise, or lacks a structured BLUF output format that commanders and senior stakeholders can act on immediately. The result is slower incident response and preventable escalation of breaches.

---

## 💡 Solution

We built a pure-Python command-line pipeline that ingests a raw JSON alert feed (SIEM events and threat intelligence indicators), normalises it into a unified schema, groups related alerts into correlation clusters using configurable field-matching rules and a time window, maps each cluster to MITRE ATT&CK techniques via two-stage keyword matching, and writes both a structured `report.json` and a human-readable BLUF to stdout. The BLUF format matches the CTID (Centre for Threat-Informed Defence) convention — one sentence of bottom line, one sentence naming the highest-risk cluster, and one sentence of recommended action. Because the entire solution uses Python 3 standard library only, it runs on any system with Python 3.10+ and requires no installation step.

---

## ✨ Key Features

- **Alert correlation:** Groups SIEM and threat-intel events into clusters based on shared IP pairs or source-IP/hostname pairs within a configurable 5-minute time window — surfacing multi-step attack chains that individual alerts would miss.
- **MITRE ATT&CK mapping:** Matches each cluster to up to 10 ATT&CK techniques (T1003, T1021, T1059, T1071, T1078, T1083, T1105, T1055, T1110, T1566) using whole-word keyword matching with negation suppression; every match records the exact triggering keywords for auditable attribution.
- **Risk scoring:** Ranks clusters by a severity-weighted risk score (`base_score × min(alert_count/3, 3.0)`), so the highest-confidence, highest-severity activity always appears first.
- **CTID BLUF output:** Prints a structured three-sentence Bottom Line Up Front to stdout — severity bar chart, top-5 ATT&CK technique frequency, affected asset inventory, and per-cluster detail — readable in under 30 seconds by an analyst or commander.
- **Dual output with zero dependencies:** Writes a fully machine-readable `report.json` (for downstream SOAR/SIEM ingest) and the human-readable console summary simultaneously, using only Python 3 standard library modules.

---

## 🛠️ Tech Stack

| Category | Technologies |
|---|---|
| **Languages** | Python 3.10+ (standard library only — `argparse`, `hashlib`, `json`, `re`, `dataclasses`, `datetime`, `pathlib`, `logging`, `collections`) |
| **Frameworks** | None — no third-party packages required |
| **IBM Technologies** | IBM Bob (AI coding assistant used throughout development) |
| **Databases** | None — report output is written to `report.json` |
| **Other** | MITRE ATT&CK framework (technique taxonomy), CTID BLUF format |

---

## 📁 Repository Structure

```
├── src/
│   ├── main.py           # Entry point — orchestrates the full pipeline
│   ├── normalizer.py     # Normalises raw SIEM/intel events to NormalizedAlert
│   ├── correlator.py     # Groups alerts into CorrelationClusters
│   ├── mitre_mapper.py   # Maps clusters to MITRE ATT&CK techniques
│   └── sample.json       # 23-event realistic attack scenario dataset
├── docs/
│   ├── problem-statement.md
│   ├── solution-overview.md
│   ├── architecture.md
│   └── setup-guide.md
├── demo/                 # Demo artifacts
│   ├── screenshots/
│   └── demo-video-link.txt
├── presentation/         # Slide deck
└── submission.yaml       # Structured submission metadata
```

---

## ⚡ How to Run

```bash
# 1. Clone the repo
git clone https://github.com/your-org/bob-ai-hackathon-titans-coders.git
cd bob-ai-hackathon-titans-coders

# 2. No dependencies to install — Python 3.10+ stdlib only

# 3. Run against the included sample dataset
python src/main.py src/sample.json

# Output:
#   - Prints BLUF + 4-section structured report to stdout
#   - Writes src/report.json (machine-readable full report)
```

Optional flags:

```bash
# Custom output path
python src/main.py src/sample.json --output /tmp/report.json

# Override correlation time window (default: 300 seconds)
python src/main.py src/sample.json --time-window 600

# Override match fields with a single custom rule
python src/main.py src/sample.json --match-fields src_ip,hostname
```

---

## 🖥️ Demo

| Artifact | Link |
|---|---|
| 📹 Demo Video | [See demo/demo-video-link.txt](demo/demo-video-link.txt) |
| 🖼️ Screenshots | [See demo/screenshots/](demo/screenshots/) |
| 📊 Presentation | [See presentation/](presentation/) |

---

## ⚠️ Known Limitations

- **Keyword-based ATT&CK mapping only:** Technique matching uses whole-word regex against the `description` and `rule_name` fields; it does not use ML embeddings or a full ATT&CK navigator query, so techniques not covered by the 10-entry `TECHNIQUE_MAP` will not be detected.
- **Greedy, single-pass correlation:** The correlator uses a greedy algorithm — an alert is assigned to the first cluster it matches. In edge cases with overlapping IP pairs, this may produce suboptimal cluster boundaries.
- **No persistent state:** Each run is fully stateless; there is no database or time-series store, so cross-run correlation (e.g., the same attacker returning a day later) is not supported.
- **Flat JSON input only:** The normaliser accepts a top-level JSON array; CEF, syslog, and XML feed formats are not supported without a pre-processing step.
- **Single-threaded:** Large alert files (tens of thousands of events) will process sequentially; no parallelism is implemented.

---

## 🏅 What We're Most Proud Of

The cleanest part of this submission is the end-to-end pipeline design: four small, single-responsibility modules that can each be tested in isolation, produce a fully deterministic output for any given input, and require absolutely nothing beyond a Python 3.10 interpreter. The BLUF generator is particularly satisfying — it distils 23 raw alerts into a three-sentence executive summary that names the highest-risk cluster, its source IP, its ATT&CK techniques, and what action to take, in under a second. The `matched_rule` and `matched_keywords` fields in the JSON output mean every correlation and every technique attribution can be fully explained and audited, which is essential for defence and SOC use cases.

---
