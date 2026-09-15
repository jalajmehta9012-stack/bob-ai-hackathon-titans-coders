# Problem Statement

## Background

Modern enterprise and government networks generate security events at a rate that far exceeds human capacity to review. A mid-sized organisation's Security Information and Event Management (SIEM) system routinely fires thousands of individual alerts per day — each one a raw signal from an endpoint detection agent, a network sensor, or a threat intelligence feed. Individually, these signals are often ambiguous. Collectively, a handful of them may describe a coordinated, multi-stage intrusion in progress.

The discipline of cyber threat intelligence and Security Operations Centre (SOC) analysis exists to convert that noise into actionable decisions. The challenge is doing it fast enough to matter.

---

## The Problem

Security analysts today face three compounding problems:

1. **Alert volume and fatigue.** A typical enterprise SOC receives between 1,000 and 10,000 SIEM alerts per day. Analysts must manually triage each one, often spending 15–45 minutes per incident just to determine whether a cluster of related alerts represents a real attack or a false positive. At that rate, genuine intrusions sit unactioned for hours.

2. **No BLUF-format summaries for decision-makers.** Military and defence operations, as well as executive stakeholders in corporate SOCs, need conclusions in a Bottom Line Up Front (BLUF) format: what happened, how bad is it, what should I do. Existing SIEM dashboards produce tables and charts that require specialist interpretation — they do not produce a three-sentence briefing a commander can act on immediately.

3. **False positive fatigue erodes trust.** When analysts are overwhelmed by volume, they begin tuning out or suppressing alert categories wholesale. Critical alerts are missed not because the detection failed, but because the analyst has stopped reading. This is the documented cause of several high-profile breaches where the intrusion was logged but never acted upon.

---

## Who Is Affected

**SOC analysts** in enterprises and government agencies who spend the majority of their shift triaging raw alerts rather than investigating confirmed incidents. They need automated grouping and prioritisation so they can focus human attention where it matters.

**Defence analysts and commanders** who require concise, authoritative summaries of network threat status before making decisions about incident response, network isolation, or escalation. They do not have time to read SIEM dashboards; they need a single paragraph that tells them the bottom line.

**Incident response teams** who need to reconstruct the sequence of events across a multi-stage attack. Individual alerts from different source types (EDR, network, threat intel feeds) need to be correlated and attributed to known adversary techniques before a coherent incident timeline can be established.

**Small security teams** (5–20 analysts) who cannot afford enterprise SOAR platforms costing hundreds of thousands of dollars per year, but still need correlation and MITRE ATT&CK attribution to meet compliance and audit requirements.

---

## Why It Matters

The cost of slow or missed detection is high:

- **Mean Time to Detect (MTTD)** for a network intrusion is [reported](https://www.ibm.com/reports/threat-intelligence) at over 200 days industry-wide. Alert correlation is one of the primary levers available to reduce it.
- A single undetected lateral movement campaign — the kind that begins with one compromised workstation and ends at domain administrator — can take weeks of effort and millions of dollars to remediate.
- In defence and critical infrastructure contexts, a delayed response to a Command-and-Control (C2) beacon or credential dumping event is not a financial risk; it is an operational and national security risk.
- False positive fatigue is not a minor inconvenience. It is the proximate cause of analyst burnout, staff turnover, and the "alert blindness" that allowed several major breaches to proceed undetected despite the evidence being present in the logs.

---

## Why Existing Solutions Fall Short

**Enterprise SIEM platforms** (Splunk, Microsoft Sentinel, IBM QRadar) provide powerful correlation engines, but they are expensive, require significant tuning effort, and produce outputs designed for dashboard consumption rather than briefing-ready summaries. Their ATT&CK mappings are either manual or require purchased content packs.

**Open-source correlation engines** (Sigma rules, Suricata) focus on detection at the individual alert level and do not provide cross-event clustering, risk scoring, or executive summary generation out of the box.

**Threat intelligence platforms** (MISP, OpenCTI) ingest and share indicators but do not correlate them against live SIEM data or produce cluster-level risk assessments.

**LLM-based summarisation tools** can produce narrative summaries but cannot perform deterministic, auditable attribution — every technique match must trace back to a specific keyword and rule for the output to be defensible in an incident report or legal proceeding.

None of these options provides the combination of: zero-dependency deployment, configurable correlation rules, deterministic ATT&CK attribution with an audit trail, and a CTID-format BLUF summary — in a single tool that runs with `python src/main.py src/sample.json`.
