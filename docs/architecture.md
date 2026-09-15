# Architecture

## System Architecture

The pipeline is a linear, single-process data transformation with no external services, no network calls, and no persistent state. All processing happens in memory; the only I/O is reading the input JSON file and writing `report.json`.

```mermaid
graph LR
    A["sample.json\n(raw alerts)"] -->|normalize_file()| B["normalizer.py\nNormalizedAlert list"]
    B -->|correlate()| C["correlator.py\nCorrelationCluster list"]
    C -->|map_cluster()| D["mitre_mapper.py\nMitreTechnique list per cluster"]
    C --> E["main.py\nreport builder"]
    D --> E
    E -->|json.dump()| F["report.json\n(machine-readable)"]
    E -->|_print_report()| G["stdout\nBLUF + 4 sections"]
```

---

## Components

| File | Responsibility |
|---|---|
| [`src/main.py`](../src/main.py) | Entry point. Parses CLI arguments, orchestrates the full pipeline (normalise → correlate → map → report), builds the BLUF, writes `report.json`, and prints the structured stdout output. |
| [`src/normalizer.py`](../src/normalizer.py) | Converts heterogeneous raw events into a unified `NormalizedAlert` dataclass. Handles `siem_alert` and `threat_intel` source types with separate parsers. Assigns a deterministic SHA-256 ID to every alert. |
| [`src/correlator.py`](../src/correlator.py) | Groups `NormalizedAlert` objects into `CorrelationCluster` objects using configurable `CorrelationRule` definitions. Computes per-cluster severity (max of member severities) and a risk score. Returns clusters sorted by risk score descending. |
| [`src/mitre_mapper.py`](../src/mitre_mapper.py) | Maps each cluster to MITRE ATT&CK techniques via a 10-entry `TECHNIQUE_MAP`. Uses two-stage whole-word regex matching (positive keywords, then negation suppression). Returns deduplicated `MitreTechnique` objects with a `matched_keywords` audit list. |
| [`src/sample.json`](../src/sample.json) | A 23-event realistic dataset covering five attack scenarios: credential dumping, lateral movement, C2 beacon, brute force, and phishing, plus isolated events for PowerShell execution, tool download, DLL injection, and a C2 domain indicator. |

---

## Data Flow

### 1. Ingest

`main.py` opens the input file and passes it to `normalizer.normalize_file()`. The file must be a JSON array at the top level. The raw list of dicts is passed to `normalizer.normalize()`.

### 2. Normalise

For each raw event dict, `normalize()` selects the appropriate source parser:

- **`siem_alert`** → `_from_siem()`: extracts `src_ip`, `dst_ip`, `hostname`, `description`, `severity`, and `timestamp`. The timestamp is parsed from ISO 8601 to a UTC-aware `datetime` via `_parse_timestamp()`. If parsing fails, `timestamp` is set to `None` rather than dropping the event.
- **`threat_intel`** → `_from_intel()`: extracts `indicator_type` and `indicator_value`; maps `ip`-type indicators to `src_ip` and leaves `domain`/`url`/`hash` indicators with `src_ip = None`. Falls back to a generated description if the `description` field is absent.
- **Unknown** → falls back to `_from_siem()` with a warning log entry.

Every event receives a 12-character deterministic ID computed as `SHA-256(source_type | timestamp | src_ip | description)[:12]`.

The output is a flat `list[NormalizedAlert]` sorted by timestamp in the correlator (not here — the normaliser returns in input order).

### 3. Correlate

`correlator.correlate()` processes alerts in timestamp order (ascending). For each alert, it walks the existing cluster list and checks each `CorrelationRule` in order:

1. If all `match_fields` are `None` on either the cluster's anchor alert or the candidate alert, skip this rule.
2. If all `match_fields` share the same non-`None` value between the anchor and candidate, and the candidate's timestamp is within `time_window_seconds` of the cluster's `last_seen`, the candidate is merged into the cluster.
3. The first matching rule wins; the first matching cluster wins. The rule name is recorded in `cluster.matched_rule` on the first merge.
4. Unmerged alerts become new singleton clusters.

After all alerts are assigned, each cluster's `severity` is set to the maximum severity across its members and `risk_score = base_score × min(alert_count / 3, 3.0)`.

The default rules are:

| Rule name | Match fields | Time window |
|---|---|---|
| `ip-pair` | `src_ip`, `dst_ip` | 300 seconds |
| `src-host` | `src_ip`, `hostname` | 300 seconds |

### 4. MITRE ATT&CK Mapping

`mitre_mapper.map_cluster()` calls `_match_alert()` on every alert in the cluster. `_match_alert()` concatenates `description` and `raw["rule_name"]` into a search string, then checks each entry in `TECHNIQUE_MAP`:

1. Check all `keywords` using `re.search(r'\b' + re.escape(kw) + r'\b', text, re.IGNORECASE)`. If none match, skip.
2. Check all `negate_keywords` the same way. If any match, suppress the technique and log at DEBUG.
3. Otherwise, record a `MitreTechnique` with the matched keyword list.

`map_cluster()` deduplicates across cluster members: if the same technique ID fires on two different alerts, the `matched_keywords` lists are merged.

### 5. Report Assembly

`main.py._build_report()` computes:
- `severity_counts` — count of clusters at each severity level.
- `top_techniques` — top-5 ATT&CK technique IDs by number of clusters they appear in.

`_build_cluster_dict()` flattens each `CorrelationCluster` + its `MitreTechnique` list into a plain `dict` suitable for JSON serialisation, applying the T1566 severity floor.

`_build_bluf()` generates the three-sentence BLUF and an optional NOTES line for clusters corroborated by both SIEM and threat intel.

### 6. Output

- `report.json` — written via `json.dump()` with a custom `_DatetimeEncoder` that serialises `datetime` objects to ISO 8601 strings. Written to the same directory as the input file by default, or to the path specified by `--output`.
- **stdout** — `_print_report()` word-wraps the BLUF to 70 characters, then prints Sections 1–4 using ASCII separator lines.

---

## Security Considerations

- No network calls are made at any point. The tool is fully air-gap safe.
- No secrets, credentials, or environment variables are required or read.
- The input file path is provided by the user on the CLI; there is no user-controllable path construction beyond `pathlib.Path(args.input_file)`.
- Output is written to a file path derived from the input path or from `--output`; no web server, socket, or remote endpoint is involved.

---

## Scalability Notes

The current implementation is a single-threaded, in-memory pipeline. For the hackathon prototype and typical SOC alert batch sizes (hundreds to low thousands of events), this is sufficient. Paths to production scale:

- **Streaming input:** Replace `normalize_file()` with a generator that yields `NormalizedAlert` objects from a Kafka or SIEM API stream.
- **Incremental correlation:** Replace the greedy single-pass algorithm with a sliding-window state machine that maintains open clusters across batches.
- **Parallel ATT&CK mapping:** `map_cluster()` is stateless per cluster and could be parallelised with `concurrent.futures.ThreadPoolExecutor` with no changes to the public API.
- **Persistent report store:** Serialise `report.json` to a PostgreSQL or Elasticsearch index for cross-run trend analysis and MTTD tracking.
