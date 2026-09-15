# Setup Guide

> **This file is read by the automated evaluation pipeline. Be precise and complete.**

## Prerequisites

Before you begin, ensure you have the following:

- [x] **Python 3.10 or later** — the only runtime requirement. No virtual environment or package manager is needed.

To verify your Python version:

```powershell
# Windows (PowerShell)
python --version
```

```bash
# macOS / Linux
python3 --version
```

Expected output: `Python 3.10.x` or higher. If Python is not installed, download it from [python.org](https://www.python.org/downloads/).

---

## Environment Variables

None required. The tool uses no API keys, no environment variables, and no `.env` file.

---

## Installation

No installation step is required. The tool uses only Python 3 standard library modules. There is no `requirements.txt` and no `pip install` needed.

```powershell
# Windows (PowerShell) — clone and enter the repo
git clone https://github.com/your-org/bob-ai-hackathon-titans-coders.git
cd bob-ai-hackathon-titans-coders
```

```bash
# macOS / Linux
git clone https://github.com/your-org/bob-ai-hackathon-titans-coders.git
cd bob-ai-hackathon-titans-coders
```

---

## Running the Application

### Windows (PowerShell)

```powershell
python src/main.py src/sample.json
```

### macOS / Linux

```bash
python3 src/main.py src/sample.json
```

### Expected output

The tool prints a BLUF summary and four structured sections to stdout, then writes `src/report.json`:

```
========================================================================
  BOTTOM LINE UP FRONT (BLUF)
========================================================================
  Analysis of 23 raw alerts produced N correlated clusters across M
  unique source IPs. The highest-risk cluster (C00X, [CRITICAL], risk
  score Y.YY) originates from <IP> and maps to <techniques>.
  Immediate investigation is recommended for N critical/high clusters;
  review report.json for full detail.
  NOTES: Threat intelligence corroborates SIEM activity in ...
========================================================================

  SECTION 1 -- ALERT COUNTS BY SEVERITY
  ...

  SECTION 2 -- TOP 5 ATT&CK TECHNIQUES (by cluster frequency)
  ...

  SECTION 3 -- AFFECTED HOSTS / IPs
  ...

  SECTION 4 -- CLUSTER DETAIL  (sorted by risk score desc)
  ...

Report written to: src/report.json
```

---

## Optional CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--output PATH` or `-o PATH` | `<input_dir>/report.json` | Path to write the JSON report |
| `--time-window SECONDS` | `300` | Correlation time window in seconds |
| `--match-fields FIELD,FIELD` | Uses `DEFAULT_RULES` | Override correlation fields with a single custom rule |

Examples:

```powershell
# Windows — custom output path
python src/main.py src/sample.json --output C:\tmp\report.json

# Windows — wider time window (10 minutes)
python src/main.py src/sample.json --time-window 600

# Windows — correlate only on src_ip + hostname
python src/main.py src/sample.json --match-fields src_ip,hostname
```

---

## Verifying It Works

After a successful run:

1. **Console output** ends with `Report written to: src/report.json`.
2. **`src/report.json` exists** and contains a JSON object with keys `generated_at`, `total_raw_alerts`, `total_clusters`, `severity_counts`, `top_techniques`, and `clusters`.

Quick check on Windows:

```powershell
# Confirm the file exists and show the top-level keys
python -c "import json; d=json.load(open('src/report.json')); print(list(d.keys()))"
```

Expected output:

```
['generated_at', 'total_raw_alerts', 'total_clusters', 'severity_counts', 'top_techniques', 'clusters']
```

---

## Running the MITRE Mapper Self-Test

[`src/mitre_mapper.py`](../src/mitre_mapper.py) includes an inline test that shows which ATT&CK techniques each event in `sample.json` matches, with the triggering keywords printed for every match:

```powershell
# Windows
python src/mitre_mapper.py
```

```bash
# macOS / Linux
python3 src/mitre_mapper.py
```

---

## Troubleshooting

| Issue | Likely cause | Solution |
|---|---|---|
| `python: command not found` | Python not in PATH | Use `python3` instead of `python`, or add Python to PATH |
| `Python 3.X.Y` but `X < 10` | Python version too old | Install Python 3.10+ from python.org |
| `ModuleNotFoundError: No module named 'normalizer'` | Script not run from the repo root | Run as `python src/main.py src/sample.json` from the repo root directory, not from inside `src/` |
| `ERROR: input file not found: src/sample.json` | Wrong working directory | Ensure your terminal is in the repo root (`bob-ai-hackathon-titans-coders/`) before running |
| `ERROR: could not parse input file` | Malformed JSON in input | Validate the input file with `python -m json.tool src/sample.json` |
| `report.json` is not created | Permission error on output path | Check write permissions on `src/`, or use `--output` to write to a writable location |
| Empty stdout output | Input JSON array is empty | Confirm `src/sample.json` is not empty; the tool prints `WARNING: no alerts produced` and exits with code 0 if the normalised list is empty |
