# Vulnerability Auditor MVP

Defensive web vulnerability auditor for **authorized targets**. Runs OWASP ZAP, Nmap, and Nikto, correlates findings across tools, classifies by OWASP Top 10 / CWE, and uses the Claude API to generate actionable mitigations and an executive summary.

> **Important**: Only scan targets you own or have explicit written authorization to test.

---

## Quick Start (local, Arch Linux)

```bash
git clone <repo>
cd Vulnerability_detector

python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env
# Edit .env and set ANTHROPIC_API_KEY (optional but recommended)

uvicorn api.app:app --reload
```

The API is now at `http://localhost:8000`. Docs at `http://localhost:8000/docs`.

---

## Quick Start (Docker)

```bash
cp .env.example .env
# Edit .env

# Without ZAP (uses nmap + nikto if installed in the image):
docker-compose up

# With ZAP sidecar:
docker-compose --profile with-zap up
# Then set ZAP_API_URL=http://zap:8090 in .env
```

---

## API Usage

### Launch a scan

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://your-authorized-target.com",
    "tools": ["nmap", "zap", "nikto"]
  }'
```

Response (202):

```json
{
  "scan_id": "3f7a1b2c-...",
  "status": "pending",
  "target": "http://your-authorized-target.com",
  "poll_url": "/scan/3f7a1b2c-..."
}
```

### Poll for results

```bash
curl http://localhost:8000/scan/3f7a1b2c-...
```

### Get Markdown report

```bash
curl http://localhost:8000/report/3f7a1b2c-... > report.md
```

### Health check

```bash
curl http://localhost:8000/health
```

```json
{
  "status": "ok",
  "version": "0.1.0",
  "tools_available": {
    "zap": false,
    "nmap": true,
    "nikto": false
  },
  "ai_enabled": true
}
```

---

## Tools

| Tool | Required | Notes |
|------|----------|-------|
| nmap | No | Install via `pacman -S nmap` |
| nikto | No | Install via `pacman -S nikto` |
| OWASP ZAP | No | Set `ZAP_API_URL` or use Docker profile |

If a tool is unavailable it is marked `tool_unavailable` and the scan continues with the rest.

---

## Configuration (`.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | — | Claude API key (optional — AI disabled if absent) |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-6` | Claude model to use |
| `ZAP_API_URL` | — | Remote ZAP API URL (e.g. `http://localhost:8090`) |
| `DATA_DIR` | `./data` | Root directory for scan persistence |
| `SCAN_TIMEOUT_SECONDS` | `300` | Per-tool subprocess timeout |
| `NMAP_FLAGS` | `-sV -sC --script=vuln -T4` | Nmap command flags |

---

## Running Tests

```bash
pytest -v
# Single test file:
pytest tests/test_correlator.py -v
# Single test:
pytest tests/test_scorer.py::test_elevate_to_critical_sql_injection -v
```

---

## Persistence

All scan data is stored in `data/scans/{scan_id}/`:

```
data/scans/{scan_id}/
  scan.json          — metadata and status
  normalized.json    — correlated findings
  report.md          — Markdown report
  raw/
    nmap_raw.xml
    zap_raw.json
    nikto_raw.json
```

---

## Example Report

```markdown
# Vulnerability Scan Report

| Field | Value |
|-------|-------|
| Scan ID | `3f7a1b2c-...` |
| Target  | `http://example.com` |
| Status  | DONE |
| Date    | 2026-04-29 15:30 UTC |

## Executive Summary
...

## Findings

### 🔴 CRITICAL — SQL Injection
| Severity | critical |
| Confidence | high |
| OWASP | A03:2021-Injection |
| CWE | CWE-89 |
...
```

---

## Architecture

```
POST /scan → BackgroundTasks → [zap | nmap | nikto] (concurrent)
                                      ↓
                              parser.py → RawFinding[]
                                      ↓
                           correlator.py → Finding[] (deduped, confidence boosted)
                                      ↓
                            classifier.py → OWASP + CWE
                                      ↓
                               scorer.py → severity + confidence
                                      ↓
                      ai/analyzer + fixer → executive summary + mitigations
                                      ↓
                      markdown_report.py → report.md
                                      ↓
                              disk: data/scans/{id}/
```
