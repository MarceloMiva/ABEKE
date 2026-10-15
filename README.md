# ABEKE
### Automated Breach & Event Knowledge Engine

ABEKE is a SOC (Security Operations Center) analysis framework. It ingests security events, correlates them into incidents, scores severity, maps MITRE ATT&CK techniques, extracts IOCs, and builds a searchable breach knowledge base — distinct from SIMI (pentesting/vuln assessment).

> ⚠️ **Authorized Use Only** — for environments you own, manage, or are explicitly authorized to monitor.

## Stack
FastAPI · SQLAlchemy · PostgreSQL (falls back to SQLite automatically for local testing, zero setup)

## Quick Start (test locally — nothing deployed yet)
```bash
cd ABEKE
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

# no .env needed to test — it auto-falls-back to local SQLite
uvicorn app.main:app --reload
```
Then open **http://127.0.0.1:8000/docs** — full interactive API (Swagger UI) to fire test events at it immediately.

## Try it
```bash
curl -X POST http://127.0.0.1:8000/ingest/event \
  -H "Content-Type: application/json" \
  -d '{
    "source": "auth-log",
    "event_type": "login_failed",
    "src_ip": "10.0.0.5",
    "raw_payload": {"user": "admin", "ip": "10.0.0.5", "attempt": 4}
  }'
```
Fire that 3–4 times with the same `src_ip` and you'll see it correlate into one incident with a rising severity score — check `GET /incidents/`.

## Core Features (implemented as stubs, ready to extend)
- **Alert Correlation Engine** (`services/correlation.py`) — groups events by src_ip + type within a time window
- **Severity Scoring** (`services/scoring.py`) — weighted scoring per event type, escalates on volume + known-bad IOCs
- **MITRE ATT&CK Mapping** (`services/mitre_mapping.py`) — event_type → technique ID lookup
- **IOC Extraction** (`services/ioc_extraction.py`) — regex-based IP/domain/hash extraction from payloads
- **Incident Reports** — `GET /incidents/{id}/report` returns ready-to-export markdown

## Switching to real PostgreSQL
Copy `.env.example` to `.env`, fill in your `DATABASE_URL`, then:
```bash
alembic init alembic   # first time only, for migrations
```

## Roadmap
- [ ] Swap IOC known-bad seed list for a real threat intel feed (AbuseIPDB / OTX / VirusTotal)
- [ ] Replace rule-based correlation with graph/ML-based correlator
- [ ] Analyst dashboard (React, matching SIMI's frontend stack)
- [ ] PDF export for incident reports (markdown → PDF)
- [ ] Auth layer before any public deployment

## Author
**Fashipe Oluwadamilare Ayoola (Marcelo)**
Cybersecurity Student, Miva Open University
GitHub: [MarceloMiva](https://github.com/MarceloMiva) · Portfolio: marcelomiva.github.io

## License
*(add license — MIT recommended)*
