# SQL Injection Playground + Detection Engine

## Overview
This repo contains a deliberately vulnerable Flask application and a small detection engine that demonstrates:
- how simple payloads can alter responses (SQLi),
- how to detect suspicious requests via heuristics (error messages, response-size changes),
- how parameterized queries mitigate the issue.

**Always run locally in an isolated lab.**

## Files
- `init_db.py` — creates `playground.db` with sample users & products.
- `app_vuln.py` — vulnerable app (port 5000).
- `app_safe.py` — safe app with parameterized queries (port 5001).
- `detector.py` — runs payloads from `payloads.txt` and logs findings to `findings.db`.
- `payloads.txt` — example injection payloads.

## Setup & Run
1. Create a virtualenv and install:
```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
