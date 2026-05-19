# Lightweight SIEM System
Real-time Security Information and Event Management

A fully functional SIEM system built in Python that monitors Linux auth logs,
detects threats using rule-based and ML detection, and visualises alerts on a
live dashboard. No Docker, no cloud, no paid tools required.

## Quick Start

Terminal 1 - pipeline:
  sudo /home/kali/siem-system/venv/bin/python main.py

Terminal 2 - API:
  source venv/bin/activate && python webapp.py

Terminal 3 - dashboard:
  source venv/bin/activate && streamlit run dashboard.py

Open browser: http://localhost:8501

## Features

- Real-time log ingestion from /var/log/auth.log
- 6 detection rules: brute force, root login, off-hours, IP cycling, credential stuffing, new user
- Isolation Forest ML anomaly detection (8 features, auto-retrains, persists with joblib)
- MITRE ATT&CK technique mapping (T1110, T1078, T1090)
- GeoIP enrichment via MaxMind GeoLite2
- Composite risk scoring (rules + ML + threat intel) out of 100
- Flask REST API with 8 endpoints
- Streamlit dashboard with 5-second auto-refresh
- SQLite storage - no external database needed

## Detection Rules

Rule                  | MITRE   | Trigger
----------------------|---------|----------------------------------------
BRUTE_FORCE           | T1110   | 5+ failed logins in 60s from same IP
ROOT_LOGIN_ATTEMPT    | T1078   | Any login attempt for root
OFF_HOURS_LOGIN       | T1078   | Successful login between 11PM-6AM
IP_CYCLING            | T1090   | Same user from 3+ IPs in 5 min
CREDENTIAL_STUFFING   | T1110   | 5+ usernames tried from same IP in 2 min
NEW_USER_LOGIN        | T1078   | First-ever successful login for a username

## Project Structure

siem-system/
  main.py              - Entry point
  pipeline.py          - Queue-based event pipeline
  webapp.py            - Flask REST API (8 endpoints)
  dashboard.py         - Streamlit dashboard
  enrichments.py       - GeoIP + MITRE + threat intel
  config/settings.py   - Centralized configuration
  ingestion/           - Log file watchers + simulator
  parsers/             - Auth log parser + normalizer
  detection/           - Rule engine + ML engine
  storage/             - SQLite store
  alerts/              - Alert dispatcher
  tests/               - 23 unit tests (all passing)

## Running Tests

  source venv/bin/activate
  python -m unittest discover tests/ -v

## Tech Stack

Python, Flask, Streamlit, SQLite, scikit-learn, MaxMind GeoLite2

## Simulate Attack Traffic

  python main.py --simulate

  sudo service ssh start
  for i in {1..15}; do sshpass -p wrong ssh -o StrictHostKeyChecking=no root@127.0.0.1 2>/dev/null; done
