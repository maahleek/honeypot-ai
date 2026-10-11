# AI-Enhanced Honeypot System

Real-time network attack capture, machine-learning classification, and monitoring dashboard.

This project was developed as an academic cybersecurity system and as a portfolio project demonstrating Python backend engineering, network programming, data pipelines, machine learning, SQLite, Flask, and cloud deployment.

## What the system does

The application exposes four low-interaction honeypot services:

- SSH
- HTTP
- FTP
- Telnet

Incoming activity is captured as structured events, transformed into a 17-feature vector, classified by the trained model, stored in SQLite/JSONL, and displayed through a Flask dashboard.

The live data path is:

```text
Internet traffic
      |
      v
SSH / HTTP / FTP / Telnet honeypots
      |
      v
Event capture + feature extraction
      |
      v
ML classifier
      |
      +----> SQLite / JSONL
      |
      v
Flask monitoring dashboard
```

## Portfolio highlights

- Multi-service honeypot built in Python
- Real internet traffic collection on AWS EC2
- 13,616 captured events in the published research dataset
- 17-feature real-time classification pipeline
- Random Forest and XGBoost model comparison
- Genuine-only held-out evaluation protocol
- Synthetic examples restricted to training
- SQLite persistence and JSONL event logging
- Responsive Flask/Chart.js monitoring dashboard
- Safer isolated FTP environment
- Password redaction before persistent storage
- Private-by-default dashboard binding
- Automated regression tests with GitHub Actions

## Attack categories

The classifier defines seven research categories:

| Label | Category | Severity |
|---:|---|---|
| 0 | Normal / Benign | Low |
| 1 | Brute Force | High |
| 2 | Port Scan | Medium |
| 3 | DoS / Flood | Critical |
| 4 | SQL Injection | Critical |
| 5 | Command Injection | Critical |
| 6 | Credential Stuffing | High |

The captured dataset contains genuine examples for Normal, Brute Force, Port Scan, SQL Injection, and Credential Stuffing. DoS/Flood and Command Injection are represented by synthetic training-only examples because those classes were not observed in the captured dataset.

## Dataset and evaluation protocol

The repository includes 13,616 captured honeypot events.

Training now follows this sequence:

```text
13,616 genuine events
        |
        +---- 80% genuine training partition
        |
        +---- 20% untouched genuine test partition (2,724 rows)

genuine training partition
        +
1,050 synthetic training-only rows
        |
        v
model training

untouched genuine test partition
        |
        v
final evaluation
```

Synthetic rows are never added to the held-out test partition.

The scaler is also fitted on training data only.

Historical CSV exports used 14 stored feature columns. The current loader deterministically backfills the three event-state flags from the recorded event type so old captures remain reproducible with the current 17-feature pipeline.

### Important research limitation

The historical dataset was labelled using deterministic event rules from the honeypot. Some current features are also derived from event metadata, so this repository treats the model as a baseline event-classification system rather than claiming that the historical labels constitute an independent ground truth.

A stronger future research version would add temporal/session behaviour such as connection rate, authentication-attempt rate, unique ports, username diversity, and rolling request counts, then label/evaluate those sessions independently.

## 17-feature vector

1. `service_ssh`
2. `service_http`
3. `service_ftp`
4. `service_telnet`
5. `is_auth_attempt`
6. `is_admin_access`
7. `is_sqli`
8. `is_path_traversal`
9. `is_command`
10. `password_len`
11. `username_is_root`
12. `has_sqli_chars`
13. `has_traversal`
14. `payload_len`
15. `is_connection`
16. `is_disconnection`
17. `is_request`

Raw passwords are used only long enough to derive features for the current event. Before an event is written to JSONL or SQLite, the password is removed and only its length is retained.

The public training dataset also excludes attacker IP addresses because IP address is not a model feature.

## Model training

Two ensemble classifiers are evaluated:

### Random Forest

Current training configuration:

- 500 trees
- maximum depth 20
- balanced class weights
- fixed random seed
- 17 input features

### XGBoost

XGBoost is trained on the same training partition and evaluated against the same untouched genuine test partition.

The model with the stronger genuine holdout accuracy is saved as `ml/model/classifier.joblib`. An exact tie is resolved in favour of Random Forest because it is easier to explain and cheaper to run for this project.

Generated model binaries and reports are intentionally not committed to Git.

Run:

```bash
python -m ml.train
```

This generates:

```text
ml/model/classifier.joblib
ml/model/scaler.joblib
ml/model/training_report.json
```

The generated report is the source of truth for accuracy and per-class precision/recall/F1. The README intentionally does not hard-code a headline accuracy that can become stale after retraining.

## Security hardening

This portfolio branch includes several safeguards for internet-facing deployment:

- anonymous FTP is rooted in `data/ftp_root`, not the operating-system user's home directory
- anonymous FTP is read-only
- SSH host keys are created inside the ignored `keys/` directory
- the dashboard binds to `127.0.0.1` by default
- raw passwords are redacted before persistent storage
- attacker IP addresses are removed from the published ML dataset
- runtime logs, databases, keys, secrets, and generated model files are ignored by Git
- dashboard confidence is not fabricated when confidence was not persisted

For a public server, expose only the honeypot ports you intend to study. Keep the dashboard behind SSH tunnelling, a VPN, firewall rules, or an authenticated reverse proxy.

## Project structure

```text
honeypot-ai/
├── honeypots/
│   ├── ssh_honeypot.py
│   ├── http_honeypot.py
│   ├── ftp_honeypot.py
│   └── telnet_honeypot.py
├── capture/
│   ├── logger.py
│   ├── database.py
│   ├── feature_extractor.py
│   └── exporter.py
├── ml/
│   ├── dataset.py
│   ├── train.py
│   └── predict.py
├── dashboard/
│   ├── app.py
│   └── templates/
│       └── index.html
├── data/
│   └── dataset.csv
├── config.py
├── main.py
├── test_hardening.py
├── requirements.txt
└── README.md
```

## Installation

Python 3.11+ is recommended.

```bash
git clone https://github.com/maahleek/honeypot-ai.git
cd honeypot-ai

python -m venv venv
```

Linux/macOS:

```bash
source venv/bin/activate
```

Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Copy `.env.example` to `.env` if you want to change ports or dashboard settings.

Train the model:

```bash
python -m ml.train
```

Run the complete system:

```bash
python main.py
```

## Development ports

| Service | Default port |
|---|---:|
| SSH | 2222 |
| HTTP | 8080 |
| FTP | 2121 |
| Telnet | 2323 |
| Dashboard | 5000 |

The honeypot services listen on `0.0.0.0` by default. The dashboard listens only on `127.0.0.1` unless explicitly changed.

## Local testing

SSH:

```bash
ssh root@localhost -p 2222
```

HTTP:

```bash
curl http://localhost:8080/admin
```

FTP:

```bash
ftp localhost 2121
```

Telnet:

```bash
telnet localhost 2323
```

Regression tests:

```bash
python test_hardening.py
```

The same compile and hardening tests run automatically through GitHub Actions.

## Tech stack

| Area | Technology |
|---|---|
| Language | Python |
| SSH | Paramiko |
| FTP | pyftpdlib |
| HTTP honeypot | Flask |
| Dashboard | Flask + Chart.js |
| Database | SQLite + SQLAlchemy |
| ML | scikit-learn + XGBoost |
| Data | pandas + NumPy |
| Model persistence | joblib |
| Cloud deployment | AWS EC2 |
| CI | GitHub Actions |

## Academic context

Project title:

**Design and Implementation of an AI-Enhanced Honeypot System for Real-Time Network Attack Classification**

Department of Computer Science  
University of Maiduguri  
2026

## Author

**Abdulmalik Adams Onoruoyiza (Maahleek)**

## Responsible use

This repository is intended for defensive cybersecurity research, controlled lab testing, education, and authorized honeypot deployment. Do not deploy services or capture traffic on systems you do not own or have permission to monitor.
