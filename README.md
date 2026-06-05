# 🍯 AI-Enhanced Honeypot System

> Real-Time Network Attack Classification using Machine Learning

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Flask](https://img.shields.io/badge/Flask-3.1-green)
![XGBoost](https://img.shields.io/badge/XGBoost-3.2-orange)
![Accuracy](https://img.shields.io/badge/Accuracy-98%25-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

A final project that combines **honeypot deception technology** with **AI-based attack classification** and a **real-time web dashboard**. The system captures, classifies, and visualises network attacks across four simulated services.

---

## 📸 Dashboard Preview

The live dashboard shows real-time attack statistics, service breakdowns, attack type charts, and an AI-classified attack feed with severity badges.

---

## 🚀 Features

- **4 Honeypot Services** — SSH, HTTP, FTP, and Telnet running concurrently
- **Real-time AI Classification** — 98% accuracy across 7 attack categories
- **Live Web Dashboard** — auto-refreshes every 3 seconds
- **SQLite Database** — persistent storage of all attack events
- **14-feature ML pipeline** — service-agnostic feature extraction
- **Severity Scoring** — LOW / MEDIUM / HIGH / CRITICAL badges

---

## 🧠 Attack Categories

| Label | Attack Type | Severity |
|-------|------------|----------|
| 0 | Normal / Benign | Low |
| 1 | Brute Force | High |
| 2 | Port Scan | Medium |
| 3 | DoS / Flood | Critical |
| 4 | SQL Injection | Critical |
| 5 | Command Injection | Critical |
| 6 | Credential Stuffing | High |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────┐
│         HONEYPOT LAYER              │
│   SSH | HTTP | FTP | Telnet         │
└──────────────┬──────────────────────┘
               │ raw events
┌──────────────▼──────────────────────┐
│     CAPTURE & FEATURE ENGINE        │
│  Logger → Extractor → SQLite DB     │
└──────────────┬──────────────────────┘
               │ feature vectors
┌──────────────▼──────────────────────┐
│         AI CLASSIFIER               │
│   Random Forest + XGBoost (98%)     │
└──────────────┬──────────────────────┘
               │ labeled results
┌──────────────▼──────────────────────┐
│       REAL-TIME DASHBOARD           │
│   Flask + Chart.js + Live Feed      │
└─────────────────────────────────────┘
```

---

## 📁 Project Structure

```
honeypot-ai/
├── honeypots/
│   ├── ssh_honeypot.py       # Fake SSH server (paramiko)
│   ├── http_honeypot.py      # Fake HTTP server (Flask)
│   ├── ftp_honeypot.py       # Fake FTP server (pyftpdlib)
│   └── telnet_honeypot.py    # Fake Telnet server (raw sockets)
├── capture/
│   ├── logger.py             # Shared event logger
│   ├── database.py           # SQLite schema and queries
│   ├── feature_extractor.py  # 14-feature extraction pipeline
│   ├── exporter.py           # CSV dataset exporter
│   └── inference_engine.py   # Background AI classification thread
├── ml/
│   ├── dataset.py            # Dataset loader + synthetic data generator
│   ├── train.py              # Model training script
│   └── predict.py            # Real-time classifier
├── dashboard/
│   ├── app.py                # Flask dashboard backend
│   └── templates/
│       └── index.html        # Live dashboard UI
├── data/                     # SQLite database (gitignored)
├── logs/                     # JSONL attack logs (gitignored)
├── config.py                 # Central configuration
├── main.py                   # Entry point
└── requirements.txt          # Python dependencies
```

---

## ⚙️ Installation

### Prerequisites
- Python 3.11+
- Kubuntu / Ubuntu Linux (recommended)

### Setup

```bash
# Clone the repository
git clone https://github.com/Mkdarkside/honeypot-ai.git
cd honeypot-ai

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Train the AI model
python -m ml.train

# Start the system
python main.py
```

Open your browser at **http://localhost:5000**

---

## 🧪 Testing the Honeypots

```bash
# Test SSH honeypot
ssh root@localhost -p 2222

# Test HTTP honeypot
curl http://localhost:8080/admin
curl "http://localhost:8080/search?q=' OR 1=1--"

# Test FTP honeypot
ftp localhost 2121

# Test Telnet honeypot
telnet localhost 2323
```

---

## 📊 Port Reference

| Service | Dev Port | Production Port |
|---------|----------|----------------|
| SSH | 2222 | 22 |
| HTTP | 8080 | 80 |
| FTP | 2121 | 21 |
| Telnet | 2323 | 23 |
| Dashboard | 5000 | 5000 |

> For production ports (<1024), run with `sudo python main.py`

---

## 🤖 ML Model Performance

| Metric | Random Forest | XGBoost |
|--------|--------------|---------|
| Accuracy | 97.6% | **98.1%** |
| Precision | 97.6% | 97.6% |
| Recall | 97.6% | 97.6% |
| F1-Score | 97.6% | 97.6% |

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| SSH Honeypot | paramiko |
| FTP Honeypot | pyftpdlib |
| HTTP Honeypot + Dashboard | Flask |
| Database | SQLite + SQLAlchemy |
| ML Models | scikit-learn + XGBoost |
| Data Processing | pandas + numpy |
| Frontend | HTML/CSS/JS + Chart.js |

---

## 👨‍💻 Author

**Abdulmalik** (Maahleek)
Final Year Computer Science Student
University of Maiduguri, Nigeria

---

## 📄 License

This project is licensed under the MIT License.

---

## 🙏 Acknowledgements

- University of Maiduguri, Department of Computer Science
- Supervisor: Prof. Emmanuel Gbenga Dada
- NSL-KDD Dataset contributors
