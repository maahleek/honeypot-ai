# 🍯 AI-Enhanced Honeypot System

> Real-Time Network Attack Classification Using Machine Learning

An AI-enhanced honeypot system designed to capture real-world network interactions, extract relevant features, classify network attacks using machine learning, and present detected activity through a real-time web dashboard.

The system simulates four commonly targeted network services — **SSH, HTTP, FTP, and Telnet** — and was deployed on **AWS EC2** to collect genuine internet attack traffic for model training and evaluation.

---

## Dashboard Preview

The web dashboard provides real-time monitoring of honeypot activity, including attack statistics, service breakdowns, attack classifications, severity levels, source information, and recent events.

---

## Features

- **4 Honeypot Services** — SSH, HTTP, FTP, and Telnet
- **Real-World Attack Collection** — deployed on AWS EC2 to capture genuine internet traffic
- **Real-Time Attack Classification** — captured events are classified as they occur
- **17-Feature ML Pipeline** — 14 core features plus 3 event-type features
- **Random Forest Classifier** — selected as the final deployed classification model
- **XGBoost Comparison** — evaluated alongside Random Forest during model development
- **Live Web Dashboard** — Flask-based interface for monitoring captured activity
- **Persistent Event Storage** — SQLite database and JSONL logging
- **Severity Scoring** — LOW, MEDIUM, HIGH, and CRITICAL classifications

---

## Attack Categories

The machine learning pipeline defines seven attack categories:

| Label | Attack Type | Severity |
|---|---|---|
| 0 | Normal / Benign | Low |
| 1 | Brute Force | High |
| 2 | Port Scan | Medium |
| 3 | DoS / Flood | Critical |
| 4 | SQL Injection | Critical |
| 5 | Command Injection | Critical |
| 6 | Credential Stuffing | High |

During the live AWS deployment, genuine samples were observed for five of these categories:

- Normal / Benign
- Brute Force
- Port Scan
- SQL Injection
- Credential Stuffing

**DoS / Flood** and **Command Injection** were not observed in the genuine internet-captured dataset. Synthetic samples for these under-represented classes were therefore used during training only and were excluded from the final real-world evaluation.

---

## Dataset

The final dataset consisted of:

| Data Source | Samples |
|---|---:|
| Genuine internet-captured events | 13,616 |
| Synthetic training samples | 1,050 |
| **Total** | **14,666** |

From the **13,616 genuine samples**, **2,724 samples** were reserved as the held-out real-world test set.

The remaining **10,892 genuine samples**, together with the **1,050 synthetic samples**, were used during model training.

Synthetic samples were **not included in the final real-world test set**.

---

## Feature Extraction

Each captured honeypot event is transformed into a **17-feature vector** before classification.

The extracted features are:

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

The final three event-type features help distinguish connection, disconnection, and request behaviour within captured honeypot traffic.

---

## System Architecture

```text
┌─────────────────────────────────────┐
│          INTERNET / ATTACKERS       │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│            HONEYPOT LAYER           │
│      SSH | HTTP | FTP | Telnet      │
└──────────────────┬──────────────────┘
                   │
                   │ Raw Events
                   ▼
┌─────────────────────────────────────┐
│       CAPTURE & FEATURE LAYER       │
│       Logger → 17-Feature Extractor │
│          JSONL + SQLite Storage     │
└──────────────────┬──────────────────┘
                   │
                   │ Feature Vector
                   ▼
┌─────────────────────────────────────┐
│       ML CLASSIFICATION LAYER       │
│           Random Forest             │
└──────────────────┬──────────────────┘
                   │
                   │ Classified Events
                   ▼
┌─────────────────────────────────────┐
│        REAL-TIME DASHBOARD          │
│       Flask REST API + Web UI       │
└─────────────────────────────────────┘
```

Captured events are processed through the feature extraction pipeline and classified synchronously by the deployed Random Forest model. The event and its classification result are then stored and made available to the monitoring dashboard.

---

## Project Structure

```text
honeypot-ai/
├── honeypots/
│   ├── ssh_honeypot.py
│   ├── http_honeypot.py
│   ├── ftp_honeypot.py
│   └── telnet_honeypot.py
│
├── capture/
│   ├── logger.py
│   ├── database.py
│   ├── feature_extractor.py
│   ├── exporter.py
│   └── inference_engine.py
│
├── ml/
│   ├── dataset.py
│   ├── train.py
│   ├── predict.py
│   └── model/
│       ├── classifier.joblib
│       ├── label_encoder.joblib
│       └── scaler.joblib
│
├── dashboard/
│   ├── app.py
│   └── templates/
│       └── index.html
│
├── data/
├── logs/
├── config.py
├── main.py
├── requirements.txt
└── README.md
```

---

## Installation

### Prerequisites

- Python 3.11+
- Linux environment recommended
- Git
- pip

### 1. Clone the Repository

```bash
git clone https://github.com/maahleek/honeypot-ai.git
cd honeypot-ai
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
source venv/bin/activate
```

On Windows:

```bash
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Train the Models

```bash
python -m ml.train
```

### 5. Start the Honeypot System

```bash
python main.py
```

The monitoring dashboard is available locally on port `5000`.

---

## Testing the Honeypots

### SSH

```bash
ssh root@localhost -p 2222
```

### HTTP

```bash
curl http://localhost:8080/admin
```

Example SQL injection-style request:

```bash
curl "http://localhost:8080/search?q=' OR 1=1--"
```

### FTP

```bash
ftp localhost 2121
```

### Telnet

```bash
telnet localhost 2323
```

---

## Port Reference

| Service | Development Port | Deployment Port |
|---|---:|---:|
| SSH | 2222 | 22 |
| HTTP | 8080 | 80 |
| FTP | 2121 | 21 |
| Telnet | 2323 | 23 |
| Dashboard | 5000 | 5000 |

> Ports below 1024 may require elevated privileges depending on the deployment environment.

---

## Machine Learning Models

Two ensemble machine learning algorithms were evaluated:

### Random Forest

The final Random Forest classifier was configured with:

- **500 decision trees**
- Maximum depth of **20**
- Balanced class weighting
- **17 input features**

Random Forest was selected as the final deployed classifier.

### XGBoost

XGBoost was also trained and evaluated as a comparative model.

The final evaluation showed that Random Forest performed substantially better on the genuine held-out honeypot data.

---

## Final Model Evaluation

The final evaluation was performed using **2,724 held-out samples drawn entirely from genuine internet-captured honeypot traffic**.

| Model | Accuracy |
|---|---:|
| **Random Forest** | **100%** |
| XGBoost | **60.8%** |

The Random Forest model achieved perfect classification across the **five real-world classes represented in the held-out test set**.

The result should be interpreted within the scope of the collected dataset. In particular, **SQL Injection had only one genuine test instance**, while **DoS / Flood and Command Injection had no genuine test samples** and were therefore not part of the final real-world evaluation.

---

## Tech Stack

| Component | Technology |
|---|---|
| Programming Language | Python |
| SSH Honeypot | Paramiko |
| FTP Honeypot | pyftpdlib |
| HTTP Honeypot | Flask |
| Dashboard Backend | Flask |
| Database | SQLite / SQLAlchemy |
| Machine Learning | scikit-learn / XGBoost |
| Data Processing | pandas / NumPy |
| Model Serialization | joblib |
| Frontend | HTML / CSS / JavaScript / Chart.js |
| Deployment | AWS EC2 |
| Version Control | Git / GitHub |

---

## Project Limitations

- The system is a **low-interaction honeypot** and does not provide attackers with a complete operating-system environment.
- DoS / Flood and Command Injection were not observed during live internet data collection.
- SQL Injection had very limited representation in the genuine held-out test data.
- The system was developed and evaluated as an academic research project rather than a large-scale production security platform.
- Model performance may change when exposed to different traffic distributions and previously unseen attack patterns.

---

## Future Improvements

Possible future improvements include:

- Collecting more genuine attack samples for under-represented classes
- Extending the duration and scale of live honeypot deployment
- Periodically retraining the classifier as new attack data becomes available
- Further tuning and evaluating XGBoost and other machine learning models
- Exploring higher-interaction honeypot environments
- Extending the dashboard with historical trends and additional alerting capabilities

---

## Author

**Abdulmalik Adams Onoruoyiza (Maahleek)**  
Computer Science  
University of Maiduguri, Nigeria

---

## Academic Project

**Project Title:**  
*Design and Implementation of an AI-Enhanced Honeypot System for Real-Time Network Attack Classification*

**Department:** Computer Science  
**Faculty:** Faculty of Physical Sciences  
**Institution:** University of Maiduguri  
**Year:** 2026

---

## Acknowledgements

- Department of Computer Science, University of Maiduguri
- Project Supervisor: **Prof. Dada Emmanuel Gbenga**

---

## License

This repository is intended primarily for academic and cybersecurity research purposes.

If an MIT `LICENSE` file is included in the repository, the source code is distributed according to the terms of that license.
