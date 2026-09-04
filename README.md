# AI-Powered Intelligent Phishing Website Detection and Browser Protection System

An end-to-end cybersecurity solution developed for MCA project viva, research, and production demonstration. The system combines Machine Learning ensemble classifiers, multi-dimensional feature extraction, high-speed Threat Intelligence feeds, and a Chrome Manifest V3 extension for real-time proactive web protection.

---

## 🌟 Key Highlights & Performance

* **Detection Accuracy:** **98.64%** on held-out multi-source test datasets.
* **Precision / Recall:** **99.51% Precision** / **98.31% Recall** (0.9891 F1-Score, 0.9991 ROC-AUC).
* **Ultra-Low Latency:** Sub-**10ms** real-time scoring to ensure zero browsing lag.
* **Explainable AI (XAI):** Automatically highlights exact risk factors (brand spoofing, raw IP hosts, deceptive TLDs, credential harvesting forms).
* **100% Free & Open-Source:** Zero paid API dependencies required; fully operable offline/locally.

---

## 🏛️ System Architecture

```
┌────────────────────────────────────────────────────────┐
│             User Browser (Chrome / Edge)               │
│                                                        │
│  ┌──────────────────────┐    ┌──────────────────────┐  │
│  │   Navigation Event   │    │ Extension Popup &    │  │
│  │ (webNavigation API)  │    │ Interstitial Shield  │  │
│  └──────────┬───────────┘    └──────────▲───────────┘  │
└─────────────┼───────────────────────────┼──────────────┘
              │                           │
              │ JSON Request (URL / DOM)  │ Score & Verdict
              ▼                           │
┌────────────────────────────────────────────────────────┐
│            FastAPI Backend Service (Port 8000)         │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Tier 1: Threat Intelligence & Reputation Cache   │  │
│  │ (Verified Whitelist + Known Blocklist)           │  │
│  └──────────────────────────┬───────────────────────┘  │
│                             │ (If unlisted)            │
│                             ▼                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Tier 2: 25-D Feature Extraction Engine           │  │
│  │ (Lexical, Shannon Entropy, Structural, Content)  │  │
│  └──────────────────────────┬───────────────────────┘  │
│                             │                          │
│                             ▼                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Tier 3: ML Inference (Random Forest Ensemble)    │  │
│  │ Output: Risk Score (0-100%) + XAI Factors        │  │
│  └──────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────┘
```

---

## 📂 Project Structure

```
MCA Project/
├── backend/                  # FastAPI Backend API & Services
│   ├── main.py               # REST API endpoints & static dashboard routing
│   ├── predictor.py          # Real-time scoring & XAI explainability engine
│   ├── threat_intel.py       # Whitelist/Blocklist manager & community feeds
│   └── models/               # Serialized ML models (.joblib) & metrics (.json)
├── ml_pipeline/              # Machine Learning Training & Data Suite
│   ├── features.py           # 25+ Lexical, structural, and DOM feature extractors
│   ├── dataset_builder.py    # Benchmark dataset generator & OpenPhish feeder
│   └── train.py              # Multi-model cross-validation, comparison & export
├── extension/                # Chrome / Edge Browser Extension (Manifest V3)
│   ├── manifest.json         # Extension configuration & permissions
│   ├── background.js         # Service worker intercepting navigation
│   ├── content.js            # In-page DOM inspector
│   ├── popup/                # Extension toolbar popup (UI & controls)
│   ├── blocked/              # Interstitial red warning screen
│   └── icons/                # Extension icon assets
├── dashboard/                # Modern Web Management Dashboard
│   ├── index.html            # Real-time URL Scanner & Model Analytics portal
│   ├── app.js                # Interactive logic & dynamic visual charts
│   └── style.css             # Glassmorphism dark cybersecurity theme
├── tests/                    # Automated Unit Tests
│   ├── test_features.py      # Feature extraction validation
│   └── test_api.py           # API endpoint integration tests
├── requirements.txt          # Python dependencies
└── README.md                 # Project documentation
```

---

## 🚀 Quick Start Guide

### 1. Install Dependencies
Ensure you are in the project folder and run:
```bash
pip install -r requirements.txt
```

### 2. (Optional) Retrain or Benchmark ML Models
To train the models from scratch and regenerate benchmark reports:
```bash
python -m ml_pipeline.train
```

### 3. Run the FastAPI Backend Server & Web Dashboard
Start the backend server:
```bash
python -m uvicorn backend.main:app --reload --port 8000
```
Open your browser and navigate to:
👉 **[http://localhost:8000](http://localhost:8000)**

---

## 🧩 Loading the Browser Extension in Chrome / Edge

1. Open **Google Chrome** or **Microsoft Edge**.
2. In the address bar, go to `chrome://extensions` (or `edge://extensions`).
3. Toggle on **Developer mode** in the top-right corner.
4. Click **"Load unpacked"** in the top-left.
5. Select the **`extension/`** folder inside this project directory (`MCA Project/extension`).
6. The **AI Phishing Sentinel** icon will appear in your browser extensions bar!

---

## 📊 Model Evaluation Summary

| Model Architecture | Accuracy | Precision | Recall | F1-Score | ROC-AUC |
|---|---|---|---|---|---|
| **Random Forest (Champion 🏆)** | **98.64%** | **99.51%** | **98.31%** | **0.9891** | **0.9991** |
| Extra Trees Classifier | 98.48% | 99.75% | 97.83% | 0.9878 | 0.9992 |
| Decision Tree | 98.18% | 99.27% | 97.83% | 0.9854 | 0.9840 |
| Gradient Boosting | 97.73% | 98.54% | 97.83% | 0.9819 | 0.9982 |
| Logistic Regression | 97.27% | 100.00% | 95.66% | 0.9778 | 0.9909 |

---

## 🧪 Running Automated Tests
Execute the unit and integration test suite:
```bash
python -m pytest tests/ -v
```
All 10 tests test lexical extraction, DOM parsing, API responses, and risk classification.
## To Run
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000


http://localhost:8000/