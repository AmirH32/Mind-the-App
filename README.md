# Mind the App: Detecting Dual-Use Applications

An end-to-end pipeline designed to detect **Dual-Use Applications**. These are Android apps that may appear genuine (e.g. parental control or recovery tools) but are frequently repurposed for malicious surveillance or spying.

The project covers the complete workflow from:
- APK discovery and scraping
- Static APK analysis
- Feature engineering
- Machine learning-based classification
- Evaluation
- Web interface dashboard

---

# Project Structure
```text
```text
/ Project Root
├── data
│   ├── features
│   │   └── suspicious_permissions.json
│   ├── processed
│   │   ├── apk_data.csv
│   │   └── archive
│   │       ├── apk_data_old.csv
│   │       └── apk_data_old1.csv
│   ├── raw
│   │   └── scraping
│   │       ├── direct_downloads.json
│   │       ├── expanded_queries.json
│   │       ├── search_results.json
│   │       └── temp_downloads.json
│   └── runtime
│       └── progress.json
│
├── evaluation
│   ├── plots
│   │   ├── combined_shap_bar.png
│   │   ├── feature_importance.png
│   │   ├── gradient_boosting_shap_bar.png
│   │   ├── gradient_boosting_shap_summary.png
│   │   ├── logistic_shap_bar.png
│   │   ├── logistic_shap_summary.png
│   │   ├── model_comparison.png
│   │   ├── random_forest_shap_bar.png
│   │   ├── random_forest_shap_summary.png
│   │   ├── svm_shap_bar.png
│   │   └── svm_shap_summary.png
│   └── sheets
│       └── model_comparison.csv
│
├── models
│   ├── consensus_hard_model.pkl
│   ├── consensus_soft_model.pkl
│   ├── gradient_boosting_model.pkl
│   ├── logistic_model.pkl
│   ├── random_forest_model.pkl
│   └── svm_model.pkl
│
├── src
│   ├── apk_analysis
│   │   ├── APK_analyser.py
│   │   └── utils
│   │       ├── config.py
│   │       ├── .env
│   │       ├── .env.example
│   │       └── __init__.py
│   │
│   ├── apk_discovery_tool
│   │   ├── main.py
│   │   ├── apk_finder
│   │   │   ├── base_apk_searcher.py
│   │   │   ├── google_cse_client.py
│   │   │   └── __init__.py
│   │   ├── downloaders
│   │   │   ├── base_downloader.py
│   │   │   ├── cleaner.py
│   │   │   ├── downloader.py
│   │   │   ├── selenium_downloader.py
│   │   │   └── __init__.py
│   │   ├── query_provider
│   │   │   ├── base_query_provider.py
│   │   │   ├── google_provider.py
│   │   │   └── __init__.py
│   │   ├── query_snowballer
│   │   │   └── snowballer.py
│   │   ├── scrapers
│   │   │   ├── base_scraper.py
│   │   │   ├── apkmirror_scraper.py
│   │   │   └── __init__.py
│   │   └── utils
│   │       ├── config.py
│   │       ├── .env
│   │       ├── .env.example
│   │       └── __init__.py
│   │
│   ├── machine_learning
│   │   ├── train_model.py
│   │   ├── models
│   │   │   ├── base_model.py
│   │   │   ├── consensus.py
│   │   │   ├── dummy.py
│   │   │   ├── grm.py
│   │   │   ├── lrm.py
│   │   │   ├── rfm.py
│   │   │   └── svm.py
│   │   └── utils
│   │       ├── config.py
│   │       ├── .env
│   │       └── .env.example
│   │
│   └── web_app
│       ├── app.py
│       ├── templates
│       │   ├── about.html
│       │   ├── index.html
│       │   └── result.html
│       └── utils
│           ├── config.py
│           ├── .env
│           ├── .env.example
│           └── __init__.py
│
└── README.md
└── LICENSE
└── requirements.txt
``````---

# Modules Overview

## 1. APK Discovery Tool (`main.py`)

Responsible for the **Snowballing Discovery Technique** used to identify potential dual-use applications.

The module:

- Expands seed queries (e.g., `"track my wife"`)
- Uses Google Custom Search for APK discovery
- Scrapes APKMirror for downloadable APKs
- Handles automated downloading in batches

### Key Features

- Query expansion
- Automated scraping
- Selenium + Cloudscraper integration
- Fault-tolerant batching
- Automated APK collection pipeline

---

## 2. APK Analyser (`APK_analyser.py`)

Performs static analysis on downloaded APK files using **Androguard**.

Extracted features include:

- Android permissions
- Intent filters
- Suspicious libraries
- Network indicators (IPs/domains)

The extracted data is exported into structured CSV datasets for machine learning.

### Key Features

- Multi-processing support
- Suspicious permission mapping
- Static feature extraction
- CSV dataset generation

---

## 3. Machine Learning Pipeline (`train_model.py`)

Trains and evaluates multiple machine learning models for dual-use app detection.

### Supported Models

- Random Forest
- Support Vector Machine (SVM)
- Logistic Regression
- Gradient Boosting
- Consensus Voting Ensembles

The module also provides explainability using SHAP analysis and feature importance visualizations.

### Key Features

- Automated model training
- Consensus voting models
- SHAP explainability
- Evaluation plot generation
- Model serialization using `joblib`

---

## 4. Detection Web App (`app.py`)

A Flask-based web interface for real-time APK analysis and risk assessment.

Users can upload APK files and receive:

- Risk predictions
- Dual-use classification
- Flagged suspicious features
- Model-based confidence outputs

### Key Features

- Drag-and-drop APK upload
- Multiple model selection
- Visual risk indicators
- Real-time prediction pipeline

---

# Execution Guide

> Run all commands from the project root directory.

Ensure your `PYTHONPATH` includes the `src` directory for proper module resolution.

---

## 1. Discovery & Scraping

Expand search queries and begin APK scraping/downloading:

```bash
python -m src.apk_discovery_tool.main -g -s -a -b
```

---

## 2. Static Analysis & Feature Extraction

Analyze APK files and generate the ML dataset:

```bash
python -m src.apk_analysis.APK_analyser \
data/raw/apks \
data/processed/apk_data.csv \
data/features/suspicious_permissions.json
```

---

## 3. Model Training

Train all machine learning models and generate evaluation outputs:

```bash
python -m src.machine_learning.train_model --all_models --consensus
```

---

## 4. Running the Web Application

Launch the Flask web server for real-time APK classification:

```bash
PYTHONPATH=$(pwd)/src python src/web_app/app.py
```

---

# Setup

## Environment Configuration

Ensure all required `.env` files are configured within the relevant `utils/` directories.

Examples include:

- Google Custom Search API keys
- Scraping credentials
- Runtime configuration variables

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Evaluation Outputs

Generated evaluation artifacts include:

- SHAP global importance plots
- Feature importance visualizations
- Model comparison sheets
- Ensemble performance metrics

Outputs are stored in:

```text
evaluation/
├── plots/
└── sheets/
```

---

# Technologies Used

- Python
- Flask
- Androguard
- Scikit-learn
- SHAP
- Selenium
- Cloudscraper
- Joblib
- Pandas
- NumPy

---

# License

Copyright (C) 2026 Amir Hassanali

Licensed under the **GNU General Public License v3.0**.
