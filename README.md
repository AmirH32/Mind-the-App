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
/ Project Root — 5155 Lines
├── data
│   ├── features
│   │   └── suspicious_permissions.json — Suspicious permission mapping dataset
│   ├── processed — Analysed APK dataset
│   │   ├── apk_data.csv — Main processed dataset
│   │   └── archive — Legacy dataset versions
│   │       ├── apk_data_old.csv — Older dataset version
│   │       └── apk_data_old1.csv — Backup dataset version
│   ├── raw — Temporary extracted data
│   │   └── scraping — Temporary scraping outputs
│   │       ├── direct_downloads.json — APK download metadata
│   │       ├── expanded_queries.json — Expanded search queries
│   │       ├── search_results.json — Scraped APK results
│   │       └── temp_downloads.json — Current batch download metadata
│   └── runtime
│       └── progress.json — Pipeline progress tracking file
│
├── evaluation — Classifier evaluation outputs
│   ├── plots — Evaluation plots (SHAP, feature importance, comparisons)
│   │   ├── combined_shap_bar.png — Global SHAP feature importance
│   │   ├── feature_importance.png — Feature ranking plot
│   │   ├── gradient_boosting_shap_bar.png — GB SHAP bar plot
│   │   ├── gradient_boosting_shap_summary.png — GB SHAP summary plot
│   │   ├── logistic_shap_bar.png — Logistic SHAP bar plot
│   │   ├── logistic_shap_summary.png — Logistic SHAP summary plot
│   │   ├── model_comparison.png — Model comparison chart
│   │   ├── random_forest_shap_bar.png — RF SHAP bar plot
│   │   ├── random_forest_shap_summary.png — RF SHAP summary plot
│   │   ├── svm_shap_bar.png — SVM SHAP bar plot
│   │   └── svm_shap_summary.png — SVM SHAP summary plot
│   └── sheets
│       └── model_comparison.csv — Model evaluation metrics table
│
├── models — Trained ML models
│   ├── consensus_hard_model.pkl — Hard voting ensemble model
│   ├── consensus_soft_model.pkl — Soft voting ensemble model
│   ├── gradient_boosting_model.pkl — Gradient Boosting classifier
│   ├── logistic_model.pkl — Logistic Regression classifier
│   ├── random_forest_model.pkl — Random Forest classifier
│   └── svm_model.pkl — Support Vector Machine classifier
│
├── src — Source code
│   ├── apk_analysis — Static APK analysis module
│   │   ├── APK_analyser.py — Androguard-based static analysis engine
│   │   └── utils
│   │       ├── config.py — Loads environment variables and settings
│   │       ├── .env
│   │       ├── .env.example
│   │       └── __init__.py
│   │
│   ├── apk_discovery_tool — APK scraping and discovery pipeline
│   │   ├── main.py — Pipeline entry point
│   │   ├── apk_finder — APK search subsystem
│   │   │   ├── base_apk_searcher.py — Base search interface
│   │   │   ├── google_cse_client.py — Google CSE API client
│   │   │   └── __init__.py
│   │   ├── downloaders — APK download system
│   │   │   ├── base_downloader.py — Base downloader class
│   │   │   ├── cleaner.py — Download cleanup logic
│   │   │   ├── downloader.py — HTTP downloader
│   │   │   ├── selenium_downloader.py — Browser-based downloader
│   │   │   └── __init__.py
│   │   ├── query_provider — Related query generation
│   │   │   ├── base_query_provider.py — Base query provider
│   │   │   ├── google_provider.py — Google suggestion API provider
│   │   │   └── __init__.py
│   │   ├── query_snowballer — Query expansion engine
│   │   │   └── snowballer.py — BFS-style query expansion
│   │   ├── scrapers — APK scraping modules
│   │   │   ├── base_scraper.py — Base scraper class
│   │   │   ├── apkmirror_scraper.py — APKMirror scraper
│   │   │   └── __init__.py
│   │   └── utils
│   │       ├── config.py — Loads scraping configuration
│   │       ├── .env
│   │       ├── .env.example
│   │       └── __init__.py
│   │
│   ├── machine_learning — ML training pipeline
│   │   ├── train_model.py — Full training pipeline
│   │   ├── models — ML model implementations
│   │   │   ├── base_model.py — Abstract model class
│   │   │   ├── consensus.py — Ensemble voting model
│   │   │   ├── dummy.py — Baseline model
│   │   │   ├── grm.py — Gradient Boosting model
│   │   │   ├── lrm.py — Logistic Regression model
│   │   │   ├── rfm.py — Random Forest model
│   │   │   └── svm.py — SVM model
│   │   └── utils
│   │       ├── config.py — ML configuration loader
│   │       ├── .env
│   │       └── .env.example
│   │
│   └── web_app — Flask web application
│       ├── app.py — Flask server
│       ├── templates
│       │   ├── about.html — About page
│       │   ├── index.html — Upload page
│       │   └── result.html — Results page
│       └── utils
│           ├── config.py — Web config loader
│           ├── .env
│           └── .env.example
│
└── README.md / LICENSE / requirements.txt
```---

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
