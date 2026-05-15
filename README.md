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
```

---

# Modules Overview

## 1. APK Discovery Tool (`main.py`)

Contains the **Snowballing Discovery Technique** and **scraper** used to identify potential dual-use applications.

The module:

- Expands seed queries
- Uses Google Custom Search for APK discovery
- Scrapes APKMirror for downloadable APKs
- Handles automated downloading and cleanup

---

## 2. APK Analyser (`APK_analyser.py`)

Performs static analysis on downloaded APK files using **Androguard**.

Extracted features include:

- Android permissions
- Intent filters
- Suspicious libraries
- Network indicators (IPs/domains)
- Targeted SDK version
- Exported Provider
- Services
- Persistence and evasion techniques

The extracted data is outputted and exported into structured CSV datasets for machine learning.

---

## 3. Machine Learning Pipeline (`train_model.py`)

Trains and evaluates multiple machine learning models for dual-use app detection.

### Supported Models

- Random Forest
- Support Vector Machine (SVM)
- Logistic Regression
- Gradient Boosting
- Consensus Voting Ensembles ("hard" and "soft")

The module also provides explain ability using SHAP analysis and feature importance visualisations. It also provides plots for model comparison of the key metrics used (accuracy, precision, recall, F1-score, ROC-AUC) and saves the trained models for later use.

The saved models can be loaded and then used and evaluated.

---

## 4. Detection Web App (`app.py`)

A Flask-based web interface for real-time APK analysis and risk assessment.

Users can upload APK files, select one of the various trained and saved models and receive:

- Risk predictions
- Dual-use classification
- Flagged suspicious features
- Model-based confidence outputs

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

### Flags Overview

- `-g` → Generate and expand seed queries into a larger search set  
- `-s` → Search for APK-related results using Google Custom Search  
- `-a` → Scrape APKMirror for APK metadata and download links  
- `-b` → Run in batched mode with checkpointing and fault tolerance (progress saving)
```
```
```

---

## 2. Static Analysis & Feature Extraction

Analyse APK files and generate the ML dataset:

```bash
python -m src.apk_analysis.APK_analyser \
data/raw/apks \
data/processed/apk_data.csv \
data/features/suspicious_permissions.json
```

### Flags Overview

- `apk_dir` — directory containing APK files to analyse  
- `output_csv` — path to export extracted feature dataset  
- `json_path` — suspicious permissions configuration file  
- `-o`, `--overwrite` — overwrite existing CSV instead of appending  

---

## 3. Model Training

Train all machine learning models and generate evaluation outputs:

```bash
python -m src.machine_learning.train_model --all_models --consensus
```

### Core Execution Flags

- `--all_models` (`-a`)  
  Trains **all available models** in the system, overriding any selection made with `--models`.  
  This includes:
  - Random Forest
  - Logistic Regression
  - SVM
  - Gradient Boosting
  - Dummy model

- `--consensus` (`-c`)  
  Enables **ensemble (voting) models** after base model training.  
  Builds:
  - Hard voting consensus model
  - Soft voting consensus model  
  Requires multiple base models to be meaningful.

- `--load` (`-l`)  
  Skips training and **loads previously saved models** from `OUTPUT_DIR`.  

---

### Model Selection Flags

- `--models` (`-m`)  
  Specifies which models to train manually. Accepts one or more values:

  ```bash
  --models random_forest logistic svm gradient_boosting dummy
  ```

---

## 4. Running the Web Application

Launch the Flask web server for APK classification dashboard:

```bash
PYTHONPATH=$(pwd)/src python src/web_app/app.py
```

---

# Setup

## Environment Configuration

Ensure all required `.env` files are configured within the relevant `utils/` directories.

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
