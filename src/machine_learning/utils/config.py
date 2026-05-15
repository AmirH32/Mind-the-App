from models.base_model import ModelConfig
from dotenv import load_dotenv
import os

load_dotenv()

CSV_FILE = os.getenv("CSV_FILE")
OUTPUT_DIR = os.getenv("OUTPUT_DIR")

# Model configurations with hyperparameter spaces
MODEL_CONFIGS = {
    "random_forest": ModelConfig(
        name="Random Forest",
        param_space={
            "classifier__n_estimators": [100, 200, 300],
            "classifier__max_depth": [None, 10, 20, 30],
            "classifier__min_samples_split": [2, 5, 10],
            "classifier__min_samples_leaf": [1, 2, 4],
        },
    ),
    "logistic": ModelConfig(
        name="Logistic Regression",
        param_space={
            "classifier__C": [0.1, 1.0, 10.0, 100.0],
            "classifier__solver": ["saga"],
            "classifier__l1_ratio": [0.0, 1.0],
            "classifier__penalty": ["elasticnet"],
            "classifier__max_iter": [1000, 2000, 5000],
        },
    ),
    "svm": ModelConfig(
        name="Support Vector Machine",
        param_space={
            "classifier__C": [0.1, 1.0, 10.0, 100.0],
            "classifier__kernel": ["linear", "rbf", "poly"],
            "classifier__gamma": ["scale", "auto", 0.1, 1.0],
        },
    ),
    "gradient_boosting": ModelConfig(
        name="Gradient Boosting",
        param_space={
            "classifier__n_estimators": [100, 200, 300],
            "classifier__learning_rate": [0.01, 0.1, 0.2],
            "classifier__max_depth": [3, 5, 7, 9],
            "classifier__subsample": [0.8, 0.9, 1.0],
        },
    ),
    "dummy": ModelConfig(
        name="Dummy Baseline",
        param_space={},  # No tuning needed for baseline
        cv_folds=3,  # Keep consistent with others
        metric="f1",  # Keep consistent with others
    ),
}
