import os
import sys
import argparse
import pandas as pd
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from typing import List, Tuple, Type, Dict

from base_model import BaseModel
from models.grm import GradientBoostingModel
from models.rfm import RandomForestModel
from models.lrm import LogisticRegressionModel
from models.svm import SVMModel
from models.consensus import ConsensusModel

# Model imports
from sklearn.model_selection import train_test_split

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.config import CSV_FILE, MODEL_FILE, MODEL_CONFIGS


def check_constants():
    """Checks if essential constants are set."""
    missing = []
    if not isinstance(CSV_FILE, str):
        missing.append("CSV_FILE")
    if not isinstance(MODEL_FILE, str):
        missing.append("MODEL_FILE")
    if missing:
        raise ValueError(f"Missing or invalid constants: {', '.join(missing)}")


class APKMalwareDetector:
    """Main orchestrator for APK malware detection"""

    def __init__(
        self,
        csv_path: str = CSV_FILE,  # pyright: ignore
        output_dir: str = MODEL_FILE,  # pyright: ignore
        configs: dict = MODEL_CONFIGS,
    ):
        self.csv_path = csv_path
        self.output_dir = output_dir
        self.configs = configs
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.feature_names = None
        self.trained_models = {}

        # Create output directory, exist_ok makes sure it won't raise an error if it already exists
        os.makedirs(output_dir, exist_ok=True)

    def load_and_prepare_data(self) -> Tuple[pd.DataFrame, pd.Series]:
        """Load CSV and prepare features/target"""
        # Make sure the csv file with the required features and truth labels exists
        if not os.path.exists(self.csv_path):
            raise FileNotFoundError(f"CSV file not found: {self.csv_path}")

        df = pd.read_csv(self.csv_path)
        print(f"Loaded {len(df)} samples")

        label_col = "label"

        # Drop columns that aren't used as features
        non_feature_cols = [label_col, "risk_score_prediction"]

        X = df.drop(columns=non_feature_cols)
        y = df[label_col].as_type("int")

        # Handle missing values in case it was blank
        X = X.fillna(0)

        # Store feature names
        self.feature_names = X.columns.tolist()

        print(f"Features shape: {X.shape}")
        print(f"True label distribution:\n{y.value_counts()}")
        print(f"Malware sample distribution: {y.mean():.2%}")

        return X, y

    def split_data(self, X: pd.DataFrame, y: pd.Series, test_size: float = 0.2):
        """Split data into train/test sets"""
        if self.X_train is None:
            raise ValueError("Data not loaded. Call load_and_prepare_data() first.")

        # Stratifies so that there is the same distribution of malware/benign samples in both train and test sets
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y, test_size=test_size, random_state=50, stratify=y
        )
        if not isinstance(self.X_train, pd.DataFrame):
            raise ValueError("Data split failed. Check the input data and parameters.")

        print("\nData split:")
        print(f"  Training samples: {len(self.X_train)}")
        print(f"  Testing samples: {len(self.X_test)}")
        print(f"  Features: {self.X_train.shape[1]}")

    def create_model(self, model_type: str) -> BaseModel:
        """Factory method to create model instances"""
        # Dictionary that maps the model's names to the class
        model_map: Dict[str, Type[BaseModel]] = {
            "random_forest": RandomForestModel,
            "logistic": LogisticRegressionModel,
            "svm": SVMModel,
            "gradient_boosting": GradientBoostingModel,
        }

        # Use the model type string to index the config dictionary to obtain the configuration for the model
        config = self.configs[model_type]

        # Get the model class from the model_map dictionary
        model_class = model_map[model_type]
        # Return an instance of the model class, initialised by passing the config into the constructor
        return model_class(config)

    def train_single_model(self, model_type: str) -> BaseModel:
        """Train a single model"""
        model = self.create_model(model_type)

        # To pass pyright annoying warnings we check the type first of both the training data and the y labels
        if isinstance(self.X_train, pd.DataFrame) and isinstance(
            self.y_train, pd.Series
        ):
            # We fit the model based on the truth label using the X dataset features mapped to the true labels (y)
            model.fit(self.X_train, self.y_train)
            # We store the trained model in a dictionary with the model type as the key and the trained model as the value so we can later access as well as export the model            self.trained_models[model_type] = model
            return model
        else:
            raise ValueError(
                "Training data not properly set. Check the data loading and splitting steps."
            )

    # TODO
    def train_consensus(self, model_types: List[str]) -> ConsensusModel:
        """Construct models for the consensus model and then fit it"""
        if isinstance(self.X_train, pd.DataFrame) and isinstance(
            self.y_train, pd.Series
        ):
            models = []
            for model_type in model_types:
                # Create a model for each model_type you passed into the function as a list
                model = self.create_model(model_type)
                # Adds the untrained  model to the list of models
                models.append(model)

            # Create a consensus model instance that takes the trained models and uses soft voting (can be changed to hard if needed)
            consensus = ConsensusModel(models, voting="soft")
            # Fit the consensus model to the training data
            consensus.fit(self.X_train, self.y_train)
            # Add the consensus model to the dictionary of trained models
            self.trained_models["consensus"] = consensus
            return consensus
        else:
            raise ValueError(
                "Training data not properly set. Check the data loading and splitting steps."
            )

    # TODO
    def evaluate_all_models(self):
        """Evaluate all trained models, if you want all models this requires running train_all_models()"""
        print(f"\n{'=' * 60}")
        print("MODEL PERFORMANCE COMPARISON")
        print(f"{'=' * 60}")

        results = []
        # Iterate through the trained models list
        for name, model in self.trained_models.items():
            # Evaluate the models
            metrics = model.evaluate(self.X_test, self.y_test)

            # Append the results for each model into the results
            results.append(
                {
                    "Model": name.replace("_", " ").title(),
                    "Accuracy": f"{metrics.get('accuracy', 0):.4f}",
                    "Precision": f"{metrics.get('precision', 0):.4f}",
                    "Recall": f"{metrics.get('recall', 0):.4f}",
                    "F1-Score": f"{metrics.get('f1', 0):.4f}",
                    "ROC-AUC": f"{metrics.get('roc_auc', 'N/A')}",
                }
            )

        # Display results
        results_df = pd.DataFrame(results)
        print(results_df.to_string(index=False))

        # Save results to a csv to compare the models
        results_df.to_csv(
            os.path.join(self.output_dir, "model_comparison.csv"), index=False
        )

        return results_df
