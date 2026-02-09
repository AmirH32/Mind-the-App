import os
import sys
import argparse
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Tuple


# Model imports
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from apk_discovery_tool.utils.config import CSV_FILE, MODEL_FILE


class APKMalwareDetector:
    """Main orchestrator for APK malware detection"""

    # Model configurations with hyperparameter grids
    MODEL_CONFIGS = {
        "random_forest": ModelConfig(
            name="Random Forest",
            param_grid={
                "classifier__n_estimators": [100, 200, 300],
                "classifier__max_depth": [None, 10, 20, 30],
                "classifier__min_samples_split": [2, 5, 10],
                "classifier__min_samples_leaf": [1, 2, 4],
            },
        ),
        "logistic": ModelConfig(
            name="Logistic Regression",
            param_grid={
                "classifier__C": [0.1, 1.0, 10.0, 100.0],
                "classifier__penalty": ["l1", "l2"],
                "classifier__solver": ["liblinear", "saga"],
                "classifier__max_iter": [500, 1000, 2000],
            },
        ),
        "svm": ModelConfig(
            name="Support Vector Machine",
            param_grid={
                "classifier__C": [0.1, 1.0, 10.0, 100.0],
                "classifier__kernel": ["linear", "rbf", "poly"],
                "classifier__gamma": ["scale", "auto", 0.1, 1.0],
            },
        ),
        "gradient_boosting": ModelConfig(
            name="Gradient Boosting",
            param_grid={
                "classifier__n_estimators": [100, 200, 300],
                "classifier__learning_rate": [0.01, 0.1, 0.2],
                "classifier__max_depth": [3, 5, 7, 9],
                "classifier__subsample": [0.8, 0.9, 1.0],
            },
        ),
    }

    def __init__(self, csv_path: str = CSV_FILE, output_dir: str = "models"):
        self.csv_path = csv_path
        self.output_dir = output_dir
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.feature_names = None
        self.trained_models = {}

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

    def load_and_prepare_data(self) -> Tuple[pd.DataFrame, pd.Series]:
        """Load CSV and prepare features/target"""
        print(f"Loading data from: {self.csv_path}")

        if not os.path.exists(self.csv_path):
            raise FileNotFoundError(f"CSV file not found: {self.csv_path}")

        df = pd.read_csv(self.csv_path)
        print(f"✓ Loaded {len(df)} samples with {len(df.columns)} features")

        # Identify target column
        target_candidates = ["label", "malware", "is_malicious", "target", "class"]
        target_col = next((col for col in target_candidates if col in df.columns), None)

        if target_col is None:
            raise ValueError(
                f"No target column found. Available columns: {list(df.columns)}"
            )

        # Prepare features
        non_feature_cols = [
            "apk_name",
            "package_name",
            "version_name",
            "app_name",
            target_col,
        ]
        cols_to_drop = [col for col in non_feature_cols if col in df.columns]

        X = df.drop(columns=cols_to_drop)
        y = df[target_col]

        # Convert target to binary if needed
        if y.dtype == "object":
            label_encoder = LabelEncoder()
            y = pd.Series(label_encoder.fit_transform(y), name=target_col)
            print(
                f"✓ Encoded target labels: {dict(zip(label_encoder.classes_, range(len(label_encoder.classes_))))}"
            )

        # Handle missing values
        X = X.fillna(0)

        # Store feature names
        self.feature_names = X.columns.tolist()

        print(f"✓ Features shape: {X.shape}")
        print(f"✓ Target distribution:\n{y.value_counts()}")
        print(f"✓ Malware ratio: {y.mean():.2%}")

        return X, y

    def split_data(self, X: pd.DataFrame, y: pd.Series, test_size: float = 0.2):
        """Split data into train/test sets"""
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        print(f"\nData split:")
        print(f"  Training samples: {len(self.X_train)}")
        print(f"  Testing samples: {len(self.X_test)}")
        print(f"  Features: {self.X_train.shape[1]}")

    def create_model(self, model_type: str) -> BaseModel:
        """Factory method to create model instances"""
        model_map = {
            "random_forest": RandomForestModel,
            "logistic": LogisticRegressionModel,
            "svm": SVMModel,
            "gradient_boosting": GradientBoostingModel,
        }

        if model_type not in model_map:
            raise ValueError(
                f"Unknown model type: {model_type}. Available: {list(model_map.keys())}"
            )

        config = self.MODEL_CONFIGS[model_type]
        return model_map[model_type](config)

    def train_single_model(self, model_type: str) -> BaseModel:
        """Train a single model"""
        model = self.create_model(model_type)
        model.fit(self.X_train, self.y_train)
        self.trained_models[model_type] = model
        return model

    def train_consensus(self, model_types: List[str]) -> ConsensusModel:
        """Train multiple models for consensus"""
        models = []
        for model_type in model_types:
            model = self.create_model(model_type)
            model.fit(self.X_train, self.y_train)
            models.append(model)
            self.trained_models[model_type] = model

        consensus = ConsensusModel(models, voting="soft")
        consensus.fit(self.X_train, self.y_train)
        self.trained_models["consensus"] = consensus
        return consensus

    def evaluate_all_models(self):
        """Evaluate all trained models"""
        print(f"\n{'=' * 80}")
        print("MODEL PERFORMANCE COMPARISON")
        print(f"{'=' * 80}")

        results = []
        for name, model in self.trained_models.items():
            if name == "consensus":
                metrics = model.evaluate(self.X_test, self.y_test)
            else:
                metrics = model.evaluate(self.X_test, self.y_test)

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

        # Save results
        results_df.to_csv(
            os.path.join(self.output_dir, "model_comparison.csv"), index=False
        )

        return results_df

    def plot_comparison(self, results_df: pd.DataFrame):
        """Create visualization of model comparison"""
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle("Model Performance Comparison", fontsize=16)

        metrics = ["Accuracy", "Precision", "Recall", "F1-Score"]

        for idx, metric in enumerate(metrics):
            ax = axes[idx // 2, idx % 2]
            # Convert strings to float for plotting
            values = results_df[metric].astype(float)
            ax.barh(results_df["Model"], values)
            ax.set_xlabel(metric)
            ax.set_xlim(0, 1)
            ax.set_title(f"{metric} Comparison")

            # Add value labels
            for i, v in enumerate(values):
                ax.text(v + 0.01, i, f"{v:.3f}", va="center")

        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, "model_comparison.png"), dpi=300)
        plt.show()

    def plot_feature_importance(self, top_n: int = 15):
        """Plot feature importance for models that support it"""
        importance_dfs = []

        for name, model in self.trained_models.items():
            if name != "consensus" and hasattr(model, "get_feature_importance"):
                importance_df = model.get_feature_importance(self.feature_names)
                importance_df["model"] = name.replace("_", " ").title()
                importance_dfs.append(importance_df.head(top_n))

        if importance_dfs:
            combined_importance = pd.concat(importance_dfs)

            plt.figure(figsize=(12, 8))
            for i, (model_name, group) in enumerate(
                combined_importance.groupby("model")
            ):
                plt.subplot(2, 2, i + 1)
                sns.barplot(x="importance", y="feature", data=group.head(10))
                plt.title(f"Top Features - {model_name}")
                plt.tight_layout()

            plt.suptitle("Feature Importance Across Models", fontsize=16)
            plt.tight_layout()
            plt.savefig(
                os.path.join(self.output_dir, "feature_importance.png"), dpi=300
            )
            plt.show()

    def save_models(self):
        """Save all trained models"""
        for name, model in self.trained_models.items():
            model_path = os.path.join(self.output_dir, f"{name}_model.pkl")
            joblib.dump(model, model_path)
            print(f"✓ Saved {name} model to: {model_path}")

    def run(self, model_types: List[str], use_consensus: bool = False):
        """Main execution pipeline"""
        print(f"\n{'=' * 80}")
        print("APK MALWARE DETECTION - ADVANCED ML PIPELINE")
        print(f"{'=' * 80}")

        # Load and prepare data
        X, y = self.load_and_prepare_data()
        self.split_data(X, y)

        # Train models
        if use_consensus:
            print(f"\nTraining consensus model with: {', '.join(model_types)}")
            self.train_consensus(model_types)
        elif len(model_types) == 1:
            print(f"\nTraining single model: {model_types[0]}")
            self.train_single_model(model_types[0])
        else:
            print(f"\nTraining multiple models: {', '.join(model_types)}")
            for model_type in model_types:
                self.train_single_model(model_type)

        # Evaluate
        results_df = self.evaluate_all_models()

        # Visualizations
        self.plot_comparison(results_df)
        self.plot_feature_importance()

        # Save models
        self.save_models()

        print(f"\n{'=' * 80}")
        print("TRAINING COMPLETE")
        print(f"{'=' * 80}")


def main():
    """Command line interface"""
    parser = argparse.ArgumentParser(
        description="APK Malware Detection ML Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python train_advanced.py --models random_forest                    # Single model
  python train_advanced.py --models random_forest logistic svm      # Multiple models
  python train_advanced.py --models all --consensus                 # All models with consensus
  python train_advanced.py --models rf logistic --output my_models  # Custom output dir
        """,
    )

    parser.add_argument(
        "--models",
        "-m",
        nargs="+",
        default=["random_forest"],
        choices=["random_forest", "logistic", "svm", "gradient_boosting", "all", "rf"],
        help='Models to train (use "all" for all models)',
    )

    parser.add_argument(
        "--consensus",
        "-c",
        action="store_true",
        help="Use consensus voting with trained models",
    )

    parser.add_argument(
        "--output", "-o", default="models", help="Output directory for saved models"
    )

    parser.add_argument("--csv", "-i", default=CSV_FILE, help="Path to input CSV file")

    args = parser.parse_args()

    # Handle model aliases
    if "all" in args.models:
        model_types = ["random_forest", "logistic", "svm", "gradient_boosting"]
    elif "rf" in args.models:
        model_types = ["random_forest"]
        if len(args.models) > 1:
            model_types.extend([m for m in args.models if m != "rf"])
    else:
        model_types = args.models

    # Create and run detector
    detector = APKMalwareDetector(csv_path=args.csv, output_dir=args.output)

    try:
        detector.run(model_types=model_types, use_consensus=args.consensus)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
