# Mind the App: Detecting Dual-Use Applications
# Copyright (C) 2026 Amir Hassanali
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import os
import sys
import warnings
import argparse
import pandas as pd
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from typing import List, Tuple, Type, Dict

from models.base_model import BaseModel
from models.grm import GradientBoostingModel
from models.rfm import RandomForestModel
from models.lrm import LogisticRegressionModel
from models.svm import SVMModel
from models.consensus import ConsensusModel

# Model imports
from sklearn.model_selection import train_test_split

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.config import CSV_FILE, OUTPUT_DIR, MODEL_CONFIGS

warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)


def check_constants():
    """Checks if essential constants are set."""
    missing = []
    if not isinstance(CSV_FILE, str):
        missing.append("CSV_FILE")
    if not isinstance(OUTPUT_DIR, str):
        missing.append("OUTPUT_DIR")
    if missing:
        raise ValueError(f"Missing or invalid constants: {', '.join(missing)}")


class APKMalwareDetector:
    """Main orchestrator for APK malware detection"""

    def __init__(
        self,
        csv_path: str = CSV_FILE,  # pyright: ignore
        output_dir: str = OUTPUT_DIR,  # pyright: ignore
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

        # Drop columns that aren't used as features (add bag of words so we can do apk_name)
        non_feature_cols = [
            label_col,
            "risk_score_prediction",
            "apk_name",
            "package_name",
        ]

        X = df.drop(columns=non_feature_cols)
        y = df[label_col].astype("int")

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
        if X is None or y is None:
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
            # We store the trained model in a dictionary with the model type as the key and the trained model as the value so we can later access as well as export the model
            self.trained_models[model_type] = model
            return model
        else:
            raise ValueError(
                "Training data not properly set. Check the data loading and splitting steps."
            )

    # TODO
    def train_consensus(self, model_types: List[str]):
        """Construct models for both consensus models and then fit it"""
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
            consensus_hard = ConsensusModel(models, voting="hard")
            # Fit the consensus model to the training data
            consensus_hard.fit(self.X_train, self.y_train)
            # Add the consensus model to the dictionary of trained models
            self.trained_models["consensus_hard"] = consensus_hard

            consensus_soft = ConsensusModel(models, voting="soft")
            consensus_soft.fit(self.X_train, self.y_train)
            self.trained_models["consensus_soft"] = consensus_soft

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

    def plot_comparison(self, results_df: pd.DataFrame):
        """Create plots to compare models"""
        # Create a grid of 4 with a title
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle("Model Performance Comparison", fontsize=16)

        metrics = ["Accuracy", "Precision", "Recall", "F1-Score"]

        for idx, metric in enumerate(metrics):
            # Use modular math and integer divide to switch between the rows and columns
            ax = axes[idx // 2, idx % 2]
            # Convert strings to float for plotting
            values = results_df[metric].astype(float)
            # Horizontal bar chart with y-axis being model name and x-axis the value for the metric
            ax.barh(results_df["Model"], values)
            ax.set_xlabel(metric)
            # Ensure x ranges from 0 to 1
            ax.set_xlim(0, 1)
            ax.set_title(f"{metric} Comparison")

            # Add value labels
            for i, v in enumerate(values):
                # For each bar we add the value of the metric for the bar
                ax.text(v + 0.01, i, f"{v:.3f}", va="center")

        # prevent label/title overlap
        plt.tight_layout()
        # Save the evaluation plot
        plt.savefig(os.path.join(self.output_dir, "model_comparison.png"), dpi=300)
        plt.show()

    def plot_feature_importance(self, top_n: int = 15):
        """Plot feature importance for models that support it"""
        importance_dfs = []

        for name, model in self.trained_models.items():
            # Get feature importance for each model that supports it
            if "consensus" not in name and hasattr(model, "get_feature_importance"):
                importance_df = model.get_feature_importance(self.feature_names)
                # Change the underscore for space and makes it title case
                if importance_df is not None:
                    importance_df["model"] = name.replace("_", " ").title()

                    # Append the top n features in a dataframe for each model to the importance features list
                    importance_dfs.append(importance_df.head(top_n))
                else:
                    continue

        if importance_dfs:
            # Combine all the importance dataframes into one dataframe to plot them together
            combined_importance = pd.concat(importance_dfs)

            plt.figure(figsize=(12, 8))
            # Loop over each model's importance features
            for i, (model_name, group) in enumerate(
                combined_importance.groupby("model")
            ):
                # Each model gets its own subplot
                plt.subplot(2, 2, i + 1)
                # Only plots 10 features
                sns.barplot(x="importance", y="feature", data=group.head(10))
                plt.title(f"Top Features - {model_name}")
                plt.tight_layout()

            plt.suptitle("Feature Importance Across Models", fontsize=16)
            plt.tight_layout()

            # Save the features
            plt.savefig(
                os.path.join(self.output_dir, "feature_importance.png"), dpi=300
            )
            plt.show()

    def save_models(self):
        """Save all trained models"""
        for name, model in self.trained_models.items():
            model_path = os.path.join(self.output_dir, f"{name}_model.pkl")
            # joblib instead of pickle as more optimal for large numpy arrays. Saves the model in a file
            joblib.dump(model, model_path)
            print(f"Saved {name} model to: {model_path}")

    def load_models(self, model_types: List[str], use_cons: bool):
        """Load the pre-trained models from the directory"""
        for name in model_types:
            # Find the model path name
            model_path = os.path.join(self.output_dir, f"{name}_model.pkl")

            # If model file exists then we load it
            if os.path.exists(model_path):
                self.trained_models[name] = joblib.load(model_path)
                print(f"Loaded {name} model.")
            else:
                print(f"Model file not found: {model_path}")

        if use_cons:
            for mode in ["hard", "soft"]:
                cons_path = os.path.join(self.output_dir, f"consensus_{mode}_model.pkl")
                if os.path.exists(cons_path):
                    self.trained_models[f"consensus_{mode}"] = joblib.load(cons_path)
                    print(f"Loaded {mode} consensus model.")
                else:
                    print(f"Consensus model file not found: {cons_path}")

    def run(
        self,
        model_types: List[str],
        use_consensus: bool = False,
        all_models: bool = False,
        load: bool = False,
    ):
        """Main execution pipeline"""
        print("APK MALWARE DETECTION - ML PIPELINE")

        # Load the data and split into test and training sets
        X, y = self.load_and_prepare_data()
        self.split_data(X, y)

        if load:
            print(f"\nLoading models from {self.output_dir}...")
            self.load_models(model_types, use_consensus)
        else:
            # Train the models
            if use_consensus and len(model_types) > 1:
                # Iterate through each model type to show which we are using
                print("\nTraining consensus model with:")
                for model_t in model_types:
                    print(f"\n- {model_t}")

                self.train_consensus(model_types)

            else:
                # Can't do consensus with only one model
                print(f"\nTraining single model: {model_types[0]}")
                self.train_single_model(model_types[0])

            if all_models:
                print("\nTraining multiple models:")
                for model_type in model_types:
                    # Don't retrain models already trained by the consensus model
                    if model_type not in self.trained_models:
                        print(f"\n- {model_type}")
                        self.train_single_model(model_type)

            # Save the models
            self.save_models()

        if self.trained_models:
            # Evaluate
            results_df = self.evaluate_all_models()

            # Plot the results
            self.plot_comparison(results_df)
            self.plot_feature_importance()

            print("TRAINING COMPLETE, PLOTS and MODELS SAVED")
        else:
            print("No models loaded/trained.")


def main():
    """Command line interface"""
    parser = argparse.ArgumentParser(
        description="APK Malware Detection ML Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        Examples:
        python -m train_model --models random_forest                    # Single model
        python -m train_model --models random_forest logistic svm  --consensus    # Multiple models
        python -m train_model -a --consensus  # Train all models with consensus
        python -m train_model --models rf logistic --output my_models  # Custom output dir
        python -m train_model -l --models svm logistic --consensus # Loads pre-trained SVM and logistic model from directory as well as their combined consensus model
        """,
    )

    parser.add_argument(
        "--models",
        "-m",
        # Expect one or more arguments
        nargs="+",
        default=["random_forest"],
        choices=["random_forest", "logistic", "svm", "gradient_boosting"],
        help='Models to train (use "all" for all models)',
    )

    parser.add_argument(
        "--all_models",
        "-a",
        action="store_true",
        help="Train all models (overrides --models if set)",
    )

    parser.add_argument(
        "--consensus",
        "-c",
        action="store_true",
        help="Use consensus voting with trained models",
    )

    parser.add_argument(
        "--load",
        "-l",
        action="store_true",
        help="Directory to load pre-trained models from",
    )

    args = parser.parse_args()

    check_constants()

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
    detector = APKMalwareDetector(csv_path=CSV_FILE, output_dir=OUTPUT_DIR)  # pyright: ignore

    if args.all_models:
        model_types = ["random_forest", "logistic", "svm", "gradient_boosting"]

    detector.run(
        model_types=model_types,
        use_consensus=args.consensus,
        all_models=args.all_models,
        load=args.load,
    )


if __name__ == "__main__":
    main()
