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


from abc import ABC, abstractmethod
import pandas as pd
import numpy as np
from dataclasses import dataclass
from typing import Optional, List, Dict
import shap


from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GridSearchCV
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    confusion_matrix,
)


@dataclass
class ModelConfig:
    """Configuration for each model type"""

    name: str
    param_space: Dict[str, List]
    pipeline: Optional[Pipeline] = None
    cv_folds: int = 3  # Change to 5 when I have more data
    metric: str = "f1"


class BaseModel(ABC):
    """Abstract base class for all ML models"""

    def __init__(self, config: ModelConfig):
        self.config = config
        self.model = None
        self.best_params = None
        self.best_score = None
        self.feature_importance = None
        self.scaler = StandardScaler()

    @abstractmethod
    def create_pipeline(self) -> Pipeline:
        """Create model pipeline"""
        raise NotImplementedError("Subclass must implemet create_pipeline method")

    def fit(self, X_train: pd.DataFrame, y_train: pd.Series) -> "BaseModel":
        """Train model with grid search"""
        print(f"|TRANING {self.config.name.upper()}")

        if self.config.pipeline is None:
            self.config.pipeline = self.create_pipeline()

        # Configure the grrid search and instantiate
        grid_search = GridSearchCV(
            estimator=self.config.pipeline,
            param_grid=self.config.param_space,
            cv=self.config.cv_folds,
            scoring=self.config.metric,
            n_jobs=-1,
            verbose=1,
        )

        print(f"Grid search with {len(self.config.param_space)} param combinations.")
        # Fit the grid search models
        grid_search.fit(X_train, y_train)

        # Extract the best model, its params and the score (configured earlier)
        self.model = grid_search.best_estimator_
        self.best_params = grid_search.best_params_
        self.best_score = grid_search.best_score_

        return self

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """Makes predictions using the best model"""
        if self.model is None:
            raise ValueError("Model not trained yet. Call fit() first.")
        # Predictions using the obtained model
        return self.model.predict(X)

    def predict_probs(self, X: pd.DataFrame) -> np.ndarray:
        """Get prediction probs"""
        if self.model is None:
            raise ValueError("Model not trained yet. Call fit() first.")
        # Get the prediction probabilities obtained from the model
        return self.model.predict_proba(X)

    def evaluate(self, X_test: pd.DataFrame, y_test: pd.Series) -> Dict[str, float]:
        """Evaluate model"""
        # Get predicted labels
        y_pred = self.predict(X_test)

        # Gets predicted probability of dual use if model can get prediction probs, since first column is prob of class 'benign'
        if hasattr(self.model, "predict_proba"):
            y_proba = self.predict_probs(X_test)[:, 1]
        else:
            y_proba = None

        print(y_proba)

        # Calculate metrics for both classes and weight by class sample size
        metrics = {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred, average="weighted"),
            "recall": recall_score(y_test, y_pred, average="weighted"),
            "f1": f1_score(y_test, y_pred, average="weighted"),
            "confusion_matrix": confusion_matrix(y_test, y_pred),
        }

        # Calculates roc_auc which is how well the model can distinguish between the classes
        if y_proba is not None:
            metrics["roc_auc"] = roc_auc_score(y_test, y_proba)

        return metrics

    def get_feature_importance(
        self, feature_names: List[str]
    ) -> Optional[pd.DataFrame]:
        """Find the most important features"""
        if self.model:
            # Extract the actual classifier from the pipeline
            try:
                classifier = self.model.named_steps["classifier"]
            except:
                print(
                    f"Warning: No classifier step found in pipeline in {self.config.name}"
                )
                return None

            if hasattr(classifier, "feature_importances_"):
                # For tree-based models (Random Forest, Gradient Boosting)
                importances = classifier.feature_importances_
            elif hasattr(classifier, "coef_"):
                # For linear models (Logistic Regression, SVM) look at the magnitude of the coefficients
                importances = np.abs(classifier.coef_[0])
            else:
                return None

            # Returns data frame with feature against importance in descending order
            return pd.DataFrame(
                {"feature": feature_names, "importance": importances}
            ).sort_values("importance", ascending=False)
        else:
            return None

    def get_shap_values(self, X_test: pd.DataFrame) -> Optional[Dict]:
        """Calculate SHAP values for feature importance, for larger datasets use samples because SHAPLEY can take a long time"""

        if self.model is None:
            raise ValueError("Model not trained yet. Call fit() first.")

        # Get the classifier from pipeline
        classifier = self.model.named_steps["classifier"]

        pipeline_steps = list(self.model.steps)
        # Get all pipeline steps apart from the classifier
        pre_steps = pipeline_steps[:-1]

        if pre_steps:
            pre_pipeline = Pipeline(pre_steps)
            # Transforms data with scalar for models that require it like logistic regression and SVM
            X_transformed = pre_pipeline.transform(X_test)
            # Convert numpy back into pandas with original column names
            X_sample = pd.DataFrame(X_transformed, columns=X_test.columns)
        else:
            X_sample = X_test.reset_index(drop=True)

        # Choose explainer based on model type
        if hasattr(classifier, "coef_"):
            # Linear models, use LinearExplainer (faster)
            explainer = shap.LinearExplainer(classifier, X_sample)
        elif self.config.name in ["random_forest", "gradient_boosting"]:
            # Use TreeExplainer for tree-based models
            explainer = shap.TreeExplainer(classifier, X_sample)
        else:
            # Non-linear use explainer that approximates SHAP values, use raw data
            explainer = shap.KernelExplainer(self.predict_probs, X_test)

        # Calculate SHAP values
        shap_values = explainer.shap_values(X_sample)

        return {
            "shap_values": shap_values,
            "explainer": explainer,
            "X_sample": X_sample,
            "features": X_sample.columns.tolist(),
        }
