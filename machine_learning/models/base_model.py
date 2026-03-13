from abc import ABC
import pandas as pd
import numpy as np
from dataclasses import dataclass
from typing import Optional, List, Dict

from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GridSearchCV
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


@dataclass
class ModelConfig:
    """
    Configuration for each model type

    Attributes:
        name (str): Name of the model
        param_space (Dict[str, List): Hyperparameter space for tuning
        pipeline (Optional[Pipeline]): Predefined Pipeline
        cv_folds (int): Number of cross-val folds
        metric (str):  metric for eval
    """

    name: str
    param_space: Dict[str, List]
    pipeline: Optional[Pipeline] = None
    cv_folds: int = 3  # Change to 5 when I have more data
    metric: str = "f1"


class BaseModel(ABC):
    """

    Abstract base class for all ML models

    Attributes:
        config (ModelConfig): Configuration for the model
        model (Any): Trained model instance
        best_params (Dict[str, Any]): Best hyperparameters after tuning
        best_score (float): Best score achieved during tuning
        feature_importance (Optional[pd.DataFrame]): Feature importance DataFrame
        scaler (StandardScaler): Scaler for feature normalising
    """

    def __init__(self, config: ModelConfig):
        self.config = config
        self.model = None
        self.best_params = None
        self.best_score = None
        self.feature_importance = None
        self.scaler = StandardScaler()

    def create_pipeline(self) -> Pipeline:
        """
        Create model pipeline

        Returns:
            Pipeline: pipeline object
        """
        raise NotImplementedError("Subclass must implemet create_pipeline method")

    def fit(self, X_train: pd.DataFrame, y_train: pd.Series) -> "BaseModel":
        """
        Train model with grid search

        Args:
            X_train (pd.DataFrame): Training features
            y_train (pd.Series): Training labels

        Returns:
            BaseModel: Trained model
        """
        print(f"\n{'=' * 60}")
        print(f"TRANING {self.config.name.upper()}")

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
        """
        Makes predictions using the best model

        Args:
            X (pd.DataFrame): Features

        Returns:
            np.ndarray: Predicted labels
        """
        if self.model is None:
            raise ValueError("Model not trained yet. Call fit() first.")
        # Predictions using the obtained model
        return self.model.predict(X)

    def predict_probs(self, X: pd.DataFrame) -> np.ndarray:
        """
        Get prediction probs

        Args:
            X (pd.DataFrame): features
        Returns:
            np.ndarray: Predicted probs
        """
        if self.model is None:
            raise ValueError("Model not trained yet. Call fit() first.")
        # Get the prediction probabilities obtained from the model
        return self.model.predict_proba(X)

    def evaluate(self, X_test: pd.DataFrame, y_test: pd.Series) -> Dict[str, float]:
        """
        Evaluate model

        Args:
            X_test (pd.DataFrame): Features
            y_test (pd.Series): True labels

        Returns:
            Dict[str, float]: Dictionary of eval metric
        """
        # Get predicted labels
        y_pred = self.predict(X_test)

        # Gets predicted probability of dual use if model can get prediction probs, since first column is prob of class 'benign'
        if hasattr(self.model, "predict_probabilities"):
            y_proba = self.predict_probs(X_test)[:, 1]
        else:
            y_proba = None

        # Calculate metrics for both classes and weight by class sample size
        metrics = {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred, average="weighted"),
            "recall": recall_score(y_test, y_pred, average="weighted"),
            "f1": f1_score(y_test, y_pred, average="weighted"),
        }

        # Calculates roc_auc which is how well the model can distinguish between the classes
        if y_proba is not None:
            metrics["roc_auc"] = roc_auc_score(y_test, y_proba)

        return metrics

    def get_feature_importance(
        self, feature_names: List[str]
    ) -> Optional[pd.DataFrame]:
        """
        Find the most important features

        Args:
            feature_names (List[str]): List of features

        Returns:
            pd.DataFrame: DataFrame of features and numerical importance
        """
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
