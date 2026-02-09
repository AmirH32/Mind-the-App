import pandas as pd
import numpy as np
from ..base_model import BaseModel
from typing import List

from sklearn.model_selection import cross_val_score


class ConsensusModel:
    """
    Consensus model that combines predictions from multiple models that inherit from BaseModel
    """

    def __init__(self, models: List[BaseModel], voting: str = "soft"):
        self.models = models
        self.voting = voting  # "hard" or "soft"
        self.weights = None

    # Utilise forward referencing since the class is not yet fully defined but I want to refer to it
    def fit(self, X_train: pd.DataFrame, y_train: pd.Series) -> "ConsensusModel":
        """Train all individual models"""
        for model in self.models:
            model.fit(X_train, y_train)

        # Calculate weights based on cross-validation scores
        self.weights = []
        for model in self.models:
            # Performs 5-fold cross-validation using F1 score as the metric
            cv_scores = cross_val_score(
                model.model, X_train, y_train, cv=5, scoring="f1"
            )
            # stores the mean as model weight (the better the model performs with f1 metric the more weight it gets in the final say)
            weight = cv_scores.mean()
            self.weights.append(weight)

        # Normalize weights to sum to one
        total = sum(self.weights)
        if total > 0:
            self.weights = [w / total for w in self.weights]
        else:
            # If all weights are zero (shouldn't happen), assign equal weight to each model
            self.weights = [1 / len(self.models)] * len(self.models)

        # Pairs models against their weights as a dictionary
        print(
            f"\nModel weights for consensus: {dict(zip([m.config.name for m in self.models], self.weights))}"
        )
        return self

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """Make consensus predictions"""
        if self.voting == "hard":
            # Majority vote
            predictions = np.array([model.predict(X) for model in self.models])
            # Weighted voting
            weighted_votes = np.zeros((X.shape[0], 2))  # Assuming binary classification
            for pred, weight in zip(predictions, self.weights):
                for i in range(2):  # For binary classification
                    weighted_votes[:, i] += (pred == i) * weight
            return np.argmax(weighted_votes, axis=1)
        else:
            # Soft voting (average probabilities)
            probas = np.array([model.predict_proba(X) for model in self.models])
            weighted_probas = np.zeros_like(probas[0])
            for proba, weight in zip(probas, self.weights):
                weighted_probas += proba * weight
            return np.argmax(weighted_probas, axis=1)

    def evaluate(self, X_test: pd.DataFrame, y_test: pd.Series) -> Dict[str, float]:
        """Evaluate consensus model"""
        y_pred = self.predict(X_test)

        return {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred, average="weighted"),
            "recall": recall_score(y_test, y_pred, average="weighted"),
            "f1": f1_score(y_test, y_pred, average="weighted"),
        }
