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

import pandas as pd
import numpy as np
from .base_model import BaseModel
from typing import List
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from sklearn.model_selection import cross_val_score


class ConsensusModel:
    """
    Consensus model that combines predictions from multiple models that inherit from BaseModel
    """

    def __init__(self, models: List[BaseModel], voting: str = "soft"):
        self.models = models
        self.voting = voting  # "hard" or "soft", hard voting uses the predicted class label, while soft voting uses the predicted probability to make a final prediction.
        self.weights = None

    # Utilise forward referencing using speech marks since the class is not yet fully defined but I want to refer to it
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
        model_to_weight = {}

        for m, w in zip(self.models, self.weights):
            model_to_weight[m] = w
        print(f"\nModel weights for consensus: {model_to_weight}")
        return self

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """Make consensus predictions"""
        if self.weights is None:
            raise ValueError("Model weights not calculated. Call fit() first.")
        if self.voting == "hard":
            # Each predict returns a Numpy array that looks like [0, 1, 0, 1] for each sample
            # All models vote with their prediction resulting in Numpy arrow that has row for each model and a column for each sample
            predictions = np.array([model.predict(X) for model in self.models])

            # Weighted voting where we initialise the number of samples and the possible binary classification: benign or dual use. We use NumPy array to do this
            # Each row is a sample and each column is a class, then we accumulate the weighted predictions across all models to find the likelihood of either class being correct.
            weighted_votes = np.zeros((X.shape[0], 2))

            for pred, weight in zip(predictions, self.weights):
                # for both possible classes (benign and dual use) we check if the prediction is equal to the class across all samples for that particular model and we iterate to cover all models. We check if it is equal and then multiply by the weight of that model using vector operations.
                for i in range(2):  # For binary classification
                    weighted_votes[:, i] += ((pred == i).astype(int)) * weight
            # Finds the index of the largest value in the each row and returns that
            # Perhaps we can add method to return the confidence of the prediction as well
            return np.argmax(weighted_votes, axis=1)
        else:
            # predict_probs returns a numpy array which is 2D and looks like [[0.8, 0.2], [0.3, 0.7]]. Each row is a sample and each column is the probability of being in that class
            # Create an array storing the prediction probabilities for each model. Model is the row and column is the sample
            probs = np.array([model.predict_probs(X) for model in self.models])

            # Gets the probabilities from the first model and uses its shape to create a 2D array of zeros
            weighted_probs = np.zeros_like(probs[0])

            # Iterate through the probability predictions from each model along with their corresponding weights and adds it as a vectorised computation, essentially goes over each element in the vector and adds the probability the model predicted multiplied by that models weight. Since all weights sum to 1 the probabilities should still sum to 1.
            for probs, weight in zip(probs, self.weights):
                weighted_probs += probs * weight
            # Finds the largest value in each row and returns the index of the column corresponding to that value which will be 0 for benign and 1 for dual use.
            return np.argmax(weighted_probs, axis=1)

    def predict_probs(self, X: pd.DataFrame) -> np.ndarray:
        """Returns confidence/prediction probabilities for each sample"""
        if self.weights is None:
            raise ValueError("Model weights not calculated. Call fit() first.")
        if self.voting == "hard":
            # Each predict returns a Numpy array that looks like [0, 1, 0, 1] for each sample
            # All models vote with their prediction resulting in Numpy arrow that has row for each model and a column for each sample
            predictions = np.array([model.predict(X) for model in self.models])

            # Weighted voting where we initialise the number of samples and the possible binary classification: benign or dual use. We use NumPy array to do this
            # Each row is a sample and each column is a class, then we accumulate the weighted predictions across all models to find the likelihood of either class being correct.
            weighted_votes = np.zeros((X.shape[0], 2))

            for pred, weight in zip(predictions, self.weights):
                # for both possible classes (benign and dual use) we check if the prediction is equal to the class across all samples for that particular model and we iterate to cover all models. We check if it is equal and then multiply by the weight of that model using vector operations.
                for i in range(2):  # For binary classification
                    weighted_votes[:, i] += ((pred == i).astype(int)) * weight
            # Finds the index of the largest value in the each row and returns that
            # Perhaps we can add method to return the confidence of the prediction as well
            return weighted_votes
        else:
            # predict_probs returns a numpy array which is 2D and looks like [[0.8, 0.2], [0.3, 0.7]]. Each row is a sample and each column is the probability of being in that class
            # Create an array storing the prediction probabilities for each model. Model is the row and column is the sample
            probs = np.array([model.predict_probs(X) for model in self.models])

            # Gets the probabilities from the first model and uses its shape to create a 2D array of zeros
            weighted_probs = np.zeros_like(probs[0])

            # Iterate through the probability predictions from each model along with their corresponding weights and adds it as a vectorised computation, essentially goes over each element in the vector and adds the probability the model predicted multiplied by that models weight. Since all weights sum to 1 the probabilities should still sum to 1.
            for probs, weight in zip(probs, self.weights):
                weighted_probs += probs * weight
            # Finds the largest value in each row and returns the index of the column corresponding to that value which will be 0 for benign and 1 for dual use.
            return weighted_probs

    def evaluate(self, X_test: pd.DataFrame, y_test: pd.Series) -> dict[str, float]:
        """Evaluate consensus model"""
        y_pred = self.predict(X_test)

        return {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred, average="weighted"),
            "recall": recall_score(y_test, y_pred, average="weighted"),
            "f1": f1_score(y_test, y_pred, average="weighted"),
        }
