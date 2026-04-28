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


from .base_model import BaseModel

from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


class LogisticRegressionModel(BaseModel):
    """
    Logistic Regression Classifier model that inherits from BaseModel
    """

    def create_pipeline(self) -> Pipeline:
        """
        Creates a pipeline using a logistic regression classifier.

        Returns:
            Pipeline: A Pipeline object
        """
        return Pipeline(
            [
                # Uses scaling since LRM is distance-based and scaling prevents extreme weights
                ("scaler", self.scaler),
                (
                    "classifier",
                    # Class weight set to balanced to handle imbalance in class frequency
                    LogisticRegression(random_state=50, class_weight="balanced"),
                ),
            ]
        )
