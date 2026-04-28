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

from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier


class RandomForestModel(BaseModel):
    """
    Random Forest Classifier that inherits from BaseModel
    """

    def create_pipeline(self) -> Pipeline:
        """
        Creates a pipeline using a random forest classifier.

        Returns:
            Pipeline: A Pipeline object
        """
        return Pipeline(
            [
                # No need for a scalar since Random Forest is not distance-based
                # If it were distance based it would look for the closest point
                (
                    "classifier",
                    # Class weight set to balanced to handle imbalance in class frequency
                    RandomForestClassifier(random_state=50, class_weight="balanced"),
                ),
            ]
        )
