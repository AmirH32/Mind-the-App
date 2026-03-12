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
