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
