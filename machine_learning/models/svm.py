from sklearn.svm import SVC
from sklearn.pipeline import Pipeline

from ..base_model import BaseModel


class SVMModel(BaseModel):
    """
    Support Vector Machine Classifier model that inherits from BaseModel
    """

    def create_pipeline(self) -> Pipeline:
        """
        Creates a pipeline using a Support Vector Machine model.

        Returns:
            Pipeline: A Pipeline object
        """
        return Pipeline(
            [
                # SVM is distance based so we need to scale the data
                ("scaler", self.scaler),
                (
                    # Set probability to true so we can see confidence levels. Further it accounts for difference in class distribution.
                    "classifier",
                    SVC(random_state=50, class_weight="balanced", probability=True),
                ),
            ]
        )
