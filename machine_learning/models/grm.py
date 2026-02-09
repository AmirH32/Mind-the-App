from sklearn.ensemble import GradientBoostingClassifier
from sklearn.pipeline import Pipeline

from ..base_model import BaseModel


class GradientBoostingModel(BaseModel):
    """
    Gradient Boosting Classifier model that inherits from BaseModel
    """

    def create_pipeline(self) -> Pipeline:
        """
        Creates a pipeline using a gradient boosting model.

        Returns:
            Pipeline: A Pipeline object
        """
        return Pipeline(
            [
                # No need for a scalar since Gradient Boosting is not distance-based but instead uses iterative weighted trees.
                ("classifier", GradientBoostingClassifier(random_state=50)),
            ]
        )
