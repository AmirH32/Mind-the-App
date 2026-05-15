from sklearn.dummy import DummyClassifier
from sklearn.pipeline import Pipeline
from .base_model import BaseModel


class DummyModel(BaseModel):
    """Baseline model that uses the 'most_frequent' strategy."""

    def create_pipeline(self) -> Pipeline:
        # A simple pipeline with just the dummy classifier
        return Pipeline([("classifier", DummyClassifier(strategy="most_frequent"))])

    def get_feature_importance(self, feature_names):
        # Dummy models don't have feature importance, so we return None
        return None

    def get_shap_values(self, X_test):
        # SHAP analysis isn't meaningful for a dummy classifier
        return None
