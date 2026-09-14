from pathlib import Path

import joblib
from sklearn.pipeline import Pipeline

from app.models.email_models import EmailData


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_MODEL_PATH = (
    PROJECT_ROOT
    / "models"
    / "baseline_tfidf_logistic_regression.joblib"
)


class MLInferenceService:
    """Run phishing-probability inference using the trained baseline model."""

    def __init__(self, model_path: Path | str = DEFAULT_MODEL_PATH) -> None:
        self.model_path = Path(model_path)
        self._pipeline: Pipeline | None = None

    def _load_pipeline(self) -> Pipeline:
        """Load and cache the trained ML pipeline."""
        if self._pipeline is None:
            if not self.model_path.is_file():
                raise FileNotFoundError(
                    f"ML model not found: {self.model_path}"
                )

            pipeline = joblib.load(self.model_path)

            if not isinstance(pipeline, Pipeline):
                raise TypeError(
                    "Loaded ML model must be a scikit-learn Pipeline."
                )

            self._pipeline = pipeline

        return self._pipeline

    @staticmethod
    def _prepare_text(email: EmailData) -> str:
        """Build the inference text using the Phase 4 subject/body format."""
        subject = email.subject or ""
        body = email.plain_text_body or ""

        return f"{subject} {body}".strip()

    def predict_phishing_probability(self, email: EmailData) -> float:
        """Return the model probability that the email is phishing."""
        pipeline = self._load_pipeline()
        text = self._prepare_text(email)

        probabilities = pipeline.predict_proba([text])

        classes = pipeline.named_steps["classifier"].classes_
        phishing_index = list(classes).index("phishing")

        return float(probabilities[0, phishing_index])