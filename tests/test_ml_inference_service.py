from pathlib import Path

import pytest
from sklearn.pipeline import Pipeline

from app.models.email_models import EmailData
from app.services.ml_inference_service import (
    DEFAULT_MODEL_PATH,
    MLInferenceService,
)


def create_email(
    subject: str | None = "Test subject",
    body: str | None = "Test body",
) -> EmailData:
    return EmailData(
        sender="sender@example.com",
        recipients=["recipient@example.com"],
        subject=subject,
        plain_text_body=body,
    )


def test_default_model_path_exists():
    assert DEFAULT_MODEL_PATH.is_file()


def test_service_loads_trained_pipeline():
    service = MLInferenceService()

    pipeline = service._load_pipeline()

    assert isinstance(pipeline, Pipeline)
    assert list(pipeline.named_steps.keys()) == [
        "tfidf",
        "classifier",
    ]


def test_service_caches_loaded_pipeline():
    service = MLInferenceService()

    first_pipeline = service._load_pipeline()
    second_pipeline = service._load_pipeline()

    assert first_pipeline is second_pipeline


def test_prepare_text_matches_phase_4_format():
    email = create_email(
        subject="Hello",
        body="Normal message",
    )

    result = MLInferenceService._prepare_text(email)

    assert result == "Hello Normal message"


def test_prepare_text_handles_missing_subject():
    email = create_email(
        subject=None,
        body="This is the email body",
    )

    result = MLInferenceService._prepare_text(email)

    assert result == "This is the email body"


def test_prepare_text_handles_missing_body():
    email = create_email(
        subject="Test subject",
        body=None,
    )

    result = MLInferenceService._prepare_text(email)

    assert result == "Test subject"


def test_predict_phishing_probability_returns_probability():
    service = MLInferenceService()

    probability = service.predict_phishing_probability(
        create_email(
            subject="Normal meeting",
            body="Please find the meeting notes attached.",
        )
    )

    assert isinstance(probability, float)
    assert 0.0 <= probability <= 1.0


def test_predict_phishing_probability_uses_phishing_class():
    service = MLInferenceService()

    pipeline = service._load_pipeline()
    email = create_email(
        subject="Urgent account verification",
        body="Click this link immediately to verify your account.",
    )

    probabilities = pipeline.predict_proba(
        [MLInferenceService._prepare_text(email)]
    )

    classes = pipeline.named_steps["classifier"].classes_
    phishing_index = list(classes).index("phishing")

    expected_probability = float(
        probabilities[0, phishing_index]
    )

    actual_probability = service.predict_phishing_probability(email)

    assert actual_probability == expected_probability


def test_missing_model_raises_file_not_found(tmp_path: Path):
    missing_model = tmp_path / "missing_model.joblib"

    service = MLInferenceService(model_path=missing_model)

    with pytest.raises(
        FileNotFoundError,
        match="ML model not found",
    ):
        service.predict_phishing_probability(create_email())