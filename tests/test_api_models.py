import pytest
from pydantic import ValidationError

from app.models.api_models import EmailAnalysisRequest
from app.models.pipeline_models import PipelineResult


def test_email_analysis_request_accepts_raw_email():
    request = EmailAnalysisRequest(
        raw_email="From: sender@example.com\r\nSubject: Test\r\n\r\nHello"
    )

    assert request.raw_email == (
        "From: sender@example.com\r\nSubject: Test\r\n\r\nHello"
    )


def test_email_analysis_request_rejects_empty_raw_email():
    with pytest.raises(ValidationError):
        EmailAnalysisRequest(raw_email="")


def test_email_analysis_request_rejects_missing_raw_email():
    with pytest.raises(ValidationError):
        EmailAnalysisRequest()


def test_pipeline_result_is_the_api_response_contract():
    expected_fields = {
        "email",
        "ml_phishing_probability",
        "url_analyses",
        "header_analysis",
        "attachment_analysis",
        "rule_results",
        "risk_score",
        "explainability",
    }

    assert set(PipelineResult.model_fields) == expected_fields
