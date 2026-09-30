from fastapi.testclient import TestClient

from app.api.dependencies import get_unified_pipeline
from app.main import app
from app.models.pipeline_models import PipelineResult


class StubPipeline:
    def analyze(self, email):
        return {
            "email": email,
            "ml_phishing_probability": 0.25,
            "url_analyses": [],
            "header_analysis": {
                "from_present": True,
                "reply_to_present": False,
                "return_path_present": False,
                "from_domain": "example.com",
                "reply_to_domain": None,
                "return_path_domain": None,
                "from_reply_to_domain_mismatch": False,
                "from_return_path_domain_mismatch": False,
                "received_header_count": 0,
                "authentication_results_present": False,
                "received_spf_present": False,
                "dkim_signature_present": False,
                "arc_authentication_results_present": False,
                "arc_message_signature_present": False,
                "arc_seal_present": False,
                "spf_statuses": [],
                "dkim_statuses": [],
                "dmarc_statuses": [],
            },
            "attachment_analysis": {
                "attachment_present": False,
                "attachment_count": 0,
                "attachments": [],
                "dangerous_extensions": [],
                "double_extensions": [],
                "mime_mismatches": [],
                "unusual_filenames": [],
            },
            "rule_results": [],
            "risk_score": 17.5,
            "explainability": {
                "risk_score": 17.5,
                "ml_phishing_probability": 0.25,
                "explanations": [],
            },
        }


def test_analyze_endpoint_returns_pipeline_result():
    app.dependency_overrides.clear()
    app.dependency_overrides[get_unified_pipeline] = lambda: StubPipeline()

    client = TestClient(app)

    raw_email = (
        "From: sender@example.com\r\n"
        "To: recipient@example.com\r\n"
        "Subject: API Test\r\n"
        "\r\n"
        "Hello from the API."
    )

    response = client.post(
        "/analyze",
        json={"raw_email": raw_email},
    )

    app.dependency_overrides.clear()

    assert response.status_code == 200

    result = PipelineResult.model_validate(response.json())

    assert result.email.sender == "sender@example.com"
    assert result.email.subject == "API Test"
    assert result.ml_phishing_probability == 0.25
    assert result.risk_score == 17.5


def test_analyze_endpoint_requires_raw_email():
    client = TestClient(app)

    response = client.post(
        "/analyze",
        json={},
    )

    assert response.status_code == 422


def test_analyze_endpoint_rejects_empty_raw_email():
    client = TestClient(app)

    response = client.post(
        "/analyze",
        json={"raw_email": ""},
    )

    assert response.status_code == 422


def test_analyze_endpoint_rejects_whitespace_only_raw_email():
    client = TestClient(app)

    response = client.post(
        "/analyze",
        json={"raw_email": "   \r\n\t"},
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": "raw_email must not be empty."
    }


def test_analyze_endpoint_rejects_invalid_json_field_type():
    client = TestClient(app)

    response = client.post(
        "/analyze",
        json={"raw_email": 12345},
    )

    assert response.status_code == 422


def test_analyze_endpoint_serializes_complete_pipeline_result():
    app.dependency_overrides.clear()
    app.dependency_overrides[get_unified_pipeline] = lambda: StubPipeline()

    client = TestClient(app)

    raw_email = (
        "From: sender@example.com\r\n"
        "To: recipient@example.com\r\n"
        "Subject: API Test\r\n"
        "\r\n"
        "Hello from the API."
    )

    response = client.post(
        "/analyze",
        json={"raw_email": raw_email},
    )

    app.dependency_overrides.clear()

    assert response.status_code == 200

    data = response.json()

    assert set(data) == {
        "email",
        "ml_phishing_probability",
        "url_analyses",
        "header_analysis",
        "attachment_analysis",
        "rule_results",
        "risk_score",
        "explainability",
    }

    assert data["url_analyses"] == []

    assert set(data["header_analysis"]) == {
        "from_present",
        "reply_to_present",
        "return_path_present",
        "from_domain",
        "reply_to_domain",
        "return_path_domain",
        "from_reply_to_domain_mismatch",
        "from_return_path_domain_mismatch",
        "received_header_count",
        "authentication_results_present",
        "received_spf_present",
        "dkim_signature_present",
        "arc_authentication_results_present",
        "arc_message_signature_present",
        "arc_seal_present",
        "spf_statuses",
        "dkim_statuses",
        "dmarc_statuses",
    }

    assert data["header_analysis"]["from_present"] is True
    assert data["header_analysis"]["reply_to_present"] is False
    assert data["header_analysis"]["return_path_present"] is False
    assert data["header_analysis"]["from_domain"] == "example.com"
    assert data["header_analysis"]["reply_to_domain"] is None
    assert data["header_analysis"]["return_path_domain"] is None
    assert data["header_analysis"]["from_reply_to_domain_mismatch"] is False
    assert data["header_analysis"]["from_return_path_domain_mismatch"] is False
    assert data["header_analysis"]["received_header_count"] == 0
    assert data["header_analysis"]["authentication_results_present"] is False
    assert data["header_analysis"]["received_spf_present"] is False
    assert data["header_analysis"]["dkim_signature_present"] is False
    assert data["header_analysis"]["arc_authentication_results_present"] is False
    assert data["header_analysis"]["arc_message_signature_present"] is False
    assert data["header_analysis"]["arc_seal_present"] is False
    assert data["header_analysis"]["spf_statuses"] == []
    assert data["header_analysis"]["dkim_statuses"] == []
    assert data["header_analysis"]["dmarc_statuses"] == []

    assert set(data["attachment_analysis"]) == {
        "attachment_present",
        "attachment_count",
        "attachments",
        "dangerous_extensions",
        "double_extensions",
        "mime_mismatches",
        "unusual_filenames",
    }

    assert data["attachment_analysis"]["attachment_present"] is False
    assert data["attachment_analysis"]["attachment_count"] == 0
    assert data["attachment_analysis"]["attachments"] == []
    assert data["attachment_analysis"]["dangerous_extensions"] == []
    assert data["attachment_analysis"]["double_extensions"] == []
    assert data["attachment_analysis"]["mime_mismatches"] == []
    assert data["attachment_analysis"]["unusual_filenames"] == []

    assert data["rule_results"] == []

    assert set(data["explainability"]) == {
        "risk_score",
        "ml_phishing_probability",
        "explanations",
    }

    assert data["explainability"]["risk_score"] == 17.5
    assert data["explainability"]["ml_phishing_probability"] == 0.25
    assert data["explainability"]["explanations"] == []


def test_root_endpoint_still_works():
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
        "message": "Suspicious Email Detection API is running",
        "status": "healthy",
        "version": "0.1.0",
    }


def test_health_endpoint_still_works():
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy"
    }