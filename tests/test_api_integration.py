from fastapi.testclient import TestClient

from app.api.dependencies import get_unified_pipeline
from app.main import app
from app.models.email_models import EmailData


class IntegrationPipelineStub:
    """Test double that records the parsed email received from FastAPI."""

    def __init__(self):
        self.received_email = None

    def analyze(self, email):
        self.received_email = email

        return {
            "email": email,
            "ml_phishing_probability": 0.10,
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
            "risk_score": 7.0,
            "explainability": {
                "risk_score": 7.0,
                "ml_phishing_probability": 0.10,
                "explanations": [],
            },
        }


def create_client_with_stub():
    """Create a TestClient using the integration pipeline stub."""

    pipeline = IntegrationPipelineStub()

    app.dependency_overrides.clear()
    app.dependency_overrides[get_unified_pipeline] = lambda: pipeline

    return TestClient(app), pipeline


def clear_dependency_overrides():
    """Restore the application's normal dependency configuration."""

    app.dependency_overrides.clear()


def test_analyze_endpoint_integrates_request_parser_and_pipeline():
    client, pipeline = create_client_with_stub()

    try:
        raw_email = (
            "From: sender@example.com\r\n"
            "To: recipient@example.com\r\n"
            "Subject: Integration Test\r\n"
            "Message-ID: <integration@example.com>\r\n"
            "\r\n"
            "This is an integration test email."
        )

        response = client.post(
            "/analyze",
            json={"raw_email": raw_email},
        )
    finally:
        clear_dependency_overrides()

    assert response.status_code == 200
    assert pipeline.received_email is not None
    assert isinstance(pipeline.received_email, EmailData)

    assert pipeline.received_email.sender == "sender@example.com"
    assert pipeline.received_email.subject == "Integration Test"
    assert pipeline.received_email.message_id == "<integration@example.com>"
    assert pipeline.received_email.plain_text_body == (
        "This is an integration test email."
    )


def test_analyze_endpoint_returns_pipeline_result_through_response_model():
    client, _ = create_client_with_stub()

    try:
        raw_email = (
            "From: sender@example.com\r\n"
            "To: recipient@example.com\r\n"
            "Subject: Response Model Test\r\n"
            "\r\n"
            "Testing response serialization."
        )

        response = client.post(
            "/analyze",
            json={"raw_email": raw_email},
        )
    finally:
        clear_dependency_overrides()

    assert response.status_code == 200

    data = response.json()

    assert data["email"]["sender"] == "sender@example.com"
    assert data["email"]["subject"] == "Response Model Test"
    assert data["ml_phishing_probability"] == 0.10
    assert data["risk_score"] == 7.0

    assert data["url_analyses"] == []
    assert data["rule_results"] == []

    assert data["explainability"] == {
        "risk_score": 7.0,
        "ml_phishing_probability": 0.10,
        "explanations": [],
    }


def test_analyze_endpoint_accepts_multiline_raw_email():
    client, pipeline = create_client_with_stub()

    try:
        raw_email = (
            "From: sender@example.com\r\n"
            "To: recipient@example.com\r\n"
            "Subject: Multiline Test\r\n"
            "\r\n"
            "First line.\r\n"
            "Second line.\r\n"
            "Third line."
        )

        response = client.post(
            "/analyze",
            json={"raw_email": raw_email},
        )
    finally:
        clear_dependency_overrides()

    assert response.status_code == 200
    assert pipeline.received_email is not None
    assert pipeline.received_email.plain_text_body == (
        "First line.\r\n"
        "Second line.\r\n"
        "Third line."
    )


def test_analyze_endpoint_accepts_unicode_email_content():
    client, pipeline = create_client_with_stub()

    try:
        raw_email = (
            "From: sender@example.com\r\n"
            "To: recipient@example.com\r\n"
            "Subject: Unicode Test\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Hello from India — नमस्ते — café — 日本語"
        )

        response = client.post(
            "/analyze",
            json={"raw_email": raw_email},
        )
    finally:
        clear_dependency_overrides()

    assert response.status_code == 200
    assert pipeline.received_email is not None
    assert pipeline.received_email.subject == "Unicode Test"
    assert pipeline.received_email.plain_text_body == (
        "Hello from India — नमस्ते — café — 日本語"
    )


def test_analyze_endpoint_accepts_header_only_email():
    client, pipeline = create_client_with_stub()

    try:
        raw_email = (
            "From: sender@example.com\r\n"
            "To: recipient@example.com\r\n"
            "Subject: Header Only\r\n"
            "\r\n"
        )

        response = client.post(
            "/analyze",
            json={"raw_email": raw_email},
        )
    finally:
        clear_dependency_overrides()

    assert response.status_code == 200
    assert pipeline.received_email is not None
    assert pipeline.received_email.sender == "sender@example.com"
    assert pipeline.received_email.subject == "Header Only"


def test_analyze_endpoint_accepts_multiple_recipients():
    client, pipeline = create_client_with_stub()

    try:
        raw_email = (
            "From: sender@example.com\r\n"
            "To: first@example.com, second@example.com\r\n"
            "Cc: third@example.com\r\n"
            "Subject: Multiple Recipients\r\n"
            "\r\n"
            "Multiple recipient test."
        )

        response = client.post(
            "/analyze",
            json={"raw_email": raw_email},
        )
    finally:
        clear_dependency_overrides()

    assert response.status_code == 200
    assert pipeline.received_email is not None
    assert pipeline.received_email.recipients == [
        "first@example.com",
        "second@example.com",
    ]
    assert pipeline.received_email.cc == ["third@example.com"]


def test_analyze_endpoint_accepts_email_containing_url():
    client, pipeline = create_client_with_stub()

    try:
        raw_email = (
            "From: sender@example.com\r\n"
            "To: recipient@example.com\r\n"
            "Subject: URL Test\r\n"
            "\r\n"
            "Visit https://example.com/account for more information."
        )

        response = client.post(
            "/analyze",
            json={"raw_email": raw_email},
        )
    finally:
        clear_dependency_overrides()

    assert response.status_code == 200
    assert pipeline.received_email is not None
    assert "https://example.com/account" in pipeline.received_email.urls


def test_analyze_endpoint_rejects_missing_request_body():
    client = TestClient(app)

    response = client.post("/analyze")

    assert response.status_code == 422


def test_analyze_endpoint_rejects_empty_json_object():
    client = TestClient(app)

    response = client.post(
        "/analyze",
        json={},
    )

    assert response.status_code == 422


def test_analyze_endpoint_rejects_non_object_json_body():
    client = TestClient(app)

    response = client.post(
        "/analyze",
        json=["not", "an", "object"],
    )

    assert response.status_code == 422


def test_analyze_endpoint_rejects_null_raw_email():
    client = TestClient(app)

    response = client.post(
        "/analyze",
        json={"raw_email": None},
    )

    assert response.status_code == 422