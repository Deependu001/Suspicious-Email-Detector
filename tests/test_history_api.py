import pytest
from fastapi.testclient import TestClient

from app.api.dependencies import (
    get_history_service,
    get_unified_pipeline,
)
from app.main import app
from app.services.history_service import HistoryService


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


@pytest.fixture
def client(tmp_path):
    history_service = HistoryService(
        tmp_path / "history.sqlite3"
    )

    app.dependency_overrides[get_unified_pipeline] = (
        lambda: StubPipeline()
    )
    app.dependency_overrides[get_history_service] = (
        lambda: history_service
    )

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


def make_raw_email(subject="History API Test"):
    return (
        "From: sender@example.com\r\n"
        "To: recipient@example.com\r\n"
        f"Subject: {subject}\r\n"
        "\r\n"
        "This is a test message."
    )


def test_analyze_endpoint_saves_history(client):
    response = client.post(
        "/analyze",
        json={"raw_email": make_raw_email()},
    )

    assert response.status_code == 200

    # The existing analysis response contract is unchanged.
    assert set(response.json()) == {
        "email",
        "ml_phishing_probability",
        "url_analyses",
        "header_analysis",
        "attachment_analysis",
        "rule_results",
        "risk_score",
        "explainability",
    }

    history_response = client.get("/history")

    assert history_response.status_code == 200

    history = history_response.json()

    assert history["total"] == 1
    assert len(history["items"]) == 1

    record = history["items"][0]

    assert record["sender"] == "sender@example.com"
    assert record["subject"] == "History API Test"
    assert record["risk_score"] == 17.5
    assert record["ml_phishing_probability"] == 0.25
    assert "result" not in record


def test_history_record_endpoint_returns_sanitized_result(client):
    client.post(
        "/analyze",
        json={"raw_email": make_raw_email()},
    )

    history = client.get("/history").json()
    record_id = history["items"][0]["id"]

    response = client.get(f"/history/{record_id}")

    assert response.status_code == 200

    record = response.json()

    assert record["id"] == record_id
    assert record["sender"] == "sender@example.com"
    assert record["subject"] == "History API Test"
    assert record["risk_score"] == 17.5
    assert record["result"]["rule_results"] == []

    # Email bodies and complete email objects are not stored in findings.
    assert "email" not in record["result"]


def test_history_endpoint_returns_empty_list(client):
    response = client.get("/history")

    assert response.status_code == 200
    assert response.json() == {
        "items": [],
        "total": 0,
    }


def test_history_endpoint_respects_limit(client):
    for index in range(3):
        response = client.post(
            "/analyze",
            json={
                "raw_email": make_raw_email(
                    subject=f"History Test {index}"
                )
            },
        )
        assert response.status_code == 200

    response = client.get("/history?limit=2")

    assert response.status_code == 200
    assert response.json()["total"] == 3
    assert len(response.json()["items"]) == 2


@pytest.mark.parametrize(
    "limit",
    ["0", "-1", "101", "not-a-number"],
)
def test_history_endpoint_rejects_invalid_limit(client, limit):
    response = client.get(f"/history?limit={limit}")

    assert response.status_code == 422


def test_history_record_endpoint_returns_404_for_unknown_id(client):
    response = client.get("/history/missing-record")

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Analysis history record not found."
    }


def test_history_endpoints_do_not_change_root_or_health(client):
    root_response = client.get("/")
    health_response = client.get("/health")

    assert root_response.status_code == 200
    assert root_response.json()["version"] == "0.1.0"

    assert health_response.status_code == 200
    assert health_response.json() == {
        "status": "healthy"
    }
