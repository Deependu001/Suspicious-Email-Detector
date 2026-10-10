import json
import sqlite3
from datetime import datetime
from pathlib import Path

import pytest

from app.services.history_service import HistoryService


@pytest.fixture
def history_service(tmp_path: Path) -> HistoryService:
    """Use an isolated SQLite database for each test."""

    return HistoryService(
        database_path=tmp_path / "history.sqlite3"
    )


def make_result(
    sender: str = "sender@example.com",
    subject: str = "Example message",
) -> dict:
    """Build a representative pipeline result."""

    return {
        "email": {
            "sender": sender,
            "subject": subject,
            "recipients": ["recipient@example.com"],
            "cc": ["copy@example.com"],
            "bcc": ["hidden@example.com"],
            "plain_text_body": "PRIVATE BODY CONTENT",
            "html_body": "<p>PRIVATE HTML CONTENT</p>",
            "normalized_plain_text_body": "NORMALIZED PRIVATE BODY",
            "normalized_html_body": "<p>NORMALIZED PRIVATE HTML</p>",
            "headers": {
                "authorization": ["PRIVATE RAW HEADER"]
            },
            "normalized_headers": {
                "authorization": ["PRIVATE NORMALIZED HEADER"]
            },
            "authentication": {
                "authentication_results": [
                    "PRIVATE AUTHENTICATION VALUE"
                ]
            },
        },
        "ml_phishing_probability": 0.35,
        "url_analyses": [
            {
                "url": "https://example.com/path",
                "is_suspicious": False,
            }
        ],
        "header_analysis": {
            "from_address": sender,
            "reply_to": "reply@example.com",
            "return_path": "bounce@example.com",
            "received_count": 2,
            "spf_status": "pass",
        },
        "attachment_analysis": {
            "attachments_found": False,
            "findings": [],
        },
        "rule_results": [
            {
                "rule_id": "TEST_RULE",
                "triggered": False,
            }
        ],
        "risk_score": 42.0,
        "explainability": {
            "summary": "Example analysis findings",
        },
    }


def test_initializes_database_and_table(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "nested" / "history.sqlite3"

    HistoryService(database_path)

    assert database_path.is_file()

    with sqlite3.connect(database_path) as connection:
        rows = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table' AND name = ?
            """,
            ("analysis_history",),
        ).fetchall()

    assert rows == [("analysis_history",)]


def test_saves_and_retrieves_analysis(
    history_service: HistoryService,
) -> None:
    saved = history_service.save_analysis(make_result())

    assert saved["id"]
    assert saved["sender"] == "sender@example.com"
    assert saved["subject"] == "Example message"
    assert saved["risk_score"] == 42.0
    assert saved["ml_phishing_probability"] == 0.35
    assert saved["result"]["rule_results"]

    retrieved = history_service.get_history_record(saved["id"])

    assert retrieved == saved


def test_record_has_utc_timestamp(
    history_service: HistoryService,
) -> None:
    saved = history_service.save_analysis(make_result())

    assert saved["analyzed_at"].endswith("Z")

    parsed = datetime.fromisoformat(
        saved["analyzed_at"].replace("Z", "+00:00")
    )

    assert parsed.utcoffset().total_seconds() == 0


def test_each_record_has_unique_id(
    history_service: HistoryService,
) -> None:
    first = history_service.save_analysis(make_result())
    second = history_service.save_analysis(make_result())

    assert first["id"] != second["id"]


def test_history_is_persistent_across_service_instances(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "history.sqlite3"

    first_service = HistoryService(database_path)
    saved = first_service.save_analysis(make_result())

    second_service = HistoryService(database_path)

    retrieved = second_service.get_history_record(saved["id"])

    assert retrieved == saved


def test_list_history_returns_summaries(
    history_service: HistoryService,
) -> None:
    first = history_service.save_analysis(
        make_result(subject="First")
    )
    second = history_service.save_analysis(
        make_result(subject="Second")
    )

    history = history_service.list_history()

    assert history["total"] == 2
    assert len(history["items"]) == 2

    returned_ids = {
        item["id"]
        for item in history["items"]
    }

    assert returned_ids == {first["id"], second["id"]}

    assert all(
        "result" not in item
        for item in history["items"]
    )


def test_list_history_respects_limit(
    history_service: HistoryService,
) -> None:
    for index in range(3):
        history_service.save_analysis(
            make_result(subject=f"Message {index}")
        )

    history = history_service.list_history(limit=2)

    assert history["total"] == 3
    assert len(history["items"]) == 2


def test_empty_history(
    history_service: HistoryService,
) -> None:
    history = history_service.list_history()

    assert history == {
        "items": [],
        "total": 0,
    }


def test_unknown_record_returns_none(
    history_service: HistoryService,
) -> None:
    assert (
        history_service.get_history_record("missing-record")
        is None
    )


@pytest.mark.parametrize(
    "limit",
    [0, -1, 101, True, 1.5, "10"],
)
def test_invalid_history_limit_is_rejected(
    history_service: HistoryService,
    limit,
) -> None:
    with pytest.raises(ValueError):
        history_service.list_history(limit=limit)


def test_sanitizes_sensitive_email_content(
    history_service: HistoryService,
) -> None:
    saved = history_service.save_analysis(make_result())

    serialized = json.dumps(saved["result"])

    assert "PRIVATE BODY CONTENT" not in serialized
    assert "PRIVATE HTML CONTENT" not in serialized
    assert "NORMALIZED PRIVATE BODY" not in serialized
    assert "NORMALIZED PRIVATE HTML" not in serialized
    assert "PRIVATE RAW HEADER" not in serialized
    assert "PRIVATE NORMALIZED HEADER" not in serialized
    assert "PRIVATE AUTHENTICATION VALUE" not in serialized
    assert "recipient@example.com" not in serialized
    assert "copy@example.com" not in serialized
    assert "hidden@example.com" not in serialized
    assert "reply@example.com" not in serialized
    assert "bounce@example.com" not in serialized

    assert "from_address" not in saved["result"]["header_analysis"]
    assert "reply_to" not in saved["result"]["header_analysis"]
    assert "return_path" not in saved["result"]["header_analysis"]

    assert saved["sender"] == "sender@example.com"
    assert saved["subject"] == "Example message"


def test_sanitizes_sensitive_url_components_in_history(
    history_service: HistoryService,
) -> None:
    result = make_result()

    result["url_analyses"] = [
        {
            "original_url": (
                "https://example.com/reset/PRIVATE_PATH_TOKEN"
                "?session=PRIVATE_QUERY_TOKEN"
                "#PRIVATE_FRAGMENT_TOKEN"
            ),
            "normalized_url": (
                "https://example.com/reset/PRIVATE_PATH_TOKEN"
                "?session=PRIVATE_QUERY_TOKEN"
                "#PRIVATE_FRAGMENT_TOKEN"
            ),
            "scheme": "https",
            "hostname": "example.com",
            "port": None,
            "path": "/reset/PRIVATE_PATH_TOKEN",
            "query": "session=PRIVATE_QUERY_TOKEN",
            "fragment": "PRIVATE_FRAGMENT_TOKEN",
            "url_length": 100,
            "has_ip_address": False,
            "has_unusual_port": False,
            "has_suspicious_characters": False,
            "has_encoding": False,
            "has_subdomain": False,
            "suspicious_indicators": [],
        }
    ]

    saved = history_service.save_analysis(result)

    serialized = json.dumps(saved["result"])

    assert "PRIVATE_PATH_TOKEN" not in serialized
    assert "PRIVATE_QUERY_TOKEN" not in serialized
    assert "PRIVATE_FRAGMENT_TOKEN" not in serialized

    saved_url = saved["result"]["url_analyses"][0]

    assert saved_url["hostname"] == "example.com"
    assert saved_url["original_url"] == (
        "https://example.com/[REDACTED]"
    )
    assert saved_url["normalized_url"] == (
        "https://example.com/[REDACTED]"
    )
    assert saved_url["path"] is None
    assert saved_url["query"] is None
    assert saved_url["fragment"] is None


def test_sanitizes_urls_embedded_in_rules_and_explanations(
    history_service: HistoryService,
) -> None:
    result = make_result()

    sensitive_url = (
        "https://example.com/reset/OBSERVATION_PATH_SECRET"
        "?session=OBSERVATION_QUERY_SECRET"
        "#OBSERVATION_FRAGMENT_SECRET"
    )

    result["rule_results"] = [
        {
            "rule_id": "URL_ENCODING",
            "description": "A URL contains encoded characters",
            "triggered": True,
            "observations": [
                f"url={sensitive_url}",
                f"Additional evidence: {sensitive_url}",
            ],
        }
    ]

    result["explainability"] = {
        "risk_score": 42.0,
        "ml_phishing_probability": 0.35,
        "explanations": [
            {
                "rule_id": "URL_ENCODING",
                "category": "URL",
                "message": "A URL contains encoded characters",
                "observations": [
                    f"url={sensitive_url}",
                    f"Observed link: {sensitive_url}",
                ],
            }
        ],
    }

    saved = history_service.save_analysis(result)

    serialized = json.dumps(saved["result"])

    assert "OBSERVATION_PATH_SECRET" not in serialized
    assert "OBSERVATION_QUERY_SECRET" not in serialized
    assert "OBSERVATION_FRAGMENT_SECRET" not in serialized

    saved_rule_observations = (
        saved["result"]["rule_results"][0]["observations"]
    )
    saved_explanation_observations = (
        saved["result"]["explainability"]["explanations"][0][
            "observations"
        ]
    )

    assert saved_rule_observations[0] == (
        "url=https://example.com/[REDACTED]"
    )
    assert saved_rule_observations[1] == (
        "Additional evidence: https://example.com/[REDACTED]"
    )
    assert saved_explanation_observations[0] == (
        "url=https://example.com/[REDACTED]"
    )
    assert saved_explanation_observations[1] == (
        "Observed link: https://example.com/[REDACTED]"
    )


def test_missing_required_analysis_fields_are_rejected(
    history_service: HistoryService,
) -> None:
    result = make_result()
    del result["risk_score"]

    with pytest.raises(ValueError, match="risk_score"):
        history_service.save_analysis(result)


@pytest.mark.parametrize(
    ("risk_score", "probability"),
    [
        (-1, 0.5),
        (101, 0.5),
        (20, -0.1),
        (20, 1.1),
    ],
)
def test_out_of_range_scores_are_rejected(
    history_service: HistoryService,
    risk_score: float,
    probability: float,
) -> None:
    result = make_result()
    result["risk_score"] = risk_score
    result["ml_phishing_probability"] = probability

    with pytest.raises(ValueError):
        history_service.save_analysis(result)


def test_non_json_analysis_data_is_rejected(
    history_service: HistoryService,
) -> None:
    result = make_result()
    result["explainability"] = {"unsupported": object()}

    with pytest.raises(ValueError, match="valid JSON"):
        history_service.save_analysis(result)