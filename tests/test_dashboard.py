import importlib.util
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests


DASHBOARD_PATH = (
    Path(__file__).resolve().parents[1] / "dashboard" / "app.py"
)

spec = importlib.util.spec_from_file_location(
    "dashboard_app",
    DASHBOARD_PATH,
)

dashboard_app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dashboard_app)


@pytest.fixture
def mock_post(monkeypatch):
    """Replace HTTP requests with a controllable mock."""
    post = Mock()
    monkeypatch.setattr(dashboard_app.requests, "post", post)
    return post


def test_empty_api_url_does_not_send_request(mock_post):
    result, error = dashboard_app.analyze_email(
        "   ",
        "From: sender@example.com\n\nHello",
    )

    assert result is None
    assert error == "FastAPI Base URL cannot be empty."
    mock_post.assert_not_called()


def test_empty_email_does_not_send_request(mock_post):
    result, error = dashboard_app.analyze_email(
        "http://127.0.0.1:8000",
        "  \n ",
    )

    assert result is None
    assert error == "Please enter a raw email before analyzing."
    mock_post.assert_not_called()


def test_invalid_url_error(mock_post):
    mock_post.side_effect = requests.exceptions.InvalidURL(
        "Invalid URL"
    )

    result, error = dashboard_app.analyze_email(
        "not-a-valid-url",
        "From: sender@example.com\n\nHello",
    )

    assert result is None
    assert error == "The FastAPI Base URL is invalid."


def test_timeout_error(mock_post):
    mock_post.side_effect = requests.exceptions.Timeout()

    result, error = dashboard_app.analyze_email(
        "http://127.0.0.1:8000",
        "From: sender@example.com\n\nHello",
    )

    assert result is None
    assert "did not respond within 60 seconds" in error


def test_connection_error(mock_post):
    mock_post.side_effect = requests.exceptions.ConnectionError()

    result, error = dashboard_app.analyze_email(
        "http://127.0.0.1:8000",
        "From: sender@example.com\n\nHello",
    )

    assert result is None
    assert "Unable to connect to the FastAPI backend" in error


def test_generic_request_error(mock_post):
    mock_post.side_effect = requests.exceptions.RequestException(
        "Unexpected request failure"
    )

    result, error = dashboard_app.analyze_email(
        "http://127.0.0.1:8000",
        "From: sender@example.com\n\nHello",
    )

    assert result is None
    assert "Unable to contact the FastAPI backend" in error
    assert "Unexpected request failure" in error


def test_http_error_uses_json_detail(mock_post):
    response = Mock()
    response.ok = False
    response.status_code = 422
    response.json.return_value = {
        "detail": "Invalid email input"
    }
    response.text = "Unprocessable Entity"
    mock_post.return_value = response

    result, error = dashboard_app.analyze_email(
        "http://127.0.0.1:8000",
        "From: sender@example.com\n\nHello",
    )

    assert result is None
    assert error == "Analysis failed (HTTP 422): Invalid email input"


def test_http_error_uses_text_when_json_is_invalid(mock_post):
    response = Mock()
    response.ok = False
    response.status_code = 500
    response.json.side_effect = ValueError("Invalid JSON")
    response.text = "Internal Server Error"
    mock_post.return_value = response

    result, error = dashboard_app.analyze_email(
        "http://127.0.0.1:8000",
        "From: sender@example.com\n\nHello",
    )

    assert result is None
    assert (
        error
        == "Analysis failed (HTTP 500): Internal Server Error"
    )


def test_http_error_without_detail_or_text(mock_post):
    response = Mock()
    response.ok = False
    response.status_code = 503
    response.json.return_value = {}
    response.text = ""
    mock_post.return_value = response

    result, error = dashboard_app.analyze_email(
        "http://127.0.0.1:8000",
        "From: sender@example.com\n\nHello",
    )

    assert result is None
    assert error == (
        "Analysis failed (HTTP 503): The API returned an error."
    )


def test_invalid_json_response(mock_post):
    response = Mock()
    response.ok = True
    response.json.side_effect = ValueError("Invalid JSON")
    mock_post.return_value = response

    result, error = dashboard_app.analyze_email(
        "http://127.0.0.1:8000",
        "From: sender@example.com\n\nHello",
    )

    assert result is None
    assert error == (
        "The FastAPI backend returned an invalid JSON response."
    )


@pytest.mark.parametrize(
    "payload",
    [
        [],
        ["unexpected"],
        "unexpected",
        123,
        None,
    ],
)
def test_unexpected_response_format(mock_post, payload):
    response = Mock()
    response.ok = True
    response.json.return_value = payload
    mock_post.return_value = response

    result, error = dashboard_app.analyze_email(
        "http://127.0.0.1:8000",
        "From: sender@example.com\n\nHello",
    )

    assert result is None
    assert error == (
        "The FastAPI backend returned an unexpected response format."
    )


def test_successful_analysis(mock_post):
    expected_result = {
        "risk_score": 42.0,
        "ml_phishing_probability": 0.35,
        "rule_results": [],
    }

    response = Mock()
    response.ok = True
    response.json.return_value = expected_result
    mock_post.return_value = response

    raw_email = "From: sender@example.com\n\nHello"

    result, error = dashboard_app.analyze_email(
        "http://127.0.0.1:8000",
        raw_email,
    )

    assert result == expected_result
    assert error is None

    mock_post.assert_called_once_with(
        "http://127.0.0.1:8000/analyze",
        json={"raw_email": raw_email},
        timeout=60,
    )


def test_trailing_slash_is_removed_from_api_url(mock_post):
    response = Mock()
    response.ok = True
    response.json.return_value = {"risk_score": 10.0}
    mock_post.return_value = response

    dashboard_app.analyze_email(
        "http://127.0.0.1:8000///",
        "From: sender@example.com\n\nHello",
    )

    assert mock_post.call_args.args[0] == (
        "http://127.0.0.1:8000/analyze"
    )