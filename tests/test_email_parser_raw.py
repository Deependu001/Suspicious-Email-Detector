import pytest

from app.models.email_models import EmailData
from app.services.email_parser import EmailParser


def test_parse_raw_email_returns_email_data():
    raw_email = (
        "From: sender@example.com\r\n"
        "To: recipient@example.com\r\n"
        "Subject: Test Email\r\n"
        "\r\n"
        "Hello from a raw email."
    )

    email = EmailParser().parse_raw_email(raw_email)

    assert isinstance(email, EmailData)
    assert email.sender == "sender@example.com"
    assert email.recipients == ["recipient@example.com"]
    assert email.subject == "Test Email"
    assert email.plain_text_body == "Hello from a raw email."


def test_parse_raw_email_extracts_urls():
    raw_email = (
        "From: sender@example.com\r\n"
        "To: recipient@example.com\r\n"
        "Subject: URL Test\r\n"
        "\r\n"
        "Visit https://example.com/login"
    )

    email = EmailParser().parse_raw_email(raw_email)

    assert email.urls == ["https://example.com/login"]


def test_parse_raw_email_rejects_non_string_input():
    with pytest.raises(TypeError, match="raw_email must be a string"):
        EmailParser().parse_raw_email(None)


def test_parse_raw_email_rejects_empty_input():
    with pytest.raises(ValueError, match="raw_email must not be empty"):
        EmailParser().parse_raw_email("")


def test_parse_raw_email_rejects_whitespace_only_input():
    with pytest.raises(ValueError, match="raw_email must not be empty"):
        EmailParser().parse_raw_email("   \r\n   ")
