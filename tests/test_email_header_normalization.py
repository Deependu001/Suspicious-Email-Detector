from pathlib import Path

from app.services.email_parser import EmailParser


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"


def test_normalized_headers_use_lowercase_names():
    """
    Verify that normalized header names are stored in lowercase.
    """

    parser = EmailParser()

    email = parser.parse_file(
        RAW_DATA_DIR / "sample_authentication_headers.eml"
    )

    normalized_headers = email.normalized_headers

    assert "from" in normalized_headers
    assert "to" in normalized_headers
    assert "subject" in normalized_headers
    assert "authentication-results" in normalized_headers
    assert "dkim-signature" in normalized_headers
    assert "return-path" in normalized_headers


def test_normalized_headers_preserve_header_values():
    """
    Verify that normalization changes header names only and does not
    modify the original header values.
    """

    parser = EmailParser()

    email = parser.parse_file(
        RAW_DATA_DIR / "sample_authentication_headers.eml"
    )

    normalized_headers = email.normalized_headers

    assert normalized_headers["from"] == [
        "Security Team <security@example.com>"
    ]

    assert normalized_headers["subject"] == [
        "Authentication Header Test"
    ]

    assert "spf=pass" in normalized_headers[
        "authentication-results"
    ][0]

    assert "d=example.com" in normalized_headers[
        "dkim-signature"
    ][0]


def test_raw_headers_are_preserved_separately():
    """
    Verify that the original headers remain available with their
    original capitalization.
    """

    parser = EmailParser()

    email = parser.parse_file(
        RAW_DATA_DIR / "sample_authentication_headers.eml"
    )

    assert "From" in email.headers
    assert "Authentication-Results" in email.headers
    assert "DKIM-Signature" in email.headers

    assert "from" not in email.headers
    assert "authentication-results" not in email.headers
    assert "dkim-signature" not in email.headers


def test_normalized_headers_support_case_insensitive_lookup():
    """
    Verify that important headers can be accessed consistently using
    lowercase names regardless of their original capitalization.
    """

    parser = EmailParser()

    email = parser.parse_file(
        RAW_DATA_DIR / "sample_authentication_headers.eml"
    )

    normalized_headers = email.normalized_headers

    assert normalized_headers.get("from") is not None
    assert normalized_headers.get("FROM".lower()) is not None

    assert normalized_headers.get("authentication-results") is not None
    assert normalized_headers.get(
        "AUTHENTICATION-RESULTS".lower()
    ) is not None