from pathlib import Path

from app.models.header_models import HeaderAnalysis
from app.services.email_parser import EmailParser
from app.services.header_analyzer import HeaderAnalyzer


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"


def test_header_analyzer_returns_header_analysis_model():
    """
    Verify that header analysis returns the expected Pydantic model.
    """

    parser = EmailParser()

    email = parser.parse_file(
        RAW_DATA_DIR / "sample_authentication_headers.eml"
    )

    result = HeaderAnalyzer.analyze(email)

    assert isinstance(result, HeaderAnalysis)


def test_extracts_sender_and_return_path_domains():
    """
    Verify that sender and Return-Path domains are extracted correctly.
    """

    parser = EmailParser()

    email = parser.parse_file(
        RAW_DATA_DIR / "sample_authentication_headers.eml"
    )

    result = HeaderAnalyzer.analyze(email)

    assert result.from_present is True
    assert result.return_path_present is True

    assert result.from_domain == "example.com"
    assert result.return_path_domain == "example.com"


def test_detects_from_and_reply_to_domain_mismatch():
    """
    Verify that a differing Reply-To domain is detected descriptively.
    """

    email = parser_email(
        """
From: Security Team <security@example.com>
Reply-To: attacker@evil.example
Return-Path: <security@example.com>
Subject: Test

Hello
"""
    )

    result = HeaderAnalyzer.analyze(email)

    assert result.from_domain == "example.com"
    assert result.reply_to_domain == "evil.example"
    assert result.from_reply_to_domain_mismatch is True


def test_detects_from_and_return_path_domain_mismatch():
    """
    Verify that a differing Return-Path domain is detected descriptively.
    """

    email = parser_email(
        """
From: Security Team <security@example.com>
Return-Path: <bounce@evil.example>
Subject: Test

Hello
"""
    )

    result = HeaderAnalyzer.analyze(email)

    assert result.from_domain == "example.com"
    assert result.return_path_domain == "evil.example"
    assert result.from_return_path_domain_mismatch is True


def test_extracts_authentication_presence_and_statuses():
    """
    Verify that authentication headers are detected and their
    descriptive statuses are extracted.
    """

    parser = EmailParser()

    email = parser.parse_file(
        RAW_DATA_DIR / "sample_authentication_headers.eml"
    )

    result = HeaderAnalyzer.analyze(email)

    assert result.authentication_results_present is True
    assert result.received_spf_present is True
    assert result.dkim_signature_present is True
    assert result.arc_authentication_results_present is True
    assert result.arc_message_signature_present is True
    assert result.arc_seal_present is True

    assert result.spf_statuses == ["pass"]
    assert result.dkim_statuses == ["pass"]
    assert result.dmarc_statuses == ["pass"]


def test_counts_received_headers():
    """
    Verify that Received headers are counted from normalized headers.
    """

    email = parser_email(
        """
From: sender@example.com
Received: from mail1.example.com
Received: from mail2.example.com
Subject: Test

Hello
"""
    )

    result = HeaderAnalyzer.analyze(email)

    assert result.received_header_count == 2


def test_missing_headers_produce_safe_defaults():
    """
    Verify that missing security-relevant headers produce safe,
    descriptive defaults rather than errors.
    """

    email = parser_email(
        """
Subject: Test

Hello
"""
    )

    result = HeaderAnalyzer.analyze(email)

    assert result.from_present is False
    assert result.reply_to_present is False
    assert result.return_path_present is False

    assert result.from_domain is None
    assert result.reply_to_domain is None
    assert result.return_path_domain is None

    assert result.from_reply_to_domain_mismatch is False
    assert result.from_return_path_domain_mismatch is False

    assert result.received_header_count == 0

    assert result.authentication_results_present is False
    assert result.received_spf_present is False
    assert result.dkim_signature_present is False

    assert result.spf_statuses == []
    assert result.dkim_statuses == []
    assert result.dmarc_statuses == []


def parser_email(raw_email: str):
    """
    Parse a raw email string using the same parser used by the application.

    A temporary in-memory .eml file is avoided so these tests remain
    self-contained and do not create additional project files.
    """

    from email import policy
    from email.parser import Parser

    message = Parser(policy=policy.default).parsestr(raw_email.strip())

    return EmailParser()._build_email_data(message)