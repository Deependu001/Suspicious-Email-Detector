from pathlib import Path

from app.services.email_parser import EmailParser


RAW_DATA_DIR = Path("data/raw")


def test_extracts_authentication_headers():
    """
    Verify that authentication-related email headers are extracted
    into the structured authentication model.
    """

    parser = EmailParser()

    email = parser.parse_file(
        RAW_DATA_DIR / "sample_authentication_headers.eml"
    )

    authentication = email.authentication

    assert len(authentication.authentication_results) == 1
    assert len(authentication.received_spf) == 1
    assert len(authentication.dkim_signature) == 1
    assert len(authentication.arc_authentication_results) == 1
    assert len(authentication.arc_message_signature) == 1
    assert len(authentication.arc_seal) == 1


def test_authentication_header_values_are_preserved():
    """
    Verify that extracted authentication header values are preserved
    rather than being independently interpreted or modified.
    """

    parser = EmailParser()

    email = parser.parse_file(
        RAW_DATA_DIR / "sample_authentication_headers.eml"
    )

    authentication = email.authentication

    assert "spf=pass" in authentication.authentication_results[0]
    assert "dkim=pass" in authentication.authentication_results[0]
    assert "dmarc=pass" in authentication.authentication_results[0]

    assert "pass" in authentication.received_spf[0]

    assert "rsa-sha256" in authentication.dkim_signature[0]
    assert "d=example.com" in authentication.dkim_signature[0]

    assert "spf=pass" in authentication.arc_authentication_results[0]
    assert "dkim=pass" in authentication.arc_authentication_results[0]
    assert "dmarc=pass" in authentication.arc_authentication_results[0]

    assert "rsa-sha256" in authentication.arc_message_signature[0]
    assert "rsa-sha256" in authentication.arc_seal[0]


def test_missing_authentication_headers_return_empty_lists():
    """
    Verify that an email without authentication-related headers
    produces empty authentication lists rather than None values.
    """

    parser = EmailParser()

    email = parser.parse_file(
        RAW_DATA_DIR / "sample_attachments.eml"
    )

    authentication = email.authentication

    assert authentication.authentication_results == []
    assert authentication.received_spf == []
    assert authentication.dkim_signature == []
    assert authentication.arc_authentication_results == []
    assert authentication.arc_message_signature == []
    assert authentication.arc_seal == []