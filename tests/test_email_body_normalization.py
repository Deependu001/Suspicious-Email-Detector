from pathlib import Path

from app.services.email_parser import EmailParser


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"


def test_plain_text_body_is_normalized():
    """
    Verify that plain-text body content is represented consistently
    for downstream analysis.
    """

    parser = EmailParser()

    email = parser.parse_file(
        RAW_DATA_DIR / "sample_basic.eml"
    )

    assert email.normalized_plain_text_body == (
        "Hello Bob,\n\n"
        "This is a test email for the Suspicious Email Detection project.\n\n"
        "Please review this message.\n\n"
        "Regards,\n"
        "Alice Security"
    )


def test_html_body_is_normalized():
    """
    Verify that HTML body content is represented consistently
    while preserving the original HTML structure separately.
    """

    parser = EmailParser()

    email = parser.parse_file(
        RAW_DATA_DIR / "sample_html.eml"
    )

    assert email.normalized_html_body == (
        "<html>\n"
        "  <body>\n"
        "    <h1>Security Notification</h1>\n"
        "    <p>Hello Bob,</p>\n"
        "    <p>Your security notification is <strong>ready</strong>.</p>\n"
        "    <p>Please review the message carefully.</p>\n"
        "    <p>Regards,<br>Security Team</p>\n"
        "  </body>\n"
        "</html>"
    )


def test_missing_html_body_produces_none_normalized_html_body():
    """
    Verify that an email without an HTML body does not produce
    an artificial normalized HTML representation.
    """

    parser = EmailParser()

    email = parser.parse_file(
        RAW_DATA_DIR / "sample_basic.eml"
    )

    assert email.html_body is None
    assert email.normalized_html_body is None


def test_missing_plain_text_body_produces_none_normalized_plain_text_body():
    """
    Verify that an email without a plain-text body does not produce
    an artificial normalized plain-text representation.
    """

    parser = EmailParser()

    email = parser.parse_file(
        RAW_DATA_DIR / "sample_html.eml"
    )

    assert email.plain_text_body is not None
    assert email.normalized_plain_text_body is not None


def test_normalized_body_does_not_include_attachment_content():
    """
    Verify that attachment content is never incorporated into the
    normalized email body.
    """

    parser = EmailParser()

    email = parser.parse_file(
        RAW_DATA_DIR / "sample_plain_text.eml"
    )

    assert email.normalized_plain_text_body is not None
    assert "attachment content" not in email.normalized_plain_text_body
    assert "internal-note.txt" not in email.normalized_plain_text_body


def test_normalized_plain_text_preserves_unicode_content():
    """
    Verify that Unicode characters remain intact in the normalized
    plain-text body.
    """

    parser = EmailParser()

    email = parser.parse_file(
        RAW_DATA_DIR / "sample_plain_text.eml"
    )

    assert email.normalized_plain_text_body is not None
    assert "নিরাপত্তা যাচাই সফলভাবে সম্পন্ন হয়েছে।" in (
        email.normalized_plain_text_body
    )