from pathlib import Path

from app.services.email_parser import EmailParser


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"


def test_extracts_multiple_attachment_metadata():
    """
    Verify that multiple attachments are extracted with
    the expected metadata.
    """

    parser = EmailParser()

    email = parser.parse_file(
        RAW_DATA_DIR / "sample_attachments.eml"
    )

    assert len(email.attachments) == 2

    first_attachment = email.attachments[0]
    second_attachment = email.attachments[1]

    assert first_attachment.filename == "security-report.pdf"
    assert first_attachment.content_type == "application/pdf"
    assert first_attachment.size_bytes == 90
    assert first_attachment.content_disposition == "attachment"

    assert second_attachment.filename == "security-findings.csv"
    assert second_attachment.content_type == "text/csv"
    assert second_attachment.size_bytes == 32
    assert second_attachment.content_disposition == "attachment"


def test_attachment_content_is_not_stored():
    """
    Verify that EmailData contains only attachment metadata
    and does not store attachment content.
    """

    parser = EmailParser()

    email = parser.parse_file(
        RAW_DATA_DIR / "sample_attachments.eml"
    )

    for attachment in email.attachments:
        assert not hasattr(attachment, "content")


def test_body_parts_are_not_treated_as_attachments():
    """
    Verify that normal plain-text and HTML body parts are
    not incorrectly classified as attachments.
    """

    parser = EmailParser()

    email = parser.parse_file(
        RAW_DATA_DIR / "sample_attachment_edge_cases.eml"
    )

    assert email.plain_text_body is not None
    assert email.html_body is not None

    assert len(email.attachments) == 3

    filenames = [
        attachment.filename
        for attachment in email.attachments
    ]

    assert "report.pdf" in filenames
    assert "unknown-file.bin" in filenames
    assert None in filenames


def test_handles_missing_attachment_filename():
    """
    Verify that an attachment without a filename is handled
    without inventing a filename.
    """

    parser = EmailParser()

    email = parser.parse_file(
        RAW_DATA_DIR / "sample_attachment_edge_cases.eml"
    )

    missing_filename_attachment = next(
        attachment
        for attachment in email.attachments
        if attachment.filename is None
    )

    assert missing_filename_attachment.filename is None
    assert missing_filename_attachment.content_type == "application/zip"
    assert missing_filename_attachment.content_disposition == "attachment"
    assert missing_filename_attachment.size_bytes == 25


def test_handles_unusual_mime_type():
    """
    Verify that a generic MIME type such as
    application/octet-stream is preserved.
    """

    parser = EmailParser()

    email = parser.parse_file(
        RAW_DATA_DIR / "sample_attachment_edge_cases.eml"
    )

    unknown_file_attachment = next(
        attachment
        for attachment in email.attachments
        if attachment.filename == "unknown-file.bin"
    )

    assert unknown_file_attachment.content_type == "application/octet-stream"
    assert unknown_file_attachment.size_bytes == 27
    assert unknown_file_attachment.content_disposition == "attachment"