from pathlib import Path

from app.models.email_models import EmailAttachment, EmailData
from app.services.attachment_analyzer import AttachmentAnalyzer
from app.services.email_parser import EmailParser


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"


def test_analyze_email_without_attachments():
    email = EmailData()

    analysis = AttachmentAnalyzer.analyze(email)

    assert analysis.attachment_present is False
    assert analysis.attachment_count == 0
    assert analysis.attachments == []
    assert analysis.dangerous_extensions == []
    assert analysis.double_extensions == []
    assert analysis.mime_mismatches == []
    assert analysis.unusual_filenames == []


def test_analyze_existing_attachment_metadata():
    parser = EmailParser()

    email = parser.parse_file(
        RAW_DATA_DIR / "sample_attachments.eml"
    )

    analysis = AttachmentAnalyzer.analyze(email)

    assert analysis.attachment_present is True
    assert analysis.attachment_count == 2
    assert len(analysis.attachments) == 2

    first = analysis.attachments[0]
    second = analysis.attachments[1]

    assert first.filename == "security-report.pdf"
    assert first.extension == ".pdf"
    assert first.content_type == "application/pdf"
    assert first.has_filename is True
    assert first.has_extension is True
    assert first.is_double_extension is False
    assert first.is_potentially_dangerous_extension is False
    assert first.is_filename_mime_mismatch is False
    assert first.size_bytes == 90

    assert second.filename == "security-findings.csv"
    assert second.extension == ".csv"
    assert second.content_type == "text/csv"
    assert second.has_filename is True
    assert second.has_extension is True
    assert second.is_double_extension is False
    assert second.is_potentially_dangerous_extension is False
    assert second.is_filename_mime_mismatch is False
    assert second.size_bytes == 32


def test_detects_potentially_dangerous_extension():
    email = EmailData(
        attachments=[
            EmailAttachment(
                filename="invoice.exe",
                content_type="application/octet-stream",
                size_bytes=100,
                content_disposition="attachment",
            )
        ]
    )

    analysis = AttachmentAnalyzer.analyze(email)

    item = analysis.attachments[0]

    assert item.extension == ".exe"
    assert item.is_potentially_dangerous_extension is True
    assert analysis.dangerous_extensions == [".exe"]


def test_detects_double_extension():
    email = EmailData(
        attachments=[
            EmailAttachment(
                filename="invoice.pdf.exe",
                content_type="application/octet-stream",
                size_bytes=100,
                content_disposition="attachment",
            )
        ]
    )

    analysis = AttachmentAnalyzer.analyze(email)

    item = analysis.attachments[0]

    assert item.extension == ".exe"
    assert item.is_double_extension is True
    assert analysis.double_extensions == ["invoice.pdf.exe"]


def test_detects_filename_mime_mismatch():
    email = EmailData(
        attachments=[
            EmailAttachment(
                filename="report.pdf",
                content_type="text/plain",
                size_bytes=100,
                content_disposition="attachment",
            )
        ]
    )

    analysis = AttachmentAnalyzer.analyze(email)

    item = analysis.attachments[0]

    assert item.extension == ".pdf"
    assert item.is_filename_mime_mismatch is True
    assert analysis.mime_mismatches == ["report.pdf"]


def test_does_not_flag_matching_filename_mime_pair():
    email = EmailData(
        attachments=[
            EmailAttachment(
                filename="report.pdf",
                content_type="application/pdf",
                size_bytes=100,
                content_disposition="attachment",
            )
        ]
    )

    analysis = AttachmentAnalyzer.analyze(email)

    item = analysis.attachments[0]

    assert item.is_filename_mime_mismatch is False
    assert analysis.mime_mismatches == []


def test_handles_missing_filename():
    email = EmailData(
        attachments=[
            EmailAttachment(
                filename=None,
                content_type="application/zip",
                size_bytes=25,
                content_disposition="attachment",
            )
        ]
    )

    analysis = AttachmentAnalyzer.analyze(email)

    item = analysis.attachments[0]

    assert item.filename is None
    assert item.extension is None
    assert item.has_filename is False
    assert item.has_extension is False
    assert item.is_double_extension is False
    assert item.is_potentially_dangerous_extension is False
    assert item.is_filename_mime_mismatch is False

    assert analysis.unusual_filenames == [""]


def test_unknown_extension_and_mime_are_not_flagged_as_mismatch():
    email = EmailData(
        attachments=[
            EmailAttachment(
                filename="archive.xyz",
                content_type="application/octet-stream",
                size_bytes=100,
                content_disposition="attachment",
            )
        ]
    )

    analysis = AttachmentAnalyzer.analyze(email)

    item = analysis.attachments[0]

    assert item.extension == ".xyz"
    assert item.is_filename_mime_mismatch is False
    assert analysis.mime_mismatches == []


def test_analyzer_rejects_invalid_input():
    try:
        AttachmentAnalyzer.analyze("not an email")
        assert False, "Expected TypeError"
    except TypeError as exc:
        assert str(exc) == "email must be an EmailData instance."