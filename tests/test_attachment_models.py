from app.models.attachment_models import (
    AttachmentAnalysis,
    AttachmentAnalysisItem,
)


def test_attachment_analysis_defaults_to_no_attachments():
    analysis = AttachmentAnalysis()

    assert analysis.attachment_present is False
    assert analysis.attachment_count == 0
    assert analysis.attachments == []
    assert analysis.dangerous_extensions == []
    assert analysis.double_extensions == []
    assert analysis.mime_mismatches == []
    assert analysis.unusual_filenames == []


def test_attachment_analysis_item_stores_attachment_observations():
    item = AttachmentAnalysisItem(
        filename="invoice.pdf",
        extension=".pdf",
        content_type="application/pdf",
        has_filename=True,
        has_extension=True,
        is_double_extension=False,
        is_potentially_dangerous_extension=False,
        is_filename_mime_mismatch=False,
        size_bytes=1024,
    )

    assert item.filename == "invoice.pdf"
    assert item.extension == ".pdf"
    assert item.content_type == "application/pdf"
    assert item.has_filename is True
    assert item.has_extension is True
    assert item.is_double_extension is False
    assert item.is_potentially_dangerous_extension is False
    assert item.is_filename_mime_mismatch is False
    assert item.size_bytes == 1024


def test_attachment_analysis_stores_multiple_attachment_results():
    first = AttachmentAnalysisItem(
        filename="report.pdf",
        extension=".pdf",
        content_type="application/pdf",
        has_filename=True,
        has_extension=True,
        size_bytes=100,
    )

    second = AttachmentAnalysisItem(
        filename="data.csv",
        extension=".csv",
        content_type="text/csv",
        has_filename=True,
        has_extension=True,
        size_bytes=200,
    )

    analysis = AttachmentAnalysis(
        attachment_present=True,
        attachment_count=2,
        attachments=[first, second],
    )

    assert analysis.attachment_present is True
    assert analysis.attachment_count == 2
    assert len(analysis.attachments) == 2
    assert analysis.attachments[0].filename == "report.pdf"
    assert analysis.attachments[1].filename == "data.csv"


def test_attachment_analysis_stores_descriptive_indicator_lists():
    analysis = AttachmentAnalysis(
        attachment_present=True,
        attachment_count=3,
        dangerous_extensions=[".exe"],
        double_extensions=["invoice.pdf.exe"],
        mime_mismatches=["report.pdf"],
        unusual_filenames=["unknown-file"],
    )

    assert analysis.dangerous_extensions == [".exe"]
    assert analysis.double_extensions == ["invoice.pdf.exe"]
    assert analysis.mime_mismatches == ["report.pdf"]
    assert analysis.unusual_filenames == ["unknown-file"]


def test_attachment_analysis_item_supports_missing_filename():
    item = AttachmentAnalysisItem(
        filename=None,
        extension=None,
        content_type="application/zip",
        has_filename=False,
        has_extension=False,
        size_bytes=25,
    )

    assert item.filename is None
    assert item.extension is None
    assert item.content_type == "application/zip"
    assert item.has_filename is False
    assert item.has_extension is False
    assert item.size_bytes == 25