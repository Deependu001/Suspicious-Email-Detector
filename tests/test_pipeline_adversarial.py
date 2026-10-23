from app.models.email_models import EmailData
from app.services.unified_pipeline import UnifiedPipeline


def test_malformed_url_does_not_abort_email_analysis() -> None:
    email = EmailData(
        sender="sender@example.com",
        recipients=["recipient@example.com"],
        subject="Review these links",
        plain_text_body="Please review the links in this message.",
        urls=[
            "http://[",
            "https://192.168.1.10/login",
            "https://example.com/login",
        ],
    )

    result = UnifiedPipeline().analyze(email)

    assert len(result.url_analyses) == len(email.urls)

    assert [
        analysis.original_url
        for analysis in result.url_analyses
    ] == email.urls

    assert (
        "invalid_url_syntax"
        in result.url_analyses[0].suspicious_indicators
    )

    assert result.url_analyses[1].has_ip_address is True
    assert result.url_analyses[2].hostname == "example.com"

    assert result.header_analysis is not None
    assert result.attachment_analysis is not None
    assert result.risk_score is not None
    assert result.explainability is not None
