from app.models.email_models import EmailData
from app.models.pipeline_models import PipelineResult
from app.services.unified_pipeline import UnifiedPipeline


def create_legitimate_email() -> EmailData:
    return EmailData(
        sender="alice@example.com",
        recipients=["bob@example.com"],
        subject="Project meeting",
        plain_text_body=(
            "Hello Bob, let's meet tomorrow at 10 AM "
            "to discuss the project."
        ),
        urls=[],
    )


def create_suspicious_url_email() -> EmailData:
    return EmailData(
        sender="security@example.com",
        recipients=["user@example.com"],
        subject="Urgent account verification",
        plain_text_body=(
            "Your account requires immediate verification. "
            "Please use the following link."
        ),
        urls=[
            "https://192.168.1.10/login",
        ],
    )


def create_authentication_failure_email() -> EmailData:
    return EmailData(
        sender="sender@example.com",
        recipients=["user@example.com"],
        subject="Authentication warning",
        plain_text_body="Please review this authentication message.",
        urls=[],
        authentication={
            "received_spf": [
                (
                    "fail (example.com: domain of sender@example.com "
                    "does not designate this host as permitted sender)"
                )
            ]
        },
    )


def create_dangerous_attachment_email() -> EmailData:
    return EmailData(
        sender="sender@example.com",
        recipients=["user@example.com"],
        subject="Important document",
        plain_text_body="Please review the attached document.",
        urls=[],
        attachments=[
            {
                "filename": "invoice.exe",
                "content_type": "application/octet-stream",
                "size": 1024,
            }
        ],
    )


def create_minimal_email() -> EmailData:
    return EmailData(
        sender=None,
        recipients=[],
        subject=None,
        plain_text_body=None,
        html_body=None,
        urls=[],
        attachments=[],
    )


def create_multi_url_email() -> EmailData:
    return EmailData(
        sender="sender@example.com",
        recipients=["user@example.com"],
        subject="Multiple links",
        plain_text_body=(
            "Please review these links: "
            "https://example.com/account "
            "https://192.168.1.10/login "
            "https://sub.example.com/reset"
        ),
        urls=[
            "https://example.com/account",
            "https://192.168.1.10/login",
            "https://sub.example.com/reset",
        ],
    )


def create_multi_attachment_email() -> EmailData:
    return EmailData(
        sender="sender@example.com",
        recipients=["user@example.com"],
        subject="Multiple attachments",
        plain_text_body="Please review the attached files.",
        urls=[],
        attachments=[
            {
                "filename": "report.pdf",
                "content_type": "application/pdf",
                "size": 2048,
            },
            {
                "filename": "invoice.exe",
                "content_type": "application/octet-stream",
                "size": 1024,
            },
        ],
    )


def test_end_to_end_legitimate_email_produces_complete_pipeline_result() -> None:
    pipeline = UnifiedPipeline()
    email = create_legitimate_email()

    result = pipeline.analyze(email)

    assert isinstance(result, PipelineResult)
    assert result.email == email
    assert 0.0 <= result.ml_phishing_probability <= 1.0
    assert result.url_analyses == []
    assert result.header_analysis is not None
    assert result.attachment_analysis is not None
    assert isinstance(result.rule_results, list)
    assert 0.0 <= result.risk_score <= 100.0
    assert result.explainability is not None


def test_end_to_end_suspicious_url_flows_through_complete_pipeline() -> None:
    pipeline = UnifiedPipeline()
    email = create_suspicious_url_email()

    result = pipeline.analyze(email)

    assert isinstance(result, PipelineResult)
    assert len(result.url_analyses) == 1

    url_analysis = result.url_analyses[0]

    assert url_analysis.original_url == email.urls[0]
    assert url_analysis.has_ip_address is True

    triggered_rule_ids = {
        rule.rule_id
        for rule in result.rule_results
        if rule.triggered
    }

    assert "URL_IP_ADDRESS" in triggered_rule_ids

    explanation_rule_ids = {
        explanation.rule_id
        for explanation in result.explainability.explanations
    }

    assert "URL_IP_ADDRESS" in explanation_rule_ids


def test_end_to_end_authentication_failure_flows_through_rule_engine() -> None:
    pipeline = UnifiedPipeline()
    email = create_authentication_failure_email()

    result = pipeline.analyze(email)

    assert isinstance(result, PipelineResult)

    triggered_rule_ids = {
        rule.rule_id
        for rule in result.rule_results
        if rule.triggered
    }

    assert "HEADER_SPF_FAILURE" in triggered_rule_ids

    explanation_rule_ids = {
        explanation.rule_id
        for explanation in result.explainability.explanations
    }

    assert "HEADER_SPF_FAILURE" in explanation_rule_ids


def test_end_to_end_dangerous_attachment_flows_through_rule_engine() -> None:
    pipeline = UnifiedPipeline()
    email = create_dangerous_attachment_email()

    result = pipeline.analyze(email)

    assert isinstance(result, PipelineResult)
    assert len(result.attachment_analysis.attachments) == 1

    triggered_rule_ids = {
        rule.rule_id
        for rule in result.rule_results
        if rule.triggered
    }

    assert "ATTACHMENT_DANGEROUS_EXTENSION" in triggered_rule_ids

    explanation_rule_ids = {
        explanation.rule_id
        for explanation in result.explainability.explanations
    }

    assert "ATTACHMENT_DANGEROUS_EXTENSION" in explanation_rule_ids


def test_end_to_end_explainability_matches_pipeline_outputs() -> None:
    pipeline = UnifiedPipeline()
    email = create_suspicious_url_email()

    result = pipeline.analyze(email)

    assert result.explainability.risk_score == result.risk_score
    assert (
        result.explainability.ml_phishing_probability
        == result.ml_phishing_probability
    )


def test_end_to_end_pipeline_is_deterministic_for_same_email() -> None:
    pipeline = UnifiedPipeline()
    email = create_suspicious_url_email()

    first_result = pipeline.analyze(email)
    second_result = pipeline.analyze(email)

    assert first_result == second_result


def test_edge_case_minimal_email_produces_valid_pipeline_contract() -> None:
    pipeline = UnifiedPipeline()
    email = create_minimal_email()

    result = pipeline.analyze(email)

    assert isinstance(result, PipelineResult)
    assert result.email == email
    assert 0.0 <= result.ml_phishing_probability <= 1.0
    assert result.url_analyses == []
    assert result.header_analysis is not None
    assert result.attachment_analysis is not None
    assert isinstance(result.rule_results, list)
    assert 0.0 <= result.risk_score <= 100.0
    assert result.explainability is not None


def test_edge_case_multiple_urls_are_all_preserved_in_pipeline_result() -> None:
    pipeline = UnifiedPipeline()
    email = create_multi_url_email()

    result = pipeline.analyze(email)

    assert len(result.url_analyses) == len(email.urls)

    analyzed_urls = [
        analysis.original_url
        for analysis in result.url_analyses
    ]

    assert analyzed_urls == email.urls

    ip_url_analyses = [
        analysis
        for analysis in result.url_analyses
        if analysis.has_ip_address
    ]

    assert len(ip_url_analyses) == 1
    assert ip_url_analyses[0].original_url == (
        "https://192.168.1.10/login"
    )


def test_edge_case_multiple_attachments_are_all_preserved() -> None:
    pipeline = UnifiedPipeline()
    email = create_multi_attachment_email()

    result = pipeline.analyze(email)

    assert len(result.attachment_analysis.attachments) == 2

    analyzed_filenames = [
        attachment.filename
        for attachment in result.attachment_analysis.attachments
    ]

    assert analyzed_filenames == [
        "report.pdf",
        "invoice.exe",
    ]

    triggered_rule_ids = {
        rule.rule_id
        for rule in result.rule_results
        if rule.triggered
    }

    assert "ATTACHMENT_DANGEROUS_EXTENSION" in triggered_rule_ids


def test_edge_case_pipeline_result_components_remain_consistent() -> None:
    pipeline = UnifiedPipeline()
    email = create_multi_url_email()

    result = pipeline.analyze(email)

    assert result.email == email
    assert len(result.url_analyses) == len(email.urls)

    assert result.explainability.risk_score == result.risk_score
    assert (
        result.explainability.ml_phishing_probability
        == result.ml_phishing_probability
    )

    assert 0.0 <= result.ml_phishing_probability <= 1.0
    assert 0.0 <= result.risk_score <= 100.0

    assert all(
        isinstance(rule.triggered, bool)
        for rule in result.rule_results
    )

    assert all(
        explanation.rule_id
        for explanation in result.explainability.explanations
    )


def test_edge_case_pipeline_is_deterministic_for_minimal_email() -> None:
    pipeline = UnifiedPipeline()
    email = create_minimal_email()

    first_result = pipeline.analyze(email)
    second_result = pipeline.analyze(email)

    assert first_result == second_result
