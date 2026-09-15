from unittest.mock import Mock

import pytest

from app.models.attachment_models import AttachmentAnalysis
from app.models.email_models import EmailData
from app.models.explainability_models import ExplainabilityResult
from app.models.header_models import HeaderAnalysis
from app.models.rule_models import RuleResult
from app.models.scoring_models import ScoringInput
from app.models.url_models import URLAnalysis
from app.services.unified_pipeline import UnifiedPipeline


def create_email() -> EmailData:
    return EmailData(
        sender="sender@example.com",
        recipients=["recipient@example.com"],
        subject="Test email",
        plain_text_body="Test body",
        urls=[
            "https://example.com/login",
            "https://192.168.1.10/login",
        ],
    )


def create_url_analysis(url: str) -> URLAnalysis:
    return URLAnalysis(
        original_url=url,
        normalized_url=url,
        scheme="https",
        hostname="example.com",
        domain="example.com",
        registered_domain="example.com",
        subdomain=None,
        tld="com",
        path="/login",
        query=None,
        fragment=None,
        url_length=len(url),
        has_ip_address=False,
        has_unusual_port=False,
        has_suspicious_characters=False,
        has_encoding=False,
        has_subdomain=False,
        suspicious_indicators=[],
    )


def create_header_analysis() -> HeaderAnalysis:
    return HeaderAnalysis()


def create_attachment_analysis() -> AttachmentAnalysis:
    return AttachmentAnalysis()


def create_rule_result() -> RuleResult:
    return RuleResult(
        rule_id="URL_IP_ADDRESS",
        description="A URL uses an IP address as its hostname",
        triggered=True,
        observations=["url=https://192.168.1.10/login"],
    )


def create_explainability_result(
    risk_score: float = 65.0,
    probability: float = 0.8,
) -> ExplainabilityResult:
    return ExplainabilityResult(
        risk_score=risk_score,
        ml_phishing_probability=probability,
        explanations=[],
    )


def build_mock_pipeline() -> tuple[
    UnifiedPipeline,
    Mock,
    Mock,
    Mock,
    Mock,
    Mock,
    Mock,
    Mock,
]:
    ml_service = Mock()
    url_analyzer = Mock()
    header_analyzer = Mock()
    attachment_analyzer = Mock()
    rule_engine = Mock()
    scoring_service = Mock()
    explainability_service = Mock()

    return (
        UnifiedPipeline(
            ml_inference_service=ml_service,
            url_analyzer=url_analyzer,
            header_analyzer=header_analyzer,
            attachment_analyzer=attachment_analyzer,
            rule_engine=rule_engine,
            scoring_service=scoring_service,
            explainability_service=explainability_service,
        ),
        ml_service,
        url_analyzer,
        header_analyzer,
        attachment_analyzer,
        rule_engine,
        scoring_service,
        explainability_service,
    )


def test_pipeline_orchestrates_components_in_expected_order():
    (
        pipeline,
        ml_service,
        url_analyzer,
        header_analyzer,
        attachment_analyzer,
        rule_engine,
        scoring_service,
        explainability_service,
    ) = build_mock_pipeline()

    email = create_email()

    url_analysis_1 = create_url_analysis(email.urls[0])
    url_analysis_2 = create_url_analysis(email.urls[1])
    header_analysis = create_header_analysis()
    attachment_analysis = create_attachment_analysis()
    rule_result = create_rule_result()
    explanation = create_explainability_result()

    ml_service.predict_phishing_probability.return_value = 0.8

    url_analyzer.analyze.side_effect = [
        url_analysis_1,
        url_analysis_2,
    ]

    header_analyzer.analyze.return_value = header_analysis
    attachment_analyzer.analyze.return_value = attachment_analysis
    rule_engine.evaluate.return_value = [rule_result]
    scoring_service.calculate.return_value = 65.0
    explainability_service.generate_explanation.return_value = explanation

    result = pipeline.analyze(email)

    ml_service.predict_phishing_probability.assert_called_once_with(
        email
    )

    assert url_analyzer.analyze.call_count == 2
    url_analyzer.analyze.assert_any_call(email.urls[0])
    url_analyzer.analyze.assert_any_call(email.urls[1])

    header_analyzer.analyze.assert_called_once_with(email)
    attachment_analyzer.analyze.assert_called_once_with(email)

    rule_engine.evaluate.assert_called_once_with(
        email=email,
        url_analyses=[url_analysis_1, url_analysis_2],
        header_analysis=header_analysis,
        attachment_analysis=attachment_analysis,
    )

    scoring_service.calculate.assert_called_once_with(
        ScoringInput(
            ml_phishing_probability=0.8,
            rule_results=[rule_result],
        )
    )

    explainability_service.generate_explanation.assert_called_once_with(
        risk_score=65.0,
        ml_phishing_probability=0.8,
        rule_results=[rule_result],
    )

    assert result.email == email
    assert result.ml_phishing_probability == 0.8
    assert result.url_analyses == [
        url_analysis_1,
        url_analysis_2,
    ]
    assert result.header_analysis == header_analysis
    assert result.attachment_analysis == attachment_analysis
    assert result.rule_results == [rule_result]
    assert result.risk_score == 65.0
    assert result.explainability == explanation


def test_pipeline_passes_all_urls_to_url_analyzer():
    (
        pipeline,
        ml_service,
        url_analyzer,
        header_analyzer,
        attachment_analyzer,
        rule_engine,
        scoring_service,
        explainability_service,
    ) = build_mock_pipeline()

    email = create_email()

    url_analyses = [
        create_url_analysis(url)
        for url in email.urls
    ]

    url_analyzer.analyze.side_effect = url_analyses

    ml_service.predict_phishing_probability.return_value = 0.2
    header_analyzer.analyze.return_value = create_header_analysis()
    attachment_analyzer.analyze.return_value = (
        create_attachment_analysis()
    )
    rule_engine.evaluate.return_value = []
    scoring_service.calculate.return_value = 20.0
    explainability_service.generate_explanation.return_value = (
        create_explainability_result(
            risk_score=20.0,
            probability=0.2,
        )
    )

    result = pipeline.analyze(email)

    assert result.url_analyses == url_analyses
    assert url_analyzer.analyze.call_count == len(email.urls)
    url_analyzer.analyze.assert_any_call(email.urls[0])
    url_analyzer.analyze.assert_any_call(email.urls[1])


def test_pipeline_handles_email_without_urls():
    (
        pipeline,
        ml_service,
        url_analyzer,
        header_analyzer,
        attachment_analyzer,
        rule_engine,
        scoring_service,
        explainability_service,
    ) = build_mock_pipeline()

    email = EmailData(
        sender="sender@example.com",
        recipients=["recipient@example.com"],
        subject="No URLs",
        plain_text_body="Normal message",
    )

    ml_service.predict_phishing_probability.return_value = 0.1

    header_analysis = create_header_analysis()
    attachment_analysis = create_attachment_analysis()
    explanation = create_explainability_result(
        risk_score=7.0,
        probability=0.1,
    )

    header_analyzer.analyze.return_value = header_analysis
    attachment_analyzer.analyze.return_value = attachment_analysis
    rule_engine.evaluate.return_value = []
    scoring_service.calculate.return_value = 7.0
    explainability_service.generate_explanation.return_value = explanation

    result = pipeline.analyze(email)

    url_analyzer.analyze.assert_not_called()

    assert result.url_analyses == []
    assert result.header_analysis == header_analysis
    assert result.attachment_analysis == attachment_analysis
    assert result.rule_results == []
    assert result.risk_score == 7.0
    assert result.explainability == explanation


def test_pipeline_passes_rule_results_to_scoring():
    (
        pipeline,
        ml_service,
        url_analyzer,
        header_analyzer,
        attachment_analyzer,
        rule_engine,
        scoring_service,
        explainability_service,
    ) = build_mock_pipeline()

    email = create_email()

    url_analyses = [
        create_url_analysis(url)
        for url in email.urls
    ]

    rule_results = [
        create_rule_result(),
        RuleResult(
            rule_id="URL_ENCODING",
            description="A URL contains percent encoding",
            triggered=False,
            observations=[],
        ),
    ]

    ml_service.predict_phishing_probability.return_value = 0.75
    url_analyzer.analyze.side_effect = url_analyses
    header_analyzer.analyze.return_value = create_header_analysis()
    attachment_analyzer.analyze.return_value = (
        create_attachment_analysis()
    )
    rule_engine.evaluate.return_value = rule_results
    scoring_service.calculate.return_value = 55.0
    explainability_service.generate_explanation.return_value = (
        create_explainability_result(
            risk_score=55.0,
            probability=0.75,
        )
    )

    pipeline.analyze(email)

    scoring_service.calculate.assert_called_once_with(
        ScoringInput(
            ml_phishing_probability=0.75,
            rule_results=rule_results,
        )
    )


def test_pipeline_passes_score_and_detection_results_to_explainability():
    (
        pipeline,
        ml_service,
        url_analyzer,
        header_analyzer,
        attachment_analyzer,
        rule_engine,
        scoring_service,
        explainability_service,
    ) = build_mock_pipeline()

    email = create_email()
    rule_results = [create_rule_result()]

    ml_service.predict_phishing_probability.return_value = 0.65

    url_analyzer.analyze.side_effect = [
        create_url_analysis(url)
        for url in email.urls
    ]

    header_analyzer.analyze.return_value = create_header_analysis()
    attachment_analyzer.analyze.return_value = (
        create_attachment_analysis()
    )
    rule_engine.evaluate.return_value = rule_results
    scoring_service.calculate.return_value = 48.0

    explanation = create_explainability_result(
        risk_score=48.0,
        probability=0.65,
    )

    explainability_service.generate_explanation.return_value = explanation

    result = pipeline.analyze(email)

    explainability_service.generate_explanation.assert_called_once_with(
        risk_score=48.0,
        ml_phishing_probability=0.65,
        rule_results=rule_results,
    )

    assert result.explainability == explanation


def test_pipeline_rejects_invalid_email_input():
    pipeline = UnifiedPipeline()

    with pytest.raises(
        TypeError,
        match="email must be an EmailData instance",
    ):
        pipeline.analyze("not-an-email")


def test_pipeline_returns_pipeline_result():
    (
        pipeline,
        ml_service,
        url_analyzer,
        header_analyzer,
        attachment_analyzer,
        rule_engine,
        scoring_service,
        explainability_service,
    ) = build_mock_pipeline()

    email = create_email()

    ml_service.predict_phishing_probability.return_value = 0.4

    url_analyzer.analyze.side_effect = [
        create_url_analysis(url)
        for url in email.urls
    ]

    header_analyzer.analyze.return_value = create_header_analysis()
    attachment_analyzer.analyze.return_value = (
        create_attachment_analysis()
    )
    rule_engine.evaluate.return_value = []
    scoring_service.calculate.return_value = 28.0
    explainability_service.generate_explanation.return_value = (
        create_explainability_result(
            risk_score=28.0,
            probability=0.4,
        )
    )

    result = pipeline.analyze(email)

    assert result.__class__.__name__ == "PipelineResult"