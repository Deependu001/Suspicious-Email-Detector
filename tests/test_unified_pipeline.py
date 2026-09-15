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
        plain_text_body="This is a test email.",
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
        port=None,
        has_ip_address=False,
        has_unusual_port=False,
        has_suspicious_characters=False,
        has_encoding=False,
        has_subdomain=False,
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


def create_non_triggered_rule_result() -> RuleResult:
    return RuleResult(
        rule_id="URL_ENCODING",
        description="A URL contains percent encoding",
        triggered=False,
        observations=[],
    )


def create_explainability_result(
    risk_score: float = 75.0,
    ml_phishing_probability: float = 0.9,
    rule_results: list[RuleResult] | None = None,
) -> ExplainabilityResult:
    return ExplainabilityResult(
        risk_score=risk_score,
        ml_phishing_probability=ml_phishing_probability,
        explanations=[],
    )


def build_mock_pipeline() -> UnifiedPipeline:
    return UnifiedPipeline(
        ml_inference_service=Mock(),
        url_analyzer=Mock(),
        header_analyzer=Mock(),
        attachment_analyzer=Mock(),
        rule_engine=Mock(),
        scoring_service=Mock(),
        explainability_service=Mock(),
    )


def configure_non_ml_components(
    pipeline: UnifiedPipeline,
    rule_results: list[RuleResult] | None = None,
) -> None:
    pipeline.url_analyzer.analyze.side_effect = create_url_analysis
    pipeline.header_analyzer.analyze.return_value = create_header_analysis()
    pipeline.attachment_analyzer.analyze.return_value = (
        create_attachment_analysis()
    )

    pipeline.rule_engine.evaluate.return_value = (
        rule_results if rule_results is not None else [create_rule_result()]
    )

    pipeline.scoring_service.calculate.return_value = 75.0

    pipeline.explainability_service.generate_explanation.return_value = (
        create_explainability_result()
    )


def test_pipeline_orchestrates_components_in_expected_order() -> None:
    pipeline = build_mock_pipeline()
    email = create_email()

    pipeline.ml_inference_service.predict_phishing_probability.return_value = 0.9
    configure_non_ml_components(pipeline)

    pipeline.analyze(email)

    assert pipeline.ml_inference_service.predict_phishing_probability.called
    assert pipeline.url_analyzer.analyze.call_count == 2
    pipeline.header_analyzer.analyze.assert_called_once_with(email)
    pipeline.attachment_analyzer.analyze.assert_called_once_with(email)
    pipeline.rule_engine.evaluate.assert_called_once()
    pipeline.scoring_service.calculate.assert_called_once()
    pipeline.explainability_service.generate_explanation.assert_called_once()


def test_pipeline_passes_all_urls_to_url_analyzer() -> None:
    pipeline = build_mock_pipeline()
    email = create_email()

    pipeline.ml_inference_service.predict_phishing_probability.return_value = 0.4
    configure_non_ml_components(pipeline)

    pipeline.analyze(email)

    analyzed_urls = [
        call.args[0]
        for call in pipeline.url_analyzer.analyze.call_args_list
    ]

    assert analyzed_urls == email.urls


def test_pipeline_handles_email_without_urls() -> None:
    pipeline = build_mock_pipeline()
    email = EmailData(
        sender="sender@example.com",
        recipients=["recipient@example.com"],
        subject="No URL email",
        plain_text_body="This email contains no URLs.",
        urls=[],
    )

    pipeline.ml_inference_service.predict_phishing_probability.return_value = 0.2
    configure_non_ml_components(pipeline)

    result = pipeline.analyze(email)

    pipeline.url_analyzer.analyze.assert_not_called()
    assert result.url_analyses == []


def test_pipeline_passes_rule_results_to_scoring() -> None:
    pipeline = build_mock_pipeline()
    email = create_email()

    rule_results = [create_rule_result()]

    pipeline.ml_inference_service.predict_phishing_probability.return_value = 0.8
    configure_non_ml_components(
        pipeline,
        rule_results=rule_results,
    )

    pipeline.analyze(email)

    scoring_input = pipeline.scoring_service.calculate.call_args.args[0]

    assert isinstance(scoring_input, ScoringInput)
    assert scoring_input.rule_results == rule_results


def test_pipeline_passes_score_and_detection_results_to_explainability() -> None:
    pipeline = build_mock_pipeline()
    email = create_email()

    rule_results = [create_rule_result()]

    pipeline.ml_inference_service.predict_phishing_probability.return_value = 0.8
    configure_non_ml_components(
        pipeline,
        rule_results=rule_results,
    )

    pipeline.scoring_service.calculate.return_value = 82.0
    pipeline.explainability_service.generate_explanation.return_value = (
        create_explainability_result(
            risk_score=82.0,
            ml_phishing_probability=0.8,
            rule_results=rule_results,
        )
    )

    pipeline.analyze(email)

    pipeline.explainability_service.generate_explanation.assert_called_once_with(
        risk_score=82.0,
        ml_phishing_probability=0.8,
        rule_results=rule_results,
    )


def test_pipeline_rejects_invalid_email_input() -> None:
    pipeline = build_mock_pipeline()

    with pytest.raises(TypeError, match="email must be an EmailData instance"):
        pipeline.analyze("not an email")  # type: ignore[arg-type]


def test_pipeline_returns_pipeline_result() -> None:
    pipeline = build_mock_pipeline()
    email = create_email()

    pipeline.ml_inference_service.predict_phishing_probability.return_value = 0.9
    configure_non_ml_components(pipeline)

    result = pipeline.analyze(email)

    assert result.email == email
    assert result.ml_phishing_probability == 0.9
    assert len(result.url_analyses) == 2
    assert result.header_analysis == create_header_analysis()
    assert result.attachment_analysis == create_attachment_analysis()
    assert result.rule_results == [create_rule_result()]
    assert result.risk_score == 75.0
    assert result.explainability == create_explainability_result()


def test_pipeline_passes_ml_probability_unchanged_to_scoring() -> None:
    pipeline = build_mock_pipeline()
    email = create_email()

    ml_probability = 0.731234

    pipeline.ml_inference_service.predict_phishing_probability.return_value = (
        ml_probability
    )
    configure_non_ml_components(pipeline)

    pipeline.analyze(email)

    scoring_input = pipeline.scoring_service.calculate.call_args.args[0]

    assert scoring_input.ml_phishing_probability == ml_probability


def test_pipeline_preserves_ml_probability_in_result() -> None:
    pipeline = build_mock_pipeline()
    email = create_email()

    ml_probability = 0.731234

    pipeline.ml_inference_service.predict_phishing_probability.return_value = (
        ml_probability
    )
    configure_non_ml_components(pipeline)

    result = pipeline.analyze(email)

    assert result.ml_phishing_probability == ml_probability


def test_pipeline_propagates_url_analysis_to_rule_engine() -> None:
    pipeline = build_mock_pipeline()
    email = create_email()

    pipeline.ml_inference_service.predict_phishing_probability.return_value = 0.5
    configure_non_ml_components(pipeline)

    pipeline.analyze(email)

    rule_engine_call = pipeline.rule_engine.evaluate.call_args

    assert rule_engine_call.kwargs["email"] == email
    assert rule_engine_call.kwargs["url_analyses"] == [
        create_url_analysis(email.urls[0]),
        create_url_analysis(email.urls[1]),
    ]


def test_pipeline_propagates_header_analysis_to_rule_engine_and_result() -> None:
    pipeline = build_mock_pipeline()
    email = create_email()

    header_analysis = create_header_analysis()

    pipeline.ml_inference_service.predict_phishing_probability.return_value = 0.5
    configure_non_ml_components(pipeline)
    pipeline.header_analyzer.analyze.return_value = header_analysis

    result = pipeline.analyze(email)

    rule_engine_call = pipeline.rule_engine.evaluate.call_args

    assert rule_engine_call.kwargs["header_analysis"] == header_analysis
    assert result.header_analysis == header_analysis


def test_pipeline_propagates_attachment_analysis_to_rule_engine_and_result() -> None:
    pipeline = build_mock_pipeline()
    email = create_email()

    attachment_analysis = create_attachment_analysis()

    pipeline.ml_inference_service.predict_phishing_probability.return_value = 0.5
    configure_non_ml_components(pipeline)
    pipeline.attachment_analyzer.analyze.return_value = attachment_analysis

    result = pipeline.analyze(email)

    rule_engine_call = pipeline.rule_engine.evaluate.call_args

    assert (
        rule_engine_call.kwargs["attachment_analysis"]
        == attachment_analysis
    )
    assert result.attachment_analysis == attachment_analysis


def test_pipeline_preserves_complete_rule_results_from_rule_engine() -> None:
    pipeline = build_mock_pipeline()
    email = create_email()

    rule_results = [
        create_rule_result(),
        create_non_triggered_rule_result(),
        RuleResult(
            rule_id="HEADER_SPF_FAILURE",
            description="An observed SPF authentication result is fail",
            triggered=True,
            observations=["spf_status=fail"],
        ),
    ]

    pipeline.ml_inference_service.predict_phishing_probability.return_value = 0.8
    configure_non_ml_components(
        pipeline,
        rule_results=rule_results,
    )

    result = pipeline.analyze(email)

    assert result.rule_results == rule_results
    assert len(result.rule_results) == len(rule_results)
    assert result.rule_results[0] == rule_results[0]
    assert result.rule_results[1] == rule_results[1]
    assert result.rule_results[2] == rule_results[2]


def test_pipeline_preserves_triggered_and_non_triggered_rule_results() -> None:
    pipeline = build_mock_pipeline()
    email = create_email()

    triggered_rule = create_rule_result()
    non_triggered_rule = create_non_triggered_rule_result()

    rule_results = [triggered_rule, non_triggered_rule]

    pipeline.ml_inference_service.predict_phishing_probability.return_value = 0.6
    configure_non_ml_components(
        pipeline,
        rule_results=rule_results,
    )

    result = pipeline.analyze(email)

    assert result.rule_results[0].triggered is True
    assert result.rule_results[1].triggered is False
    assert result.rule_results[0].rule_id == "URL_IP_ADDRESS"
    assert result.rule_results[1].rule_id == "URL_ENCODING"


def test_pipeline_passes_rule_results_unchanged_to_scoring_and_explainability() -> None:
    pipeline = build_mock_pipeline()
    email = create_email()

    rule_results = [
        create_rule_result(),
        create_non_triggered_rule_result(),
    ]

    ml_probability = 0.85
    risk_score = 78.5

    pipeline.ml_inference_service.predict_phishing_probability.return_value = (
        ml_probability
    )
    configure_non_ml_components(
        pipeline,
        rule_results=rule_results,
    )
    pipeline.scoring_service.calculate.return_value = risk_score
    pipeline.explainability_service.generate_explanation.return_value = (
        create_explainability_result(
            risk_score=risk_score,
            ml_phishing_probability=ml_probability,
            rule_results=rule_results,
        )
    )

    result = pipeline.analyze(email)

    scoring_input = pipeline.scoring_service.calculate.call_args.args[0]

    assert scoring_input.rule_results == rule_results

    pipeline.explainability_service.generate_explanation.assert_called_once_with(
        risk_score=risk_score,
        ml_phishing_probability=ml_probability,
        rule_results=rule_results,
    )

    explanation_call = (
        pipeline.explainability_service.generate_explanation.call_args
    )

    assert explanation_call.kwargs["rule_results"] == rule_results
    assert result.rule_results == rule_results