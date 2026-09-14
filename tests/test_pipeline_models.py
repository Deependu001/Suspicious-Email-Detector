from app.models.attachment_models import AttachmentAnalysis
from app.models.email_models import EmailData
from app.models.explainability_models import ExplainabilityResult
from app.models.header_models import HeaderAnalysis
from app.models.pipeline_models import PipelineResult
from app.models.rule_models import RuleResult
from app.models.url_models import URLAnalysis


def create_email() -> EmailData:
    return EmailData(
        sender="sender@example.com",
        recipients=["recipient@example.com"],
        subject="Test email",
        plain_text_body="Test body",
    )


def create_header_analysis() -> HeaderAnalysis:
    return HeaderAnalysis()


def create_attachment_analysis() -> AttachmentAnalysis:
    return AttachmentAnalysis()


def create_explainability_result() -> ExplainabilityResult:
    return ExplainabilityResult(
        risk_score=50.0,
        ml_phishing_probability=0.5,
        explanations=[],
    )


def test_pipeline_result_accepts_complete_contract():
    url_analysis = URLAnalysis(
        original_url="https://example.com",
        normalized_url="https://example.com",
        scheme="https",
        hostname="example.com",
        domain="example.com",
        registered_domain="example.com",
        tld="com",
        path="",
        query="",
        fragment="",
        url_length=19,
    )

    rule_result = RuleResult(
        rule_id="URL_IP_ADDRESS",
        description="URL uses an IP address.",
        triggered=True,
        observations=["host=192.168.1.10"],
    )

    result = PipelineResult(
        email=create_email(),
        ml_phishing_probability=0.8,
        url_analyses=[url_analysis],
        header_analysis=create_header_analysis(),
        attachment_analysis=create_attachment_analysis(),
        rule_results=[rule_result],
        risk_score=65.6,
        explainability=create_explainability_result(),
    )

    assert result.email.sender == "sender@example.com"
    assert result.ml_phishing_probability == 0.8
    assert result.url_analyses == [url_analysis]
    assert result.header_analysis == create_header_analysis()
    assert result.attachment_analysis == create_attachment_analysis()
    assert result.rule_results == [rule_result]
    assert result.risk_score == 65.6
    assert result.explainability == create_explainability_result()


def test_pipeline_result_defaults_empty_collections():
    result = PipelineResult(
        email=create_email(),
        ml_phishing_probability=0.2,
        header_analysis=create_header_analysis(),
        attachment_analysis=create_attachment_analysis(),
        risk_score=14.0,
        explainability=create_explainability_result(),
    )

    assert result.url_analyses == []
    assert result.rule_results == []


def test_pipeline_result_preserves_nested_component_results():
    url_analysis = URLAnalysis(
        original_url="https://example.com/login",
        normalized_url="https://example.com/login",
        scheme="https",
        hostname="example.com",
        domain="example.com",
        registered_domain="example.com",
        tld="com",
        path="/login",
        query="",
        fragment="",
        url_length=25,
    )

    rule_result = RuleResult(
        rule_id="URL_ENCODING",
        description="URL contains encoded characters.",
        triggered=True,
        observations=["url=https://example.com/login%20now"],
    )

    explanation_result = ExplainabilityResult(
        risk_score=70.0,
        ml_phishing_probability=0.9,
        explanations=[],
    )

    result = PipelineResult(
        email=create_email(),
        ml_phishing_probability=0.9,
        url_analyses=[url_analysis],
        header_analysis=create_header_analysis(),
        attachment_analysis=create_attachment_analysis(),
        rule_results=[rule_result],
        risk_score=70.0,
        explainability=explanation_result,
    )

    assert result.url_analyses[0].original_url == (
        "https://example.com/login"
    )
    assert result.rule_results[0].rule_id == "URL_ENCODING"
    assert result.explainability.risk_score == 70.0


def test_pipeline_result_requires_core_outputs():
    fields = PipelineResult.model_fields

    assert "email" in fields
    assert "ml_phishing_probability" in fields
    assert "url_analyses" in fields
    assert "header_analysis" in fields
    assert "attachment_analysis" in fields
    assert "rule_results" in fields
    assert "risk_score" in fields
    assert "explainability" in fields


def test_pipeline_result_serializes_nested_results():
    result = PipelineResult(
        email=create_email(),
        ml_phishing_probability=0.75,
        header_analysis=create_header_analysis(),
        attachment_analysis=create_attachment_analysis(),
        risk_score=52.5,
        explainability=create_explainability_result(),
    )

    data = result.model_dump()

    assert data["email"]["sender"] == "sender@example.com"
    assert data["ml_phishing_probability"] == 0.75
    assert data["url_analyses"] == []
    assert data["rule_results"] == []
    assert data["risk_score"] == 52.5
    assert data["explainability"]["risk_score"] == 50.0