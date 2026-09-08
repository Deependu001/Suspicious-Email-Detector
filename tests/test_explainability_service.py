import pytest

from app.models.rule_models import RuleResult
from app.services.explainability_service import ExplainabilityService


def create_rule_result(
    rule_id: str,
    *,
    triggered: bool = True,
    observations: list[str] | None = None,
) -> RuleResult:
    return RuleResult(
        rule_id=rule_id,
        description="Test rule",
        triggered=triggered,
        observations=observations or [],
    )


@pytest.fixture
def service() -> ExplainabilityService:
    return ExplainabilityService()


def test_explain_triggered_header_rule(service):
    result = create_rule_result(
        "HEADER_SPF_FAILURE",
        observations=["spf_status=fail"],
    )

    explanation = service.explain_rule(result)

    assert explanation is not None
    assert explanation.rule_id == "HEADER_SPF_FAILURE"
    assert explanation.category == "HEADER"
    assert explanation.message == (
        "The email failed SPF authentication."
    )
    assert explanation.observations == ["spf_status=fail"]


def test_explain_triggered_url_rule(service):
    result = create_rule_result(
        "URL_IP_ADDRESS",
        observations=["url=http://192.168.1.10/login"],
    )

    explanation = service.explain_rule(result)

    assert explanation is not None
    assert explanation.rule_id == "URL_IP_ADDRESS"
    assert explanation.category == "URL"
    assert explanation.observations == [
        "url=http://192.168.1.10/login"
    ]


def test_explain_triggered_attachment_rule(service):
    result = create_rule_result(
        "ATTACHMENT_DANGEROUS_EXTENSION",
        observations=["filename=invoice.pdf.exe"],
    )

    explanation = service.explain_rule(result)

    assert explanation is not None
    assert explanation.rule_id == (
        "ATTACHMENT_DANGEROUS_EXTENSION"
    )
    assert explanation.category == "ATTACHMENT"
    assert explanation.observations == [
        "filename=invoice.pdf.exe"
    ]


def test_non_triggered_rule_returns_no_explanation(service):
    result = create_rule_result(
        "HEADER_SPF_FAILURE",
        triggered=False,
        observations=["spf_status=pass"],
    )

    explanation = service.explain_rule(result)

    assert explanation is None


def test_unknown_rule_returns_no_explanation(service):
    result = create_rule_result(
        "UNKNOWN_RULE",
        observations=["test"],
    )

    explanation = service.explain_rule(result)

    assert explanation is None


@pytest.mark.parametrize(
    "rule_id,expected_category",
    [
        ("HEADER_FROM_REPLY_TO_MISMATCH", "HEADER"),
        ("HEADER_FROM_RETURN_PATH_MISMATCH", "HEADER"),
        ("HEADER_SPF_FAILURE", "HEADER"),
        ("HEADER_DKIM_FAILURE", "HEADER"),
        ("HEADER_DMARC_FAILURE", "HEADER"),
        ("URL_IP_ADDRESS", "URL"),
        ("URL_UNUSUAL_PORT", "URL"),
        ("URL_SUSPICIOUS_CHARACTERS", "URL"),
        ("URL_ENCODING", "URL"),
        ("ATTACHMENT_DANGEROUS_EXTENSION", "ATTACHMENT"),
        ("ATTACHMENT_DOUBLE_EXTENSION", "ATTACHMENT"),
        ("ATTACHMENT_MIME_MISMATCH", "ATTACHMENT"),
        ("ATTACHMENT_UNUSUAL_FILENAME", "ATTACHMENT"),
    ],
)
def test_all_configured_rules_have_explanations(
    service,
    rule_id,
    expected_category,
):
    result = create_rule_result(rule_id)

    explanation = service.explain_rule(result)

    assert explanation is not None
    assert explanation.rule_id == rule_id
    assert explanation.category == expected_category


def test_observations_are_copied(service):
    observations = ["url=http://192.168.1.10/login"]

    result = create_rule_result(
        "URL_IP_ADDRESS",
        observations=observations,
    )

    explanation = service.explain_rule(result)

    assert explanation is not None

    observations.append(
        "url=http://10.0.0.1/test"
    )

    assert explanation.observations == [
        "url=http://192.168.1.10/login"
    ]


def test_explanation_is_deterministic(service):
    result = create_rule_result(
        "URL_ENCODING",
        observations=[
            "url=https://example.com/login%20now"
        ],
    )

    first = service.explain_rule(result)
    second = service.explain_rule(result)

    assert first == second


def test_ml_probability_low_explanation():
    explanation = ExplainabilityService.explain_ml_probability(
        0.15
    )

    assert explanation.rule_id == "ML_MODEL"
    assert explanation.category == "ML"
    assert explanation.message == (
        "The ML classifier assigned a low "
        "phishing probability of 15.0%."
    )
    assert explanation.observations == [
        "ml_phishing_probability=0.150000"
    ]


def test_ml_probability_moderate_explanation():
    explanation = ExplainabilityService.explain_ml_probability(
        0.50
    )

    assert explanation.rule_id == "ML_MODEL"
    assert explanation.category == "ML"
    assert explanation.message == (
        "The ML classifier assigned a moderate "
        "phishing probability of 50.0%."
    )


def test_ml_probability_high_explanation():
    explanation = ExplainabilityService.explain_ml_probability(
        0.92
    )

    assert explanation.rule_id == "ML_MODEL"
    assert explanation.category == "ML"
    assert explanation.message == (
        "The ML classifier assigned a high "
        "phishing probability of 92.0%."
    )
    assert explanation.observations == [
        "ml_phishing_probability=0.920000"
    ]


def test_ml_probability_zero_is_valid():
    explanation = ExplainabilityService.explain_ml_probability(
        0.0
    )

    assert explanation.message == (
        "The ML classifier assigned a low "
        "phishing probability of 0.0%."
    )


def test_ml_probability_one_is_valid():
    explanation = ExplainabilityService.explain_ml_probability(
        1.0
    )

    assert explanation.message == (
        "The ML classifier assigned a high "
        "phishing probability of 100.0%."
    )


@pytest.mark.parametrize(
    "probability",
    [-0.01, 1.01],
)
def test_ml_probability_out_of_range_raises_value_error(
    probability,
):
    with pytest.raises(
        ValueError,
        match="ML phishing probability must be between 0.0 and 1.0.",
    ):
        ExplainabilityService.explain_ml_probability(
            probability
        )


def test_ml_probability_explanation_is_deterministic():
    first = ExplainabilityService.explain_ml_probability(
        0.823456
    )
    second = ExplainabilityService.explain_ml_probability(
        0.823456
    )

    assert first == second
