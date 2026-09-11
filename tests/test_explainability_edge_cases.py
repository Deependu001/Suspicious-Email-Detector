from app.models.rule_models import RuleResult
from app.services.explainability_service import ExplainabilityService


def create_rule_result(
    rule_id: str,
    triggered: bool = True,
    observations: list[str] | None = None,
) -> RuleResult:
    return RuleResult(
        rule_id=rule_id,
        description=f"Description for {rule_id}",
        triggered=triggered,
        observations=observations or [],
    )


def test_generate_explanation_with_duplicate_triggered_rules():
    service = ExplainabilityService()

    rule_results = [
        create_rule_result(
            "URL_IP_ADDRESS",
            observations=["url=https://192.168.1.10/login"],
        ),
        create_rule_result(
            "URL_IP_ADDRESS",
            observations=["url=https://192.168.1.10/login"],
        ),
    ]

    result = service.generate_explanation(
        risk_score=80.0,
        ml_phishing_probability=0.90,
        rule_results=rule_results,
    )

    assert [
        explanation.rule_id
        for explanation in result.explanations
    ] == [
        "ML_MODEL",
        "URL_IP_ADDRESS",
        "URL_IP_ADDRESS",
    ]


def test_generate_explanation_with_only_ignored_rules():
    service = ExplainabilityService()

    rule_results = [
        create_rule_result(
            "UNKNOWN_RULE",
            triggered=True,
            observations=["unknown=true"],
        ),
        create_rule_result(
            "URL_IP_ADDRESS",
            triggered=False,
            observations=["url=https://192.168.1.10/login"],
        ),
    ]

    result = service.generate_explanation(
        risk_score=25.0,
        ml_phishing_probability=0.20,
        rule_results=rule_results,
    )

    assert len(result.explanations) == 1
    assert result.explanations[0].rule_id == "ML_MODEL"


def test_generate_explanation_handles_mixed_known_unknown_and_non_triggered():
    service = ExplainabilityService()

    rule_results = [
        create_rule_result(
            "UNKNOWN_RULE",
            triggered=True,
            observations=["unknown=true"],
        ),
        create_rule_result(
            "URL_ENCODING",
            triggered=False,
            observations=["url=https://example.com/login%20now"],
        ),
        create_rule_result(
            "HEADER_SPF_FAILURE",
            triggered=True,
            observations=["spf_status=fail"],
        ),
        create_rule_result(
            "URL_IP_ADDRESS",
            triggered=True,
            observations=["url=https://192.168.1.10/login"],
        ),
    ]

    result = service.generate_explanation(
        risk_score=75.0,
        ml_phishing_probability=0.85,
        rule_results=rule_results,
    )

    assert [
        explanation.rule_id
        for explanation in result.explanations
    ] == [
        "ML_MODEL",
        "HEADER_SPF_FAILURE",
        "URL_IP_ADDRESS",
    ]


def test_explain_ml_probability_at_moderate_lower_boundary():
    service = ExplainabilityService()

    result = service.explain_ml_probability(0.30)

    assert result.category == "ML"
    assert result.message == (
        "The ML classifier assigned a moderate "
        "phishing probability of 30.0%."
    )


def test_explain_ml_probability_at_high_lower_boundary():
    service = ExplainabilityService()

    result = service.explain_ml_probability(0.70)

    assert result.category == "ML"
    assert result.message == (
        "The ML classifier assigned a high "
        "phishing probability of 70.0%."
    )


def test_generate_explanation_preserves_empty_rule_observations():
    service = ExplainabilityService()

    rule_results = [
        create_rule_result(
            "HEADER_SPF_FAILURE",
            observations=[],
        ),
    ]

    result = service.generate_explanation(
        risk_score=65.0,
        ml_phishing_probability=0.75,
        rule_results=rule_results,
    )

    assert result.explanations[0].rule_id == "ML_MODEL"
    assert result.explanations[1].rule_id == "HEADER_SPF_FAILURE"
    assert result.explanations[1].observations == []


def test_generate_explanation_is_deterministic_across_repeated_calls():
    service = ExplainabilityService()

    rule_results = [
        create_rule_result(
            "ATTACHMENT_DOUBLE_EXTENSION",
            observations=["filename=invoice.pdf.exe"],
        ),
        create_rule_result(
            "URL_ENCODING",
            observations=["url=https://example.com/login%20now"],
        ),
        create_rule_result(
            "HEADER_DKIM_FAILURE",
            observations=["dkim_status=fail"],
        ),
        create_rule_result(
            "HEADER_SPF_FAILURE",
            observations=["spf_status=fail"],
        ),
    ]

    first_result = service.generate_explanation(
        risk_score=82.5,
        ml_phishing_probability=0.91,
        rule_results=rule_results,
    )

    second_result = service.generate_explanation(
        risk_score=82.5,
        ml_phishing_probability=0.91,
        rule_results=rule_results,
    )

    assert first_result == second_result