from app.models.explainability_models import (
    Explanation,
    ExplainabilityResult,
)


def test_explanation_model_contains_structured_information():
    explanation = Explanation(
        rule_id="URL_IP_ADDRESS",
        category="URL",
        message=(
            "The email contains a URL that uses an IP address "
            "instead of a domain name."
        ),
        observations=[
            "url=http://192.168.1.10/login"
        ],
    )

    assert explanation.rule_id == "URL_IP_ADDRESS"
    assert explanation.category == "URL"
    assert (
        explanation.message
        == (
            "The email contains a URL that uses an IP address "
            "instead of a domain name."
        )
    )
    assert explanation.observations == [
        "url=http://192.168.1.10/login"
    ]


def test_explanation_observations_default_to_empty_list():
    explanation = Explanation(
        rule_id="HEADER_SPF_FAILURE",
        category="HEADER",
        message="The email failed SPF authentication.",
    )

    assert explanation.observations == []


def test_explainability_result_contains_score_and_probability():
    result = ExplainabilityResult(
        risk_score=65.6,
        ml_phishing_probability=0.80,
    )

    assert result.risk_score == 65.6
    assert result.ml_phishing_probability == 0.80
    assert result.explanations == []


def test_explainability_result_contains_explanations():
    explanation = Explanation(
        rule_id="ATTACHMENT_DANGEROUS_EXTENSION",
        category="ATTACHMENT",
        message="The email contains a potentially dangerous attachment.",
        observations=[
            "filename=invoice.pdf.exe"
        ],
    )

    result = ExplainabilityResult(
        risk_score=72.0,
        ml_phishing_probability=0.85,
        explanations=[explanation],
    )

    assert len(result.explanations) == 1
    assert result.explanations[0].rule_id == (
        "ATTACHMENT_DANGEROUS_EXTENSION"
    )


def test_explainability_result_supports_multiple_explanations():
    explanations = [
        Explanation(
            rule_id="HEADER_SPF_FAILURE",
            category="HEADER",
            message="The email failed SPF authentication.",
            observations=["spf_status=fail"],
        ),
        Explanation(
            rule_id="URL_IP_ADDRESS",
            category="URL",
            message=(
                "The email contains a URL that uses an IP address "
                "instead of a domain name."
            ),
            observations=[
                "url=http://192.168.1.10/login"
            ],
        ),
    ]

    result = ExplainabilityResult(
        risk_score=68.5,
        ml_phishing_probability=0.82,
        explanations=explanations,
    )

    assert len(result.explanations) == 2
    assert result.explanations[0].rule_id == "HEADER_SPF_FAILURE"
    assert result.explanations[1].rule_id == "URL_IP_ADDRESS"