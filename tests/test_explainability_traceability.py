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


def test_ml_explanation_has_explicit_traceable_rule_id():
    service = ExplainabilityService()

    result = service.generate_explanation(
        risk_score=20.0,
        ml_phishing_probability=0.20,
        rule_results=[],
    )

    ml_explanation = result.explanations[0]

    assert ml_explanation.rule_id == "ML_MODEL"
    assert ml_explanation.category == "ML"


def test_rule_explanation_preserves_originating_rule_id():
    service = ExplainabilityService()

    rule_result = create_rule_result(
        "HEADER_SPF_FAILURE",
        observations=["spf_status=fail"],
    )

    result = service.generate_explanation(
        risk_score=70.0,
        ml_phishing_probability=0.80,
        rule_results=[rule_result],
    )

    explanation = result.explanations[1]

    assert explanation.rule_id == rule_result.rule_id


def test_rule_explanation_category_matches_rule_definition():
    service = ExplainabilityService()

    rule_result = create_rule_result(
        "URL_IP_ADDRESS",
        observations=["url=https://192.168.1.10/login"],
    )

    result = service.generate_explanation(
        risk_score=75.0,
        ml_phishing_probability=0.85,
        rule_results=[rule_result],
    )

    explanation = result.explanations[1]

    assert explanation.rule_id == "URL_IP_ADDRESS"
    assert explanation.category == (
        service.RULE_EXPLANATIONS["URL_IP_ADDRESS"]["category"]
    )


def test_rule_observations_remain_traceable_after_prioritization():
    service = ExplainabilityService()

    header_observations = [
        "spf_status=fail",
        "smtp_mail_from=attacker@example.net",
    ]

    url_observations = [
        "url=https://192.168.1.10/login",
        "host=192.168.1.10",
    ]

    rule_results = [
        create_rule_result(
            "URL_IP_ADDRESS",
            observations=url_observations,
        ),
        create_rule_result(
            "HEADER_SPF_FAILURE",
            observations=header_observations,
        ),
    ]

    result = service.generate_explanation(
        risk_score=80.0,
        ml_phishing_probability=0.90,
        rule_results=rule_results,
    )

    header_explanation = result.explanations[1]
    url_explanation = result.explanations[2]

    assert header_explanation.rule_id == "HEADER_SPF_FAILURE"
    assert header_explanation.observations == header_observations

    assert url_explanation.rule_id == "URL_IP_ADDRESS"
    assert url_explanation.observations == url_observations


def test_unknown_rule_cannot_create_untraceable_explanation():
    service = ExplainabilityService()

    result = service.generate_explanation(
        risk_score=50.0,
        ml_phishing_probability=0.50,
        rule_results=[
            create_rule_result(
                "UNKNOWN_RULE",
                observations=["unknown=true"],
            )
        ],
    )

    assert [
        explanation.rule_id
        for explanation in result.explanations
    ] == ["ML_MODEL"]


def test_traceability_is_preserved_for_multiple_rule_categories():
    service = ExplainabilityService()

    rule_results = [
        create_rule_result(
            "ATTACHMENT_MIME_MISMATCH",
            observations=[
                "filename=document.pdf",
                "detected_mime=application/x-dosexec",
            ],
        ),
        create_rule_result(
            "URL_UNUSUAL_PORT",
            observations=["url=https://example.com:8080/login"],
        ),
        create_rule_result(
            "HEADER_DMARC_FAILURE",
            observations=["dmarc_status=fail"],
        ),
    ]

    result = service.generate_explanation(
        risk_score=90.0,
        ml_phishing_probability=0.95,
        rule_results=rule_results,
    )

    explanations = result.explanations

    assert [explanation.rule_id for explanation in explanations] == [
        "ML_MODEL",
        "HEADER_DMARC_FAILURE",
        "URL_UNUSUAL_PORT",
        "ATTACHMENT_MIME_MISMATCH",
    ]

    assert explanations[1].observations == [
        "dmarc_status=fail",
    ]

    assert explanations[2].observations == [
        "url=https://example.com:8080/login",
    ]

    assert explanations[3].observations == [
        "filename=document.pdf",
        "detected_mime=application/x-dosexec",
    ]


def test_explainability_result_preserves_detection_context():
    service = ExplainabilityService()

    result = service.generate_explanation(
        risk_score=87.5,
        ml_phishing_probability=0.925,
        rule_results=[
            create_rule_result(
                "HEADER_SPF_FAILURE",
                observations=["spf_status=fail"],
            ),
        ],
    )

    assert result.risk_score == 87.5
    assert result.ml_phishing_probability == 0.925
    assert result.explanations[0].rule_id == "ML_MODEL"
    assert result.explanations[1].rule_id == "HEADER_SPF_FAILURE"