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


# ---------------------------------------------------------------------------
# Rule explanation tests
# ---------------------------------------------------------------------------


def test_explain_rule_returns_none_for_non_triggered_rule():
    service = ExplainabilityService()

    rule_result = create_rule_result(
        "URL_IP_ADDRESS",
        triggered=False,
        observations=["url=https://192.168.1.10/login"],
    )

    result = service.explain_rule(rule_result)

    assert result is None


def test_explain_rule_returns_none_for_unknown_rule():
    service = ExplainabilityService()

    rule_result = create_rule_result(
        "UNKNOWN_RULE",
        observations=["some observation"],
    )

    result = service.explain_rule(rule_result)

    assert result is None


def test_explain_rule_returns_explanation_for_known_rule():
    service = ExplainabilityService()

    rule_result = create_rule_result(
        "URL_IP_ADDRESS",
        observations=["url=https://192.168.1.10/login"],
    )

    result = service.explain_rule(rule_result)

    assert result is not None
    assert result.rule_id == "URL_IP_ADDRESS"
    assert result.category == "URL"
    assert result.observations == [
        "url=https://192.168.1.10/login"
    ]


def test_explain_rule_preserves_observations():
    service = ExplainabilityService()

    observations = [
        "url=https://192.168.1.10/login",
        "host=192.168.1.10",
    ]

    rule_result = create_rule_result(
        "URL_IP_ADDRESS",
        observations=observations,
    )

    result = service.explain_rule(rule_result)

    assert result is not None
    assert result.observations == observations


def test_explain_rule_handles_empty_observations():
    service = ExplainabilityService()

    rule_result = create_rule_result(
        "URL_IP_ADDRESS",
        observations=[],
    )

    result = service.explain_rule(rule_result)

    assert result is not None
    assert result.observations == []


def test_all_known_rules_have_explanations():
    service = ExplainabilityService()

    expected_rule_ids = {
        "HEADER_FROM_REPLY_TO_MISMATCH",
        "HEADER_FROM_RETURN_PATH_MISMATCH",
        "HEADER_SPF_FAILURE",
        "HEADER_DKIM_FAILURE",
        "HEADER_DMARC_FAILURE",
        "URL_IP_ADDRESS",
        "URL_UNUSUAL_PORT",
        "URL_SUSPICIOUS_CHARACTERS",
        "URL_ENCODING",
        "ATTACHMENT_DANGEROUS_EXTENSION",
        "ATTACHMENT_DOUBLE_EXTENSION",
        "ATTACHMENT_MIME_MISMATCH",
        "ATTACHMENT_UNUSUAL_FILENAME",
    }

    assert set(service.RULE_EXPLANATIONS) == expected_rule_ids


def test_header_reply_to_mismatch_explanation():
    service = ExplainabilityService()

    result = service.explain_rule(
        create_rule_result(
            "HEADER_FROM_REPLY_TO_MISMATCH",
            observations=[
                "from=alice@example.com",
                "reply_to=attacker@example.net",
            ],
        )
    )

    assert result is not None
    assert result.category == "HEADER"
    assert result.rule_id == "HEADER_FROM_REPLY_TO_MISMATCH"


def test_header_return_path_mismatch_explanation():
    service = ExplainabilityService()

    result = service.explain_rule(
        create_rule_result(
            "HEADER_FROM_RETURN_PATH_MISMATCH",
            observations=[
                "from=alice@example.com",
                "return_path=attacker@example.net",
            ],
        )
    )

    assert result is not None
    assert result.category == "HEADER"


def test_header_spf_failure_explanation():
    service = ExplainabilityService()

    result = service.explain_rule(
        create_rule_result(
            "HEADER_SPF_FAILURE",
            observations=["spf_status=fail"],
        )
    )

    assert result is not None
    assert result.category == "HEADER"


def test_header_dkim_failure_explanation():
    service = ExplainabilityService()

    result = service.explain_rule(
        create_rule_result(
            "HEADER_DKIM_FAILURE",
            observations=["dkim_status=fail"],
        )
    )

    assert result is not None
    assert result.category == "HEADER"


def test_header_dmarc_failure_explanation():
    service = ExplainabilityService()

    result = service.explain_rule(
        create_rule_result(
            "HEADER_DMARC_FAILURE",
            observations=["dmarc_status=fail"],
        )
    )

    assert result is not None
    assert result.category == "HEADER"


def test_url_ip_address_explanation():
    service = ExplainabilityService()

    result = service.explain_rule(
        create_rule_result(
            "URL_IP_ADDRESS",
            observations=["url=https://192.168.1.10/login"],
        )
    )

    assert result is not None
    assert result.category == "URL"


def test_url_unusual_port_explanation():
    service = ExplainabilityService()

    result = service.explain_rule(
        create_rule_result(
            "URL_UNUSUAL_PORT",
            observations=["url=https://example.com:8080/login"],
        )
    )

    assert result is not None
    assert result.category == "URL"


def test_url_suspicious_characters_explanation():
    service = ExplainabilityService()

    result = service.explain_rule(
        create_rule_result(
            "URL_SUSPICIOUS_CHARACTERS",
            observations=["url=https://example.com/%40login"],
        )
    )

    assert result is not None
    assert result.category == "URL"


def test_url_encoding_explanation():
    service = ExplainabilityService()

    result = service.explain_rule(
        create_rule_result(
            "URL_ENCODING",
            observations=["url=https://example.com/login%20now"],
        )
    )

    assert result is not None
    assert result.category == "URL"


def test_attachment_dangerous_extension_explanation():
    service = ExplainabilityService()

    result = service.explain_rule(
        create_rule_result(
            "ATTACHMENT_DANGEROUS_EXTENSION",
            observations=["filename=invoice.exe"],
        )
    )

    assert result is not None
    assert result.category == "ATTACHMENT"


def test_attachment_double_extension_explanation():
    service = ExplainabilityService()

    result = service.explain_rule(
        create_rule_result(
            "ATTACHMENT_DOUBLE_EXTENSION",
            observations=["filename=invoice.pdf.exe"],
        )
    )

    assert result is not None
    assert result.category == "ATTACHMENT"


def test_attachment_mime_mismatch_explanation():
    service = ExplainabilityService()

    result = service.explain_rule(
        create_rule_result(
            "ATTACHMENT_MIME_MISMATCH",
            observations=[
                "filename=document.pdf",
                "declared_mime=application/pdf",
                "detected_mime=application/x-dosexec",
            ],
        )
    )

    assert result is not None
    assert result.category == "ATTACHMENT"


def test_attachment_unusual_filename_explanation():
    service = ExplainabilityService()

    result = service.explain_rule(
        create_rule_result(
            "ATTACHMENT_UNUSUAL_FILENAME",
            observations=["filename=invoice_1234567890.tmp"],
        )
    )

    assert result is not None
    assert result.category == "ATTACHMENT"


# ---------------------------------------------------------------------------
# ML probability explanation tests
# ---------------------------------------------------------------------------


def test_explain_ml_probability_low():
    service = ExplainabilityService()

    result = service.explain_ml_probability(0.15)

    assert result.rule_id == "ML_MODEL"
    assert result.category == "ML"
    assert result.message == (
        "The ML classifier assigned a low phishing probability of 15.0%."
    )
    assert result.observations == [
        "ml_phishing_probability=0.150000"
    ]


def test_explain_ml_probability_moderate():
    service = ExplainabilityService()

    result = service.explain_ml_probability(0.50)

    assert result.rule_id == "ML_MODEL"
    assert result.category == "ML"
    assert result.message == (
        "The ML classifier assigned a moderate phishing probability of 50.0%."
    )
    assert result.observations == [
        "ml_phishing_probability=0.500000"
    ]


def test_explain_ml_probability_high():
    service = ExplainabilityService()

    result = service.explain_ml_probability(0.92)

    assert result.rule_id == "ML_MODEL"
    assert result.category == "ML"
    assert result.message == (
        "The ML classifier assigned a high phishing probability of 92.0%."
    )
    assert result.observations == [
        "ml_phishing_probability=0.920000"
    ]


def test_explain_ml_probability_zero():
    service = ExplainabilityService()

    result = service.explain_ml_probability(0.0)

    assert result.category == "ML"
    assert result.message == (
        "The ML classifier assigned a low phishing probability of 0.0%."
    )


def test_explain_ml_probability_one():
    service = ExplainabilityService()

    result = service.explain_ml_probability(1.0)

    assert result.category == "ML"
    assert result.message == (
        "The ML classifier assigned a high phishing probability of 100.0%."
    )


def test_explain_ml_probability_rejects_negative_value():
    service = ExplainabilityService()

    try:
        service.explain_ml_probability(-0.01)
        assert False
    except ValueError as exc:
        assert str(exc) == (
            "ML phishing probability must be between 0.0 and 1.0."
        )


def test_explain_ml_probability_rejects_value_above_one():
    service = ExplainabilityService()

    try:
        service.explain_ml_probability(1.01)
        assert False
    except ValueError as exc:
        assert str(exc) == (
            "ML phishing probability must be between 0.0 and 1.0."
        )


# ---------------------------------------------------------------------------
# Combined explanation generation tests
# ---------------------------------------------------------------------------


def test_generate_explanation_includes_ml_explanation():
    service = ExplainabilityService()

    result = service.generate_explanation(
        risk_score=60.0,
        ml_phishing_probability=0.75,
        rule_results=[],
    )

    assert len(result.explanations) == 1
    assert result.explanations[0].rule_id == "ML_MODEL"
    assert result.explanations[0].category == "ML"


def test_generate_explanation_includes_triggered_rules():
    service = ExplainabilityService()

    rule_results = [
        create_rule_result(
            "URL_IP_ADDRESS",
            observations=["url=https://192.168.1.10/login"],
        ),
        create_rule_result(
            "HEADER_SPF_FAILURE",
            observations=["spf_status=fail"],
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
        "HEADER_SPF_FAILURE",
        "URL_IP_ADDRESS",
    ]


def test_generate_explanation_ignores_non_triggered_rules():
    service = ExplainabilityService()

    rule_results = [
        create_rule_result(
            "URL_IP_ADDRESS",
            triggered=False,
        ),
        create_rule_result(
            "HEADER_SPF_FAILURE",
            triggered=True,
        ),
    ]

    result = service.generate_explanation(
        risk_score=50.0,
        ml_phishing_probability=0.60,
        rule_results=rule_results,
    )

    assert [
        explanation.rule_id
        for explanation in result.explanations
    ] == [
        "ML_MODEL",
        "HEADER_SPF_FAILURE",
    ]


def test_generate_explanation_ignores_unknown_rules():
    service = ExplainabilityService()

    rule_results = [
        create_rule_result("UNKNOWN_RULE"),
        create_rule_result("URL_IP_ADDRESS"),
    ]

    result = service.generate_explanation(
        risk_score=50.0,
        ml_phishing_probability=0.60,
        rule_results=rule_results,
    )

    assert [
        explanation.rule_id
        for explanation in result.explanations
    ] == [
        "ML_MODEL",
        "URL_IP_ADDRESS",
    ]


def test_generate_explanation_preserves_risk_score():
    service = ExplainabilityService()

    result = service.generate_explanation(
        risk_score=73.5,
        ml_phishing_probability=0.80,
        rule_results=[],
    )

    assert result.risk_score == 73.5


def test_generate_explanation_preserves_ml_probability():
    service = ExplainabilityService()

    result = service.generate_explanation(
        risk_score=73.5,
        ml_phishing_probability=0.80,
        rule_results=[],
    )

    assert result.ml_phishing_probability == 0.80


def test_generate_explanation_with_no_rules():
    service = ExplainabilityService()

    result = service.generate_explanation(
        risk_score=10.0,
        ml_phishing_probability=0.10,
        rule_results=[],
    )

    assert len(result.explanations) == 1
    assert result.explanations[0].rule_id == "ML_MODEL"


def test_generate_explanation_rejects_invalid_ml_probability():
    service = ExplainabilityService()

    try:
        service.generate_explanation(
            risk_score=50.0,
            ml_phishing_probability=1.5,
            rule_results=[],
        )
        assert False
    except ValueError as exc:
        assert str(exc) == (
            "ML phishing probability must be between 0.0 and 1.0."
        )


def test_generate_explanation_preserves_rule_observations():
    service = ExplainabilityService()

    rule_results = [
        create_rule_result(
            "URL_IP_ADDRESS",
            observations=[
                "url=https://192.168.1.10/login",
                "host=192.168.1.10",
            ],
        )
    ]

    result = service.generate_explanation(
        risk_score=70.0,
        ml_phishing_probability=0.88,
        rule_results=rule_results,
    )

    explanation = result.explanations[1]

    assert explanation.rule_id == "URL_IP_ADDRESS"
    assert explanation.observations == [
        "url=https://192.168.1.10/login",
        "host=192.168.1.10",
    ]


# ---------------------------------------------------------------------------
# Step 5 — Explanation prioritization tests
# ---------------------------------------------------------------------------


def test_generate_explanation_prioritizes_categories():
    service = ExplainabilityService()

    rule_results = [
        create_rule_result(
            "URL_ENCODING",
            observations=[
                "url=https://example.com/login%20now"
            ],
        ),
        create_rule_result(
            "ATTACHMENT_DOUBLE_EXTENSION",
            observations=[
                "filename=invoice.pdf.exe"
            ],
        ),
        create_rule_result(
            "HEADER_SPF_FAILURE",
            observations=["spf_status=fail"],
        ),
        create_rule_result(
            "URL_IP_ADDRESS",
            observations=[
                "url=https://192.168.1.10/login"
            ],
        ),
    ]

    result = service.generate_explanation(
        risk_score=70.0,
        ml_phishing_probability=0.88,
        rule_results=rule_results,
    )

    assert [
        explanation.rule_id
        for explanation in result.explanations
    ] == [
        "ML_MODEL",
        "HEADER_SPF_FAILURE",
        "URL_IP_ADDRESS",
        "URL_ENCODING",
        "ATTACHMENT_DOUBLE_EXTENSION",
    ]


def test_generate_explanation_uses_rule_order_within_category():
    service = ExplainabilityService()

    rule_results = [
        create_rule_result(
            "HEADER_SPF_FAILURE",
            observations=["spf_status=fail"],
        ),
        create_rule_result(
            "HEADER_FROM_REPLY_TO_MISMATCH",
            observations=[
                "from=alice@example.com",
                "reply_to=attacker@example.net",
            ],
        ),
        create_rule_result(
            "HEADER_DKIM_FAILURE",
            observations=["dkim_status=fail"],
        ),
    ]

    result = service.generate_explanation(
        risk_score=75.0,
        ml_phishing_probability=0.90,
        rule_results=rule_results,
    )

    assert [
        explanation.rule_id
        for explanation in result.explanations
    ] == [
        "ML_MODEL",
        "HEADER_FROM_REPLY_TO_MISMATCH",
        "HEADER_SPF_FAILURE",
        "HEADER_DKIM_FAILURE",
    ]


def test_generate_explanation_priority_is_independent_of_input_order():
    service = ExplainabilityService()

    rule_results = [
        create_rule_result(
            "ATTACHMENT_DOUBLE_EXTENSION",
            observations=["filename=invoice.pdf.exe"],
        ),
        create_rule_result(
            "URL_ENCODING",
            observations=[
                "url=https://example.com/login%20now"
            ],
        ),
        create_rule_result(
            "HEADER_DKIM_FAILURE",
            observations=["dkim_status=fail"],
        ),
        create_rule_result(
            "URL_IP_ADDRESS",
            observations=[
                "url=https://192.168.1.10/login"
            ],
        ),
    ]

    result = service.generate_explanation(
        risk_score=80.0,
        ml_phishing_probability=0.91,
        rule_results=rule_results,
    )

    assert [
        explanation.rule_id
        for explanation in result.explanations
    ] == [
        "ML_MODEL",
        "HEADER_DKIM_FAILURE",
        "URL_IP_ADDRESS",
        "URL_ENCODING",
        "ATTACHMENT_DOUBLE_EXTENSION",
    ]


def test_generate_explanation_preserves_observations_after_sorting():
    service = ExplainabilityService()

    rule_results = [
        create_rule_result(
            "URL_ENCODING",
            observations=[
                "url=https://example.com/login%20now"
            ],
        ),
        create_rule_result(
            "HEADER_SPF_FAILURE",
            observations=[
                "spf_status=fail",
                "smtp_mail_from=attacker@example.net",
            ],
        ),
        create_rule_result(
            "ATTACHMENT_DOUBLE_EXTENSION",
            observations=[
                "filename=invoice.pdf.exe"
            ],
        ),
    ]

    result = service.generate_explanation(
        risk_score=70.0,
        ml_phishing_probability=0.88,
        rule_results=rule_results,
    )

    assert result.explanations[1].rule_id == "HEADER_SPF_FAILURE"
    assert result.explanations[1].observations == [
        "spf_status=fail",
        "smtp_mail_from=attacker@example.net",
    ]

    assert result.explanations[2].rule_id == "URL_ENCODING"
    assert result.explanations[2].observations == [
        "url=https://example.com/login%20now"
    ]

    assert result.explanations[3].rule_id == "ATTACHMENT_DOUBLE_EXTENSION"
    assert result.explanations[3].observations == [
        "filename=invoice.pdf.exe"
    ]


def test_generate_explanation_uses_deterministic_priority_order():
    service = ExplainabilityService()

    rule_results = [
        create_rule_result(
            "URL_ENCODING",
            observations=[
                "url=https://example.com/login%20now"
            ],
        ),
        create_rule_result(
            "HEADER_SPF_FAILURE",
            observations=["spf_status=fail"],
        ),
        create_rule_result(
            "ATTACHMENT_DOUBLE_EXTENSION",
            observations=["filename=invoice.pdf.exe"],
        ),
    ]

    result = service.generate_explanation(
        risk_score=70.0,
        ml_phishing_probability=0.88,
        rule_results=rule_results,
    )

    assert [
        explanation.rule_id
        for explanation in result.explanations
    ] == [
        "ML_MODEL",
        "HEADER_SPF_FAILURE",
        "URL_ENCODING",
        "ATTACHMENT_DOUBLE_EXTENSION",
    ]