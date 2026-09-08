from app.models.rule_models import RuleResult
from app.models.scoring_models import (
    RuleWeight,
    ScoringInput,
    ScoringWeights,
)


def test_scoring_input_accepts_ml_probability_and_rules():
    rule = RuleResult(
        rule_id="URL_IP_ADDRESS",
        description="A URL uses an IP address as its hostname",
        triggered=True,
        observations=["url=http://192.168.1.10/login"],
    )

    result = ScoringInput(
        ml_phishing_probability=0.85,
        rule_results=[rule],
    )

    assert result.ml_phishing_probability == 0.85
    assert len(result.rule_results) == 1
    assert result.rule_results[0].rule_id == "URL_IP_ADDRESS"
    assert result.rule_results[0].triggered is True


def test_scoring_input_defaults_to_empty_rules():
    result = ScoringInput(
        ml_phishing_probability=0.25,
    )

    assert result.ml_phishing_probability == 0.25
    assert result.rule_results == []


def test_rule_weight_stores_rule_id_and_weight():
    result = RuleWeight(
        rule_id="HEADER_SPF_FAILURE",
        weight=0.10,
    )

    assert result.rule_id == "HEADER_SPF_FAILURE"
    assert result.weight == 0.10


def test_scoring_weights_stores_ml_and_rule_weights():
    result = ScoringWeights(
        ml_weight=0.70,
        rule_weights=[
            RuleWeight(
                rule_id="URL_IP_ADDRESS",
                weight=0.30,
            )
        ],
    )

    assert result.ml_weight == 0.70
    assert len(result.rule_weights) == 1
    assert result.rule_weights[0].rule_id == "URL_IP_ADDRESS"
    assert result.rule_weights[0].weight == 0.30


def test_scoring_weights_defaults_to_empty_rule_weights():
    result = ScoringWeights(
        ml_weight=1.0,
    )

    assert result.ml_weight == 1.0
    assert result.rule_weights == []
