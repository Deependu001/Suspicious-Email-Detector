import pytest

from app.models.rule_models import RuleResult
from app.models.scoring_models import ScoringInput, ScoringWeights
from app.services.scoring_service import ScoringService


def make_rule(rule_id: str, triggered: bool = True) -> RuleResult:
    return RuleResult(
        rule_id=rule_id,
        description=f"Test rule: {rule_id}",
        triggered=triggered,
        observations=[],
    )


def test_ml_only_score():
    service = ScoringService()

    scoring_input = ScoringInput(
        ml_phishing_probability=0.50,
        rule_results=[],
    )

    score = service.calculate(scoring_input)

    assert score == pytest.approx(35.0)


def test_rule_only_score():
    service = ScoringService()

    scoring_input = ScoringInput(
        ml_phishing_probability=0.0,
        rule_results=[
            make_rule("HEADER_DMARC_FAILURE"),
        ],
    )

    score = service.calculate(scoring_input)

    assert score == pytest.approx(3.0)


def test_combined_score():
    service = ScoringService()

    scoring_input = ScoringInput(
        ml_phishing_probability=0.80,
        rule_results=[
            make_rule("URL_IP_ADDRESS"),
            make_rule("ATTACHMENT_DANGEROUS_EXTENSION"),
        ],
    )

    score = service.calculate(scoring_input)

    expected = (
        (0.80 * 0.70)
        + ((0.10 + 0.12) * 0.30)
    ) * 100.0

    assert score == pytest.approx(expected)


def test_all_rules_with_zero_ml_probability_reaches_rule_maximum():
    service = ScoringService()

    scoring_input = ScoringInput(
        ml_phishing_probability=0.0,
        rule_results=[
            make_rule(rule_weight.rule_id)
            for rule_weight in service.DEFAULT_WEIGHTS.rule_weights
        ],
    )

    score = service.calculate(scoring_input)

    assert score == pytest.approx(30.0)


def test_maximum_score_reaches_100():
    service = ScoringService()

    scoring_input = ScoringInput(
        ml_phishing_probability=1.0,
        rule_results=[
            make_rule(rule_weight.rule_id)
            for rule_weight in service.DEFAULT_WEIGHTS.rule_weights
        ],
    )

    score = service.calculate(scoring_input)

    assert score == pytest.approx(100.0)


def test_minimum_score_is_zero():
    service = ScoringService()

    scoring_input = ScoringInput(
        ml_phishing_probability=0.0,
        rule_results=[],
    )

    score = service.calculate(scoring_input)

    assert score == pytest.approx(0.0)


def test_unknown_rule_is_ignored():
    service = ScoringService()

    scoring_input = ScoringInput(
        ml_phishing_probability=0.0,
        rule_results=[
            make_rule("UNKNOWN_RULE"),
        ],
    )

    score = service.calculate(scoring_input)

    assert score == pytest.approx(0.0)


def test_non_triggered_rule_does_not_contribute():
    service = ScoringService()

    scoring_input = ScoringInput(
        ml_phishing_probability=0.0,
        rule_results=[
            make_rule("URL_IP_ADDRESS", triggered=False),
        ],
    )

    score = service.calculate(scoring_input)

    assert score == pytest.approx(0.0)


def test_duplicate_triggered_rule_is_counted_once():
    service = ScoringService()

    scoring_input = ScoringInput(
        ml_phishing_probability=0.0,
        rule_results=[
            make_rule("URL_IP_ADDRESS"),
            make_rule("URL_IP_ADDRESS"),
            make_rule("URL_IP_ADDRESS"),
        ],
    )

    score = service.calculate(scoring_input)

    assert score == pytest.approx(3.0)


def test_calculation_is_deterministic():
    service = ScoringService()

    scoring_input = ScoringInput(
        ml_phishing_probability=0.73,
        rule_results=[
            make_rule("HEADER_SPF_FAILURE"),
            make_rule("URL_ENCODING"),
            make_rule("ATTACHMENT_MIME_MISMATCH"),
        ],
    )

    first_score = service.calculate(scoring_input)
    second_score = service.calculate(scoring_input)

    assert first_score == second_score


@pytest.mark.parametrize(
    "probability",
    [-0.01, 1.01],
)
def test_invalid_ml_probability_raises(probability):
    service = ScoringService()

    scoring_input = ScoringInput(
        ml_phishing_probability=probability,
        rule_results=[],
    )

    with pytest.raises(
        ValueError,
        match="ML phishing probability must be between 0.0 and 1.0.",
    ):
        service.calculate(scoring_input)


@pytest.mark.parametrize(
    "ml_weight",
    [-0.01, 1.01],
)
def test_invalid_ml_weight_raises(ml_weight):
    service = ScoringService()

    weights = ScoringWeights(
        ml_weight=ml_weight,
        rule_weights=[
            {
                "rule_id": rule_weight.rule_id,
                "weight": rule_weight.weight,
            }
            for rule_weight in service.DEFAULT_WEIGHTS.rule_weights
        ],
    )

    scoring_input = ScoringInput(
        ml_phishing_probability=0.5,
        rule_results=[],
    )

    with pytest.raises(
        ValueError,
        match="ML weight must be between 0.0 and 1.0.",
    ):
        service.calculate(scoring_input, weights)


def test_rule_weights_must_sum_to_one():
    service = ScoringService()

    weights = ScoringWeights(
        ml_weight=0.70,
        rule_weights=[
            {
                "rule_id": "URL_IP_ADDRESS",
                "weight": 0.50,
            },
        ],
    )

    scoring_input = ScoringInput(
        ml_phishing_probability=0.5,
        rule_results=[],
    )

    with pytest.raises(
        ValueError,
        match="Rule weights must sum to 1.0.",
    ):
        service.calculate(scoring_input, weights)


def test_negative_rule_weight_raises():
    service = ScoringService()

    weights = ScoringWeights(
        ml_weight=0.70,
        rule_weights=[
            {
                "rule_id": "URL_IP_ADDRESS",
                "weight": -0.10,
            },
            {
                "rule_id": "URL_ENCODING",
                "weight": 1.10,
            },
        ],
    )

    scoring_input = ScoringInput(
        ml_phishing_probability=0.5,
        rule_results=[],
    )

    with pytest.raises(
        ValueError,
        match="Rule weights must not be negative.",
    ):
        service.calculate(scoring_input, weights)
