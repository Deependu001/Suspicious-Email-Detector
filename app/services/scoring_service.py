from app.models.scoring_models import (
    ScoringInput,
    ScoringWeights,
)


class ScoringService:
    """Calculate a deterministic combined phishing risk score."""

    DEFAULT_WEIGHTS = ScoringWeights(
        ml_weight=0.70,
        rule_weights=[
            {"rule_id": "HEADER_FROM_REPLY_TO_MISMATCH", "weight": 0.08},
            {"rule_id": "HEADER_FROM_RETURN_PATH_MISMATCH", "weight": 0.06},
            {"rule_id": "HEADER_SPF_FAILURE", "weight": 0.08},
            {"rule_id": "HEADER_DKIM_FAILURE", "weight": 0.06},
            {"rule_id": "HEADER_DMARC_FAILURE", "weight": 0.10},
            {"rule_id": "URL_IP_ADDRESS", "weight": 0.10},
            {"rule_id": "URL_UNUSUAL_PORT", "weight": 0.05},
            {"rule_id": "URL_SUSPICIOUS_CHARACTERS", "weight": 0.05},
            {"rule_id": "URL_ENCODING", "weight": 0.04},
            {"rule_id": "ATTACHMENT_DANGEROUS_EXTENSION", "weight": 0.12},
            {"rule_id": "ATTACHMENT_DOUBLE_EXTENSION", "weight": 0.08},
            {"rule_id": "ATTACHMENT_MIME_MISMATCH", "weight": 0.10},
            {"rule_id": "ATTACHMENT_UNUSUAL_FILENAME", "weight": 0.08},
        ],
    )

    def calculate(
        self,
        scoring_input: ScoringInput,
        weights: ScoringWeights | None = None,
    ) -> float:
        """Return a deterministic risk score between 0 and 100."""

        active_weights = weights or self.DEFAULT_WEIGHTS

        self._validate_weights(active_weights)
        self._validate_ml_probability(
            scoring_input.ml_phishing_probability
        )

        rule_weight_map = {
            rule_weight.rule_id: rule_weight.weight
            for rule_weight in active_weights.rule_weights
        }

        triggered_rule_ids = {
            rule.rule_id
            for rule in scoring_input.rule_results
            if rule.triggered and rule.rule_id in rule_weight_map
        }

        triggered_rule_weight = sum(
            rule_weight_map[rule_id]
            for rule_id in triggered_rule_ids
        )

        combined_score = (
            scoring_input.ml_phishing_probability
            * active_weights.ml_weight
        ) + (triggered_rule_weight * (1.0 - active_weights.ml_weight))

        risk_score = combined_score * 100.0

        return max(0.0, min(100.0, risk_score))

    @staticmethod
    def _validate_ml_probability(probability: float) -> None:
        if not 0.0 <= probability <= 1.0:
            raise ValueError(
                "ML phishing probability must be between 0.0 and 1.0."
            )

    @staticmethod
    def _validate_weights(weights: ScoringWeights) -> None:
        if not 0.0 <= weights.ml_weight <= 1.0:
            raise ValueError(
                "ML weight must be between 0.0 and 1.0."
            )

        total_rule_weight = sum(
            rule_weight.weight
            for rule_weight in weights.rule_weights
        )

        if not 0.999999 <= total_rule_weight <= 1.000001:
            raise ValueError(
                "Rule weights must sum to 1.0."
            )

        if any(
            rule_weight.weight < 0.0
            for rule_weight in weights.rule_weights
        ):
            raise ValueError(
                "Rule weights must not be negative."
            )
