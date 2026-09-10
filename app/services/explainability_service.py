from app.models.explainability_models import (
    Explanation,
    ExplainabilityResult,
)
from app.models.rule_models import RuleResult


class ExplainabilityService:
    """Convert detection results into human-readable explanations."""

    RULE_EXPLANATIONS = {
        "HEADER_FROM_REPLY_TO_MISMATCH": {
            "category": "HEADER",
            "message": (
                "The sender address domain does not match the "
                "Reply-To domain."
            ),
        },
        "HEADER_FROM_RETURN_PATH_MISMATCH": {
            "category": "HEADER",
            "message": (
                "The sender address domain does not match the "
                "Return-Path domain."
            ),
        },
        "HEADER_SPF_FAILURE": {
            "category": "HEADER",
            "message": (
                "The email failed SPF authentication."
            ),
        },
        "HEADER_DKIM_FAILURE": {
            "category": "HEADER",
            "message": (
                "The email failed DKIM authentication."
            ),
        },
        "HEADER_DMARC_FAILURE": {
            "category": "HEADER",
            "message": (
                "The email failed DMARC authentication."
            ),
        },
        "URL_IP_ADDRESS": {
            "category": "URL",
            "message": (
                "The email contains a URL that uses an IP address "
                "instead of a domain name."
            ),
        },
        "URL_UNUSUAL_PORT": {
            "category": "URL",
            "message": (
                "The email contains a URL using an unusual "
                "network port."
            ),
        },
        "URL_SUSPICIOUS_CHARACTERS": {
            "category": "URL",
            "message": (
                "The email contains a URL with suspicious "
                "characters that may obscure its destination."
            ),
        },
        "URL_ENCODING": {
            "category": "URL",
            "message": (
                "The email contains a URL with encoded characters "
                "that may obscure its destination."
            ),
        },
        "ATTACHMENT_DANGEROUS_EXTENSION": {
            "category": "ATTACHMENT",
            "message": (
                "The email contains an attachment with a potentially "
                "dangerous file extension."
            ),
        },
        "ATTACHMENT_DOUBLE_EXTENSION": {
            "category": "ATTACHMENT",
            "message": (
                "The email contains an attachment with a double "
                "file extension, which may disguise its true type."
            ),
        },
        "ATTACHMENT_MIME_MISMATCH": {
            "category": "ATTACHMENT",
            "message": (
                "The email contains an attachment whose filename "
                "extension does not match its MIME type."
            ),
        },
        "ATTACHMENT_UNUSUAL_FILENAME": {
            "category": "ATTACHMENT",
            "message": (
                "The email contains an attachment with an unusual "
                "filename."
            ),
        },
    }

    EXPLANATION_CATEGORY_ORDER = {
        "HEADER": 0,
        "URL": 1,
        "ATTACHMENT": 2,
    }

    def explain_rule(
        self,
        rule_result: RuleResult,
    ) -> Explanation | None:
        """Return an explanation for a triggered known rule."""

        if not rule_result.triggered:
            return None

        rule_definition = self.RULE_EXPLANATIONS.get(
            rule_result.rule_id
        )

        if rule_definition is None:
            return None

        return Explanation(
            rule_id=rule_result.rule_id,
            category=rule_definition["category"],
            message=rule_definition["message"],
            observations=list(rule_result.observations),
        )

    @staticmethod
    def explain_ml_probability(
        probability: float,
    ) -> Explanation:
        """Create a human-readable explanation for ML probability."""

        if not 0.0 <= probability <= 1.0:
            raise ValueError(
                "ML phishing probability must be between 0.0 and 1.0."
            )

        percentage = probability * 100.0

        if probability < 0.30:
            level = "low"
        elif probability < 0.70:
            level = "moderate"
        else:
            level = "high"

        return Explanation(
            rule_id="ML_MODEL",
            category="ML",
            message=(
                f"The ML classifier assigned a {level} "
                f"phishing probability of {percentage:.1f}%."
            ),
            observations=[
                f"ml_phishing_probability={probability:.6f}"
            ],
        )

    def _sort_explanations(
        self,
        explanations: list[Explanation],
    ) -> list[Explanation]:
        """Return explanations in deterministic category/rule order."""

        rule_order = {
            rule_id: index
            for index, rule_id in enumerate(
                self.RULE_EXPLANATIONS
            )
        }

        return sorted(
            explanations,
            key=lambda explanation: (
                self.EXPLANATION_CATEGORY_ORDER.get(
                    explanation.category,
                    len(self.EXPLANATION_CATEGORY_ORDER),
                ),
                rule_order.get(
                    explanation.rule_id,
                    len(rule_order),
                ),
            ),
        )

    def generate_explanation(
        self,
        risk_score: float,
        ml_phishing_probability: float,
        rule_results: list[RuleResult],
    ) -> ExplainabilityResult:
        """Generate a combined explanation result."""

        ml_explanation = self.explain_ml_probability(
            ml_phishing_probability
        )

        rule_explanations = []

        for rule_result in rule_results:
            explanation = self.explain_rule(rule_result)

            if explanation is not None:
                rule_explanations.append(explanation)

        ordered_rule_explanations = self._sort_explanations(
            rule_explanations
        )

        explanations = [
            ml_explanation,
            *ordered_rule_explanations,
        ]

        return ExplainabilityResult(
            risk_score=risk_score,
            ml_phishing_probability=ml_phishing_probability,
            explanations=explanations,
        )