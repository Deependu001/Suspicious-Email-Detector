from app.models.explainability_models import Explanation
from app.models.rule_models import RuleResult


class ExplainabilityService:
    """Convert triggered rule results into human-readable explanations."""

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

    def explain_rule(self, rule_result: RuleResult) -> Explanation | None:
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