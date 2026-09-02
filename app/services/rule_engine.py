from app.models.attachment_models import AttachmentAnalysis
from app.models.email_models import EmailData
from app.models.header_models import HeaderAnalysis
from app.models.rule_models import RuleResult
from app.models.url_models import URLAnalysis


class RuleEngine:
    """Evaluate deterministic rules against existing email analysis results."""

    def evaluate(
        self,
        email: EmailData,
        url_analyses: list[URLAnalysis],
        header_analysis: HeaderAnalysis,
        attachment_analysis: AttachmentAnalysis,
    ) -> list[RuleResult]:
        """Evaluate all Phase 8 rules and return structured results."""

        # `email` is part of the contract so the rule engine can work
        # with the complete parsed email context. Current rules operate
        # on the dedicated analysis models.
        _ = email

        results: list[RuleResult] = []

        results.extend(self._evaluate_header_rules(header_analysis))
        results.extend(self._evaluate_url_rules(url_analyses))
        results.extend(self._evaluate_attachment_rules(attachment_analysis))

        return results

    def _evaluate_header_rules(
        self,
        analysis: HeaderAnalysis,
    ) -> list[RuleResult]:
        """Evaluate deterministic header-related rules."""

        results = []

        results.append(
            RuleResult(
                rule_id="HEADER_FROM_REPLY_TO_MISMATCH",
                description="From and Reply-To domains differ",
                triggered=analysis.from_reply_to_domain_mismatch,
                observations=self._domain_mismatch_observations(
                    "from_domain",
                    analysis.from_domain,
                    "reply_to_domain",
                    analysis.reply_to_domain,
                ),
            )
        )

        results.append(
            RuleResult(
                rule_id="HEADER_FROM_RETURN_PATH_MISMATCH",
                description="From and Return-Path domains differ",
                triggered=analysis.from_return_path_domain_mismatch,
                observations=self._domain_mismatch_observations(
                    "from_domain",
                    analysis.from_domain,
                    "return_path_domain",
                    analysis.return_path_domain,
                ),
            )
        )

        spf_failures = self._failed_statuses(analysis.spf_statuses)
        results.append(
            RuleResult(
                rule_id="HEADER_SPF_FAILURE",
                description="An observed SPF authentication result is fail",
                triggered=bool(spf_failures),
                observations=[
                    f"spf_status={status}" for status in spf_failures
                ],
            )
        )

        dkim_failures = self._failed_statuses(analysis.dkim_statuses)
        results.append(
            RuleResult(
                rule_id="HEADER_DKIM_FAILURE",
                description="An observed DKIM authentication result is fail",
                triggered=bool(dkim_failures),
                observations=[
                    f"dkim_status={status}" for status in dkim_failures
                ],
            )
        )

        dmarc_failures = self._failed_statuses(analysis.dmarc_statuses)
        results.append(
            RuleResult(
                rule_id="HEADER_DMARC_FAILURE",
                description="An observed DMARC authentication result is fail",
                triggered=bool(dmarc_failures),
                observations=[
                    f"dmarc_status={status}" for status in dmarc_failures
                ],
            )
        )

        return results

    def _evaluate_url_rules(
        self,
        analyses: list[URLAnalysis],
    ) -> list[RuleResult]:
        """Evaluate deterministic URL-related rules."""

        ip_urls = [
            analysis.original_url
            for analysis in analyses
            if analysis.has_ip_address
        ]

        unusual_port_urls = [
            analysis.original_url
            for analysis in analyses
            if analysis.has_unusual_port
        ]

        suspicious_character_urls = [
            analysis.original_url
            for analysis in analyses
            if analysis.has_suspicious_characters
        ]

        encoded_urls = [
            analysis.original_url
            for analysis in analyses
            if analysis.has_encoding
        ]

        return [
            RuleResult(
                rule_id="URL_IP_ADDRESS",
                description="A URL uses an IP address as its hostname",
                triggered=bool(ip_urls),
                observations=[
                    f"url={url}" for url in ip_urls
                ],
            ),
            RuleResult(
                rule_id="URL_UNUSUAL_PORT",
                description="A URL uses an unusual port",
                triggered=bool(unusual_port_urls),
                observations=[
                    f"url={url}" for url in unusual_port_urls
                ],
            ),
            RuleResult(
                rule_id="URL_SUSPICIOUS_CHARACTERS",
                description="A URL contains suspicious characters",
                triggered=bool(suspicious_character_urls),
                observations=[
                    f"url={url}" for url in suspicious_character_urls
                ],
            ),
            RuleResult(
                rule_id="URL_ENCODING",
                description="A URL contains percent encoding",
                triggered=bool(encoded_urls),
                observations=[
                    f"url={url}" for url in encoded_urls
                ],
            ),
        ]

    def _evaluate_attachment_rules(
        self,
        analysis: AttachmentAnalysis,
    ) -> list[RuleResult]:
        """Evaluate deterministic attachment-related rules."""

        dangerous_extensions = list(analysis.dangerous_extensions)
        double_extensions = list(analysis.double_extensions)
        mime_mismatches = list(analysis.mime_mismatches)
        unusual_filenames = list(analysis.unusual_filenames)

        return [
            RuleResult(
                rule_id="ATTACHMENT_DANGEROUS_EXTENSION",
                description="An attachment uses a potentially dangerous extension",
                triggered=bool(dangerous_extensions),
                observations=[
                    f"filename={filename}"
                    for filename in dangerous_extensions
                ],
            ),
            RuleResult(
                rule_id="ATTACHMENT_DOUBLE_EXTENSION",
                description="An attachment uses a double extension",
                triggered=bool(double_extensions),
                observations=[
                    f"filename={filename}"
                    for filename in double_extensions
                ],
            ),
            RuleResult(
                rule_id="ATTACHMENT_MIME_MISMATCH",
                description="An attachment filename extension does not match its MIME type",
                triggered=bool(mime_mismatches),
                observations=[
                    f"filename={filename}"
                    for filename in mime_mismatches
                ],
            ),
            RuleResult(
                rule_id="ATTACHMENT_UNUSUAL_FILENAME",
                description="An attachment has an unusual filename",
                triggered=bool(unusual_filenames),
                observations=[
                    f"filename={filename}"
                    for filename in unusual_filenames
                ],
            ),
        ]

    @staticmethod
    def _failed_statuses(statuses: list[str]) -> list[str]:
        """Return authentication statuses whose value is exactly fail."""

        return [
            status
            for status in statuses
            if status.strip().lower() == "fail"
        ]

    @staticmethod
    def _domain_mismatch_observations(
        first_name: str,
        first_domain: str | None,
        second_name: str,
        second_domain: str | None,
    ) -> list[str]:
        """Build observations for a domain mismatch rule."""

        if not first_domain or not second_domain:
            return []

        return [
            f"{first_name}={first_domain}",
            f"{second_name}={second_domain}",
        ]