import re
from email.utils import parseaddr

from app.models.email_models import EmailData
from app.models.header_models import HeaderAnalysis


class HeaderAnalyzer:
    """
    Analyze security-relevant email header characteristics.

    This component produces descriptive header observations only.
    It does not calculate risk, determine a verdict, or modify the
    original parsed email data.
    """

    AUTHENTICATION_HEADERS = {
        "authentication-results": "authentication_results_present",
        "received-spf": "received_spf_present",
        "dkim-signature": "dkim_signature_present",
        "arc-authentication-results": "arc_authentication_results_present",
        "arc-message-signature": "arc_message_signature_present",
        "arc-seal": "arc_seal_present",
    }

    @staticmethod
    def analyze(email: EmailData) -> HeaderAnalysis:
        """
        Analyze header-derived security characteristics from EmailData.
        """

        from_domain = HeaderAnalyzer._extract_domain(email.sender)
        reply_to_domain = HeaderAnalyzer._extract_domain(email.reply_to)
        return_path_domain = HeaderAnalyzer._extract_domain(email.return_path)

        normalized_headers = email.normalized_headers

        authentication_results = (
            email.authentication.authentication_results
        )
        received_spf = email.authentication.received_spf
        dkim_signature = email.authentication.dkim_signature
        arc_authentication_results = (
            email.authentication.arc_authentication_results
        )
        arc_message_signature = email.authentication.arc_message_signature
        arc_seal = email.authentication.arc_seal

        return HeaderAnalysis(
            from_present=email.sender is not None,
            reply_to_present=email.reply_to is not None,
            return_path_present=email.return_path is not None,
            from_domain=from_domain,
            reply_to_domain=reply_to_domain,
            return_path_domain=return_path_domain,
            from_reply_to_domain_mismatch=(
                HeaderAnalyzer._domains_mismatch(
                    from_domain,
                    reply_to_domain,
                )
            ),
            from_return_path_domain_mismatch=(
                HeaderAnalyzer._domains_mismatch(
                    from_domain,
                    return_path_domain,
                )
            ),
            received_header_count=len(
                normalized_headers.get("received", [])
            ),
            authentication_results_present=bool(authentication_results),
            received_spf_present=bool(received_spf),
            dkim_signature_present=bool(dkim_signature),
            arc_authentication_results_present=bool(
                arc_authentication_results
            ),
            arc_message_signature_present=bool(arc_message_signature),
            arc_seal_present=bool(arc_seal),
            spf_statuses=HeaderAnalyzer._extract_spf_statuses(
                received_spf
            ),
            dkim_statuses=HeaderAnalyzer._extract_statuses(
                authentication_results,
                mechanism="dkim",
            ),
            dmarc_statuses=HeaderAnalyzer._extract_statuses(
                authentication_results,
                mechanism="dmarc",
            ),
        )

    @staticmethod
    def _extract_domain(address: str | None) -> str | None:
        """
        Extract the lowercase domain from an email address.
        """

        if not address:
            return None

        _, parsed_address = parseaddr(address)

        if "@" not in parsed_address:
            return None

        domain = parsed_address.rsplit("@", 1)[1].strip().lower()

        return domain or None

    @staticmethod
    def _domains_mismatch(
        first_domain: str | None,
        second_domain: str | None,
    ) -> bool:
        """
        Return True only when both domains exist and differ.
        """

        if not first_domain or not second_domain:
            return False

        return first_domain != second_domain

    @staticmethod
    def _extract_spf_statuses(values: list[str]) -> list[str]:
        """
        Extract SPF result statuses from Received-SPF headers.

        Received-SPF commonly starts with a result such as:
        pass, fail, softfail, neutral, or none.
        """

        statuses = []

        for value in values:
            match = re.match(
                r"\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
                value,
                flags=re.IGNORECASE,
            )

            if match:
                status = match.group(1).lower()

                if status not in statuses:
                    statuses.append(status)

        return statuses

    @staticmethod
    def _extract_statuses(
        values: list[str],
        mechanism: str | None = None,
    ) -> list[str]:
        """
        Extract authentication status values such as pass, fail,
        softfail, neutral, or none.

        When a mechanism is provided, only matching authentication
        mechanisms are considered.
        """

        statuses = []

        for value in values:
            text = value.lower()

            if mechanism is not None:
                pattern = (
                    rf"\b{re.escape(mechanism)}\s*=\s*([a-z]+)"
                )
            else:
                pattern = r"\bspf\s*=\s*([a-z]+)"

            matches = re.findall(pattern, text)

            for status in matches:
                if status not in statuses:
                    statuses.append(status)

        return statuses