from ipaddress import ip_address
from urllib.parse import urlparse, unquote

import tldextract

from app.models.url_models import URLAnalysis


class URLAnalyzer:
    """
    Analyze structural and security-related characteristics of URLs.

    This component extracts URL features and indicators only.
    It does not assign a phishing score, verdict, or final risk level.
    """

    UNUSUAL_PORTS = {
        21,
        22,
        23,
        25,
        110,
        143,
        445,
        3389,
        5900,
        8080,
        8443,
    }

    SUSPICIOUS_CHARACTERS = {
        "@",
        "\\",
        "<",
        ">",
        '"',
        "'",
    }

    @staticmethod
    def analyze(url: str) -> URLAnalysis:
        """
        Analyze a single URL and return structured URL characteristics.
        """

        if not isinstance(url, str):
            raise TypeError("URL must be a string.")

        original_url = url.strip()

        if not original_url:
            raise ValueError("URL cannot be empty.")

        normalized_url = original_url

        parsed = urlparse(normalized_url)

        scheme = parsed.scheme.lower() or None
        hostname = parsed.hostname.lower() if parsed.hostname else None

        port = None

        try:
            port = parsed.port
        except ValueError:
            port = None

        path = parsed.path or None
        query = parsed.query or None
        fragment = parsed.fragment or None

        domain = None
        registered_domain = None
        subdomain = None
        tld = None

        if hostname:
            extracted = tldextract.extract(hostname)

            domain = extracted.domain or None
            registered_domain = (
                extracted.top_domain_under_public_suffix or None
            )
            subdomain = extracted.subdomain or None
            tld = extracted.suffix or None

        has_ip_address = URLAnalyzer._is_ip_address(hostname)

        has_unusual_port = (
            port is not None and port in URLAnalyzer.UNUSUAL_PORTS
        )

        has_suspicious_characters = any(
            character in original_url
            for character in URLAnalyzer.SUSPICIOUS_CHARACTERS
        )

        has_encoding = URLAnalyzer._has_encoding(original_url)

        has_subdomain = bool(subdomain)

        suspicious_indicators = URLAnalyzer._build_indicators(
            has_ip_address=has_ip_address,
            has_unusual_port=has_unusual_port,
            has_suspicious_characters=has_suspicious_characters,
            has_encoding=has_encoding,
            has_subdomain=has_subdomain,
        )

        return URLAnalysis(
            original_url=original_url,
            normalized_url=normalized_url,
            scheme=scheme,
            hostname=hostname,
            port=port,
            domain=domain,
            registered_domain=registered_domain,
            subdomain=subdomain,
            tld=tld,
            path=path,
            query=query,
            fragment=fragment,
            url_length=len(normalized_url),
            has_ip_address=has_ip_address,
            has_unusual_port=has_unusual_port,
            has_suspicious_characters=has_suspicious_characters,
            has_encoding=has_encoding,
            has_subdomain=has_subdomain,
            suspicious_indicators=suspicious_indicators,
        )

    @staticmethod
    def _is_ip_address(hostname: str | None) -> bool:
        """
        Determine whether the hostname is an IPv4 or IPv6 address.
        """

        if not hostname:
            return False

        try:
            ip_address(hostname)
            return True
        except ValueError:
            return False

    @staticmethod
    def _has_encoding(url: str) -> bool:
        """
        Detect percent-encoded content in a URL.

        The URL is considered encoded when percent-decoding changes
        its content.
        """

        try:
            return unquote(url) != url
        except Exception:
            return False

    @staticmethod
    def _build_indicators(
        has_ip_address: bool,
        has_unusual_port: bool,
        has_suspicious_characters: bool,
        has_encoding: bool,
        has_subdomain: bool,
    ) -> list[str]:
        """
        Build descriptive URL indicators from extracted characteristics.

        These are descriptive signals only. No risk score is assigned.
        """

        indicators = []

        if has_ip_address:
            indicators.append("ip_address_url")

        if has_unusual_port:
            indicators.append("unusual_port")

        if has_suspicious_characters:
            indicators.append("suspicious_characters")

        if has_encoding:
            indicators.append("encoded_url")

        if has_subdomain:
            indicators.append("subdomain_present")

        return indicators