import re
from ipaddress import ip_address
from urllib.parse import unquote, urlparse

import tldextract

from app.models.url_models import URLAnalysis


class URLAnalyzer:
    """Extract security-related indicators from URLs."""

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

    SUSPICIOUS_CHARACTERS = {"@", "\\", "<", ">", '"', "'"}

    @staticmethod
    def analyze(url: str) -> URLAnalysis:
        """Analyze a URL without allowing malformed syntax to crash callers."""

        if not isinstance(url, str):
            raise TypeError("URL must be a string.")

        original_url = url.strip()

        if not original_url:
            raise ValueError("URL cannot be empty.")

        normalized_url = original_url
        suspicious_indicators: list[str] = []

        try:
            parsed = urlparse(normalized_url)
            scheme = parsed.scheme.lower() or None
            hostname = parsed.hostname.lower() if parsed.hostname else None
            path = parsed.path or None
            query = parsed.query or None
            fragment = parsed.fragment or None

            port = None
            port_is_invalid = False

            if parsed.netloc:
                try:
                    port = parsed.port
                except ValueError:
                    port_is_invalid = True

                port_text = URLAnalyzer._extract_port_text(
                    parsed.netloc,
                    hostname,
                )

                if port_text is not None:
                    if (
                        not port_text.isascii()
                        or not port_text.isdecimal()
                        or not 1 <= int(port_text) <= 65535
                    ):
                        port_is_invalid = True

            if port_is_invalid:
                suspicious_indicators.append("invalid_url_syntax")

        except ValueError:
            scheme = URLAnalyzer._extract_scheme(normalized_url)
            hostname = None
            port = None
            path = None
            query = None
            fragment = None
            port_is_invalid = False
            suspicious_indicators.append("invalid_url_syntax")

        domain = None
        registered_domain = None
        subdomain = None
        tld = None

        if hostname:
            try:
                extracted = tldextract.extract(hostname)
                domain = extracted.domain or None
                registered_domain = (
                    extracted.top_domain_under_public_suffix or None
                )
                subdomain = extracted.subdomain or None
                tld = extracted.suffix or None
            except (TypeError, ValueError):
                suspicious_indicators.append("invalid_url_syntax")

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

        indicators = URLAnalyzer._build_indicators(
            has_ip_address=has_ip_address,
            has_unusual_port=has_unusual_port,
            has_suspicious_characters=has_suspicious_characters,
            has_encoding=has_encoding,
            has_subdomain=has_subdomain,
        )

        for indicator in indicators:
            if indicator not in suspicious_indicators:
                suspicious_indicators.append(indicator)

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
    def _extract_scheme(url: str) -> str | None:
        """Recover a syntactically recognizable scheme from malformed input."""

        match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*):", url)
        return match.group(1).lower() if match else None

    @staticmethod
    def _extract_port_text(
        netloc: str,
        hostname: str | None,
    ) -> str | None:
        """Extract raw port text, including values rejected by urlparse."""

        if not hostname:
            return None

        authority = netloc.rsplit("@", 1)[-1]

        if authority.startswith("["):
            closing_bracket = authority.find("]")

            if closing_bracket == -1:
                return None

            suffix = authority[closing_bracket + 1:]

            if suffix.startswith(":"):
                return suffix[1:]

            return None

        if ":" not in authority:
            return None

        return authority.rsplit(":", 1)[1]

    @staticmethod
    def _is_ip_address(hostname: str | None) -> bool:
        if not hostname:
            return False

        try:
            ip_address(hostname)
            return True
        except ValueError:
            return False

    @staticmethod
    def _has_encoding(url: str) -> bool:
        try:
            return unquote(url) != url
        except Exception:
            return False

    @staticmethod
    def _build_indicators(
        *,
        has_ip_address: bool,
        has_unusual_port: bool,
        has_suspicious_characters: bool,
        has_encoding: bool,
        has_subdomain: bool,
    ) -> list[str]:
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
