import tldextract

from app.services.url_analyzer import URLAnalyzer


def test_analyze_standard_https_url():
    result = URLAnalyzer.analyze("https://example.com/login")

    assert result.original_url == "https://example.com/login"
    assert result.normalized_url == "https://example.com/login"
    assert result.scheme == "https"
    assert result.hostname == "example.com"
    assert result.domain == "example"
    assert result.registered_domain == "example.com"
    assert result.tld == "com"
    assert result.path == "/login"
    assert result.query is None
    assert result.fragment is None
    assert result.port is None

    assert result.has_ip_address is False
    assert result.has_unusual_port is False
    assert result.has_suspicious_characters is False
    assert result.has_encoding is False
    assert result.has_subdomain is False
    assert result.suspicious_indicators == []


def test_analysis_does_not_use_tldextract_default_cache(monkeypatch):
    """Domain extraction must work when package directories are read-only."""

    def unexpected_default_extractor(*args, **kwargs):
        raise AssertionError("The default tldextract extractor was used.")

    monkeypatch.setattr(tldextract, "extract", unexpected_default_extractor)

    result = URLAnalyzer.analyze("https://secure.example.com/login")

    assert result.registered_domain == "example.com"
    assert result.subdomain == "secure"


def test_detect_ip_address_url():
    result = URLAnalyzer.analyze("http://192.168.1.10/login")

    assert result.hostname == "192.168.1.10"
    assert result.has_ip_address is True
    assert "ip_address_url" in result.suspicious_indicators


def test_detect_ipv6_address_url():
    result = URLAnalyzer.analyze("http://[2001:db8::1]/login")

    assert result.hostname == "2001:db8::1"
    assert result.has_ip_address is True
    assert "ip_address_url" in result.suspicious_indicators


def test_detect_unusual_port():
    result = URLAnalyzer.analyze("https://example.com:8080/login")

    assert result.port == 8080
    assert result.has_unusual_port is True
    assert "unusual_port" in result.suspicious_indicators


def test_normal_port_is_not_flagged():
    result = URLAnalyzer.analyze("https://example.com:443/login")

    assert result.port == 443
    assert result.has_unusual_port is False
    assert "unusual_port" not in result.suspicious_indicators


def test_detect_suspicious_characters():
    result = URLAnalyzer.analyze(
        "https://example.com/login?user=test@example.com"
    )

    assert result.has_suspicious_characters is True
    assert "suspicious_characters" in result.suspicious_indicators


def test_detect_percent_encoding():
    result = URLAnalyzer.analyze(
        "https://example.com/login/%70%61%79%70%61%6c"
    )

    assert result.has_encoding is True
    assert "encoded_url" in result.suspicious_indicators


def test_detect_subdomain():
    result = URLAnalyzer.analyze(
        "https://secure.login.example.com/account"
    )

    assert result.subdomain == "secure.login"
    assert result.has_subdomain is True
    assert "subdomain_present" in result.suspicious_indicators


def test_extract_query_and_fragment():
    result = URLAnalyzer.analyze(
        "https://example.com/login?token=abc123#section"
    )

    assert result.path == "/login"
    assert result.query == "token=abc123"
    assert result.fragment == "section"


def test_url_length_is_calculated():
    url = "https://example.com/login"

    result = URLAnalyzer.analyze(url)

    assert result.url_length == len(url)


def test_url_is_stripped_before_analysis():
    result = URLAnalyzer.analyze("  https://example.com/login  ")

    assert result.original_url == "https://example.com/login"
    assert result.normalized_url == "https://example.com/login"


def test_combined_url_indicators():
    result = URLAnalyzer.analyze(
        "http://192.168.1.10:8080/login/%70%61%79%70%61%6c"
    )

    assert result.has_ip_address is True
    assert result.has_unusual_port is True
    assert result.has_encoding is True

    assert "ip_address_url" in result.suspicious_indicators
    assert "unusual_port" in result.suspicious_indicators
    assert "encoded_url" in result.suspicious_indicators


def test_empty_url_is_rejected():
    try:
        URLAnalyzer.analyze("")
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert str(exc) == "URL cannot be empty."


def test_non_string_url_is_rejected():
    try:
        URLAnalyzer.analyze(None)
        assert False, "Expected TypeError"
    except TypeError as exc:
        assert str(exc) == "URL must be a string."
