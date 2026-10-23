import pytest

from app.services.url_analyzer import URLAnalyzer


@pytest.mark.parametrize(
    "url",
    [
        "http://[",
        "http://[invalid]/path",
        "http://example.com:99999/path",
        "http://example.com:abc/path",
    ],
)
def test_malformed_url_returns_analysis_without_raising(
    url: str,
) -> None:
    result = URLAnalyzer.analyze(url)

    assert result.original_url == url
    assert result.normalized_url == url
    assert result.url_length == len(url)
    assert "invalid_url_syntax" in result.suspicious_indicators


def test_valid_url_remains_analyzed_normally() -> None:
    result = URLAnalyzer.analyze("https://example.com/login")

    assert result.hostname == "example.com"
    assert result.scheme == "https"
    assert result.suspicious_indicators == []


def test_extremely_long_invalid_port_does_not_raise() -> None:
    url = "https://example.com:" + ("9" * 5000) + "/path"

    result = URLAnalyzer.analyze(url)

    assert result.original_url == url
    assert "invalid_url_syntax" in result.suspicious_indicators