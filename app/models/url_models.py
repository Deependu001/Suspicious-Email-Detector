from typing import List, Optional

from pydantic import BaseModel, Field


class URLAnalysis(BaseModel):
    """
    Structured security-related analysis of a single URL.

    This model contains extracted URL characteristics and indicators.
    It does not determine whether the URL is malicious by itself.
    """

    original_url: str

    normalized_url: str

    scheme: Optional[str] = None
    hostname: Optional[str] = None
    port: Optional[int] = None

    domain: Optional[str] = None
    registered_domain: Optional[str] = None
    subdomain: Optional[str] = None
    tld: Optional[str] = None

    path: Optional[str] = None
    query: Optional[str] = None
    fragment: Optional[str] = None

    url_length: int = 0

    has_ip_address: bool = False
    has_unusual_port: bool = False
    has_suspicious_characters: bool = False
    has_encoding: bool = False
    has_subdomain: bool = False

    suspicious_indicators: List[str] = Field(default_factory=list)