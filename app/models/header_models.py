from typing import List, Optional

from pydantic import BaseModel, Field


class HeaderAnalysis(BaseModel):
    """
    Descriptive security-related observations derived from email headers.

    This model does not calculate risk, determine a final verdict,
    or independently verify email authentication.
    """

    from_present: bool = False
    reply_to_present: bool = False
    return_path_present: bool = False

    from_domain: Optional[str] = None
    reply_to_domain: Optional[str] = None
    return_path_domain: Optional[str] = None

    from_reply_to_domain_mismatch: bool = False
    from_return_path_domain_mismatch: bool = False

    received_header_count: int = 0

    authentication_results_present: bool = False
    received_spf_present: bool = False
    dkim_signature_present: bool = False
    arc_authentication_results_present: bool = False
    arc_message_signature_present: bool = False
    arc_seal_present: bool = False

    spf_statuses: List[str] = Field(default_factory=list)
    dkim_statuses: List[str] = Field(default_factory=list)
    dmarc_statuses: List[str] = Field(default_factory=list)