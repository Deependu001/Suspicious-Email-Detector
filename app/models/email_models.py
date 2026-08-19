from typing import List, Optional

from pydantic import BaseModel, Field


class EmailAttachment(BaseModel):
    """
    Metadata about an email attachment.

    The actual attachment content is intentionally not stored here.
    At this stage we only collect metadata useful for later analysis.
    """

    filename: Optional[str] = None
    content_type: Optional[str] = None
    size_bytes: Optional[int] = None
    content_disposition: Optional[str] = None


class EmailAuthenticationHeaders(BaseModel):
    """
    Authentication-related headers extracted from the email.

    These values represent headers that were present in the email.
    They are NOT independently verified by our application.
    """

    authentication_results: List[str] = Field(default_factory=list)
    received_spf: List[str] = Field(default_factory=list)
    dkim_signature: List[str] = Field(default_factory=list)
    arc_authentication_results: List[str] = Field(default_factory=list)
    arc_message_signature: List[str] = Field(default_factory=list)
    arc_seal: List[str] = Field(default_factory=list)


class EmailData(BaseModel):
    """
    Structured representation of a parsed email.

    This model represents extracted email information only.
    It does not determine whether the email is legitimate or malicious.
    """

    sender: Optional[str] = None
    recipients: List[str] = Field(default_factory=list)
    cc: List[str] = Field(default_factory=list)
    bcc: List[str] = Field(default_factory=list)

    subject: Optional[str] = None
    date: Optional[str] = None

    reply_to: Optional[str] = None
    message_id: Optional[str] = None
    return_path: Optional[str] = None

    content_type: Optional[str] = None
    mime_version: Optional[str] = None
    is_multipart: bool = False

    plain_text_body: Optional[str] = None
    html_body: Optional[str] = None

    urls: List[str] = Field(default_factory=list)

    attachments: List[EmailAttachment] = Field(default_factory=list)

    authentication: EmailAuthenticationHeaders = Field(
        default_factory=EmailAuthenticationHeaders
    )

    headers: dict[str, List[str]] = Field(default_factory=dict)

    normalized_headers: dict[str, List[str]] = Field(
        default_factory=dict
    )