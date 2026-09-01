from typing import List, Optional

from pydantic import BaseModel, Field


class AttachmentAnalysisItem(BaseModel):
    """
    Descriptive analysis results for a single email attachment.

    This model contains observations derived from attachment metadata
    already extracted by the Phase 2 email parser.

    It does not calculate risk, determine a verdict, or inspect the
    actual attachment contents.
    """

    filename: Optional[str] = None
    extension: Optional[str] = None
    content_type: Optional[str] = None

    has_filename: bool = False
    has_extension: bool = False

    is_double_extension: bool = False
    is_potentially_dangerous_extension: bool = False
    is_filename_mime_mismatch: bool = False

    size_bytes: Optional[int] = None


class AttachmentAnalysis(BaseModel):
    """
    Descriptive attachment-analysis results for an email.

    The model summarizes attachment metadata and observations derived
    from the attachments extracted by the Phase 2 email parser.

    This phase does not calculate risk, determine a final verdict,
    invoke the machine-learning model, or generate explanations.
    """

    attachment_present: bool = False
    attachment_count: int = 0

    attachments: List[AttachmentAnalysisItem] = Field(
        default_factory=list
    )

    dangerous_extensions: List[str] = Field(
        default_factory=list
    )

    double_extensions: List[str] = Field(
        default_factory=list
    )

    mime_mismatches: List[str] = Field(
        default_factory=list
    )

    unusual_filenames: List[str] = Field(
        default_factory=list
    )