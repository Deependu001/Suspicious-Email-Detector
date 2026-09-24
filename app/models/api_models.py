from pydantic import BaseModel, Field


class EmailAnalysisRequest(BaseModel):
    """Request contract for email analysis through the FastAPI layer."""

    raw_email: str = Field(
        ...,
        min_length=1,
        description="Raw RFC 5322 email content, including headers and body.",
    )
