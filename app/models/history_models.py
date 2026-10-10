from typing import Any

from pydantic import BaseModel, Field


class AnalysisHistorySummary(BaseModel):
    """Summary of an analysis stored in history."""

    id: str
    analyzed_at: str
    sender: str | None = None
    subject: str | None = None
    risk_score: float
    ml_phishing_probability: float


class AnalysisHistoryRecord(AnalysisHistorySummary):
    """A saved analysis record with sanitized analysis findings."""

    result: dict[str, Any] = Field(default_factory=dict)


class AnalysisHistoryList(BaseModel):
    """Response containing recent analysis history."""

    items: list[AnalysisHistorySummary] = Field(default_factory=list)
    total: int = 0