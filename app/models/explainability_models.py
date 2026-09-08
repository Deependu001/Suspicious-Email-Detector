from pydantic import BaseModel, Field


class Explanation(BaseModel):
    """Human-readable explanation for a triggered detection rule."""

    rule_id: str
    category: str
    message: str
    observations: list[str] = Field(default_factory=list)


class ExplainabilityResult(BaseModel):
    """Structured explainability output for an evaluated email."""

    risk_score: float
    ml_phishing_probability: float
    explanations: list[Explanation] = Field(
        default_factory=list
    )