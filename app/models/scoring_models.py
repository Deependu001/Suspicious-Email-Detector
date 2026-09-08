from pydantic import BaseModel, Field

from app.models.rule_models import RuleResult


class ScoringInput(BaseModel):
    """Inputs consumed by the Phase 9 combined scoring layer."""

    ml_phishing_probability: float

    rule_results: list[RuleResult] = Field(
        default_factory=list
    )


class RuleWeight(BaseModel):
    """Weight assigned to a deterministic rule."""

    rule_id: str
    weight: float


class ScoringWeights(BaseModel):
    """Configured weights used by the Phase 9 scoring layer."""

    ml_weight: float
    rule_weights: list[RuleWeight] = Field(
        default_factory=list
    )
