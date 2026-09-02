from pydantic import BaseModel, Field


class RuleResult(BaseModel):
    """Structured result produced by a single rule evaluation."""

    rule_id: str
    description: str
    triggered: bool
    observations: list[str] = Field(default_factory=list)