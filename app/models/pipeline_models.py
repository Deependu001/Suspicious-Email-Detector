from pydantic import BaseModel, Field

from app.models.attachment_models import AttachmentAnalysis
from app.models.email_models import EmailData
from app.models.explainability_models import ExplainabilityResult
from app.models.header_models import HeaderAnalysis
from app.models.rule_models import RuleResult
from app.models.url_models import URLAnalysis


class PipelineResult(BaseModel):
    """Structured result produced by the unified detection pipeline."""

    email: EmailData
    ml_phishing_probability: float
    url_analyses: list[URLAnalysis] = Field(default_factory=list)
    header_analysis: HeaderAnalysis
    attachment_analysis: AttachmentAnalysis
    rule_results: list[RuleResult] = Field(default_factory=list)
    risk_score: float
    explainability: ExplainabilityResult