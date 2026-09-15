from app.models.email_models import EmailData
from app.models.pipeline_models import PipelineResult
from app.models.scoring_models import ScoringInput
from app.services.attachment_analyzer import AttachmentAnalyzer
from app.services.explainability_service import ExplainabilityService
from app.services.header_analyzer import HeaderAnalyzer
from app.services.ml_inference_service import MLInferenceService
from app.services.rule_engine import RuleEngine
from app.services.scoring_service import ScoringService
from app.services.url_analyzer import URLAnalyzer


class UnifiedPipeline:
    """Orchestrate the complete email detection workflow."""

    def __init__(
        self,
        ml_inference_service: MLInferenceService | None = None,
        url_analyzer: URLAnalyzer | None = None,
        header_analyzer: HeaderAnalyzer | None = None,
        attachment_analyzer: AttachmentAnalyzer | None = None,
        rule_engine: RuleEngine | None = None,
        scoring_service: ScoringService | None = None,
        explainability_service: ExplainabilityService | None = None,
    ) -> None:
        self.ml_inference_service = (
            ml_inference_service or MLInferenceService()
        )
        self.url_analyzer = url_analyzer or URLAnalyzer()
        self.header_analyzer = header_analyzer or HeaderAnalyzer()
        self.attachment_analyzer = (
            attachment_analyzer or AttachmentAnalyzer()
        )
        self.rule_engine = rule_engine or RuleEngine()
        self.scoring_service = scoring_service or ScoringService()
        self.explainability_service = (
            explainability_service or ExplainabilityService()
        )

    def analyze(self, email: EmailData) -> PipelineResult:
        """Run the complete email detection pipeline."""

        if not isinstance(email, EmailData):
            raise TypeError("email must be an EmailData instance.")

        ml_phishing_probability = (
            self.ml_inference_service.predict_phishing_probability(email)
        )

        url_analyses = [
            self.url_analyzer.analyze(url)
            for url in email.urls
        ]

        header_analysis = self.header_analyzer.analyze(email)

        attachment_analysis = self.attachment_analyzer.analyze(email)

        rule_results = self.rule_engine.evaluate(
            email=email,
            url_analyses=url_analyses,
            header_analysis=header_analysis,
            attachment_analysis=attachment_analysis,
        )

        risk_score = self.scoring_service.calculate(
            ScoringInput(
                ml_phishing_probability=ml_phishing_probability,
                rule_results=rule_results,
            )
        )

        explainability = (
            self.explainability_service.generate_explanation(
                risk_score=risk_score,
                ml_phishing_probability=ml_phishing_probability,
                rule_results=rule_results,
            )
        )

        return PipelineResult(
            email=email,
            ml_phishing_probability=ml_phishing_probability,
            url_analyses=url_analyses,
            header_analysis=header_analysis,
            attachment_analysis=attachment_analysis,
            rule_results=rule_results,
            risk_score=risk_score,
            explainability=explainability,
        )