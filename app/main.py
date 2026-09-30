from fastapi import Depends, FastAPI, HTTPException

from app.api.dependencies import get_unified_pipeline
from app.models.api_models import EmailAnalysisRequest
from app.models.pipeline_models import PipelineResult
from app.services.email_parser import EmailParser
from app.services.unified_pipeline import UnifiedPipeline

app = FastAPI(
    title="Explainable Suspicious Email & Phishing Detection System",
    description="API for detecting suspicious and phishing emails using machine learning and rule-based analysis.",
    version="0.1.0",
)


@app.get("/")
def root():
    return {
        "message": "Suspicious Email Detection API is running",
        "status": "healthy",
        "version": "0.1.0",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


@app.post("/analyze", response_model=PipelineResult)
def analyze_email(
    request: EmailAnalysisRequest,
    pipeline: UnifiedPipeline = Depends(get_unified_pipeline),
) -> PipelineResult:
    """Analyze a raw RFC 5322 email through the unified detection pipeline."""

    try:
        email = EmailParser().parse_raw_email(request.raw_email)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    return pipeline.analyze(email)