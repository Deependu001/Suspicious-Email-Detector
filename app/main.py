import sqlite3

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import ValidationError

from app.api.dependencies import (
    get_history_service,
    get_unified_pipeline,
)
from app.models.api_models import EmailAnalysisRequest
from app.models.history_models import (
    AnalysisHistoryList,
    AnalysisHistoryRecord,
)
from app.models.pipeline_models import PipelineResult
from app.services.email_parser import EmailParser
from app.services.history_service import HistoryService
from app.services.unified_pipeline import UnifiedPipeline

app = FastAPI(
    title="Explainable Suspicious Email & Phishing Detection System",
    description=(
        "API for detecting suspicious and phishing emails "
        "using machine learning and rule-based analysis."
    ),
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
    return {"status": "healthy"}


@app.post("/analyze", response_model=PipelineResult)
def analyze_email(
    request: EmailAnalysisRequest,
    pipeline: UnifiedPipeline = Depends(get_unified_pipeline),
    history_service: HistoryService = Depends(get_history_service),
) -> PipelineResult:
    """Analyze a raw email and persist its sanitized findings."""

    try:
        email = EmailParser().parse_raw_email(request.raw_email)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    result = pipeline.analyze(email)

    try:
        history_service.save_analysis(result)
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=500,
            detail="Analysis completed, but saving its history failed.",
        ) from exc

    return result


@app.get("/history", response_model=AnalysisHistoryList)
def list_analysis_history(
    limit: int = Query(default=20, ge=1, le=100),
    history_service: HistoryService = Depends(get_history_service),
) -> AnalysisHistoryList:
    """List recent analysis summaries, newest first."""

    try:
        history = history_service.list_history(limit=limit)
        return AnalysisHistoryList.model_validate(history)
    except (OSError, sqlite3.Error, ValueError, ValidationError) as exc:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve analysis history.",
        ) from exc


@app.get(
    "/history/{record_id}",
    response_model=AnalysisHistoryRecord,
)
def get_analysis_history_record(
    record_id: str,
    history_service: HistoryService = Depends(get_history_service),
) -> AnalysisHistoryRecord:
    """Retrieve one saved analysis and its sanitized findings."""

    try:
        record = history_service.get_history_record(record_id)
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve the requested history record.",
        ) from exc

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="Analysis history record not found.",
        )

    try:
        return AnalysisHistoryRecord.model_validate(record)
    except ValidationError as exc:
        raise HTTPException(
            status_code=500,
            detail="Stored analysis history record is invalid.",
        ) from exc
