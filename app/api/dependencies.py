from app.services.history_service import HistoryService
from app.services.unified_pipeline import UnifiedPipeline


def get_unified_pipeline() -> UnifiedPipeline:
    """Provide the unified email detection pipeline to FastAPI routes."""
    return UnifiedPipeline()


def get_history_service() -> HistoryService:
    """Provide the SQLite history service to FastAPI routes."""
    return HistoryService()
