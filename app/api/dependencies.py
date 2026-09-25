from app.services.unified_pipeline import UnifiedPipeline


def get_unified_pipeline() -> UnifiedPipeline:
    """Provide the unified email detection pipeline to FastAPI routes."""
    return UnifiedPipeline()
