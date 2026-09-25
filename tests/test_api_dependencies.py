from app.api.dependencies import get_unified_pipeline
from app.services.unified_pipeline import UnifiedPipeline


def test_get_unified_pipeline_returns_unified_pipeline():
    pipeline = get_unified_pipeline()

    assert isinstance(pipeline, UnifiedPipeline)
