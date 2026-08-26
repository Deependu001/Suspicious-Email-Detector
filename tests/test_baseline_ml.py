import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from scripts.ml.train_baseline import (
    build_baseline_pipeline,
    load_dataset,
    prepare_text,
)


def test_load_dataset():
    dataframe = pd.DataFrame(
        {
            "email_id": ["test-001", "test-002"],
            "source": ["test", "test"],
            "label": ["legitimate", "phishing"],
            "subject": ["Hello", "Important Offer"],
            "body": ["Normal message", "Click this link"],
            "file_path": ["", ""],
        }
    )

    assert isinstance(dataframe, pd.DataFrame)
    assert list(dataframe.columns) == [
        "email_id",
        "source",
        "label",
        "subject",
        "body",
        "file_path",
    ]
    assert len(dataframe) == 2


def test_prepare_text_combines_subject_and_body():
    dataframe = pd.DataFrame(
        {
            "subject": ["Hello", "Urgent Offer"],
            "body": ["Normal message", "Click this link"],
        }
    )

    result = prepare_text(dataframe)

    assert result.tolist() == [
        "Hello Normal message",
        "Urgent Offer Click this link",
    ]


def test_prepare_text_handles_missing_subject():
    dataframe = pd.DataFrame(
        {
            "subject": [None],
            "body": ["This is the email body"],
        }
    )

    result = prepare_text(dataframe)

    assert result.tolist() == [
        "This is the email body",
    ]


def test_build_baseline_pipeline():
    pipeline = build_baseline_pipeline()

    assert isinstance(pipeline, Pipeline)
    assert list(pipeline.named_steps.keys()) == [
        "tfidf",
        "classifier",
    ]

    assert isinstance(
        pipeline.named_steps["tfidf"],
        TfidfVectorizer,
    )

    assert isinstance(
        pipeline.named_steps["classifier"],
        LogisticRegression,
    )


def test_baseline_pipeline_configuration():
    pipeline = build_baseline_pipeline()

    classifier = pipeline.named_steps["classifier"]

    assert classifier.random_state == 42
    assert classifier.max_iter == 1000