from pathlib import Path

import pandas as pd


DATASET_PATH = Path("data/dataset/emails.csv")

EXPECTED_COLUMNS = [
    "email_id",
    "source",
    "label",
    "subject",
    "body",
    "file_path",
]

EXPECTED_LABELS = {
    "legitimate",
    "phishing",
}


def load_dataset() -> pd.DataFrame:
    """Load the prepared email dataset."""
    assert DATASET_PATH.exists(), (
        f"Dataset not found: {DATASET_PATH}"
    )

    return pd.read_csv(DATASET_PATH)


def test_dataset_has_expected_structure():
    """Verify the dataset contains the expected columns and rows."""
    dataframe = load_dataset()

    assert not dataframe.empty
    assert dataframe.columns.tolist() == EXPECTED_COLUMNS


def test_dataset_labels_are_valid():
    """Verify labels are present and use the expected classes."""
    dataframe = load_dataset()

    assert dataframe["label"].notna().all()
    assert set(dataframe["label"].unique()) == EXPECTED_LABELS


def test_dataset_has_no_empty_bodies():
    """Verify every dataset record contains email body text."""
    dataframe = load_dataset()

    assert dataframe["body"].notna().all()
    assert (dataframe["body"].str.strip() != "").all()


def test_dataset_has_unique_email_ids():
    """Verify every email has a unique identifier."""
    dataframe = load_dataset()

    assert dataframe["email_id"].notna().all()
    assert dataframe["email_id"].is_unique


def test_dataset_has_no_cross_label_duplicate_content():
    """Verify identical subject/body content has only one label."""
    dataframe = load_dataset()

    content_key = (
        dataframe["subject"].fillna("").str.strip()
        + "||"
        + dataframe["body"].fillna("").str.strip()
    )

    labels_per_content = (
        dataframe.assign(content_key=content_key)
        .groupby("content_key")["label"]
        .nunique()
    )

    assert (labels_per_content > 1).sum() == 0