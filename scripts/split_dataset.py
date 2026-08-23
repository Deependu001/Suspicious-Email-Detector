from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split


INPUT_DATASET_PATH = Path("data/dataset/emails.csv")
OUTPUT_DIRECTORY = Path("data/processed")

TRAIN_PATH = OUTPUT_DIRECTORY / "train.csv"
VALIDATION_PATH = OUTPUT_DIRECTORY / "validation.csv"
TEST_PATH = OUTPUT_DIRECTORY / "test.csv"

RANDOM_STATE = 42
TRAIN_SIZE = 0.70
VALIDATION_SIZE = 0.15
TEST_SIZE = 0.15


def split_dataset() -> None:
    """Create reproducible stratified train, validation, and test splits."""

    if not INPUT_DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Prepared dataset not found: {INPUT_DATASET_PATH}"
        )

    if abs(TRAIN_SIZE + VALIDATION_SIZE + TEST_SIZE - 1.0) > 1e-9:
        raise ValueError("Dataset split sizes must sum to 1.0.")

    dataframe = pd.read_csv(INPUT_DATASET_PATH)

    if dataframe.empty:
        raise ValueError("Prepared dataset is empty.")

    required_columns = {
        "email_id",
        "source",
        "label",
        "subject",
        "body",
        "file_path",
    }

    missing_columns = required_columns - set(dataframe.columns)

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {sorted(missing_columns)}"
        )

    train_dataframe, temporary_dataframe = train_test_split(
        dataframe,
        test_size=VALIDATION_SIZE + TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=dataframe["label"],
    )

    validation_relative_size = (
        VALIDATION_SIZE / (VALIDATION_SIZE + TEST_SIZE)
    )

    validation_dataframe, test_dataframe = train_test_split(
        temporary_dataframe,
        test_size=1 - validation_relative_size,
        random_state=RANDOM_STATE,
        stratify=temporary_dataframe["label"],
    )

    OUTPUT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    train_dataframe.to_csv(TRAIN_PATH, index=False)
    validation_dataframe.to_csv(VALIDATION_PATH, index=False)
    test_dataframe.to_csv(TEST_PATH, index=False)

    train_ids = set(train_dataframe["email_id"])
    validation_ids = set(validation_dataframe["email_id"])
    test_ids = set(test_dataframe["email_id"])

    if train_ids & validation_ids:
        raise ValueError("Train and validation sets contain duplicate email IDs.")

    if train_ids & test_ids:
        raise ValueError("Train and test sets contain duplicate email IDs.")

    if validation_ids & test_ids:
        raise ValueError("Validation and test sets contain duplicate email IDs.")

    if len(train_dataframe) + len(validation_dataframe) + len(test_dataframe) != len(dataframe):
        raise ValueError("Split row counts do not equal the original dataset size.")

    print("Dataset split completed.")
    print(f"Input: {INPUT_DATASET_PATH}")
    print(f"Train: {TRAIN_PATH} ({len(train_dataframe)} rows)")
    print(
        f"Validation: {VALIDATION_PATH} "
        f"({len(validation_dataframe)} rows)"
    )
    print(f"Test: {TEST_PATH} ({len(test_dataframe)} rows)")

    print("\nTrain label distribution:")
    print(train_dataframe["label"].value_counts())

    print("\nValidation label distribution:")
    print(validation_dataframe["label"].value_counts())

    print("\nTest label distribution:")
    print(test_dataframe["label"].value_counts())


if __name__ == "__main__":
    split_dataset()