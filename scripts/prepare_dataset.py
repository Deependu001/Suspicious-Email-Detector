from pathlib import Path

import pandas as pd


RAW_DATASET_PATH = Path("data/raw/CEAS_08.csv")
OUTPUT_DATASET_PATH = Path("data/dataset/emails.csv")

LABEL_MAPPING = {
    0: "legitimate",
    1: "phishing",
}


def prepare_dataset() -> None:
    """Prepare the standardized email dataset from the raw CEAS-08 dataset."""

    if not RAW_DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Raw dataset not found: {RAW_DATASET_PATH}"
        )

    dataframe = pd.read_csv(
        RAW_DATASET_PATH,
        usecols=["subject", "body", "label"],
    )

    dataframe["subject"] = dataframe["subject"].fillna("").astype(str)
    dataframe["body"] = dataframe["body"].fillna("").astype(str)

    dataframe = dataframe[
        dataframe["body"].str.strip() != ""
    ].copy()

    unknown_labels = set(dataframe["label"].unique()) - set(LABEL_MAPPING)

    if unknown_labels:
        raise ValueError(
            f"Unexpected labels found in dataset: {sorted(unknown_labels)}"
        )

    dataframe["label"] = dataframe["label"].map(LABEL_MAPPING)

    dataframe["source"] = "CEAS-08"
    dataframe["file_path"] = str(RAW_DATASET_PATH)

    dataframe.insert(
        0,
        "email_id",
        [
            f"ceas08-{index:05d}"
            for index in range(1, len(dataframe) + 1)
        ],
    )

    dataframe = dataframe[
        [
            "email_id",
            "source",
            "label",
            "subject",
            "body",
            "file_path",
        ]
    ]

    dataframe = dataframe.drop_duplicates(
        subset=["subject", "body", "label"]
    ).reset_index(drop=True)

    dataframe["email_id"] = [
        f"ceas08-{index:05d}"
        for index in range(1, len(dataframe) + 1)
    ]

    OUTPUT_DATASET_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    dataframe.to_csv(
        OUTPUT_DATASET_PATH,
        index=False,
    )

    print("Dataset preparation completed.")
    print(f"Input: {RAW_DATASET_PATH}")
    print(f"Output: {OUTPUT_DATASET_PATH}")
    print(f"Rows written: {len(dataframe)}")
    print("\nLabel distribution:")
    print(dataframe["label"].value_counts())
    print("\nMissing values:")
    print(dataframe.isna().sum())


if __name__ == "__main__":
    prepare_dataset()