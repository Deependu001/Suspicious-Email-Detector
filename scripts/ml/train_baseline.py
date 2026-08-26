from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

TRAIN_PATH = PROJECT_ROOT / "data" / "processed" / "train.csv"
VALIDATION_PATH = PROJECT_ROOT / "data" / "processed" / "validation.csv"

MODEL_DIR = PROJECT_ROOT / "models"
MODEL_PATH = MODEL_DIR / "baseline_tfidf_logistic_regression.joblib"


def load_dataset(path: Path) -> pd.DataFrame:
    """Load a prepared dataset from CSV."""
    return pd.read_csv(path)


def prepare_text(dataframe: pd.DataFrame) -> pd.Series:
    """Combine email subject and body into a single text feature."""
    subjects = dataframe["subject"].fillna("")
    bodies = dataframe["body"].fillna("")

    return (subjects + " " + bodies).str.strip()


def build_baseline_pipeline() -> Pipeline:
    """Build the baseline TF-IDF + Logistic Regression pipeline."""
    return Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=1000,
                    random_state=42,
                ),
            ),
        ]
    )


def evaluate_validation(
    pipeline: Pipeline,
    X_validation: pd.Series,
    y_validation: pd.Series,
) -> None:
    """Evaluate the trained model on the validation dataset."""
    predictions = pipeline.predict(X_validation)
    probabilities = pipeline.predict_proba(X_validation)

    classes = pipeline.named_steps["classifier"].classes_
    phishing_index = list(classes).index("phishing")

    phishing_probabilities = probabilities[:, phishing_index]

    accuracy = accuracy_score(y_validation, predictions)
    precision = precision_score(
        y_validation,
        predictions,
        pos_label="phishing",
    )
    recall = recall_score(
        y_validation,
        predictions,
        pos_label="phishing",
    )
    f1 = f1_score(
        y_validation,
        predictions,
        pos_label="phishing",
    )
    roc_auc = roc_auc_score(
        (y_validation == "phishing").astype(int),
        phishing_probabilities,
    )

    matrix = confusion_matrix(
        y_validation,
        predictions,
        labels=["legitimate", "phishing"],
    )

    true_negatives = matrix[0, 0]
    false_positives = matrix[0, 1]
    false_negatives = matrix[1, 0]
    true_positives = matrix[1, 1]

    legitimate_mask = y_validation == "legitimate"
    phishing_mask = y_validation == "phishing"

    average_legitimate_probability = (
        phishing_probabilities[legitimate_mask].mean()
    )
    average_phishing_probability = (
        phishing_probabilities[phishing_mask].mean()
    )

    print()
    print("Validation Results")
    print("------------------")
    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1 Score : {f1:.4f}")
    print(f"ROC-AUC  : {roc_auc:.4f}")

    print()
    print("Confusion Matrix")
    print("----------------")
    print("                 Predicted")
    print("                 Legitimate  Phishing")
    print(
        f"Actual Legitimate   {true_negatives:6d}   {false_positives:6d}"
    )
    print(
        f"Actual Phishing     {false_negatives:6d}   {true_positives:6d}"
    )

    print()
    print("ML Probability Summary")
    print("----------------------")
    print(
        f"Average phishing probability for legitimate emails: "
        f"{average_legitimate_probability:.4f}"
    )
    print(
        f"Average phishing probability for phishing emails:   "
        f"{average_phishing_probability:.4f}"
    )


def save_model(pipeline: Pipeline) -> None:
    """Save the trained baseline pipeline to the models directory."""
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)

    print()
    print("Model Saved")
    print("-----------")
    print(f"Model path: {MODEL_PATH}")
    print(f"Model size: {MODEL_PATH.stat().st_size:,} bytes")


def main() -> None:
    """Train, evaluate, and save the baseline ML model."""
    train_df = load_dataset(TRAIN_PATH)
    validation_df = load_dataset(VALIDATION_PATH)

    X_train = prepare_text(train_df)
    y_train = train_df["label"]

    X_validation = prepare_text(validation_df)
    y_validation = validation_df["label"]

    pipeline = build_baseline_pipeline()

    print("Training baseline TF-IDF + Logistic Regression model...")
    print(f"Training samples: {len(X_train)}")
    print(f"Validation samples: {len(X_validation)}")

    pipeline.fit(X_train, y_train)

    print("Training completed successfully.")

    evaluate_validation(
        pipeline,
        X_validation,
        y_validation,
    )

    save_model(pipeline)


if __name__ == "__main__":
    main()