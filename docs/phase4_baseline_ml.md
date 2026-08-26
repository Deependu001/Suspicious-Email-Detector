# Phase 4 - Baseline ML

## Objective

Build and evaluate a baseline phishing email classifier using only email subject and body text.

## Pipeline

Subject + Body
    |
    v
TF-IDF
    |
    v
Logistic Regression
    |
    v
Prediction + Phishing Probability

## Dataset

The processed dataset was split into:

- Training: 27,407 emails
- Validation: 5,873 emails
- Test: 5,874 emails

Labels:

- `legitimate`
- `phishing`

The test set was kept separate until final evaluation.

## Model

The baseline model uses:

- `TfidfVectorizer`
- `LogisticRegression`
- `random_state=42`
- `max_iter=1000`

The complete trained pipeline was saved as:

`models/baseline_tfidf_logistic_regression.joblib`

## Validation Results

| Metric | Result |
|---|---:|
| Accuracy | 99.30% |
| Precision | 99.27% |
| Recall | 99.48% |
| F1 Score | 99.37% |
| ROC-AUC | 99.96% |

### Validation Confusion Matrix

| Actual / Predicted | Legitimate | Phishing |
|---|---:|---:|
| Legitimate | 2,573 | 24 |
| Phishing | 17 | 3,259 |

## Final Test Results

The saved baseline model was evaluated once against the held-out test dataset.

| Metric | Result |
|---|---:|
| Accuracy | 99.27% |
| Precision | 99.12% |
| Recall | 99.57% |
| F1 Score | 99.35% |
| ROC-AUC | 99.97% |

### Final Test Confusion Matrix

| Actual / Predicted | Legitimate | Phishing |
|---|---:|---:|
| Legitimate | 2,568 | 29 |
| Phishing | 14 | 3,263 |

## Interpretation

The baseline model demonstrates strong performance using only subject and body text.

The final test recall of 99.57% means that the model correctly identified the vast majority of phishing emails in the held-out test set.

The baseline also produced a final ROC-AUC of 99.97%, indicating strong separation between legitimate and phishing emails on this dataset.

These results represent the baseline ML component only. They do not represent the final suspicious-email detection system.

Later phases will add additional analysis components such as:

- URL analysis
- Sender and Reply-To analysis
- Header and authentication analysis
- Attachment analysis
- Rule-based detection
- Combined risk scoring
- Explainability
- API and dashboard integration

## Verification

The complete project test suite passed:

`30 passed, 1 warning`

The warning is an existing Starlette/httpx deprecation warning and did not cause test failure.

## Phase 4 Status

**Complete - Baseline ML implemented, evaluated, tested, and documented.**
