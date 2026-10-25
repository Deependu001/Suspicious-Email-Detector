# Explainable Suspicious Email & Phishing Detection System

An explainable cybersecurity project that combines machine learning and deterministic detection rules to assess suspicious emails and potential phishing attempts. It provides risk scoring, detection findings, a REST API, an interactive dashboard, and SQLite-based analysis history.

**Built with:** Python, scikit-learn, FastAPI, Streamlit, SQLite, and Docker.

---

## Table of Contents

* [Overview](#overview)

* [Features](#features)

* [Architecture](#architecture)

* [Detection Methodology](#detection-methodology)

* [Machine Learning Evaluation](#machine-learning-evaluation)

* [Project Structure](#project-structure)

* [Requirements](#requirements)

* [Local Installation](#local-installation)

* [Running the Application](#running-the-application)

* [Using the API](#using-the-api)

* [Analysis History](#analysis-history)

* [Docker Deployment](#docker-deployment)

* [Testing](#testing)

* [Documentation](#documentation)

* [Limitations and Security Considerations](#limitations-and-security-considerations)

* [Future Improvements](#future-improvements)

* [Resume Highlights](#resume-highlights)

* [License](#license)

## Overview

Phishing emails use deceptive messages, links, sender information, and other indicators to manipulate recipients into disclosing information or taking unsafe actions.

This project analyzes supplied email content using a machine learning classifier and complementary rule-based checks. It combines their findings into a risk score and provides human-readable explanations to help users understand why an email may be suspicious.

The application supports:

* Email analysis through a REST API.

* An interactive Streamlit dashboard.

* Machine learning predictions and deterministic detection rules.

* URL, header, and attachment-metadata analysis.

* Explainable findings and a combined risk score.

* Persistent analysis history using SQLite.

* Containerized deployment using Docker Compose.

The system is intended as a cybersecurity portfolio and learning project. Its output should support investigation rather than replace professional security analysis.

## Features

### 1. Machine Learning Classification

A scikit-learn pipeline uses TF-IDF text features and Logistic Regression to estimate the likelihood that an email is phishing-related.

The baseline model uses email subject and plain-text body content.

### 2. URL Analysis

The URL analyzer checks for suspicious structural indicators, including:

* IP addresses used as URL hosts.

* Unusual ports.

* Suspicious characters and encoding patterns.

* Other URL-structure indicators implemented by the analyzer.

These findings identify potential warning signs; they do not establish that a URL is malicious.

### 3. Email Header Analysis

The header analyzer evaluates available email-header information and supported authentication-result headers, including SPF, DKIM, and DMARC results when present.

It analyzes supplied header evidence rather than independently verifying authentication with mail servers.

### 4. Attachment Metadata Analysis

The attachment analyzer evaluates supported attachment metadata and indicators, such as potentially risky filenames or file types.

It does not execute attachments or perform full file-content malware scanning.

### 5. Rule-Based Detection

A deterministic rule engine evaluates supported indicators and produces identifiable rule findings. These findings complement the machine learning prediction.

### 6. Combined Risk Scoring

The scoring service combines the ML phishing probability with the normalized weights of unique triggered rules to produce a project-defined risk score from 0 to 100.

### 7. Explainability

The analysis response includes detection findings and supporting information so users can understand which indicators contributed to the assessment.

### 8. REST API

FastAPI exposes endpoints for health checks, email analysis, and access to saved analysis history. Interactive API documentation is available through Swagger UI.

### 9. Interactive Dashboard

The Streamlit dashboard allows users to submit raw email content and inspect the resulting score, ML probability, rule findings, URL analysis, header analysis, attachment analysis, and explanations.

### 10. Persistent History

SQLite stores analysis-history records so previous results can be retrieved through the API.

### 11. Containerization

Docker and Docker Compose define the API and dashboard services and provide persistent storage for the history database.

## Architecture

The application follows this processing flow:

```text

&#x20;                Raw Email Content

&#x20;                        |

&#x20;                        v

&#x20;                   Email Parser

&#x20;                        |

&#x20;                        v

&#x20;                 Parsed Email Data

&#x20;                        |

&#x20;           +------------+------------+

&#x20;           |            |            |

&#x20;           v            v            v

&#x20;      ML Inference   URL Analysis   Header Analysis

&#x20;           |            |            |

&#x20;           |            +------+-----+

&#x20;           |                   |

&#x20;           |            Attachment Analysis

&#x20;           |                   |

&#x20;           +---------+---------+

&#x20;                     |

&#x20;                     v

&#x20;                 Rule Engine

&#x20;                     |

&#x20;                     v

&#x20;                Risk Scoring

&#x20;                     |

&#x20;                     v

&#x20;                Explainability

&#x20;                     |

&#x20;                     v

&#x20;               Unified Pipeline

&#x20;                     |

&#x20;                     v

&#x20;                  FastAPI

&#x20;                     |

&#x20;             +-------+--------+

&#x20;             |                |

&#x20;             v                v

&#x20;      Streamlit Dashboard   SQLite History

```

The unified pipeline coordinates parsing, analysis, scoring, and explainability. FastAPI exposes the pipeline to the dashboard and other API clients.

## Detection Methodology

### Machine Learning Component

The baseline classifier uses:

* TF-IDF text vectorization.

* Logistic Regression.

* Email subject and plain-text body features.

* A trained scikit-learn pipeline saved as a Joblib model artifact.

The classifier produces a phishing probability that contributes to the combined risk score.

### Combined Risk Score

The implemented scoring formula is:

```text

Combined Score =

&#x20;   (ML Phishing Probability × 0.70)

&#x20;   + (Normalized Unique Rule Weight × 0.30)

Risk Score = clamp(Combined Score × 100, 0, 100)

```

The ML probability and normalized rule contribution are combined according to the project's scoring implementation.

**Important:** The resulting 0–100 risk score is a project-defined indicator, not a calibrated probability that an email is malicious. A high score does not prove phishing, and a low score does not guarantee safety.

The assessment should be interpreted alongside the reported findings and the limitations of the underlying model and analyzers.

## Machine Learning Evaluation

The baseline TF-IDF and Logistic Regression model was evaluated using separate validation and held-out test splits.

### Dataset Splits

| Split      | Number of samples |

| ---------- | ----------------: |

| Training   |            27,407 |

| Validation |             5,873 |

| Test       |             5,874 |

### Validation Results

| Metric    |  Score |

| --------- | -----: |

| Accuracy  | 99.30% |

| Precision | 99.27% |

| Recall    | 99.48% |

| F1-score  | 99.37% |

| ROC-AUC   | 99.96% |

### Held-Out Test Results

| Metric    |  Score |

| --------- | -----: |

| Accuracy  | 99.27% |

| Precision | 99.12% |

| Recall    | 99.57% |

| F1-score  | 99.35% |

| ROC-AUC   | 99.97% |

**Evaluation scope:** These metrics describe the baseline machine learning classifier on the evaluated dataset. They are not end-to-end performance metrics for the complete detector, which also includes URL, header, attachment-metadata, and rule-based analysis.

Performance on other datasets, real-world mail traffic, new phishing campaigns, or adversarially modified emails may differ. These results should not be interpreted as a guarantee of production detection accuracy.

## Project Structure

```text

Suspicious-Email-Detector/

├── app/

│   ├── api/

│   ├── models/

│   ├── services/

│   └── main.py

├── dashboard/

│   └── app.py

├── data/

│   ├── raw/

│   ├── dataset/

│   └── processed/

├── docs/

│   ├── phase4_baseline_ml.md

│   ├── phase5_url_analysis.md

│   ├── phase6_header_analysis.md

│   ├── phase7_attachment_analysis.md

│   ├── phase8_rule_engine.md

│   ├── phase9_combined_scoring.md

│   ├── phase10_explainability.md

│   ├── phase11_unified_pipeline.md

│   ├── phase12_fastapi.md

│   ├── phase13_dashboard.md

│   ├── phase14_sqlite_history.md

│   └── phase16_docker_deployment.md

├── models/

│   └── baseline_tfidf_logistic_regression.joblib

├── notebooks/

├── scripts/

├── tests/

├── .dockerignore

├── .gitignore

├── compose.yaml

├── Dockerfile

├── Dockerfile.dashboard

├── README.md

└── requirements.txt

```

The tree highlights the principal application components. Individual files and subdirectories may vary as the project evolves.

## Requirements

For local development:

* Python 3.13, matching the development environment used for this project.

* pip.

* Git.

* The repository's trained model artifact.

* A Windows PowerShell terminal or another compatible shell.

For containerized deployment:

* Docker Desktop or another working Docker Engine.

* Docker Compose.

## Local Installation

The following commands assume Windows PowerShell and the repository directory:

`E:\\GITHUB\\Suspicious-Email-Detector`

### 1. Clone the repository

If you have not already cloned it:

```powershell

git clone https://github.com/Deependu001/Suspicious-Email-Detector.git

Set-Location .\\Suspicious-Email-Detector

```

If you are already working in the repository, skip this step.

### 2. Create a virtual environment

```powershell

py -3.13 -m venv .venv

```

### 3. Activate the environment

```powershell

.\\.venv\\Scripts\\Activate.ps1

```

### 4. Install dependencies

```powershell

python -m pip install --upgrade pip

python -m pip install -r requirements.txt

```

### 5. Verify the model artifact

Check that the trained model exists:

```powershell

Test-Path .\\models\\baseline_tfidf_logistic_regression.joblib

```

The command should return `True`. If it returns `False`, the application may be unable to load the baseline classifier.

## Running the Application

Run the API and dashboard in separate PowerShell terminals. Activate the project's virtual environment in each terminal.

### Terminal 1: Start FastAPI

From the repository root:

```powershell

.\\.venv\\Scripts\\Activate.ps1

python -m uvicorn app.main:app --reload

```

The API will normally be available at:

* API root: `http://127.0.0.1:8000/`

* Health check: `http://127.0.0.1:8000/health`

* Swagger UI: `http://127.0.0.1:8000/docs`

### Terminal 2: Start Streamlit

```powershell

Set-Location "E:\\GITHUB\\Suspicious-Email-Detector"

.\\.venv\\Scripts\\Activate.ps1

$env:EMAIL_DETECTOR_API_URL = "http://127.0.0.1:8000"

python -m streamlit run dashboard/app.py

```

The dashboard will normally be available at:

`http://localhost:8501`

The `EMAIL_DETECTOR_API_URL` environment variable allows the dashboard to target a different API address when required.

### Configure the SQLite Database Path

By default, the application uses:

`data/history.sqlite3`

To specify a different database path, set the environment variable before starting the API:

```powershell

$env:EMAIL_DETECTOR_DATABASE_PATH = "data/history.sqlite3"

python -m uvicorn app.main:app --reload

```

Use an appropriate writable path for your environment. Database initialization and persistence depend on the application's configured database implementation.

## Using the API

The API accepts raw email content for analysis and exposes saved analysis history.

### Available Endpoints

| Method | Endpoint               | Purpose                          |

| ------ | ---------------------- | -------------------------------- |

| `GET`  | `/`                    | API root and application status  |

| `GET`  | `/health`              | Health check                     |

| `POST` | `/analyze`             | Analyze raw email content        |

| `GET`  | `/history`             | List saved analysis records      |

| `GET`  | `/history/{record_id}` | Retrieve a saved analysis record |

### Analyze an Email

Send a JSON request to `POST /analyze` with a `raw_email` field.

Example using Python and `requests`:

```python

import requests

raw_email = """From: Security Team <security@example.com>

To: recipient@example.net

Subject: Example email for analysis

MIME-Version: 1.0

Content-Type: text/plain; charset="utf-8"

This is an example message for testing the email analysis pipeline.

"""

response = requests.post(

&#x20;   "http://127.0.0.1:8000/analyze",

&#x20;   json={"raw_email": raw_email},

&#x20;   timeout=60,

)

response.raise_for_status()

result = response.json()

print(result)

```

Replace the example email with content you are authorized to analyze.

The response includes the parsed email information and the pipeline's analysis results, including ML probability, URL analysis, header analysis, attachment analysis, triggered rules, risk score, and explainability information as defined by the response schema.

For the exact request and response models, open:

`http://127.0.0.1:8000/docs`

### Retrieve Analysis History

List recent records:

```python

import requests

response = requests.get(

&#x20;   "http://127.0.0.1:8000/history",

&#x20;   params={"limit": 20},

&#x20;   timeout=30,

)

response.raise_for_status()

print(response.json())

```

The `limit` parameter accepts values from 1 to 100 and defaults to 20.

Retrieve one record using its ID:

```python

import requests

record_id = 1

response = requests.get(

&#x20;   f"http://127.0.0.1:8000/history/{record_id}",

&#x20;   timeout=30,

)

response.raise_for_status()

print(response.json())

```

Use an actual record ID returned by your API. The example ID is illustrative.

## Analysis History

The application uses SQLite to persist analysis history.

The default database location is:

```text

data/history.sqlite3

```

The database path can be configured with `EMAIL_DETECTOR_DATABASE_PATH`.

The history API provides access to saved analysis records. The implementation sanitizes selected fields before storing history data, including omitting the full parsed email and redacting URL paths, query strings, and fragments.

However, **history storage is not completely anonymous**: summary records retain sender and subject information. Treat the database as potentially sensitive, restrict access to it, and avoid submitting real confidential emails unless you have authorization and an appropriate data-handling arrangement.

For implementation details, see [`docs/phase14_sqlite_history.md`](docs/phase14_sqlite_history.md).

## Docker Deployment

The repository includes Dockerfiles for the API and dashboard and a Docker Compose configuration for running the services together.

### Prerequisites

Ensure Docker Desktop is running and that its Docker Engine is accessible before running these commands.

Verify Docker availability:

```powershell

docker --version

docker compose version

docker info

```

If `docker info` fails because the engine is unavailable, start Docker Desktop and wait for the engine to become ready before continuing.

### Validate the Compose Configuration

From the repository root:

```powershell

docker compose config --quiet

```

This checks the Compose configuration. It does not prove that the images build or the services start successfully.

### Build and Start the Services

```powershell

docker compose up -d --build

```

Inspect service status:

```powershell

docker compose ps

```

View logs:

```powershell

docker compose logs --tail=100

```

The configured services expose the API on port `8000` and the dashboard on port `8501`, subject to the Compose configuration and host port availability.

### Stop the Services

```powershell

docker compose down

```

The Compose configuration uses a named volume for SQLite history. Stopping the services with `docker compose down` preserves that volume by default.

To remove the volume as well, Docker Compose supports:

```powershell

docker compose down --volumes

```

**Warning:** Removing the volume can permanently delete the database history stored in it. Do this only when you intentionally want to discard that data.

For deployment details, see [`docs/phase16_docker_deployment.md`](docs/phase16_docker_deployment.md).

## Testing

The project includes automated tests for its components and integrated application behavior.

Activate the virtual environment from the repository root:

```powershell

.\\.venv\\Scripts\\Activate.ps1

```

### Run the Test Suite

```powershell

python -m pytest -q

```

### Compile Python Files

```powershell

python -m compileall -q app dashboard scripts tests

```

### Check Whitespace and Patch Formatting

```powershell

git diff --check

git diff --cached --check

```

Test results and warnings may vary by environment and installed dependency versions. Report the actual results from your latest test run rather than assuming an earlier result still applies.

## Documentation

The `docs/` directory contains phase-specific technical notes covering the implemented components.

| Document                                                                   | Subject                      |

| -------------------------------------------------------------------------- | ---------------------------- |

| [`docs/phase4_baseline_ml.md`](docs/phase4_baseline_ml.md)                 | Baseline machine learning    |

| [`docs/phase5_url_analysis.md`](docs/phase5_url_analysis.md)               | URL analysis                 |

| [`docs/phase6_header_analysis.md`](docs/phase6_header_analysis.md)         | Header analysis              |

| [`docs/phase7_attachment_analysis.md`](docs/phase7_attachment_analysis.md) | Attachment metadata analysis |

| [`docs/phase8_rule_engine.md`](docs/phase8_rule_engine.md)                 | Rule engine                  |

| [`docs/phase9_combined_scoring.md`](docs/phase9_combined_scoring.md)       | Combined risk scoring        |

| [`docs/phase10_explainability.md`](docs/phase10_explainability.md)         | Explainability               |

| [`docs/phase11_unified_pipeline.md`](docs/phase11_unified_pipeline.md)     | Unified analysis pipeline    |

| [`docs/phase12_fastapi.md`](docs/phase12_fastapi.md)                       | FastAPI integration          |

| [`docs/phase13_dashboard.md`](docs/phase13_dashboard.md)                   | Streamlit dashboard          |

| [`docs/phase14_sqlite_history.md`](docs/phase14_sqlite_history.md)         | SQLite history               |

| [`docs/phase16_docker_deployment.md`](docs/phase16_docker_deployment.md)   | Docker deployment            |

## Limitations and Security Considerations

This project is a portfolio-oriented detection system and should not be treated as a complete enterprise email security gateway.

* **No guaranteed detection:** A phishing probability or risk score is an estimate from the implemented system, not proof of maliciousness or safety.

* **Dataset dependence:** Baseline model performance may not generalize to different email populations, languages, campaigns, or adversarially modified messages.

* **No external URL reputation service:** URL analysis relies on implemented structural indicators rather than a comprehensive external reputation or threat-intelligence lookup.

* **No independent email-authentication verification:** SPF, DKIM, and DMARC findings are derived from available supplied headers; the application does not independently authenticate the sending infrastructure.

* **Limited attachment inspection:** Attachment analysis evaluates supported metadata and does not execute files or replace antivirus, sandboxing, or full content scanning.

* **Sensitive email content:** Email headers and message bodies can contain personal, confidential, or business-sensitive information. Use only authorized samples and protect saved records.

* **Local development configuration:** The development server and default local configuration are intended for development and testing. A production deployment requires appropriate authentication, access controls, secure configuration, logging, monitoring, and operational hardening.

## Future Improvements

Potential directions for future research and development include:

* Evaluation on additional representative and independently sourced datasets.

* Monitoring for model drift and changes in phishing tactics.

* More extensive adversarial robustness evaluation.

* Integration with authorized threat-intelligence and URL-reputation sources.

* Deeper attachment inspection through isolated scanning tools.

* Authentication and access controls for multi-user deployments.

* Additional operational monitoring and production-hardening measures.

These are potential extensions, not claims about functionality currently implemented in the repository.

## Resume Highlights

**Explainable Suspicious Email & Phishing Detection System | Python, scikit-learn, FastAPI, Streamlit, SQLite, Docker**

* Developed an explainable email-analysis pipeline combining TF-IDF and Logistic Regression with deterministic rules and URL, header, and attachment-metadata indicators.

* Implemented a combined 0–100 risk-scoring mechanism and human-readable findings to support analysis of suspicious email characteristics.

* Built REST API endpoints with FastAPI and an interactive Streamlit dashboard for email analysis and saved-result retrieval.

* Integrated SQLite-based analysis history and Docker Compose configuration for containerized API and dashboard deployment.

* Evaluated the baseline ML classifier on separate validation and held-out test sets, achieving **99.27% test accuracy and a 99.35% F1-score** on the evaluated dataset.

The metrics above describe the baseline ML component, not end-to-end detection performance. Describe Docker deployment as configured unless you have successfully built and run the containers.

## License

This project includes a `LICENSE` file in the repository root. Refer to that file for the applicable license terms.
