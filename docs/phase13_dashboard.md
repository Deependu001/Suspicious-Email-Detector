# Phase 13: Dashboard

## 1. Overview

Phase 13 introduces a Streamlit dashboard for the Explainable Suspicious Email & Phishing Detection System.

The dashboard provides a graphical interface for submitting raw email content to the existing FastAPI backend and viewing the resulting analysis.

The dashboard communicates with FastAPI over HTTP. It does not independently implement the machine-learning classifier, URL analysis, header analysis, attachment analysis, rule engine, risk scoring, or explainability logic.

## 2. Architecture

```text
User
  |
  v
Streamlit Dashboard
  |
  | HTTP POST /analyze
  v
FastAPI Backend
  |
  v
Email Parser
  |
  v
Unified Detection Pipeline
  |
  +-- Machine Learning Classification
  +-- URL Analysis
  +-- Header Analysis
  +-- Attachment Analysis
  +-- Rule Engine
  +-- Combined Risk Scoring
  +-- Explainability
  |
  v
PipelineResult
  |
  v
FastAPI JSON Response
  |
  v
Streamlit Results Display
```

## 3. Technology

* Python
* Streamlit
* Requests
* FastAPI
* Pydantic
* Existing unified detection pipeline

## 4. Prerequisites

Before starting the dashboard:

1. Use the project's Python virtual environment.
2. Install the dependencies listed in `requirements.txt`.
3. Ensure the baseline ML model required by the existing detection pipeline is available.
4. Start the FastAPI backend before submitting emails for analysis.

Activate the virtual environment from the project root:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies if necessary:

```powershell
python -m pip install -r requirements.txt
```

## 5. Starting the FastAPI Backend

Open a PowerShell terminal in the project root and run:

```powershell
python -m uvicorn app.main:app --reload
```

The default local API address is:

`http://127.0.0.1:8000`

Interactive API documentation:

`http://127.0.0.1:8000/docs`

Keep this terminal running while using the dashboard.

## 6. Starting the Dashboard

Open a second PowerShell terminal in the project root. Activate the virtual environment if necessary:

```powershell
.\.venv\Scripts\Activate.ps1
```

Start Streamlit:

```powershell
python -m streamlit run dashboard\app.py
```

Open the dashboard:

`http://localhost:8501`

The default FastAPI Base URL configured in the dashboard is:

`http://127.0.0.1:8000`

The dashboard also provides a field for changing the API base URL.

## 7. Analyzing an Email

1. Confirm that the FastAPI backend is running.
2. Open the Streamlit dashboard.
3. Enter the FastAPI Base URL.
4. Paste the raw email, including its headers and body, into the Raw Email field.
5. Select **Analyze Email**.
6. Review the results returned by the backend.

The dashboard sends the raw email to the FastAPI `/analyze` endpoint as JSON.

The request has the following structure:

```json
{
  "raw_email": "From: sender@example.com\nSubject: Example\n\nExample email body."
}
```

The dashboard displays the analysis returned by the backend rather than recalculating detection results locally.

## 8. Results Display

### 8.1 Risk Score

Displays the risk score returned by the backend on its existing 0-100 scale.

### 8.2 ML Phishing Probability

Displays the machine-learning phishing probability as a percentage.

### 8.3 Email Information

Displays available extracted email fields, including:

* Sender
* Reply-To
* Subject
* Date
* Recipients
* CC
* Return-Path
* Message-ID

### 8.4 Detection Rules

Displays triggered detection rules and their available descriptions and observations.

### 8.5 URL Analysis

Displays extracted URL analysis information, including available URL details and suspicious indicators.

### 8.6 Header Analysis

Displays header mismatch indicators, Received header count, authentication-header presence, and available SPF, DKIM, and DMARC statuses.

### 8.7 Attachment Analysis

Displays attachment analysis information and available indicators such as dangerous extensions, double extensions, MIME mismatches, and unusual filenames.

### 8.8 Explainability

Displays explanations returned by the backend, including their categories, messages, and available observations.

### 8.9 Raw API Response

An expandable section provides the complete JSON response returned by FastAPI.

## 9. Error Handling

The dashboard handles common request and response failures.

| Scenario                   | Dashboard behavior                                   |
| -------------------------- | ---------------------------------------------------- |
| Empty API Base URL         | Displays a validation error                          |
| Empty raw email            | Requests that the user enter an email                |
| Invalid URL                | Displays an invalid URL error                        |
| Backend unavailable        | Displays a connection error                          |
| Request timeout            | Displays a timeout message                           |
| Other request failure      | Displays a request error                             |
| HTTP error response        | Displays the HTTP status and available error details |
| Invalid JSON response      | Displays a response parsing error                    |
| Unexpected response format | Displays a response format error                     |
| Successful response        | Stores and displays the analysis result              |

A failed subsequent request does not overwrite the previously stored successful result in the dashboard session.

## 10. Automated Testing

Dashboard HTTP behavior is tested in:

`tests/test_dashboard.py`

Run dashboard-specific tests:

```powershell
python -m pytest tests\test_dashboard.py -v
```

Compile the dashboard and its tests:

```powershell
python -m py_compile dashboard\app.py tests\test_dashboard.py
```

Run the complete project test suite:

```powershell
python -m pytest -q
```

The Phase 13.6 validation run completed with **251 passed, 61 warnings**. Repeat these commands when validating subsequent changes; the recorded result describes that validation run.

## 11. Phase Scope

Phase 13 covers the Streamlit dashboard, its communication with the existing FastAPI backend, result presentation, error handling, and dashboard tests.

The remaining roadmap phases are:

* Phase 14: SQLite History
* Phase 15: Testing & Adversarial
* Phase 16: Docker & Deployment
* Phase 17: Documentation/Resume

No functionality from these later phases is introduced by this dashboard implementation.

## 12. Dashboard Files

```text
dashboard/
    app.py

tests/
    test_dashboard.py

docs/
    phase13_dashboard.md
```

The dashboard uses the existing FastAPI endpoint and unified detection pipeline. Detection logic remains in the backend.
