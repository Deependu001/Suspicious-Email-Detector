# Phase 11 - Unified Pipeline

## 1. Purpose

Phase 11 integrates the completed detection components from Phases 1-10 into one deterministic, reusable email-analysis pipeline.

The unified pipeline accepts a parsed `EmailData` object and coordinates:

* ML phishing-probability inference.
* URL analysis.
* Header analysis.
* Attachment analysis.
* Rule evaluation.
* Combined risk scoring.
* Explainability generation.

The pipeline produces one structured `PipelineResult` containing the original email data, component analysis results, ML probability, rule results, risk score, and explainability result.

Phase 11 focuses exclusively on orchestration and end-to-end integration.

### Explicitly out of scope

The following remain deferred to later phases:

* FastAPI endpoint integration.
* Dashboard/UI.
* SQLite persistence and history.
* Broad adversarial/evasion testing.
* Docker/deployment.
* Final project documentation and resume material.

---

## 2. Phase 11 Responsibilities

Phase 11 is responsible for connecting the already implemented detection components without duplicating their internal logic.

The unified workflow is:

```text
EmailData
    |
    +--> ML Inference
    |
    +--> URL Analysis
    |
    +--> Header Analysis
    |
    +--> Attachment Analysis
    |
    +--> Rule Engine
    |
    +--> Combined Scoring
    |
    +--> Explainability
    |
    v
PipelineResult
```

Each existing component remains responsible for its own domain-specific behavior.

The unified pipeline is responsible for orchestration, data flow, validation, and construction of the final result contract.

---

## 3. Pipeline Input

The unified pipeline accepts:

```python
EmailData
```

The pipeline does not parse raw email input itself.

Email parsing remains the responsibility of the email parser implemented in Phase 2.

This keeps the pipeline independent from input transport and allows it to operate on an already normalized `EmailData` representation.

The pipeline validates that the supplied input is an `EmailData` instance.

---

## 4. Unified Pipeline Data Contract

The final pipeline output is represented by:

```text
app/models/pipeline_models.py
```

The primary model is:

```python
PipelineResult
```

The contract contains:

* `email`
* `ml_phishing_probability`
* `url_analyses`
* `header_analysis`
* `attachment_analysis`
* `rule_results`
* `risk_score`
* `explainability`

Conceptually:

```text
PipelineResult
├── email: EmailData
├── ml_phishing_probability: float
├── url_analyses: list[URLAnalysis]
├── header_analysis: HeaderAnalysis
├── attachment_analysis: AttachmentAnalysis
├── rule_results: list[RuleResult]
├── risk_score: float
└── explainability: ExplainabilityResult
```

This contract provides a single structured representation of the complete analysis performed by the system.

---

## 5. Pipeline Architecture

The unified pipeline is implemented in:

```text
app/services/unified_pipeline.py
```

The pipeline coordinates the following services:

```text
MLInferenceService
URLAnalyzer
HeaderAnalyzer
AttachmentAnalyzer
RuleEngine
ScoringService
ExplainabilityService
```

The pipeline does not reimplement the logic of these services.

Instead, it invokes the existing services in the required dependency order.

---

## 6. ML Integration

ML inference is implemented through:

```text
app/services/ml_inference_service.py
```

The `MLInferenceService` loads the trained baseline model:

```text
models/baseline_tfidf_logistic_regression.joblib
```

The model uses the Phase 4 baseline TF-IDF and Logistic Regression pipeline.

For an email, the inference service prepares the model input from:

```text
subject + plain-text body
```

It then extracts the probability associated with the:

```text
phishing
```

class.

The resulting probability is returned as:

```python
ml_phishing_probability: float
```

The unified pipeline passes this value unchanged into combined scoring and preserves it in the final `PipelineResult`.

---

## 7. URL Integration

URL analysis continues to be handled by:

```text
app/services/url_analyzer.py
```

For every URL contained in:

```python
EmailData.urls
```

the unified pipeline calls:

```python
URLAnalyzer.analyze(url)
```

The resulting objects are stored in:

```python
url_analyses: list[URLAnalysis]
```

The pipeline does not duplicate URL detection logic.

URL observations remain descriptive until they are consumed by the existing rule engine and scoring components.

Multiple URLs are preserved independently in the final pipeline result.

---

## 8. Header Integration

Header analysis continues to be handled by:

```text
app/services/header_analyzer.py
```

The pipeline calls:

```python
HeaderAnalyzer.analyze(email)
```

The resulting:

```python
HeaderAnalysis
```

object is included in the final `PipelineResult`.

Header analysis remains responsible for descriptive observations such as:

* From/Reply-To relationships.
* Return-Path relationships.
* Domain mismatches.
* Received-header information.
* Authentication-header information.
* SPF-related observations.

The unified pipeline does not duplicate header-analysis logic.

---

## 9. Attachment Integration

Attachment analysis continues to be handled by:

```text
app/services/attachment_analyzer.py
```

The pipeline calls:

```python
AttachmentAnalyzer.analyze(email)
```

The resulting:

```python
AttachmentAnalysis
```

object is included in the final `PipelineResult`.

Existing attachment detection remains responsible for observations such as:

* Dangerous extensions.
* Double extensions.
* MIME mismatches.
* Unusual filenames.

The unified pipeline only coordinates the analysis and preserves its result.

---

## 10. Rule Engine Integration

Rule evaluation continues to be handled by:

```text
app/services/rule_engine.py
```

The rule engine receives:

```text
EmailData
URLAnalysis results
HeaderAnalysis
AttachmentAnalysis
```

The unified pipeline invokes:

```python
RuleEngine.evaluate(
    email=email,
    url_analyses=url_analyses,
    header_analysis=header_analysis,
    attachment_analysis=attachment_analysis,
)
```

The resulting:

```python
list[RuleResult]
```

is preserved in the final pipeline contract.

The pipeline does not create additional detection rules.

The existing deterministic rule set from Phase 8 remains the source of rule-based detection.

---

## 11. Combined Scoring Integration

Combined risk scoring continues to be handled by:

```text
app/services/scoring_service.py
```

The unified pipeline constructs:

```python
ScoringInput(
    ml_phishing_probability=ml_phishing_probability,
    rule_results=rule_results,
)
```

and passes it to:

```python
ScoringService.calculate(...)
```

The resulting numerical risk score is preserved as:

```python
risk_score: float
```

The Phase 9 scoring formula remains unchanged.

The unified pipeline does not introduce new scoring weights or scoring logic.

---

## 12. Explainability Integration

Explainability continues to be handled by:

```text
app/services/explainability_service.py
```

The pipeline provides:

```text
risk_score
ml_phishing_probability
rule_results
```

to:

```python
ExplainabilityService.generate_explanation(...)
```

The resulting:

```python
ExplainabilityResult
```

is stored in the final pipeline result.

This preserves traceability between:

```text
ML probability
       +
triggered rules
       +
risk score
       |
       v
explanation
```

The pipeline does not independently generate explanation messages.

---

## 13. Pipeline Execution Order

The final execution order is deterministic:

### Step 1 - Validate input

Confirm that the supplied object is an `EmailData` instance.

### Step 2 - ML inference

Calculate:

```text
ml_phishing_probability
```

### Step 3 - URL analysis

Analyze every URL in:

```text
EmailData.urls
```

### Step 4 - Header analysis

Analyze the email headers.

### Step 5 - Attachment analysis

Analyze the email attachments.

### Step 6 - Rule evaluation

Evaluate the existing deterministic rule engine using the component analysis results.

### Step 7 - Combined scoring

Combine the ML probability and rule results using the existing Phase 9 scoring service.

### Step 8 - Explainability

Generate explanations using the final risk score, ML probability, and rule results.

### Step 9 - Pipeline result construction

Return a complete:

```python
PipelineResult
```

containing all analysis outputs.

---

## 14. Implemented Components

Phase 11 introduced or completed the following integration components.

### Unified pipeline contract

```text
app/models/pipeline_models.py
```

Provides:

```python
PipelineResult
```

### ML inference service

```text
app/services/ml_inference_service.py
```

Provides reusable inference against the trained baseline model.

### Unified pipeline

```text
app/services/unified_pipeline.py
```

Provides complete orchestration of the existing detection system.

---

## 15. Unit-Level Integration Testing

The primary integration test file is:

```text
tests/test_unified_pipeline.py
```

The test suite verifies:

* Pipeline construction.
* Input validation.
* ML integration.
* Preservation of ML probability.
* URL integration.
* Header integration.
* Attachment integration.
* Rule-engine integration.
* Preservation of rule results.
* Scoring integration.
* Construction of the scoring input.
* Preservation of the risk score.
* Explainability integration.
* Preservation of the complete explainability result.
* Correct context passed to explainability.

The test file contains:

```text
21 tests
```

---

## 16. End-to-End Testing

End-to-end pipeline tests are located in:

```text
tests/test_unified_pipeline_e2e.py
```

These tests exercise the complete pipeline using realistic combinations of email characteristics.

The end-to-end tests verify scenarios including:

* Legitimate email processing.
* Suspicious IP-based URLs.
* Authentication failures.
* Dangerous attachments.
* Explainability consistency.
* Deterministic repeated analysis.
* Minimal emails.
* Multiple URLs.
* Multiple attachments.
* Pipeline-result component consistency.

The end-to-end test file contains:

```text
11 tests
```

The end-to-end suite verifies that information survives the complete flow:

```text
EmailData
    ↓
ML
    ↓
URL/Header/Attachment Analysis
    ↓
Rule Engine
    ↓
Scoring
    ↓
Explainability
    ↓
PipelineResult
```

---

## 17. Edge-Case and Contract Hardening

Phase 11 includes contract-focused edge-case testing.

The following cases are covered:

### Minimal email

A minimal valid `EmailData` object must still produce a valid `PipelineResult`.

### Multiple URLs

All URLs supplied by the email must remain represented in the pipeline result.

### Multiple attachments

All attachments supplied by the email must remain represented in the pipeline result.

### Component consistency

The final pipeline result must remain internally consistent with the intermediate analysis outputs.

### Determinism

Running the same email through the pipeline repeatedly must produce equivalent results.

These tests ensure that orchestration does not accidentally lose or mutate important component information.

---

## 18. Phase 11 Validation

The Phase 11 validation sequence includes:

```powershell
python -m py_compile app\services\unified_pipeline.py app\services\ml_inference_service.py
```

and:

```powershell
python -m pytest -q
```

The completed Phase 11 regression suite produced:

```text
205 passed, 61 warnings
```

No test failures were present.

The existing warnings do not represent Phase 11 test failures.

---

## 19. Existing Warnings

The regression suite currently reports two categories of warnings.

### Starlette/httpx warning

The project contains an existing deprecation warning related to:

```text
starlette.testclient
httpx
```

This warning is not caused by the Phase 11 unified pipeline implementation.

### ML/joblib/NumPy warnings

The ML inference and end-to-end tests produce warnings originating from the model-loading/dependency stack.

These warnings do not cause test failures and do not alter the Phase 11 pipeline contract.

Phase 11 does not change dependency versions solely to remove these warnings.

---

## 20. Determinism

The unified pipeline is designed to preserve the deterministic behavior of the components completed in earlier phases.

For a given `EmailData` input and unchanged model/dependencies/configuration:

```text
same input
    ↓
same component analyses
    ↓
same rule results
    ↓
same risk score
    ↓
same explainability result
```

The Phase 11 tests explicitly verify repeated analysis of the same email.

---

## 21. Phase Boundary

Phase 11 ends at the reusable unified pipeline.

The following functionality is intentionally not implemented here:

### Phase 12 - FastAPI

API endpoints and HTTP integration remain deferred to Phase 12.

### Phase 13 - Dashboard

User-interface and dashboard functionality remain deferred to Phase 13.

### Phase 14 - SQLite History

Persistence, history, and database functionality remain deferred to Phase 14.

### Phase 15 - Testing & Adversarial

Broader adversarial/evasion testing remains deferred to Phase 15.

### Phase 16 - Docker & Deployment

Containerization and deployment remain deferred to Phase 16.

### Phase 17 - Documentation/Resume

Final portfolio documentation and resume-oriented material remain deferred to Phase 17.

This boundary is intentional so that Phase 11 remains focused on pipeline orchestration.

---

## 22. Phase 11 Completion Criteria

Phase 11 is considered complete when all of the following are satisfied:

* A unified pipeline input/output contract exists.
* The trained ML model is callable through a reusable inference service.
* URL analysis is integrated.
* Header analysis is integrated.
* Attachment analysis is integrated.
* Rule evaluation is integrated.
* Combined scoring is integrated.
* Explainability is integrated.
* The complete pipeline produces a structured `PipelineResult`.
* Unit-level integration tests pass.
* End-to-end tests pass.
* Edge-case and contract tests pass.
* Full regression testing passes.
* Documentation accurately describes the implementation.
* The Phase 11 working tree is clean after commit.

---

## 23. Phase 11 Implementation History

The major Phase 11 implementation commits are:

```text
fac3f58  Add unified pipeline result contract
92bf481  Add reusable ML inference service
6d79ee4  Add unified pipeline orchestration
8a5eb06  Verify ML integration in unified pipeline
748b193  Verify component integration in unified pipeline
1fa3728  Verify rule engine integration in unified pipeline
8511712  Verify combined scoring integration in unified pipeline
5d22ade  Add end-to-end unified pipeline tests
e417231  Harden unified pipeline edge cases and contracts
```

These commits represent the completed implementation and verification work leading into the final Phase 11 documentation and closure validation.

---

## 24. Phase 11 Status

At the completion of the implementation and testing work, the unified detection pipeline provides a single deterministic orchestration layer over the completed detection components from Phases 1-10.

The resulting architecture is:

```text
Email Input
    ↓
EmailData
    ↓
UnifiedPipeline
    ├── MLInferenceService
    ├── URLAnalyzer
    ├── HeaderAnalyzer
    ├── AttachmentAnalyzer
    ├── RuleEngine
    ├── ScoringService
    └── ExplainabilityService
    ↓
PipelineResult
```

Phase 11 therefore establishes the internal application pipeline that later phases can consume.

FastAPI integration is intentionally deferred to Phase 12.