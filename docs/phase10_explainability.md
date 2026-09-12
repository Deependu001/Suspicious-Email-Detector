# Phase 10 Ã¢â‚¬â€ Explainability

## 1. Purpose

Phase 10 adds a deterministic explainability layer to the suspicious email detection system.

The explainability layer converts already-produced detection results into structured, human-readable explanations.

It does not perform detection, machine-learning inference, risk scoring, or pipeline orchestration.

### Phase 10 responsibilities

- Explain triggered detection rules.
- Explain the ML phishing probability.
- Combine ML and rule explanations.
- Prioritize explanations deterministically.
- Preserve traceability to the originating rule or ML component.
- Handle explainability edge cases and contract boundaries.

### Explicitly out of scope

The following are intentionally deferred to later phases:

- Unified detection pipeline.
- FastAPI API integration.
- Dashboard/UI.
- SQLite persistence/history.
- Broad adversarial/evasion testing.
- Docker/deployment.
- Final project documentation and resume material.

---

## 2. Inputs

The explainability service consumes outputs that were already produced by earlier phases.

### ML input

The ML component provides:

```text
ml_phishing_probability