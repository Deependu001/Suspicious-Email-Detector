# Phase 9 - Combined Scoring

## 1. Objective

Phase 9 introduces the deterministic combined scoring layer for the suspicious email detection system.

The purpose of this phase is to combine:

- the phishing probability produced by the Phase 4 baseline ML model
- the deterministic rule results produced by the Phase 8 Rule Engine

into a single numerical risk score between 0 and 100.

Phase 9 does not introduce verdict generation, natural-language explanations, full pipeline orchestration, API integration, dashboard functionality, persistence, adversarial testing, or deployment.

---

## 2. Scoring Inputs

The Phase 9 scoring layer consumes two categories of inputs.

### 2.1 ML phishing probability

The baseline ML classifier provides:

`ml_phishing_probability`

This value represents the model's estimated probability that the email is phishing.

The accepted range is:

`0.0 <= probability <= 1.0`

The probability is validated before scoring.

---

### 2.2 Rule results

The Phase 8 Rule Engine produces a list of `RuleResult` objects.

Each rule result contains:

- `rule_id`
- `description`
- `triggered`
- `observations`

Only triggered rules with configured scoring weights contribute to the deterministic rule component.

Unknown rule IDs are ignored by the scoring layer.

Non-triggered rules do not contribute to the score.

Duplicate triggered rule IDs are counted only once.

---

## 3. Scoring Architecture

The combined score consists of two components:

1. ML contribution
2. deterministic rule contribution

The default architecture uses:

- ML contribution weight: `0.70`
- Rule contribution weight: `0.30`

Therefore:

`combined_score = ML contribution + Rule contribution`

The resulting score is converted to the 0-100 risk-score range.

---

## 4. ML Weight

The default ML weight is:

`0.70`

The ML contribution is calculated as:

`ML contribution = ml_phishing_probability * 0.70`

For example, if the ML phishing probability is `0.80`:

`0.80 * 0.70 = 0.56`

---

## 5. Rule Weights

The deterministic rule component uses the following normalized rule weights:

| Rule ID | Weight |
|---|---:|
| HEADER_FROM_REPLY_TO_MISMATCH | 0.08 |
| HEADER_FROM_RETURN_PATH_MISMATCH | 0.06 |
| HEADER_SPF_FAILURE | 0.08 |
| HEADER_DKIM_FAILURE | 0.06 |
| HEADER_DMARC_FAILURE | 0.10 |
| URL_IP_ADDRESS | 0.10 |
| URL_UNUSUAL_PORT | 0.05 |
| URL_SUSPICIOUS_CHARACTERS | 0.05 |
| URL_ENCODING | 0.04 |
| ATTACHMENT_DANGEROUS_EXTENSION | 0.12 |
| ATTACHMENT_DOUBLE_EXTENSION | 0.08 |
| ATTACHMENT_MIME_MISMATCH | 0.10 |
| ATTACHMENT_UNUSUAL_FILENAME | 0.08 |

The total rule weight is:

`1.00`

The rule weights represent the relative contribution of each deterministic indicator to the rule component.

---

## 6. Rule Contribution

For every triggered configured rule, its weight is included in the deterministic rule contribution.

Duplicate rule IDs are counted only once.

The total triggered rule weight is calculated as:

`triggered_rule_weight = sum(weight of unique triggered configured rules)`

The rule contribution is then:

`Rule contribution = triggered_rule_weight * 0.30`

For example, if the following rules are triggered:

- `URL_IP_ADDRESS` = `0.10`
- `HEADER_DMARC_FAILURE` = `0.10`

then:

`triggered_rule_weight = 0.20`

and:

`Rule contribution = 0.20 * 0.30 = 0.06`

---

## 7. Combined Score Formula

The complete Phase 9 formula is:

`combined_score = (ml_phishing_probability * 0.70) + (triggered_rule_weight * 0.30)`

The final risk score is:

`risk_score = combined_score * 100`

The score is bounded to the range:

`0 <= risk_score <= 100`

---

## 8. Example Calculation

Assume:

`ml_phishing_probability = 0.80`

and the following rules are triggered:

- `URL_IP_ADDRESS` = `0.10`
- `HEADER_DMARC_FAILURE` = `0.10`
- `ATTACHMENT_DANGEROUS_EXTENSION` = `0.12`

The triggered rule weight is:

`0.10 + 0.10 + 0.12 = 0.32`

ML contribution:

`0.80 * 0.70 = 0.56`

Rule contribution:

`0.32 * 0.30 = 0.096`

Combined score:

`0.56 + 0.096 = 0.656`

Final risk score:

`0.656 * 100 = 65.6`

Therefore, the Phase 9 scoring layer returns:

`65.6`

No verdict is generated from this value in Phase 9.

---

## 9. Score Boundaries

The scoring layer guarantees a final risk score between:

`0.0` and `100.0`

### Minimum

With:

`ml_phishing_probability = 0.0`

and no triggered rules:

`risk_score = 0.0`

### Maximum

With:

`ml_phishing_probability = 1.0`

and all configured rules triggered:

`risk_score = 100.0`

The implementation clamps the final result to the valid range.

---

## 10. Validation

The scoring layer validates the ML probability.

Values outside the range:

`0.0 <= probability <= 1.0`

raise:

`ValueError`

The scoring configuration validates:

- ML weight must be between `0.0` and `1.0`
- rule weights must sum to `1.0`
- rule weights must not be negative

Non-finite ML probability values such as:

- NaN
- positive infinity
- negative infinity

are rejected by the probability validation.

---

## 11. Determinism

Phase 9 scoring is deterministic.

For identical:

- ML phishing probability
- rule results
- scoring weights

the scoring layer produces the same risk score.

There is no randomness, external service dependency, database dependency, or time-dependent behavior in the scoring calculation.

---

## 12. Implemented Components

### Model

`app/models/scoring_models.py`

Defines:

- `ScoringInput`
- `RuleWeight`
- `ScoringWeights`

### Service

`app/services/scoring_service.py`

Defines:

- `ScoringService`
- default scoring weights
- deterministic combined-score calculation
- ML probability validation
- scoring-weight validation
- score boundary enforcement

### Tests

`tests/test_scoring_models.py`

Tests the Phase 9 scoring data models.

`tests/test_scoring_service.py`

Tests:

- ML-only scoring
- rule-only scoring
- combined scoring
- minimum score
- maximum score
- all rules
- unknown rules
- non-triggered rules
- duplicate triggered rules
- deterministic behavior
- invalid ML probabilities
- invalid ML weights
- invalid rule-weight totals
- negative rule weights

---

## 13. Phase 9 Verification

Focused Phase 9 tests:

`21 passed`

Complete project regression:

`99 passed`

The complete regression suite also reports one existing Starlette deprecation warning related to the current `httpx`/Starlette test-client dependency combination.

That warning is unrelated to the Phase 9 scoring implementation and is not modified during this phase.

Additional Phase 9 edge-case verification confirmed that:

- duplicate triggered rules do not inflate the score
- NaN is rejected
- positive infinity is rejected
- negative infinity is rejected
- default ML weight is `0.70`
- default rule weights total `1.00`
- exactly 13 deterministic rules have configured weights

---

## 14. Phase Boundary

Phase 9 is limited to the combined numerical scoring layer.

The following functionality is intentionally deferred.

### Phase 10 - Explainability

Natural-language explanations and human-readable reasons are deferred to Phase 10.

### Phase 11 - Unified Pipeline

Combining parsing, analysis, ML, rules, scoring, and later components into the complete application pipeline is deferred to Phase 11.

### Phase 12 - FastAPI

Final API integration of the complete analysis pipeline is deferred to Phase 12.

### Phase 13 - Dashboard

Web dashboard functionality is deferred to Phase 13.

### Phase 14 - SQLite History

Persistence and analysis history are deferred to Phase 14.

### Phase 15 - Testing & Adversarial

Broad adversarial testing is deferred to Phase 15.

### Phase 16 - Docker & Deployment

Containerization and deployment are deferred to Phase 16.

### Phase 17 - Documentation & Resume

Final project documentation and resume presentation are deferred to Phase 17.

Phase 9 therefore provides only the deterministic numerical risk-scoring layer required by the roadmap.
