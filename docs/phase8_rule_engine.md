# Phase 8 — Rule Engine

## 1. Overview

Phase 8 introduces the deterministic rule engine for the Explainable Suspicious Email & Phishing Detection System.

The Rule Engine evaluates structured results produced by the previously implemented analysis components:

* Header Analysis
* URL Analysis
* Attachment Analysis

The Rule Engine does not perform the underlying analysis itself. Instead, it consumes the existing analysis models and converts relevant observations into structured rule results.

The output of this phase is intended to provide deterministic rule observations that can be consumed by later phases.

---

## 2. Phase 8 Scope

### Included

Phase 8 implements:

* Structured rule-result representation
* Deterministic rule evaluation
* Header-based rules
* URL-based rules
* Attachment-based rules
* Rule trigger status
* Structured observations
* Edge-case handling
* Deterministic evaluation behavior
* Unit testing and regression testing

### Not Included

The following functionality is intentionally outside Phase 8:

* Risk scores
* Rule weights
* Risk-point calculations
* Combined scoring
* ML probability integration
* Final email verdicts
* Natural-language explanations
* Unified analysis pipeline
* FastAPI integration
* Dashboard integration
* Database/history storage

These belong to later phases of the locked project roadmap.

---

## 3. Architecture Position

The Rule Engine sits after the individual analysis components.

```text
Email
  │
  ▼
Email Parser
  │
  ├──────────────► URL Analysis
  │
  ├──────────────► Header Analysis
  │
  └──────────────► Attachment Analysis
                         │
                         ▼
                    Rule Engine
                         │
                         ▼
                  Structured Rules
```

The Rule Engine consumes analysis results rather than duplicating their detection logic.

---

## 4. Rule Result Model

The Rule Engine returns a list of `RuleResult` objects.

The model is defined in:

```text
app/models/rule_models.py
```

Each result contains:

| Field          | Type        | Description                                  |
| -------------- | ----------- | -------------------------------------------- |
| `rule_id`      | `str`       | Unique identifier for the rule               |
| `description`  | `str`       | Short description of the condition           |
| `triggered`    | `bool`      | Whether the rule condition was observed      |
| `observations` | `list[str]` | Structured evidence associated with the rule |

Example structure:

```text
RuleResult(
    rule_id="URL_IP_ADDRESS",
    description="A URL uses an IP address as its hostname",
    triggered=True,
    observations=["url=http://192.168.1.10/login"]
)
```

The Rule Engine does not assign severity or numerical risk to this result.

---

## 5. Rule Engine Interface

The Rule Engine is implemented in:

```text
app/services/rule_engine.py
```

Its primary interface is:

```text
RuleEngine.evaluate(
    email,
    url_analyses,
    header_analysis,
    attachment_analysis
)
```

The method accepts:

* `EmailData`
* A list of `URLAnalysis` objects
* `HeaderAnalysis`
* `AttachmentAnalysis`

It returns:

```text
list[RuleResult]
```

The email object is accepted as part of the defined Rule Engine contract, while the current rules operate on the already-computed analysis results.

---

# 6. Implemented Rules

Phase 8 implements 13 deterministic rules.

## 6.1 Header Rules

### HEADER_FROM_REPLY_TO_MISMATCH

Triggers when the `From` domain and `Reply-To` domain differ.

The rule uses:

```text
HeaderAnalysis.from_reply_to_domain_mismatch
```

Observations include the available domains when a mismatch is present.

---

### HEADER_FROM_RETURN_PATH_MISMATCH

Triggers when the `From` domain and `Return-Path` domain differ.

The rule uses:

```text
HeaderAnalysis.from_return_path_domain_mismatch
```

Observations include the available domains when a mismatch is present.

---

### HEADER_SPF_FAILURE

Triggers when an observed SPF authentication status is:

```text
fail
```

Matching is case-insensitive and ignores surrounding whitespace.

Other SPF statuses do not trigger this rule.

Examples of non-triggering statuses include:

```text
pass
softfail
neutral
none
temperror
permerror
```

---

### HEADER_DKIM_FAILURE

Triggers when an observed DKIM authentication status is:

```text
fail
```

Matching is case-insensitive and ignores surrounding whitespace.

---

### HEADER_DMARC_FAILURE

Triggers when an observed DMARC authentication status is:

```text
fail
```

Matching is case-insensitive and ignores surrounding whitespace.

---

# 6.2 URL Rules

### URL_IP_ADDRESS

Triggers when at least one analyzed URL uses an IP address as its hostname.

The rule uses:

```text
URLAnalysis.has_ip_address
```

All matching URLs are included in the observations.

---

### URL_UNUSUAL_PORT

Triggers when at least one analyzed URL uses an unusual port.

The rule uses:

```text
URLAnalysis.has_unusual_port
```

The underlying unusual-port detection remains the responsibility of the existing URL Analyzer.

---

### URL_SUSPICIOUS_CHARACTERS

Triggers when at least one analyzed URL contains characters already identified by the URL Analyzer as suspicious.

The rule uses:

```text
URLAnalysis.has_suspicious_characters
```

The Rule Engine does not independently redefine the suspicious-character set.

---

### URL_ENCODING

Triggers when at least one analyzed URL contains percent encoding.

The rule uses:

```text
URLAnalysis.has_encoding
```

The Rule Engine therefore consumes the existing URL analysis result rather than performing URL parsing itself.

---

# 6.3 Attachment Rules

### ATTACHMENT_DANGEROUS_EXTENSION

Triggers when at least one attachment has an extension classified by the Attachment Analyzer as potentially dangerous.

The rule uses:

```text
AttachmentAnalysis.dangerous_extensions
```

---

### ATTACHMENT_DOUBLE_EXTENSION

Triggers when at least one attachment has a detected double extension.

The rule uses:

```text
AttachmentAnalysis.double_extensions
```

---

### ATTACHMENT_MIME_MISMATCH

Triggers when an attachment filename extension does not match its detected MIME type according to the existing Attachment Analyzer logic.

The rule uses:

```text
AttachmentAnalysis.mime_mismatches
```

---

### ATTACHMENT_UNUSUAL_FILENAME

Triggers when an attachment filename has already been classified as unusual by the Attachment Analyzer.

The rule uses:

```text
AttachmentAnalysis.unusual_filenames
```

---

# 7. Rule Evaluation Behavior

Every defined rule produces a `RuleResult`.

Therefore, the Rule Engine returns all 13 rule results even when none of the rules trigger.

For example:

```text
Rule 1  → triggered=False
Rule 2  → triggered=False
Rule 3  → triggered=True
...
Rule 13 → triggered=False
```

This provides a consistent and deterministic output structure.

---

# 8. Multiple Matches

The Rule Engine preserves multiple observations for the same rule.

For example, if three URLs contain IP-address hostnames:

```text
URL_IP_ADDRESS
    triggered=True
    observations=[
        "url=http://192.168.1.10/login",
        "url=http://10.0.0.5/update",
        "url=http://172.16.0.20/account"
    ]
```

Similarly, multiple matching attachments are preserved.

This prevents evidence from being silently discarded.

---

# 9. Empty and Missing Inputs

The Rule Engine handles empty analysis collections without raising errors.

Examples:

* No URLs
* No attachments
* No authentication failures
* Missing header domains
* No triggered rules

A missing domain does not cause a header mismatch rule to trigger.

This is consistent with the existing Header Analyzer behavior, where a domain mismatch requires both domains to be available.

---

# 10. Authentication Status Handling

Authentication rules specifically detect the status:

```text
fail
```

Status comparison is:

* case-insensitive
* whitespace-insensitive

For example:

```text
fail
FAIL
 Fail
FAIL
```

are treated as failures.

Other statuses are not treated as failures.

The Rule Engine does not independently verify SPF, DKIM, or DMARC. It evaluates the authentication information already extracted and analyzed by the existing components.

---

# 11. Deterministic Behavior

Rule evaluation is deterministic.

Given the same:

* `EmailData`
* URL analysis results
* Header analysis result
* Attachment analysis result

the Rule Engine produces the same ordered list of rule results.

Rules are evaluated in a fixed order:

```text
1.  HEADER_FROM_REPLY_TO_MISMATCH
2.  HEADER_FROM_RETURN_PATH_MISMATCH
3.  HEADER_SPF_FAILURE
4.  HEADER_DKIM_FAILURE
5.  HEADER_DMARC_FAILURE
6.  URL_IP_ADDRESS
7.  URL_UNUSUAL_PORT
8.  URL_SUSPICIOUS_CHARACTERS
9.  URL_ENCODING
10. ATTACHMENT_DANGEROUS_EXTENSION
11. ATTACHMENT_DOUBLE_EXTENSION
12. ATTACHMENT_MIME_MISMATCH
13. ATTACHMENT_UNUSUAL_FILENAME
```

---

# 12. Separation of Responsibilities

The Phase 8 architecture intentionally separates analysis from rule evaluation.

### Email Parser

Responsible for extracting and normalizing email information.

### URL Analyzer

Responsible for analyzing URLs and producing `URLAnalysis`.

### Header Analyzer

Responsible for analyzing email headers and producing `HeaderAnalysis`.

### Attachment Analyzer

Responsible for analyzing attachment metadata and producing `AttachmentAnalysis`.

### Rule Engine

Responsible for evaluating deterministic conditions against those analysis results.

The Rule Engine does not duplicate parser or analyzer functionality.

---

# 13. Testing

Phase 8 includes focused Rule Engine tests in:

```text
tests/test_rule_engine.py
```

The tests cover:

* Complete rule output
* Rule ordering
* Header mismatch detection
* Authentication failure detection
* URL rule triggering
* Attachment rule triggering
* Non-triggering behavior
* Authentication status handling
* Empty inputs
* Missing domains
* Case and whitespace handling
* Multiple matching URLs
* Multiple matching attachments
* Deterministic evaluation
* Structured result fields

---

# 14. Regression Test Result

After Phase 8 Rule Engine implementation and edge-case testing, the complete project test suite produced:

```text
79 passed, 1 warning
```

The warning is the existing Starlette/httpx deprecation warning and is unrelated to Phase 8 functionality.

No Phase 8 work was added to address that warning because doing so would be unrelated to the current phase scope.

---

# 15. Phase 8 Design Boundaries

The Rule Engine intentionally does not answer:

> "How risky is this email?"

It only answers:

> "Which deterministic rule conditions were observed?"

For example:

```text
Rule:
URL_IP_ADDRESS

Result:
triggered = True

Observation:
url=http://192.168.1.10/login
```

The Rule Engine does not convert this into:

```text
+20 risk points
```

and does not produce:

```text
High Risk
```

Those responsibilities belong to later phases.

---

# 16. Explicitly Deferred Functionality

The following functionality remains deferred.

### Combined Scoring

Combining ML probability with rule results and analysis signals belongs to:

```text
Phase 9 — Combined Scoring
```

### Explainability

Converting structured evidence into final human-readable explanations belongs to:

```text
Phase 10 — Explainability
```

### Unified Pipeline

Connecting the complete analysis system into one unified processing flow belongs to:

```text
Phase 11 — Unified Pipeline
```

### FastAPI Integration

Exposing the completed detection pipeline through the API belongs to:

```text
Phase 12 — FastAPI
```

No functionality from these phases is implemented by the Phase 8 Rule Engine.

---

# 17. Files Added in Phase 8

```text
app/
├── models/
│   └── rule_models.py
│
└── services/
    └── rule_engine.py

tests/
└── test_rule_engine.py

docs/
└── phase8_rule_engine.md
```

---

# 18. Phase 8 Completion Criteria

Phase 8 can be considered complete only after:

* [x] Rule Engine contract defined
* [x] Rule result model implemented
* [x] 13 deterministic rules implemented
* [x] Focused tests implemented
* [x] Edge cases tested
* [x] Full regression completed
* [x] Documentation completed
* [ ] Git review completed
* [ ] Phase 8 commit created
* [ ] Working tree verified clean
* [ ] Phase 8 formally closed

The remaining Git steps are intentionally performed after documentation.

---

# 19. Phase 8 Status

**Phase 8 — Rule Engine: Implementation Complete**

The Rule Engine now provides a deterministic, structured representation of suspicious conditions detected by the existing Header, URL, and Attachment analysis components.

No scoring, verdict, explainability, or unified pipeline functionality has been introduced.

The next required activity is the final Git review and commit process for Phase 8.
