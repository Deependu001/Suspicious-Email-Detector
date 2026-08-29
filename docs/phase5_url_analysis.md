# Phase 5 - URL Analysis

## Overview

Phase 5 adds a dedicated URL analysis component to the Explainable Suspicious Email & Phishing Detection System.

The URL analyzer operates on URLs already extracted by the email parser. It produces structured URL characteristics and descriptive security indicators for downstream analysis.

This phase does not determine whether an email or URL is malicious. Risk scoring, rule-based decisions, explainability, and final verdict logic are implemented in later phases.

---

## Objective

The objective of Phase 5 is to analyze URLs found inside emails and extract meaningful structural and security-related features.

The analyzer is designed to provide clean, testable URL-analysis data for later components of the detection pipeline.

---

## Components

### URL Analysis Model

File: `app/models/url_models.py`

The `URLAnalysis` model represents the structured analysis of one URL.

It contains:

- Original URL
- Normalized URL
- Scheme
- Hostname
- Port
- Domain
- Registered domain
- Subdomain
- TLD
- Path
- Query
- Fragment
- URL length
- IP-address indicator
- Unusual-port indicator
- Suspicious-character indicator
- Encoding indicator
- Subdomain indicator
- Descriptive suspicious indicators

---

## URL Analyzer

File: `app/services/url_analyzer.py`

The `URLAnalyzer` class analyzes individual URLs and returns a `URLAnalysis` object.

### URL Structure Analysis

The analyzer extracts:

- Scheme
- Hostname
- Port
- Domain
- Registered domain
- Subdomain
- TLD
- Path
- Query
- Fragment

### Security-Related Characteristics

The analyzer detects:

- IPv4 address URLs
- IPv6 address URLs
- Unusual ports
- Suspicious characters
- Percent-encoded URLs
- Presence of subdomains
- URL length

---

## Descriptive Indicators

The analyzer can produce the following descriptive indicators:

- `ip_address_url`
- `unusual_port`
- `suspicious_characters`
- `encoded_url`
- `subdomain_present`

These indicators are signals only.

They do not directly produce:

- Risk scores
- Phishing classifications
- Suspicious/High Risk verdicts
- Rule-engine decisions

Those responsibilities belong to later phases.

---

## URL Extraction Integration

Phase 2 already extracts URLs from email content.

The existing email parser extracts URLs from:

1. Plain-text email bodies
2. HTML `href` attributes

Duplicate URLs are removed while preserving discovery order.

Phase 5 consumes those extracted URLs without moving URL security-analysis logic into the email parser.

This keeps parsing and security analysis as separate components.

---

## Testing

Focused tests are located at:

`tests/test_url_analyzer.py`

The test suite covers:

- Standard HTTPS URLs
- IPv4 address URLs
- IPv6 address URLs
- Unusual ports
- Normal ports
- Suspicious characters
- Percent encoding
- Subdomains
- Query strings
- URL fragments
- URL length
- Whitespace handling
- Combined indicators
- Empty URLs
- Invalid input types

Phase 5 focused test result:

`14 passed`

The complete project test suite was also executed after the URL-analysis implementation.

Final project test result at this stage:

`44 passed, 1 warning`

The remaining warning is an existing FastAPI/Starlette `httpx` deprecation warning and is unrelated to the Phase 5 URL analyzer.

---

## Design Boundary

Phase 5 intentionally does not implement:

- Rule engine
- Combined risk scoring
- Explainability
- Unified detection pipeline
- FastAPI integration
- SQLite history
- Dashboard
- Docker deployment

These components belong to later phases of the project roadmap.

---

## Phase 5 Outcome

Phase 5 provides a clean and independently testable URL-analysis layer between email parsing and the later detection/scoring components.

The component can analyze extracted URLs and expose structured URL features for use by subsequent phases.
