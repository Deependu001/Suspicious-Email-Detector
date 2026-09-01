# Phase 7 - Attachment Analysis

## Overview

Phase 7 adds a dedicated attachment-analysis component to the
Explainable Suspicious Email & Phishing Detection System.

The purpose of this phase is to derive descriptive security-related
signals from attachment metadata that was already extracted by the
Phase 2 email parser.

This phase does not calculate risk, determine a final verdict, invoke
the machine-learning model, generate explanations, or integrate the
attachment analysis into a unified detection pipeline.

---

## Objectives

The Attachment Analysis component focuses on:

* Attachment presence detection
* Attachment count
* Filename analysis
* File extension extraction
* Potentially dangerous extension detection
* Double-extension detection
* Filename and MIME type comparison
* Missing or unusual filename detection
* Attachment size metadata preservation

---

## Existing Phase 2 Integration

Phase 2 already provides attachment metadata through the
`EmailAttachment` model and `EmailData.attachments`.

The Phase 7 analyzer reuses this existing parser output instead of
duplicating attachment extraction logic.

The analyzer does not store or inspect actual attachment contents.

---

## Attachment Analysis Model

The Phase 7 implementation uses:

```text
app/models/attachment_models.py
```

The main models are:

```text
AttachmentAnalysis
AttachmentAnalysisItem
```

`AttachmentAnalysis` stores aggregate attachment observations.

`AttachmentAnalysisItem` stores observations for an individual
attachment.

---

## Attachment Analyzer

The analyzer is implemented in:

```text
app/services/attachment_analyzer.py
```

The main component is:

```text
AttachmentAnalyzer
```

The public analysis operation is:

```text
AttachmentAnalyzer.analyze(email)
```

The analyzer receives an `EmailData` instance and analyzes the
attachment metadata contained within it.

---

## Attachment Presence and Count

The analyzer records:

```text
attachment_present
attachment_count
```

For an email without attachments:

```text
attachment_present = False
attachment_count = 0
```

For an email containing attachments, the count reflects the number of
attachment metadata records provided by the parser.

---

## Filename and Extension Analysis

For each attachment, the analyzer records:

```text
filename
extension
has_filename
has_extension
```

Extensions are normalized to lowercase.

For example:

```text
Invoice.PDF
```

is represented with:

```text
extension = ".pdf"
```

An attachment without a usable filename or extension receives safe
default values.

---

## Potentially Dangerous Extensions

The analyzer identifies a defined set of potentially dangerous
extensions.

The current set includes:

```text
.exe
.bat
.cmd
.com
.scr
.js
.jse
.vbs
.vbe
.ps1
.psm1
.msi
.msp
.reg
.dll
.hta
```

Detection of one of these extensions produces a descriptive
observation:

```text
is_potentially_dangerous_extension = True
```

This is only an attachment characteristic.

No risk score or verdict is assigned in Phase 7.

---

## Double-Extension Detection

The analyzer detects filenames containing multiple extensions.

Examples:

```text
invoice.pdf.exe
report.doc.pdf
```

These can produce:

```text
is_double_extension = True
```

A normal filename such as:

```text
report.pdf
```

does not produce a double-extension observation.

The detected filenames are also stored in:

```text
double_extensions
```

---

## Filename and MIME Type Comparison

The analyzer performs metadata-level comparison between known filename
extensions and expected MIME types.

Supported mappings include:

```text
.pdf   -> application/pdf
.csv   -> text/csv
.txt   -> text/plain
.html  -> text/html
.htm   -> text/html
.jpg   -> image/jpeg
.jpeg  -> image/jpeg
.png   -> image/png
.zip   -> application/zip
.exe   -> application/vnd.microsoft.portable-executable
```

When a known filename extension is paired with a different MIME type,
the analyzer records:

```text
is_filename_mime_mismatch = True
```

The detected filenames are also stored in:

```text
mime_mismatches
```

Unknown extensions are not automatically considered mismatches.

This avoids making unsupported assumptions about MIME types.

---

## Missing or Unusual Filenames

Attachments without a usable filename are identified through:

```text
has_filename = False
```

They are also recorded in:

```text
unusual_filenames
```

No assumption is made about why the filename is missing.

The analyzer only records the metadata characteristic.

---

## Attachment Size

The analyzer preserves the existing attachment size metadata:

```text
size_bytes
```

This value originates from the Phase 2 parser.

Phase 7 does not assign risk based on attachment size.

---

## Design Principles

Phase 7 follows these principles:

* Reuse Phase 2 parser output
* Analyze metadata rather than attachment contents
* Keep attachment analysis separate from scoring
* Keep analysis deterministic
* Use structured Pydantic models
* Avoid unnecessary dependencies
* Provide focused unit tests
* Preserve compatibility with earlier phases

---

## Testing

Focused tests are located at:

```text
tests/test_attachment_analyzer.py
```

The focused test suite contains coverage for:

* Emails without attachments
* Existing attachment metadata
* Potentially dangerous extensions
* Double extensions
* Filename/MIME mismatches
* Matching filename/MIME pairs
* Missing filenames
* Unknown extensions and MIME types
* Invalid analyzer input

Focused test result:

```text
9 passed
```

Full regression result after Phase 7 implementation:

```text
65 passed, 1 warning
```

The warning is an existing FastAPI/Starlette `httpx` deprecation
warning and is outside the scope of Phase 7.

---

## Files Added in Phase 7

The Phase 7 implementation adds:

```text
app/services/attachment_analyzer.py
tests/test_attachment_analyzer.py
docs/phase7_attachment_analysis.md
```

The attachment models in:

```text
app/models/attachment_models.py
```

were already established as part of the Phase 7 attachment-analysis
foundation before the analyzer implementation.

---

## Phase 7 Scope Boundary

Phase 7 intentionally does not implement:

```text
Rule Engine
Risk Scoring
Combined Scoring
Machine-Learning Integration
Explainability
Unified Detection Pipeline
FastAPI Integration
Dashboard
SQLite History
Docker
Deployment
```

Those responsibilities belong to later phases in the locked project
roadmap.

If functionality is identified that belongs to a later phase, it will
be deferred rather than implemented early.

---

## Phase 7 Verification

The Phase 7 focused test suite passed successfully:

```text
9 passed in 0.27s
```

The complete project regression suite also passed successfully:

```text
65 passed, 1 warning in 10.17s
```

All previously completed phases remain compatible with the Phase 7
implementation.

---

## Phase Status

```text
Phase 7 - Attachment Analysis: COMPLETE
```

Phase 7 is ready for Git review and commit.

The next roadmap phase is:

```text
Phase 8 - Rule Engine
```

Phase 8 will not begin until the Phase 7 changes have been reviewed,
committed, and the working tree has been verified clean.