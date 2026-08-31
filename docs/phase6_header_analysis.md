# Phase 6 - Header Analysis

## Overview

Phase 6 adds a dedicated header-analysis component to the
Explainable Suspicious Email & Phishing Detection System.

The purpose of this phase is to derive descriptive security-related
signals from email headers that were already extracted and normalized
by the Phase 2 email parser.

This phase does not calculate risk, determine a final verdict, invoke
the machine-learning model, or generate explanations.

---

## Objectives

The Header Analysis component focuses on:

- Sender (`From`) analysis
- `Reply-To` analysis
- `Return-Path` analysis
- Sender domain extraction
- Sender and `Reply-To` domain comparison
- Sender and `Return-Path` domain comparison
- `Received` header counting
- Authentication-header presence detection
- SPF status extraction
- DKIM status extraction
- DMARC status extraction
- ARC header presence detection

---

## Existing Phase 2 Integration

Phase 2 already provides:

- Parsed sender information
- Parsed `Reply-To`
- Parsed `Return-Path`
- Raw headers
- Normalized headers
- Authentication-related headers

Phase 6 reuses these existing structures instead of duplicating
header parsing functionality.

Important existing fields include:

```text
EmailData.sender
EmailData.reply_to
EmailData.return_path
EmailData.headers
EmailData.normalized_headers
EmailData.authentication