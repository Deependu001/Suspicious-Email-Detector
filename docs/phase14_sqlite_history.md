# Phase 14 — SQLite History

## Objective

Persist completed email-analysis results in SQLite and provide API endpoints to list and retrieve previous analyses.

## Implementation

- SQLite persistence using Python's standard-library `sqlite3`.
- Database initialization creates the history table and timestamp index.
- Each saved analysis receives a unique record ID and UTC timestamp.
- History listing returns summaries, newest first.
- Individual records include sanitized analysis findings.
- History listing supports a configurable limit from 1 to 100.
- The default database path is `data/history.sqlite3`.
- Tests use temporary databases to avoid dependence on production data.

## API Endpoints

### POST /analyze

Analyzes the submitted raw email and saves the completed result to history.

The live analysis response retains its existing API contract. History sanitization applies to the stored copy and does not change detection.

### GET /history

Lists recent history summaries.

The optional `limit` query parameter defaults to 20 and accepts values from 1 through 100.

### GET /history/{record_id}

Retrieves one history record, including its sanitized findings.

Returns HTTP 404 when the requested record does not exist.

## History Data and Privacy

History records contain an ID, UTC timestamp, sender summary, subject, risk score, ML phishing probability, and sanitized analysis findings.

The stored findings exclude the complete parsed email and remove identifying address fields from header-analysis findings.

URL paths, query strings, and fragments are redacted in URL analyses and URLs embedded in rule observations or explainability observations. Useful indicators, hostnames, rule IDs, and risk-scoring results remain available where applicable.

Sender and subject are retained as summary fields. They may contain sensitive information, so the SQLite database must be treated as sensitive application data and protected accordingly.

This phase does not implement authentication, user-specific history access controls, retention policies, or database encryption.

## Error Handling

The API returns an error if a history record cannot be saved or retrieved. Invalid history limits are rejected by request validation.

## Validation

Focused validation commands:

```powershell
python -m py_compile app\services\history_service.py tests\test_history_service.py
python -m pytest tests\test_history_service.py tests\test_history_api.py -v
```

The focused history service and API tests passed during development. Final full-suite results are recorded after Phase 14 regression validation.

## Scope Boundaries

This phase implements SQLite persistence and history retrieval only.

Dashboard changes, adversarial testing, Docker, deployment, and final resume-oriented documentation remain outside this phase.
