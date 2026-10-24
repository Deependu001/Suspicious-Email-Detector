# Phase 16: Docker and Deployment

## Architecture
Docker Compose runs a FastAPI API and a Streamlit dashboard. SQLite history is persisted in the email_detector_history named volume.

## Deployment files
- Dockerfile: Builds the API image and includes the trained ML model.
- Dockerfile.dashboard: Builds the dashboard image.
- compose.yaml: Configures services, networking, ports, health checks, and persistent storage.
- .dockerignore: Excludes development files from Docker build contexts.

## Prerequisites
Install Docker Desktop and ensure the Docker Engine is running. The trained model must exist at models/baseline_tfidf_logistic_regression.joblib.

## Build and start
Run these commands from the repository root:

    docker compose config --quiet
    docker compose up -d --build
    docker compose ps

## Endpoints
- Dashboard: http://localhost:8501
- API: http://localhost:8000/
- Health: http://localhost:8000/health
- Interactive API documentation: http://localhost:8000/docs

## Configuration
EMAIL_DETECTOR_API_URL configures the dashboard API address. Compose sets it to http://api:8000. EMAIL_DETECTOR_DATABASE_PATH configures the SQLite database path, set to /app/data/history.sqlite3 in Compose.

## Verification
Check API health with Invoke-RestMethod http://localhost:8000/health. Check the dashboard at http://localhost:8501. Inspect service logs with docker compose logs --tail 100 api and docker compose logs --tail 100 dashboard.

## Persistent history
The email_detector_history named volume preserves SQLite history across API container recreation. Avoid docker compose down -v unless you intentionally want to delete the volume and its stored data.

## Lifecycle
- Stop: docker compose stop
- Start: docker compose start
- Restart: docker compose restart
- Rebuild: docker compose up -d --build
- Remove containers and network while retaining volumes: docker compose down

## Security limitations
This configuration is intended for local development and portfolio demonstrations. Production TLS, external authentication, secrets management, and high availability are not configured. Do not expose services to untrusted networks without additional security controls. Model predictions are estimates, not guarantees.

## Phase 16 validation record
Previously verified: Compose configuration validation, healthy API, dashboard HTTP 200, containerized email analysis, and history persistence after API restart and container recreation. The full regression suite previously passed 296 tests, with 65 dependency deprecation warnings. Repeat smoke tests after deployment changes.
