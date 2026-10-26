# Phase 16: Docker and Deployment

## Architecture

Docker Compose runs two services:

- **FastAPI API:** provides email analysis, health checks, and analysis history.
- **Streamlit dashboard:** provides the Python-based dashboard and communicates with the API through the Compose network.

SQLite analysis history is persisted using the `email_detector_history` named volume.

The React/TypeScript frontend in `frontend/` is a separate application. It can be run locally using Vite and is not currently a service in the supplied Docker Compose configuration.

## Deployment Files

- `Dockerfile`: builds the API image and includes the trained ML model.
- `Dockerfile.dashboard`: builds the Streamlit dashboard image.
- `compose.yaml`: configures services, networking, ports, health checks, and persistent storage.
- `.dockerignore`: excludes development files from Docker build contexts.

## Prerequisites

- Docker Desktop installed and running.
- The trained model artifact at `models/baseline_tfidf_logistic_regression.joblib`.

The model artifact is required for analysis but is not tracked in Git. A fresh clone must obtain this artifact through an authorized distribution method before building and running the analysis service. Do not assume that cloning the repository alone supplies the model.

## Validate, Build, and Start

Run these commands from the repository root:

    docker compose config --quiet
    docker compose up -d --build
    docker compose ps

## Endpoints

- Streamlit dashboard: http://localhost:8501
- API root: http://localhost:8000/
- API health: http://localhost:8000/health
- Interactive API documentation: http://localhost:8000/docs

## Configuration

`EMAIL_DETECTOR_API_URL` configures the dashboard API address. Docker Compose sets it to `http://api:8000`.

`EMAIL_DETECTOR_DATABASE_PATH` configures the SQLite database path. Compose sets it to `/app/data/history.sqlite3`.

## Run the React Frontend Separately

Ensure the API is running and its required model artifact is available.

From a separate terminal:

    Set-Location E:\GITHUB\Suspicious-Email-Detector\frontend
    npm ci
    npm run dev

Open the local URL printed by Vite. The frontend's default API address is `http://127.0.0.1:8000`. If the API uses another address or port, update the frontend Settings interface.

For frontend build and test commands, see `frontend/README.md`.

## Verification

Check API health:

    Invoke-RestMethod http://localhost:8000/health

Check the Streamlit dashboard at `http://localhost:8501`.

Inspect service logs:

    docker compose logs --tail 100 api
    docker compose logs --tail 100 dashboard

## Persistent History

The `email_detector_history` named volume preserves SQLite history across API container recreation.

Avoid `docker compose down -v` unless you intentionally want to delete the named volume and its stored data.

## Lifecycle Commands

Stop services:

    docker compose stop

Start stopped services:

    docker compose start

Restart services:

    docker compose restart

Rebuild and start services:

    docker compose up -d --build

Remove containers and the Compose network while retaining named volumes:

    docker compose down

## Security Limitations

This configuration is intended for local development and portfolio demonstrations. Production TLS, external authentication, secrets management, and high availability are not configured.

Do not expose services to untrusted networks without additional security controls. Use synthetic or sanitized emails during demonstrations. Model predictions are estimates, not guarantees.

## Phase 16 Validation Record

The previously recorded validation covered Compose configuration, API health, dashboard HTTP 200, containerized email analysis, and history persistence after API restart and container recreation.

The earlier recorded regression run passed 296 tests with 65 dependency deprecation warnings. This is a historical result, not a current validation result. Repeat relevant smoke tests after deployment changes.
