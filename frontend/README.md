# Suspicious Email Detector — React Frontend

A React and TypeScript web interface for the Explainable Suspicious Email & Phishing Detection System.

The frontend communicates with the project's FastAPI backend to submit email content for analysis, display risk assessments and explainable findings, and review saved analysis history.

## Technology Stack

- React
- TypeScript
- Vite
- Lucide React icons
- FastAPI backend

## Prerequisites

- Node.js and npm
- The project repository
- The FastAPI backend and trained model configured according to the root README

## Install Dependencies

From this directory, run:

    npm ci

## Start the Development Server

    npm run dev

Vite prints the local development URL in the terminal. Open that URL in your browser.

## Configure the API

The default API address is:

    http://127.0.0.1:8000

Start the FastAPI backend in a separate terminal from the repository root:

    .\.venv\Scripts\Activate.ps1
    python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

The backend health endpoint is:

    http://127.0.0.1:8000/health

The interactive API documentation is:

    http://127.0.0.1:8000/docs

If the backend uses a different port, update the API address in the frontend Settings interface.

## Validation Commands

Build the production frontend:

    npm run build

Run the frontend linter:

    npm run lint

Run the UI presentation tests:

    npm run test:ui

The linter may report warnings even when it exits successfully. Review the actual output rather than treating a successful exit as proof that there are no warnings.

## Production Preview

After a successful build:

    npm run preview

Use the URL printed by Vite to preview the production build locally.

## Important Notes

- The React development server is separate from the Docker Compose API and Streamlit services unless explicitly configured otherwise.
- Email analysis requires a reachable FastAPI backend and the required trained model artifact.
- Use synthetic or sanitized emails during demonstrations. Avoid submitting confidential email content.
- The application provides risk estimates and explainable signals; it does not guarantee that an email is safe or malicious.
