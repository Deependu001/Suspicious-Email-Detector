from fastapi import FastAPI

app = FastAPI(
    title="Explainable Suspicious Email & Phishing Detection System",
    description="API for detecting suspicious and phishing emails using machine learning and rule-based analysis.",
    version="0.1.0",
)


@app.get("/")
def root():
    return {
        "message": "Suspicious Email Detection API is running",
        "status": "healthy",
        "version": "0.1.0",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }