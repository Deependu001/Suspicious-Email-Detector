FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV EMAIL_DETECTOR_DATABASE_PATH=/app/data/history.sqlite3

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip 
&& pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY models/baseline_tfidf_logistic_regression.joblib ./models/baseline_tfidf_logistic_regression.joblib

RUN mkdir -p /app/data

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
