# Build from repository root: docker build -f backend/Dockerfile -t datalineage-ai:m63 .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
RUN groupadd --system appuser && useradd --system --gid appuser --home-dir /nonexistent appuser

COPY backend/requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir -r /tmp/requirements.txt

COPY backend/app /app/backend/app
COPY backend/scripts_m50_worker.py /app/backend/scripts_m50_worker.py
COPY backend/scripts_m54_monitor_worker.py /app/backend/scripts_m54_monitor_worker.py
COPY frontend/index.html /app/frontend/index.html
COPY scripts /app/scripts

RUN mkdir -p /app/backend/data \
    && chown -R appuser:appuser /app/backend/data /app
WORKDIR /app/backend

ENV DATALINEAGE_DB_PATH=/app/backend/data/analysis_runs.sqlite3 \
    DATALINEAGE_USERS_DB_PATH=/app/backend/data/users.sqlite3 \
    DATALINEAGE_SAAS_DB_PATH=/app/backend/data/saas.sqlite3 \
    DATALINEAGE_SECURITY_DB=/app/backend/data/security.sqlite3

USER appuser
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=8s --start-period=40s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=5)"
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
