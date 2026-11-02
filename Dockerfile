# Built from the repository root, so the image carries the console (web/) beside
# the API and serves both on one origin:  docker build -t intelpulse .
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    WEB_DIR=/srv/web

WORKDIR /srv

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./
# The pages and their assets only: .dockerignore leaves out the browser tests.
COPY web/ ./web/

# Run unprivileged: the container only ever needs to read its own code and
# write to ./data.
RUN useradd --create-home --uid 10001 intelpulse \
 && mkdir -p /srv/data \
 && chown -R intelpulse:intelpulse /srv
USER intelpulse

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
