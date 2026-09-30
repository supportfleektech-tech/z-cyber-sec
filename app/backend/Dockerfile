# CYBER-SEC platform image (ADR-007) — single process: API + static SPA.
# Zero-budget: public Debian-based base images + pinned requirements; non-root runtime.
# Build from the REPO ROOT:  docker build -f app/backend/Dockerfile -t cybersec .

# ---- Stage 1: build the SPA (Node 20, locked deps)
FROM node:20-slim AS frontend
WORKDIR /srv/frontend
COPY app/frontend/package.json app/frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY app/frontend/ .
RUN npm run build

# ---- Stage 2: final image (runtime deps + app code + built SPA)
FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    ENV_NAME=LOCAL \
    DATA_DIR=/var/lib/cybersec
WORKDIR /srv

# Install pinned backend deps into this stage (not a throwaway layer)
COPY app/backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# App package + assets + built frontend (layout mirrors the repo:
#   /srv/app  = backend root (contains ./app, ./rules, ./scenarios)
#   /srv/frontend/dist = served by the backend catch-all)
COPY app/backend/app         /srv/app/app
COPY app/backend/rules       /srv/app/rules
COPY app/backend/scenarios   /srv/app/scenarios
COPY --from=frontend /srv/frontend/dist /srv/frontend/dist

# Non-root runtime user; data dir owned by it
RUN groupadd --gid 10001 cybersec \
    && useradd --uid 10001 --gid 10001 --home-dir /var/lib/cybersec --create-home cybersec \
    && mkdir -p /var/lib/cybersec \
    && chown -R cybersec:cybersec /var/lib/cybersec /srv/app /srv/frontend
USER cybersec
WORKDIR /srv/app
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/healthz', timeout=3).status==200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
