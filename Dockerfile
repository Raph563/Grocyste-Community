FROM node:24.21.0-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6 AS web
WORKDIR /build
COPY package.json ./
COPY scripts/build.mjs scripts/build.mjs
COPY web web
RUN node --check web/app.mjs && node scripts/build.mjs

FROM python:3.12.14-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS runtime
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 WEB_DIR=/app/web STATE_DIR=/state
COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY community community
COPY --from=web /build/dist web
USER 1000:1000
EXPOSE 8000
CMD ["gunicorn", "--no-control-socket", "--bind", "0.0.0.0:8000", "--workers", "3", "--threads", "2", "--timeout", "60", "--error-logfile", "-", "community.app:create_app()"]

FROM runtime AS tests
USER root
COPY requirements-dev.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements-dev.lock
COPY tests tests
USER 1000:1000
CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
