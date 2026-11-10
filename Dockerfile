# X-Ray Binary — Production Dockerfile
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/packages:/app/apps

WORKDIR /app

# System dependencies for static binary analysis
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    upx \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY pyproject.toml /app/
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    pydantic \
    networkx \
    numpy \
    scipy \
    scikit-learn \
    python-multipart \
    httpx

# Copy source code and packages
COPY packages/ /app/packages/
COPY apps/ /app/apps/
COPY artifacts/ /app/artifacts/
COPY docs/ /app/docs/
COPY tests/ /app/tests/

# Expose API and Web Dashboard port
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Default command
CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
