FROM python:3.11-slim AS builder
WORKDIR /app
RUN pip install --no-cache-dir hatchling
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY src ./src
COPY policies ./policies
ENV PYTHONPATH=/app/src
HEALTHCHECK NONE
CMD ["uvicorn", "roscyber.ingestion.app:app", "--host", "0.0.0.0", "--port", "8000"]
