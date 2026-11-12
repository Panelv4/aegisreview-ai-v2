FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY aegis ./aegis
COPY samples ./samples
COPY run.py .

# run as a non-root user
RUN useradd -m -u 10001 aegis && mkdir -p /data && chown -R aegis /data /app
USER aegis

ENV DATABASE_URL=sqlite:////data/aegis.db
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD curl -fsS http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "aegis.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
