FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-postgres.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-postgres.txt

COPY app ./app

ENV DATABASE_URL=postgresql://identityshield:identityshield@db:5432/identityshield
ENV IDENTITYSHIELD_ALLOWED_TARGETS=simulator,localhost,127.0.0.1
ENV IDENTITYSHIELD_LOCAL_ONLY=true

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
