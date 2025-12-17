FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md /app/
COPY src /app/src

RUN pip install --no-cache-dir .

COPY configs/serve.example.yaml /config/serve.example.yaml

CMD ["threat-thinker", "serve", "--config", "/config/serve.example.yaml"]
