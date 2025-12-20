FROM python:3.13-slim@sha256:baf66684c5fcafbda38a54b227ee30ec41e40af1e4073edee3a7110a417756ba

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=100

WORKDIR /app

# ---------- builder stage ----------
FROM python:3.13-slim@sha256:baf66684c5fcafbda38a54b227ee30ec41e40af1e4073edee3a7110a417756ba AS builder
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md /app/
COPY src /app/src

RUN pip wheel --no-deps -w /wheels .

# ---------- runtime stage ----------
FROM python:3.13-slim@sha256:baf66684c5fcafbda38a54b227ee30ec41e40af1e4073edee3a7110a417756ba AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd -g 10001 app && useradd -m -u 10001 -g app -s /usr/sbin/nologin app

WORKDIR /app

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-compile /wheels/*.whl \
  && rm -rf /wheels

RUN mkdir -p /config \
  && chown -R app:app /config /app

USER app:app

CMD ["threat-thinker", "serve", "--config", "/config/serve.yaml"]
