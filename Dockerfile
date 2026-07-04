# syntax=docker/dockerfile:1.7

# ---------------------------------------------------------------------------
# Builder stage: install deps + the package into /wheels.
# ---------------------------------------------------------------------------
# Pinned by digest so rebuilds are reproducible. Refresh with:
#   docker pull python:3.13-slim
#   docker inspect python:3.13-slim --format '{{index .RepoDigests 0}}'
# Dependabot keeps it fresh weekly (.github/dependabot.yml).
FROM python:3.13-slim@sha256:a0779d7c12fc20be6ec6b4ddc901a4fd7657b8a6bc9def9d3fde89ed5efe0a3d AS builder

WORKDIR /build

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Runtime deps install from the hash-pinned lockfile. Every transitive dep is
# locked with sha256 hashes; --require-hashes refuses anything that doesn't match.
# Regenerate with (target the Linux runtime so platform-only deps like
# SecretStorage/jeepney are locked; compiling on macOS omits them):
#   uv pip compile requirements.in -o requirements.lock --generate-hashes \
#     --python-version 3.13 --python-platform linux
COPY requirements.lock ./requirements.lock
RUN pip install --no-cache-dir --require-hashes --target /wheels -r requirements.lock

COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir --target /wheels --no-deps .

# ---------------------------------------------------------------------------
# Runtime stage.
# ---------------------------------------------------------------------------
FROM python:3.13-slim@sha256:a0779d7c12fc20be6ec6b4ddc901a4fd7657b8a6bc9def9d3fde89ed5efe0a3d AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/site-packages \
    PATH=/app/site-packages/bin:$PATH

# Non-root user with pinned UID 1000.
RUN groupadd --system --gid 1000 mcp \
    && useradd --system --uid 1000 --gid 1000 --no-create-home --shell /usr/sbin/nologin mcp

WORKDIR /app
COPY --from=builder /wheels /app/site-packages
RUN mkdir -p /data && chown -R mcp:mcp /app /data

USER mcp

EXPOSE 3722

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
    CMD ["python", "-m", "mcp_nixreview.healthcheck"]

ENTRYPOINT ["python", "-m", "mcp_nixreview.server"]
