# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js for npm audit support
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip and install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --no-cache-dir --user -r requirements.txt


# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL maintainer="SecureFix AI <securefix-ai@noreply.github.com>"
LABEL org.opencontainers.image.title="SecureFix AI"
LABEL org.opencontainers.image.description="Autonomous DevSecOps agent for dependency vulnerability patching"
LABEL org.opencontainers.image.version="1.0.0"

WORKDIR /app

# Runtime system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Node.js (required for npm audit)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /root/.local /root/.local

# Ensure user-installed packages are on PATH
ENV PATH=/root/.local/bin:$PATH

# Copy application source
COPY agent/        ./agent/
COPY llm/          ./llm/
COPY models/       ./models/
COPY scanners/     ./scanners/
COPY services/     ./services/
COPY triggers/     ./triggers/
COPY utils/        ./utils/
COPY workflows/    ./workflows/
COPY scripts/      ./scripts/

# Runtime configuration
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app

# Create non-root user for security
RUN groupadd -r securefix && useradd -r -g securefix -d /app -s /bin/bash securefix \
    && mkdir -p /tmp/securefix_repos \
    && chown -R securefix:securefix /app /tmp/securefix_repos

USER securefix

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["python", "-m", "uvicorn", "triggers.webhook_listener:app", \
     "--host", "0.0.0.0", "--port", "8000", "--workers", "1", \
     "--log-config", "/dev/null"]
