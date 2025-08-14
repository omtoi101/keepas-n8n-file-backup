# Multi-stage build for KeePass n8n File Backup
FROM python:3.11-slim as builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements first for better caching
COPY requirements.txt /tmp/
RUN pip install --upgrade pip && \
    pip install -r /tmp/requirements.txt

# Production stage
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    KEEPASS_BACKUP_HOME=/app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    cron \
    rsync \
    inotify-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Create non-root user
RUN groupadd -r keepass && useradd -r -g keepass -d /app -s /bin/bash keepass

# Create necessary directories
RUN mkdir -p /app /app/config /app/data /app/backups /app/logs /var/log/cron && \
    chown -R keepass:keepass /app /var/log/cron

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=keepass:keepass . /app/
# Default command (use mounted config.ini)
CMD ["python", "python_webhook_request.py"]
