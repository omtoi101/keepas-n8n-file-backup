FROM python:3.11-slim

# Set working dir
WORKDIR /app

# Install deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY python_webhook_request.py .

# Config will be mounted at runtime
VOLUME ["/config"]

# Default command (use mounted config.ini)
CMD ["python", "python_webhook_request.py", "--config", "/config/config.ini"]
