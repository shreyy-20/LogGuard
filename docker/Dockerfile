FROM python:3.11-slim

LABEL maintainer="LogGuard Developer"
LABEL version="1.0.0"
LABEL description="Sleek glassmorphic Linux Log Monitoring & Analysis Daemon and Web Console."

WORKDIR /app

# Install basic system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy dependencies list
COPY requirements.txt .

# Install dependencies without cache directory to keep size small
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY src/ ./src/
COPY config/ ./config/
COPY scripts/ ./scripts/

# Create folders for database and logs mount
RUN mkdir -p /app/logs /app/data

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV DB_PATH=/app/data/logguard.db

# Default command - can be overridden in docker-compose.yml
CMD ["python", "-m", "src.main"]
