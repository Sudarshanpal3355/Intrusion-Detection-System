# AI Intrusion Detection System - Dockerfile
# Production-ready container image

FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p models data results logs

# Expose ports
EXPOSE 8000 8501

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Default command - run API server
CMD ["python", "-m", "uvicorn", "src.ids_api_server:app", "--host", "0.0.0.0", "--port", "8000"]

# Labels
LABEL maintainer="Security Team"
LABEL description="AI-Powered Intrusion Detection System"
LABEL version="1.0.0"
