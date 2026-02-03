# Authentication Flask Application Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies including openssl for SSL cert generation
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    pkg-config \
    curl \
    openssl \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Generate self-signed SSL certificates for HTTPS
RUN mkdir -p /app/certs && \
    openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout /app/certs/key.pem \
    -out /app/certs/cert.pem \
    -days 365 \
    -subj "/C=SG/ST=Singapore/L=Singapore/O=MoveIT/CN=localhost"

# Expose port
EXPOSE 5000

# Health check (use -k to ignore self-signed cert warnings)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -fk https://localhost:5000/ || exit 1

# Run the application
CMD ["python", "app.py"]
