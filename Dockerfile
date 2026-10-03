# Dockerfile for AI-Driven DDoS SDN Detection Framework Backend & Dashboard
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    nodejs \
    npm \
    iptables \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Build frontend dashboard
WORKDIR /app/dashboard
RUN npm install && npm run build
WORKDIR /app

EXPOSE 8000 3000 6653 2055 8443

CMD ["python", "run_system.py"]
