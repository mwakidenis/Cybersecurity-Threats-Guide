FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    libpcap-dev \
    tcpdump \
    net-tools \
    iputils-ping \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create upload directory
RUN mkdir -p uploads

# Expose port
EXPOSE 5000

# Run the application
CMD ["python", "run.py"]
