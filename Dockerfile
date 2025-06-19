FROM python:3.11-slim

WORKDIR /app

# Install system dependencies required by WeasyPrint and other libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    libxml2-dev \
    libxslt-dev \
    libpq-dev \
    nmap \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better layer caching
COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . /app/
RUN mkdir -p /logs
VOLUME ["/logs"]

EXPOSE 514/tcp
EXPOSE 514/udp
EXPOSE 8080

# Run the new modular Flask app
CMD ["python", "-m", "syslogger.web.app"]
