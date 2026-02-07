# HoneyClaw - Low-Interaction SSH Honeypot
FROM python:3.11-slim

LABEL maintainer="OpenClaw Contributors"
LABEL honeyclaw.template="basic-ssh"
LABEL honeyclaw.interaction="low"

# Install dependencies - cryptography needed for full asyncssh support
# aiohttp needed for HTTP health endpoint
RUN pip install --no-cache-dir asyncssh cryptography aiohttp

# Create non-root user
RUN groupadd -r honeypot && useradd -r -g honeypot -s /usr/sbin/nologin honeypot

# Create app structure
RUN mkdir -p /app /common /var/log/honeypot /data/logs \
    && chown -R honeypot:honeypot /var/log/honeypot /data

# Copy application files
# When built from template dir: honeypot.py, common/ are local
# When built from project root (Fly.io): paths are relative to templates/basic-ssh/
COPY templates/basic-ssh/honeypot.py /app/honeypot.py
COPY templates/basic-ssh/test_tcp.py /app/test_tcp.py
COPY templates/basic-ssh/common/ /common/

# Copy src/ modules for correlation, geoip, alerts, analysis
COPY src/ /src/

# Default ports: 8022 SSH, 9090 health check
EXPOSE 8022 9090

# Health check via HTTP endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9090/health')" || exit 1

# Run as non-root
USER honeypot

# Run the honeypot
CMD ["python", "-u", "/app/honeypot.py"]
