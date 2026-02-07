# HoneyClaw - Low-Interaction SSH Honeypot
FROM python:3.11-slim

LABEL maintainer="OpenClaw Contributors"
LABEL honeyclaw.template="basic-ssh"
LABEL honeyclaw.interaction="low"

# Install dependencies - cryptography needed for full asyncssh support
RUN pip install --no-cache-dir asyncssh cryptography

# Create non-root user
RUN groupadd -r honeypot && useradd -r -g honeypot -s /usr/sbin/nologin honeypot

# Create app structure
RUN mkdir -p /app /common /var/log/honeypot \
    && chown -R honeypot:honeypot /var/log/honeypot

# Copy application files
COPY honeypot.py /app/honeypot.py
COPY test_tcp.py /app/test_tcp.py
COPY common/ /common/

# Default port - override with PORT env var
EXPOSE 8022

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('127.0.0.1', 8022)); s.close()" || exit 1

# Run as non-root
USER honeypot

# Run the honeypot
CMD ["python", "-u", "/app/honeypot.py"]
