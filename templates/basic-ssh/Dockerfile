# Simple SSH Honeypot
FROM python:3.11-slim

# Install dependencies - cryptography needed for full asyncssh support
RUN pip install --no-cache-dir asyncssh cryptography

# Create app structure
RUN mkdir -p /app /common /var/log/honeypot

# Copy application files
COPY honeypot.py /app/honeypot.py
COPY test_tcp.py /app/test_tcp.py
COPY common/ /common/

# Default port - override with PORT env var
EXPOSE 8022

# Run the honeypot
CMD ["python", "-u", "/app/honeypot.py"]
