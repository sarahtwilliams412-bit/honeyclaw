# Simple SSH Honeypot
FROM python:3.11-slim

# Install dependencies - cryptography needed for full asyncssh support
RUN pip install --no-cache-dir asyncssh cryptography

COPY honeypot.py /app/honeypot.py
COPY test_tcp.py /app/test_tcp.py
RUN mkdir -p /var/log/honeypot

# Default port - override with PORT env var
EXPOSE 8022

# Run the honeypot
CMD ["python", "-u", "/app/honeypot.py"]
