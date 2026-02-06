# Honey Claw - Fake API Honeypot
# Medium-interaction REST API honeypot

FROM node:20-slim

LABEL maintainer="OpenClaw Contributors"
LABEL honeyclaw.template="fake-api"
LABEL honeyclaw.interaction="medium"

# Create app directory
WORKDIR /app

# Create non-root user
RUN groupadd -r honeypot && useradd -r -g honeypot honeypot

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy application
COPY server.js ./
COPY routes/ ./routes/
COPY middleware/ ./middleware/
COPY data/ ./data/

# Create log directory
RUN mkdir -p /var/log/honeypot && chown honeypot:honeypot /var/log/honeypot

# Expose API port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -f http://localhost:8080/health || exit 1

# Run as non-root
USER honeypot

# Start server
CMD ["node", "server.js"]
