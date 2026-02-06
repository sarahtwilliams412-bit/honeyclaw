# Honey Claw - Enterprise Simulation Honeypot
# High-interaction multi-service honeypot

FROM ubuntu:22.04

LABEL maintainer="OpenClaw Contributors"
LABEL honeyclaw.template="enterprise-sim"
LABEL honeyclaw.interaction="high"

ENV DEBIAN_FRONTEND=noninteractive

# Install base packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    nginx \
    samba \
    python3 \
    python3-pip \
    supervisor \
    netcat-openbsd \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install --no-cache-dir \
    flask \
    gunicorn \
    ldap3 \
    impacket \
    paramiko

# Create honeypot user
RUN useradd -m -s /bin/bash honeypot

# Configure SSH
RUN mkdir -p /run/sshd
COPY sshd_config /etc/ssh/sshd_config

# Configure Samba (SMB)
COPY smb.conf /etc/samba/smb.conf
RUN mkdir -p /shares/{netlogon,sysvol,it,finance}

# Create fake sensitive files
COPY fake-files/ /shares/

# Configure nginx (HTTP/HTTPS)
COPY nginx.conf /etc/nginx/nginx.conf
COPY www/ /var/www/html/

# Copy service simulators
COPY services/ /opt/honeyclaw/services/
COPY logger/ /opt/honeyclaw/logger/

# Configure supervisor
COPY supervisord.conf /etc/supervisor/conf.d/honeyclaw.conf

# Create log directory
RUN mkdir -p /var/log/honeypot && chown honeypot:honeypot /var/log/honeypot

# Expose all ports
EXPOSE 22 80 443 3389 5985 445 389

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s \
    CMD curl -f http://localhost/health || exit 1

# Start all services via supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
