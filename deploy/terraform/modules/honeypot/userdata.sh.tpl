#!/bin/bash
# =============================================================================
# Honeyclaw Honeypot Instance Bootstrap
# Template: ${template_name}
# =============================================================================
set -euo pipefail

export HONEYPOT_ID="honeyclaw-${template_name}-$(hostname)"
export HONEYCLAW_TEMPLATE="${template_name}"
export HONEYCLAW_LOG_BUCKET="${log_bucket}"
export HONEYCLAW_SIEM_ENDPOINT="${siem_endpoint}"
export HONEYCLAW_SIEM_PORT="${siem_port}"
export HONEYCLAW_HEALTH_PORT="${health_check_port}"
export HONEYCLAW_REBUILD_INTERVAL_HOURS="${rebuild_interval_hours}"
export HONEYCLAW_ENVIRONMENT="${environment}"

# --- Install dependencies ---
yum update -y -q
yum install -y -q docker git python3 python3-pip

# --- Start Docker ---
systemctl enable docker
systemctl start docker

# --- Clone and deploy ---
cd /opt
git clone --depth 1 https://github.com/sarahtwilliams412-bit/honeyclaw.git || true
cd honeyclaw

# --- Build and run honeypot ---
pip3 install -r requirements.txt 2>/dev/null || true

# Deploy the honeypot template
bash src/deploy-honeypot.sh \
  --template "${template_name}" \
  --detach \
  --health-port "${health_check_port}"

# --- Setup automated rebuild cron ---
cat > /etc/cron.d/honeyclaw-rebuild << 'CRON'
0 */${rebuild_interval_hours} * * * root /opt/honeyclaw/deploy/flyio/rotate.sh >> /var/log/honeyclaw/rebuild.log 2>&1
CRON

echo "[BOOTSTRAP] Honeyclaw ${template_name} deployed successfully"
