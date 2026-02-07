#!/bin/bash
# =============================================================================
# Honeyclaw Fly.io Rotation Script
# Tears down and rebuilds honeypot instances for automated rotation
#
# Designed to run as a cron job or scheduled task:
#   0 */24 * * * /path/to/rotate.sh >> /var/log/honeyclaw/rotate.log 2>&1
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="${FLY_APP_NAME:-honeyclaw}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "=== Honeyclaw Rotation: $TIMESTAMP ==="

# Check fly CLI
if ! command -v fly &> /dev/null; then
    echo "ERROR: fly CLI not found"
    exit 1
fi

# 1. Export session data before teardown
echo "[ROTATE] Exporting session data..."
fly ssh console --app "$APP_NAME" -C \
    "tar czf /tmp/sessions-export.tar.gz /var/lib/honeyclaw/recordings/ 2>/dev/null || true" \
    2>/dev/null || true

# 2. Take forensic snapshot
echo "[ROTATE] Taking snapshot..."
SNAPSHOT_DIR="/var/lib/honeyclaw/snapshots/${TIMESTAMP}"
mkdir -p "$SNAPSHOT_DIR" 2>/dev/null || true
fly ssh console --app "$APP_NAME" -C "ps auxf" > "$SNAPSHOT_DIR/processes.txt" 2>/dev/null || true
fly ssh console --app "$APP_NAME" -C "ss -tlnp" > "$SNAPSHOT_DIR/network.txt" 2>/dev/null || true

# 3. Deploy fresh instance (blue-green)
echo "[ROTATE] Deploying fresh instance..."
cd "$(dirname "$SCRIPT_DIR")/.."

fly deploy \
    --app "$APP_NAME" \
    --strategy bluegreen \
    --wait-timeout 120

# 4. Verify new instance health
echo "[ROTATE] Verifying health..."
HEALTHY=false
for i in $(seq 1 12); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "https://${APP_NAME}.fly.dev:9090/health" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
        HEALTHY=true
        break
    fi
    sleep 5
done

if [ "$HEALTHY" = true ]; then
    echo "[ROTATE] New instance healthy. Rotation complete."
else
    echo "[ROTATE] WARNING: Health check failed after rotation!"
    # Don't destroy old instance if new one is unhealthy
    exit 1
fi

echo "=== Rotation Complete: $(date -u +"%Y-%m-%dT%H:%M:%SZ") ==="
