#!/bin/bash
# =============================================================================
# Honeyclaw Fly.io Deployment Script
# Deploys honeypot instances with health verification
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Configuration
TEMPLATE="${1:-basic-ssh}"
REGION="${FLY_REGION:-iad}"
APP_NAME="${FLY_APP_NAME:-honeyclaw-${TEMPLATE}}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-120}"

echo "=== Honeyclaw Fly.io Deployment ==="
echo "Template:  $TEMPLATE"
echo "Region:    $REGION"
echo "App:       $APP_NAME"
echo ""

# Check fly CLI
if ! command -v fly &> /dev/null; then
    echo "ERROR: fly CLI not found. Install from https://fly.io/docs/getting-started/installing-flyctl/"
    exit 1
fi

# Create app if it doesn't exist
if ! fly apps list | grep -q "$APP_NAME"; then
    echo "[DEPLOY] Creating app $APP_NAME..."
    fly apps create "$APP_NAME" --org personal
fi

# Set secrets
echo "[DEPLOY] Setting secrets..."
fly secrets set \
    HONEYCLAW_TEMPLATE="$TEMPLATE" \
    HONEYPOT_ID="$APP_NAME" \
    --app "$APP_NAME" 2>/dev/null || true

# Deploy
echo "[DEPLOY] Deploying $TEMPLATE to $REGION..."
cd "$PROJECT_ROOT"
fly deploy \
    --app "$APP_NAME" \
    --region "$REGION" \
    --config "$SCRIPT_DIR/fly.toml" \
    --strategy rolling \
    --wait-timeout "$HEALTH_TIMEOUT"

# Verify health
echo "[DEPLOY] Verifying health..."
HEALTH_URL="https://${APP_NAME}.fly.dev:9090/health"

for i in $(seq 1 10); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH_URL" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
        echo "[DEPLOY] Health check passed!"
        break
    fi
    echo "[DEPLOY] Waiting for health check (attempt $i/10)..."
    sleep 5
done

echo ""
echo "=== Deployment Complete ==="
echo "App URL:    https://${APP_NAME}.fly.dev"
echo "Health:     $HEALTH_URL"
echo "SSH:        fly ssh console --app $APP_NAME"
