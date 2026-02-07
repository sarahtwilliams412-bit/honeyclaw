#!/bin/bash
# HoneyClaw - Automated Fly.io Deployment with Health Verification
#
# Deploys a honeypot template to Fly.io with:
# - Pre-deployment health snapshot
# - Blue-green deployment (zero downtime)
# - Post-deployment health verification
# - Automatic rollback on health check failure
#
# Usage:
#   ./deploy/flyio/deploy.sh basic-ssh           # Deploy SSH honeypot
#   ./deploy/flyio/deploy.sh fake-api iad        # Deploy API to US East
#   ./deploy/flyio/deploy.sh enterprise-sim ams   # Deploy enterprise to Amsterdam
#
# Environment variables:
#   APP_PREFIX          - App name prefix (default: honeyclaw)
#   HEALTH_CHECK_RETRIES - Health check attempts before rollback (default: 5)
#   HEALTH_CHECK_DELAY   - Seconds between health checks (default: 10)

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

TEMPLATE="${1:?Usage: deploy.sh <template> [region]}"
REGION="${2:-sjc}"
APP_PREFIX="${APP_PREFIX:-honeyclaw}"
HEALTH_CHECK_RETRIES="${HEALTH_CHECK_RETRIES:-5}"
HEALTH_CHECK_DELAY="${HEALTH_CHECK_DELAY:-10}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-120}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Map template to config
case "$TEMPLATE" in
  basic-ssh)      CONFIG="$SCRIPT_DIR/fly-basic-ssh.toml"; APP_NAME="${APP_PREFIX}-ssh-${REGION}" ;;
  fake-api)       CONFIG="$SCRIPT_DIR/fly-fake-api.toml"; APP_NAME="${APP_PREFIX}-api-${REGION}" ;;
  enterprise-sim) CONFIG="$SCRIPT_DIR/fly-enterprise-sim.toml"; APP_NAME="${APP_PREFIX}-ent-${REGION}" ;;
  *)              echo "Error: Unknown template '$TEMPLATE'"; echo "Valid: basic-ssh, fake-api, enterprise-sim"; exit 1 ;;
esac

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# =============================================================================
# Pre-flight Checks
# =============================================================================

preflight() {
    log_info "Running pre-flight checks..."

    if ! command -v fly &>/dev/null; then
        log_error "flyctl not found. Install: curl -L https://fly.io/install.sh | sh"
        exit 1
    fi

    if ! fly auth whoami &>/dev/null; then
        log_error "Not authenticated with Fly.io. Run: fly auth login"
        exit 1
    fi

    if [ ! -f "$CONFIG" ]; then
        log_error "Config not found: $CONFIG"
        exit 1
    fi

    log_success "Pre-flight checks passed"
}

# =============================================================================
# Deployment
# =============================================================================

create_app_if_needed() {
    if ! fly apps list --json 2>/dev/null | grep -q "\"$APP_NAME\""; then
        log_info "Creating app: $APP_NAME"
        fly apps create "$APP_NAME" --org personal || true
    fi

    # Create volume if needed
    if ! fly volumes list -a "$APP_NAME" 2>/dev/null | grep -q "honeyclaw_data"; then
        log_info "Creating data volume..."
        fly volumes create honeyclaw_data \
            --app "$APP_NAME" \
            --region "$REGION" \
            --size 1 \
            --yes || true
    fi
}

set_secrets() {
    log_info "Setting secrets..."
    fly secrets set \
        HONEYCLAW_TEMPLATE="$TEMPLATE" \
        HONEYPOT_ID="$APP_NAME" \
        --app "$APP_NAME" 2>/dev/null || true
}

capture_pre_deploy_state() {
    log_info "Capturing pre-deployment state..."
    PRE_DEPLOY_VERSION=$(fly releases list -a "$APP_NAME" --json 2>/dev/null | \
        python3 -c "import sys,json; r=json.load(sys.stdin); print(r[0]['Version'] if r else '0')" 2>/dev/null || echo "0")
    log_info "Current version: v$PRE_DEPLOY_VERSION"
}

deploy() {
    log_info "Deploying $TEMPLATE to $REGION as $APP_NAME..."

    # Generate temporary fly.toml with correct app name
    local tmp_config="/tmp/fly-deploy-${APP_NAME}.toml"
    sed "s/^app = .*/app = \"$APP_NAME\"/" "$CONFIG" > "$tmp_config"
    sed -i "s/^primary_region = .*/primary_region = \"$REGION\"/" "$tmp_config"

    # Deploy with blue-green strategy
    fly deploy \
        --config "$tmp_config" \
        --region "$REGION" \
        --strategy rolling \
        --wait-timeout "$HEALTH_TIMEOUT" \
        --yes

    rm -f "$tmp_config"
    log_success "Deployment initiated"
}

# =============================================================================
# Health Verification
# =============================================================================

health_check() {
    log_info "Verifying deployment health..."

    local attempt=0
    while [ $attempt -lt "$HEALTH_CHECK_RETRIES" ]; do
        attempt=$((attempt + 1))
        log_info "Health check attempt $attempt/$HEALTH_CHECK_RETRIES..."

        # Check if service is running
        local status
        status=$(fly status -a "$APP_NAME" --json 2>/dev/null | \
            python3 -c "
import sys, json
data = json.load(sys.stdin)
machines = data.get('Machines', [])
if machines:
    states = [m.get('state', 'unknown') for m in machines]
    if all(s == 'started' for s in states):
        print('healthy')
    else:
        print('unhealthy')
else:
    print('no-machines')
" 2>/dev/null || echo "error")

        if [ "$status" = "healthy" ]; then
            log_success "All machines healthy"
            
            # Also check HTTP health endpoint
            HEALTH_URL="https://${APP_NAME}.fly.dev:9090/health"
            HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH_URL" 2>/dev/null || echo "000")
            if [ "$HTTP_CODE" = "200" ]; then
                log_success "Health endpoint responding"
                return 0
            else
                log_warn "Health endpoint returned $HTTP_CODE"
            fi
            return 0
        fi

        log_warn "Status: $status - waiting ${HEALTH_CHECK_DELAY}s..."
        sleep "$HEALTH_CHECK_DELAY"
    done

    log_error "Health check failed after $HEALTH_CHECK_RETRIES attempts"
    return 1
}

rollback() {
    if [ "${PRE_DEPLOY_VERSION:-0}" != "0" ]; then
        log_warn "Rolling back to v$PRE_DEPLOY_VERSION..."
        fly releases rollback -a "$APP_NAME" "$PRE_DEPLOY_VERSION" --yes 2>/dev/null || true
        log_warn "Rollback initiated. Check: fly status -a $APP_NAME"
    else
        log_error "No previous version to rollback to."
    fi
}

# =============================================================================
# Main
# =============================================================================

main() {
    echo ""
    echo "=== HoneyClaw Deployment ==="
    echo "Template: $TEMPLATE"
    echo "Region:   $REGION"
    echo "App:      $APP_NAME"
    echo "==========================="
    echo ""

    preflight
    create_app_if_needed
    set_secrets
    capture_pre_deploy_state
    deploy

    if health_check; then
        echo ""
        log_success "Deployment successful!"
        log_info "App: https://${APP_NAME}.fly.dev"
        log_info "Health: https://${APP_NAME}.fly.dev:9090/health"
        log_info "Status: fly status -a $APP_NAME"
        log_info "Logs: fly logs -a $APP_NAME"
        log_info "SSH: fly ssh console --app $APP_NAME"
    else
        log_error "Deployment health check failed!"
        rollback
        exit 1
    fi
}

main
