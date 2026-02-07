#!/bin/bash
# HoneyClaw - Scheduled Honeypot Rotation Script
#
# Tears down and rebuilds honeypot containers on a schedule.
# Designed to run as a cron job or CI/CD scheduled pipeline.
#
# Before rebuild:
#   1. Export session data and logs
#   2. Take forensic snapshot of container state
#   3. Destroy old container
#   4. Deploy fresh container from latest image
#   5. Verify health before accepting traffic
#
# Usage:
#   ./deploy/flyio/rotate.sh                         # Rotate all apps
#   ./deploy/flyio/rotate.sh honeyclaw-ssh-sjc       # Rotate specific app
#   EXPORT_BUCKET=s3://bucket ./deploy/flyio/rotate.sh  # Export to S3
#
# Cron example (rotate every 24 hours at 3 AM UTC):
#   0 3 * * * /path/to/deploy/flyio/rotate.sh >> /var/log/honeyclaw-rotate.log 2>&1
#
# Environment variables:
#   APP_PREFIX     - App name prefix (default: honeyclaw)
#   EXPORT_BUCKET  - S3 bucket for pre-rotation data export (optional)
#   SNAPSHOT_DIR   - Local directory for forensic snapshots (default: /tmp/honeyclaw-snapshots)
#   DRY_RUN        - Set to "true" for dry-run mode

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

APP_PREFIX="${APP_PREFIX:-honeyclaw}"
EXPORT_BUCKET="${EXPORT_BUCKET:-}"
SNAPSHOT_DIR="${SNAPSHOT_DIR:-/tmp/honeyclaw-snapshots}"
DRY_RUN="${DRY_RUN:-false}"
TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ${GREEN}[OK]${NC} $1"; }
log_warn()    { echo -e "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ${RED}[ERROR]${NC} $1"; }

# =============================================================================
# Functions
# =============================================================================

discover_apps() {
    if [ $# -gt 0 ]; then
        APPS=("$@")
    else
        log_info "Discovering honeyclaw apps..."
        mapfile -t APPS < <(fly apps list --json 2>/dev/null | \
            python3 -c "
import sys, json
apps = json.load(sys.stdin)
for app in apps:
    name = app.get('Name', '')
    if name.startswith('${APP_PREFIX}'):
        print(name)
" 2>/dev/null)
    fi

    if [ ${#APPS[@]} -eq 0 ]; then
        log_warn "No honeyclaw apps found"
        exit 0
    fi

    log_info "Found ${#APPS[@]} app(s): ${APPS[*]}"
}

export_session_data() {
    local app="$1"
    log_info "[$app] Exporting session data..."

    local snapshot_path="$SNAPSHOT_DIR/$app/$TIMESTAMP"
    mkdir -p "$snapshot_path"

    # Capture current logs
    fly logs -a "$app" --no-tail 2>/dev/null > "$snapshot_path/logs.txt" || true

    # Capture machine state
    fly status -a "$app" --json 2>/dev/null > "$snapshot_path/status.json" || true

    # Capture release history
    fly releases list -a "$app" --json 2>/dev/null > "$snapshot_path/releases.json" || true

    # Take forensic snapshot from container
    fly ssh console --app "$app" -C \
        "tar czf /tmp/sessions-export.tar.gz /var/lib/honeyclaw/recordings/ 2>/dev/null || true" \
        2>/dev/null || true

    # Capture process list
    fly ssh console --app "$app" -C "ps auxf" > "$snapshot_path/processes.txt" 2>/dev/null || true

    # Capture network state
    fly ssh console --app "$app" -C "ss -tlnp" > "$snapshot_path/network.txt" 2>/dev/null || true

    # Upload to S3 if configured
    if [ -n "$EXPORT_BUCKET" ]; then
        log_info "[$app] Uploading snapshot to $EXPORT_BUCKET..."
        aws s3 cp "$snapshot_path" "$EXPORT_BUCKET/snapshots/$app/$TIMESTAMP/" \
            --recursive --quiet 2>/dev/null || log_warn "[$app] S3 upload failed"
    fi

    log_success "[$app] Session data exported to $snapshot_path"
}

rotate_app() {
    local app="$1"

    log_info "[$app] Starting rotation..."

    if [ "$DRY_RUN" = "true" ]; then
        log_info "[$app] DRY RUN - would rotate"
        return 0
    fi

    # Step 1: Export data before teardown
    export_session_data "$app"

    # Step 2: Destroy all existing machines (force fresh start)
    log_info "[$app] Destroying existing machines..."
    local machines
    machines=$(fly machines list -a "$app" --json 2>/dev/null | \
        python3 -c "import sys,json; [print(m['id']) for m in json.load(sys.stdin)]" 2>/dev/null || true)

    for machine_id in $machines; do
        log_info "[$app] Stopping machine $machine_id..."
        fly machines stop "$machine_id" -a "$app" 2>/dev/null || true
        fly machines destroy "$machine_id" -a "$app" --force 2>/dev/null || true
    done

    # Step 3: Redeploy from latest image (blue-green)
    log_info "[$app] Redeploying from latest image..."
    fly deploy -a "$app" --strategy bluegreen --wait-timeout 120 --yes 2>/dev/null

    # Step 4: Health verification
    log_info "[$app] Verifying health..."
    local healthy=false
    for i in $(seq 1 12); do
        sleep 5
        
        # Check machine status
        local status
        status=$(fly status -a "$app" --json 2>/dev/null | \
            python3 -c "
import sys, json
data = json.load(sys.stdin)
machines = data.get('Machines', [])
started = sum(1 for m in machines if m.get('state') == 'started')
print('healthy' if started > 0 else 'waiting')
" 2>/dev/null || echo "error")

        if [ "$status" = "healthy" ]; then
            # Also check HTTP health endpoint
            HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "https://${app}.fly.dev:9090/health" 2>/dev/null || echo "000")
            if [ "$HTTP_CODE" = "200" ]; then
                healthy=true
                break
            fi
        fi
        log_info "[$app] Health check $i/12: $status"
    done

    if [ "$healthy" = "true" ]; then
        log_success "[$app] Rotation complete - healthy"
    else
        log_error "[$app] Rotation completed but health check failed!"
        return 1
    fi
}

# =============================================================================
# Main
# =============================================================================

main() {
    echo ""
    log_info "=== HoneyClaw Rotation Cycle ==="
    log_info "Timestamp: $TIMESTAMP"
    log_info "Snapshot dir: $SNAPSHOT_DIR"
    [ -n "$EXPORT_BUCKET" ] && log_info "Export bucket: $EXPORT_BUCKET"
    [ "$DRY_RUN" = "true" ] && log_warn "DRY RUN MODE"
    echo ""

    mkdir -p "$SNAPSHOT_DIR"

    discover_apps "$@"

    local failed=0
    for app in "${APPS[@]}"; do
        if ! rotate_app "$app"; then
            failed=$((failed + 1))
        fi
        echo ""
    done

    echo ""
    if [ $failed -eq 0 ]; then
        log_success "All ${#APPS[@]} app(s) rotated successfully"
    else
        log_error "$failed of ${#APPS[@]} app(s) failed rotation"
        exit 1
    fi
}

main "$@"
