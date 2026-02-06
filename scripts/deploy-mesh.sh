#!/bin/bash
# Honey Claw - Multi-Region Mesh Deployment Script
# Deploy honeypots across Fly.io regions with centralized coordination
#
# Usage:
#   ./scripts/deploy-mesh.sh                    # Deploy to default 3 regions
#   ./scripts/deploy-mesh.sh us-west eu-central # Deploy to specific regions
#   MESH_TOKEN=secret ./scripts/deploy-mesh.sh  # Set mesh token
#
# Requirements:
#   - Fly.io CLI (flyctl) installed and authenticated
#   - Docker (for building images)

set -e

# =============================================================================
# Configuration
# =============================================================================

# Default regions (Fly.io region codes)
DEFAULT_REGIONS=("sjc" "iad" "ams")  # US-West, US-East, Amsterdam

# Region display names
declare -A REGION_NAMES=(
    ["sjc"]="US West (San Jose)"
    ["iad"]="US East (Virginia)"
    ["ams"]="Europe (Amsterdam)"
    ["lhr"]="Europe (London)"
    ["fra"]="Europe (Frankfurt)"
    ["nrt"]="Asia (Tokyo)"
    ["sin"]="Asia (Singapore)"
    ["syd"]="Australia (Sydney)"
    ["gru"]="South America (São Paulo)"
)

# App naming
APP_PREFIX="${APP_PREFIX:-honeyclaw}"
COORDINATOR_APP="${APP_PREFIX}-coordinator"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# Helper Functions
# =============================================================================

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v fly &> /dev/null; then
        log_error "Fly.io CLI not found. Install with: curl -L https://fly.io/install.sh | sh"
        exit 1
    fi
    
    if ! fly auth whoami &> /dev/null; then
        log_error "Not logged in to Fly.io. Run: fly auth login"
        exit 1
    fi
    
    log_success "Prerequisites OK"
}

generate_mesh_token() {
    if [ -z "$MESH_TOKEN" ]; then
        MESH_TOKEN=$(openssl rand -hex 32)
        log_info "Generated MESH_TOKEN: ${MESH_TOKEN:0:16}..."
    fi
}

# =============================================================================
# Deployment Functions
# =============================================================================

deploy_coordinator() {
    local region="${1:-sjc}"
    
    log_info "Deploying coordinator to ${REGION_NAMES[$region]:-$region}..."
    
    # Create coordinator app if needed
    if ! fly apps list | grep -q "$COORDINATOR_APP"; then
        log_info "Creating coordinator app: $COORDINATOR_APP"
        fly apps create "$COORDINATOR_APP" --org personal || true
    fi
    
    # Create volume for database
    if ! fly volumes list -a "$COORDINATOR_APP" 2>/dev/null | grep -q "honeyclaw_data"; then
        log_info "Creating coordinator volume..."
        fly volumes create honeyclaw_data \
            --app "$COORDINATOR_APP" \
            --region "$region" \
            --size 1 \
            --yes || true
    fi
    
    # Set secrets
    log_info "Setting coordinator secrets..."
    fly secrets set \
        --app "$COORDINATOR_APP" \
        COORDINATOR_TOKEN="$MESH_TOKEN" \
        MESH_TOKEN="$MESH_TOKEN" \
        MESH_ROLE="coordinator" \
        COORDINATOR_PORT="8443" \
        --stage
    
    # Generate fly.toml for coordinator
    cat > /tmp/fly-coordinator.toml << EOF
app = "$COORDINATOR_APP"
primary_region = "$region"

[build]
  dockerfile = "templates/Dockerfile.mesh"

[[services]]
  internal_port = 8443
  protocol = "tcp"
  
  [[services.ports]]
    handlers = ["tls", "http"]
    port = 443
  
  [[services.http_checks]]
    interval = 10000
    grace_period = "30s"
    method = "get"
    path = "/health"
    protocol = "http"
    timeout = 5000

[env]
  MESH_ROLE = "coordinator"
  COORDINATOR_PORT = "8443"

[mounts]
  source = "honeyclaw_data"
  destination = "/data"

[[vm]]
  cpu_kind = "shared"
  cpus = 1
  memory_mb = 512
EOF
    
    # Deploy
    fly deploy --config /tmp/fly-coordinator.toml --region "$region" --yes
    
    COORDINATOR_URL="https://${COORDINATOR_APP}.fly.dev"
    log_success "Coordinator deployed: $COORDINATOR_URL"
}

deploy_node() {
    local region="$1"
    local node_app="${APP_PREFIX}-node-${region}"
    
    log_info "Deploying node to ${REGION_NAMES[$region]:-$region}..."
    
    # Create node app if needed
    if ! fly apps list | grep -q "$node_app"; then
        log_info "Creating node app: $node_app"
        fly apps create "$node_app" --org personal || true
    fi
    
    # Create volume for logs
    if ! fly volumes list -a "$node_app" 2>/dev/null | grep -q "honeyclaw_data"; then
        log_info "Creating node volume..."
        fly volumes create honeyclaw_data \
            --app "$node_app" \
            --region "$region" \
            --size 1 \
            --yes || true
    fi
    
    # Set secrets
    log_info "Setting node secrets..."
    fly secrets set \
        --app "$node_app" \
        MESH_TOKEN="$MESH_TOKEN" \
        MESH_COORDINATOR_URL="$COORDINATOR_URL" \
        MESH_ENABLED="true" \
        MESH_REGION="$region" \
        MESH_ROLE="node" \
        --stage
    
    # Generate fly.toml for node
    cat > /tmp/fly-node-${region}.toml << EOF
app = "$node_app"
primary_region = "$region"

[build]
  dockerfile = "templates/Dockerfile.mesh"

[[services]]
  internal_port = 8022
  protocol = "tcp"
  
  [[services.ports]]
    port = 2222

[env]
  MESH_ENABLED = "true"
  MESH_REGION = "$region"
  MESH_ROLE = "node"
  PORT = "8022"
  SSH_BANNER = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  RATELIMIT_ENABLED = "true"
  RATELIMIT_CONN_PER_MIN = "20"
  RATELIMIT_AUTH_PER_HOUR = "200"

[mounts]
  source = "honeyclaw_data"
  destination = "/data"

[[vm]]
  cpu_kind = "shared"
  cpus = 1
  memory_mb = 256
EOF
    
    # Deploy
    fly deploy --config /tmp/fly-node-${region}.toml --region "$region" --yes
    
    # Get IP
    local node_ip=$(fly ips list -a "$node_app" --json 2>/dev/null | jq -r '.[0].address // "pending"')
    
    log_success "Node deployed: $node_app ($node_ip:2222)"
}

show_summary() {
    echo ""
    echo "=========================================="
    echo "       HONEYCLAW MESH DEPLOYED"
    echo "=========================================="
    echo ""
    echo "Coordinator: $COORDINATOR_URL"
    echo ""
    echo "Nodes:"
    
    for region in "${REGIONS[@]}"; do
        local node_app="${APP_PREFIX}-node-${region}"
        local node_ip=$(fly ips list -a "$node_app" --json 2>/dev/null | jq -r '.[0].address // "pending"')
        echo "  - ${REGION_NAMES[$region]:-$region}: ssh -p 2222 admin@${node_ip}"
    done
    
    echo ""
    echo "Monitor:"
    echo "  curl -H 'Authorization: Bearer ${MESH_TOKEN:0:16}...' $COORDINATOR_URL/stats"
    echo ""
    echo "View attackers:"
    echo "  curl -H 'Authorization: Bearer ${MESH_TOKEN:0:16}...' $COORDINATOR_URL/attackers?multi_region=true"
    echo ""
    echo "=========================================="
}

# =============================================================================
# Main
# =============================================================================

main() {
    echo ""
    echo "🍯 Honey Claw - Multi-Region Mesh Deployment"
    echo ""
    
    # Parse arguments
    if [ $# -gt 0 ]; then
        REGIONS=("$@")
    else
        REGIONS=("${DEFAULT_REGIONS[@]}")
    fi
    
    log_info "Deploying to regions: ${REGIONS[*]}"
    
    # Check prerequisites
    check_prerequisites
    
    # Generate token
    generate_mesh_token
    
    # Deploy coordinator first (in first region)
    deploy_coordinator "${REGIONS[0]}"
    
    # Deploy nodes in all regions
    for region in "${REGIONS[@]}"; do
        deploy_node "$region"
    done
    
    # Show summary
    show_summary
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
