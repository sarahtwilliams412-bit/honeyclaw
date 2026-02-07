#!/usr/bin/env bash
#
# Honey Claw - Honeypot Deployment Script
# Deploys sandboxed honeypot containers for threat detection
#
# Usage: ./deploy-honeypot.sh --template <template> --name <name> [options]
#

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEMPLATES_DIR="${PROJECT_ROOT}/templates"
NETWORK_NAME="${HONEYCLAW_NETWORK:-honeyclaw-net}"
LOG_DIR="${HONEYCLAW_LOG_DIR:-/var/log/honeyclaw}"
S3_BUCKET="${HONEYCLAW_S3_BUCKET:-}"
S3_ENDPOINT="${HONEYCLAW_S3_ENDPOINT:-https://s3.amazonaws.com}"
DEPLOY_DIR="${PROJECT_ROOT}/deploy"

# SIEM Integration
SIEM_CONFIG="${HONEYCLAW_SIEM_CONFIG:-}"
SIEM_PROVIDER="${HONEYCLAW_SIEM_PROVIDER:-}"
SIEM_ENDPOINT="${HONEYCLAW_SIEM_ENDPOINT:-}"
SIEM_TOKEN="${HONEYCLAW_SIEM_TOKEN:-}"

# Security profiles
APPARMOR_ENABLED="${HONEYCLAW_APPARMOR:-true}"
SECCOMP_ENABLED="${HONEYCLAW_SECCOMP:-true}"
ISOLATION_STRICT="${HONEYCLAW_STRICT_ISOLATION:-true}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Default values
TEMPLATE=""
NAME=""
PORT=""
PORTS=""
DETACH=true
FORCE=false
SIEM_ENABLED=false
SIEM_ARG=""
NO_APPARMOR=false
NO_SECCOMP=false
NO_ISOLATION=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --template|-t)
            TEMPLATE="$2"
            shift 2
            ;;
        --name|-n)
            NAME="$2"
            shift 2
            ;;
        --port|-p)
            PORT="$2"
            shift 2
            ;;
        --ports)
            PORTS="$2"
            shift 2
            ;;
        --detach|-d)
            DETACH=true
            shift
            ;;
        --no-detach)
            DETACH=false
            shift
            ;;
        --force|-f)
            FORCE=true
            shift
            ;;
        --siem)
            SIEM_ENABLED=true
            if [[ -n "${2:-}" && ! "$2" =~ ^- ]]; then
                SIEM_ARG="$2"
                shift
            fi
            shift
            ;;
        --no-apparmor)
            NO_APPARMOR=true
            shift
            ;;
        --no-seccomp)
            NO_SECCOMP=true
            shift
            ;;
        --no-isolation)
            NO_ISOLATION=true
            shift
            ;;
        --help|-h)
            cat <<EOF
Honey Claw - Honeypot Deployment

Usage: $(basename "$0") --template <template> --name <name> [options]

Options:
  -t, --template <name>   Honeypot template (basic-ssh, fake-api, enterprise-sim)
  -n, --name <id>         Unique identifier for this honeypot
  -p, --port <port>       External port mapping (default: template default)
      --ports <ports>     Multiple ports, comma-separated
  -d, --detach            Run in background (default)
      --no-detach         Run in foreground
  -f, --force             Remove existing honeypot with same name
      --siem [config]     Enable SIEM integration (config file or provider name)
      --no-apparmor       Disable AppArmor profile (not recommended)
      --no-seccomp        Disable seccomp profile (not recommended)
      --no-isolation      Disable strict network isolation
  -h, --help              Show this help message

Environment Variables:
  HONEYCLAW_NETWORK       Docker network name (default: honeyclaw-net)
  HONEYCLAW_LOG_DIR       Local log directory (default: /var/log/honeyclaw)
  HONEYCLAW_S3_BUCKET     S3 bucket for log shipping
  HONEYCLAW_S3_ENDPOINT   S3 endpoint URL
  HONEYCLAW_SIEM_PROVIDER SIEM provider (splunk, elastic, sentinel, syslog)
  HONEYCLAW_SIEM_ENDPOINT SIEM endpoint URL
  HONEYCLAW_SIEM_TOKEN    SIEM authentication token
  HONEYCLAW_APPARMOR      Enable AppArmor profiles (default: true)
  HONEYCLAW_SECCOMP       Enable seccomp profiles (default: true)
  HONEYCLAW_STRICT_ISOLATION  Enable strict network isolation (default: true)

Examples:
  # Deploy SSH honeypot on port 2222
  $(basename "$0") --template basic-ssh --name prod-bastion --port 2222

  # Deploy fake API on port 8080
  $(basename "$0") --template fake-api --name api-staging --port 8080

  # Deploy full enterprise simulation
  $(basename "$0") --template enterprise-sim --name corp-dc --ports 22,80,443,3389

  # Deploy with Splunk SIEM integration
  $(basename "$0") --template basic-ssh --name edge-ssh --port 22 --siem splunk

  # Deploy with custom SIEM config file
  $(basename "$0") --template basic-ssh --name ssh-prod --siem /etc/honeyclaw/siem.yaml
EOF
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate required arguments
if [[ -z "$TEMPLATE" ]]; then
    log_error "Template is required. Use --template <name>"
    exit 1
fi

if [[ -z "$NAME" ]]; then
    log_error "Name is required. Use --name <id>"
    exit 1
fi

# Validate template exists
TEMPLATE_DIR="${TEMPLATES_DIR}/${TEMPLATE}"
if [[ ! -d "$TEMPLATE_DIR" ]]; then
    log_error "Template not found: $TEMPLATE"
    log_info "Available templates:"
    ls -1 "$TEMPLATES_DIR" 2>/dev/null || echo "  (none)"
    exit 1
fi

# Container name
CONTAINER_NAME="honeyclaw-${NAME}"

# Check for existing container
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    if [[ "$FORCE" == true ]]; then
        log_warn "Removing existing container: $CONTAINER_NAME"
        docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    else
        log_error "Container already exists: $CONTAINER_NAME"
        log_info "Use --force to replace it"
        exit 1
    fi
fi

# Ensure network exists
if ! docker network ls --format '{{.Name}}' | grep -q "^${NETWORK_NAME}$"; then
    log_info "Creating Docker network: $NETWORK_NAME"
    NETWORK_OPTS=(
        --driver bridge
        --opt com.docker.network.bridge.enable_icc=false
    )
    if [[ "$NO_ISOLATION" != true && "$ISOLATION_STRICT" == true ]]; then
        NETWORK_OPTS+=(
            --opt com.docker.network.bridge.enable_ip_masquerade=false
            --internal
        )
        log_info "Strict network isolation enabled (no egress, no ICC)"
    else
        NETWORK_OPTS+=(
            --opt com.docker.network.bridge.enable_ip_masquerade=false
        )
        if [[ "$NO_ISOLATION" == true ]]; then
            log_warn "Strict isolation disabled via --no-isolation flag"
        fi
    fi
    docker network create "$NETWORK_NAME" "${NETWORK_OPTS[@]}"
    log_ok "Network created"
fi

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Load template configuration
TEMPLATE_CONFIG="${TEMPLATE_DIR}/config.yaml"
if [[ ! -f "$TEMPLATE_CONFIG" ]]; then
    log_error "Template config not found: $TEMPLATE_CONFIG"
    exit 1
fi

# Get default port from template if not specified
if [[ -z "$PORT" && -z "$PORTS" ]]; then
    # Try to extract default port from config
    PORT=$(grep -E "^default_port:" "$TEMPLATE_CONFIG" 2>/dev/null | awk '{print $2}' || echo "")
fi

# Build port mapping
PORT_ARGS=""
if [[ -n "$PORTS" ]]; then
    IFS=',' read -ra PORT_ARRAY <<< "$PORTS"
    for p in "${PORT_ARRAY[@]}"; do
        PORT_ARGS="$PORT_ARGS -p ${p}:${p}"
    done
elif [[ -n "$PORT" ]]; then
    # Map to internal port based on template
    case "$TEMPLATE" in
        basic-ssh)
            PORT_ARGS="-p ${PORT}:22"
            ;;
        fake-api)
            PORT_ARGS="-p ${PORT}:8080"
            ;;
        enterprise-sim)
            PORT_ARGS="-p ${PORT}:22"
            ;;
        *)
            PORT_ARGS="-p ${PORT}:${PORT}"
            ;;
    esac
fi

# Build the container image if Dockerfile exists
DOCKERFILE="${TEMPLATE_DIR}/Dockerfile"
IMAGE_NAME="honeyclaw/${TEMPLATE}:latest"

if [[ -f "$DOCKERFILE" ]]; then
    log_info "Building image: $IMAGE_NAME"
    docker build -t "$IMAGE_NAME" "$TEMPLATE_DIR" --quiet
    log_ok "Image built"
else
    log_error "Dockerfile not found: $DOCKERFILE"
    exit 1
fi

# Prepare logging
HONEYPOT_LOG_DIR="${LOG_DIR}/${NAME}"
mkdir -p "$HONEYPOT_LOG_DIR"

# Process SIEM configuration
if [[ "$SIEM_ENABLED" == true ]]; then
    log_info "SIEM integration enabled"
    
    # If SIEM_ARG is a file, source it
    if [[ -f "$SIEM_ARG" ]]; then
        log_info "Loading SIEM config from: $SIEM_ARG"
        # For YAML files, we'd need yq or similar - for now, support simple key=value
        if [[ "$SIEM_ARG" =~ \.yaml$ || "$SIEM_ARG" =~ \.yml$ ]]; then
            SIEM_PROVIDER=$(grep -E "^\s*provider:" "$SIEM_ARG" 2>/dev/null | awk '{print $2}' || echo "")
            SIEM_ENDPOINT=$(grep -E "^\s*endpoint:" "$SIEM_ARG" 2>/dev/null | awk '{print $2}' || echo "")
            # Token might be env var reference like ${SPLUNK_HEC_TOKEN}
            SIEM_TOKEN_RAW=$(grep -E "^\s*token:" "$SIEM_ARG" 2>/dev/null | awk '{print $2}' || echo "")
            if [[ "$SIEM_TOKEN_RAW" =~ ^\$\{([^}]+)\}$ ]]; then
                SIEM_TOKEN="${!BASH_REMATCH[1]:-}"
            else
                SIEM_TOKEN="$SIEM_TOKEN_RAW"
            fi
        fi
    elif [[ -n "$SIEM_ARG" ]]; then
        # Treat as provider name if not a file
        SIEM_PROVIDER="$SIEM_ARG"
    fi
    
    # Use environment variables as fallback
    SIEM_PROVIDER="${SIEM_PROVIDER:-$HONEYCLAW_SIEM_PROVIDER}"
    SIEM_ENDPOINT="${SIEM_ENDPOINT:-$HONEYCLAW_SIEM_ENDPOINT}"
    SIEM_TOKEN="${SIEM_TOKEN:-$HONEYCLAW_SIEM_TOKEN}"
    
    if [[ -n "$SIEM_PROVIDER" ]]; then
        log_ok "SIEM Provider: $SIEM_PROVIDER"
    else
        log_warn "SIEM enabled but no provider specified. Set HONEYCLAW_SIEM_PROVIDER or use --siem <provider>"
    fi
fi

# Deploy container
log_info "Deploying honeypot: $NAME (template: $TEMPLATE)"

DETACH_FLAG=""
if [[ "$DETACH" == true ]]; then
    DETACH_FLAG="-d"
fi

# Template-specific resource limits
case "$TEMPLATE" in
    basic-ssh)
        MEMORY_LIMIT="64m"
        CPU_LIMIT="0.25"
        PIDS_LIMIT="20"
        SECCOMP_PROFILE="honeyclaw-ssh.json"
        APPARMOR_PROFILE="honeyclaw-ssh"
        ;;
    fake-api)
        MEMORY_LIMIT="128m"
        CPU_LIMIT="0.5"
        PIDS_LIMIT="30"
        SECCOMP_PROFILE="honeyclaw-default.json"
        APPARMOR_PROFILE="honeyclaw-api"
        ;;
    enterprise-sim)
        MEMORY_LIMIT="512m"
        CPU_LIMIT="0.5"
        PIDS_LIMIT="100"
        SECCOMP_PROFILE="honeyclaw-enterprise.json"
        APPARMOR_PROFILE="honeyclaw-enterprise"
        ;;
    *)
        MEMORY_LIMIT="128m"
        CPU_LIMIT="0.5"
        PIDS_LIMIT="50"
        SECCOMP_PROFILE="honeyclaw-default.json"
        APPARMOR_PROFILE=""
        ;;
esac

# Build docker run command
DOCKER_CMD=(
    docker run
    $DETACH_FLAG
    --name "$CONTAINER_NAME"
    --network "$NETWORK_NAME"
    --restart unless-stopped
    --read-only
    --security-opt no-new-privileges:true
    --cap-drop ALL
    --memory "$MEMORY_LIMIT"
    --cpus "$CPU_LIMIT"
    --pids-limit "$PIDS_LIMIT"
    --tmpfs /tmp:noexec,nosuid,size=32m
    -v "${HONEYPOT_LOG_DIR}:/var/log/honeypot:rw"
    -e "HONEYPOT_ID=${NAME}"
    -e "HONEYPOT_TEMPLATE=${TEMPLATE}"
    -e "S3_BUCKET=${S3_BUCKET}"
    -e "S3_ENDPOINT=${S3_ENDPOINT}"
    -e "SIEM_ENABLED=${SIEM_ENABLED}"
    -e "SIEM_PROVIDER=${SIEM_PROVIDER}"
    -e "SIEM_ENDPOINT=${SIEM_ENDPOINT}"
    -e "SIEM_TOKEN=${SIEM_TOKEN}"
    --label "honeyclaw.name=${NAME}"
    --label "honeyclaw.template=${TEMPLATE}"
    --label "honeyclaw.deployed=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    --label "honeyclaw.isolation=strict"
)

# Enterprise-sim needs specific capabilities for multi-service operation
if [[ "$TEMPLATE" == "enterprise-sim" ]]; then
    DOCKER_CMD+=(
        --cap-add NET_BIND_SERVICE
        --cap-add CHOWN
        --cap-add SETGID
        --cap-add SETUID
        --cap-add DAC_OVERRIDE
        --tmpfs /run:noexec,nosuid,size=16m
        --tmpfs /var/run:noexec,nosuid,size=16m
    )
fi

# AppArmor profile
if [[ "$NO_APPARMOR" != true && "$APPARMOR_ENABLED" == true && -n "$APPARMOR_PROFILE" ]]; then
    PROFILE_PATH="${DEPLOY_DIR}/apparmor/${APPARMOR_PROFILE}.profile"
    if [[ -f "$PROFILE_PATH" ]]; then
        DOCKER_CMD+=(--security-opt "apparmor=${APPARMOR_PROFILE}")
        log_info "AppArmor profile: $APPARMOR_PROFILE"
    else
        log_warn "AppArmor profile not found at $PROFILE_PATH - running without AppArmor"
    fi
elif [[ "$NO_APPARMOR" == true ]]; then
    log_warn "AppArmor disabled via --no-apparmor flag"
fi

# Seccomp profile
if [[ "$NO_SECCOMP" != true && "$SECCOMP_ENABLED" == true ]]; then
    SECCOMP_PATH="${DEPLOY_DIR}/seccomp/${SECCOMP_PROFILE}"
    if [[ -f "$SECCOMP_PATH" ]]; then
        DOCKER_CMD+=(--security-opt "seccomp=${SECCOMP_PATH}")
        log_info "Seccomp profile: $SECCOMP_PROFILE"
    else
        log_warn "Seccomp profile not found at $SECCOMP_PATH - running with Docker default seccomp"
    fi
elif [[ "$NO_SECCOMP" == true ]]; then
    log_warn "Seccomp disabled via --no-seccomp flag"
fi

# Add port mappings
if [[ -n "$PORT_ARGS" ]]; then
    # shellcheck disable=SC2206
    DOCKER_CMD+=($PORT_ARGS)
fi

# Add image name
DOCKER_CMD+=("$IMAGE_NAME")

# Execute
CONTAINER_ID=$("${DOCKER_CMD[@]}")

if [[ "$DETACH" == true ]]; then
    # Get short container ID
    SHORT_ID="${CONTAINER_ID:0:12}"
    
    log_ok "Honeypot deployed successfully!"
    echo ""
    echo "  Honeypot ID:    $NAME"
    echo "  Container ID:   $SHORT_ID"
    echo "  Template:       $TEMPLATE"
    echo "  Network:        $NETWORK_NAME"
    echo "  Logs:           $HONEYPOT_LOG_DIR"
    echo "  Resources:      CPU=${CPU_LIMIT}, Mem=${MEMORY_LIMIT}, PIDs=${PIDS_LIMIT}"
    echo "  AppArmor:       ${APPARMOR_PROFILE:-none}"
    echo "  Seccomp:        ${SECCOMP_PROFILE}"
    echo "  Isolation:      $([ "$NO_ISOLATION" != true ] && echo 'strict' || echo 'standard')"
    echo ""
    
    # Show port mappings
    if [[ -n "$PORT_ARGS" ]]; then
        echo "  Ports:"
        docker port "$CONTAINER_NAME" 2>/dev/null | while read -r line; do
            echo "    $line"
        done
        echo ""
    fi
    
    log_info "Monitor with: docker logs -f $CONTAINER_NAME"
    log_info "Destroy with: docker rm -f $CONTAINER_NAME"
    
    # Output JSON for programmatic use
    if [[ "${HONEYCLAW_OUTPUT_JSON:-false}" == "true" ]]; then
        cat <<EOF
{
  "success": true,
  "honeypot_id": "$NAME",
  "container_id": "$CONTAINER_ID",
  "template": "$TEMPLATE",
  "network": "$NETWORK_NAME",
  "log_dir": "$HONEYPOT_LOG_DIR",
  "status": "running"
}
EOF
    fi
else
    # Running in foreground, container will output directly
    log_info "Running in foreground. Ctrl+C to stop."
fi
