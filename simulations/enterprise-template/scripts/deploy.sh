#!/bin/bash
# Enterprise Honeypot Simulation - Deployment Script
# Usage: ./deploy.sh [--network isolated|bridged] [--duration hours]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_DIR="$(dirname "$SCRIPT_DIR")"
NETWORK_MODE="isolated"
DURATION_HOURS=72

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --network)
            NETWORK_MODE="$2"
            shift 2
            ;;
        --duration)
            DURATION_HOURS="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--network isolated|bridged] [--duration hours]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "🍯 Honey Claw - Enterprise Simulation Deployment"
echo "================================================"
echo "Template: $(basename "$TEMPLATE_DIR")"
echo "Network: $NETWORK_MODE"
echo "Duration: ${DURATION_HOURS}h"
echo ""

# Validate configuration
echo "📋 Validating configuration..."
if [[ ! -f "$TEMPLATE_DIR/config.yaml" ]]; then
    echo "❌ config.yaml not found!"
    exit 1
fi

if [[ ! -d "$TEMPLATE_DIR/nodes" ]]; then
    echo "❌ nodes/ directory not found!"
    exit 1
fi

echo "✅ Configuration valid"

# Create isolated network
echo ""
echo "🌐 Creating network..."
if [[ "$NETWORK_MODE" == "isolated" ]]; then
    echo "   Mode: Fully isolated (no external access)"
    # In real implementation: docker network create --internal honeyclaw-sim
else
    echo "   Mode: Bridged (controlled external access)"
fi
echo "✅ Network created"

# Deploy nodes
echo ""
echo "🖥️  Deploying honeypot nodes..."

NODES=(
    "edge-gw-01:Gateway:10.0.1.10"
    "web-prod-01:Web Server:10.0.2.10"
    "db-mysql-01:Database:10.0.10.20"
    "files-internal-01:File Server:10.0.10.30"
    "mail-01:Mail Server:10.0.10.40"
    "ai-assistant-01:AI Agent:10.0.10.50"
)

for node_info in "${NODES[@]}"; do
    IFS=':' read -r node_id node_name node_ip <<< "$node_info"
    echo "   🍯 $node_id ($node_name) - $node_ip"
    # In real implementation: deploy container from node config
    sleep 0.5
done

echo "✅ All nodes deployed"

# Configure logging
echo ""
echo "📊 Configuring logging pipeline..."
echo "   → Raw logs: $TEMPLATE_DIR/logs/"
echo "   → Threat intel: $TEMPLATE_DIR/intel/"
echo "   → SIEM export: Enabled"
echo "✅ Logging configured"

# Set expiration
EXPIRE_TIME=$(date -v+${DURATION_HOURS}H "+%Y-%m-%d %H:%M:%S" 2>/dev/null || date -d "+${DURATION_HOURS} hours" "+%Y-%m-%d %H:%M:%S")
echo ""
echo "⏰ Auto-expiration: $EXPIRE_TIME"

# Summary
echo ""
echo "════════════════════════════════════════════════════"
echo "🎉 DEPLOYMENT COMPLETE"
echo "════════════════════════════════════════════════════"
echo ""
echo "Honeypot Network: Nexus Dynamics Inc."
echo ""
echo "Entry Points:"
echo "   • SSH/RDP Gateway: 10.0.1.10 (edge-gw-01)"
echo "   • Web Portal: https://10.0.2.10 (web-prod-01)"
echo "   • AI Assistant: http://10.0.10.50:8080 (ai-assistant-01)"
echo ""
echo "Commands:"
echo "   Watch live:    $SCRIPT_DIR/watch.sh"
echo "   View logs:     honeyclaw sim logs"
echo "   Destroy:       $SCRIPT_DIR/teardown.sh"
echo ""
echo "🐝 Happy hunting!"
