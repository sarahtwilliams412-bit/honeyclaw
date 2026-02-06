#!/bin/bash
# Enterprise Honeypot Simulation - Teardown Script
# Safely destroys all simulation resources

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_DIR="$(dirname "$SCRIPT_DIR")"

echo "🍯 Honey Claw - Simulation Teardown"
echo "===================================="
echo ""
echo "⚠️  This will destroy the following:"
echo "   • All honeypot containers"
echo "   • Isolated network"
echo "   • In-memory state"
echo ""
echo "📁 The following will be PRESERVED:"
echo "   • Logs: $TEMPLATE_DIR/logs/"
echo "   • Intel: $TEMPLATE_DIR/intel/"
echo "   • Configuration files"
echo ""

read -p "Are you sure you want to proceed? [y/N] " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Teardown cancelled."
    exit 0
fi

echo ""
echo "🛑 Stopping nodes..."

NODES=(
    "ai-assistant-01"
    "mail-01"
    "files-internal-01"
    "db-mysql-01"
    "web-prod-01"
    "edge-gw-01"
)

for node in "${NODES[@]}"; do
    echo "   ⏹️  Stopping $node..."
    # In real implementation: docker stop honeyclaw-$node
    sleep 0.3
done

echo "✅ All nodes stopped"

echo ""
echo "🗑️  Removing containers..."
for node in "${NODES[@]}"; do
    echo "   🗑️  Removing $node..."
    # In real implementation: docker rm honeyclaw-$node
    sleep 0.2
done
echo "✅ Containers removed"

echo ""
echo "🌐 Removing network..."
# In real implementation: docker network rm honeyclaw-sim
echo "✅ Network removed"

echo ""
echo "════════════════════════════════════════════════════"
echo "✅ TEARDOWN COMPLETE"
echo "════════════════════════════════════════════════════"
echo ""
echo "Logs preserved at: $TEMPLATE_DIR/logs/"
echo "Intel preserved at: $TEMPLATE_DIR/intel/"
echo ""
echo "To redeploy: $SCRIPT_DIR/deploy.sh"
