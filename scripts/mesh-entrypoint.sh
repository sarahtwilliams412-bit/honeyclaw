#!/bin/bash
# Honey Claw Mesh - Container Entrypoint
# Determines node role and starts appropriate services

set -e

echo "[MESH] Starting Honey Claw Mesh Node"
echo "[MESH] Role: ${MESH_ROLE:-node}"
echo "[MESH] Region: ${MESH_REGION:-unknown}"

# Create log directories
mkdir -p /data/logs /data/mesh

case "${MESH_ROLE:-node}" in
    coordinator)
        echo "[MESH] Starting as COORDINATOR"
        exec python -m mesh.coordinator
        ;;
    node)
        echo "[MESH] Starting as NODE"
        # Start honeypot with mesh integration
        exec python honeypot.py
        ;;
    both)
        echo "[MESH] Starting COORDINATOR + NODE (combined mode)"
        # Start coordinator in background
        python -m mesh.coordinator &
        COORDINATOR_PID=$!
        
        # Wait for coordinator to be ready
        sleep 5
        
        # Start honeypot
        python honeypot.py &
        HONEYPOT_PID=$!
        
        # Wait for either to exit
        wait -n $COORDINATOR_PID $HONEYPOT_PID
        ;;
    *)
        echo "[MESH] Unknown role: ${MESH_ROLE}"
        exit 1
        ;;
esac
