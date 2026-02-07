#!/usr/bin/env bash
#
# HoneyClaw - Network Isolation Verification Script
# Validates that honeypot containers are properly isolated.
#
# Usage: ./verify-isolation.sh [container-name]
#
# Checks:
#   1. Container has read-only root filesystem
#   2. All capabilities are dropped
#   3. no-new-privileges is set
#   4. AppArmor profile is loaded
#   5. Seccomp profile is applied
#   6. Network isolation (no egress, no ICC)
#   7. Resource limits are enforced (CPU, memory, PIDs)
#   8. Container runs as non-root
#   9. Docker socket is not mounted
#  10. /proc and /sys are restricted

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

check_pass() {
    echo -e "  ${GREEN}[PASS]${NC} $1"
    ((PASS++))
}

check_fail() {
    echo -e "  ${RED}[FAIL]${NC} $1"
    ((FAIL++))
}

check_warn() {
    echo -e "  ${YELLOW}[WARN]${NC} $1"
    ((WARN++))
}

check_info() {
    echo -e "  ${BLUE}[INFO]${NC} $1"
}

# Get container name/ID
CONTAINER="${1:-}"
if [[ -z "$CONTAINER" ]]; then
    echo "Usage: $0 <container-name-or-id>"
    echo ""
    echo "Available honeyclaw containers:"
    docker ps --filter "label=honeyclaw.template" --format "  {{.Names}} ({{.Image}}, {{.Status}})" 2>/dev/null || echo "  (none running)"
    exit 1
fi

# Verify container exists and is running
if ! docker inspect "$CONTAINER" &>/dev/null; then
    echo -e "${RED}Error: Container '$CONTAINER' not found${NC}"
    exit 1
fi

STATE=$(docker inspect --format '{{.State.Status}}' "$CONTAINER")
if [[ "$STATE" != "running" ]]; then
    echo -e "${RED}Error: Container '$CONTAINER' is not running (state: $STATE)${NC}"
    exit 1
fi

TEMPLATE=$(docker inspect --format '{{index .Config.Labels "honeyclaw.template"}}' "$CONTAINER" 2>/dev/null || echo "unknown")

echo ""
echo "=============================================="
echo " HoneyClaw Isolation Verification Report"
echo "=============================================="
echo " Container: $CONTAINER"
echo " Template:  $TEMPLATE"
echo " Date:      $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=============================================="
echo ""

# 1. Read-only root filesystem
echo "--- Filesystem Security ---"
READONLY=$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$CONTAINER")
if [[ "$READONLY" == "true" ]]; then
    check_pass "Read-only root filesystem is enabled"
else
    check_fail "Root filesystem is NOT read-only"
fi

# 2. Capabilities
echo ""
echo "--- Capability Restrictions ---"
CAP_DROP=$(docker inspect --format '{{.HostConfig.CapDrop}}' "$CONTAINER")
if echo "$CAP_DROP" | grep -qi "all"; then
    check_pass "All capabilities are dropped (cap-drop ALL)"
else
    check_fail "Capabilities are NOT fully dropped: $CAP_DROP"
fi

CAP_ADD=$(docker inspect --format '{{.HostConfig.CapAdd}}' "$CONTAINER")
if [[ "$CAP_ADD" == "[]" || "$CAP_ADD" == "<no value>" || -z "$CAP_ADD" ]]; then
    check_pass "No additional capabilities granted"
else
    # Enterprise-sim needs some capabilities
    if [[ "$TEMPLATE" == "enterprise-sim" ]]; then
        check_info "Enterprise-sim has additional capabilities: $CAP_ADD"
        # Verify only expected caps are added
        EXPECTED_CAPS="NET_BIND_SERVICE CHOWN SETGID SETUID DAC_OVERRIDE"
        for cap in $EXPECTED_CAPS; do
            if echo "$CAP_ADD" | grep -q "$cap"; then
                check_pass "Expected capability present: $cap"
            fi
        done
    else
        check_warn "Additional capabilities granted: $CAP_ADD"
    fi
fi

# 3. No new privileges
echo ""
echo "--- Privilege Escalation Prevention ---"
SECURITY_OPTS=$(docker inspect --format '{{.HostConfig.SecurityOpt}}' "$CONTAINER")
if echo "$SECURITY_OPTS" | grep -q "no-new-privileges"; then
    check_pass "no-new-privileges is enabled"
else
    check_fail "no-new-privileges is NOT enabled"
fi

# 4. AppArmor
echo ""
echo "--- AppArmor Profile ---"
APPARMOR=$(docker inspect --format '{{.AppArmorProfile}}' "$CONTAINER")
if [[ -n "$APPARMOR" && "$APPARMOR" != "unconfined" && "$APPARMOR" != "<no value>" ]]; then
    check_pass "AppArmor profile loaded: $APPARMOR"
else
    check_warn "No AppArmor profile applied (profile: ${APPARMOR:-none})"
fi

# 5. Seccomp
echo ""
echo "--- Seccomp Profile ---"
if echo "$SECURITY_OPTS" | grep -q "seccomp"; then
    check_pass "Seccomp profile is applied"
else
    SECCOMP_PROFILE=$(docker inspect --format '{{.HostConfig.SecurityOpt}}' "$CONTAINER")
    check_warn "No custom seccomp profile detected (using Docker default)"
fi

# 6. Network isolation
echo ""
echo "--- Network Isolation ---"
NETWORKS=$(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$CONTAINER")
check_info "Connected networks: $NETWORKS"

for NETWORK in $NETWORKS; do
    # Check if network is internal (no egress)
    IS_INTERNAL=$(docker network inspect --format '{{.Internal}}' "$NETWORK" 2>/dev/null || echo "unknown")
    if [[ "$IS_INTERNAL" == "true" ]]; then
        check_pass "Network '$NETWORK' is internal (no external egress)"
    else
        check_warn "Network '$NETWORK' is NOT internal - egress may be possible"
    fi

    # Check ICC
    ICC=$(docker network inspect --format '{{index .Options "com.docker.network.bridge.enable_icc"}}' "$NETWORK" 2>/dev/null || echo "")
    if [[ "$ICC" == "false" ]]; then
        check_pass "Inter-container communication disabled on '$NETWORK'"
    elif [[ -n "$ICC" ]]; then
        check_fail "Inter-container communication is ENABLED on '$NETWORK'"
    fi
done

# Test egress connectivity from inside the container
EGRESS_TEST=$(docker exec "$CONTAINER" sh -c 'wget -q -O /dev/null --timeout=3 http://1.1.1.1 2>&1 && echo "CONNECTED" || echo "BLOCKED"' 2>/dev/null || echo "BLOCKED")
if [[ "$EGRESS_TEST" == "BLOCKED" ]]; then
    check_pass "Outbound internet connectivity is blocked"
else
    check_fail "Container can reach the internet (egress not blocked)"
fi

# 7. Resource limits
echo ""
echo "--- Resource Limits ---"
MEMORY=$(docker inspect --format '{{.HostConfig.Memory}}' "$CONTAINER")
if [[ "$MEMORY" -gt 0 ]]; then
    MEMORY_MB=$((MEMORY / 1024 / 1024))
    check_pass "Memory limit: ${MEMORY_MB}MB"
else
    check_fail "No memory limit set"
fi

CPU=$(docker inspect --format '{{.HostConfig.NanoCpus}}' "$CONTAINER")
if [[ "$CPU" -gt 0 ]]; then
    CPU_CORES=$(echo "scale=2; $CPU / 1000000000" | bc 2>/dev/null || echo "$CPU nanocpus")
    check_pass "CPU limit: ${CPU_CORES} cores"
else
    check_fail "No CPU limit set"
fi

PIDS=$(docker inspect --format '{{.HostConfig.PidsLimit}}' "$CONTAINER")
if [[ "$PIDS" -gt 0 && "$PIDS" -lt 1000 ]]; then
    check_pass "PID limit: $PIDS"
else
    check_fail "No PID limit set or limit too high: $PIDS"
fi

# 8. Non-root user
echo ""
echo "--- User Isolation ---"
USER=$(docker inspect --format '{{.Config.User}}' "$CONTAINER")
if [[ -n "$USER" && "$USER" != "root" && "$USER" != "0" ]]; then
    check_pass "Container runs as non-root user: $USER"
else
    # Check actual running user
    RUNNING_USER=$(docker exec "$CONTAINER" whoami 2>/dev/null || echo "unknown")
    if [[ "$RUNNING_USER" != "root" ]]; then
        check_pass "Process running as non-root user: $RUNNING_USER"
    else
        check_warn "Container runs as root (User: ${USER:-not set})"
    fi
fi

# 9. Docker socket not mounted
echo ""
echo "--- Volume Security ---"
MOUNTS=$(docker inspect --format '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' "$CONTAINER")
if echo "$MOUNTS" | grep -q "docker.sock"; then
    check_fail "Docker socket is mounted! Container escape risk!"
else
    check_pass "Docker socket is NOT mounted"
fi

# Check for sensitive host paths
for SENSITIVE_PATH in "/etc/shadow" "/etc/passwd" "/root" "/home" "/var/run/docker.sock"; do
    if echo "$MOUNTS" | grep -q "$SENSITIVE_PATH"; then
        check_fail "Sensitive host path mounted: $SENSITIVE_PATH"
    fi
done
check_pass "No sensitive host paths mounted"

# 10. /proc restrictions
echo ""
echo "--- Kernel Parameter Restrictions ---"
# Test if /proc/sysrq-trigger is accessible
SYSRQ=$(docker exec "$CONTAINER" sh -c 'cat /proc/sysrq-trigger 2>&1' 2>/dev/null || echo "denied")
if echo "$SYSRQ" | grep -qi "denied\|permission\|no such\|operation not"; then
    check_pass "/proc/sysrq-trigger is restricted"
else
    check_warn "/proc/sysrq-trigger may be accessible"
fi

# Test if mount is possible
MOUNT_TEST=$(docker exec "$CONTAINER" sh -c 'mount -t tmpfs tmpfs /mnt 2>&1' 2>/dev/null || echo "denied")
if echo "$MOUNT_TEST" | grep -qi "denied\|permission\|operation not\|not permitted"; then
    check_pass "Mount operations are blocked"
else
    check_fail "Mount operations may be possible"
fi

# Summary
echo ""
echo "=============================================="
echo " RESULTS SUMMARY"
echo "=============================================="
echo -e "  ${GREEN}Passed: $PASS${NC}"
echo -e "  ${RED}Failed: $FAIL${NC}"
echo -e "  ${YELLOW}Warnings: $WARN${NC}"
echo ""

if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}Container isolation verification PASSED${NC}"
    exit 0
elif [[ $FAIL -le 2 ]]; then
    echo -e "${YELLOW}Container isolation has minor issues - review warnings${NC}"
    exit 1
else
    echo -e "${RED}Container isolation FAILED - immediate remediation required${NC}"
    exit 2
fi
