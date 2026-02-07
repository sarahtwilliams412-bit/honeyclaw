"""
Honeyclaw Health Monitoring & Self-Healing System

Periodic health checks for all active honeypot services with
compromise detection, resource monitoring, and automated response.

Features:
- Service availability checks (port connectivity)
- Resource usage monitoring (CPU, memory, disk, file descriptors)
- Network isolation verification (egress blocking, credential hygiene)
- Compromise detection (unexpected processes, cron jobs, filesystem changes)
- Automated self-healing (alerting, forensic snapshots, container rebuild)
- Background monitoring with configurable intervals
- CLI integration (honeyclaw health status/check/log)
"""

from .monitor import (
    HealthMonitor,
    HealthConfig,
    HealthReport,
    HealthStatus,
    ServiceCheck,
    ServiceStatus,
    IsolationCheck,
    ResourceMetrics,
    CompromiseIndicator,
    get_monitor,
    check_health,
    start_monitoring,
    stop_monitoring,
)
from .self_heal import (
    SelfHealer,
    SelfHealConfig,
    HealAction,
)

__all__ = [
    # Monitor
    'HealthMonitor',
    'HealthConfig',
    'HealthReport',
    'HealthStatus',
    'ServiceCheck',
    'ServiceStatus',
    'IsolationCheck',
    'ResourceMetrics',
    'CompromiseIndicator',
    'get_monitor',
    'check_health',
    'start_monitoring',
    'stop_monitoring',
    # Self-heal
    'SelfHealer',
    'SelfHealConfig',
    'HealAction',
]
