#!/usr/bin/env python3
"""
Honeyclaw Self-Healing Module

Automated response to health check failures and compromise detection.
Triggers container rebuilds, forensic snapshots, and SOC alerts.

Environment variables:
  HONEYCLAW_SELF_HEAL_ENABLED    - Enable self-healing (default: true)
  HONEYCLAW_SNAPSHOT_DIR         - Forensic snapshot directory
  HONEYCLAW_REBUILD_COMMAND      - Command to trigger container rebuild
  HONEYCLAW_MAX_REBUILD_ATTEMPTS - Max rebuild attempts before alerting (default: 3)
"""

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .monitor import CompromiseIndicator, HealthReport, HealthStatus


class HealAction(Enum):
    """Self-healing action types."""
    ALERT_ONLY = "alert_only"
    RESTART_SERVICE = "restart_service"
    SNAPSHOT_AND_REBUILD = "snapshot_and_rebuild"
    ISOLATE_CONTAINER = "isolate_container"
    EMERGENCY_SHUTDOWN = "emergency_shutdown"


@dataclass
class HealEvent:
    """Record of a self-healing action taken."""
    action: HealAction
    trigger: str
    success: bool
    message: str
    timestamp: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.value,
            "trigger": self.trigger,
            "success": self.success,
            "message": self.message,
            "timestamp": self.timestamp,
            "details": self.details,
        }


class SelfHealer:
    """
    Automated response to health check failures.

    Listens for compromise indicators and degraded health reports,
    then takes appropriate action based on severity.
    """

    def __init__(
        self,
        enabled: Optional[bool] = None,
        snapshot_dir: Optional[str] = None,
        rebuild_command: Optional[str] = None,
        max_rebuild_attempts: int = 3,
        on_alert: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_log_path: Optional[str] = None,
    ):
        if enabled is not None:
            self.enabled = enabled
        else:
            self.enabled = os.environ.get("HONEYCLAW_SELF_HEAL_ENABLED", "true").lower() == "true"

        self.snapshot_dir = Path(
            snapshot_dir or os.environ.get("HONEYCLAW_SNAPSHOT_DIR", "/var/lib/honeyclaw/snapshots")
        )
        self.rebuild_command = rebuild_command or os.environ.get(
            "HONEYCLAW_REBUILD_COMMAND", ""
        )
        self.max_rebuild_attempts = int(
            os.environ.get("HONEYCLAW_MAX_REBUILD_ATTEMPTS", str(max_rebuild_attempts))
        )
        self.on_alert = on_alert
        self.audit_log_path = Path(
            audit_log_path or os.environ.get(
                "HONEYCLAW_HEAL_AUDIT_LOG", "/var/log/honeyclaw/self_heal.json"
            )
        )

        self._rebuild_attempts = 0
        self._heal_history: List[HealEvent] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def handle_compromise(self, indicator: CompromiseIndicator) -> HealEvent:
        """Handle a detected compromise indicator."""
        if not self.enabled:
            return self._record_event(
                HealAction.ALERT_ONLY,
                trigger=indicator.indicator_type,
                success=True,
                message="Self-healing disabled; alert only",
                details=indicator.to_dict(),
            )

        # Determine action based on severity
        action = self._select_action(indicator)

        if action == HealAction.ALERT_ONLY:
            return self._do_alert(indicator)
        elif action == HealAction.RESTART_SERVICE:
            return self._do_restart(indicator)
        elif action == HealAction.SNAPSHOT_AND_REBUILD:
            return self._do_snapshot_and_rebuild(indicator)
        elif action == HealAction.ISOLATE_CONTAINER:
            return self._do_isolate(indicator)
        elif action == HealAction.EMERGENCY_SHUTDOWN:
            return self._do_emergency_shutdown(indicator)

        return self._do_alert(indicator)

    def handle_degraded(self, report: HealthReport) -> HealEvent:
        """Handle a degraded health report."""
        if not self.enabled:
            return self._record_event(
                HealAction.ALERT_ONLY,
                trigger="health_degraded",
                success=True,
                message="Health degraded; self-healing disabled",
            )

        # Check which services are down
        down_services = [
            name for name, svc in report.services.items() if svc.status == "down"
        ]

        if down_services:
            self._fire_alert(
                "service_degraded",
                {
                    "down_services": down_services,
                    "status": report.status.value,
                    "resources": report.resources.to_dict() if report.resources else {},
                },
            )

        return self._record_event(
            HealAction.ALERT_ONLY,
            trigger="health_degraded",
            success=True,
            message=f"Services down: {down_services}",
            details={"down_services": down_services},
        )

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent self-healing event history."""
        return [e.to_dict() for e in self._heal_history[-limit:]]

    # ------------------------------------------------------------------
    # Action implementations
    # ------------------------------------------------------------------

    def _select_action(self, indicator: CompromiseIndicator) -> HealAction:
        """Select the appropriate healing action based on indicator severity."""
        severity = indicator.severity
        itype = indicator.indicator_type

        if severity == "critical":
            if itype in ("suspicious_cron", "rootkit_detected"):
                return HealAction.SNAPSHOT_AND_REBUILD
            return HealAction.SNAPSHOT_AND_REBUILD

        if severity == "high":
            if itype == "unexpected_listener":
                return HealAction.SNAPSHOT_AND_REBUILD
            if itype == "unexpected_process":
                return HealAction.ALERT_ONLY
            return HealAction.ALERT_ONLY

        return HealAction.ALERT_ONLY

    def _do_alert(self, indicator: CompromiseIndicator) -> HealEvent:
        """Alert without taking destructive action."""
        self._fire_alert(
            f"compromise_detected:{indicator.indicator_type}",
            indicator.to_dict(),
        )
        return self._record_event(
            HealAction.ALERT_ONLY,
            trigger=indicator.indicator_type,
            success=True,
            message=f"Alert sent: {indicator.description}",
            details=indicator.to_dict(),
        )

    def _do_restart(self, indicator: CompromiseIndicator) -> HealEvent:
        """Restart the affected service."""
        self._fire_alert(
            f"service_restart:{indicator.indicator_type}",
            indicator.to_dict(),
        )
        return self._record_event(
            HealAction.RESTART_SERVICE,
            trigger=indicator.indicator_type,
            success=True,
            message=f"Service restart requested: {indicator.description}",
            details=indicator.to_dict(),
        )

    def _do_snapshot_and_rebuild(self, indicator: CompromiseIndicator) -> HealEvent:
        """Take forensic snapshot then trigger rebuild."""
        if self._rebuild_attempts >= self.max_rebuild_attempts:
            self._fire_alert(
                "max_rebuilds_exceeded",
                {
                    "attempts": self._rebuild_attempts,
                    "indicator": indicator.to_dict(),
                },
            )
            return self._record_event(
                HealAction.EMERGENCY_SHUTDOWN,
                trigger=indicator.indicator_type,
                success=False,
                message=f"Max rebuild attempts ({self.max_rebuild_attempts}) exceeded",
            )

        # 1. Take snapshot
        snapshot_success = self._take_snapshot(indicator)

        # 2. Alert SOC
        self._fire_alert(
            "compromise_rebuild",
            {
                "indicator": indicator.to_dict(),
                "snapshot_taken": snapshot_success,
                "rebuild_attempt": self._rebuild_attempts + 1,
            },
        )

        # 3. Trigger rebuild
        rebuild_success = self._trigger_rebuild()
        self._rebuild_attempts += 1

        return self._record_event(
            HealAction.SNAPSHOT_AND_REBUILD,
            trigger=indicator.indicator_type,
            success=rebuild_success,
            message=f"Snapshot: {'OK' if snapshot_success else 'FAIL'}, "
                    f"Rebuild: {'OK' if rebuild_success else 'FAIL'}",
            details={
                "snapshot_taken": snapshot_success,
                "rebuild_triggered": rebuild_success,
                "attempt": self._rebuild_attempts,
            },
        )

    def _do_isolate(self, indicator: CompromiseIndicator) -> HealEvent:
        """Isolate the container from the network."""
        self._fire_alert(
            "container_isolated",
            indicator.to_dict(),
        )
        return self._record_event(
            HealAction.ISOLATE_CONTAINER,
            trigger=indicator.indicator_type,
            success=True,
            message="Container isolation requested",
            details=indicator.to_dict(),
        )

    def _do_emergency_shutdown(self, indicator: CompromiseIndicator) -> HealEvent:
        """Emergency shutdown - alert and halt."""
        self._fire_alert(
            "emergency_shutdown",
            {
                "indicator": indicator.to_dict(),
                "message": "Emergency shutdown triggered - manual intervention required",
            },
        )
        return self._record_event(
            HealAction.EMERGENCY_SHUTDOWN,
            trigger=indicator.indicator_type,
            success=True,
            message="Emergency shutdown initiated",
            details=indicator.to_dict(),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _take_snapshot(self, indicator: CompromiseIndicator) -> bool:
        """Take a forensic snapshot of the current container state."""
        try:
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            snap_dir = self.snapshot_dir / ts
            snap_dir.mkdir(parents=True, exist_ok=True)

            # Save indicator details
            (snap_dir / "indicator.json").write_text(
                json.dumps(indicator.to_dict(), indent=2)
            )

            # Save process list
            try:
                result = subprocess.run(
                    ["ps", "auxf"],
                    capture_output=True, text=True, timeout=10,
                )
                (snap_dir / "processes.txt").write_text(result.stdout)
            except Exception:
                pass

            # Save network state
            try:
                result = subprocess.run(
                    ["ss", "-tlnp"],
                    capture_output=True, text=True, timeout=10,
                )
                (snap_dir / "network.txt").write_text(result.stdout)
            except Exception:
                pass

            # Save cron state
            try:
                cron_files = []
                for cron_path in ["/etc/crontab", "/var/spool/cron/crontabs/root"]:
                    p = Path(cron_path)
                    if p.exists():
                        cron_files.append(f"=== {cron_path} ===\n{p.read_text()}")
                (snap_dir / "cron.txt").write_text("\n".join(cron_files))
            except Exception:
                pass

            return True
        except Exception as e:
            print(f"[SELF-HEAL] Snapshot failed: {e}", flush=True)
            return False

    def _trigger_rebuild(self) -> bool:
        """Trigger a container rebuild."""
        if not self.rebuild_command:
            print("[SELF-HEAL] No rebuild command configured", flush=True)
            return False

        try:
            result = subprocess.run(
                self.rebuild_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
            return result.returncode == 0
        except Exception as e:
            print(f"[SELF-HEAL] Rebuild failed: {e}", flush=True)
            return False

    def _fire_alert(self, event_type: str, data: Dict[str, Any]):
        """Fire an alert callback."""
        if self.on_alert:
            try:
                self.on_alert(event_type, data)
            except Exception as e:
                print(f"[SELF-HEAL] Alert callback failed: {e}", flush=True)

    def _record_event(
        self,
        action: HealAction,
        trigger: str,
        success: bool,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> HealEvent:
        """Record a healing event to history and audit log."""
        event = HealEvent(
            action=action,
            trigger=trigger,
            success=success,
            message=message,
            details=details or {},
        )
        self._heal_history.append(event)

        # Write to audit log
        try:
            self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.audit_log_path, "a") as f:
                f.write(json.dumps(event.to_dict()) + "\n")
        except Exception:
            pass

        return event
