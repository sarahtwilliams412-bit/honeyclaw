#!/usr/bin/env python3
"""
Honeyclaw Self-Healing System

Automated response to health check failures and compromise detection.
Triggers container rebuilds, alerts SOC teams, and captures forensic
snapshots before teardown.
"""

import json
import logging
import os
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .monitor import HealthMonitor, HealthReport, HealthStatus, HealthConfig


logger = logging.getLogger('honeyclaw.health.self_heal')


@dataclass
class SelfHealConfig:
    """Configuration for self-healing responses."""
    enabled: bool = True
    auto_rebuild_on_compromise: bool = True
    alert_on_degraded: bool = True
    alert_on_compromise: bool = True
    forensic_snapshot_enabled: bool = True
    forensic_snapshot_path: str = '/var/lib/honeyclaw/forensics'
    rebuild_command: str = ''
    rebuild_timeout_sec: int = 300
    max_rebuild_attempts: int = 3
    rebuild_cooldown_sec: int = 600  # Min time between rebuilds

    @classmethod
    def from_env(cls) -> 'SelfHealConfig':
        """Create config from environment variables."""
        return cls(
            enabled=os.environ.get('SELF_HEAL_ENABLED', 'true').lower() == 'true',
            auto_rebuild_on_compromise=os.environ.get(
                'SELF_HEAL_AUTO_REBUILD', 'true'
            ).lower() == 'true',
            alert_on_degraded=os.environ.get(
                'SELF_HEAL_ALERT_DEGRADED', 'true'
            ).lower() == 'true',
            alert_on_compromise=os.environ.get(
                'SELF_HEAL_ALERT_COMPROMISE', 'true'
            ).lower() == 'true',
            forensic_snapshot_enabled=os.environ.get(
                'SELF_HEAL_FORENSIC_SNAPSHOT', 'true'
            ).lower() == 'true',
            forensic_snapshot_path=os.environ.get(
                'SELF_HEAL_FORENSIC_PATH', '/var/lib/honeyclaw/forensics'
            ),
            rebuild_command=os.environ.get('SELF_HEAL_REBUILD_COMMAND', ''),
            rebuild_timeout_sec=int(os.environ.get('SELF_HEAL_REBUILD_TIMEOUT', '300')),
            max_rebuild_attempts=int(os.environ.get('SELF_HEAL_MAX_REBUILDS', '3')),
            rebuild_cooldown_sec=int(os.environ.get('SELF_HEAL_REBUILD_COOLDOWN', '600')),
        )


@dataclass
class HealAction:
    """Record of a self-healing action taken."""
    action_type: str  # 'alert', 'snapshot', 'rebuild'
    trigger: str  # What triggered this action
    success: bool
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            'action_type': self.action_type,
            'trigger': self.trigger,
            'success': self.success,
            'message': self.message,
            'details': self.details,
            'timestamp': self.timestamp,
        }


class SelfHealer:
    """
    Automated response system for health check failures.

    Handles:
    - Alerting SOC teams on anomalies
    - Capturing forensic snapshots before teardown
    - Triggering container rebuilds on compromise detection
    - Rate-limiting rebuild attempts

    Usage:
        healer = SelfHealer(config=SelfHealConfig.from_env())
        healer.handle_report(health_report)

        # Or integrate with HealthMonitor:
        monitor = HealthMonitor(
            on_compromise=healer.handle_compromise,
            on_degraded=healer.handle_degraded,
        )
    """

    def __init__(
        self,
        config: Optional[SelfHealConfig] = None,
        alert_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.config = config or SelfHealConfig.from_env()
        self.alert_callback = alert_callback

        self._action_log: List[HealAction] = []
        self._last_rebuild_time: float = 0
        self._rebuild_attempts: int = 0
        self._lock = threading.Lock()

        # Try to import alerting system
        self._alert_func = None
        try:
            from src.alerts.dispatcher import alert as send_alert
            if os.environ.get('ALERT_WEBHOOK_URL'):
                self._alert_func = send_alert
        except ImportError:
            pass

    def handle_report(self, report: HealthReport):
        """
        Handle a health report and take appropriate action.

        This is the main entry point for self-healing logic.
        """
        if not self.config.enabled:
            return

        if report.status == HealthStatus.COMPROMISED:
            self.handle_compromise(report)
        elif report.status == HealthStatus.DEGRADED:
            self.handle_degraded(report)

    def handle_compromise(self, report: HealthReport):
        """Handle a compromise detection."""
        logger.critical(
            f"COMPROMISE DETECTED on {report.honeypot_id}: "
            f"{len(report.compromise_indicators)} indicator(s)"
        )

        # 1. Alert SOC immediately
        if self.config.alert_on_compromise:
            self._send_compromise_alert(report)

        # 2. Capture forensic snapshot
        if self.config.forensic_snapshot_enabled:
            self._capture_forensic_snapshot(report)

        # 3. Trigger rebuild
        if self.config.auto_rebuild_on_compromise:
            self._trigger_rebuild(report, reason='compromise_detected')

    def handle_degraded(self, report: HealthReport):
        """Handle a degraded state."""
        logger.warning(
            f"DEGRADED state on {report.honeypot_id}: "
            f"{len(report.compromise_indicators)} indicator(s), "
            f"{sum(1 for s in report.services if s.status.name == 'DOWN')} service(s) down"
        )

        if self.config.alert_on_degraded:
            self._send_degraded_alert(report)

    def get_action_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent self-healing action log."""
        with self._lock:
            actions = self._action_log[-limit:]
        return [a.to_dict() for a in reversed(actions)]

    def get_stats(self) -> Dict[str, Any]:
        """Get self-healing statistics."""
        with self._lock:
            return {
                'total_actions': len(self._action_log),
                'rebuild_attempts': self._rebuild_attempts,
                'last_rebuild_time': (
                    datetime.fromtimestamp(
                        self._last_rebuild_time, tz=timezone.utc
                    ).isoformat()
                    if self._last_rebuild_time > 0
                    else None
                ),
                'actions_by_type': self._count_actions_by_type(),
                'config': {
                    'enabled': self.config.enabled,
                    'auto_rebuild': self.config.auto_rebuild_on_compromise,
                    'forensic_snapshots': self.config.forensic_snapshot_enabled,
                },
            }

    # === Alert Sending ===

    def _send_compromise_alert(self, report: HealthReport):
        """Send critical alert for compromise detection."""
        event = {
            'event': 'honeypot_compromised',
            'honeypot_id': report.honeypot_id,
            'status': report.status.name,
            'indicators': [i.to_dict() for i in report.compromise_indicators],
            'services': {s.name: s.status.name for s in report.services},
            'timestamp': report.last_check,
        }

        success = self._dispatch_alert(event, 'health_compromise')

        self._record_action(HealAction(
            action_type='alert',
            trigger='compromise_detected',
            success=success,
            message='Compromise alert sent to SOC' if success else 'Failed to send alert',
            details={'indicator_count': len(report.compromise_indicators)},
        ))

    def _send_degraded_alert(self, report: HealthReport):
        """Send warning alert for degraded state."""
        down_services = [s.name for s in report.services if s.status.name == 'DOWN']

        event = {
            'event': 'honeypot_degraded',
            'honeypot_id': report.honeypot_id,
            'status': report.status.name,
            'down_services': down_services,
            'indicators': [i.to_dict() for i in report.compromise_indicators],
            'timestamp': report.last_check,
        }

        success = self._dispatch_alert(event, 'health_degraded')

        self._record_action(HealAction(
            action_type='alert',
            trigger='degraded_state',
            success=success,
            message='Degraded alert sent' if success else 'Failed to send alert',
            details={'down_services': down_services},
        ))

    def _dispatch_alert(self, event: Dict[str, Any], event_type: str) -> bool:
        """Send alert through available channels."""
        sent = False

        # Try the built-in alert system
        if self._alert_func:
            try:
                self._alert_func(event, event_type)
                sent = True
            except Exception as e:
                logger.error(f"Failed to send alert via dispatcher: {e}")

        # Try the custom callback
        if self.alert_callback:
            try:
                self.alert_callback(event)
                sent = True
            except Exception as e:
                logger.error(f"Failed to send alert via callback: {e}")

        if not sent:
            # Last resort: log it
            logger.critical(f"ALERT ({event_type}): {json.dumps(event)}")

        return sent

    # === Forensic Snapshot ===

    def _capture_forensic_snapshot(self, report: HealthReport) -> bool:
        """
        Capture system state for forensic analysis before teardown.

        Collects:
        - Running processes
        - Network connections
        - File listing of key directories
        - Environment variables (sanitized)
        - Health report
        """
        snapshot_dir = Path(self.config.forensic_snapshot_path)
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        snapshot_path = snapshot_dir / f"snapshot_{report.honeypot_id}_{timestamp}"

        try:
            snapshot_path.mkdir(parents=True, exist_ok=True)

            # Save health report
            report_path = snapshot_path / 'health_report.json'
            report_path.write_text(json.dumps(report.to_dict(), indent=2))

            # Capture process list
            self._capture_command(
                ['ps', 'auxww'],
                snapshot_path / 'processes.txt',
            )

            # Capture network connections
            self._capture_command(
                ['ss', '-tlnp'],
                snapshot_path / 'network_connections.txt',
            )

            # Capture network stats
            self._capture_command(
                ['ss', '-s'],
                snapshot_path / 'network_stats.txt',
            )

            # Capture environment (sanitize secrets)
            env_data = {}
            for key, value in os.environ.items():
                if any(s in key.upper() for s in ['SECRET', 'PASSWORD', 'TOKEN', 'KEY', 'CREDENTIAL']):
                    env_data[key] = '***REDACTED***'
                else:
                    env_data[key] = value
            env_path = snapshot_path / 'environment.json'
            env_path.write_text(json.dumps(env_data, indent=2))

            # Capture file listing of /tmp and home
            self._capture_command(
                ['ls', '-laR', '/tmp'],
                snapshot_path / 'tmp_listing.txt',
            )

            logger.info(f"Forensic snapshot captured: {snapshot_path}")

            self._record_action(HealAction(
                action_type='snapshot',
                trigger='compromise_detected',
                success=True,
                message=f'Forensic snapshot saved to {snapshot_path}',
                details={'path': str(snapshot_path)},
            ))
            return True

        except Exception as e:
            logger.error(f"Failed to capture forensic snapshot: {e}")
            self._record_action(HealAction(
                action_type='snapshot',
                trigger='compromise_detected',
                success=False,
                message=f'Snapshot failed: {e}',
            ))
            return False

    def _capture_command(self, cmd: List[str], output_path: Path):
        """Run a command and save output to file."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            output_path.write_text(result.stdout)
            if result.stderr:
                stderr_path = output_path.with_suffix('.stderr')
                stderr_path.write_text(result.stderr)
        except (subprocess.TimeoutExpired, OSError, FileNotFoundError) as e:
            output_path.write_text(f"Command failed: {e}\n")

    # === Container Rebuild ===

    def _trigger_rebuild(self, report: HealthReport, reason: str) -> bool:
        """
        Trigger a container rebuild.

        Respects cooldown period and max rebuild attempts.
        """
        if not self.config.rebuild_command:
            logger.warning("Rebuild requested but no rebuild command configured "
                           "(set SELF_HEAL_REBUILD_COMMAND)")
            self._record_action(HealAction(
                action_type='rebuild',
                trigger=reason,
                success=False,
                message='No rebuild command configured',
            ))
            return False

        current_time = time.time()

        with self._lock:
            # Check cooldown
            elapsed = current_time - self._last_rebuild_time
            if elapsed < self.config.rebuild_cooldown_sec:
                remaining = self.config.rebuild_cooldown_sec - elapsed
                cooldown_msg = f'Rebuild cooldown active ({remaining:.0f}s remaining)'
                logger.warning(cooldown_msg)
                # Record action outside the lock to avoid deadlock
                action = HealAction(
                    action_type='rebuild',
                    trigger=reason,
                    success=False,
                    message=cooldown_msg,
                )
                self._action_log.append(action)
                return False

            # Check max attempts
            if self._rebuild_attempts >= self.config.max_rebuild_attempts:
                max_msg = f'Max rebuild attempts reached ({self.config.max_rebuild_attempts})'
                logger.error(max_msg)
                action = HealAction(
                    action_type='rebuild',
                    trigger=reason,
                    success=False,
                    message=max_msg,
                )
                self._action_log.append(action)
                return False

            self._rebuild_attempts += 1
            self._last_rebuild_time = current_time

        # Execute rebuild
        logger.critical(f"Triggering container rebuild (reason: {reason})")

        try:
            result = subprocess.run(
                self.config.rebuild_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.config.rebuild_timeout_sec,
            )

            success = result.returncode == 0

            self._record_action(HealAction(
                action_type='rebuild',
                trigger=reason,
                success=success,
                message=(
                    'Rebuild completed successfully'
                    if success
                    else f'Rebuild failed (exit code {result.returncode})'
                ),
                details={
                    'exit_code': result.returncode,
                    'stdout': result.stdout[:500] if result.stdout else '',
                    'stderr': result.stderr[:500] if result.stderr else '',
                },
            ))

            if success:
                logger.info("Container rebuild completed successfully")
            else:
                logger.error(
                    f"Container rebuild failed (exit code {result.returncode}): "
                    f"{result.stderr[:200]}"
                )

            return success

        except subprocess.TimeoutExpired:
            logger.error(
                f"Container rebuild timed out after {self.config.rebuild_timeout_sec}s"
            )
            self._record_action(HealAction(
                action_type='rebuild',
                trigger=reason,
                success=False,
                message=f'Rebuild timed out after {self.config.rebuild_timeout_sec}s',
            ))
            return False
        except Exception as e:
            logger.error(f"Container rebuild failed: {e}")
            self._record_action(HealAction(
                action_type='rebuild',
                trigger=reason,
                success=False,
                message=f'Rebuild error: {e}',
            ))
            return False

    # === Internal Helpers ===

    def _record_action(self, action: HealAction):
        """Record a self-healing action."""
        with self._lock:
            self._action_log.append(action)
            # Keep log bounded
            if len(self._action_log) > 1000:
                self._action_log = self._action_log[-500:]

    def _count_actions_by_type(self) -> Dict[str, int]:
        """Count actions by type."""
        counts: Dict[str, int] = {}
        for action in self._action_log:
            counts[action.action_type] = counts.get(action.action_type, 0) + 1
        return counts
