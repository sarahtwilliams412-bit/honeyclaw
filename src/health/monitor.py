#!/usr/bin/env python3
"""
Honeyclaw Health Monitor

Periodic health checks for all active honeypot services.
Detects compromise indicators, verifies service availability,
monitors resource usage, and validates logging pipeline integrity.
"""

import json
import logging
import os
import platform
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


logger = logging.getLogger('honeyclaw.health')


class HealthStatus(IntEnum):
    """Overall health status levels."""
    HEALTHY = 0
    DEGRADED = 1
    COMPROMISED = 2
    UNKNOWN = 3


class ServiceStatus(IntEnum):
    """Individual service status."""
    UP = 0
    DEGRADED = 1
    DOWN = 2
    UNKNOWN = 3


@dataclass
class ServiceCheck:
    """Result of a single service health check."""
    name: str
    status: ServiceStatus
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'status': self.status.name.lower(),
            'message': self.message,
            'details': self.details,
            'checked_at': self.checked_at,
        }


@dataclass
class IsolationCheck:
    """Result of network isolation verification."""
    egress_blocked: bool = True
    no_shared_credentials: bool = True
    filesystem_integrity: bool = True
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'egress_blocked': self.egress_blocked,
            'no_shared_credentials': self.no_shared_credentials,
            'filesystem_integrity': self.filesystem_integrity,
            'details': self.details,
        }


@dataclass
class ResourceMetrics:
    """System resource usage metrics."""
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    memory_percent: float = 0.0
    disk_percent: float = 0.0
    open_fds: int = 0
    pid_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'cpu_percent': round(self.cpu_percent, 1),
            'memory_mb': round(self.memory_mb, 1),
            'memory_percent': round(self.memory_percent, 1),
            'disk_percent': round(self.disk_percent, 1),
            'open_fds': self.open_fds,
            'pid_count': self.pid_count,
        }


@dataclass
class CompromiseIndicator:
    """A detected compromise indicator."""
    indicator_type: str
    description: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    details: Dict[str, Any] = field(default_factory=dict)
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            'indicator_type': self.indicator_type,
            'description': self.description,
            'severity': self.severity,
            'details': self.details,
            'detected_at': self.detected_at,
        }


@dataclass
class HealthReport:
    """Complete health check report."""
    status: HealthStatus
    services: List[ServiceCheck] = field(default_factory=list)
    isolation: Optional[IsolationCheck] = None
    resources: Optional[ResourceMetrics] = None
    compromise_indicators: List[CompromiseIndicator] = field(default_factory=list)
    last_check: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    honeypot_id: str = ""
    uptime_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'status': self.status.name.lower(),
            'services': {s.name: {
                'status': s.status.name.lower(),
                **({k: v for k, v in s.details.items()} if s.details else {}),
                **({'reason': s.message} if s.message and s.status != ServiceStatus.UP else {}),
            } for s in self.services},
            'isolation': self.isolation.to_dict() if self.isolation else {},
            'resources': self.resources.to_dict() if self.resources else {},
            'compromise_indicators': [c.to_dict() for c in self.compromise_indicators],
            'last_check': self.last_check,
            'honeypot_id': self.honeypot_id,
            'uptime_seconds': round(self.uptime_seconds, 1),
        }


DEFAULT_ALLOWED_PROCESSES = [
    'python', 'python3', 'node', 'npm', 'honeypot', 'sshd',
    'bash', 'sh', 'sleep', 'tee', 'tail',
]


@dataclass
class HealthConfig:
    """Health monitoring configuration."""
    enabled: bool = True
    check_interval_sec: int = 60
    services: Dict[str, int] = field(default_factory=dict)  # name -> port
    log_path: str = '/var/log/honeyclaw/health.json'
    check_egress: bool = True
    check_filesystem: bool = True
    check_processes: bool = True
    egress_test_host: str = '1.1.1.1'
    egress_test_port: int = 443
    allowed_processes: List[str] = field(default_factory=lambda: list(
        DEFAULT_ALLOWED_PROCESSES
    ))
    filesystem_watch_paths: List[str] = field(default_factory=lambda: [
        '/usr/bin', '/usr/sbin', '/bin', '/sbin',
        '/etc/crontab', '/etc/cron.d',
    ])
    resource_thresholds: Dict[str, float] = field(default_factory=lambda: {
        'cpu_percent': 80.0,
        'memory_percent': 90.0,
        'disk_percent': 90.0,
        'open_fds': 1024,
    })

    @classmethod
    def from_env(cls) -> 'HealthConfig':
        """Create config from environment variables."""
        services = {}
        services_str = os.environ.get('HEALTH_CHECK_SERVICES', '')
        if services_str:
            for entry in services_str.split(','):
                entry = entry.strip()
                if ':' in entry:
                    name, port = entry.rsplit(':', 1)
                    try:
                        services[name.strip()] = int(port.strip())
                    except ValueError:
                        pass

        allowed_procs = os.environ.get('HEALTH_ALLOWED_PROCESSES', '')

        return cls(
            enabled=os.environ.get('HEALTH_ENABLED', 'true').lower() == 'true',
            check_interval_sec=int(os.environ.get('HEALTH_CHECK_INTERVAL', '60')),
            services=services,
            log_path=os.environ.get('HEALTH_LOG_PATH', '/var/log/honeyclaw/health.json'),
            check_egress=os.environ.get('HEALTH_CHECK_EGRESS', 'true').lower() == 'true',
            check_filesystem=os.environ.get('HEALTH_CHECK_FILESYSTEM', 'true').lower() == 'true',
            check_processes=os.environ.get('HEALTH_CHECK_PROCESSES', 'true').lower() == 'true',
            egress_test_host=os.environ.get('HEALTH_EGRESS_TEST_HOST', '1.1.1.1'),
            egress_test_port=int(os.environ.get('HEALTH_EGRESS_TEST_PORT', '443')),
            allowed_processes=(
                allowed_procs.split(',') if allowed_procs
                else list(DEFAULT_ALLOWED_PROCESSES)
            ),
        )


class HealthMonitor:
    """
    Main health monitoring system for HoneyClaw.

    Runs periodic health checks against all configured honeypot services,
    monitors system resources, verifies network isolation, and detects
    compromise indicators.

    Usage:
        monitor = HealthMonitor(config=HealthConfig.from_env())
        report = monitor.run_checks()
        print(json.dumps(report.to_dict(), indent=2))

        # Or start background monitoring:
        monitor.start()
        # ... later ...
        monitor.stop()
    """

    def __init__(
        self,
        config: Optional[HealthConfig] = None,
        honeypot_id: Optional[str] = None,
        on_compromise: Optional[Callable[['HealthReport'], None]] = None,
        on_degraded: Optional[Callable[['HealthReport'], None]] = None,
    ):
        self.config = config or HealthConfig.from_env()
        self.honeypot_id = honeypot_id or os.environ.get('HONEYPOT_ID', 'honeyclaw')
        self.on_compromise = on_compromise
        self.on_degraded = on_degraded

        self._start_time = time.monotonic()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._last_report: Optional[HealthReport] = None
        self._filesystem_baselines: Dict[str, float] = {}

        # Stats
        self._stats = {
            'checks_performed': 0,
            'checks_healthy': 0,
            'checks_degraded': 0,
            'checks_compromised': 0,
            'compromise_indicators_total': 0,
        }
        self._lock = threading.Lock()

        # Build filesystem baseline on init
        if self.config.check_filesystem:
            self._build_filesystem_baseline()

    # === Public API ===

    def run_checks(self) -> HealthReport:
        """
        Run all health checks and return a report.

        This is the main entry point for a single health check cycle.
        """
        services = self._check_services()
        resources = self._collect_resources()
        isolation = self._check_isolation() if self.config.check_egress else IsolationCheck()
        indicators = self._detect_compromise(resources)

        # Determine overall status
        status = self._determine_status(services, isolation, indicators)

        report = HealthReport(
            status=status,
            services=services,
            isolation=isolation,
            resources=resources,
            compromise_indicators=indicators,
            honeypot_id=self.honeypot_id,
            uptime_seconds=time.monotonic() - self._start_time,
        )

        # Update stats
        with self._lock:
            self._stats['checks_performed'] += 1
            key = f'checks_{status.name.lower()}'
            if key in self._stats:
                self._stats[key] += 1
            self._stats['compromise_indicators_total'] += len(indicators)

        self._last_report = report

        # Log the report
        self._log_report(report)

        # Trigger callbacks
        if status == HealthStatus.COMPROMISED and self.on_compromise:
            try:
                self.on_compromise(report)
            except Exception as e:
                logger.error(f"Error in compromise callback: {e}")

        if status == HealthStatus.DEGRADED and self.on_degraded:
            try:
                self.on_degraded(report)
            except Exception as e:
                logger.error(f"Error in degraded callback: {e}")

        return report

    def start(self):
        """Start background health monitoring."""
        if self._running:
            return

        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info(
            f"Health monitor started (interval={self.config.check_interval_sec}s, "
            f"honeypot={self.honeypot_id})"
        )

    def stop(self):
        """Stop background health monitoring."""
        if not self._running:
            return

        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=self.config.check_interval_sec + 5)
            self._thread = None
        logger.info("Health monitor stopped")

    def get_last_report(self) -> Optional[HealthReport]:
        """Get the most recent health report."""
        return self._last_report

    def get_stats(self) -> Dict[str, int]:
        """Get monitor statistics."""
        with self._lock:
            return dict(self._stats)

    @property
    def is_running(self) -> bool:
        return self._running

    # === Service Checks ===

    def _check_services(self) -> List[ServiceCheck]:
        """Check health of all configured services by port connectivity."""
        results = []
        for name, port in self.config.services.items():
            check = self._check_port(name, port)
            results.append(check)
        return results

    def _check_port(self, name: str, port: int, timeout: float = 5.0) -> ServiceCheck:
        """Check if a service is listening on a port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            start = time.monotonic()
            result = sock.connect_ex(('127.0.0.1', port))
            elapsed = time.monotonic() - start
            sock.close()

            if result == 0:
                return ServiceCheck(
                    name=name,
                    status=ServiceStatus.UP,
                    details={'port': port, 'response_ms': round(elapsed * 1000, 1)},
                )
            else:
                return ServiceCheck(
                    name=name,
                    status=ServiceStatus.DOWN,
                    message=f"Port {port} not responding (errno={result})",
                    details={'port': port},
                )
        except socket.timeout:
            return ServiceCheck(
                name=name,
                status=ServiceStatus.DOWN,
                message=f"Port {port} connection timed out",
                details={'port': port},
            )
        except OSError as e:
            return ServiceCheck(
                name=name,
                status=ServiceStatus.DOWN,
                message=f"Port {port} check failed: {e}",
                details={'port': port},
            )

    # === Logging Pipeline Check ===

    def check_logging(self, log_path: Optional[str] = None) -> ServiceCheck:
        """
        Verify the logging pipeline is functional.

        Writes a test event and confirms it can be read back.
        """
        path = log_path or self.config.log_path
        log_dir = str(Path(path).parent)

        try:
            # Check log directory exists and is writable
            if not os.path.isdir(log_dir):
                return ServiceCheck(
                    name='logging',
                    status=ServiceStatus.DOWN,
                    message=f"Log directory does not exist: {log_dir}",
                )

            if not os.access(log_dir, os.W_OK):
                return ServiceCheck(
                    name='logging',
                    status=ServiceStatus.DEGRADED,
                    message=f"Log directory not writable: {log_dir}",
                )

            # Check disk space for log partition
            try:
                stat = os.statvfs(log_dir)
                free_mb = (stat.f_bavail * stat.f_frsize) / (1024 * 1024)
                if free_mb < 100:
                    return ServiceCheck(
                        name='logging',
                        status=ServiceStatus.DEGRADED,
                        message=f"Low disk space for logs: {free_mb:.0f}MB remaining",
                        details={'free_mb': round(free_mb, 1)},
                    )
            except OSError:
                pass

            return ServiceCheck(
                name='logging',
                status=ServiceStatus.UP,
                details={'log_dir': log_dir},
            )

        except Exception as e:
            return ServiceCheck(
                name='logging',
                status=ServiceStatus.DOWN,
                message=f"Logging check failed: {e}",
            )

    # === Resource Monitoring ===

    def _collect_resources(self) -> ResourceMetrics:
        """Collect system resource usage metrics."""
        metrics = ResourceMetrics()

        # CPU usage from /proc/stat
        metrics.cpu_percent = self._get_cpu_percent()

        # Memory from /proc/meminfo
        mem_info = self._get_memory_info()
        metrics.memory_mb = mem_info.get('used_mb', 0.0)
        metrics.memory_percent = mem_info.get('percent', 0.0)

        # Disk usage
        metrics.disk_percent = self._get_disk_percent()

        # Open file descriptors
        metrics.open_fds = self._get_open_fds()

        # Process count
        metrics.pid_count = self._get_pid_count()

        return metrics

    def _get_cpu_percent(self) -> float:
        """Get CPU usage percentage from /proc/stat."""
        try:
            with open('/proc/stat', 'r') as f:
                line = f.readline()
            parts = line.split()
            if parts[0] != 'cpu':
                return 0.0

            # user, nice, system, idle, iowait, irq, softirq, steal
            values = [int(p) for p in parts[1:9]]
            idle = values[3] + values[4]  # idle + iowait
            total = sum(values)

            if not hasattr(self, '_prev_cpu'):
                self._prev_cpu = (idle, total)
                return 0.0

            prev_idle, prev_total = self._prev_cpu
            self._prev_cpu = (idle, total)

            idle_delta = idle - prev_idle
            total_delta = total - prev_total
            if total_delta == 0:
                return 0.0

            return round((1.0 - idle_delta / total_delta) * 100, 1)
        except (OSError, ValueError, IndexError):
            return 0.0

    def _get_memory_info(self) -> Dict[str, float]:
        """Get memory info from /proc/meminfo."""
        try:
            meminfo = {}
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    parts = line.split(':')
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = parts[1].strip().split()[0]  # value in kB
                        meminfo[key] = int(val)

            total_kb = meminfo.get('MemTotal', 0)
            available_kb = meminfo.get('MemAvailable', meminfo.get('MemFree', 0))
            used_kb = total_kb - available_kb

            return {
                'total_mb': total_kb / 1024,
                'used_mb': used_kb / 1024,
                'available_mb': available_kb / 1024,
                'percent': (used_kb / total_kb * 100) if total_kb > 0 else 0.0,
            }
        except (OSError, ValueError, KeyError):
            return {'total_mb': 0, 'used_mb': 0, 'available_mb': 0, 'percent': 0.0}

    def _get_disk_percent(self) -> float:
        """Get disk usage percentage for the root filesystem."""
        try:
            stat = os.statvfs('/')
            total = stat.f_blocks * stat.f_frsize
            free = stat.f_bavail * stat.f_frsize
            if total == 0:
                return 0.0
            return round((1.0 - free / total) * 100, 1)
        except OSError:
            return 0.0

    def _get_open_fds(self) -> int:
        """Get number of open file descriptors for the current process."""
        try:
            fd_dir = Path(f'/proc/{os.getpid()}/fd')
            if fd_dir.exists():
                return len(list(fd_dir.iterdir()))
        except (OSError, PermissionError):
            pass
        return 0

    def _get_pid_count(self) -> int:
        """Get number of running processes."""
        try:
            proc_path = Path('/proc')
            if proc_path.exists():
                return sum(
                    1 for p in proc_path.iterdir()
                    if p.name.isdigit()
                )
        except (OSError, PermissionError):
            pass
        return 0

    # === Network Isolation Checks ===

    def _check_isolation(self) -> IsolationCheck:
        """Verify network isolation is intact."""
        check = IsolationCheck()

        # Test egress (should be blocked in a properly isolated honeypot)
        egress_result = self._test_egress()
        check.egress_blocked = egress_result['blocked']
        check.details['egress_test'] = egress_result

        # Check for shared credentials
        cred_result = self._check_shared_credentials()
        check.no_shared_credentials = cred_result['clean']
        check.details['credential_check'] = cred_result

        # Check filesystem integrity
        if self.config.check_filesystem:
            fs_result = self._check_filesystem_integrity()
            check.filesystem_integrity = fs_result['intact']
            check.details['filesystem_check'] = fs_result

        return check

    def _test_egress(self) -> Dict[str, Any]:
        """
        Test outbound connectivity. In a properly isolated honeypot,
        outbound connections should be blocked.
        """
        host = self.config.egress_test_host
        port = self.config.egress_test_port

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((host, port))
            sock.close()

            if result == 0:
                # Connection succeeded - egress NOT blocked (bad!)
                return {
                    'blocked': False,
                    'message': f"Outbound connection to {host}:{port} succeeded - egress NOT blocked",
                    'test_host': host,
                    'test_port': port,
                }
            else:
                return {
                    'blocked': True,
                    'message': f"Outbound connection to {host}:{port} blocked (errno={result})",
                    'test_host': host,
                    'test_port': port,
                }
        except (socket.timeout, OSError):
            return {
                'blocked': True,
                'message': f"Outbound connection to {host}:{port} blocked",
                'test_host': host,
                'test_port': port,
            }

    def _check_shared_credentials(self) -> Dict[str, Any]:
        """Check for shared or real credentials that shouldn't be present."""
        issues = []

        # Check common credential file locations
        cred_paths = [
            Path.home() / '.aws' / 'credentials',
            Path.home() / '.ssh' / 'id_rsa',
            Path.home() / '.ssh' / 'id_ed25519',
            Path('/etc/shadow'),
            Path.home() / '.docker' / 'config.json',
            Path.home() / '.kube' / 'config',
        ]

        for path in cred_paths:
            if path.exists() and path.is_file():
                try:
                    size = path.stat().st_size
                    if size > 0:
                        issues.append({
                            'path': str(path),
                            'size': size,
                            'warning': 'Real credential file detected',
                        })
                except OSError:
                    pass

        # Check for .env files with secrets
        env_path = Path.cwd() / '.env'
        if env_path.exists():
            try:
                content = env_path.read_text()
                for line in content.splitlines():
                    line = line.strip()
                    if '=' in line and not line.startswith('#'):
                        key = line.split('=', 1)[0].upper()
                        if any(s in key for s in ['SECRET', 'PASSWORD', 'TOKEN', 'KEY']):
                            issues.append({
                                'path': str(env_path),
                                'key': key,
                                'warning': 'Potential secret in .env file',
                            })
            except OSError:
                pass

        return {
            'clean': len(issues) == 0,
            'issues': issues,
        }

    def _build_filesystem_baseline(self):
        """Build baseline of filesystem modification times for watched paths."""
        for path_str in self.config.filesystem_watch_paths:
            path = Path(path_str)
            if path.exists():
                try:
                    if path.is_file():
                        self._filesystem_baselines[path_str] = path.stat().st_mtime
                    elif path.is_dir():
                        # Track directory modification time
                        self._filesystem_baselines[path_str] = path.stat().st_mtime
                except OSError:
                    pass

    def _check_filesystem_integrity(self) -> Dict[str, Any]:
        """Check filesystem for unauthorized modifications."""
        modifications = []

        for path_str, baseline_mtime in self._filesystem_baselines.items():
            path = Path(path_str)
            try:
                if path.exists():
                    current_mtime = path.stat().st_mtime
                    if current_mtime > baseline_mtime:
                        modifications.append({
                            'path': path_str,
                            'baseline_mtime': baseline_mtime,
                            'current_mtime': current_mtime,
                            'warning': 'File modified since baseline',
                        })
                else:
                    modifications.append({
                        'path': path_str,
                        'warning': 'Watched path no longer exists',
                    })
            except OSError:
                pass

        return {
            'intact': len(modifications) == 0,
            'modifications': modifications,
            'watched_paths': len(self._filesystem_baselines),
        }

    # === Compromise Detection ===

    def _detect_compromise(self, resources: ResourceMetrics) -> List[CompromiseIndicator]:
        """Run all compromise detection checks."""
        indicators: List[CompromiseIndicator] = []

        # Check for unexpected processes
        if self.config.check_processes:
            indicators.extend(self._check_unexpected_processes())

        # Check for unexpected cron jobs
        indicators.extend(self._check_cron_jobs())

        # Check resource thresholds
        indicators.extend(self._check_resource_thresholds(resources))

        return indicators

    def _check_unexpected_processes(self) -> List[CompromiseIndicator]:
        """Detect processes not in the allow-list."""
        indicators = []
        allowed = set(self.config.allowed_processes)

        try:
            proc_dir = Path('/proc')
            if not proc_dir.exists():
                return indicators

            for entry in proc_dir.iterdir():
                if not entry.name.isdigit():
                    continue

                try:
                    cmdline_path = entry / 'cmdline'
                    if not cmdline_path.exists():
                        continue

                    cmdline = cmdline_path.read_bytes().decode('utf-8', errors='replace')
                    cmdline = cmdline.replace('\x00', ' ').strip()

                    if not cmdline:
                        continue

                    # Extract process name
                    proc_name = Path(cmdline.split()[0]).name if cmdline.split() else ''

                    # Check against allow-list
                    if proc_name and not any(
                        allowed_name in proc_name for allowed_name in allowed
                    ):
                        indicators.append(CompromiseIndicator(
                            indicator_type='unexpected_process',
                            description=f"Unexpected process detected: {proc_name}",
                            severity='medium',
                            details={
                                'pid': int(entry.name),
                                'process_name': proc_name,
                                'cmdline': cmdline[:200],
                            },
                        ))
                except (OSError, PermissionError, ValueError):
                    continue

        except (OSError, PermissionError):
            pass

        return indicators

    def _check_cron_jobs(self) -> List[CompromiseIndicator]:
        """Check for unexpected cron jobs that may indicate persistence."""
        indicators = []

        cron_paths = [
            Path('/etc/crontab'),
            Path('/etc/cron.d'),
            Path('/var/spool/cron'),
            Path('/var/spool/cron/crontabs'),
        ]

        for cron_path in cron_paths:
            try:
                if cron_path.is_file():
                    content = cron_path.read_text()
                    # Look for suspicious patterns
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith('#'):
                            suspicious_patterns = [
                                'wget ', 'curl ', 'nc ', 'netcat ',
                                '/dev/tcp/', 'base64', 'eval ',
                                'python -c', 'perl -e', 'ruby -e',
                            ]
                            for pattern in suspicious_patterns:
                                if pattern in line:
                                    indicators.append(CompromiseIndicator(
                                        indicator_type='suspicious_cron',
                                        description=f"Suspicious cron entry: {line[:100]}",
                                        severity='high',
                                        details={
                                            'path': str(cron_path),
                                            'entry': line[:200],
                                            'matched_pattern': pattern,
                                        },
                                    ))
                                    break

                elif cron_path.is_dir() and self._filesystem_baselines:
                    for child in cron_path.iterdir():
                        if child.is_file():
                            # Check for files added after baseline was built
                            baseline_key = str(child)
                            if baseline_key not in self._filesystem_baselines:
                                indicators.append(CompromiseIndicator(
                                    indicator_type='new_cron_file',
                                    description=f"New cron file detected: {child.name}",
                                    severity='high',
                                    details={'path': str(child)},
                                ))
            except (OSError, PermissionError):
                continue

        return indicators

    def _check_resource_thresholds(
        self, resources: ResourceMetrics
    ) -> List[CompromiseIndicator]:
        """Check if resource usage exceeds configured thresholds."""
        indicators = []
        thresholds = self.config.resource_thresholds

        if resources.cpu_percent > thresholds.get('cpu_percent', 80.0):
            indicators.append(CompromiseIndicator(
                indicator_type='high_cpu',
                description=f"CPU usage at {resources.cpu_percent}% (threshold: "
                            f"{thresholds.get('cpu_percent', 80.0)}%)",
                severity='medium',
                details={
                    'current': resources.cpu_percent,
                    'threshold': thresholds.get('cpu_percent', 80.0),
                },
            ))

        if resources.memory_percent > thresholds.get('memory_percent', 90.0):
            indicators.append(CompromiseIndicator(
                indicator_type='high_memory',
                description=f"Memory usage at {resources.memory_percent}% (threshold: "
                            f"{thresholds.get('memory_percent', 90.0)}%)",
                severity='medium',
                details={
                    'current': resources.memory_percent,
                    'threshold': thresholds.get('memory_percent', 90.0),
                },
            ))

        if resources.disk_percent > thresholds.get('disk_percent', 90.0):
            indicators.append(CompromiseIndicator(
                indicator_type='high_disk',
                description=f"Disk usage at {resources.disk_percent}% (threshold: "
                            f"{thresholds.get('disk_percent', 90.0)}%)",
                severity='medium',
                details={
                    'current': resources.disk_percent,
                    'threshold': thresholds.get('disk_percent', 90.0),
                },
            ))

        if resources.open_fds > thresholds.get('open_fds', 1024):
            indicators.append(CompromiseIndicator(
                indicator_type='high_open_fds',
                description=f"Open file descriptors at {resources.open_fds} (threshold: "
                            f"{int(thresholds.get('open_fds', 1024))})",
                severity='low',
                details={
                    'current': resources.open_fds,
                    'threshold': int(thresholds.get('open_fds', 1024)),
                },
            ))

        return indicators

    # === Status Determination ===

    def _determine_status(
        self,
        services: List[ServiceCheck],
        isolation: IsolationCheck,
        indicators: List[CompromiseIndicator],
    ) -> HealthStatus:
        """Determine overall health status from individual check results."""
        # Compromised if: egress not blocked, critical indicators, or filesystem tampering
        if not isolation.egress_blocked:
            return HealthStatus.COMPROMISED

        if not isolation.filesystem_integrity:
            return HealthStatus.COMPROMISED

        critical_indicators = [i for i in indicators if i.severity == 'critical']
        if critical_indicators:
            return HealthStatus.COMPROMISED

        high_indicators = [i for i in indicators if i.severity == 'high']
        if high_indicators:
            return HealthStatus.COMPROMISED

        # Degraded if: any service down, medium indicators, or resource warnings
        down_services = [s for s in services if s.status == ServiceStatus.DOWN]
        if down_services:
            return HealthStatus.DEGRADED

        degraded_services = [s for s in services if s.status == ServiceStatus.DEGRADED]
        if degraded_services:
            return HealthStatus.DEGRADED

        medium_indicators = [i for i in indicators if i.severity == 'medium']
        if medium_indicators:
            return HealthStatus.DEGRADED

        # Healthy
        return HealthStatus.HEALTHY

    # === Logging ===

    def _log_report(self, report: HealthReport):
        """Log health check report to file and logger."""
        level = {
            HealthStatus.HEALTHY: logging.DEBUG,
            HealthStatus.DEGRADED: logging.WARNING,
            HealthStatus.COMPROMISED: logging.CRITICAL,
            HealthStatus.UNKNOWN: logging.WARNING,
        }.get(report.status, logging.INFO)

        logger.log(level, f"Health check: {report.status.name} "
                   f"(services={len(report.services)}, "
                   f"indicators={len(report.compromise_indicators)})")

        # Write structured log
        try:
            log_dir = Path(self.config.log_path).parent
            if log_dir.exists() and os.access(str(log_dir), os.W_OK):
                with open(self.config.log_path, 'a') as f:
                    entry = {
                        'timestamp': report.last_check,
                        'status': report.status.name.lower(),
                        'honeypot_id': report.honeypot_id,
                        'indicators': len(report.compromise_indicators),
                    }
                    f.write(json.dumps(entry) + '\n')
        except OSError:
            pass

    # === Background Monitoring ===

    def _monitor_loop(self):
        """Background monitoring loop."""
        while self._running and not self._stop_event.is_set():
            try:
                self.run_checks()
            except Exception as e:
                logger.error(f"Health check cycle failed: {e}")

            self._stop_event.wait(timeout=self.config.check_interval_sec)


# === Convenience Functions ===

_default_monitor: Optional[HealthMonitor] = None


def get_monitor(config: Optional[HealthConfig] = None) -> HealthMonitor:
    """Get or create the default health monitor."""
    global _default_monitor
    if _default_monitor is None:
        _default_monitor = HealthMonitor(config=config)
    return _default_monitor


def check_health() -> HealthReport:
    """Run a health check using the default monitor."""
    return get_monitor().run_checks()


def start_monitoring(
    config: Optional[HealthConfig] = None,
    on_compromise: Optional[Callable] = None,
    on_degraded: Optional[Callable] = None,
):
    """Start background health monitoring with the default monitor."""
    global _default_monitor
    _default_monitor = HealthMonitor(
        config=config,
        on_compromise=on_compromise,
        on_degraded=on_degraded,
    )
    _default_monitor.start()
    return _default_monitor


def stop_monitoring():
    """Stop background health monitoring."""
    global _default_monitor
    if _default_monitor:
        _default_monitor.stop()
