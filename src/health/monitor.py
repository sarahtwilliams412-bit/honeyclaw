#!/usr/bin/env python3
"""
Honeyclaw Health Monitor

Periodic health checks for honeypot services with compromise detection.

Environment variables:
  HONEYCLAW_HEALTH_INTERVAL     - Check interval in seconds (default: 60)
  HONEYCLAW_HEALTH_PORT         - Health endpoint port (default: 9090)
  HONEYCLAW_ALLOWED_PROCESSES   - Comma-separated process allowlist
  HONEYCLAW_LOG_TEST_PATH       - Path to write test log events
  HONEYCLAW_WATCHED_PATHS       - Comma-separated paths to monitor for changes
"""

import asyncio
import json
import os
import platform
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set


class HealthStatus(Enum):
    """Overall health status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    COMPROMISED = "compromised"
    UNKNOWN = "unknown"


@dataclass
class ServiceHealth:
    """Health state of an individual service."""
    name: str
    status: str  # "up", "down", "degraded"
    port: Optional[int] = None
    connections_active: int = 0
    requests_last_hour: int = 0
    last_check: Optional[str] = None
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {"status": self.status}
        if self.connections_active:
            d["connections_active"] = self.connections_active
        if self.requests_last_hour:
            d["requests_last_hour"] = self.requests_last_hour
        if self.reason:
            d["reason"] = self.reason
        return d


@dataclass
class ResourceUsage:
    """System resource usage snapshot."""
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    memory_percent: float = 0.0
    disk_percent: float = 0.0
    open_fds: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cpu_percent": round(self.cpu_percent, 1),
            "memory_mb": round(self.memory_mb, 1),
            "memory_percent": round(self.memory_percent, 1),
            "disk_percent": round(self.disk_percent, 1),
            "open_fds": self.open_fds,
        }


@dataclass
class IsolationCheck:
    """Network and filesystem isolation verification."""
    egress_blocked: bool = True
    no_shared_credentials: bool = True
    filesystem_integrity: bool = True
    details: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "egress_blocked": self.egress_blocked,
            "no_shared_credentials": self.no_shared_credentials,
            "filesystem_integrity": self.filesystem_integrity,
        }
        if self.details:
            d["details"] = self.details
        return d


@dataclass
class CompromiseIndicator:
    """A detected compromise indicator."""
    indicator_type: str  # "unexpected_connection", "filesystem_change", "new_process", etc.
    severity: str  # "low", "medium", "high", "critical"
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    detected_at: str = ""

    def __post_init__(self):
        if not self.detected_at:
            self.detected_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.indicator_type,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "detected_at": self.detected_at,
        }


@dataclass
class HealthReport:
    """Complete health check report."""
    status: HealthStatus = HealthStatus.UNKNOWN
    services: Dict[str, ServiceHealth] = field(default_factory=dict)
    isolation: Optional[IsolationCheck] = None
    resources: Optional[ResourceUsage] = None
    compromise_indicators: List[CompromiseIndicator] = field(default_factory=list)
    last_check: str = ""
    honeypot_id: str = ""
    uptime_seconds: float = 0.0

    def __post_init__(self):
        if not self.last_check:
            self.last_check = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "honeypot_id": self.honeypot_id,
            "services": {k: v.to_dict() for k, v in self.services.items()},
            "isolation": self.isolation.to_dict() if self.isolation else {},
            "resources": self.resources.to_dict() if self.resources else {},
            "compromise_indicators": [c.to_dict() for c in self.compromise_indicators],
            "uptime_seconds": round(self.uptime_seconds, 1),
            "last_check": self.last_check,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class HealthMonitor:
    """
    Monitors honeypot health and detects compromise indicators.

    Runs periodic checks against services, resources, filesystem integrity,
    and network isolation. Generates HealthReports and triggers callbacks
    on anomaly detection.
    """

    def __init__(
        self,
        honeypot_id: Optional[str] = None,
        check_interval: int = 60,
        services: Optional[Dict[str, int]] = None,
        allowed_processes: Optional[Set[str]] = None,
        watched_paths: Optional[List[str]] = None,
        on_compromise: Optional[Callable[[CompromiseIndicator], None]] = None,
        on_degraded: Optional[Callable[[HealthReport], None]] = None,
    ):
        self.honeypot_id = honeypot_id or os.environ.get("HONEYPOT_ID", "honeyclaw")
        self.check_interval = int(
            os.environ.get("HONEYCLAW_HEALTH_INTERVAL", str(check_interval))
        )
        self.on_compromise = on_compromise
        self.on_degraded = on_degraded

        # Services to monitor: name -> port
        self.services = services or {}

        # Process allowlist
        default_procs = {
            "python", "python3", "node", "sshd", "bash", "sh",
            "sleep", "honeypot", "honeyclaw", "systemd", "init",
        }
        env_procs = os.environ.get("HONEYCLAW_ALLOWED_PROCESSES", "")
        if env_procs:
            default_procs.update(p.strip() for p in env_procs.split(",") if p.strip())
        self.allowed_processes = allowed_processes or default_procs

        # Filesystem paths to watch for integrity
        default_watched = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
        env_watched = os.environ.get("HONEYCLAW_WATCHED_PATHS", "")
        if env_watched:
            default_watched = [p.strip() for p in env_watched.split(",") if p.strip()]
        self.watched_paths = watched_paths or default_watched

        # State
        self._start_time = time.time()
        self._running = False
        self._last_report: Optional[HealthReport] = None
        self._filesystem_baseline: Dict[str, float] = {}
        self._baseline_initialized = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def check(self) -> HealthReport:
        """Run a full health check and return the report."""
        report = HealthReport(
            honeypot_id=self.honeypot_id,
            uptime_seconds=time.time() - self._start_time,
        )

        # 1. Check services
        for name, port in self.services.items():
            report.services[name] = await self._check_service(name, port)

        # 2. Check resources
        report.resources = self._check_resources()

        # 3. Check isolation
        report.isolation = await self._check_isolation()

        # 4. Check for compromise indicators
        report.compromise_indicators = self._detect_compromise()

        # 5. Initialize baseline on first run
        if not self._baseline_initialized:
            self._initialize_baseline()
            self._baseline_initialized = True

        # 6. Determine overall status
        report.status = self._determine_status(report)
        report.last_check = datetime.now(timezone.utc).isoformat()

        # 7. Fire callbacks
        if report.compromise_indicators and self.on_compromise:
            for indicator in report.compromise_indicators:
                try:
                    self.on_compromise(indicator)
                except Exception:
                    pass

        if report.status == HealthStatus.DEGRADED and self.on_degraded:
            try:
                self.on_degraded(report)
            except Exception:
                pass

        self._last_report = report
        return report

    async def start(self):
        """Start periodic health checking."""
        self._running = True
        while self._running:
            try:
                await self.check()
            except Exception as e:
                print(f"[HEALTH] Check failed: {e}", flush=True)
            await asyncio.sleep(self.check_interval)

    def stop(self):
        """Stop periodic health checking."""
        self._running = False

    @property
    def last_report(self) -> Optional[HealthReport]:
        return self._last_report

    # ------------------------------------------------------------------
    # Service checks
    # ------------------------------------------------------------------

    async def _check_service(self, name: str, port: int) -> ServiceHealth:
        """Check if a service is responding on the expected port."""
        svc = ServiceHealth(name=name, port=port)
        try:
            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = await loop.run_in_executor(
                None, lambda: sock.connect_ex(("127.0.0.1", port))
            )
            sock.close()
            if result == 0:
                svc.status = "up"
            else:
                svc.status = "down"
                svc.reason = f"Connection refused on port {port}"
        except Exception as e:
            svc.status = "down"
            svc.reason = str(e)

        svc.last_check = datetime.now(timezone.utc).isoformat()
        return svc

    # ------------------------------------------------------------------
    # Resource checks
    # ------------------------------------------------------------------

    def _check_resources(self) -> ResourceUsage:
        """Check system resource usage."""
        usage = ResourceUsage()

        # CPU: read from /proc/stat
        try:
            with open("/proc/loadavg", "r") as f:
                parts = f.read().split()
                usage.cpu_percent = float(parts[0]) * 100  # 1-min load avg as pct
        except Exception:
            pass

        # Memory: read from /proc/meminfo
        try:
            meminfo = {}
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = parts[1].strip().split()[0]
                        meminfo[key] = int(val)

            total = meminfo.get("MemTotal", 1)
            available = meminfo.get("MemAvailable", total)
            used = total - available
            usage.memory_mb = used / 1024
            usage.memory_percent = (used / total) * 100 if total else 0
        except Exception:
            pass

        # Disk
        try:
            st = os.statvfs("/")
            total = st.f_blocks * st.f_frsize
            free = st.f_bfree * st.f_frsize
            used = total - free
            usage.disk_percent = (used / total) * 100 if total else 0
        except Exception:
            pass

        # Open file descriptors
        try:
            pid = os.getpid()
            fd_dir = Path(f"/proc/{pid}/fd")
            if fd_dir.exists():
                usage.open_fds = len(list(fd_dir.iterdir()))
        except Exception:
            pass

        return usage

    # ------------------------------------------------------------------
    # Isolation checks
    # ------------------------------------------------------------------

    async def _check_isolation(self) -> IsolationCheck:
        """Verify network and filesystem isolation."""
        check = IsolationCheck()

        # Test egress: try to connect to a well-known external IP
        try:
            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = await loop.run_in_executor(
                None, lambda: sock.connect_ex(("8.8.8.8", 53))
            )
            sock.close()
            if result == 0:
                check.egress_blocked = False
                check.details["egress"] = "WARNING: Outbound connection to 8.8.8.8:53 succeeded"
            else:
                check.details["egress"] = "Outbound connections blocked as expected"
        except Exception:
            check.details["egress"] = "Outbound connections blocked as expected"

        # Check for shared credentials in environment
        suspicious_env_keys = [
            "AWS_SECRET_ACCESS_KEY", "DATABASE_URL", "DB_PASSWORD",
            "PROD_API_KEY", "PRODUCTION_SECRET",
        ]
        found_creds = [k for k in suspicious_env_keys if os.environ.get(k)]
        if found_creds:
            check.no_shared_credentials = False
            check.details["credentials"] = f"WARNING: Production credentials found: {found_creds}"

        # Filesystem integrity: check watched paths for modifications
        integrity_ok = True
        for watched in self.watched_paths:
            p = Path(watched)
            if p.exists() and p.is_dir():
                try:
                    current_mtime = max(
                        (f.stat().st_mtime for f in p.iterdir() if f.is_file()),
                        default=0,
                    )
                    baseline = self._filesystem_baseline.get(watched, 0)
                    if baseline > 0 and current_mtime > baseline:
                        integrity_ok = False
                        check.details[f"fs:{watched}"] = (
                            f"WARNING: Files modified since baseline in {watched}"
                        )
                except Exception:
                    pass

        check.filesystem_integrity = integrity_ok
        return check

    # ------------------------------------------------------------------
    # Compromise detection
    # ------------------------------------------------------------------

    def _detect_compromise(self) -> List[CompromiseIndicator]:
        """Detect potential compromise indicators."""
        indicators: List[CompromiseIndicator] = []

        # 1. Check for unexpected processes
        indicators.extend(self._check_unexpected_processes())

        # 2. Check for unexpected cron jobs
        indicators.extend(self._check_cron_jobs())

        # 3. Check for unexpected network listeners
        indicators.extend(self._check_network_listeners())

        return indicators

    def _check_unexpected_processes(self) -> List[CompromiseIndicator]:
        """Detect processes not in the allowlist."""
        indicators = []
        try:
            proc_dir = Path("/proc")
            if not proc_dir.exists():
                return indicators

            for entry in proc_dir.iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    cmdline_path = entry / "cmdline"
                    if cmdline_path.exists():
                        cmdline = cmdline_path.read_text().replace("\x00", " ").strip()
                        if not cmdline:
                            continue
                        proc_name = Path(cmdline.split()[0]).name
                        if proc_name and proc_name not in self.allowed_processes:
                            # Check if it's a common system process we should skip
                            if proc_name.startswith("[") or proc_name in ("cat", "ls", "ps"):
                                continue
                            indicators.append(CompromiseIndicator(
                                indicator_type="unexpected_process",
                                severity="high",
                                description=f"Unexpected process detected: {proc_name}",
                                evidence={
                                    "pid": entry.name,
                                    "cmdline": cmdline[:200],
                                    "process_name": proc_name,
                                },
                            ))
                except (PermissionError, FileNotFoundError, ProcessLookupError):
                    continue
        except Exception:
            pass
        return indicators

    def _check_cron_jobs(self) -> List[CompromiseIndicator]:
        """Check for unexpected cron entries."""
        indicators = []
        cron_paths = [
            "/etc/crontab",
            "/var/spool/cron/crontabs/root",
            "/etc/cron.d/",
        ]
        for cron_path in cron_paths:
            p = Path(cron_path)
            try:
                if p.is_file():
                    content = p.read_text()
                    # Look for suspicious entries (downloads, reverse shells)
                    suspicious_patterns = [
                        "wget", "curl", "nc ", "netcat", "bash -i",
                        "/dev/tcp", "python -c", "perl -e", "base64",
                    ]
                    for pattern in suspicious_patterns:
                        if pattern in content.lower():
                            indicators.append(CompromiseIndicator(
                                indicator_type="suspicious_cron",
                                severity="critical",
                                description=f"Suspicious cron entry found in {cron_path}",
                                evidence={
                                    "path": cron_path,
                                    "pattern": pattern,
                                },
                            ))
                            break
                elif p.is_dir():
                    for f in p.iterdir():
                        if f.is_file():
                            try:
                                content = f.read_text()
                                for pattern in ["wget", "curl", "nc ", "/dev/tcp", "base64"]:
                                    if pattern in content.lower():
                                        indicators.append(CompromiseIndicator(
                                            indicator_type="suspicious_cron",
                                            severity="critical",
                                            description=f"Suspicious cron entry: {f}",
                                            evidence={"path": str(f), "pattern": pattern},
                                        ))
                                        break
                            except (PermissionError, UnicodeDecodeError):
                                continue
            except (PermissionError, FileNotFoundError):
                continue
        return indicators

    def _check_network_listeners(self) -> List[CompromiseIndicator]:
        """Check for unexpected network listeners via /proc/net/tcp."""
        indicators = []
        expected_ports = set(self.services.values())
        # Always allow the health check port
        health_port = int(os.environ.get("HONEYCLAW_HEALTH_PORT", "9090"))
        expected_ports.add(health_port)

        try:
            for proto_file in ["/proc/net/tcp", "/proc/net/tcp6"]:
                p = Path(proto_file)
                if not p.exists():
                    continue
                with open(p, "r") as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) < 4 or parts[0] == "sl":
                            continue
                        # State 0A = LISTEN
                        if parts[3] != "0A":
                            continue
                        local_addr = parts[1]
                        port_hex = local_addr.split(":")[1]
                        port = int(port_hex, 16)
                        if port not in expected_ports and port > 0:
                            indicators.append(CompromiseIndicator(
                                indicator_type="unexpected_listener",
                                severity="high",
                                description=f"Unexpected network listener on port {port}",
                                evidence={"port": port, "source": proto_file},
                            ))
        except Exception:
            pass
        return indicators

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _initialize_baseline(self):
        """Capture filesystem modification baseline."""
        for watched in self.watched_paths:
            p = Path(watched)
            if p.exists() and p.is_dir():
                try:
                    mtime = max(
                        (f.stat().st_mtime for f in p.iterdir() if f.is_file()),
                        default=0,
                    )
                    self._filesystem_baseline[watched] = mtime
                except Exception:
                    pass

    def _determine_status(self, report: HealthReport) -> HealthStatus:
        """Determine overall health status from report data."""
        # Any compromise indicators => compromised
        critical_indicators = [
            c for c in report.compromise_indicators if c.severity == "critical"
        ]
        if critical_indicators:
            return HealthStatus.COMPROMISED

        high_indicators = [
            c for c in report.compromise_indicators if c.severity == "high"
        ]
        if len(high_indicators) >= 3:
            return HealthStatus.COMPROMISED

        # Any service down => degraded
        down_services = [
            s for s in report.services.values() if s.status == "down"
        ]
        if down_services:
            return HealthStatus.DEGRADED

        # Isolation broken => compromised
        if report.isolation:
            if not report.isolation.egress_blocked:
                return HealthStatus.COMPROMISED
            if not report.isolation.filesystem_integrity:
                return HealthStatus.DEGRADED

        # Resource pressure => degraded
        if report.resources:
            if report.resources.cpu_percent > 80:
                return HealthStatus.DEGRADED
            if report.resources.memory_percent > 90:
                return HealthStatus.DEGRADED
            if report.resources.disk_percent > 95:
                return HealthStatus.DEGRADED

        # High indicators present but not critical
        if high_indicators:
            return HealthStatus.DEGRADED

        return HealthStatus.HEALTHY


# ------------------------------------------------------------------
# HTTP Health Endpoint
# ------------------------------------------------------------------

async def serve_health_endpoint(monitor: HealthMonitor, port: int = 9090):
    """Serve a simple HTTP health endpoint."""
    import http.server
    import socketserver

    class HealthHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/health":
                report = monitor.last_report
                if report is None:
                    self.send_response(503)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "unknown", "message": "No health check run yet"}).encode())
                    return

                status_code = {
                    HealthStatus.HEALTHY: 200,
                    HealthStatus.DEGRADED: 200,
                    HealthStatus.COMPROMISED: 503,
                    HealthStatus.UNKNOWN: 503,
                }.get(report.status, 503)

                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(report.to_json().encode())
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):
            pass  # Suppress request logging

    with socketserver.TCPServer(("0.0.0.0", port), HealthHandler) as httpd:
        print(f"[HEALTH] Endpoint listening on :{port}/health", flush=True)
        httpd.serve_forever()
