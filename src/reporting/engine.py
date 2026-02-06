#!/usr/bin/env python3
"""
Honeyclaw Auto-Abuse Reporting Engine

Coordinates automatic reporting of attackers to abuse databases.
Features:
- Multi-provider support (AbuseIPDB, ISP email)
- Intelligent filtering (cooldown, severity, researcher detection)
- Rate limiting to respect API limits
- Comprehensive audit logging
- Async operation for high throughput
"""

import os
import json
import time
import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from enum import Enum

from .filters import ReportFilter, Severity, FilterResult
from .providers.abuseipdb import AbuseIPDBReporter, ReportResult, AbuseCategory
from .providers.isp_abuse import ISPAbuseReporter, ISPReportResult


# Set up logging
logger = logging.getLogger('honeyclaw.reporting')


class Provider(Enum):
    """Available reporting providers."""
    ABUSEIPDB = "abuseipdb"
    ISP_EMAIL = "isp_email"


@dataclass
class ReportingConfig:
    """
    Configuration for the reporting engine.
    
    Can be loaded from environment or YAML config.
    """
    enabled: bool = True
    min_severity: str = "high"
    cooldown_hours: float = 24
    require_confirmation: bool = False
    providers: List[str] = field(default_factory=lambda: ["abuseipdb"])
    daily_limit: int = 500
    enable_greynoise_filter: bool = True
    audit_log_path: Optional[str] = None
    state_dir: Optional[str] = None
    honeypot_id: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ReportingConfig':
        """Create config from dictionary (e.g., YAML parsed)."""
        return cls(
            enabled=data.get('enabled', True),
            min_severity=data.get('min_severity', 'high'),
            cooldown_hours=float(data.get('cooldown', '24h').rstrip('h')),
            require_confirmation=data.get('require_confirmation', False),
            providers=data.get('providers', ['abuseipdb']),
            daily_limit=data.get('daily_limit', 500),
            enable_greynoise_filter=data.get('enable_greynoise_filter', True),
            audit_log_path=data.get('audit_log'),
            state_dir=data.get('state_dir'),
            honeypot_id=data.get('honeypot_id'),
        )
    
    @classmethod
    def from_env(cls) -> 'ReportingConfig':
        """Create config from environment variables."""
        return cls(
            enabled=os.environ.get('HONEYCLAW_REPORTING_ENABLED', 'true').lower() == 'true',
            min_severity=os.environ.get('HONEYCLAW_REPORTING_MIN_SEVERITY', 'high'),
            cooldown_hours=float(os.environ.get('HONEYCLAW_REPORTING_COOLDOWN', '24')),
            require_confirmation=os.environ.get('HONEYCLAW_REPORTING_REQUIRE_CONFIRM', 'false').lower() == 'true',
            providers=os.environ.get('HONEYCLAW_REPORTING_PROVIDERS', 'abuseipdb').split(','),
            daily_limit=int(os.environ.get('HONEYCLAW_REPORTING_DAILY_LIMIT', '500')),
            enable_greynoise_filter=os.environ.get('HONEYCLAW_REPORTING_GREYNOISE_FILTER', 'true').lower() == 'true',
            audit_log_path=os.environ.get('HONEYCLAW_REPORTING_AUDIT_LOG'),
            state_dir=os.environ.get('HONEYCLAW_STATE_DIR', '/var/lib/honeyclaw'),
            honeypot_id=os.environ.get('HONEYPOT_ID', 'honeyclaw'),
        )


@dataclass
class AuditLogEntry:
    """Audit log entry for a report."""
    timestamp: str
    ip: str
    event_type: str
    severity: str
    provider: str
    success: bool
    message: Optional[str] = None
    error: Optional[str] = None
    filter_result: Optional[Dict[str, Any]] = None
    evidence_summary: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v is not None}
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class ReportingEngine:
    """
    Main reporting engine that coordinates abuse reports.
    
    Usage:
        engine = ReportingEngine()
        
        # Auto-report based on event
        await engine.report_event(
            ip="1.2.3.4",
            event_type="ssh_brute_force",
            severity="high",
            evidence={'username': 'root', 'attempts': 50}
        )
        
        # Manual report
        await engine.report_ip("1.2.3.4", reason="SSH brute force attack")
    """
    
    def __init__(
        self,
        config: Optional[ReportingConfig] = None,
        on_report: Optional[Callable[[AuditLogEntry], None]] = None,
    ):
        """
        Initialize the reporting engine.
        
        Args:
            config: Reporting configuration
            on_report: Callback when a report is submitted
        """
        self.config = config or ReportingConfig.from_env()
        self.on_report = on_report
        
        # Initialize filter
        self.filter = ReportFilter(
            cooldown_hours=self.config.cooldown_hours,
            min_severity=Severity.from_string(self.config.min_severity),
            state_file=f"{self.config.state_dir}/report_state.json" if self.config.state_dir else None,
            enable_greynoise=self.config.enable_greynoise_filter,
            daily_limit=self.config.daily_limit,
        )
        
        # Initialize providers
        self.providers: Dict[str, Any] = {}
        self._init_providers()
        
        # Audit log
        self._audit_log_file = None
        if self.config.audit_log_path:
            self._init_audit_log()
        
        # Pending confirmations (for require_confirmation mode)
        self._pending: Dict[str, Dict[str, Any]] = {}
        
        # Stats
        self._stats = {
            'reports_submitted': 0,
            'reports_filtered': 0,
            'reports_failed': 0,
        }
    
    def _init_providers(self):
        """Initialize reporting providers based on config."""
        for provider_name in self.config.providers:
            provider_name = provider_name.strip().lower()
            
            if provider_name == 'abuseipdb':
                provider = AbuseIPDBReporter()
                if provider.enabled:
                    self.providers['abuseipdb'] = provider
                    logger.info("AbuseIPDB reporter enabled")
                else:
                    logger.warning("AbuseIPDB API key not configured")
            
            elif provider_name == 'isp_email':
                provider = ISPAbuseReporter()
                if provider.email_enabled:
                    self.providers['isp_email'] = provider
                    logger.info("ISP email reporter enabled")
                else:
                    logger.warning("ISP email SMTP not configured")
    
    def _init_audit_log(self):
        """Initialize the audit log file."""
        log_path = Path(self.config.audit_log_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._audit_log_file = log_path
    
    def _write_audit_log(self, entry: AuditLogEntry):
        """Write an entry to the audit log."""
        if self._audit_log_file:
            try:
                with open(self._audit_log_file, 'a') as f:
                    f.write(entry.to_json() + '\n')
            except IOError as e:
                logger.error(f"Failed to write audit log: {e}")
        
        # Also log to logger
        log_msg = f"REPORT: {entry.ip} via {entry.provider} - {'SUCCESS' if entry.success else 'FAILED'}"
        if entry.success:
            logger.info(log_msg)
        else:
            logger.warning(f"{log_msg}: {entry.error}")
        
        # Callback
        if self.on_report:
            self.on_report(entry)
    
    async def report_event(
        self,
        ip: str,
        event_type: str,
        severity: str,
        evidence: Dict[str, Any],
        enrichment: Optional[Dict[str, Any]] = None,
        force: bool = False,
    ) -> List[AuditLogEntry]:
        """
        Report an event to all configured providers.
        
        Args:
            ip: Attacker IP address
            event_type: Type of attack
            severity: Event severity (debug/info/low/medium/high/critical)
            evidence: Dict containing attack evidence
            enrichment: Pre-enriched threat intelligence data
            force: Skip filters (use with caution)
            
        Returns:
            List of audit log entries for each provider
        """
        if not self.config.enabled:
            return []
        
        results = []
        
        # Apply filters unless forced
        if not force:
            filter_result = await self.filter.check(
                ip=ip,
                severity=Severity.from_string(severity),
                event_type=event_type,
                enrichment=enrichment,
            )
            
            if not filter_result.should_report:
                self._stats['reports_filtered'] += 1
                logger.debug(f"Filtered: {ip} - {filter_result.reason}")
                return []
        else:
            filter_result = None
        
        # Check confirmation requirement
        if self.config.require_confirmation:
            report_id = f"{ip}_{int(time.time())}"
            self._pending[report_id] = {
                'ip': ip,
                'event_type': event_type,
                'severity': severity,
                'evidence': evidence,
                'timestamp': datetime.utcnow().isoformat(),
            }
            logger.info(f"Report pending confirmation: {report_id}")
            # Would notify admin here
            return []
        
        # Submit to all providers
        for provider_name, provider in self.providers.items():
            try:
                if provider_name == 'abuseipdb':
                    result = await provider.report_attack(
                        ip=ip,
                        event_type=event_type,
                        evidence=evidence,
                        honeypot_id=self.config.honeypot_id or 'honeyclaw',
                    )
                    success = result.success
                    message = result.message
                    error = result.error
                    
                elif provider_name == 'isp_email':
                    result = await provider.send_abuse_email(
                        ip=ip,
                        event_type=event_type,
                        evidence=evidence,
                        honeypot_id=self.config.honeypot_id or 'honeyclaw',
                    )
                    success = result.success
                    message = result.message
                    error = result.error
                
                else:
                    continue
                
                # Create audit entry
                entry = AuditLogEntry(
                    timestamp=datetime.utcnow().isoformat() + 'Z',
                    ip=ip,
                    event_type=event_type,
                    severity=severity,
                    provider=provider_name,
                    success=success,
                    message=message,
                    error=error,
                    filter_result=filter_result.to_dict() if filter_result else None,
                    evidence_summary={
                        k: v for k, v in evidence.items() 
                        if k not in ('raw', 'password') and v
                    }
                )
                
                results.append(entry)
                self._write_audit_log(entry)
                
                if success:
                    self._stats['reports_submitted'] += 1
                    self.filter.record_report(ip)
                else:
                    self._stats['reports_failed'] += 1
                    
            except Exception as e:
                logger.error(f"Error reporting to {provider_name}: {e}")
                entry = AuditLogEntry(
                    timestamp=datetime.utcnow().isoformat() + 'Z',
                    ip=ip,
                    event_type=event_type,
                    severity=severity,
                    provider=provider_name,
                    success=False,
                    error=str(e),
                )
                results.append(entry)
                self._write_audit_log(entry)
                self._stats['reports_failed'] += 1
        
        return results
    
    async def report_ip(
        self,
        ip: str,
        reason: str,
        categories: Optional[List[int]] = None,
        force: bool = False,
    ) -> List[AuditLogEntry]:
        """
        Manually report an IP address.
        
        Args:
            ip: IP address to report
            reason: Human-readable reason for report
            categories: AbuseIPDB categories (auto-detected if not provided)
            force: Skip filters
            
        Returns:
            List of audit log entries
        """
        # Auto-detect categories from reason
        if categories is None:
            reason_lower = reason.lower()
            if 'ssh' in reason_lower or 'brute' in reason_lower:
                categories = [int(AbuseCategory.SSH), int(AbuseCategory.BRUTE_FORCE)]
            elif 'scan' in reason_lower:
                categories = [int(AbuseCategory.PORT_SCAN)]
            elif 'sql' in reason_lower:
                categories = [int(AbuseCategory.SQL_INJECTION)]
            elif 'ddos' in reason_lower:
                categories = [int(AbuseCategory.DDOS_ATTACK)]
            else:
                categories = [int(AbuseCategory.HACKING)]
        
        return await self.report_event(
            ip=ip,
            event_type='manual_report',
            severity='high',
            evidence={'reason': reason, 'manual': True},
            force=force,
        )
    
    async def confirm_report(self, report_id: str) -> bool:
        """Confirm a pending report."""
        if report_id not in self._pending:
            return False
        
        pending = self._pending.pop(report_id)
        await self.report_event(
            ip=pending['ip'],
            event_type=pending['event_type'],
            severity=pending['severity'],
            evidence=pending['evidence'],
            force=True,  # Already filtered once
        )
        return True
    
    def get_pending_reports(self) -> Dict[str, Dict[str, Any]]:
        """Get all pending reports awaiting confirmation."""
        return dict(self._pending)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get reporting statistics."""
        return {
            **self._stats,
            'filter_stats': self.filter.get_stats(),
            'providers_enabled': list(self.providers.keys()),
            'config': {
                'enabled': self.config.enabled,
                'min_severity': self.config.min_severity,
                'cooldown_hours': self.config.cooldown_hours,
                'require_confirmation': self.config.require_confirmation,
            }
        }
    
    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent audit log entries."""
        if not self._audit_log_file or not self._audit_log_file.exists():
            return []
        
        entries = []
        with open(self._audit_log_file, 'r') as f:
            for line in f:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        
        # Return most recent
        return entries[-limit:]


# === Convenience functions ===

_default_engine: Optional[ReportingEngine] = None


def get_engine() -> ReportingEngine:
    """Get or create the default reporting engine."""
    global _default_engine
    if _default_engine is None:
        _default_engine = ReportingEngine()
    return _default_engine


async def report_attack(
    ip: str,
    event_type: str,
    severity: str = "high",
    evidence: Optional[Dict[str, Any]] = None,
) -> List[AuditLogEntry]:
    """
    Convenience function to report an attack.
    
    Usage:
        from src.reporting import report_attack
        
        await report_attack(
            ip="1.2.3.4",
            event_type="ssh_brute_force",
            evidence={'username': 'root', 'attempts': 50}
        )
    """
    return await get_engine().report_event(
        ip=ip,
        event_type=event_type,
        severity=severity,
        evidence=evidence or {},
    )
