#!/usr/bin/env python3
"""
Honeyclaw Report Filters

Smart filtering to avoid reporting:
- Known security researchers (GreyNoise benign classification)
- Already reported IPs (cooldown period)
- Low-severity events
- Known good networks (configurable allowlist)

Responsible reporting is crucial - false reports harm the reputation
of legitimate services and waste abuse team resources.
"""

import os
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
from enum import IntEnum


class Severity(IntEnum):
    """Event severity levels."""
    DEBUG = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    
    @classmethod
    def from_string(cls, s: str) -> 'Severity':
        """Convert string to severity level."""
        return cls[s.upper()]


@dataclass
class FilterResult:
    """Result of filtering decision."""
    should_report: bool
    ip: str
    reason: Optional[str] = None
    filter_name: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'should_report': self.should_report,
            'ip': self.ip,
            'reason': self.reason,
            'filter_name': self.filter_name,
            'details': self.details,
        }


class ReportFilter:
    """
    Filter to determine if an IP should be reported.
    
    Applies multiple checks:
    1. Cooldown period - don't report same IP within cooldown window
    2. Severity threshold - only report high-severity events
    3. Researcher filter - skip known benign researchers
    4. Allowlist - skip known good networks
    5. Rate limit - respect API limits
    """
    
    # Default allowlisted networks (security researchers, CDNs, etc.)
    DEFAULT_ALLOWLIST = [
        # GreyNoise
        '185.180.143.',  # GreyNoise sensors
        
        # Major security researchers (partial, expand as needed)
        '64.62.197.',    # Censys
        '162.142.125.',  # Censys
        '167.248.',      # Censys
        
        # Major CDNs (shouldn't appear in honeypots anyway)
        '13.32.',        # AWS CloudFront
        '104.16.',       # Cloudflare
        '151.101.',      # Fastly
        
        # University security research
        '141.212.',      # UMich
        '128.2.',        # CMU
    ]
    
    def __init__(
        self,
        cooldown_hours: float = 24,
        min_severity: Severity = Severity.HIGH,
        state_file: Optional[str] = None,
        allowlist: Optional[List[str]] = None,
        enable_greynoise: bool = True,
        daily_limit: int = 500,  # Conservative limit below API max
    ):
        """
        Initialize the report filter.
        
        Args:
            cooldown_hours: Hours to wait before re-reporting same IP
            min_severity: Minimum severity level to report
            state_file: Path to state file for persistence
            allowlist: IP prefixes to never report
            enable_greynoise: Use GreyNoise to filter researchers
            daily_limit: Maximum reports per day
        """
        self.cooldown_seconds = cooldown_hours * 3600
        self.min_severity = min_severity
        self.enable_greynoise = enable_greynoise
        self.daily_limit = daily_limit
        
        # State file for persistence
        if state_file:
            self.state_file = Path(state_file)
        else:
            self.state_file = Path(os.environ.get(
                'HONEYCLAW_STATE_DIR', 
                '/var/lib/honeyclaw'
            )) / 'report_state.json'
        
        # Allowlist
        self.allowlist: Set[str] = set(allowlist or [])
        self.allowlist.update(self.DEFAULT_ALLOWLIST)
        
        # Load state
        self._reported_ips: Dict[str, float] = {}  # ip -> last_report_timestamp
        self._daily_count: Dict[str, int] = {}     # date -> count
        self._benign_cache: Dict[str, bool] = {}   # ip -> is_benign (from GreyNoise)
        self._load_state()
    
    def _load_state(self):
        """Load persistent state from file."""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    self._reported_ips = state.get('reported_ips', {})
                    self._daily_count = state.get('daily_count', {})
            except (json.JSONDecodeError, IOError):
                pass  # Start fresh on error
    
    def _save_state(self):
        """Save state to file."""
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.state_file, 'w') as f:
                json.dump({
                    'reported_ips': self._reported_ips,
                    'daily_count': self._daily_count,
                }, f, indent=2)
        except IOError:
            pass  # Log but don't fail
    
    async def check(
        self,
        ip: str,
        severity: Severity,
        event_type: str = "",
        enrichment: Optional[Dict[str, Any]] = None,
    ) -> FilterResult:
        """
        Check if an IP should be reported.
        
        Args:
            ip: IP address to check
            severity: Event severity level
            event_type: Type of event
            enrichment: Pre-enriched data (e.g., from GreyNoise)
            
        Returns:
            FilterResult with decision and reason
        """
        # 1. Check severity threshold
        if severity < self.min_severity:
            return FilterResult(
                should_report=False,
                ip=ip,
                reason=f"Severity {severity.name} below threshold {self.min_severity.name}",
                filter_name="severity",
            )
        
        # 2. Check allowlist
        for prefix in self.allowlist:
            if ip.startswith(prefix):
                return FilterResult(
                    should_report=False,
                    ip=ip,
                    reason=f"IP matches allowlisted prefix {prefix}",
                    filter_name="allowlist",
                )
        
        # 3. Check cooldown
        if ip in self._reported_ips:
            last_report = self._reported_ips[ip]
            time_since = time.time() - last_report
            if time_since < self.cooldown_seconds:
                remaining = (self.cooldown_seconds - time_since) / 3600
                return FilterResult(
                    should_report=False,
                    ip=ip,
                    reason=f"IP reported {time_since/3600:.1f}h ago, cooldown {remaining:.1f}h remaining",
                    filter_name="cooldown",
                    details={'last_report': last_report, 'cooldown_remaining': remaining}
                )
        
        # 4. Check daily rate limit
        today = datetime.utcnow().strftime('%Y-%m-%d')
        daily_count = self._daily_count.get(today, 0)
        if daily_count >= self.daily_limit:
            return FilterResult(
                should_report=False,
                ip=ip,
                reason=f"Daily report limit ({self.daily_limit}) reached",
                filter_name="rate_limit",
                details={'daily_count': daily_count}
            )
        
        # 5. Check GreyNoise for researchers
        if self.enable_greynoise:
            is_benign = await self._check_greynoise_benign(ip, enrichment)
            if is_benign:
                return FilterResult(
                    should_report=False,
                    ip=ip,
                    reason="IP classified as benign by GreyNoise (likely researcher)",
                    filter_name="greynoise_benign",
                )
        
        # All checks passed
        return FilterResult(
            should_report=True,
            ip=ip,
            reason="Passed all filters",
        )
    
    async def _check_greynoise_benign(
        self,
        ip: str,
        enrichment: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Check if IP is classified as benign by GreyNoise.
        
        GreyNoise tracks internet-wide scanners. "RIOT" IPs are known
        good services, and some noise IPs are benign researchers.
        """
        # Check cache first
        if ip in self._benign_cache:
            return self._benign_cache[ip]
        
        # Check pre-provided enrichment
        if enrichment:
            greynoise = enrichment.get('greynoise', {})
            if greynoise:
                # RIOT = known good
                if greynoise.get('riot'):
                    self._benign_cache[ip] = True
                    return True
                
                # Check classification
                classification = greynoise.get('classification', '').lower()
                if classification == 'benign':
                    self._benign_cache[ip] = True
                    return True
        
        # Live lookup if enabled (optional, requires greynoise provider)
        try:
            from ..enrichment.providers.greynoise import GreyNoiseProvider
            provider = GreyNoiseProvider()
            
            if provider.enabled:
                result = await provider.lookup(ip)
                if result.success:
                    is_benign = (
                        'benign' in result.categories or
                        'riot' in result.tags or
                        result.raw.get('riot', False)
                    )
                    self._benign_cache[ip] = is_benign
                    return is_benign
        except ImportError:
            pass  # GreyNoise provider not available
        except Exception:
            pass  # Lookup failed, don't block on this
        
        self._benign_cache[ip] = False
        return False
    
    def record_report(self, ip: str):
        """Record that an IP was reported."""
        self._reported_ips[ip] = time.time()
        
        today = datetime.utcnow().strftime('%Y-%m-%d')
        self._daily_count[today] = self._daily_count.get(today, 0) + 1
        
        # Clean old entries
        self._clean_old_entries()
        
        # Persist
        self._save_state()
    
    def _clean_old_entries(self):
        """Remove expired entries from state."""
        now = time.time()
        cutoff = now - (self.cooldown_seconds * 2)  # Keep 2x cooldown
        
        # Clean reported IPs
        self._reported_ips = {
            ip: ts for ip, ts in self._reported_ips.items()
            if ts > cutoff
        }
        
        # Clean daily counts (keep last 7 days)
        recent_dates = set()
        for i in range(7):
            date = datetime.utcnow()
            date = date.replace(day=date.day - i) if date.day > i else date
            recent_dates.add(date.strftime('%Y-%m-%d'))
        
        self._daily_count = {
            date: count for date, count in self._daily_count.items()
            if date in recent_dates
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get filter statistics."""
        today = datetime.utcnow().strftime('%Y-%m-%d')
        return {
            'reported_ips_cached': len(self._reported_ips),
            'benign_cache_size': len(self._benign_cache),
            'daily_count': self._daily_count.get(today, 0),
            'daily_limit': self.daily_limit,
            'cooldown_hours': self.cooldown_seconds / 3600,
            'min_severity': self.min_severity.name,
        }
    
    def add_to_allowlist(self, prefix: str):
        """Add an IP prefix to the allowlist."""
        self.allowlist.add(prefix)
    
    def remove_from_allowlist(self, prefix: str):
        """Remove an IP prefix from the allowlist."""
        self.allowlist.discard(prefix)


# === Convenience function ===

_default_filter: Optional[ReportFilter] = None


def get_filter() -> ReportFilter:
    """Get or create the default report filter."""
    global _default_filter
    if _default_filter is None:
        _default_filter = ReportFilter()
    return _default_filter


async def should_report(
    ip: str,
    severity: str = "HIGH",
    event_type: str = "",
    enrichment: Optional[Dict[str, Any]] = None,
) -> FilterResult:
    """
    Convenience function to check if an IP should be reported.
    
    Usage:
        from src.reporting.filters import should_report
        
        result = await should_report("1.2.3.4", severity="HIGH")
        if result.should_report:
            # Submit report
    """
    severity_level = Severity.from_string(severity)
    return await get_filter().check(ip, severity_level, event_type, enrichment)
