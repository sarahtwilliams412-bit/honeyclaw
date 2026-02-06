#!/usr/bin/env python3
"""
Honeyclaw Alert Rules Engine

Configurable rules for detecting high-value security events.
"""

import os
import re
import fnmatch
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass, field


class Severity(IntEnum):
    """Alert severity levels (higher = more urgent)"""
    DEBUG = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass
class AlertRule:
    """
    A single alert rule definition.
    
    Attributes:
        name: Unique rule identifier
        description: Human-readable description
        severity: Alert severity level
        event_types: Event types this rule applies to (supports wildcards)
        conditions: Dict of field patterns to match (supports regex with r'...')
        tags: Additional tags for categorization
        enabled: Whether the rule is active
        dedup_key: Fields to use for deduplication (default: source IP)
        dedup_window_sec: Window for deduplication in seconds
    """
    name: str
    description: str
    severity: Severity
    event_types: List[str] = field(default_factory=list)
    conditions: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    enabled: bool = True
    dedup_key: List[str] = field(default_factory=lambda: ['ip'])
    dedup_window_sec: int = 300  # 5 minutes default
    
    def matches_event_type(self, event_type: str) -> bool:
        """Check if this rule applies to the given event type."""
        if not self.event_types:
            return True  # Empty = match all
        
        for pattern in self.event_types:
            if fnmatch.fnmatch(event_type, pattern):
                return True
        return False
    
    def check_conditions(self, event: Dict[str, Any]) -> bool:
        """Check if event matches all conditions."""
        for field_path, pattern in self.conditions.items():
            value = self._get_nested_value(event, field_path)
            if not self._match_pattern(value, pattern):
                return False
        return True
    
    def _get_nested_value(self, data: Dict, path: str) -> Any:
        """Get value from nested dict using dot notation."""
        keys = path.split('.')
        current = data
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return current
    
    def _match_pattern(self, value: Any, pattern: Any) -> bool:
        """Match a value against a pattern."""
        if value is None:
            return pattern is None
        
        # Regex pattern (starts with r')
        if isinstance(pattern, str) and pattern.startswith('r\'') and pattern.endswith('\''):
            regex = pattern[2:-1]
            return bool(re.search(regex, str(value), re.IGNORECASE))
        
        # List = any match
        if isinstance(pattern, list):
            return value in pattern
        
        # Callable
        if callable(pattern):
            return pattern(value)
        
        # Direct comparison
        return value == pattern
    
    def get_dedup_hash(self, event: Dict[str, Any]) -> str:
        """Generate deduplication hash for an event."""
        parts = [self.name]
        for key in self.dedup_key:
            value = self._get_nested_value(event, key)
            parts.append(f"{key}={value}")
        return ':'.join(parts)


# === Built-in Rules ===

BUILTIN_RULES: List[AlertRule] = [
    # Critical: Successful authentication (in a honeypot = definitely malicious)
    AlertRule(
        name="successful_auth",
        description="Successful authentication detected in honeypot",
        severity=Severity.CRITICAL,
        event_types=["auth_success", "login_success", "session_established"],
        tags=["auth", "critical", "immediate"],
        dedup_window_sec=60,
    ),
    
    # Critical: Known malware signatures
    AlertRule(
        name="malware_signature",
        description="Known malware signature detected",
        severity=Severity.CRITICAL,
        event_types=["*"],
        conditions={
            "payload_hash": r'.*',  # Will be overridden with actual hashes
        },
        tags=["malware", "critical"],
        enabled=False,  # Enable when hashes configured
    ),
    
    # High: Rate limit bypass attempts
    AlertRule(
        name="rate_limit_bypass",
        description="Potential rate limit bypass detected",
        severity=Severity.HIGH,
        event_types=["rate_limit_*"],
        conditions={
            "count": lambda x: x and int(x) > 50,
        },
        tags=["evasion", "rate_limit"],
        dedup_key=["ip"],
        dedup_window_sec=600,
    ),
    
    # High: Data exfiltration patterns
    AlertRule(
        name="exfil_attempt",
        description="Potential data exfiltration attempt",
        severity=Severity.HIGH,
        event_types=["command", "file_read", "api_request"],
        conditions={
            "command": r'(curl|wget|nc|netcat|scp|rsync|ftp).*\|',  # Piping to network tools
        },
        tags=["exfiltration", "data_theft"],
    ),
    
    # High: Privilege escalation attempts
    AlertRule(
        name="privesc_attempt",
        description="Privilege escalation attempt detected",
        severity=Severity.HIGH,
        event_types=["command", "shell_command"],
        conditions={
            "command": r'(sudo|su |chmod \+s|chown root|setuid|/etc/passwd|/etc/shadow)',
        },
        tags=["privesc", "critical"],
    ),
    
    # Medium: Admin/root login attempts
    AlertRule(
        name="admin_login_attempt",
        description="Login attempt with admin/root username",
        severity=Severity.MEDIUM,
        event_types=["login_attempt", "pubkey_attempt", "auth_*"],
        conditions={
            "username": ["root", "admin", "administrator", "Administrator", "ADMIN"],
        },
        tags=["auth", "admin"],
        dedup_key=["ip", "username"],
        dedup_window_sec=300,
    ),
    
    # Medium: SQL injection attempts
    AlertRule(
        name="sqli_attempt",
        description="SQL injection attempt detected",
        severity=Severity.MEDIUM,
        event_types=["api_request", "http_request"],
        conditions={
            "path": r'(\%27|\'|--|;|\/\*|\*\/|union.*select|select.*from)',
        },
        tags=["injection", "sqli"],
    ),
    
    # Medium: Path traversal
    AlertRule(
        name="path_traversal",
        description="Path traversal attempt detected",
        severity=Severity.MEDIUM,
        event_types=["api_request", "http_request", "file_*"],
        conditions={
            "path": r'(\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e%252f)',
        },
        tags=["traversal", "lfi"],
    ),
    
    # Medium: Command injection
    AlertRule(
        name="cmd_injection",
        description="Command injection attempt detected",
        severity=Severity.MEDIUM,
        event_types=["api_request", "http_request"],
        conditions={
            "body": r'(\||;|`|\$\(|&&)',
        },
        tags=["injection", "rce"],
    ),
    
    # Low: Credential stuffing (bulk attempts)
    AlertRule(
        name="credential_stuffing",
        description="Credential stuffing attack detected",
        severity=Severity.LOW,
        event_types=["rate_limit_auth"],
        tags=["auth", "brute_force"],
        dedup_window_sec=3600,
    ),
    
    # Low: Port scan detected
    AlertRule(
        name="port_scan",
        description="Port scanning activity detected",
        severity=Severity.LOW,
        event_types=["connection"],
        tags=["recon", "scan"],
        dedup_key=["ip"],
        dedup_window_sec=1800,
    ),
    
    # Info: New unique IP
    AlertRule(
        name="new_attacker_ip",
        description="New attacker IP observed",
        severity=Severity.INFO,
        event_types=["connection", "api_request"],
        tags=["recon"],
        dedup_key=["ip"],
        dedup_window_sec=86400,  # 24 hours
    ),
]


class AlertEngine:
    """
    Main alert processing engine.
    
    Evaluates events against rules and generates alerts.
    """
    
    def __init__(
        self,
        rules: Optional[List[AlertRule]] = None,
        min_severity: Optional[Severity] = None,
        enable_builtin: bool = True,
    ):
        """
        Initialize the alert engine.
        
        Args:
            rules: Custom rules to add
            min_severity: Minimum severity threshold (from env or param)
            enable_builtin: Whether to include built-in rules
        """
        self.rules: List[AlertRule] = []
        
        # Load built-in rules if enabled
        if enable_builtin:
            self.rules.extend(BUILTIN_RULES)
        
        # Add custom rules
        if rules:
            self.rules.extend(rules)
        
        # Set severity threshold from env or param
        env_threshold = os.environ.get('ALERT_SEVERITY_THRESHOLD', '').upper()
        if env_threshold and hasattr(Severity, env_threshold):
            self.min_severity = Severity[env_threshold]
        elif min_severity is not None:
            self.min_severity = min_severity
        else:
            self.min_severity = Severity.LOW  # Default
        
        # Deduplication cache: hash -> (timestamp, count)
        self._dedup_cache: Dict[str, tuple] = {}
        
    def add_rule(self, rule: AlertRule):
        """Add a custom rule."""
        self.rules.append(rule)
    
    def remove_rule(self, name: str):
        """Remove a rule by name."""
        self.rules = [r for r in self.rules if r.name != name]
    
    def get_rule(self, name: str) -> Optional[AlertRule]:
        """Get a rule by name."""
        for rule in self.rules:
            if rule.name == name:
                return rule
        return None
    
    def evaluate(self, event: Dict[str, Any], event_type: str) -> List[Dict[str, Any]]:
        """
        Evaluate an event against all rules.
        
        Args:
            event: The event data
            event_type: The event type string
            
        Returns:
            List of alert dicts for triggered rules
        """
        import time
        
        alerts = []
        current_time = time.time()
        
        # Clean expired dedup entries periodically
        self._clean_dedup_cache(current_time)
        
        for rule in self.rules:
            # Skip disabled rules
            if not rule.enabled:
                continue
            
            # Check severity threshold
            if rule.severity < self.min_severity:
                continue
            
            # Check event type match
            if not rule.matches_event_type(event_type):
                continue
            
            # Check conditions
            if not rule.check_conditions(event):
                continue
            
            # Check deduplication
            dedup_hash = rule.get_dedup_hash(event)
            if dedup_hash in self._dedup_cache:
                last_time, count = self._dedup_cache[dedup_hash]
                if current_time - last_time < rule.dedup_window_sec:
                    # Update count but don't alert
                    self._dedup_cache[dedup_hash] = (last_time, count + 1)
                    continue
            
            # Record for dedup
            self._dedup_cache[dedup_hash] = (current_time, 1)
            
            # Generate alert
            alert = {
                'rule': rule.name,
                'description': rule.description,
                'severity': rule.severity.name,
                'severity_level': int(rule.severity),
                'tags': rule.tags,
                'event_type': event_type,
                'event': event,
                'timestamp': current_time,
            }
            alerts.append(alert)
        
        return alerts
    
    def _clean_dedup_cache(self, current_time: float):
        """Remove expired dedup entries."""
        # Only clean occasionally
        if not hasattr(self, '_last_clean') or current_time - self._last_clean > 60:
            max_window = max(r.dedup_window_sec for r in self.rules) if self.rules else 3600
            expired = [
                h for h, (t, _) in self._dedup_cache.items()
                if current_time - t > max_window
            ]
            for h in expired:
                del self._dedup_cache[h]
            self._last_clean = current_time


# === Malware Signature Matching ===

# Common malware hashes (extend this list)
KNOWN_MALWARE_HASHES = {
    # Example: Add real hashes in production
    # "d41d8cd98f00b204e9800998ecf8427e": "Empty file test",
}

def create_malware_rule(hashes: Dict[str, str] = None) -> AlertRule:
    """Create a rule for malware signature detection."""
    if hashes is None:
        hashes = KNOWN_MALWARE_HASHES
    
    return AlertRule(
        name="malware_signature",
        description="Known malware signature detected",
        severity=Severity.CRITICAL,
        event_types=["file_upload", "payload_received", "*"],
        conditions={
            "payload_hash": lambda h: h in hashes,
        },
        tags=["malware", "critical", "ioc"],
        enabled=bool(hashes),
    )


# === Helper for Quick Setup ===

def create_default_engine() -> AlertEngine:
    """Create an alert engine with default configuration."""
    return AlertEngine(enable_builtin=True)
