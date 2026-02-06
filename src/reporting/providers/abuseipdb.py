#!/usr/bin/env python3
"""
AbuseIPDB Reporter - Submit abuse reports to AbuseIPDB.

API docs: https://docs.abuseipdb.com/#report-endpoint

Free tier: 1,000 reports/day
Environment variable: ABUSEIPDB_API_KEY

Note: Reporting should be done responsibly. Only report genuine malicious
activity with supporting evidence. False reports can damage reputation
and waste resources for abuse teams.
"""

import os
import json
import aiohttp
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import IntEnum


class AbuseCategory(IntEnum):
    """
    AbuseIPDB attack categories.
    https://www.abuseipdb.com/categories
    """
    DNS_COMPROMISE = 1
    DNS_POISONING = 2
    FRAUD_ORDERS = 3
    DDOS_ATTACK = 4
    FTP_BRUTE_FORCE = 5
    PING_OF_DEATH = 6
    PHISHING = 7
    FRAUD_VOIP = 8
    OPEN_PROXY = 9
    WEB_SPAM = 10
    EMAIL_SPAM = 11
    BLOG_SPAM = 12
    VPN_IP = 13
    PORT_SCAN = 14
    HACKING = 15
    SQL_INJECTION = 16
    SPOOFING = 17
    BRUTE_FORCE = 18
    BAD_WEB_BOT = 19
    EXPLOITED_HOST = 20
    WEB_APP_ATTACK = 21
    SSH = 22
    IOT_TARGETED = 23
    
    @classmethod
    def from_event_type(cls, event_type: str) -> List['AbuseCategory']:
        """Map Honeyclaw event types to AbuseIPDB categories."""
        mapping = {
            'ssh_brute_force': [cls.SSH, cls.BRUTE_FORCE],
            'login_attempt': [cls.BRUTE_FORCE],
            'auth_failure': [cls.BRUTE_FORCE],
            'password_spray': [cls.BRUTE_FORCE],
            'port_scan': [cls.PORT_SCAN],
            'command_injection': [cls.WEB_APP_ATTACK, cls.HACKING],
            'sql_injection': [cls.SQL_INJECTION, cls.WEB_APP_ATTACK],
            'path_traversal': [cls.WEB_APP_ATTACK],
            'rce_attempt': [cls.HACKING],
            'malware_upload': [cls.HACKING, cls.EXPLOITED_HOST],
            'ddos': [cls.DDOS_ATTACK],
            'web_attack': [cls.WEB_APP_ATTACK],
            'api_abuse': [cls.HACKING, cls.BAD_WEB_BOT],
            'crawler_abuse': [cls.BAD_WEB_BOT],
            'http_flood': [cls.DDOS_ATTACK, cls.BAD_WEB_BOT],
        }
        
        event_lower = event_type.lower()
        
        # Direct match
        if event_lower in mapping:
            return mapping[event_lower]
        
        # Partial match
        for key, categories in mapping.items():
            if key in event_lower or event_lower in key:
                return categories
        
        # Default for unknown attack types
        return [cls.HACKING]


@dataclass 
class ReportResult:
    """Result of an abuse report submission."""
    success: bool
    ip: str
    provider: str = "abuseipdb"
    report_id: Optional[str] = None
    message: Optional[str] = None
    error: Optional[str] = None
    timestamp: str = ""
    raw_response: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat() + 'Z'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging."""
        return {
            'success': self.success,
            'ip': self.ip,
            'provider': self.provider,
            'report_id': self.report_id,
            'message': self.message,
            'error': self.error,
            'timestamp': self.timestamp,
        }


class AbuseIPDBReporter:
    """
    Submit abuse reports to AbuseIPDB.
    
    Features:
    - Automatic category detection from event types
    - Evidence formatting with attack details
    - Rate limiting awareness
    - Error handling and retry logic
    """
    
    name = "abuseipdb"
    REPORT_URL = "https://api.abuseipdb.com/api/v2/report"
    
    # Rate limit: 1000 reports/day = ~41/hour
    DAILY_LIMIT = 1000
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the reporter.
        
        Args:
            api_key: AbuseIPDB API key (or from ABUSEIPDB_API_KEY env var)
        """
        self.api_key = api_key or os.environ.get('ABUSEIPDB_API_KEY')
        self._enabled = bool(self.api_key)
    
    @property
    def enabled(self) -> bool:
        """Check if reporter is enabled."""
        return self._enabled
    
    async def report(
        self,
        ip: str,
        categories: List[int],
        comment: str,
        timestamp: Optional[str] = None,
    ) -> ReportResult:
        """
        Submit an abuse report to AbuseIPDB.
        
        Args:
            ip: IP address to report
            categories: List of AbuseCategory values
            comment: Description of the abuse (max 1024 chars)
            timestamp: ISO timestamp of the attack (optional)
            
        Returns:
            ReportResult with submission status
        """
        if not self.enabled:
            return ReportResult(
                success=False,
                ip=ip,
                error="API key not configured. Set ABUSEIPDB_API_KEY environment variable."
            )
        
        # Validate IP
        if not self._validate_ip(ip):
            return ReportResult(
                success=False,
                ip=ip,
                error="Invalid IP address format"
            )
        
        # Don't report private IPs
        if self._is_private_ip(ip):
            return ReportResult(
                success=False,
                ip=ip,
                error="Cannot report private IP addresses"
            )
        
        # Truncate comment to max length
        comment = comment[:1024] if len(comment) > 1024 else comment
        
        # Build request
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        
        data = {
            "ip": ip,
            "categories": ",".join(str(c) for c in categories),
            "comment": comment,
        }
        
        if timestamp:
            data["timestamp"] = timestamp
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.REPORT_URL,
                    headers=headers,
                    data=data,
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as response:
                    response_data = await response.json()
                    
                    if response.status == 200:
                        report_data = response_data.get("data", {})
                        return ReportResult(
                            success=True,
                            ip=ip,
                            report_id=str(report_data.get("abuseConfidenceScore", "")),
                            message=f"Report accepted. IP confidence score: {report_data.get('abuseConfidenceScore')}%",
                            raw_response=response_data
                        )
                    elif response.status == 422:
                        # Validation error (e.g., duplicate report)
                        errors = response_data.get("errors", [])
                        error_msg = errors[0].get("detail", "Validation error") if errors else "Validation error"
                        return ReportResult(
                            success=False,
                            ip=ip,
                            error=error_msg,
                            raw_response=response_data
                        )
                    elif response.status == 429:
                        return ReportResult(
                            success=False,
                            ip=ip,
                            error="Rate limit exceeded. Try again later.",
                            raw_response=response_data
                        )
                    elif response.status == 401:
                        return ReportResult(
                            success=False,
                            ip=ip,
                            error="Invalid API key",
                            raw_response=response_data
                        )
                    else:
                        return ReportResult(
                            success=False,
                            ip=ip,
                            error=f"API error: HTTP {response.status}",
                            raw_response=response_data
                        )
                        
        except aiohttp.ClientError as e:
            return ReportResult(
                success=False,
                ip=ip,
                error=f"Connection error: {str(e)}"
            )
        except Exception as e:
            return ReportResult(
                success=False,
                ip=ip,
                error=f"Unexpected error: {str(e)}"
            )
    
    async def report_attack(
        self,
        ip: str,
        event_type: str,
        evidence: Dict[str, Any],
        honeypot_id: str = "honeyclaw",
    ) -> ReportResult:
        """
        High-level method to report an attack with automatic category detection.
        
        Args:
            ip: Attacker IP address
            event_type: Type of attack (e.g., 'ssh_brute_force')
            evidence: Dict containing attack evidence
            honeypot_id: Identifier for this honeypot
            
        Returns:
            ReportResult with submission status
        """
        # Get categories from event type
        categories = [int(c) for c in AbuseCategory.from_event_type(event_type)]
        
        # Build evidence comment
        comment = self._format_evidence(event_type, evidence, honeypot_id)
        
        # Get timestamp from evidence if available
        timestamp = evidence.get('timestamp') or evidence.get('time')
        
        return await self.report(ip, categories, comment, timestamp)
    
    def _format_evidence(
        self,
        event_type: str,
        evidence: Dict[str, Any],
        honeypot_id: str
    ) -> str:
        """Format evidence into a readable comment."""
        lines = [
            f"[Honeyclaw/{honeypot_id}] {event_type.replace('_', ' ').title()} Attack",
            "",
        ]
        
        # Add relevant evidence fields
        evidence_fields = [
            ('username', 'Username attempted'),
            ('password', 'Password attempted'),
            ('command', 'Command executed'),
            ('path', 'Path accessed'),
            ('payload', 'Payload'),
            ('method', 'HTTP Method'),
            ('user_agent', 'User-Agent'),
            ('port', 'Target port'),
            ('attempts', 'Attempt count'),
            ('session_id', 'Session ID'),
        ]
        
        for field, label in evidence_fields:
            if field in evidence and evidence[field]:
                value = str(evidence[field])
                # Truncate long values
                if len(value) > 100:
                    value = value[:97] + "..."
                # Mask passwords partially
                if field == 'password' and len(value) > 2:
                    value = value[0] + '*' * (len(value) - 2) + value[-1]
                lines.append(f"{label}: {value}")
        
        # Add timestamp
        if 'timestamp' in evidence:
            lines.append(f"Time: {evidence['timestamp']}")
        
        lines.append("")
        lines.append("Reported via Honeyclaw honeypot system")
        
        return "\n".join(lines)
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IPv4 address format."""
        import re
        pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(pattern, ip))
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/reserved."""
        octets = [int(x) for x in ip.split('.')]
        
        # RFC 1918 private ranges
        if octets[0] == 10:
            return True
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True
        if octets[0] == 192 and octets[1] == 168:
            return True
        # Localhost
        if octets[0] == 127:
            return True
        # Link-local
        if octets[0] == 169 and octets[1] == 254:
            return True
        
        return False
