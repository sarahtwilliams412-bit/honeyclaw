#!/usr/bin/env python3
"""
Base Provider - Abstract base class for threat intelligence providers.
"""

import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List


@dataclass
class ProviderResult:
    """
    Standardized result from a threat intelligence provider.
    """
    provider: str
    ip: str
    success: bool
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + 'Z')
    
    # Threat assessment
    is_malicious: Optional[bool] = None
    confidence: Optional[float] = None  # 0.0 to 1.0
    risk_score: Optional[int] = None    # 0 to 100
    
    # Classification
    categories: List[str] = field(default_factory=list)  # e.g., ["scanner", "botnet", "tor"]
    tags: List[str] = field(default_factory=list)
    
    # Metadata
    country: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[int] = None
    org: Optional[str] = None
    
    # Activity
    last_seen: Optional[str] = None
    first_seen: Optional[str] = None
    report_count: Optional[int] = None
    
    # Raw data from provider
    raw: Dict[str, Any] = field(default_factory=dict)
    
    # Error info if failed
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, omitting None values"""
        return {k: v for k, v in {
            'provider': self.provider,
            'ip': self.ip,
            'success': self.success,
            'timestamp': self.timestamp,
            'is_malicious': self.is_malicious,
            'confidence': self.confidence,
            'risk_score': self.risk_score,
            'categories': self.categories if self.categories else None,
            'tags': self.tags if self.tags else None,
            'country': self.country,
            'isp': self.isp,
            'asn': self.asn,
            'org': self.org,
            'last_seen': self.last_seen,
            'first_seen': self.first_seen,
            'report_count': self.report_count,
            'error': self.error,
        }.items() if v is not None}


class BaseProvider(ABC):
    """
    Abstract base class for threat intelligence providers.
    Subclasses must implement the lookup method.
    """
    
    # Override in subclass
    name: str = "base"
    requires_api_key: bool = True
    free_tier: bool = False
    rate_limit_per_day: Optional[int] = None
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the provider.
        
        Args:
            api_key: API key for the provider (or from env var)
        """
        env_var = f"{self.name.upper()}_API_KEY"
        self.api_key = api_key or os.environ.get(env_var)
        
        if self.requires_api_key and not self.api_key:
            self._enabled = False
        else:
            self._enabled = True
    
    @property
    def enabled(self) -> bool:
        """Check if provider is enabled and configured"""
        return self._enabled
    
    def validate_ip(self, ip: str) -> bool:
        """Validate that the input is a valid IPv4 address"""
        pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(pattern, ip))
    
    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is a private/reserved address"""
        octets = [int(x) for x in ip.split('.')]
        
        # 10.0.0.0/8
        if octets[0] == 10:
            return True
        # 172.16.0.0/12
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True
        # 192.168.0.0/16
        if octets[0] == 192 and octets[1] == 168:
            return True
        # 127.0.0.0/8 (localhost)
        if octets[0] == 127:
            return True
        # 169.254.0.0/16 (link-local)
        if octets[0] == 169 and octets[1] == 254:
            return True
        # 0.0.0.0
        if all(o == 0 for o in octets):
            return True
        
        return False
    
    @abstractmethod
    async def lookup(self, ip: str) -> ProviderResult:
        """
        Look up threat intelligence for an IP address.
        
        Args:
            ip: IPv4 address to look up
            
        Returns:
            ProviderResult with enrichment data
        """
        pass
    
    def _error_result(self, ip: str, error: str) -> ProviderResult:
        """Create an error result"""
        return ProviderResult(
            provider=self.name,
            ip=ip,
            success=False,
            error=error
        )
