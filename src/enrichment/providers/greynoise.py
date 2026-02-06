#!/usr/bin/env python3
"""
GreyNoise Provider - Internet-wide scanner classification.

Community API (free): Unlimited queries with rate limiting
API docs: https://docs.greynoise.io/

Environment variable: GREYNOISE_API_KEY (optional for community API)
"""

import aiohttp
from typing import Optional
from .base import BaseProvider, ProviderResult


class GreyNoiseProvider(BaseProvider):
    """
    GreyNoise threat intelligence provider.
    Identifies scanners, bots, and benign internet background noise.
    """
    
    name = "greynoise"
    requires_api_key = False  # Community API works without key
    free_tier = True
    rate_limit_per_day = None  # Rate-limited but not hard-capped
    
    # Community API endpoint (free, no key required)
    COMMUNITY_URL = "https://api.greynoise.io/v3/community/{ip}"
    
    # Enterprise API endpoint (requires key)
    ENTERPRISE_URL = "https://api.greynoise.io/v2/noise/context/{ip}"
    
    def __init__(self, api_key: Optional[str] = None):
        # Allow operation without API key (community mode)
        super().__init__(api_key)
        self._enabled = True  # Always enabled since community API is free
        self.use_enterprise = bool(self.api_key)
    
    async def lookup(self, ip: str) -> ProviderResult:
        """
        Look up IP classification on GreyNoise.
        
        Args:
            ip: IPv4 address to check
            
        Returns:
            ProviderResult with scanner classification
        """
        if not self.validate_ip(ip):
            return self._error_result(ip, "Invalid IP address format")
        
        if self.is_private_ip(ip):
            return self._error_result(ip, "Cannot look up private IP addresses")
        
        if self.use_enterprise:
            return await self._lookup_enterprise(ip)
        else:
            return await self._lookup_community(ip)
    
    async def _lookup_community(self, ip: str) -> ProviderResult:
        """Use the free community API"""
        url = self.COMMUNITY_URL.format(ip=ip)
        
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["key"] = self.api_key
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, 
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 404:
                        # IP not observed by GreyNoise - this is actually useful info
                        return ProviderResult(
                            provider=self.name,
                            ip=ip,
                            success=True,
                            is_malicious=False,
                            confidence=0.5,
                            categories=["not_observed"],
                            tags=["not_in_greynoise"],
                            raw={"noise": False, "riot": False}
                        )
                    elif response.status == 429:
                        return self._error_result(ip, "Rate limit exceeded")
                    elif response.status != 200:
                        return self._error_result(ip, f"API error: HTTP {response.status}")
                    
                    data = await response.json()
        
        except aiohttp.ClientError as e:
            return self._error_result(ip, f"Connection error: {str(e)}")
        except Exception as e:
            return self._error_result(ip, f"Unexpected error: {str(e)}")
        
        return self._parse_community_response(ip, data)
    
    async def _lookup_enterprise(self, ip: str) -> ProviderResult:
        """Use the enterprise API (requires key)"""
        url = self.ENTERPRISE_URL.format(ip=ip)
        
        headers = {
            "key": self.api_key,
            "Accept": "application/json"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, 
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 401:
                        return self._error_result(ip, "Invalid API key")
                    elif response.status == 404:
                        return ProviderResult(
                            provider=self.name,
                            ip=ip,
                            success=True,
                            is_malicious=False,
                            categories=["not_observed"],
                            tags=["not_in_greynoise"],
                            raw={"seen": False}
                        )
                    elif response.status == 429:
                        return self._error_result(ip, "Rate limit exceeded")
                    elif response.status != 200:
                        return self._error_result(ip, f"API error: HTTP {response.status}")
                    
                    data = await response.json()
        
        except aiohttp.ClientError as e:
            return self._error_result(ip, f"Connection error: {str(e)}")
        except Exception as e:
            return self._error_result(ip, f"Unexpected error: {str(e)}")
        
        return self._parse_enterprise_response(ip, data)
    
    def _parse_community_response(self, ip: str, data: dict) -> ProviderResult:
        """Parse community API response"""
        is_noise = data.get("noise", False)
        is_riot = data.get("riot", False)
        classification = data.get("classification", "unknown")
        
        categories = []
        tags = []
        
        if is_noise:
            categories.append("scanner")
            tags.append("internet_noise")
        
        if is_riot:
            categories.append("benign_service")
            tags.append("riot_trusted")
        
        # Classification: benign, malicious, or unknown
        if classification == "malicious":
            is_malicious = True
            confidence = 0.8
        elif classification == "benign":
            is_malicious = False
            confidence = 0.8
            categories.append("benign")
        else:
            is_malicious = is_noise and not is_riot
            confidence = 0.5
        
        if data.get("name"):
            tags.append(f"actor:{data['name']}")
        
        return ProviderResult(
            provider=self.name,
            ip=ip,
            success=True,
            is_malicious=is_malicious,
            confidence=confidence,
            categories=categories,
            tags=tags,
            last_seen=data.get("last_seen"),
            raw=data
        )
    
    def _parse_enterprise_response(self, ip: str, data: dict) -> ProviderResult:
        """Parse enterprise API response"""
        classification = data.get("classification", "unknown")
        
        categories = []
        tags = data.get("tags", [])
        
        if data.get("seen"):
            categories.append("scanner")
        
        if data.get("bot"):
            categories.append("bot")
            tags.append(f"bot:{data.get('bot', 'unknown')}")
        
        # Classification: benign, malicious, or unknown
        is_malicious = classification == "malicious"
        if classification in ["benign", "malicious"]:
            confidence = 0.9
        else:
            confidence = 0.5
        
        # Extract actor info
        if data.get("actor"):
            tags.append(f"actor:{data['actor']}")
            categories.append("known_actor")
        
        # Extract CVEs being exploited
        for cve in data.get("cve", []):
            tags.append(f"cve:{cve}")
        
        return ProviderResult(
            provider=self.name,
            ip=ip,
            success=True,
            is_malicious=is_malicious,
            confidence=confidence,
            categories=categories,
            tags=tags,
            country=data.get("metadata", {}).get("country_code"),
            asn=data.get("metadata", {}).get("asn"),
            org=data.get("metadata", {}).get("organization"),
            first_seen=data.get("first_seen"),
            last_seen=data.get("last_seen"),
            raw=data
        )
