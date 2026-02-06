#!/usr/bin/env python3
"""
Shodan Provider - Open ports, services, and vulnerability data.

Free tier: Limited queries (requires account)
API docs: https://developer.shodan.io/api

Environment variable: SHODAN_API_KEY
"""

import aiohttp
from typing import Optional
from .base import BaseProvider, ProviderResult


class ShodanProvider(BaseProvider):
    """
    Shodan threat intelligence provider.
    Returns information about open ports, services, and known vulnerabilities.
    """
    
    name = "shodan"
    requires_api_key = True
    free_tier = True  # Limited free tier with account
    rate_limit_per_day = 100  # Free tier limit
    
    API_URL = "https://api.shodan.io/shodan/host/{ip}"
    
    async def lookup(self, ip: str) -> ProviderResult:
        """
        Look up IP information on Shodan.
        
        Args:
            ip: IPv4 address to check
            
        Returns:
            ProviderResult with port/service information
        """
        if not self.enabled:
            return self._error_result(ip, "API key not configured (set SHODAN_API_KEY)")
        
        if not self.validate_ip(ip):
            return self._error_result(ip, "Invalid IP address format")
        
        if self.is_private_ip(ip):
            return self._error_result(ip, "Cannot look up private IP addresses")
        
        url = self.API_URL.format(ip=ip)
        params = {"key": self.api_key}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, 
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as response:
                    if response.status == 401:
                        return self._error_result(ip, "Invalid API key")
                    elif response.status == 404:
                        # IP not in Shodan database
                        return ProviderResult(
                            provider=self.name,
                            ip=ip,
                            success=True,
                            is_malicious=None,
                            confidence=0.0,
                            categories=["not_indexed"],
                            tags=["no_shodan_data"],
                            raw={}
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
        
        return self._parse_response(ip, data)
    
    def _parse_response(self, ip: str, data: dict) -> ProviderResult:
        """Parse Shodan API response"""
        categories = []
        tags = []
        
        # Extract open ports
        ports = data.get("ports", [])
        if ports:
            tags.append(f"ports:{','.join(map(str, sorted(ports)))}")
        
        # Common suspicious indicators
        suspicious_ports = {22, 23, 3389, 5900, 6379, 27017, 9200}
        exposed_critical = set(ports) & suspicious_ports
        if exposed_critical:
            categories.append("exposed_services")
            tags.append(f"critical_ports:{','.join(map(str, sorted(exposed_critical)))}")
        
        # Check for vulnerabilities
        vulns = data.get("vulns", [])
        if vulns:
            categories.append("vulnerable")
            for vuln in vulns[:10]:  # Limit to first 10
                tags.append(f"vuln:{vuln}")
        
        # Extract hostnames
        hostnames = data.get("hostnames", [])
        if hostnames:
            for h in hostnames[:5]:  # Limit to first 5
                tags.append(f"hostname:{h}")
        
        # Determine if potentially malicious based on indicators
        is_malicious = None  # Shodan doesn't directly classify
        risk_score = 0
        
        # Scoring heuristics
        if vulns:
            risk_score += min(len(vulns) * 10, 50)  # Up to 50 for vulns
        if exposed_critical:
            risk_score += len(exposed_critical) * 10  # 10 per critical port
        if len(ports) > 20:
            risk_score += 10  # Many open ports
            categories.append("heavily_exposed")
        
        # Check for known services that might indicate compromise
        for service in data.get("data", []):
            product = service.get("product", "").lower()
            if any(x in product for x in ["tor", "proxy", "vpn"]):
                categories.append("anonymizer")
            if "honeypot" in product:
                categories.append("honeypot")
        
        # Normalize risk score to 0-100
        risk_score = min(risk_score, 100)
        
        return ProviderResult(
            provider=self.name,
            ip=ip,
            success=True,
            is_malicious=risk_score >= 50,  # Threshold for "malicious"
            confidence=0.6 if risk_score > 0 else 0.3,
            risk_score=risk_score,
            categories=categories,
            tags=tags,
            country=data.get("country_code"),
            isp=data.get("isp"),
            asn=data.get("asn"),
            org=data.get("org"),
            last_seen=data.get("last_update"),
            raw={
                "ports": ports,
                "vulns": vulns,
                "hostnames": hostnames,
                "os": data.get("os"),
                "org": data.get("org"),
            }
        )
