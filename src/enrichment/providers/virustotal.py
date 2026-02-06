#!/usr/bin/env python3
"""
VirusTotal Provider - IP/domain reputation from 70+ security vendors.

Free tier: 500 queries/day, 4 queries/minute
API docs: https://developers.virustotal.com/reference/ip-info

Environment variable: VIRUSTOTAL_API_KEY
"""

import aiohttp
from typing import Optional
from .base import BaseProvider, ProviderResult


class VirusTotalProvider(BaseProvider):
    """
    VirusTotal threat intelligence provider.
    Aggregates reputation data from 70+ security vendors.
    """
    
    name = "virustotal"
    requires_api_key = True
    free_tier = True
    rate_limit_per_day = 500
    
    API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    
    async def lookup(self, ip: str) -> ProviderResult:
        """
        Look up IP reputation on VirusTotal.
        
        Args:
            ip: IPv4 address to check
            
        Returns:
            ProviderResult with multi-vendor reputation
        """
        if not self.enabled:
            return self._error_result(ip, "API key not configured (set VIRUSTOTAL_API_KEY)")
        
        if not self.validate_ip(ip):
            return self._error_result(ip, "Invalid IP address format")
        
        if self.is_private_ip(ip):
            return self._error_result(ip, "Cannot look up private IP addresses")
        
        url = self.API_URL.format(ip=ip)
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, 
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as response:
                    if response.status == 401:
                        return self._error_result(ip, "Invalid API key")
                    elif response.status == 404:
                        return ProviderResult(
                            provider=self.name,
                            ip=ip,
                            success=True,
                            is_malicious=None,
                            categories=["not_found"],
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
        """Parse VirusTotal API response"""
        attributes = data.get("data", {}).get("attributes", {})
        
        categories = []
        tags = []
        
        # Last analysis stats
        stats = attributes.get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        harmless_count = stats.get("harmless", 0)
        undetected_count = stats.get("undetected", 0)
        total_vendors = malicious_count + suspicious_count + harmless_count + undetected_count
        
        tags.append(f"detections:{malicious_count}/{total_vendors}")
        
        if malicious_count > 0:
            categories.append("malicious_by_vendors")
            tags.append(f"malicious_detections:{malicious_count}")
        
        if suspicious_count > 0:
            categories.append("suspicious_by_vendors")
            tags.append(f"suspicious_detections:{suspicious_count}")
        
        # Calculate risk score based on vendor consensus
        if total_vendors > 0:
            risk_score = int(((malicious_count + suspicious_count * 0.5) / total_vendors) * 100)
        else:
            risk_score = 0
        
        # Determine maliciousness - at least 3 vendors flagging as malicious
        is_malicious = malicious_count >= 3
        
        # Confidence based on vendor coverage
        if total_vendors >= 50:
            confidence = 0.9
        elif total_vendors >= 20:
            confidence = 0.7
        else:
            confidence = 0.5
        
        # Extract reputation score
        reputation = attributes.get("reputation", 0)
        if reputation < -10:
            categories.append("poor_reputation")
            tags.append(f"reputation:{reputation}")
        elif reputation > 10:
            categories.append("good_reputation")
        
        # ASN and network info
        asn = attributes.get("asn")
        if asn:
            tags.append(f"asn:{asn}")
        
        # WHOIS info
        as_owner = attributes.get("as_owner")
        
        # Check for known categories
        vt_categories = attributes.get("categories", {})
        for vendor, category in vt_categories.items():
            if category and category.lower() not in ["unrated"]:
                sanitized = category.lower().replace(" ", "_")
                if sanitized not in categories:
                    categories.append(sanitized)
        
        # Extract last analysis results (top flagging vendors)
        results = attributes.get("last_analysis_results", {})
        flagging_vendors = [
            vendor for vendor, result in results.items()
            if result.get("category") in ["malicious", "suspicious"]
        ][:5]  # Top 5
        if flagging_vendors:
            tags.append(f"flagged_by:{','.join(flagging_vendors)}")
        
        return ProviderResult(
            provider=self.name,
            ip=ip,
            success=True,
            is_malicious=is_malicious,
            confidence=confidence,
            risk_score=risk_score,
            categories=categories,
            tags=tags,
            country=attributes.get("country"),
            asn=asn,
            org=as_owner,
            raw={
                "reputation": reputation,
                "analysis_stats": stats,
                "total_vendors": total_vendors,
                "flagging_vendors": flagging_vendors[:10],
            }
        )
