#!/usr/bin/env python3
"""
AbuseIPDB Provider - IP reputation and abuse reports.

Free tier: 1,000 queries/day
API docs: https://docs.abuseipdb.com/

Environment variable: ABUSEIPDB_API_KEY
"""

import aiohttp
from typing import Optional
from .base import BaseProvider, ProviderResult


class AbuseIPDBProvider(BaseProvider):
    """
    AbuseIPDB threat intelligence provider.
    Returns abuse confidence score and report history.
    """
    
    name = "abuseipdb"
    requires_api_key = True
    free_tier = True
    rate_limit_per_day = 1000
    
    API_URL = "https://api.abuseipdb.com/api/v2/check"
    
    # Map AbuseIPDB categories to human-readable names
    CATEGORY_MAP = {
        1: "dns_compromise",
        2: "dns_poisoning",
        3: "fraud_orders",
        4: "ddos_attack",
        5: "ftp_brute_force",
        6: "ping_of_death",
        7: "phishing",
        8: "fraud_voip",
        9: "open_proxy",
        10: "web_spam",
        11: "email_spam",
        12: "blog_spam",
        13: "vpn_ip",
        14: "port_scan",
        15: "hacking",
        16: "sql_injection",
        17: "spoofing",
        18: "brute_force",
        19: "bad_web_bot",
        20: "exploited_host",
        21: "web_app_attack",
        22: "ssh",
        23: "iot_targeted",
    }
    
    async def lookup(self, ip: str) -> ProviderResult:
        """
        Look up IP reputation on AbuseIPDB.
        
        Args:
            ip: IPv4 address to check
            
        Returns:
            ProviderResult with abuse confidence score and reports
        """
        if not self.enabled:
            return self._error_result(ip, "API key not configured")
        
        if not self.validate_ip(ip):
            return self._error_result(ip, "Invalid IP address format")
        
        if self.is_private_ip(ip):
            return self._error_result(ip, "Cannot look up private IP addresses")
        
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,  # Check reports from last 90 days
            "verbose": ""       # Include verbose report data
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.API_URL, 
                    headers=headers, 
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 401:
                        return self._error_result(ip, "Invalid API key")
                    elif response.status == 429:
                        return self._error_result(ip, "Rate limit exceeded")
                    elif response.status != 200:
                        return self._error_result(ip, f"API error: HTTP {response.status}")
                    
                    data = await response.json()
        
        except aiohttp.ClientError as e:
            return self._error_result(ip, f"Connection error: {str(e)}")
        except Exception as e:
            return self._error_result(ip, f"Unexpected error: {str(e)}")
        
        # Parse response
        result_data = data.get("data", {})
        
        # Extract categories from reports
        categories = []
        if "reports" in result_data:
            seen_categories = set()
            for report in result_data.get("reports", []):
                for cat_id in report.get("categories", []):
                    if cat_id not in seen_categories:
                        seen_categories.add(cat_id)
                        categories.append(self.CATEGORY_MAP.get(cat_id, f"category_{cat_id}"))
        
        # Calculate maliciousness based on abuse confidence
        abuse_confidence = result_data.get("abuseConfidencePercentage", 0)
        is_malicious = abuse_confidence >= 25  # 25%+ considered malicious
        
        return ProviderResult(
            provider=self.name,
            ip=ip,
            success=True,
            is_malicious=is_malicious,
            confidence=abuse_confidence / 100.0,  # Normalize to 0-1
            risk_score=abuse_confidence,
            categories=categories,
            country=result_data.get("countryCode"),
            isp=result_data.get("isp"),
            org=result_data.get("domain"),
            report_count=result_data.get("totalReports", 0),
            last_seen=result_data.get("lastReportedAt"),
            tags=[
                f"confidence:{abuse_confidence}%",
                f"reports:{result_data.get('totalReports', 0)}",
            ] + (["is_whitelisted"] if result_data.get("isWhitelisted") else []),
            raw=result_data
        )
