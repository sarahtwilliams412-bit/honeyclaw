#!/usr/bin/env python3
"""
Enrichment Engine - Async threat intelligence enrichment pipeline.
Coordinates multiple providers with caching and rate limiting.
"""

import asyncio
import json
import os
import yaml
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Set

from .cache import EnrichmentCache
from .providers import (
    BaseProvider,
    ProviderResult,
    AbuseIPDBProvider,
    GreyNoiseProvider,
    ShodanProvider,
    VirusTotalProvider,
    PROVIDERS,
)


class EnrichmentEngine:
    """
    Async threat intelligence enrichment engine.
    Queries multiple providers in parallel with caching.
    """
    
    DEFAULT_PROVIDERS = ["abuseipdb", "greynoise"]  # Free tier defaults
    
    def __init__(
        self,
        providers: Optional[List[str]] = None,
        cache_ttl: int = 3600,
        cache_dir: Optional[str] = None,
        config_path: Optional[str] = None,
    ):
        """
        Initialize the enrichment engine.
        
        Args:
            providers: List of provider names to use
            cache_ttl: Cache time-to-live in seconds (default: 1 hour)
            cache_dir: Directory for persistent cache
            config_path: Path to YAML config file
        """
        # Load config if provided
        config = self._load_config(config_path)
        
        # Merge config with explicit args (explicit args take precedence)
        if providers is None:
            providers = config.get("providers", self.DEFAULT_PROVIDERS)
        cache_ttl = config.get("cache_ttl", cache_ttl)
        cache_dir = cache_dir or config.get("cache_dir")
        
        self.enabled = config.get("enabled", True)
        
        # Initialize cache
        self.cache = EnrichmentCache(ttl=cache_ttl, cache_dir=cache_dir)
        
        # Initialize providers
        self._providers: Dict[str, BaseProvider] = {}
        self._enabled_providers: Set[str] = set()
        
        for name in providers:
            name = name.lower()
            if name in PROVIDERS:
                provider = PROVIDERS[name]()
                self._providers[name] = provider
                if provider.enabled:
                    self._enabled_providers.add(name)
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        if config_path is None:
            # Try default locations
            default_paths = [
                Path("honeyclaw.yaml"),
                Path("config/honeyclaw.yaml"),
                Path.home() / ".honeyclaw" / "config.yaml",
            ]
            for path in default_paths:
                if path.exists():
                    config_path = str(path)
                    break
        
        if config_path and Path(config_path).exists():
            try:
                with open(config_path) as f:
                    full_config = yaml.safe_load(f) or {}
                return full_config.get("enrichment", {})
            except Exception:
                pass
        
        return {}
    
    @property
    def provider_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all configured providers"""
        return {
            name: {
                "enabled": provider.enabled,
                "requires_api_key": provider.requires_api_key,
                "free_tier": provider.free_tier,
                "rate_limit_per_day": provider.rate_limit_per_day,
            }
            for name, provider in self._providers.items()
        }
    
    async def enrich(
        self,
        ip: str,
        providers: Optional[List[str]] = None,
        skip_cache: bool = False,
        timeout: float = 30.0,
    ) -> Dict[str, Any]:
        """
        Enrich an IP address with threat intelligence.
        
        Args:
            ip: IPv4 address to enrich
            providers: Specific providers to query (None for all enabled)
            skip_cache: If True, bypass cache and force fresh lookups
            timeout: Total timeout for all provider queries
            
        Returns:
            Dict with enrichment results from all providers
        """
        if not self.enabled:
            return {
                "ip": ip,
                "enriched": False,
                "reason": "Enrichment disabled",
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        
        # Determine which providers to use
        if providers:
            query_providers = [
                p.lower() for p in providers
                if p.lower() in self._enabled_providers
            ]
        else:
            query_providers = list(self._enabled_providers)
        
        if not query_providers:
            return {
                "ip": ip,
                "enriched": False,
                "reason": "No enabled providers available",
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        
        results = {}
        tasks = []
        providers_to_query = []
        
        # Check cache first
        for name in query_providers:
            if not skip_cache:
                cached = self.cache.get(ip, name)
                if cached:
                    results[name] = cached
                    continue
            providers_to_query.append(name)
        
        # Query providers not in cache
        if providers_to_query:
            for name in providers_to_query:
                provider = self._providers[name]
                tasks.append(self._query_provider(provider, ip))
            
            # Execute queries in parallel with timeout
            try:
                query_results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=timeout
                )
                
                for name, result in zip(providers_to_query, query_results):
                    if isinstance(result, Exception):
                        results[name] = {
                            "provider": name,
                            "ip": ip,
                            "success": False,
                            "error": str(result),
                        }
                    elif isinstance(result, ProviderResult):
                        result_dict = result.to_dict()
                        results[name] = result_dict
                        
                        # Cache successful results
                        if result.success:
                            self.cache.set(ip, name, result_dict)
                    else:
                        results[name] = result
            
            except asyncio.TimeoutError:
                for name in providers_to_query:
                    if name not in results:
                        results[name] = {
                            "provider": name,
                            "ip": ip,
                            "success": False,
                            "error": "Timeout",
                        }
        
        # Aggregate results
        return self._aggregate_results(ip, results)
    
    async def _query_provider(
        self, 
        provider: BaseProvider, 
        ip: str
    ) -> ProviderResult:
        """Query a single provider"""
        return await provider.lookup(ip)
    
    def _aggregate_results(
        self, 
        ip: str, 
        results: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Aggregate results from multiple providers into a summary.
        """
        # Count verdicts
        malicious_count = 0
        benign_count = 0
        unknown_count = 0
        total_confidence = 0.0
        confidence_count = 0
        max_risk_score = 0
        
        all_categories = set()
        all_tags = set()
        errors = []
        
        for name, result in results.items():
            if not result.get("success"):
                errors.append(f"{name}: {result.get('error', 'Unknown error')}")
                continue
            
            # Tally verdicts
            is_malicious = result.get("is_malicious")
            if is_malicious is True:
                malicious_count += 1
            elif is_malicious is False:
                benign_count += 1
            else:
                unknown_count += 1
            
            # Track confidence
            conf = result.get("confidence")
            if conf is not None:
                total_confidence += conf
                confidence_count += 1
            
            # Track risk score
            risk = result.get("risk_score", 0)
            max_risk_score = max(max_risk_score, risk or 0)
            
            # Collect categories and tags
            all_categories.update(result.get("categories", []))
            all_tags.update(result.get("tags", []))
        
        # Calculate overall verdict
        total_verdicts = malicious_count + benign_count + unknown_count
        if total_verdicts == 0:
            overall_verdict = "error"
            overall_confidence = 0.0
        elif malicious_count > benign_count:
            overall_verdict = "malicious"
            overall_confidence = malicious_count / total_verdicts
        elif benign_count > malicious_count:
            overall_verdict = "benign"
            overall_confidence = benign_count / total_verdicts
        else:
            overall_verdict = "unknown"
            overall_confidence = 0.5
        
        # Average confidence across providers
        avg_confidence = (
            total_confidence / confidence_count 
            if confidence_count > 0 
            else 0.0
        )
        
        return {
            "ip": ip,
            "enriched": True,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "summary": {
                "verdict": overall_verdict,
                "confidence": round(avg_confidence, 2),
                "risk_score": max_risk_score,
                "malicious_verdicts": malicious_count,
                "benign_verdicts": benign_count,
                "unknown_verdicts": unknown_count,
            },
            "categories": sorted(all_categories),
            "tags": sorted(all_tags),
            "providers": results,
            "errors": errors if errors else None,
        }
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return self.cache.get_stats()
    
    def clear_cache(self, ip: Optional[str] = None) -> None:
        """Clear cache (optionally for specific IP)"""
        if ip:
            self.cache.invalidate(ip)
        else:
            self.cache.clear()


# Module-level singleton and convenience functions
_default_engine: Optional[EnrichmentEngine] = None


def get_engine(**kwargs) -> EnrichmentEngine:
    """Get or create the default enrichment engine"""
    global _default_engine
    if _default_engine is None or kwargs:
        _default_engine = EnrichmentEngine(**kwargs)
    return _default_engine


async def enrich_ip(ip: str, **kwargs) -> Dict[str, Any]:
    """Convenience function to enrich a single IP"""
    engine = get_engine()
    return await engine.enrich(ip, **kwargs)


def enrich_ip_sync(ip: str, **kwargs) -> Dict[str, Any]:
    """Synchronous wrapper for enrich_ip"""
    return asyncio.run(enrich_ip(ip, **kwargs))
