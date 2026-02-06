#!/usr/bin/env python3
"""
Enrichment Cache - Avoid rate limits by caching threat intel results.
Supports in-memory and file-based persistence.
"""

import json
import os
import time
import threading
from pathlib import Path
from typing import Optional, Dict, Any


class EnrichmentCache:
    """
    Thread-safe cache for threat intelligence results.
    Supports both in-memory and file-backed persistence.
    """
    
    def __init__(self, 
                 ttl: int = 3600,
                 cache_dir: Optional[str] = None,
                 max_entries: int = 10000):
        """
        Initialize the enrichment cache.
        
        Args:
            ttl: Time-to-live for cache entries in seconds (default: 1 hour)
            cache_dir: Directory for persistent cache (None for memory-only)
            max_entries: Maximum number of cached entries
        """
        self.ttl = ttl
        self.max_entries = max_entries
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        
        self.cache_dir = Path(cache_dir) if cache_dir else None
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self._load_persistent_cache()
    
    def _cache_key(self, ip: str, provider: str) -> str:
        """Generate cache key from IP and provider"""
        return f"{provider}:{ip}"
    
    def _is_expired(self, entry: Dict[str, Any]) -> bool:
        """Check if a cache entry has expired"""
        return time.time() > entry.get('expires_at', 0)
    
    def get(self, ip: str, provider: str) -> Optional[Dict[str, Any]]:
        """
        Get cached enrichment data for an IP/provider combination.
        
        Args:
            ip: IP address
            provider: Provider name (e.g., 'abuseipdb')
            
        Returns:
            Cached data dict or None if not found/expired
        """
        key = self._cache_key(ip, provider)
        
        with self._lock:
            entry = self._cache.get(key)
            if entry and not self._is_expired(entry):
                entry['hits'] = entry.get('hits', 0) + 1
                return entry.get('data')
            elif entry:
                # Remove expired entry
                del self._cache[key]
        
        return None
    
    def set(self, ip: str, provider: str, data: Dict[str, Any], 
            ttl: Optional[int] = None) -> None:
        """
        Cache enrichment data for an IP/provider combination.
        
        Args:
            ip: IP address
            provider: Provider name
            data: Enrichment data to cache
            ttl: Custom TTL for this entry (uses default if None)
        """
        key = self._cache_key(ip, provider)
        cache_ttl = ttl if ttl is not None else self.ttl
        
        entry = {
            'data': data,
            'cached_at': time.time(),
            'expires_at': time.time() + cache_ttl,
            'ip': ip,
            'provider': provider,
            'hits': 0
        }
        
        with self._lock:
            # Enforce max entries with LRU-style eviction
            if len(self._cache) >= self.max_entries and key not in self._cache:
                self._evict_oldest()
            
            self._cache[key] = entry
        
        # Persist if file-backed
        if self.cache_dir:
            self._persist_entry(key, entry)
    
    def invalidate(self, ip: str, provider: Optional[str] = None) -> int:
        """
        Invalidate cached entries for an IP.
        
        Args:
            ip: IP address to invalidate
            provider: Specific provider (None for all providers)
            
        Returns:
            Number of entries invalidated
        """
        count = 0
        with self._lock:
            if provider:
                key = self._cache_key(ip, provider)
                if key in self._cache:
                    del self._cache[key]
                    count = 1
            else:
                # Remove all providers for this IP
                keys_to_remove = [k for k in self._cache if k.endswith(f":{ip}")]
                for key in keys_to_remove:
                    del self._cache[key]
                    count += 1
        
        return count
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            total = len(self._cache)
            expired = sum(1 for e in self._cache.values() if self._is_expired(e))
            hits = sum(e.get('hits', 0) for e in self._cache.values())
            
            by_provider = {}
            for entry in self._cache.values():
                provider = entry.get('provider', 'unknown')
                by_provider[provider] = by_provider.get(provider, 0) + 1
            
            return {
                'total_entries': total,
                'expired_entries': expired,
                'active_entries': total - expired,
                'total_hits': hits,
                'by_provider': by_provider,
                'max_entries': self.max_entries,
                'ttl_seconds': self.ttl,
                'persistent': self.cache_dir is not None
            }
    
    def cleanup(self) -> int:
        """Remove expired entries. Returns number removed."""
        count = 0
        with self._lock:
            expired_keys = [k for k, v in self._cache.items() if self._is_expired(v)]
            for key in expired_keys:
                del self._cache[key]
                count += 1
                # Remove from persistent storage
                if self.cache_dir:
                    cache_file = self.cache_dir / f"{key.replace(':', '_')}.json"
                    cache_file.unlink(missing_ok=True)
        return count
    
    def clear(self) -> None:
        """Clear all cached entries"""
        with self._lock:
            self._cache.clear()
        
        if self.cache_dir:
            for f in self.cache_dir.glob("*.json"):
                f.unlink()
    
    def _evict_oldest(self) -> None:
        """Evict the oldest entry (must be called with lock held)"""
        if not self._cache:
            return
        oldest_key = min(self._cache, key=lambda k: self._cache[k].get('cached_at', 0))
        del self._cache[oldest_key]
    
    def _persist_entry(self, key: str, entry: Dict[str, Any]) -> None:
        """Persist a single cache entry to disk"""
        if not self.cache_dir:
            return
        try:
            cache_file = self.cache_dir / f"{key.replace(':', '_')}.json"
            with open(cache_file, 'w') as f:
                json.dump(entry, f)
        except Exception:
            pass  # Silently fail persistence
    
    def _load_persistent_cache(self) -> None:
        """Load cached entries from disk"""
        if not self.cache_dir:
            return
        try:
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    with open(cache_file) as f:
                        entry = json.load(f)
                    if not self._is_expired(entry):
                        key = self._cache_key(entry['ip'], entry['provider'])
                        self._cache[key] = entry
                    else:
                        cache_file.unlink()  # Remove expired
                except (json.JSONDecodeError, KeyError):
                    cache_file.unlink()  # Remove corrupted
        except Exception:
            pass  # Silently fail load
