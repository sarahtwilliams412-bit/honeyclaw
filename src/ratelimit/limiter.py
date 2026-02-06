#!/usr/bin/env python3
"""
Honey Claw - Rate Limiter for Python Services
Simple in-memory per-IP rate limiting with automatic cleanup.

Configuration via environment variables:
  RATELIMIT_CONN_PER_MIN     - Max connections per IP per minute (default: 10)
  RATELIMIT_AUTH_PER_HOUR    - Max auth attempts per IP per hour (default: 100)
  RATELIMIT_CLEANUP_INTERVAL - Cleanup interval in seconds (default: 60)
  RATELIMIT_ENABLED          - Enable rate limiting (default: true)
"""
import os
import time
import threading
import json
from datetime import datetime
from collections import defaultdict
from typing import Tuple, Optional, Callable


class RateLimiter:
    """
    In-memory per-IP rate limiter with configurable limits.
    Thread-safe for use with asyncio and threaded servers.
    """
    
    def __init__(self, 
                 conn_per_min: int = None,
                 auth_per_hour: int = None,
                 cleanup_interval: int = None,
                 log_callback: Callable = None):
        """
        Initialize rate limiter with configuration.
        
        Args:
            conn_per_min: Max connections per IP per minute (env: RATELIMIT_CONN_PER_MIN)
            auth_per_hour: Max auth attempts per IP per hour (env: RATELIMIT_AUTH_PER_HOUR)
            cleanup_interval: Seconds between cleanup runs (env: RATELIMIT_CLEANUP_INTERVAL)
            log_callback: Function to call for logging (receives dict)
        """
        self.enabled = os.environ.get('RATELIMIT_ENABLED', 'true').lower() == 'true'
        self.conn_per_min = conn_per_min or int(os.environ.get('RATELIMIT_CONN_PER_MIN', '10'))
        self.auth_per_hour = auth_per_hour or int(os.environ.get('RATELIMIT_AUTH_PER_HOUR', '100'))
        self.cleanup_interval = cleanup_interval or int(os.environ.get('RATELIMIT_CLEANUP_INTERVAL', '60'))
        self.log_callback = log_callback or self._default_log
        
        # Counters: {ip: [(timestamp, count), ...]}
        self._conn_counts = defaultdict(list)  # connection timestamps
        self._auth_counts = defaultdict(list)  # auth attempt timestamps
        self._lock = threading.Lock()
        
        # Stats
        self._blocked_conns = 0
        self._blocked_auths = 0
        
        # Start cleanup thread
        self._stop_cleanup = threading.Event()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
    
    def _default_log(self, event: dict):
        """Default logging: print JSON to stdout"""
        event['timestamp'] = datetime.utcnow().isoformat() + 'Z'
        print(json.dumps(event), flush=True)
    
    def check_connection(self, ip: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a connection from IP should be allowed.
        
        Args:
            ip: Client IP address
            
        Returns:
            (allowed, reason) - True if allowed, False with reason if blocked
        """
        if not self.enabled:
            return True, None
            
        now = time.time()
        minute_ago = now - 60
        
        with self._lock:
            # Clean old entries
            self._conn_counts[ip] = [t for t in self._conn_counts[ip] if t > minute_ago]
            
            # Check limit
            if len(self._conn_counts[ip]) >= self.conn_per_min:
                self._blocked_conns += 1
                self.log_callback({
                    'event': 'rate_limit_connection',
                    'ip': ip,
                    'count': len(self._conn_counts[ip]),
                    'limit': self.conn_per_min,
                    'window': '1m',
                    'total_blocked': self._blocked_conns
                })
                return False, f"Connection rate limit exceeded ({self.conn_per_min}/min)"
            
            # Record connection
            self._conn_counts[ip].append(now)
            
        return True, None
    
    def check_auth(self, ip: str) -> Tuple[bool, Optional[str]]:
        """
        Check if an auth attempt from IP should be allowed.
        
        Args:
            ip: Client IP address
            
        Returns:
            (allowed, reason) - True if allowed, False with reason if blocked
        """
        if not self.enabled:
            return True, None
            
        now = time.time()
        hour_ago = now - 3600
        
        with self._lock:
            # Clean old entries
            self._auth_counts[ip] = [t for t in self._auth_counts[ip] if t > hour_ago]
            
            # Check limit
            if len(self._auth_counts[ip]) >= self.auth_per_hour:
                self._blocked_auths += 1
                self.log_callback({
                    'event': 'rate_limit_auth',
                    'ip': ip,
                    'count': len(self._auth_counts[ip]),
                    'limit': self.auth_per_hour,
                    'window': '1h',
                    'total_blocked': self._blocked_auths
                })
                return False, f"Auth rate limit exceeded ({self.auth_per_hour}/hour)"
            
            # Record auth attempt
            self._auth_counts[ip].append(now)
            
        return True, None
    
    def record_auth(self, ip: str):
        """Record an auth attempt without checking limits (for post-facto logging)"""
        if not self.enabled:
            return
        with self._lock:
            self._auth_counts[ip].append(time.time())
    
    def get_stats(self) -> dict:
        """Get current rate limiter statistics"""
        with self._lock:
            return {
                'enabled': self.enabled,
                'config': {
                    'conn_per_min': self.conn_per_min,
                    'auth_per_hour': self.auth_per_hour,
                    'cleanup_interval': self.cleanup_interval
                },
                'tracked_ips': {
                    'connections': len(self._conn_counts),
                    'auths': len(self._auth_counts)
                },
                'blocked': {
                    'connections': self._blocked_conns,
                    'auths': self._blocked_auths
                }
            }
    
    def _cleanup_loop(self):
        """Periodically clean up old entries to prevent memory growth"""
        while not self._stop_cleanup.wait(self.cleanup_interval):
            self._cleanup()
    
    def _cleanup(self):
        """Remove expired entries from counters"""
        now = time.time()
        minute_ago = now - 60
        hour_ago = now - 3600
        
        with self._lock:
            # Clean connection counters
            expired_conn = []
            for ip, timestamps in self._conn_counts.items():
                self._conn_counts[ip] = [t for t in timestamps if t > minute_ago]
                if not self._conn_counts[ip]:
                    expired_conn.append(ip)
            for ip in expired_conn:
                del self._conn_counts[ip]
            
            # Clean auth counters
            expired_auth = []
            for ip, timestamps in self._auth_counts.items():
                self._auth_counts[ip] = [t for t in timestamps if t > hour_ago]
                if not self._auth_counts[ip]:
                    expired_auth.append(ip)
            for ip in expired_auth:
                del self._auth_counts[ip]
    
    def shutdown(self):
        """Stop the cleanup thread"""
        self._stop_cleanup.set()
        if self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=2)


# Global singleton for simple usage
_default_limiter: Optional[RateLimiter] = None


def get_limiter(log_callback: Callable = None) -> RateLimiter:
    """Get or create the default rate limiter singleton"""
    global _default_limiter
    if _default_limiter is None:
        _default_limiter = RateLimiter(log_callback=log_callback)
    return _default_limiter


def check_connection(ip: str, log_callback: Callable = None) -> Tuple[bool, Optional[str]]:
    """Convenience function to check connection rate limit"""
    return get_limiter(log_callback).check_connection(ip)


def check_auth(ip: str, log_callback: Callable = None) -> Tuple[bool, Optional[str]]:
    """Convenience function to check auth rate limit"""
    return get_limiter(log_callback).check_auth(ip)
