#!/usr/bin/env python3
"""
Simple SSH Honeypot - Logs all connection attempts
Version: 1.4.0 (real-time alerting support)

Environment variables:
  PORT                       - Listen port (default: 8022)
  LOG_PATH                   - Log file path (default: /var/log/honeypot/ssh.json)
  SSH_BANNER                 - SSH version banner (default: OpenSSH_8.9p1 Ubuntu-3ubuntu0.6)
  
Rate limit configuration:
  RATELIMIT_ENABLED          - Enable rate limiting (default: true)
  RATELIMIT_CONN_PER_MIN     - Max connections per IP per minute (default: 10)
  RATELIMIT_AUTH_PER_HOUR    - Max auth attempts per IP per hour (default: 100)
  RATELIMIT_CLEANUP_INTERVAL - Cleanup interval in seconds (default: 60)

Alert configuration:
  ALERT_WEBHOOK_URL          - Webhook URL for alerts (Slack/Discord/PagerDuty)
  ALERT_SEVERITY_THRESHOLD   - Minimum severity (DEBUG/INFO/LOW/MEDIUM/HIGH/CRITICAL)
  HONEYPOT_ID                - Honeypot identifier for alerts
"""
import asyncio
import asyncssh
import hashlib
import json
import os
import signal
import sys
import time
import threading
import traceback
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# Add parent path for common imports
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from common.validation import (
    validate_username,
    validate_password,
    validate_ip,
    validate_ssh_fingerprint,
    sanitize_for_log,
    MAX_USERNAME_LENGTH,
    MAX_PASSWORD_LENGTH,
)

# Real-time alerting (optional - fails gracefully if not configured)
try:
    from src.alerts.dispatcher import get_dispatcher, alert as send_alert
    ALERTING_ENABLED = bool(os.environ.get('ALERT_WEBHOOK_URL'))
except ImportError:
    ALERTING_ENABLED = False
    def send_alert(event, event_type):
        pass  # No-op if alerting not available

# MITRE ATT&CK enrichment (optional)
try:
    from src.analysis.mitre_mapper import enrich_event as mitre_enrich
    MITRE_ENABLED = True
except ImportError:
    MITRE_ENABLED = False
    def mitre_enrich(event):
        return event

# =============================================================================
# Rate Limiting
# =============================================================================
class RateLimiter:
    """In-memory per-IP rate limiter with configurable limits."""
    
    def __init__(self):
        self.enabled = os.environ.get('RATELIMIT_ENABLED', 'true').lower() == 'true'
        self.conn_per_min = int(os.environ.get('RATELIMIT_CONN_PER_MIN', '10'))
        self.auth_per_hour = int(os.environ.get('RATELIMIT_AUTH_PER_HOUR', '100'))
        self.cleanup_interval = int(os.environ.get('RATELIMIT_CLEANUP_INTERVAL', '60'))
        
        self._conn_counts = defaultdict(list)
        self._auth_counts = defaultdict(list)
        self._lock = threading.Lock()
        self._blocked_conns = 0
        self._blocked_auths = 0
        
        self._stop_cleanup = threading.Event()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
        
        if self.enabled:
            print(f"[INFO] Rate limiting enabled: {self.conn_per_min}/min connections, {self.auth_per_hour}/hr auth", flush=True)
    
    def check_connection(self, ip: str):
        if not self.enabled:
            return True, None
        now = time.time()
        minute_ago = now - 60
        with self._lock:
            self._conn_counts[ip] = [t for t in self._conn_counts[ip] if t > minute_ago]
            if len(self._conn_counts[ip]) >= self.conn_per_min:
                self._blocked_conns += 1
                return False, f"Connection rate limit exceeded ({self.conn_per_min}/min)"
            self._conn_counts[ip].append(now)
        return True, None
    
    def check_auth(self, ip: str):
        if not self.enabled:
            return True, None
        now = time.time()
        hour_ago = now - 3600
        with self._lock:
            self._auth_counts[ip] = [t for t in self._auth_counts[ip] if t > hour_ago]
            if len(self._auth_counts[ip]) >= self.auth_per_hour:
                self._blocked_auths += 1
                return False, f"Auth rate limit exceeded ({self.auth_per_hour}/hour)"
            self._auth_counts[ip].append(now)
        return True, None
    
    def log_blocked(self, event_type: str, ip: str, count: int, limit: int, window: str):
        """Log a rate limit block event"""
        total = self._blocked_conns if event_type == 'connection' else self._blocked_auths
        log_event(f'rate_limit_{event_type}', {
            'ip': ip, 'count': count, 'limit': limit, 
            'window': window, 'total_blocked': total
        })
    
    def _cleanup_loop(self):
        while not self._stop_cleanup.wait(self.cleanup_interval):
            self._cleanup()
    
    def _cleanup(self):
        now = time.time()
        with self._lock:
            for ip in list(self._conn_counts.keys()):
                self._conn_counts[ip] = [t for t in self._conn_counts[ip] if t > now - 60]
                if not self._conn_counts[ip]:
                    del self._conn_counts[ip]
            for ip in list(self._auth_counts.keys()):
                self._auth_counts[ip] = [t for t in self._auth_counts[ip] if t > now - 3600]
                if not self._auth_counts[ip]:
                    del self._auth_counts[ip]
    
    def shutdown(self):
        self._stop_cleanup.set()

rate_limiter = RateLimiter()

# Graceful shutdown handling
shutdown_event = asyncio.Event()

def handle_shutdown(signum, frame):
    print(f"[INFO] Received signal {signum}, initiating shutdown...", flush=True)
    shutdown_event.set()

signal.signal(signal.SIGTERM, handle_shutdown)
signal.signal(signal.SIGINT, handle_shutdown)

def get_port():
    """Get port with validation"""
    try:
        port = int(os.environ.get("PORT", 8022))
        if not 1 <= port <= 65535:
            raise ValueError(f"Port {port} out of range")
        return port
    except ValueError as e:
        print(f"[WARN] Invalid PORT: {e}, using default 8022", flush=True)
        return 8022

PORT = get_port()
LOG_FILE = Path(os.environ.get("LOG_PATH", "/var/log/honeypot/ssh.json"))

# SSH banner - hide AsyncSSH identity
# Default looks like a common Ubuntu OpenSSH server
SSH_BANNER = os.environ.get("SSH_BANNER", "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")

def hash_password(password: str) -> str:
    """Hash password for safe logging (first 16 chars of SHA256)"""
    # Limit password length before hashing to prevent DoS
    safe_password = password[:MAX_PASSWORD_LENGTH] if password else ""
    return hashlib.sha256(safe_password.encode()).hexdigest()[:16]


class HoneypotServer(asyncssh.SSHServer):
    def __init__(self):
        self.client_ip = None
        self.client_ip_valid = False
        self._rate_limited = False
        print(f"[DEBUG] HoneypotServer instance created", flush=True)
        
    def connection_made(self, conn):
        try:
            peername = conn.get_extra_info('peername')
            raw_ip = peername[0] if peername else 'unknown'
            
            # Validate IP address
            self.client_ip, self.client_ip_valid = validate_ip(raw_ip)
            
            # Check connection rate limit
            allowed, reason = rate_limiter.check_connection(self.client_ip)
            if not allowed:
                self._rate_limited = True
                rate_limiter.log_blocked('connection', self.client_ip,
                    len(rate_limiter._conn_counts.get(self.client_ip, [])),
                    rate_limiter.conn_per_min, '1m')
                print(f"[RATELIMIT] Connection blocked from {self.client_ip}: {reason}", flush=True)
                conn.close()
                return
            
            print(f"[DEBUG] Connection from {self.client_ip}", flush=True)
            log_event('connection', {
                'ip': self.client_ip,
                'ip_valid': self.client_ip_valid
            })
        except Exception as e:
            print(f"[ERROR] connection_made: {e}", flush=True)
            traceback.print_exc()

    def connection_lost(self, exc):
        print(f"[DEBUG] Connection lost from {self.client_ip}: {exc}", flush=True)
        # Sanitize exception message
        error_msg = sanitize_for_log(str(exc), max_length=256) if exc else None
        log_event('disconnect', {'ip': self.client_ip, 'error': error_msg})

    def begin_auth(self, username):
        # Validate username immediately
        safe_username, is_valid = validate_username(username)
        print(f"[DEBUG] Auth attempt for user: {safe_username} (valid={is_valid})", flush=True)
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        # Check auth rate limit
        allowed, reason = rate_limiter.check_auth(self.client_ip)
        if not allowed:
            rate_limiter.log_blocked('auth', self.client_ip,
                len(rate_limiter._auth_counts.get(self.client_ip, [])),
                rate_limiter.auth_per_hour, '1h')
            print(f"[RATELIMIT] Auth blocked from {self.client_ip}: {reason}", flush=True)
            return False
        
        # Validate and sanitize username
        safe_username, username_valid = validate_username(username)
        
        # Validate password length (don't log content)
        pw_length, pw_valid = validate_password(password)
        
        # Hash password for safe logging
        pw_hash = hash_password(password) if password else "empty"
        
        print(f"[DEBUG] Password attempt: {safe_username}:***", flush=True)
        log_event('login_attempt', {
            'ip': self.client_ip,
            'username': safe_username,
            'username_valid': username_valid,
            'password_hash': pw_hash,
            'password_length': pw_length,
            'password_valid': pw_valid,
            'suspicious': not username_valid or not pw_valid
        })
        return False

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        # Check auth rate limit
        allowed, reason = rate_limiter.check_auth(self.client_ip)
        if not allowed:
            rate_limiter.log_blocked('auth', self.client_ip,
                len(rate_limiter._auth_counts.get(self.client_ip, [])),
                rate_limiter.auth_per_hour, '1h')
            print(f"[RATELIMIT] Auth blocked from {self.client_ip}: {reason}", flush=True)
            return False
        
        # Validate username
        safe_username, username_valid = validate_username(username)
        
        # Validate key algorithm and fingerprint
        try:
            key_type = sanitize_for_log(key.get_algorithm(), max_length=64)
            fingerprint = validate_ssh_fingerprint(key.get_fingerprint())
        except Exception as e:
            key_type = "<error>"
            fingerprint = "<error>"
        
        print(f"[DEBUG] Pubkey attempt: {safe_username}", flush=True)
        log_event('pubkey_attempt', {
            'ip': self.client_ip,
            'username': safe_username,
            'username_valid': username_valid,
            'key_type': key_type,
            'fingerprint': fingerprint
        })
        return False


def log_event(event_type, data):
    """Log event to file, stdout, and alert pipeline"""
    # Sanitize event type
    safe_event_type = sanitize_for_log(event_type, max_length=64)

    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'event': safe_event_type,
        **data
    }

    # Enrich with MITRE ATT&CK mappings
    if MITRE_ENABLED:
        try:
            mitre_enrich(event)
        except Exception:
            pass  # Non-critical enrichment failure
    
    # Ensure total log line doesn't exceed limits
    line = json.dumps(event)
    if len(line) > 16384:  # MAX_LOG_LINE_LENGTH
        event['_truncated'] = True
        event['_original_length'] = len(line)
        line = json.dumps(event)[:16384]
    
    print(line, flush=True)
    
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, 'a') as f:
            f.write(line + '\n')
    except Exception as e:
        print(f"Log write error: {e}", file=sys.stderr)
    
    # Send to real-time alert pipeline
    if ALERTING_ENABLED:
        try:
            send_alert(event, safe_event_type)
        except Exception as e:
            print(f"[ALERT] Error: {e}", file=sys.stderr)


async def start_server():
    """Start the SSH honeypot server"""
    try:
        # Generate host key on startup
        print("[DEBUG] Generating RSA host key...", flush=True)
        key = asyncssh.generate_private_key('ssh-rsa', 2048)
        print("[DEBUG] Host key generated", flush=True)
        
        log_event('startup', {
            'port': PORT, 
            'version': '1.4.0',
            'rate_limiting': rate_limiter.enabled,
            'conn_limit': f'{rate_limiter.conn_per_min}/min',
            'auth_limit': f'{rate_limiter.auth_per_hour}/hr',
            'ssh_banner': SSH_BANNER,
            'alerting_enabled': ALERTING_ENABLED,
        })
        
        if ALERTING_ENABLED:
            print(f"[INFO] Real-time alerting enabled", flush=True)
        
        print(f"[DEBUG] Starting SSH server on 0.0.0.0:{PORT}...", flush=True)
        print(f"[DEBUG] SSH banner: {SSH_BANNER}", flush=True)
        server = await asyncssh.create_server(
            HoneypotServer, '0.0.0.0', PORT,
            server_host_keys=[key],
            server_version=SSH_BANNER,
            process_factory=None
        )
        print(f"[DEBUG] Server started: {server}", flush=True)
        print(f"SSH Honeypot running on port {PORT}", flush=True)
        
        # Wait for shutdown signal
        await shutdown_event.wait()
        print("[INFO] Shutting down gracefully...", flush=True)
        rate_limiter.shutdown()
        server.close()
        await server.wait_closed()
        log_event('shutdown', {'reason': 'signal'})
        
    except Exception as e:
        print(f"[FATAL] Server error: {e}", flush=True)
        traceback.print_exc()
        raise


if __name__ == '__main__':
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        print("Shutting down...")
    except Exception as e:
        print(f"[FATAL] {e}", flush=True)
        traceback.print_exc()
        sys.exit(1)
