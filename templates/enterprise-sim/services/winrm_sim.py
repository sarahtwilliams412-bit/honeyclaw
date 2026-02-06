#!/usr/bin/env python3
"""
Honey Claw - WinRM Simulator
Simulates Windows Remote Management for credential capture

Rate limit configuration via environment variables:
  RATELIMIT_ENABLED          - Enable rate limiting (default: true)
  RATELIMIT_CONN_PER_MIN     - Max connections per IP per minute (default: 10)
  RATELIMIT_AUTH_PER_HOUR    - Max auth attempts per IP per hour (default: 100)
  RATELIMIT_CLEANUP_INTERVAL - Cleanup interval in seconds (default: 60)
"""

from flask import Flask, request, Response, g
import json
import datetime
import os
import time
import threading
from collections import defaultdict

app = Flask(__name__)

PORT = 5985
LOG_FILE = '/var/log/honeypot/winrm.json'
HONEYPOT_ID = os.environ.get('HONEYPOT_ID', 'enterprise-sim')

# =============================================================================
# Rate Limiting
# =============================================================================
class RateLimiter:
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
    
    def check_connection(self, ip):
        if not self.enabled:
            return True, None
        now = time.time()
        with self._lock:
            self._conn_counts[ip] = [t for t in self._conn_counts[ip] if t > now - 60]
            if len(self._conn_counts[ip]) >= self.conn_per_min:
                self._blocked_conns += 1
                return False, f"Connection rate limit exceeded ({self.conn_per_min}/min)"
            self._conn_counts[ip].append(now)
        return True, None
    
    def check_auth(self, ip):
        if not self.enabled:
            return True, None
        now = time.time()
        with self._lock:
            self._auth_counts[ip] = [t for t in self._auth_counts[ip] if t > now - 3600]
            if len(self._auth_counts[ip]) >= self.auth_per_hour:
                self._blocked_auths += 1
                return False, f"Auth rate limit exceeded ({self.auth_per_hour}/hour)"
            self._auth_counts[ip].append(now)
        return True, None
    
    def log_blocked(self, event_type, ip, count, limit, window):
        log_event({
            'event_type': f'rate_limit_{event_type}',
            'source_ip': ip,
            'count': count,
            'limit': limit,
            'window': window,
            'total_blocked': self._blocked_conns if event_type == 'connection' else self._blocked_auths
        })
    
    def _cleanup_loop(self):
        while not self._stop_cleanup.wait(self.cleanup_interval):
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
    
    def get_stats(self):
        with self._lock:
            return {
                'enabled': self.enabled,
                'config': {
                    'conn_per_min': self.conn_per_min,
                    'auth_per_hour': self.auth_per_hour
                },
                'blocked': {
                    'connections': self._blocked_conns,
                    'auths': self._blocked_auths
                }
            }

rate_limiter = RateLimiter()

def log_event(event):
    """Log event to JSON file"""
    event['timestamp'] = datetime.datetime.utcnow().isoformat() + 'Z'
    event['honeypot_id'] = HONEYPOT_ID
    event['service'] = 'winrm'
    
    line = json.dumps(event)
    print(line, flush=True)
    
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(line + '\n')
    except Exception as e:
        print(f"[ERROR] Log write failed: {e}")

@app.before_request
def check_rate_limit():
    """Check rate limits before processing any request"""
    ip = request.remote_addr
    
    # Check connection rate limit
    allowed, reason = rate_limiter.check_connection(ip)
    if not allowed:
        rate_limiter.log_blocked('connection', ip,
            len(rate_limiter._conn_counts.get(ip, [])),
            rate_limiter.conn_per_min, '1m')
        print(f"[RATELIMIT] Request blocked from {ip}: {reason}")
        return Response(
            '<?xml version="1.0" encoding="UTF-8"?><error>Too Many Requests</error>',
            status=429,
            mimetype='application/xml',
            headers={'Retry-After': '60'}
        )
    
    # Store IP for later use
    g.client_ip = ip

@app.before_request
def log_request():
    """Log all incoming requests"""
    if hasattr(g, 'client_ip'):
        log_event({
            'event_type': 'request',
            'source_ip': g.client_ip,
            'method': request.method,
            'path': request.path,
            'headers': dict(request.headers),
            'body': request.get_data(as_text=True)[:1024]
        })

@app.route('/wsman', methods=['POST'])
def wsman():
    """Handle WinRM SOAP requests"""
    ip = getattr(g, 'client_ip', request.remote_addr)
    
    # Check for NTLM/Kerberos auth headers
    auth_header = request.headers.get('Authorization', '')
    
    if auth_header:
        # Check auth rate limit
        auth_allowed, auth_reason = rate_limiter.check_auth(ip)
        if not auth_allowed:
            rate_limiter.log_blocked('auth', ip,
                len(rate_limiter._auth_counts.get(ip, [])),
                rate_limiter.auth_per_hour, '1h')
            print(f"[RATELIMIT] Auth blocked from {ip}: {auth_reason}")
            return Response(
                '<?xml version="1.0" encoding="UTF-8"?><error>Too Many Requests</error>',
                status=429,
                mimetype='application/xml',
                headers={'Retry-After': '3600'}
            )
        
        log_event({
            'event_type': 'auth_attempt',
            'source_ip': ip,
            'auth_header': auth_header[:256]
        })
    
    # Return 401 to prompt for credentials
    response = Response(
        '<?xml version="1.0" encoding="UTF-8"?><error>Unauthorized</error>',
        status=401,
        mimetype='application/xml'
    )
    response.headers['WWW-Authenticate'] = 'Negotiate'
    return response

@app.route('/internal/ratelimit-stats')
def ratelimit_stats():
    """Return rate limiter statistics"""
    return Response(
        json.dumps(rate_limiter.get_stats()),
        mimetype='application/json'
    )

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    """Catch all other requests"""
    return Response(status=404)

if __name__ == '__main__':
    print(f"[WinRM Simulator] Starting on port {PORT}")
    print(f"[WinRM Simulator] Rate limiting: {'enabled' if rate_limiter.enabled else 'disabled'}")
    if rate_limiter.enabled:
        print(f"[WinRM Simulator] Limits: {rate_limiter.conn_per_min}/min connections, {rate_limiter.auth_per_hour}/hr auth")
    app.run(host='0.0.0.0', port=PORT)
