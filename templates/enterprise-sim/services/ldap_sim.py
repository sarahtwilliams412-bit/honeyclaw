#!/usr/bin/env python3
"""
Honey Claw - LDAP Simulator
Simulates Active Directory LDAP for enumeration detection

Rate limit configuration via environment variables:
  RATELIMIT_ENABLED          - Enable rate limiting (default: true)
  RATELIMIT_CONN_PER_MIN     - Max connections per IP per minute (default: 10)
  RATELIMIT_AUTH_PER_HOUR    - Max auth attempts per IP per hour (default: 100)
  RATELIMIT_CLEANUP_INTERVAL - Cleanup interval in seconds (default: 60)
"""

import socket
import json
import datetime
import os
import struct
import time
import threading
from collections import defaultdict

HOST = '0.0.0.0'
PORT = 389
LOG_FILE = '/var/log/honeypot/ldap.json'
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
        
        if self.enabled:
            print(f"[INFO] Rate limiting enabled: {self.conn_per_min}/min connections, {self.auth_per_hour}/hr auth")
    
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

rate_limiter = RateLimiter()

def log_event(event):
    """Log event to JSON file"""
    event['timestamp'] = datetime.datetime.utcnow().isoformat() + 'Z'
    event['honeypot_id'] = HONEYPOT_ID
    event['service'] = 'ldap'
    
    line = json.dumps(event)
    print(line, flush=True)
    
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(line + '\n')
    except Exception as e:
        print(f"[ERROR] Log write failed: {e}")

def parse_ldap_message(data):
    """Basic LDAP message parsing"""
    # LDAP uses BER encoding - this is a simplified parser
    try:
        if len(data) < 2:
            return None
            
        # Check for LDAP sequence tag (0x30)
        if data[0] != 0x30:
            return None
            
        # Try to identify message type
        # BindRequest = 0x60, SearchRequest = 0x63, etc.
        msg_type = None
        for i, byte in enumerate(data):
            if byte == 0x60:
                msg_type = 'bind_request'
                break
            elif byte == 0x63:
                msg_type = 'search_request'
                break
            elif byte == 0x42:
                msg_type = 'unbind_request'
                break
                
        return {'type': msg_type, 'raw_len': len(data)}
        
    except Exception as e:
        return {'error': str(e)}

def handle_connection(conn, addr):
    """Handle incoming LDAP connection"""
    ip = addr[0]
    
    # Check connection rate limit
    allowed, reason = rate_limiter.check_connection(ip)
    if not allowed:
        rate_limiter.log_blocked('connection', ip, 
            len(rate_limiter._conn_counts.get(ip, [])),
            rate_limiter.conn_per_min, '1m')
        print(f"[RATELIMIT] Connection blocked from {ip}: {reason}")
        conn.close()
        return
    
    log_event({
        'event_type': 'connection',
        'source_ip': ip,
        'source_port': addr[1]
    })
    
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
                
            parsed = parse_ldap_message(data)
            
            # Check auth rate limit for bind requests
            if parsed and parsed.get('type') == 'bind_request':
                auth_allowed, auth_reason = rate_limiter.check_auth(ip)
                if not auth_allowed:
                    rate_limiter.log_blocked('auth', ip,
                        len(rate_limiter._auth_counts.get(ip, [])),
                        rate_limiter.auth_per_hour, '1h')
                    print(f"[RATELIMIT] Auth blocked from {ip}: {auth_reason}")
                    conn.close()
                    return
            
            log_event({
                'event_type': 'ldap_message',
                'source_ip': ip,
                'parsed': parsed,
                'data_hex': data[:128].hex()
            })
            
            # Send a generic LDAP error response
            # This is a minimal "operationsError" response
            error_response = bytes([
                0x30, 0x0c,  # SEQUENCE
                0x02, 0x01, 0x01,  # messageID = 1
                0x61, 0x07,  # BindResponse
                0x0a, 0x01, 0x01,  # resultCode = operationsError
                0x04, 0x00,  # matchedDN = ""
                0x04, 0x00   # diagnosticMessage = ""
            ])
            conn.send(error_response)
            
    except Exception as e:
        log_event({
            'event_type': 'error',
            'source_ip': ip,
            'error': str(e)
        })
    finally:
        conn.close()

def main():
    """Main LDAP simulator loop"""
    print(f"[LDAP Simulator] Starting on {HOST}:{PORT}")
    print(f"[LDAP Simulator] Rate limiting: {'enabled' if rate_limiter.enabled else 'disabled'}")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        
        while True:
            conn, addr = s.accept()
            print(f"[LDAP] Connection from {addr[0]}:{addr[1]}")
            # Handle in thread to allow concurrent connections
            threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()

if __name__ == '__main__':
    main()
