#!/usr/bin/env python3
"""
Simple SSH Honeypot - Logs all connection attempts
Version: 1.1.1 (security hardened)
"""
import asyncio
import asyncssh
import hashlib
import json
import os
import signal
import sys
import traceback
from datetime import datetime
from pathlib import Path

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
# Configurable salt for password hashing - MUST be set in production
HASH_SALT = os.environ.get("HONEYCLAW_HASH_SALT", "")

def hash_credential(value: str) -> str:
    """Hash credential with salt for safe logging.
    
    Uses SHA256 with configurable salt. Returns first 16 chars of hex digest.
    Salt should be set via HONEYCLAW_HASH_SALT env var in production.
    """
    if not HASH_SALT:
        print("[WARN] HONEYCLAW_HASH_SALT not set - using unsalted hash", flush=True, file=sys.stderr)
    salted = f"{HASH_SALT}{value}".encode('utf-8')
    return hashlib.sha256(salted).hexdigest()[:16]


class HoneypotServer(asyncssh.SSHServer):
    def __init__(self):
        self.client_ip = None
        print(f"[DEBUG] HoneypotServer instance created", flush=True)
        
    def connection_made(self, conn):
        try:
            peername = conn.get_extra_info('peername')
            self.client_ip = peername[0] if peername else 'unknown'
            print(f"[DEBUG] Connection from {self.client_ip}", flush=True)
            log_event('connection', {'ip': self.client_ip})
        except Exception as e:
            print(f"[ERROR] connection_made: {e}", flush=True)
            traceback.print_exc()

    def connection_lost(self, exc):
        print(f"[DEBUG] Connection lost from {self.client_ip}: {exc}", flush=True)
        log_event('disconnect', {'ip': self.client_ip, 'error': str(exc) if exc else None})

    def begin_auth(self, username):
        print(f"[DEBUG] Auth attempt for user: {username}", flush=True)
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        # Hash password with salt for safe logging
        pw_hash = hash_credential(password) if password else "empty"
        print(f"[DEBUG] Password attempt: {username}:***", flush=True)
        log_event('login_attempt', {
            'ip': self.client_ip,
            'username': username,
            'password_hash': pw_hash,
            'password_length': len(password) if password else 0
        })
        return False

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        print(f"[DEBUG] Pubkey attempt: {username}", flush=True)
        log_event('pubkey_attempt', {
            'ip': self.client_ip,
            'username': username,
            'key_type': key.get_algorithm(),
            'fingerprint': key.get_fingerprint()
        })
        return False


def log_event(event_type, data):
    """Log event to file and stdout"""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'event': event_type,
        **data
    }
    line = json.dumps(event)
    print(line, flush=True)
    
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, 'a') as f:
            f.write(line + '\n')
    except Exception as e:
        print(f"Log write error: {e}", file=sys.stderr)


async def start_server():
    """Start the SSH honeypot server"""
    try:
        # Generate host key on startup
        print("[DEBUG] Generating RSA host key...", flush=True)
        key = asyncssh.generate_private_key('ssh-rsa', 2048)
        print("[DEBUG] Host key generated", flush=True)
        
        log_event('startup', {'port': PORT, 'version': '1.1.1'})
        
        print(f"[DEBUG] Starting SSH server on 0.0.0.0:{PORT}...", flush=True)
        server = await asyncssh.create_server(
            HoneypotServer, '0.0.0.0', PORT,
            server_host_keys=[key],
            process_factory=None
        )
        print(f"[DEBUG] Server started: {server}", flush=True)
        print(f"SSH Honeypot running on port {PORT}", flush=True)
        
        # Wait for shutdown signal
        await shutdown_event.wait()
        print("[INFO] Shutting down gracefully...", flush=True)
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
