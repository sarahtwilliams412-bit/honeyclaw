#!/usr/bin/env python3
"""
Simple SSH Honeypot - Logs all connection attempts
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
HOST_KEY_PATH = Path(os.environ.get("HOST_KEY_PATH", "/data/ssh_host_key"))

def hash_password(password: str) -> str:
    """Hash password for safe logging (first 16 chars of SHA256)"""
    return hashlib.sha256(password.encode()).hexdigest()[:16]

def get_or_create_host_key():
    """Get existing host key or create new one (persisted)"""
    if HOST_KEY_PATH.exists():
        print(f"[DEBUG] Loading existing host key from {HOST_KEY_PATH}", flush=True)
        return asyncssh.read_private_key(str(HOST_KEY_PATH))
    
    print(f"[DEBUG] Generating new RSA host key (4096 bit)...", flush=True)
    HOST_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    key = asyncssh.generate_private_key('ssh-rsa', 4096)
    asyncssh.write_private_key(key, str(HOST_KEY_PATH))
    print(f"[DEBUG] Host key saved to {HOST_KEY_PATH}", flush=True)
    return key

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
        # Don't log plaintext password to stdout!
        print(f"[DEBUG] Password attempt: {username}:***", flush=True)
        log_event('login_attempt', {
            'ip': self.client_ip,
            'username': username,
            'password_hash': hash_password(password),
            'password_length': len(password)
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


def handle_signal(sig):
    """Handle shutdown signals gracefully"""
    sig_name = signal.Signals(sig).name
    print(f"[INFO] Received {sig_name}, initiating graceful shutdown...", flush=True)
    log_event('shutdown', {'signal': sig_name, 'reason': 'signal'})
    shutdown_event.set()

async def start_server():
    """Start the SSH honeypot server"""
    try:
        # Set up signal handlers
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, handle_signal, sig)
        
        # Get or create persistent host key
        key = get_or_create_host_key()
        
        log_event('startup', {'port': PORT, 'version': '1.1.0'})
        
        print(f"[DEBUG] Starting SSH server on port {PORT}...", flush=True)
        server = await asyncssh.create_server(
            HoneypotServer, '0.0.0.0', PORT,
            server_host_keys=[key],
            process_factory=None
        )
        print(f"[DEBUG] Server started: {server}", flush=True)
        print(f"SSH Honeypot running on port {PORT}", flush=True)
        
        # Wait for shutdown signal
        await shutdown_event.wait()
        
        # Graceful shutdown
        print("[INFO] Closing server...", flush=True)
        server.close()
        await server.wait_closed()
        log_event('stopped', {'reason': 'graceful'})
        print("[INFO] Server stopped gracefully", flush=True)
        
    except Exception as e:
        print(f"[FATAL] Server error: {e}", flush=True)
        traceback.print_exc()
        raise


if __name__ == '__main__':
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        # Already handled by signal handler, just exit cleanly
        pass
    except Exception as e:
        print(f"[FATAL] {e}", flush=True)
        traceback.print_exc()
        sys.exit(1)
