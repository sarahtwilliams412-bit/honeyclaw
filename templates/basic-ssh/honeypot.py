#!/usr/bin/env python3
"""
Simple SSH Honeypot - Logs all connection attempts
"""
import asyncio
import asyncssh
import json
import os
import sys
import traceback
from datetime import datetime
from pathlib import Path

PORT = int(os.environ.get("PORT", 8022))
LOG_FILE = Path("/var/log/honeypot/ssh.json")

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
        print(f"[DEBUG] Password attempt: {username}:{password}", flush=True)
        log_event('login_attempt', {
            'ip': self.client_ip,
            'username': username,
            'password': password
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
        
        log_event('startup', {'port': PORT, 'version': '1.0'})
        
        print(f"[DEBUG] Starting SSH server on port {PORT}...", flush=True)
        server = await asyncssh.create_server(
            HoneypotServer, '0.0.0.0', PORT,
            server_host_keys=[key],
            process_factory=None
        )
        print(f"[DEBUG] Server started: {server}", flush=True)
        print(f"SSH Honeypot running on port {PORT}", flush=True)
        
        # Run forever
        while True:
            await asyncio.sleep(3600)
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
