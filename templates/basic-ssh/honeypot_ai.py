#!/usr/bin/env python3
"""
AI-Enhanced SSH Honeypot - Interactive shell with LLM deception
Version: 2.1.0

This honeypot accepts configured credentials and provides an interactive
shell session powered by AI to engage attackers and extract intelligence.
When AI is disabled, a stateful shell emulator with fake filesystem
provides realistic responses to increase attacker dwell time.

Environment variables:
  PORT                       - Listen port (default: 8022)
  LOG_PATH                   - Log file path (default: /var/log/honeypot/ssh.json)
  SSH_BANNER                 - SSH version banner (default: OpenSSH_8.9p1 Ubuntu-3ubuntu0.6)

AI Deception:
  AI_DECEPTION_ENABLED       - Enable AI responses (default: false)
  AI_DECEPTION_PERSONALITY   - Personality profile (naive_intern, paranoid_admin, etc.)
  AI_DECEPTION_MODEL         - LLM model (default: claude-sonnet-4-20250514)
  ANTHROPIC_API_KEY          - Required for AI mode

Shell Emulation:
  EMULATION_PROFILE          - OS profile for fake filesystem (default: ubuntu-22.04)

Authentication:
  HONEYPOT_ALLOW_ANY_AUTH    - Accept any credentials (default: false)
  HONEYPOT_USERS             - Comma-separated user:pass pairs (e.g., "root:admin,test:test")
  HONEYPOT_USERS_FILE        - Path to file with user:pass per line

Rate limits:
  RATELIMIT_ENABLED          - Enable rate limiting (default: true)
  RATELIMIT_CONN_PER_MIN     - Max connections per IP per minute (default: 10)
  RATELIMIT_AUTH_PER_HOUR    - Max auth attempts per IP per hour (default: 100)
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
from typing import Dict, Set, Optional, Tuple

# Add paths for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from common.validation import (
    validate_username,
    validate_password,
    validate_ip,
    validate_ssh_fingerprint,
    sanitize_for_log,
    MAX_USERNAME_LENGTH,
    MAX_PASSWORD_LENGTH,
)

# AI deception module (optional)
try:
    from ai.conversation import AIConversationHandler, DeceptiveShellSession, PERSONALITIES
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    print("[WARN] AI deception module not available", flush=True)

# Shell emulation layer
try:
    from src.emulation.filesystem import FakeFilesystem, load_profile
    from src.emulation.shell import ShellEmulator
    from src.emulation.timing import TimingSimulator
    EMULATION_AVAILABLE = True
except ImportError:
    EMULATION_AVAILABLE = False
    print("[WARN] Shell emulation module not available, using static responses", flush=True)


# =============================================================================
# Configuration
# =============================================================================

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


def load_allowed_credentials() -> Dict[str, str]:
    """Load allowed username:password combinations"""
    creds = {}
    
    # Check for allow-any mode
    if os.environ.get("HONEYPOT_ALLOW_ANY_AUTH", "false").lower() == "true":
        return {"*": "*"}  # Special marker for any-auth
    
    # Load from environment variable
    users_env = os.environ.get("HONEYPOT_USERS", "")
    if users_env:
        for pair in users_env.split(","):
            if ":" in pair:
                user, passwd = pair.split(":", 1)
                creds[user.strip()] = passwd.strip()
    
    # Load from file
    users_file = os.environ.get("HONEYPOT_USERS_FILE", "")
    if users_file and Path(users_file).exists():
        try:
            with open(users_file) as f:
                for line in f:
                    line = line.strip()
                    if line and ":" in line and not line.startswith("#"):
                        user, passwd = line.split(":", 1)
                        creds[user.strip()] = passwd.strip()
        except Exception as e:
            print(f"[ERROR] Failed to load credentials file: {e}", flush=True)
    
    # Default weak credentials if nothing configured
    if not creds:
        creds = {
            "root": "admin",
            "root": "root",
            "admin": "admin",
            "test": "test",
            "user": "password",
        }
    
    return creds


PORT = get_port()
LOG_FILE = Path(os.environ.get("LOG_PATH", "/var/log/honeypot/ssh.json"))
SSH_BANNER = os.environ.get("SSH_BANNER", "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
ALLOWED_CREDS = load_allowed_credentials()
AI_ENABLED = os.environ.get("AI_DECEPTION_ENABLED", "false").lower() == "true"
AI_PERSONALITY = os.environ.get("AI_DECEPTION_PERSONALITY", "naive_intern")
EMULATION_PROFILE = os.environ.get("EMULATION_PROFILE", "ubuntu-22.04")


# =============================================================================
# Rate Limiting
# =============================================================================

class RateLimiter:
    """In-memory per-IP rate limiter"""
    
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
    
    def check_connection(self, ip: str) -> Tuple[bool, Optional[str]]:
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
    
    def check_auth(self, ip: str) -> Tuple[bool, Optional[str]]:
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


# =============================================================================
# Logging
# =============================================================================

def hash_password(password: str) -> str:
    """Hash password for safe logging"""
    safe_password = password[:MAX_PASSWORD_LENGTH] if password else ""
    return hashlib.sha256(safe_password.encode()).hexdigest()[:16]


def log_event(event_type: str, data: dict):
    """Log event to file and stdout"""
    safe_event_type = sanitize_for_log(event_type, max_length=64)
    
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'event': safe_event_type,
        **data
    }
    
    line = json.dumps(event)
    if len(line) > 16384:
        event['_truncated'] = True
        line = json.dumps(event)[:16384]
    
    print(line, flush=True)
    
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, 'a') as f:
            f.write(line + '\n')
    except Exception as e:
        print(f"Log write error: {e}", file=sys.stderr)


# =============================================================================
# SSH Server
# =============================================================================

class HoneypotServer(asyncssh.SSHServer):
    """SSH server that captures credentials and optionally allows shell access"""
    
    def __init__(self):
        self.client_ip = None
        self.client_ip_valid = False
        self._rate_limited = False
        self._authenticated_user = None
        self._conn = None
        
    def connection_made(self, conn):
        self._conn = conn
        try:
            peername = conn.get_extra_info('peername')
            raw_ip = peername[0] if peername else 'unknown'
            self.client_ip, self.client_ip_valid = validate_ip(raw_ip)
            
            allowed, reason = rate_limiter.check_connection(self.client_ip)
            if not allowed:
                self._rate_limited = True
                log_event('rate_limit_connection', {
                    'ip': self.client_ip,
                    'reason': reason
                })
                conn.close()
                return
            
            log_event('connection', {
                'ip': self.client_ip,
                'ip_valid': self.client_ip_valid
            })
        except Exception as e:
            print(f"[ERROR] connection_made: {e}", flush=True)
            traceback.print_exc()

    def connection_lost(self, exc):
        error_msg = sanitize_for_log(str(exc), max_length=256) if exc else None
        log_event('disconnect', {
            'ip': self.client_ip, 
            'error': error_msg,
            'authenticated_user': self._authenticated_user
        })

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        # Rate limit check
        allowed, reason = rate_limiter.check_auth(self.client_ip)
        if not allowed:
            log_event('rate_limit_auth', {'ip': self.client_ip, 'reason': reason})
            return False
        
        safe_username, username_valid = validate_username(username)
        pw_length, pw_valid = validate_password(password)
        pw_hash = hash_password(password) if password else "empty"
        
        # Check credentials
        auth_success = False
        if "*" in ALLOWED_CREDS:
            # Allow any credentials
            auth_success = True
        elif safe_username in ALLOWED_CREDS:
            auth_success = (ALLOWED_CREDS[safe_username] == password)
        
        log_event('login_attempt', {
            'ip': self.client_ip,
            'username': safe_username,
            'username_valid': username_valid,
            'password_hash': pw_hash,
            'password_length': pw_length,
            'password_valid': pw_valid,
            'success': auth_success,
            'ai_enabled': AI_ENABLED and AI_AVAILABLE
        })
        
        if auth_success:
            self._authenticated_user = safe_username
            log_event('auth_success', {
                'ip': self.client_ip,
                'username': safe_username,
                'personality': AI_PERSONALITY if AI_ENABLED else None
            })
        
        return auth_success

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        allowed, reason = rate_limiter.check_auth(self.client_ip)
        if not allowed:
            return False
        
        safe_username, _ = validate_username(username)
        try:
            key_type = sanitize_for_log(key.get_algorithm(), max_length=64)
            fingerprint = validate_ssh_fingerprint(key.get_fingerprint())
        except Exception:
            key_type = "<error>"
            fingerprint = "<error>"
        
        log_event('pubkey_attempt', {
            'ip': self.client_ip,
            'username': safe_username,
            'key_type': key_type,
            'fingerprint': fingerprint
        })
        return False

    def session_requested(self):
        """Allow session creation after authentication"""
        return self._authenticated_user is not None


class HoneypotProcess(asyncssh.SSHServerProcess):
    """Process handler for shell sessions"""
    
    def __init__(self, process, server):
        self._process = process
        self._server = server
    
    async def run(self):
        """Run the interactive shell session"""
        client_ip = self._server.client_ip
        username = self._server._authenticated_user
        
        log_event('shell_start', {
            'ip': client_ip,
            'username': username,
            'ai_enabled': AI_ENABLED and AI_AVAILABLE,
            'personality': AI_PERSONALITY if AI_ENABLED else None
        })
        
        stdin = self._process.stdin
        stdout = self._process.stdout  
        stderr = self._process.stderr
        
        if AI_ENABLED and AI_AVAILABLE:
            # Use AI-powered shell
            session = DeceptiveShellSession(
                client_ip=client_ip,
                personality=AI_PERSONALITY,
                on_log=log_event
            )
            exit_code = await session.run(stdin, stdout, stderr)
        else:
            # Basic non-AI shell (static responses)
            exit_code = await self._run_basic_shell(stdin, stdout, stderr, client_ip)
        
        log_event('shell_end', {
            'ip': client_ip,
            'username': username,
            'exit_code': exit_code
        })
        
        self._process.exit(exit_code)
    
    async def _run_basic_shell(self, stdin, stdout, stderr, client_ip) -> int:
        """Emulation-backed shell with stateful filesystem and realistic responses."""
        username = self._server._authenticated_user or "root"

        if EMULATION_AVAILABLE:
            shell, timer = self._init_emulation(client_ip, username)
            hostname = shell.hostname
        else:
            shell = None
            timer = None
            hostname = "server-01"

        stdout.write(f"""Welcome to Ubuntu 22.04.3 LTS ({hostname})

Last login: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from 10.0.0.1
""")
        prompt = shell.prompt if shell else f"{username}@{hostname}:~$ "
        stdout.write(prompt)

        buffer = ""
        command_count = 0

        while True:
            try:
                data = await asyncio.wait_for(stdin.read(1024), timeout=300)
                if not data:
                    break

                buffer += data

                while '\n' in buffer or '\r' in buffer:
                    if '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                    else:
                        line, buffer = buffer.split('\r', 1)

                    line = line.strip()

                    if not line:
                        prompt = shell.prompt if shell else f"{username}@{hostname}:~$ "
                        stdout.write(prompt)
                        continue

                    if line.lower() in ('exit', 'logout', 'quit'):
                        stdout.write("logout\n")
                        return 0

                    command_count += 1
                    log_event('command', {
                        'ip': client_ip,
                        'command': sanitize_for_log(line, max_length=1024),
                        'ai_mode': False,
                        'emulation': shell is not None,
                    })

                    if shell:
                        response, exit_code = shell.execute(line)
                        if timer:
                            await timer.delay_for(
                                command=line,
                                output_size=len(response),
                            )
                    else:
                        response = self._get_static_response(line)

                    if response:
                        stdout.write(response + "\n")
                    prompt = shell.prompt if shell else f"{username}@{hostname}:~$ "
                    stdout.write(prompt)

            except asyncio.TimeoutError:
                stdout.write("\nSession timed out.\n")
                break
            except Exception as e:
                print(f"[ERROR] Shell error: {e}", flush=True)
                break

        return 0

    def _init_emulation(self, client_ip: str, username: str):
        """Initialize emulation layer for a session."""
        profile = load_profile(EMULATION_PROFILE)
        hostname = profile.get("hostname", "server-01")
        fs = FakeFilesystem(profile)

        # Add canary files
        fs.add_canary("/root/.ssh/id_rsa",
                      "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                      "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUA...EXAMPLE...\n"
                      "-----END OPENSSH PRIVATE KEY-----\n",
                      token_id="ssh_key_root")
        fs.add_canary("/root/.aws/credentials",
                      "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
                      "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
                      token_id="aws_creds_root")

        uid = 0 if username == "root" else 1000
        home = "/root" if username == "root" else f"/home/{username}"

        def on_command(cmd, cwd, user):
            pass  # Already logged by the caller

        def on_canary(path, token_id):
            log_event('canary_triggered', {
                'ip': client_ip,
                'path': path,
                'token_id': token_id,
                'username': username,
            })

        shell = ShellEmulator(
            filesystem=fs,
            username=username,
            hostname=hostname,
            uid=uid,
            gid=uid,
            home=home,
            on_canary=on_canary,
        )
        timer = TimingSimulator()
        return shell, timer

    @staticmethod
    def _get_static_response(command: str) -> str:
        """Fallback static responses when emulation is not available."""
        cmd = command.split()[0] if command.split() else ""
        responses = {
            "whoami": "root",
            "id": "uid=0(root) gid=0(root) groups=0(root)",
            "hostname": "server-01",
            "pwd": "/root",
            "uname": "Linux server-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
            "ls": "Desktop  Documents  Downloads  .bashrc",
            "uptime": " 14:32:17 up 47 days,  2 users,  load average: 0.08, 0.12, 0.09",
        }
        if cmd in responses:
            return responses[cmd]
        elif "cat" in command and "/etc/passwd" in command:
            return "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
        return f"bash: {cmd}: command not found"


def process_factory(process):
    """Factory function for creating SSH process handlers"""
    # Get the server instance from the connection
    server = process.channel._conn._owner
    handler = HoneypotProcess(process, server)
    return handler.run()


# =============================================================================
# Main Server
# =============================================================================

async def start_server():
    """Start the SSH honeypot server"""
    try:
        print("[DEBUG] Generating RSA host key...", flush=True)
        key = asyncssh.generate_private_key('ssh-rsa', 2048)
        
        cred_mode = "any" if "*" in ALLOWED_CREDS else f"{len(ALLOWED_CREDS)} configured"
        
        log_event('startup', {
            'port': PORT,
            'version': '2.1.0',
            'rate_limiting': rate_limiter.enabled,
            'ai_enabled': AI_ENABLED and AI_AVAILABLE,
            'ai_personality': AI_PERSONALITY if AI_ENABLED else None,
            'emulation_available': EMULATION_AVAILABLE,
            'emulation_profile': EMULATION_PROFILE if EMULATION_AVAILABLE else None,
            'credentials_mode': cred_mode,
            'ssh_banner': SSH_BANNER
        })
        
        print(f"[INFO] SSH AI Honeypot starting on port {PORT}", flush=True)
        print(f"[INFO] AI Deception: {'ENABLED (' + AI_PERSONALITY + ')' if AI_ENABLED and AI_AVAILABLE else 'DISABLED'}", flush=True)
        print(f"[INFO] Shell Emulation: {'ENABLED (' + EMULATION_PROFILE + ')' if EMULATION_AVAILABLE else 'DISABLED (static fallback)'}", flush=True)
        print(f"[INFO] Credentials: {cred_mode}", flush=True)
        
        server = await asyncssh.create_server(
            HoneypotServer, '0.0.0.0', PORT,
            server_host_keys=[key],
            server_version=SSH_BANNER,
            process_factory=process_factory
        )
        
        print(f"[INFO] SSH Honeypot running on port {PORT}", flush=True)
        
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
