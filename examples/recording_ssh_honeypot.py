#!/usr/bin/env python3
"""
Example: SSH Honeypot with Session Recording

This example shows how to integrate session recording into the SSH honeypot.
Records all attacker activity for later replay in the dashboard.

Usage:
    HONEYCLAW_RECORDINGS_PATH=/var/lib/honeyclaw/recordings python recording_ssh_honeypot.py

Environment variables:
    HONEYCLAW_RECORDINGS_PATH - Where to store recordings (default: /var/lib/honeyclaw/recordings)
    HONEYCLAW_STORAGE         - Storage backend: 'local' or 's3' (default: local)
    HONEYCLAW_S3_BUCKET       - S3 bucket for recordings (if using S3)
"""

import asyncio
import asyncssh
import os
import signal
import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.replay.integration import RecordingSSHSession


class RecordingSSHServer(asyncssh.SSHServer):
    """SSH server that records all sessions"""
    
    def __init__(self):
        self.client_ip = 'unknown'
        self.client_port = 0
        self.recording = None
    
    def connection_made(self, conn):
        peername = conn.get_extra_info('peername')
        if peername:
            self.client_ip = peername[0]
            self.client_port = peername[1]
        
        print(f"[+] Connection from {self.client_ip}:{self.client_port}")
    
    def begin_auth(self, username):
        # Create recording session
        self.recording = RecordingSSHSession(
            source_ip=self.client_ip,
            source_port=self.client_port,
            dest_port=PORT,
            username=username
        )
        print(f"[+] Recording started: {self.recording.session_id}")
        return True
    
    def password_auth_supported(self):
        return True
    
    def validate_password(self, username, password):
        print(f"[*] Login attempt: {username}:***")
        
        if self.recording:
            # For demo: allow login with specific credentials
            if username == 'admin' and password == 'admin':
                self.recording.add_tag('successful_login')
                return True
        
        return False
    
    def connection_lost(self, exc):
        print(f"[-] Connection closed from {self.client_ip}")
        
        # Save recording when connection closes
        if self.recording:
            try:
                path = self.recording.save()
                print(f"[+] Recording saved: {path}")
            except Exception as e:
                print(f"[!] Failed to save recording: {e}")


class InteractiveSession(asyncssh.SSHServerProcess):
    """Fake interactive shell that records everything"""
    
    def __init__(self, process, recording):
        self.process = process
        self.recording = recording
        self.username = process.get_extra_info('username') or 'unknown'
    
    async def run(self):
        # Send fake banner
        banner = f"""
Linux server 5.4.0-150-generic #167-Ubuntu SMP Mon May 15 17:35:05 UTC 2023 x86_64

Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-150-generic x86_64)

Last login: Mon Feb  5 10:23:41 2024 from 192.168.1.100
"""
        self.process.stdout.write(banner)
        if self.recording:
            self.recording.record_output(banner)
        
        # Send prompt
        prompt = f"{self.username}@server:~$ "
        self.process.stdout.write(prompt)
        if self.recording:
            self.recording.record_output(prompt)
        
        # Read and respond to commands
        try:
            async for line in self.process.stdin:
                line = line.strip()
                
                # Record input
                if self.recording:
                    self.recording.record_input(line + '\n')
                
                # Generate fake response
                response = self.generate_response(line)
                
                # Send response
                self.process.stdout.write(response)
                if self.recording:
                    self.recording.record_output(response)
                
                # Send new prompt
                self.process.stdout.write(prompt)
                if self.recording:
                    self.recording.record_output(prompt)
                
        except asyncssh.BreakReceived:
            pass
        except asyncssh.TerminalSizeChanged as e:
            if self.recording:
                self.recording.record_resize(e.width, e.height)
    
    def generate_response(self, command):
        """Generate fake command responses"""
        cmd = command.split()[0] if command else ''
        
        responses = {
            'ls': 'Desktop  Documents  Downloads  Music  Pictures  Videos\n',
            'pwd': '/home/' + self.username + '\n',
            'whoami': self.username + '\n',
            'id': f'uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),4(adm),24(cdrom),27(sudo)\n',
            'uname': 'Linux server 5.4.0-150-generic #167-Ubuntu SMP x86_64 GNU/Linux\n',
            'hostname': 'server\n',
            'cat': 'Permission denied\n',
            'wget': 'wget: command not found\n',
            'curl': 'curl: command not found\n',
            'exit': '',
        }
        
        if cmd in responses:
            if cmd == 'exit':
                self.process.exit(0)
            return responses[cmd]
        elif cmd == '':
            return ''
        else:
            return f'{cmd}: command not found\n'


def session_factory(process):
    """Create interactive session with recording"""
    server = process.get_extra_info('connection').get_owner()
    return InteractiveSession(process, getattr(server, 'recording', None))


async def process_factory(process):
    """Process factory that creates recorded sessions"""
    session = session_factory(process)
    await session.run()


PORT = int(os.environ.get('PORT', 2222))


async def start_server():
    print(f"[*] Starting recording SSH honeypot on port {PORT}")
    print(f"[*] Recordings will be saved to: {os.environ.get('HONEYCLAW_RECORDINGS_PATH', '/var/lib/honeyclaw/recordings')}")
    print(f"[*] Test with: ssh admin@localhost -p {PORT}")
    print(f"[*] Password: admin")
    
    key = asyncssh.generate_private_key('ssh-rsa', 2048)
    
    server = await asyncssh.create_server(
        RecordingSSHServer,
        '0.0.0.0', PORT,
        server_host_keys=[key],
        process_factory=process_factory
    )
    
    print(f"[+] Server running")
    
    # Wait for shutdown signal
    stop = asyncio.Event()
    
    def handle_signal():
        print("\n[*] Shutting down...")
        stop.set()
    
    for sig in (signal.SIGINT, signal.SIGTERM):
        asyncio.get_event_loop().add_signal_handler(sig, handle_signal)
    
    await stop.wait()
    server.close()
    await server.wait_closed()
    print("[+] Server stopped")


if __name__ == '__main__':
    asyncio.run(start_server())
