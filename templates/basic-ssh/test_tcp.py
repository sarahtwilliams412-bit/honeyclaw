#!/usr/bin/env python3
"""
Simple TCP server to test if Fly is routing traffic
Version: 1.1.0 (input validation)
"""
import asyncio
import os
import sys
from pathlib import Path

# Add parent path for common imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from common.validation import (
    validate_ip,
    sanitize_for_log,
)

PORT = int(os.environ.get("PORT", 8022))

# Safety limits
MAX_RECV_SIZE = 256
CONNECTION_TIMEOUT = 5.0

async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    
    # Validate IP address
    raw_ip = addr[0] if addr else 'unknown'
    safe_ip, ip_valid = validate_ip(raw_ip)
    safe_port = addr[1] if addr and len(addr) > 1 else 0
    
    print(f"[TCP] Connection from {safe_ip}:{safe_port} (valid={ip_valid})", flush=True)
    
    # Send SSH banner
    writer.write(b"SSH-2.0-HoneypotSSH\r\n")
    await writer.drain()
    
    try:
        data = await asyncio.wait_for(reader.read(MAX_RECV_SIZE), timeout=CONNECTION_TIMEOUT)
        # Sanitize received data for logging
        safe_data = sanitize_for_log(data.decode('utf-8', errors='replace'), max_length=100)
        print(f"[TCP] Received from {safe_ip}: {safe_data}", flush=True)
    except asyncio.TimeoutError:
        print(f"[TCP] Timeout from {safe_ip}", flush=True)
    except Exception as e:
        safe_error = sanitize_for_log(str(e), max_length=128)
        print(f"[TCP] Error from {safe_ip}: {safe_error}", flush=True)
    
    writer.close()
    await writer.wait_closed()
    print(f"[TCP] Closed connection from {safe_ip}", flush=True)

async def main():
    print(f"[TCP] Starting simple TCP server on 0.0.0.0:{PORT}", flush=True)
    print(f"[TCP] Input validation enabled (v1.1.0)", flush=True)
    server = await asyncio.start_server(handle_client, '0.0.0.0', PORT)
    print(f"[TCP] Server started, waiting for connections...", flush=True)
    
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[TCP] Shutting down...")
