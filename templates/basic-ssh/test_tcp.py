#!/usr/bin/env python3
"""Simple TCP server to test if Fly is routing traffic"""
import asyncio
import os
import sys

PORT = int(os.environ.get("PORT", 8022))

async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    print(f"[TCP] Connection from {addr}", flush=True)
    
    # Send SSH banner
    writer.write(b"SSH-2.0-HoneypotSSH\r\n")
    await writer.drain()
    
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=5.0)
        print(f"[TCP] Received from {addr}: {data[:100]}", flush=True)
    except asyncio.TimeoutError:
        print(f"[TCP] Timeout from {addr}", flush=True)
    except Exception as e:
        print(f"[TCP] Error from {addr}: {e}", flush=True)
    
    writer.close()
    await writer.wait_closed()
    print(f"[TCP] Closed connection from {addr}", flush=True)

async def main():
    print(f"[TCP] Starting simple TCP server on 0.0.0.0:{PORT}", flush=True)
    server = await asyncio.start_server(handle_client, '0.0.0.0', PORT)
    print(f"[TCP] Server started, waiting for connections...", flush=True)
    
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[TCP] Shutting down...")
