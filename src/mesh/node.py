#!/usr/bin/env python3
"""
Honey Claw - Mesh Node Client
Individual node registration, heartbeat, and event reporting.

Integrates with honeypots to forward events to the mesh coordinator.

Environment variables:
  MESH_ENABLED           - Enable mesh mode (default: false)
  MESH_COORDINATOR_URL   - Coordinator API URL
  MESH_TOKEN             - Authentication token
  MESH_NODE_ID           - Node identifier (default: auto-generated)
  MESH_REGION            - Deployment region
  MESH_HEARTBEAT_SEC     - Heartbeat interval (default: 30)
"""

import asyncio
import aiohttp
import json
import os
import socket
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from collections import deque


@dataclass
class MeshConfig:
    """Mesh node configuration"""
    enabled: bool = False
    coordinator_url: str = ""
    token: str = ""
    node_id: str = ""
    region: str = ""
    heartbeat_interval: int = 30
    batch_size: int = 50
    batch_timeout: float = 5.0
    retry_attempts: int = 3
    retry_delay: float = 1.0
    
    @classmethod
    def from_env(cls) -> 'MeshConfig':
        """Load configuration from environment"""
        return cls(
            enabled=os.environ.get('MESH_ENABLED', 'false').lower() == 'true',
            coordinator_url=os.environ.get('MESH_COORDINATOR_URL', ''),
            token=os.environ.get('MESH_TOKEN', ''),
            node_id=os.environ.get('MESH_NODE_ID', ''),
            region=os.environ.get('MESH_REGION', 'unknown'),
            heartbeat_interval=int(os.environ.get('MESH_HEARTBEAT_SEC', '30')),
            batch_size=int(os.environ.get('MESH_BATCH_SIZE', '50')),
            batch_timeout=float(os.environ.get('MESH_BATCH_TIMEOUT', '5.0'))
        )
    
    @classmethod
    def from_yaml(cls, config: dict) -> 'MeshConfig':
        """Load configuration from YAML dict"""
        mesh = config.get('mesh', {})
        return cls(
            enabled=mesh.get('enabled', False),
            coordinator_url=mesh.get('coordinator_url', ''),
            token=mesh.get('token', os.environ.get('MESH_TOKEN', '')),
            node_id=mesh.get('node_id', 'auto'),
            region=mesh.get('region', 'unknown'),
            heartbeat_interval=mesh.get('heartbeat_interval', 30),
            batch_size=mesh.get('batch_size', 50),
            batch_timeout=mesh.get('batch_timeout', 5.0)
        )


class MeshNode:
    """
    Mesh node client for honeypot integration.
    
    Handles:
    - Node registration with coordinator
    - Periodic heartbeats
    - Batched event forwarding
    - IOC sharing
    """
    
    def __init__(self, config: Optional[MeshConfig] = None, services: List[str] = None):
        self.config = config or MeshConfig.from_env()
        self.services = services or ['ssh']
        
        # Auto-generate node ID if needed
        if not self.config.node_id or self.config.node_id == 'auto':
            self.config.node_id = self._generate_node_id()
        
        self.hostname = socket.gethostname()
        self.registered = False
        self.coordinator_id = None
        
        # Event batching
        self._event_queue: deque = deque(maxlen=10000)
        self._batch_lock = asyncio.Lock()
        self._flush_event = asyncio.Event()
        
        # HTTP session
        self._session: Optional[aiohttp.ClientSession] = None
        
        # Background tasks
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._batch_task: Optional[asyncio.Task] = None
    
    def _generate_node_id(self) -> str:
        """Generate unique node ID based on hostname and region"""
        hostname = socket.gethostname()
        region = self.config.region
        unique = uuid.uuid4().hex[:8]
        return f"{hostname}-{region}-{unique}"
    
    @property
    def _headers(self) -> dict:
        """Get API request headers"""
        return {
            'Authorization': f'Bearer {self.config.token}',
            'Content-Type': 'application/json'
        }
    
    async def start(self):
        """Start mesh node - register and begin background tasks"""
        if not self.config.enabled:
            print("[MESH] Mesh mode disabled", flush=True)
            return
        
        if not self.config.coordinator_url:
            print("[MESH] No coordinator URL configured", flush=True)
            return
        
        print(f"[MESH] Starting node {self.config.node_id} in region {self.config.region}", flush=True)
        
        # Create HTTP session
        self._session = aiohttp.ClientSession()
        
        # Register with coordinator
        await self._register()
        
        # Start background tasks
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self._batch_task = asyncio.create_task(self._batch_loop())
        
        print(f"[MESH] Node started, coordinator: {self.coordinator_id}", flush=True)
    
    async def stop(self):
        """Stop mesh node gracefully"""
        if not self.config.enabled:
            return
        
        # Cancel background tasks
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
        if self._batch_task:
            self._batch_task.cancel()
        
        # Flush remaining events
        await self._flush_events()
        
        # Close session
        if self._session:
            await self._session.close()
        
        print(f"[MESH] Node {self.config.node_id} stopped", flush=True)
    
    async def _register(self):
        """Register node with coordinator"""
        url = f"{self.config.coordinator_url}/nodes/register"
        payload = {
            'node_id': self.config.node_id,
            'region': self.config.region,
            'hostname': self.hostname,
            'services': self.services,
            'version': '1.0.0'
        }
        
        for attempt in range(self.config.retry_attempts):
            try:
                async with self._session.post(url, json=payload, headers=self._headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self.registered = True
                        self.coordinator_id = data.get('coordinator_id')
                        print(f"[MESH] Registered with coordinator: {self.coordinator_id}", flush=True)
                        return
                    else:
                        error = await resp.text()
                        print(f"[MESH] Registration failed: {error}", flush=True)
            except Exception as e:
                print(f"[MESH] Registration error (attempt {attempt+1}): {e}", flush=True)
                if attempt < self.config.retry_attempts - 1:
                    await asyncio.sleep(self.config.retry_delay * (attempt + 1))
        
        print("[MESH] Failed to register with coordinator", flush=True)
    
    async def _heartbeat_loop(self):
        """Send periodic heartbeats to coordinator"""
        while True:
            try:
                await asyncio.sleep(self.config.heartbeat_interval)
                await self._send_heartbeat()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[MESH] Heartbeat error: {e}", flush=True)
    
    async def _send_heartbeat(self):
        """Send heartbeat to coordinator"""
        if not self.registered:
            await self._register()
            return
        
        url = f"{self.config.coordinator_url}/nodes/heartbeat"
        payload = {
            'node_id': self.config.node_id,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        try:
            async with self._session.post(url, json=payload, headers=self._headers) as resp:
                if resp.status != 200:
                    print(f"[MESH] Heartbeat failed: {resp.status}", flush=True)
                    self.registered = False
        except Exception as e:
            print(f"[MESH] Heartbeat error: {e}", flush=True)
            self.registered = False
    
    async def _batch_loop(self):
        """Process event queue in batches"""
        while True:
            try:
                # Wait for batch timeout or flush signal
                try:
                    await asyncio.wait_for(
                        self._flush_event.wait(),
                        timeout=self.config.batch_timeout
                    )
                    self._flush_event.clear()
                except asyncio.TimeoutError:
                    pass
                
                await self._flush_events()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[MESH] Batch processing error: {e}", flush=True)
    
    async def _flush_events(self):
        """Flush queued events to coordinator"""
        if not self._event_queue:
            return
        
        async with self._batch_lock:
            # Collect batch
            batch = []
            while self._event_queue and len(batch) < self.config.batch_size:
                batch.append(self._event_queue.popleft())
            
            if not batch:
                return
            
            # Send batch
            url = f"{self.config.coordinator_url}/events/batch"
            payload = {'events': batch}
            
            try:
                async with self._session.post(url, json=payload, headers=self._headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        print(f"[MESH] Sent {data.get('count', len(batch))} events", flush=True)
                    else:
                        # Re-queue events on failure
                        for event in reversed(batch):
                            self._event_queue.appendleft(event)
                        print(f"[MESH] Event batch failed: {resp.status}", flush=True)
            except Exception as e:
                # Re-queue events on error
                for event in reversed(batch):
                    self._event_queue.appendleft(event)
                print(f"[MESH] Event batch error: {e}", flush=True)
    
    def record_event(self, event_type: str, data: dict):
        """
        Queue an event for mesh coordinator.
        
        Args:
            event_type: Type of event (connection, login_attempt, etc.)
            data: Event data dictionary
        """
        if not self.config.enabled:
            return
        
        event = {
            'node_id': self.config.node_id,
            'region': self.config.region,
            'event': {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'event_type': event_type,
                **data
            }
        }
        
        self._event_queue.append(event)
        
        # Trigger flush if batch is full
        if len(self._event_queue) >= self.config.batch_size:
            self._flush_event.set()
    
    async def add_ioc(self, ioc_type: str, value: str, confidence: float = 0.5,
                       tags: List[str] = None):
        """
        Add IOC to shared database.
        
        Args:
            ioc_type: Type (ip, domain, hash, fingerprint)
            value: IOC value
            confidence: Confidence score 0-1
            tags: Optional tags
        """
        if not self.config.enabled:
            return
        
        url = f"{self.config.coordinator_url}/iocs"
        payload = {
            'type': ioc_type,
            'value': value,
            'region': self.config.region,
            'node_id': self.config.node_id,
            'confidence': confidence,
            'tags': tags or []
        }
        
        try:
            async with self._session.post(url, json=payload, headers=self._headers) as resp:
                if resp.status == 200:
                    print(f"[MESH] IOC added: {ioc_type}={value[:32]}...", flush=True)
                else:
                    print(f"[MESH] IOC add failed: {resp.status}", flush=True)
        except Exception as e:
            print(f"[MESH] IOC add error: {e}", flush=True)
    
    async def get_iocs(self, ioc_type: Optional[str] = None, 
                        min_confidence: float = 0.5) -> List[dict]:
        """
        Fetch IOCs from coordinator.
        
        Args:
            ioc_type: Filter by type
            min_confidence: Minimum confidence threshold
            
        Returns:
            List of IOC dictionaries
        """
        if not self.config.enabled:
            return []
        
        url = f"{self.config.coordinator_url}/iocs"
        params = {'min_confidence': str(min_confidence)}
        if ioc_type:
            params['type'] = ioc_type
        
        try:
            async with self._session.get(url, params=params, headers=self._headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get('iocs', [])
                else:
                    print(f"[MESH] IOC fetch failed: {resp.status}", flush=True)
                    return []
        except Exception as e:
            print(f"[MESH] IOC fetch error: {e}", flush=True)
            return []
    
    async def get_known_attackers(self, min_score: float = 30.0,
                                    multi_region_only: bool = True) -> List[dict]:
        """
        Fetch known attacker profiles from coordinator.
        
        Args:
            min_score: Minimum threat score
            multi_region_only: Only return multi-region attackers
            
        Returns:
            List of attacker profiles
        """
        if not self.config.enabled:
            return []
        
        url = f"{self.config.coordinator_url}/attackers"
        params = {
            'min_score': str(min_score),
            'multi_region': str(multi_region_only).lower()
        }
        
        try:
            async with self._session.get(url, params=params, headers=self._headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get('attackers', [])
                else:
                    print(f"[MESH] Attacker fetch failed: {resp.status}", flush=True)
                    return []
        except Exception as e:
            print(f"[MESH] Attacker fetch error: {e}", flush=True)
            return []


# =============================================================================
# Honeypot Integration Helper
# =============================================================================

class MeshIntegration:
    """
    Helper class to integrate mesh reporting into existing honeypots.
    
    Usage:
        mesh = MeshIntegration(['ssh', 'rdp'])
        await mesh.start()
        
        # In your honeypot event handler:
        mesh.report_connection('192.168.1.100', 22)
        mesh.report_auth_attempt('192.168.1.100', 'admin', success=False)
        
        await mesh.stop()
    """
    
    def __init__(self, services: List[str] = None, config: MeshConfig = None):
        self.node = MeshNode(config, services)
    
    async def start(self):
        """Start mesh integration"""
        await self.node.start()
    
    async def stop(self):
        """Stop mesh integration"""
        await self.node.stop()
    
    @property
    def enabled(self) -> bool:
        """Check if mesh is enabled"""
        return self.node.config.enabled
    
    def report_connection(self, source_ip: str, dest_port: int,
                          source_port: int = None, **extra):
        """Report new connection"""
        self.node.record_event('connection', {
            'source_ip': source_ip,
            'source_port': source_port,
            'dest_port': dest_port,
            **extra
        })
    
    def report_auth_attempt(self, source_ip: str, username: str,
                            success: bool = False, method: str = 'password',
                            techniques: List[str] = None, **extra):
        """Report authentication attempt"""
        self.node.record_event('auth_attempt', {
            'source_ip': source_ip,
            'username': username,
            'success': success,
            'method': method,
            'techniques': techniques or ['T1078'],  # Valid Accounts
            **extra
        })
    
    def report_command(self, source_ip: str, command: str,
                       techniques: List[str] = None, **extra):
        """Report command execution attempt"""
        self.node.record_event('command', {
            'source_ip': source_ip,
            'command': command[:1024],  # Truncate long commands
            'techniques': techniques or ['T1059'],  # Command and Scripting
            **extra
        })
    
    def report_file_access(self, source_ip: str, path: str,
                           operation: str = 'read', **extra):
        """Report file access attempt"""
        self.node.record_event('file_access', {
            'source_ip': source_ip,
            'path': path[:512],
            'operation': operation,
            'techniques': ['T1083'],  # File and Directory Discovery
            **extra
        })
    
    def report_lateral_movement(self, source_ip: str, target_ip: str,
                                 method: str = 'ssh', **extra):
        """Report lateral movement attempt"""
        self.node.record_event('lateral_movement', {
            'source_ip': source_ip,
            'target_ip': target_ip,
            'method': method,
            'techniques': ['T1021'],  # Remote Services
            **extra
        })
    
    async def add_ioc(self, ioc_type: str, value: str, 
                       confidence: float = 0.5, tags: List[str] = None):
        """Add IOC to shared database"""
        await self.node.add_ioc(ioc_type, value, confidence, tags)
    
    async def check_ip(self, ip: str) -> Optional[dict]:
        """Check if IP is a known attacker"""
        attackers = await self.node.get_known_attackers(min_score=0)
        for attacker in attackers:
            if attacker.get('ip') == ip:
                return attacker
        return None


# =============================================================================
# Standalone runner
# =============================================================================

async def main():
    """Test mesh node connectivity"""
    config = MeshConfig.from_env()
    
    if not config.enabled:
        print("MESH_ENABLED not set to 'true'")
        print("\nExample usage:")
        print("  export MESH_ENABLED=true")
        print("  export MESH_COORDINATOR_URL=https://mesh.honeyclaw.io")
        print("  export MESH_TOKEN=your-secret-token")
        print("  export MESH_REGION=us-west")
        print("  python node.py")
        return
    
    node = MeshNode(config, services=['ssh', 'test'])
    await node.start()
    
    # Test event recording
    node.record_event('test', {
        'source_ip': '192.0.2.1',
        'message': 'Test event from node'
    })
    
    # Wait for batch to flush
    await asyncio.sleep(10)
    
    await node.stop()


if __name__ == '__main__':
    asyncio.run(main())
