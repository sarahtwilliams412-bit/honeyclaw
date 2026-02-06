#!/usr/bin/env python3
"""
Honey Claw - Mesh Coordinator
Central coordinator for geo-distributed honeypot mesh.

Responsibilities:
- Node registration and health tracking
- Cross-region attacker correlation
- IOC aggregation and distribution
- Attack pattern analysis across regions

Environment variables:
  COORDINATOR_PORT       - API listen port (default: 8443)
  COORDINATOR_TOKEN      - Shared auth token for nodes
  DATABASE_URL           - SQLite/Redis connection string
  COORDINATOR_ID         - Unique coordinator identifier
"""

import asyncio
import hashlib
import json
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set
from aiohttp import web


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class MeshNode:
    """Registered mesh node"""
    node_id: str
    region: str
    hostname: str
    ip_address: str
    services: List[str]
    registered_at: str
    last_heartbeat: str
    status: str = "active"
    version: str = "1.0.0"


@dataclass
class AttackerSighting:
    """Cross-region attacker sighting"""
    ip: str
    first_seen: str
    last_seen: str
    regions: List[str]
    node_ids: List[str]
    total_attempts: int
    techniques: List[str]
    threat_score: float


@dataclass
class IOC:
    """Indicator of Compromise"""
    ioc_id: str
    ioc_type: str  # ip, domain, hash, fingerprint
    value: str
    source_region: str
    source_node: str
    first_seen: str
    last_seen: str
    confidence: float
    tags: List[str]


# =============================================================================
# Shared IOC Database
# =============================================================================

class IOCDatabase:
    """SQLite-based IOC storage for mesh coordination"""
    
    def __init__(self, db_path: str = "/data/mesh/ioc.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _init_db(self):
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                -- Registered nodes
                CREATE TABLE IF NOT EXISTS nodes (
                    node_id TEXT PRIMARY KEY,
                    region TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    ip_address TEXT,
                    services TEXT,  -- JSON array
                    registered_at TEXT NOT NULL,
                    last_heartbeat TEXT NOT NULL,
                    status TEXT DEFAULT 'active',
                    version TEXT
                );
                
                -- Attack events from all nodes
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    node_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    source_ip TEXT,
                    source_port INTEGER,
                    dest_port INTEGER,
                    payload TEXT,  -- JSON
                    techniques TEXT,  -- JSON array
                    FOREIGN KEY (node_id) REFERENCES nodes(node_id)
                );
                
                -- Aggregated attacker profiles
                CREATE TABLE IF NOT EXISTS attackers (
                    ip TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    regions TEXT NOT NULL,  -- JSON array
                    node_ids TEXT NOT NULL,  -- JSON array
                    total_attempts INTEGER DEFAULT 0,
                    techniques TEXT,  -- JSON array
                    threat_score REAL DEFAULT 0.0
                );
                
                -- IOC database
                CREATE TABLE IF NOT EXISTS iocs (
                    ioc_id TEXT PRIMARY KEY,
                    ioc_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source_region TEXT,
                    source_node TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    confidence REAL DEFAULT 0.5,
                    tags TEXT,  -- JSON array
                    UNIQUE(ioc_type, value)
                );
                
                -- Correlation alerts
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    attacker_ip TEXT,
                    regions TEXT,  -- JSON array
                    acknowledged INTEGER DEFAULT 0
                );
                
                -- Indices for fast lookups
                CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip);
                CREATE INDEX IF NOT EXISTS idx_events_node ON events(node_id);
                CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_attackers_score ON attackers(threat_score DESC);
                CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);
            """)
    
    def register_node(self, node: MeshNode) -> bool:
        """Register or update a mesh node"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO nodes (node_id, region, hostname, ip_address, services,
                                   registered_at, last_heartbeat, status, version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET
                    last_heartbeat = excluded.last_heartbeat,
                    status = excluded.status,
                    ip_address = excluded.ip_address
            """, (
                node.node_id, node.region, node.hostname, node.ip_address,
                json.dumps(node.services), node.registered_at, node.last_heartbeat,
                node.status, node.version
            ))
            return True
    
    def get_active_nodes(self) -> List[MeshNode]:
        """Get all active nodes"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM nodes WHERE status = 'active'"
            ).fetchall()
            return [MeshNode(
                node_id=r['node_id'],
                region=r['region'],
                hostname=r['hostname'],
                ip_address=r['ip_address'],
                services=json.loads(r['services'] or '[]'),
                registered_at=r['registered_at'],
                last_heartbeat=r['last_heartbeat'],
                status=r['status'],
                version=r['version']
            ) for r in rows]
    
    def record_event(self, node_id: str, region: str, event: dict) -> str:
        """Record an attack event"""
        event_id = str(uuid.uuid4())
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO events (event_id, node_id, region, timestamp, event_type,
                                   source_ip, source_port, dest_port, payload, techniques)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_id, node_id, region,
                event.get('timestamp', datetime.utcnow().isoformat() + 'Z'),
                event.get('event_type', 'unknown'),
                event.get('source_ip'),
                event.get('source_port'),
                event.get('dest_port'),
                json.dumps(event.get('payload', {})),
                json.dumps(event.get('techniques', []))
            ))
            
            # Update attacker profile
            if event.get('source_ip'):
                self._update_attacker_profile(conn, event['source_ip'], node_id, region, event)
        
        return event_id
    
    def _update_attacker_profile(self, conn, ip: str, node_id: str, region: str, event: dict):
        """Update or create attacker profile with cross-region correlation"""
        now = datetime.utcnow().isoformat() + 'Z'
        
        # Get existing profile
        row = conn.execute(
            "SELECT * FROM attackers WHERE ip = ?", (ip,)
        ).fetchone()
        
        if row:
            # Update existing profile
            regions = set(json.loads(row[3]))
            regions.add(region)
            nodes = set(json.loads(row[4]))
            nodes.add(node_id)
            techniques = set(json.loads(row[6] or '[]'))
            techniques.update(event.get('techniques', []))
            
            # Calculate threat score based on multi-region activity
            total_attempts = row[5] + 1
            threat_score = self._calculate_threat_score(
                len(regions), total_attempts, list(techniques)
            )
            
            conn.execute("""
                UPDATE attackers SET
                    last_seen = ?,
                    regions = ?,
                    node_ids = ?,
                    total_attempts = ?,
                    techniques = ?,
                    threat_score = ?
                WHERE ip = ?
            """, (
                now, json.dumps(list(regions)), json.dumps(list(nodes)),
                total_attempts, json.dumps(list(techniques)), threat_score, ip
            ))
            
            # Generate alert if seen in multiple regions
            if len(regions) >= 2:
                self._create_correlation_alert(conn, ip, list(regions), threat_score)
        else:
            # Create new profile
            threat_score = self._calculate_threat_score(1, 1, event.get('techniques', []))
            conn.execute("""
                INSERT INTO attackers (ip, first_seen, last_seen, regions, node_ids,
                                       total_attempts, techniques, threat_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ip, now, now, json.dumps([region]), json.dumps([node_id]),
                1, json.dumps(event.get('techniques', [])), threat_score
            ))
    
    def _calculate_threat_score(self, num_regions: int, total_attempts: int, 
                                 techniques: List[str]) -> float:
        """Calculate threat score based on activity patterns"""
        # Base score from attempt volume
        volume_score = min(total_attempts / 100, 1.0) * 30
        
        # Multi-region bonus (indicates sophisticated attacker)
        region_score = min(num_regions / 3, 1.0) * 40
        
        # Technique diversity bonus
        technique_score = min(len(techniques) / 5, 1.0) * 30
        
        return round(volume_score + region_score + technique_score, 2)
    
    def _create_correlation_alert(self, conn, ip: str, regions: List[str], threat_score: float):
        """Create alert for cross-region attacker"""
        alert_id = str(uuid.uuid4())
        severity = "high" if threat_score > 60 else "medium" if threat_score > 30 else "low"
        
        conn.execute("""
            INSERT OR IGNORE INTO alerts (alert_id, created_at, alert_type, severity,
                                         title, description, attacker_ip, regions)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert_id,
            datetime.utcnow().isoformat() + 'Z',
            'cross_region_attacker',
            severity,
            f"Cross-Region Attack: {ip}",
            f"Attacker {ip} detected in {len(regions)} regions: {', '.join(regions)}",
            ip,
            json.dumps(regions)
        ))
    
    def add_ioc(self, ioc: IOC) -> bool:
        """Add or update IOC"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO iocs (ioc_id, ioc_type, value, source_region, source_node,
                                 first_seen, last_seen, confidence, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ioc_type, value) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    confidence = MAX(iocs.confidence, excluded.confidence)
            """, (
                ioc.ioc_id, ioc.ioc_type, ioc.value, ioc.source_region,
                ioc.source_node, ioc.first_seen, ioc.last_seen,
                ioc.confidence, json.dumps(ioc.tags)
            ))
            return True
    
    def get_iocs(self, ioc_type: Optional[str] = None, 
                 min_confidence: float = 0.0) -> List[IOC]:
        """Get IOCs with optional filtering"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            query = "SELECT * FROM iocs WHERE confidence >= ?"
            params = [min_confidence]
            if ioc_type:
                query += " AND ioc_type = ?"
                params.append(ioc_type)
            query += " ORDER BY last_seen DESC LIMIT 1000"
            
            rows = conn.execute(query, params).fetchall()
            return [IOC(
                ioc_id=r['ioc_id'],
                ioc_type=r['ioc_type'],
                value=r['value'],
                source_region=r['source_region'],
                source_node=r['source_node'],
                first_seen=r['first_seen'],
                last_seen=r['last_seen'],
                confidence=r['confidence'],
                tags=json.loads(r['tags'] or '[]')
            ) for r in rows]
    
    def get_attackers(self, min_score: float = 0.0, 
                       multi_region_only: bool = False) -> List[AttackerSighting]:
        """Get attacker profiles"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            query = "SELECT * FROM attackers WHERE threat_score >= ?"
            params = [min_score]
            
            rows = conn.execute(query, params).fetchall()
            attackers = []
            for r in rows:
                regions = json.loads(r['regions'])
                if multi_region_only and len(regions) < 2:
                    continue
                attackers.append(AttackerSighting(
                    ip=r['ip'],
                    first_seen=r['first_seen'],
                    last_seen=r['last_seen'],
                    regions=regions,
                    node_ids=json.loads(r['node_ids']),
                    total_attempts=r['total_attempts'],
                    techniques=json.loads(r['techniques'] or '[]'),
                    threat_score=r['threat_score']
                ))
            return sorted(attackers, key=lambda x: x.threat_score, reverse=True)
    
    def get_alerts(self, unacknowledged_only: bool = True) -> List[dict]:
        """Get correlation alerts"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            query = "SELECT * FROM alerts"
            if unacknowledged_only:
                query += " WHERE acknowledged = 0"
            query += " ORDER BY created_at DESC LIMIT 100"
            
            rows = conn.execute(query).fetchall()
            return [dict(r) for r in rows]
    
    def get_stats(self) -> dict:
        """Get mesh statistics"""
        with sqlite3.connect(self.db_path) as conn:
            stats = {
                'nodes': conn.execute("SELECT COUNT(*) FROM nodes WHERE status='active'").fetchone()[0],
                'total_events': conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                'unique_attackers': conn.execute("SELECT COUNT(*) FROM attackers").fetchone()[0],
                'multi_region_attackers': conn.execute(
                    "SELECT COUNT(*) FROM attackers WHERE json_array_length(regions) >= 2"
                ).fetchone()[0],
                'iocs': conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0],
                'pending_alerts': conn.execute(
                    "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0"
                ).fetchone()[0],
                'regions': [r[0] for r in conn.execute(
                    "SELECT DISTINCT region FROM nodes WHERE status='active'"
                ).fetchall()]
            }
            return stats


# =============================================================================
# Mesh Coordinator Server
# =============================================================================

class MeshCoordinator:
    """Central mesh coordinator API server"""
    
    def __init__(self, port: int = 8443, token: str = None, db_path: str = None):
        self.port = port
        self.token = token or os.environ.get('COORDINATOR_TOKEN', 'changeme')
        self.coordinator_id = os.environ.get('COORDINATOR_ID', str(uuid.uuid4())[:8])
        self.db = IOCDatabase(db_path or os.environ.get('DATABASE_URL', '/data/mesh/ioc.db'))
        self.app = web.Application(middlewares=[self._auth_middleware])
        self._setup_routes()
    
    @web.middleware
    async def _auth_middleware(self, request, handler):
        """Verify authentication token"""
        if request.path in ['/', '/health']:
            return await handler(request)
        
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer ') or auth[7:] != self.token:
            return web.json_response({'error': 'Unauthorized'}, status=401)
        
        return await handler(request)
    
    def _setup_routes(self):
        """Setup API routes"""
        self.app.router.add_get('/', self._handle_root)
        self.app.router.add_get('/health', self._handle_health)
        self.app.router.add_get('/stats', self._handle_stats)
        
        # Node management
        self.app.router.add_post('/nodes/register', self._handle_register)
        self.app.router.add_post('/nodes/heartbeat', self._handle_heartbeat)
        self.app.router.add_get('/nodes', self._handle_list_nodes)
        
        # Event ingestion
        self.app.router.add_post('/events', self._handle_event)
        self.app.router.add_post('/events/batch', self._handle_events_batch)
        
        # IOC management
        self.app.router.add_post('/iocs', self._handle_add_ioc)
        self.app.router.add_get('/iocs', self._handle_list_iocs)
        
        # Correlation & alerts
        self.app.router.add_get('/attackers', self._handle_list_attackers)
        self.app.router.add_get('/alerts', self._handle_list_alerts)
    
    async def _handle_root(self, request):
        """Root endpoint"""
        return web.json_response({
            'service': 'honeyclaw-mesh-coordinator',
            'coordinator_id': self.coordinator_id,
            'version': '1.0.0'
        })
    
    async def _handle_health(self, request):
        """Health check endpoint"""
        stats = self.db.get_stats()
        return web.json_response({
            'status': 'healthy',
            'coordinator_id': self.coordinator_id,
            'nodes': stats['nodes'],
            'regions': stats['regions']
        })
    
    async def _handle_stats(self, request):
        """Get mesh statistics"""
        return web.json_response(self.db.get_stats())
    
    async def _handle_register(self, request):
        """Register a new mesh node"""
        try:
            data = await request.json()
            node = MeshNode(
                node_id=data.get('node_id', str(uuid.uuid4())),
                region=data['region'],
                hostname=data['hostname'],
                ip_address=data.get('ip_address', ''),
                services=data.get('services', []),
                registered_at=datetime.utcnow().isoformat() + 'Z',
                last_heartbeat=datetime.utcnow().isoformat() + 'Z',
                version=data.get('version', '1.0.0')
            )
            self.db.register_node(node)
            print(f"[MESH] Node registered: {node.node_id} ({node.region})", flush=True)
            return web.json_response({
                'status': 'registered',
                'node_id': node.node_id,
                'coordinator_id': self.coordinator_id
            })
        except Exception as e:
            return web.json_response({'error': str(e)}, status=400)
    
    async def _handle_heartbeat(self, request):
        """Process node heartbeat"""
        try:
            data = await request.json()
            node_id = data['node_id']
            
            # Update heartbeat timestamp
            with sqlite3.connect(self.db.db_path) as conn:
                conn.execute(
                    "UPDATE nodes SET last_heartbeat = ?, status = 'active' WHERE node_id = ?",
                    (datetime.utcnow().isoformat() + 'Z', node_id)
                )
            
            return web.json_response({
                'status': 'ok',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            })
        except Exception as e:
            return web.json_response({'error': str(e)}, status=400)
    
    async def _handle_list_nodes(self, request):
        """List active nodes"""
        nodes = self.db.get_active_nodes()
        return web.json_response({
            'nodes': [asdict(n) for n in nodes]
        })
    
    async def _handle_event(self, request):
        """Record single attack event"""
        try:
            data = await request.json()
            event_id = self.db.record_event(
                data['node_id'],
                data['region'],
                data['event']
            )
            return web.json_response({
                'status': 'recorded',
                'event_id': event_id
            })
        except Exception as e:
            return web.json_response({'error': str(e)}, status=400)
    
    async def _handle_events_batch(self, request):
        """Record batch of events"""
        try:
            data = await request.json()
            event_ids = []
            for event in data.get('events', []):
                event_id = self.db.record_event(
                    event['node_id'],
                    event['region'],
                    event['event']
                )
                event_ids.append(event_id)
            
            return web.json_response({
                'status': 'recorded',
                'count': len(event_ids)
            })
        except Exception as e:
            return web.json_response({'error': str(e)}, status=400)
    
    async def _handle_add_ioc(self, request):
        """Add IOC"""
        try:
            data = await request.json()
            ioc = IOC(
                ioc_id=str(uuid.uuid4()),
                ioc_type=data['type'],
                value=data['value'],
                source_region=data.get('region'),
                source_node=data.get('node_id'),
                first_seen=datetime.utcnow().isoformat() + 'Z',
                last_seen=datetime.utcnow().isoformat() + 'Z',
                confidence=data.get('confidence', 0.5),
                tags=data.get('tags', [])
            )
            self.db.add_ioc(ioc)
            return web.json_response({
                'status': 'added',
                'ioc_id': ioc.ioc_id
            })
        except Exception as e:
            return web.json_response({'error': str(e)}, status=400)
    
    async def _handle_list_iocs(self, request):
        """List IOCs"""
        ioc_type = request.query.get('type')
        min_confidence = float(request.query.get('min_confidence', 0))
        iocs = self.db.get_iocs(ioc_type, min_confidence)
        return web.json_response({
            'iocs': [asdict(i) for i in iocs]
        })
    
    async def _handle_list_attackers(self, request):
        """List attacker profiles"""
        min_score = float(request.query.get('min_score', 0))
        multi_region = request.query.get('multi_region', 'false').lower() == 'true'
        attackers = self.db.get_attackers(min_score, multi_region)
        return web.json_response({
            'attackers': [asdict(a) for a in attackers]
        })
    
    async def _handle_list_alerts(self, request):
        """List correlation alerts"""
        unacked = request.query.get('unacknowledged', 'true').lower() == 'true'
        alerts = self.db.get_alerts(unacked)
        return web.json_response({'alerts': alerts})
    
    async def start(self):
        """Start the coordinator server"""
        print(f"[MESH] Starting coordinator {self.coordinator_id} on port {self.port}", flush=True)
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', self.port)
        await site.start()
        print(f"[MESH] Coordinator running on http://0.0.0.0:{self.port}", flush=True)
        
        # Keep running
        while True:
            await asyncio.sleep(3600)


async def main():
    """Main entry point"""
    port = int(os.environ.get('COORDINATOR_PORT', 8443))
    coordinator = MeshCoordinator(port=port)
    await coordinator.start()


if __name__ == '__main__':
    asyncio.run(main())
