#!/usr/bin/env python3
"""
Honey Claw - Mesh Incentive Mechanism

BitTorrent-style "contribute to consume" incentive system for threat intelligence.
Nodes must contribute threat intel data (events, IOCs) and host data shards
to earn query credits. You can only query the collective intelligence if you
are actively hosting and contributing to it.

Core mechanics:
  - ContributionLedger: Tracks each node's contribution ratio (upload vs download)
  - ShardManager: Assigns and manages data shards across nodes (like torrent pieces)
  - QueryGate: Enforces the "seed to leech" rule — gated access based on ratio
  - ThreatIntelFeed: Local queryable service backed by hosted shards

Environment variables:
  INCENTIVE_ENABLED           - Enable incentive system (default: true if mesh enabled)
  INCENTIVE_BOOTSTRAP_CREDITS - Initial credits for new nodes (default: 50)
  INCENTIVE_CREDIT_PER_EVENT  - Credits earned per event contributed (default: 1)
  INCENTIVE_CREDIT_PER_IOC    - Credits earned per IOC contributed (default: 5)
  INCENTIVE_COST_PER_QUERY    - Credits spent per query (default: 2)
  INCENTIVE_SHARD_BONUS       - Credits earned per shard hosted per hour (default: 10)
  INCENTIVE_MIN_RATIO         - Minimum contribution ratio for queries (default: 0.5)
"""

import hashlib
import json
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class IncentiveConfig:
    """Configuration for the incentive mechanism."""
    enabled: bool = True
    bootstrap_credits: int = 50
    credit_per_event: int = 1
    credit_per_ioc: int = 5
    cost_per_query: int = 2
    shard_bonus_per_hour: int = 10
    min_ratio: float = 0.5
    shard_size: int = 1000        # Max records per shard
    max_shards_per_node: int = 20  # Max shards a node can host
    shard_replication: int = 3     # Replicate each shard to N nodes
    stale_shard_hours: int = 24    # Shards not refreshed in this time are reassigned

    @classmethod
    def from_env(cls) -> 'IncentiveConfig':
        """Load from environment variables."""
        return cls(
            enabled=os.environ.get('INCENTIVE_ENABLED', 'true').lower() == 'true',
            bootstrap_credits=int(os.environ.get('INCENTIVE_BOOTSTRAP_CREDITS', '50')),
            credit_per_event=int(os.environ.get('INCENTIVE_CREDIT_PER_EVENT', '1')),
            credit_per_ioc=int(os.environ.get('INCENTIVE_CREDIT_PER_IOC', '5')),
            cost_per_query=int(os.environ.get('INCENTIVE_COST_PER_QUERY', '2')),
            shard_bonus_per_hour=int(os.environ.get('INCENTIVE_SHARD_BONUS', '10')),
            min_ratio=float(os.environ.get('INCENTIVE_MIN_RATIO', '0.5')),
        )


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class NodeLedgerEntry:
    """Ledger entry tracking a node's contributions and consumption."""
    node_id: str
    credits: int = 0
    events_contributed: int = 0
    iocs_contributed: int = 0
    queries_made: int = 0
    shards_hosted: int = 0
    contribution_ratio: float = 0.0
    first_seen: str = ""
    last_active: str = ""
    status: str = "active"  # active, throttled, suspended


@dataclass
class DataShard:
    """A shard of threat intelligence data distributed across the mesh."""
    shard_id: str
    shard_type: str  # events, iocs, attackers
    record_count: int = 0
    created_at: str = ""
    updated_at: str = ""
    checksum: str = ""
    assigned_nodes: List[str] = field(default_factory=list)
    # Content stored as JSON — the actual intel records in this shard
    content_summary: str = ""


@dataclass
class QueryResult:
    """Result of a gated query against the mesh."""
    success: bool
    data: List[dict] = field(default_factory=list)
    credits_spent: int = 0
    credits_remaining: int = 0
    error: str = ""
    shard_sources: List[str] = field(default_factory=list)


# =============================================================================
# Contribution Ledger
# =============================================================================

class ContributionLedger:
    """
    Tracks each node's contribution ratio to the mesh network.

    Like BitTorrent's tit-for-tat, nodes earn credits by:
      - Contributing events (attack telemetry)
      - Contributing IOCs (indicators of compromise)
      - Hosting data shards (storing collective intel locally)

    Nodes spend credits by:
      - Querying the collective threat intel database

    If a node's ratio drops below the minimum, queries are denied
    until the node contributes more.
    """

    def __init__(self, db_path: str, config: IncentiveConfig = None):
        self.db_path = db_path
        self.config = config or IncentiveConfig()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize ledger tables."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS ledger (
                    node_id TEXT PRIMARY KEY,
                    credits INTEGER DEFAULT 0,
                    events_contributed INTEGER DEFAULT 0,
                    iocs_contributed INTEGER DEFAULT 0,
                    queries_made INTEGER DEFAULT 0,
                    shards_hosted INTEGER DEFAULT 0,
                    contribution_ratio REAL DEFAULT 0.0,
                    first_seen TEXT NOT NULL,
                    last_active TEXT NOT NULL,
                    status TEXT DEFAULT 'active'
                );

                CREATE TABLE IF NOT EXISTS credit_log (
                    log_id TEXT PRIMARY KEY,
                    node_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    amount INTEGER NOT NULL,
                    balance_after INTEGER NOT NULL,
                    description TEXT,
                    FOREIGN KEY (node_id) REFERENCES ledger(node_id)
                );

                CREATE INDEX IF NOT EXISTS idx_credit_log_node
                    ON credit_log(node_id);
                CREATE INDEX IF NOT EXISTS idx_credit_log_time
                    ON credit_log(timestamp);
            """)

    def register_node(self, node_id: str) -> NodeLedgerEntry:
        """Register a new node with bootstrap credits."""
        now = datetime.utcnow().isoformat() + 'Z'
        with sqlite3.connect(self.db_path) as conn:
            # Check if already registered
            row = conn.execute(
                "SELECT * FROM ledger WHERE node_id = ?", (node_id,)
            ).fetchone()

            if row:
                return self._row_to_entry(row)

            # New node gets bootstrap credits
            conn.execute("""
                INSERT INTO ledger (node_id, credits, first_seen, last_active, status)
                VALUES (?, ?, ?, ?, 'active')
            """, (node_id, self.config.bootstrap_credits, now, now))

            self._log_credit(conn, node_id, 'bootstrap',
                             self.config.bootstrap_credits,
                             self.config.bootstrap_credits,
                             'Initial bootstrap credits for new node')

        return NodeLedgerEntry(
            node_id=node_id,
            credits=self.config.bootstrap_credits,
            first_seen=now,
            last_active=now,
        )

    def record_contribution(self, node_id: str, contribution_type: str,
                            count: int = 1) -> int:
        """
        Record a contribution from a node and award credits.

        Args:
            node_id: Contributing node
            contribution_type: 'event' or 'ioc'
            count: Number of items contributed

        Returns:
            Credits awarded
        """
        if contribution_type == 'event':
            credits = count * self.config.credit_per_event
            column = 'events_contributed'
        elif contribution_type == 'ioc':
            credits = count * self.config.credit_per_ioc
            column = 'iocs_contributed'
        else:
            return 0

        now = datetime.utcnow().isoformat() + 'Z'

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(f"""
                UPDATE ledger SET
                    credits = credits + ?,
                    {column} = {column} + ?,
                    last_active = ?
                WHERE node_id = ?
            """, (credits, count, now, node_id))

            # Update ratio
            self._update_ratio(conn, node_id)

            # Log credit
            row = conn.execute(
                "SELECT credits FROM ledger WHERE node_id = ?", (node_id,)
            ).fetchone()
            balance = row[0] if row else credits

            self._log_credit(conn, node_id, f'contribute_{contribution_type}',
                             credits, balance,
                             f'Contributed {count} {contribution_type}(s)')

        return credits

    def record_shard_hosting(self, node_id: str, shard_count: int) -> int:
        """
        Award credits for hosting data shards.

        Args:
            node_id: Hosting node
            shard_count: Number of shards being hosted

        Returns:
            Credits awarded
        """
        credits = shard_count * self.config.shard_bonus_per_hour
        now = datetime.utcnow().isoformat() + 'Z'

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE ledger SET
                    credits = credits + ?,
                    shards_hosted = ?,
                    last_active = ?
                WHERE node_id = ?
            """, (credits, shard_count, now, node_id))

            self._update_ratio(conn, node_id)

            row = conn.execute(
                "SELECT credits FROM ledger WHERE node_id = ?", (node_id,)
            ).fetchone()
            balance = row[0] if row else credits

            self._log_credit(conn, node_id, 'shard_hosting', credits, balance,
                             f'Hosting {shard_count} shard(s)')

        return credits

    def check_query_allowed(self, node_id: str) -> Tuple[bool, str]:
        """
        Check if a node is allowed to query the mesh.

        Returns:
            (allowed, reason) tuple
        """
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT credits, contribution_ratio, status FROM ledger WHERE node_id = ?",
                (node_id,)
            ).fetchone()

            if not row:
                return False, "Node not registered in mesh"

            credits, ratio, status = row

            if status == 'suspended':
                return False, "Node is suspended — contribute data to reactivate"

            if credits < self.config.cost_per_query:
                return False, (
                    f"Insufficient credits ({credits} available, "
                    f"{self.config.cost_per_query} required). "
                    "Contribute events or IOCs to earn credits."
                )

            if ratio < self.config.min_ratio:
                return False, (
                    f"Contribution ratio too low ({ratio:.2f}, "
                    f"minimum {self.config.min_ratio:.2f}). "
                    "Host more shards or contribute more data."
                )

            return True, "OK"

    def deduct_query(self, node_id: str) -> int:
        """
        Deduct credits for a query. Call after check_query_allowed.

        Returns:
            Remaining credits
        """
        cost = self.config.cost_per_query
        now = datetime.utcnow().isoformat() + 'Z'

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE ledger SET
                    credits = credits - ?,
                    queries_made = queries_made + 1,
                    last_active = ?
                WHERE node_id = ?
            """, (cost, now, node_id))

            self._update_ratio(conn, node_id)

            row = conn.execute(
                "SELECT credits FROM ledger WHERE node_id = ?", (node_id,)
            ).fetchone()
            balance = row[0] if row else 0

            self._log_credit(conn, node_id, 'query', -cost, balance,
                             'Threat intel query')

        return balance

    def get_node_standing(self, node_id: str) -> Optional[NodeLedgerEntry]:
        """Get a node's current ledger entry."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM ledger WHERE node_id = ?", (node_id,)
            ).fetchone()
            if row:
                return self._row_to_entry(row)
        return None

    def get_leaderboard(self, limit: int = 20) -> List[NodeLedgerEntry]:
        """Get top contributing nodes."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM ledger ORDER BY contribution_ratio DESC, credits DESC LIMIT ?",
                (limit,)
            ).fetchall()
            return [self._row_to_entry(r) for r in rows]

    def get_mesh_stats(self) -> dict:
        """Get aggregate mesh incentive statistics."""
        with sqlite3.connect(self.db_path) as conn:
            total_nodes = conn.execute(
                "SELECT COUNT(*) FROM ledger"
            ).fetchone()[0]
            active_nodes = conn.execute(
                "SELECT COUNT(*) FROM ledger WHERE status = 'active'"
            ).fetchone()[0]
            total_events = conn.execute(
                "SELECT COALESCE(SUM(events_contributed), 0) FROM ledger"
            ).fetchone()[0]
            total_iocs = conn.execute(
                "SELECT COALESCE(SUM(iocs_contributed), 0) FROM ledger"
            ).fetchone()[0]
            total_queries = conn.execute(
                "SELECT COALESCE(SUM(queries_made), 0) FROM ledger"
            ).fetchone()[0]
            total_shards = conn.execute(
                "SELECT COALESCE(SUM(shards_hosted), 0) FROM ledger"
            ).fetchone()[0]
            avg_ratio = conn.execute(
                "SELECT COALESCE(AVG(contribution_ratio), 0) FROM ledger"
            ).fetchone()[0]

            return {
                'total_nodes': total_nodes,
                'active_nodes': active_nodes,
                'total_events_contributed': total_events,
                'total_iocs_contributed': total_iocs,
                'total_queries_served': total_queries,
                'total_shards_hosted': total_shards,
                'avg_contribution_ratio': round(avg_ratio, 3),
            }

    def _update_ratio(self, conn, node_id: str):
        """Recalculate a node's contribution ratio."""
        row = conn.execute(
            "SELECT events_contributed, iocs_contributed, queries_made, shards_hosted "
            "FROM ledger WHERE node_id = ?",
            (node_id,)
        ).fetchone()

        if not row:
            return

        events, iocs, queries, shards = row

        # Contribution score: weighted sum of contributions
        contribution_score = (
            events * self.config.credit_per_event +
            iocs * self.config.credit_per_ioc +
            shards * self.config.shard_bonus_per_hour
        )

        # Consumption score: weighted sum of queries
        consumption_score = max(queries * self.config.cost_per_query, 1)

        ratio = round(contribution_score / consumption_score, 3)

        # Update status based on ratio
        status = 'active'
        if ratio < self.config.min_ratio / 2:
            status = 'suspended'
        elif ratio < self.config.min_ratio:
            status = 'throttled'

        conn.execute(
            "UPDATE ledger SET contribution_ratio = ?, status = ? WHERE node_id = ?",
            (ratio, status, node_id)
        )

    def _log_credit(self, conn, node_id: str, action: str, amount: int,
                    balance: int, description: str):
        """Write a credit transaction log entry."""
        conn.execute("""
            INSERT INTO credit_log (log_id, node_id, timestamp, action, amount,
                                    balance_after, description)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            str(uuid.uuid4()), node_id,
            datetime.utcnow().isoformat() + 'Z',
            action, amount, balance, description
        ))

    @staticmethod
    def _row_to_entry(row) -> NodeLedgerEntry:
        """Convert a DB row to NodeLedgerEntry."""
        return NodeLedgerEntry(
            node_id=row[0],
            credits=row[1],
            events_contributed=row[2],
            iocs_contributed=row[3],
            queries_made=row[4],
            shards_hosted=row[5],
            contribution_ratio=row[6],
            first_seen=row[7],
            last_active=row[8],
            status=row[9],
        )


# =============================================================================
# Shard Manager
# =============================================================================

class ShardManager:
    """
    Manages data shards distributed across the mesh network.

    Like BitTorrent pieces, threat intel data is split into shards.
    Each shard is replicated to multiple nodes. Nodes that host more
    shards earn more credits and can make more queries.

    Shard types:
      - events: Attack event telemetry
      - iocs: Indicators of compromise
      - attackers: Attacker profiles and cross-region sightings
    """

    def __init__(self, db_path: str, config: IncentiveConfig = None):
        self.db_path = db_path
        self.config = config or IncentiveConfig()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize shard tables."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS shards (
                    shard_id TEXT PRIMARY KEY,
                    shard_type TEXT NOT NULL,
                    record_count INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    checksum TEXT,
                    content_summary TEXT
                );

                CREATE TABLE IF NOT EXISTS shard_assignments (
                    shard_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    assigned_at TEXT NOT NULL,
                    last_verified TEXT NOT NULL,
                    status TEXT DEFAULT 'assigned',
                    PRIMARY KEY (shard_id, node_id)
                );

                CREATE TABLE IF NOT EXISTS shard_data (
                    shard_id TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    record_data TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (shard_id, record_id)
                );

                CREATE INDEX IF NOT EXISTS idx_shard_type
                    ON shards(shard_type);
                CREATE INDEX IF NOT EXISTS idx_shard_assignments_node
                    ON shard_assignments(node_id);
                CREATE INDEX IF NOT EXISTS idx_shard_data_type
                    ON shard_data(record_type);
            """)

    def create_shard(self, shard_type: str, records: List[dict]) -> DataShard:
        """
        Create a new data shard from a batch of records.

        Args:
            shard_type: Type of shard (events, iocs, attackers)
            records: List of record dicts to store in this shard

        Returns:
            The created DataShard
        """
        shard_id = f"shard_{shard_type}_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat() + 'Z'
        content = json.dumps(records, sort_keys=True)
        checksum = hashlib.sha256(content.encode()).hexdigest()[:16]

        # Summarize what's in this shard
        if shard_type == 'events':
            ips = set(r.get('source_ip', '') for r in records if r.get('source_ip'))
            summary = f"{len(records)} events from {len(ips)} unique IPs"
        elif shard_type == 'iocs':
            types = set(r.get('ioc_type', '') for r in records)
            summary = f"{len(records)} IOCs of types: {', '.join(types)}"
        elif shard_type == 'attackers':
            summary = f"{len(records)} attacker profiles"
        else:
            summary = f"{len(records)} records"

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO shards (shard_id, shard_type, record_count,
                                   created_at, updated_at, checksum, content_summary)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (shard_id, shard_type, len(records), now, now, checksum, summary))

            # Store individual records
            for record in records:
                record_id = record.get('id', str(uuid.uuid4()))
                conn.execute("""
                    INSERT OR REPLACE INTO shard_data
                        (shard_id, record_id, record_type, record_data, created_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (shard_id, record_id, shard_type,
                      json.dumps(record), now))

        return DataShard(
            shard_id=shard_id,
            shard_type=shard_type,
            record_count=len(records),
            created_at=now,
            updated_at=now,
            checksum=checksum,
            content_summary=summary,
        )

    def assign_shard(self, shard_id: str, node_id: str) -> bool:
        """Assign a shard to a node for hosting."""
        now = datetime.utcnow().isoformat() + 'Z'
        with sqlite3.connect(self.db_path) as conn:
            # Check max shards per node
            count = conn.execute(
                "SELECT COUNT(*) FROM shard_assignments WHERE node_id = ? AND status = 'assigned'",
                (node_id,)
            ).fetchone()[0]

            if count >= self.config.max_shards_per_node:
                return False

            conn.execute("""
                INSERT OR REPLACE INTO shard_assignments
                    (shard_id, node_id, assigned_at, last_verified, status)
                VALUES (?, ?, ?, ?, 'assigned')
            """, (shard_id, node_id, now, now))

        return True

    def get_node_shards(self, node_id: str) -> List[DataShard]:
        """Get all shards assigned to a node."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT s.* FROM shards s
                JOIN shard_assignments sa ON s.shard_id = sa.shard_id
                WHERE sa.node_id = ? AND sa.status = 'assigned'
            """, (node_id,)).fetchall()

            shards = []
            for r in rows:
                # Get assigned nodes for this shard
                assigned = conn.execute(
                    "SELECT node_id FROM shard_assignments WHERE shard_id = ? AND status = 'assigned'",
                    (r['shard_id'],)
                ).fetchall()

                shards.append(DataShard(
                    shard_id=r['shard_id'],
                    shard_type=r['shard_type'],
                    record_count=r['record_count'],
                    created_at=r['created_at'],
                    updated_at=r['updated_at'],
                    checksum=r['checksum'],
                    assigned_nodes=[a[0] for a in assigned],
                    content_summary=r['content_summary'],
                ))

            return shards

    def get_shard_data(self, shard_id: str) -> List[dict]:
        """Get all records in a shard."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT record_data FROM shard_data WHERE shard_id = ?",
                (shard_id,)
            ).fetchall()
            return [json.loads(r[0]) for r in rows]

    def get_shards_needing_assignment(self, active_node_ids: List[str]) -> List[DataShard]:
        """Find shards that need more replicas assigned."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM shards").fetchall()

            needing = []
            for r in rows:
                assigned = conn.execute(
                    "SELECT node_id FROM shard_assignments "
                    "WHERE shard_id = ? AND status = 'assigned'",
                    (r['shard_id'],)
                ).fetchall()

                assigned_ids = [a[0] for a in assigned]
                active_assigned = [n for n in assigned_ids if n in active_node_ids]

                if len(active_assigned) < self.config.shard_replication:
                    needing.append(DataShard(
                        shard_id=r['shard_id'],
                        shard_type=r['shard_type'],
                        record_count=r['record_count'],
                        created_at=r['created_at'],
                        updated_at=r['updated_at'],
                        checksum=r['checksum'],
                        assigned_nodes=active_assigned,
                        content_summary=r['content_summary'],
                    ))

            return needing

    def verify_shard(self, shard_id: str, node_id: str) -> bool:
        """Mark a shard as verified (node confirms it still has the data)."""
        now = datetime.utcnow().isoformat() + 'Z'
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE shard_assignments SET last_verified = ?
                WHERE shard_id = ? AND node_id = ?
            """, (now, shard_id, node_id))
        return True

    def get_shard_stats(self) -> dict:
        """Get shard distribution statistics."""
        with sqlite3.connect(self.db_path) as conn:
            total_shards = conn.execute(
                "SELECT COUNT(*) FROM shards"
            ).fetchone()[0]
            total_records = conn.execute(
                "SELECT COALESCE(SUM(record_count), 0) FROM shards"
            ).fetchone()[0]
            total_assignments = conn.execute(
                "SELECT COUNT(*) FROM shard_assignments WHERE status = 'assigned'"
            ).fetchone()[0]
            by_type = conn.execute(
                "SELECT shard_type, COUNT(*), SUM(record_count) FROM shards GROUP BY shard_type"
            ).fetchall()

            return {
                'total_shards': total_shards,
                'total_records': total_records,
                'total_assignments': total_assignments,
                'avg_replication': (
                    round(total_assignments / total_shards, 2)
                    if total_shards > 0 else 0
                ),
                'by_type': {
                    t: {'shards': c, 'records': r}
                    for t, c, r in by_type
                },
            }


# =============================================================================
# Query Gate
# =============================================================================

class QueryGate:
    """
    Enforces the "contribute to consume" rule.

    Before any query is served, the gate checks:
    1. Is the node registered?
    2. Does the node have sufficient credits?
    3. Is the node's contribution ratio above the minimum?
    4. Is the node actively hosting shards?

    If all checks pass, credits are deducted and the query proceeds.
    """

    def __init__(self, ledger: ContributionLedger, shard_mgr: ShardManager,
                 config: IncentiveConfig = None):
        self.ledger = ledger
        self.shard_mgr = shard_mgr
        self.config = config or IncentiveConfig()

    def authorize_query(self, node_id: str) -> Tuple[bool, str]:
        """
        Check if a node is authorized to query the mesh.

        Returns:
            (authorized, reason) — if not authorized, reason explains why
        """
        # Check ledger standing
        allowed, reason = self.ledger.check_query_allowed(node_id)
        if not allowed:
            return False, reason

        # Check that node is hosting at least one shard
        shards = self.shard_mgr.get_node_shards(node_id)
        if not shards:
            return False, (
                "Node is not hosting any data shards. "
                "You must host shards to participate in the mesh. "
                "Request shard assignments from the coordinator."
            )

        return True, "OK"

    def execute_query(self, node_id: str, query_type: str,
                      filters: dict = None) -> QueryResult:
        """
        Execute a gated query against the mesh data.

        Args:
            node_id: Requesting node
            query_type: Type of data to query (events, iocs, attackers)
            filters: Optional filters (ip, type, min_confidence, etc.)

        Returns:
            QueryResult with data or error
        """
        # Authorization check
        authorized, reason = self.authorize_query(node_id)
        if not authorized:
            return QueryResult(success=False, error=reason)

        # Deduct credits
        remaining = self.ledger.deduct_query(node_id)

        # Gather data from all relevant shards
        filters = filters or {}
        results = []
        shard_sources = []

        with sqlite3.connect(self.shard_mgr.db_path) as conn:
            # Find matching shards
            query = "SELECT shard_id FROM shards WHERE shard_type = ?"
            params = [query_type]

            shard_ids = [r[0] for r in conn.execute(query, params).fetchall()]

            for shard_id in shard_ids:
                records = self.shard_mgr.get_shard_data(shard_id)
                matched = self._filter_records(records, filters)
                if matched:
                    results.extend(matched)
                    shard_sources.append(shard_id)

        # Deduplicate by record ID if present
        seen_ids = set()
        deduplicated = []
        for record in results:
            rid = record.get('id', record.get('ip', record.get('value', str(record))))
            if rid not in seen_ids:
                seen_ids.add(rid)
                deduplicated.append(record)

        return QueryResult(
            success=True,
            data=deduplicated,
            credits_spent=self.config.cost_per_query,
            credits_remaining=remaining,
            shard_sources=shard_sources,
        )

    @staticmethod
    def _filter_records(records: List[dict], filters: dict) -> List[dict]:
        """Apply filters to a list of records."""
        if not filters:
            return records

        matched = []
        for record in records:
            match = True

            # IP filter
            if 'ip' in filters:
                if record.get('source_ip') != filters['ip'] and record.get('ip') != filters['ip']:
                    match = False

            # IOC type filter
            if 'ioc_type' in filters:
                if record.get('ioc_type') != filters['ioc_type']:
                    match = False

            # Minimum confidence filter
            if 'min_confidence' in filters:
                if record.get('confidence', 0) < filters['min_confidence']:
                    match = False

            # Minimum threat score filter
            if 'min_score' in filters:
                if record.get('threat_score', 0) < filters['min_score']:
                    match = False

            # Time range filter
            if 'since' in filters:
                ts = record.get('timestamp', record.get('last_seen', ''))
                if ts and ts < filters['since']:
                    match = False

            if match:
                matched.append(record)

        return matched


# =============================================================================
# Threat Intel Feed — the queryable local service
# =============================================================================

class ThreatIntelFeed:
    """
    Local queryable threat intelligence service.

    This is the node-local service that allows anyone to query the
    collective threat intel — provided they are contributing to the network.
    It acts as the interface between a node and the incentive system.

    Usage:
        feed = ThreatIntelFeed(db_path="/data/mesh/incentive.db")
        feed.register("my-node-id")

        # Contribute data to earn credits
        feed.contribute_events("my-node-id", events)
        feed.contribute_iocs("my-node-id", iocs)

        # Query (costs credits)
        result = feed.query_threat_intel("my-node-id", "iocs",
                                         filters={"ioc_type": "ip"})
    """

    def __init__(self, db_path: str = "/data/mesh/incentive.db",
                 config: IncentiveConfig = None):
        self.config = config or IncentiveConfig.from_env()
        self.db_path = db_path
        self.ledger = ContributionLedger(db_path, self.config)
        self.shards = ShardManager(db_path, self.config)
        self.gate = QueryGate(self.ledger, self.shards, self.config)

    def register(self, node_id: str) -> dict:
        """Register a node and get initial standing."""
        entry = self.ledger.register_node(node_id)
        return asdict(entry)

    def contribute_events(self, node_id: str, events: List[dict]) -> dict:
        """
        Contribute attack events to the mesh. Earns credits.

        Args:
            node_id: Contributing node
            events: List of event dicts

        Returns:
            Dict with credits earned and new shard info
        """
        if not events:
            return {'credits_earned': 0}

        # Create a shard from the contributed events
        shard = self.shards.create_shard('events', events)

        # Assign the shard back to the contributing node (they host what they contribute)
        self.shards.assign_shard(shard.shard_id, node_id)

        # Award credits
        credits = self.ledger.record_contribution(node_id, 'event', len(events))

        return {
            'credits_earned': credits,
            'shard_id': shard.shard_id,
            'record_count': shard.record_count,
        }

    def contribute_iocs(self, node_id: str, iocs: List[dict]) -> dict:
        """
        Contribute IOCs to the mesh. Earns more credits than events.

        Args:
            node_id: Contributing node
            iocs: List of IOC dicts

        Returns:
            Dict with credits earned and new shard info
        """
        if not iocs:
            return {'credits_earned': 0}

        shard = self.shards.create_shard('iocs', iocs)
        self.shards.assign_shard(shard.shard_id, node_id)
        credits = self.ledger.record_contribution(node_id, 'ioc', len(iocs))

        return {
            'credits_earned': credits,
            'shard_id': shard.shard_id,
            'record_count': shard.record_count,
        }

    def host_shard(self, node_id: str, shard_id: str) -> dict:
        """
        Volunteer to host an additional shard. Earns credits over time.

        Args:
            node_id: Hosting node
            shard_id: Shard to host

        Returns:
            Dict with assignment status
        """
        assigned = self.shards.assign_shard(shard_id, node_id)
        if assigned:
            shards = self.shards.get_node_shards(node_id)
            self.ledger.record_shard_hosting(node_id, len(shards))
            return {
                'status': 'assigned',
                'shard_id': shard_id,
                'total_shards_hosted': len(shards),
            }
        return {
            'status': 'rejected',
            'reason': f'Max shards per node ({self.config.max_shards_per_node}) reached',
        }

    def query_threat_intel(self, node_id: str, query_type: str,
                           filters: dict = None) -> dict:
        """
        Query the collective threat intel. Costs credits.

        Args:
            node_id: Querying node
            query_type: Data type (events, iocs, attackers)
            filters: Optional filters

        Returns:
            Dict with results or error
        """
        result = self.gate.execute_query(node_id, query_type, filters)
        return asdict(result)

    def get_standing(self, node_id: str) -> Optional[dict]:
        """Get a node's current standing in the mesh."""
        entry = self.ledger.get_node_standing(node_id)
        if entry:
            shards = self.shards.get_node_shards(node_id)
            result = asdict(entry)
            result['hosted_shards'] = [asdict(s) for s in shards]
            return result
        return None

    def get_available_shards(self, node_id: str) -> List[dict]:
        """
        Get shards available for a node to host (shards needing more replicas).

        Args:
            node_id: The node looking for shards to host

        Returns:
            List of shards that need more hosts
        """
        # Get all active node IDs from the ledger
        with sqlite3.connect(self.db_path) as conn:
            active = conn.execute(
                "SELECT node_id FROM ledger WHERE status = 'active'"
            ).fetchall()
            active_ids = [r[0] for r in active]

        needing = self.shards.get_shards_needing_assignment(active_ids)

        # Exclude shards already hosted by this node
        node_shards = self.shards.get_node_shards(node_id)
        node_shard_ids = {s.shard_id for s in node_shards}

        return [
            asdict(s) for s in needing
            if s.shard_id not in node_shard_ids
        ]

    def get_leaderboard(self) -> List[dict]:
        """Get the mesh contribution leaderboard."""
        entries = self.ledger.get_leaderboard()
        return [asdict(e) for e in entries]

    def get_network_stats(self) -> dict:
        """Get combined mesh + incentive statistics."""
        ledger_stats = self.ledger.get_mesh_stats()
        shard_stats = self.shards.get_shard_stats()
        return {
            'incentive': ledger_stats,
            'shards': shard_stats,
        }
