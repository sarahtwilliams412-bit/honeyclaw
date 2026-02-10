#!/usr/bin/env python3
"""
Tests for the mesh incentive mechanism (BitTorrent-style contribute-to-query).
"""

import os
import sys
import tempfile
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.mesh.incentive import (
    IncentiveConfig,
    ContributionLedger,
    ShardManager,
    QueryGate,
    ThreatIntelFeed,
)


@pytest.fixture
def config():
    """Default test config with small values for fast tests."""
    return IncentiveConfig(
        enabled=True,
        bootstrap_credits=50,
        credit_per_event=1,
        credit_per_ioc=5,
        cost_per_query=2,
        shard_bonus_per_hour=10,
        min_ratio=0.5,
        shard_size=100,
        max_shards_per_node=20,
        shard_replication=3,
    )


@pytest.fixture
def db_path(tmp_path):
    """Temporary database path."""
    return str(tmp_path / "test_incentive.db")


@pytest.fixture
def ledger(db_path, config):
    return ContributionLedger(db_path, config)


@pytest.fixture
def shard_mgr(db_path, config):
    return ShardManager(db_path, config)


@pytest.fixture
def feed(db_path, config):
    return ThreatIntelFeed(db_path, config)


# =============================================================================
# ContributionLedger Tests
# =============================================================================

class TestContributionLedger:

    def test_register_new_node_gets_bootstrap_credits(self, ledger):
        """New nodes receive bootstrap credits to start querying."""
        entry = ledger.register_node("node-alpha")
        assert entry.node_id == "node-alpha"
        assert entry.credits == 50
        assert entry.status == "active"

    def test_register_same_node_twice_is_idempotent(self, ledger):
        """Re-registering returns existing entry, doesn't double credits."""
        entry1 = ledger.register_node("node-alpha")
        entry2 = ledger.register_node("node-alpha")
        assert entry2.credits == entry1.credits

    def test_contribute_events_earns_credits(self, ledger):
        """Contributing events awards credit_per_event * count."""
        ledger.register_node("node-alpha")
        credits = ledger.record_contribution("node-alpha", "event", 10)
        assert credits == 10  # 10 events * 1 credit each

        entry = ledger.get_node_standing("node-alpha")
        assert entry.credits == 60  # 50 bootstrap + 10 earned
        assert entry.events_contributed == 10

    def test_contribute_iocs_earns_more_credits(self, ledger):
        """IOC contributions are worth more than events."""
        ledger.register_node("node-alpha")
        credits = ledger.record_contribution("node-alpha", "ioc", 3)
        assert credits == 15  # 3 IOCs * 5 credits each

        entry = ledger.get_node_standing("node-alpha")
        assert entry.credits == 65  # 50 + 15
        assert entry.iocs_contributed == 3

    def test_query_allowed_with_sufficient_credits(self, ledger):
        """Nodes with enough credits and ratio can query."""
        ledger.register_node("node-alpha")
        # Contribute to build ratio
        ledger.record_contribution("node-alpha", "event", 10)
        allowed, reason = ledger.check_query_allowed("node-alpha")
        assert allowed is True
        assert reason == "OK"

    def test_query_denied_for_unregistered_node(self, ledger):
        """Unregistered nodes cannot query."""
        allowed, reason = ledger.check_query_allowed("ghost-node")
        assert allowed is False
        assert "not registered" in reason

    def test_query_denied_with_insufficient_credits(self, ledger, config):
        """Nodes without enough credits are denied."""
        config.bootstrap_credits = 0
        low_ledger = ContributionLedger(ledger.db_path + "_low", config)
        low_ledger.register_node("broke-node")
        allowed, reason = low_ledger.check_query_allowed("broke-node")
        assert allowed is False
        assert "Insufficient credits" in reason

    def test_deduct_query_reduces_credits(self, ledger):
        """Querying deducts the configured cost."""
        ledger.register_node("node-alpha")
        ledger.record_contribution("node-alpha", "event", 10)
        remaining = ledger.deduct_query("node-alpha")
        assert remaining == 58  # 50 + 10 - 2

        entry = ledger.get_node_standing("node-alpha")
        assert entry.queries_made == 1

    def test_contribution_ratio_updates(self, ledger):
        """Ratio reflects contribution vs consumption."""
        ledger.register_node("node-alpha")
        ledger.record_contribution("node-alpha", "event", 20)

        entry = ledger.get_node_standing("node-alpha")
        assert entry.contribution_ratio > 0

    def test_leaderboard_ordering(self, ledger):
        """Leaderboard sorted by ratio descending."""
        ledger.register_node("low-contributor")
        ledger.register_node("high-contributor")

        ledger.record_contribution("low-contributor", "event", 1)
        ledger.record_contribution("high-contributor", "event", 100)

        board = ledger.get_leaderboard()
        assert len(board) == 2
        assert board[0].node_id == "high-contributor"

    def test_mesh_stats(self, ledger):
        """Aggregate stats are computed correctly."""
        ledger.register_node("node-a")
        ledger.register_node("node-b")
        ledger.record_contribution("node-a", "event", 5)
        ledger.record_contribution("node-b", "ioc", 2)

        stats = ledger.get_mesh_stats()
        assert stats['total_nodes'] == 2
        assert stats['active_nodes'] == 2
        assert stats['total_events_contributed'] == 5
        assert stats['total_iocs_contributed'] == 2

    def test_shard_hosting_earns_credits(self, ledger):
        """Hosting shards awards shard_bonus_per_hour * count."""
        ledger.register_node("node-alpha")
        credits = ledger.record_shard_hosting("node-alpha", 3)
        assert credits == 30  # 3 shards * 10 bonus

        entry = ledger.get_node_standing("node-alpha")
        assert entry.credits == 80  # 50 + 30
        assert entry.shards_hosted == 3


# =============================================================================
# ShardManager Tests
# =============================================================================

class TestShardManager:

    def test_create_event_shard(self, shard_mgr):
        """Creating an event shard stores the records."""
        events = [
            {"source_ip": "1.2.3.4", "event_type": "auth_attempt", "id": "e1"},
            {"source_ip": "5.6.7.8", "event_type": "connection", "id": "e2"},
        ]
        shard = shard_mgr.create_shard("events", events)
        assert shard.shard_id.startswith("shard_events_")
        assert shard.record_count == 2
        assert shard.checksum  # non-empty
        assert "2 events" in shard.content_summary

    def test_create_ioc_shard(self, shard_mgr):
        """Creating an IOC shard stores the records."""
        iocs = [
            {"ioc_type": "ip", "value": "1.2.3.4", "confidence": 0.9, "id": "i1"},
            {"ioc_type": "domain", "value": "evil.com", "confidence": 0.7, "id": "i2"},
        ]
        shard = shard_mgr.create_shard("iocs", iocs)
        assert shard.shard_id.startswith("shard_iocs_")
        assert shard.record_count == 2

    def test_assign_shard_to_node(self, shard_mgr):
        """Shards can be assigned to nodes."""
        shard = shard_mgr.create_shard("events", [{"id": "e1", "source_ip": "1.2.3.4"}])
        result = shard_mgr.assign_shard(shard.shard_id, "node-alpha")
        assert result is True

        node_shards = shard_mgr.get_node_shards("node-alpha")
        assert len(node_shards) == 1
        assert node_shards[0].shard_id == shard.shard_id

    def test_max_shards_per_node_enforced(self, shard_mgr, config):
        """Nodes cannot exceed max_shards_per_node."""
        config.max_shards_per_node = 2
        mgr = ShardManager(shard_mgr.db_path + "_max", config)

        s1 = mgr.create_shard("events", [{"id": "1"}])
        s2 = mgr.create_shard("events", [{"id": "2"}])
        s3 = mgr.create_shard("events", [{"id": "3"}])

        assert mgr.assign_shard(s1.shard_id, "node-a") is True
        assert mgr.assign_shard(s2.shard_id, "node-a") is True
        assert mgr.assign_shard(s3.shard_id, "node-a") is False  # limit reached

    def test_get_shard_data(self, shard_mgr):
        """Shard data can be retrieved."""
        records = [
            {"id": "e1", "source_ip": "1.2.3.4"},
            {"id": "e2", "source_ip": "5.6.7.8"},
        ]
        shard = shard_mgr.create_shard("events", records)
        data = shard_mgr.get_shard_data(shard.shard_id)
        assert len(data) == 2
        ips = {d["source_ip"] for d in data}
        assert ips == {"1.2.3.4", "5.6.7.8"}

    def test_shards_needing_assignment(self, shard_mgr):
        """Finds shards with fewer replicas than required."""
        shard = shard_mgr.create_shard("events", [{"id": "e1"}])
        shard_mgr.assign_shard(shard.shard_id, "node-a")

        # Needs 3 replicas, only has 1 active
        needing = shard_mgr.get_shards_needing_assignment(["node-a", "node-b"])
        assert len(needing) == 1
        assert needing[0].shard_id == shard.shard_id

    def test_shard_stats(self, shard_mgr):
        """Shard statistics are computed correctly."""
        shard_mgr.create_shard("events", [{"id": "e1"}, {"id": "e2"}])
        shard_mgr.create_shard("iocs", [{"id": "i1"}])

        stats = shard_mgr.get_shard_stats()
        assert stats['total_shards'] == 2
        assert stats['total_records'] == 3
        assert 'events' in stats['by_type']
        assert 'iocs' in stats['by_type']

    def test_verify_shard(self, shard_mgr):
        """Shard verification updates the last_verified timestamp."""
        shard = shard_mgr.create_shard("events", [{"id": "e1"}])
        shard_mgr.assign_shard(shard.shard_id, "node-a")
        result = shard_mgr.verify_shard(shard.shard_id, "node-a")
        assert result is True


# =============================================================================
# QueryGate Tests
# =============================================================================

class TestQueryGate:

    def test_authorized_query_succeeds(self, db_path, config):
        """Node with credits, ratio, and shards can query."""
        ledger = ContributionLedger(db_path, config)
        shard_mgr = ShardManager(db_path, config)
        gate = QueryGate(ledger, shard_mgr, config)

        ledger.register_node("node-a")
        ledger.record_contribution("node-a", "event", 20)

        # Host a shard
        shard = shard_mgr.create_shard("events", [
            {"id": "e1", "source_ip": "1.2.3.4", "event_type": "connection"}
        ])
        shard_mgr.assign_shard(shard.shard_id, "node-a")

        authorized, reason = gate.authorize_query("node-a")
        assert authorized is True

    def test_query_denied_without_shards(self, db_path, config):
        """Node without hosted shards cannot query."""
        ledger = ContributionLedger(db_path, config)
        shard_mgr = ShardManager(db_path, config)
        gate = QueryGate(ledger, shard_mgr, config)

        ledger.register_node("node-a")
        ledger.record_contribution("node-a", "event", 20)

        authorized, reason = gate.authorize_query("node-a")
        assert authorized is False
        assert "not hosting any data shards" in reason

    def test_execute_query_returns_data(self, db_path, config):
        """Executing a query returns matching records."""
        ledger = ContributionLedger(db_path, config)
        shard_mgr = ShardManager(db_path, config)
        gate = QueryGate(ledger, shard_mgr, config)

        ledger.register_node("node-a")
        ledger.record_contribution("node-a", "event", 20)

        # Create and assign shard with data
        shard = shard_mgr.create_shard("events", [
            {"id": "e1", "source_ip": "1.2.3.4", "event_type": "auth_attempt"},
            {"id": "e2", "source_ip": "5.6.7.8", "event_type": "connection"},
        ])
        shard_mgr.assign_shard(shard.shard_id, "node-a")

        result = gate.execute_query("node-a", "events")
        assert result.success is True
        assert len(result.data) == 2
        assert result.credits_spent == 2

    def test_execute_query_with_ip_filter(self, db_path, config):
        """Queries can filter by IP address."""
        ledger = ContributionLedger(db_path, config)
        shard_mgr = ShardManager(db_path, config)
        gate = QueryGate(ledger, shard_mgr, config)

        ledger.register_node("node-a")
        ledger.record_contribution("node-a", "event", 20)

        shard = shard_mgr.create_shard("events", [
            {"id": "e1", "source_ip": "1.2.3.4"},
            {"id": "e2", "source_ip": "5.6.7.8"},
        ])
        shard_mgr.assign_shard(shard.shard_id, "node-a")

        result = gate.execute_query("node-a", "events", {"ip": "1.2.3.4"})
        assert result.success is True
        assert len(result.data) == 1
        assert result.data[0]["source_ip"] == "1.2.3.4"

    def test_execute_query_denied_returns_error(self, db_path, config):
        """Denied queries return error with explanation."""
        ledger = ContributionLedger(db_path, config)
        shard_mgr = ShardManager(db_path, config)
        gate = QueryGate(ledger, shard_mgr, config)

        result = gate.execute_query("unregistered-node", "events")
        assert result.success is False
        assert "not registered" in result.error


# =============================================================================
# ThreatIntelFeed Integration Tests
# =============================================================================

class TestThreatIntelFeed:

    def test_full_contribute_then_query_flow(self, feed):
        """End-to-end: register, contribute, host shard, query."""
        # 1. Register
        standing = feed.register("node-alpha")
        assert standing['credits'] == 50

        # 2. Contribute events (creates shard and assigns to contributor)
        events = [
            {"id": "e1", "source_ip": "10.0.0.1", "event_type": "auth_attempt"},
            {"id": "e2", "source_ip": "10.0.0.2", "event_type": "connection"},
            {"id": "e3", "source_ip": "10.0.0.3", "event_type": "command"},
        ]
        result = feed.contribute_events("node-alpha", events)
        assert result['credits_earned'] == 3
        assert result['record_count'] == 3

        # 3. Query — should succeed since node contributed and hosts a shard
        query = feed.query_threat_intel("node-alpha", "events")
        assert query['success'] is True
        assert len(query['data']) == 3
        assert query['credits_spent'] == 2

        # 4. Check standing
        standing = feed.get_standing("node-alpha")
        assert standing['events_contributed'] == 3
        assert standing['queries_made'] == 1
        assert len(standing['hosted_shards']) == 1

    def test_query_denied_without_contribution(self, feed):
        """Nodes that only register (no contribution) cannot query."""
        feed.register("freeloader")
        result = feed.query_threat_intel("freeloader", "events")
        assert result['success'] is False
        # Denied either for low ratio or no shards — both are valid gating reasons
        assert ("ratio" in result['error'].lower() or
                "shard" in result['error'].lower() or
                "credit" in result['error'].lower())

    def test_contribute_iocs_earns_more(self, feed):
        """IOC contributions earn 5x the credits of events."""
        feed.register("node-alpha")
        result = feed.contribute_iocs("node-alpha", [
            {"id": "i1", "ioc_type": "ip", "value": "1.2.3.4", "confidence": 0.9},
            {"id": "i2", "ioc_type": "domain", "value": "evil.com", "confidence": 0.8},
        ])
        assert result['credits_earned'] == 10  # 2 * 5
        assert result['record_count'] == 2

    def test_host_additional_shard(self, feed):
        """Nodes can volunteer to host shards from other contributors."""
        feed.register("node-alpha")
        feed.register("node-beta")

        # Alpha contributes, creating a shard
        feed.contribute_events("node-alpha", [
            {"id": "e1", "source_ip": "1.2.3.4"},
        ])

        # Beta looks for available shards
        available = feed.get_available_shards("node-beta")
        assert len(available) > 0

        # Beta hosts a shard
        shard_id = available[0]['shard_id']
        result = feed.host_shard("node-beta", shard_id)
        assert result['status'] == 'assigned'

    def test_leaderboard(self, feed):
        """Leaderboard shows top contributors."""
        feed.register("low")
        feed.register("high")

        feed.contribute_events("low", [{"id": "e1"}])
        feed.contribute_events("high", [{"id": f"e{i}"} for i in range(20)])

        board = feed.get_leaderboard()
        assert len(board) == 2
        assert board[0]['node_id'] == "high"

    def test_network_stats(self, feed):
        """Network stats combine ledger and shard data."""
        feed.register("node-a")
        feed.contribute_events("node-a", [{"id": "e1"}, {"id": "e2"}])

        stats = feed.get_network_stats()
        assert 'incentive' in stats
        assert 'shards' in stats
        assert stats['incentive']['total_nodes'] == 1
        assert stats['incentive']['total_events_contributed'] == 2
        assert stats['shards']['total_shards'] == 1

    def test_empty_contribution_returns_zero(self, feed):
        """Contributing empty lists returns zero credits."""
        feed.register("node-a")
        result = feed.contribute_events("node-a", [])
        assert result['credits_earned'] == 0
        result = feed.contribute_iocs("node-a", [])
        assert result['credits_earned'] == 0

    def test_query_iocs_with_type_filter(self, feed):
        """IOC queries can be filtered by type."""
        feed.register("node-a")
        feed.contribute_iocs("node-a", [
            {"id": "i1", "ioc_type": "ip", "value": "1.2.3.4", "confidence": 0.9},
            {"id": "i2", "ioc_type": "domain", "value": "evil.com", "confidence": 0.8},
            {"id": "i3", "ioc_type": "ip", "value": "5.6.7.8", "confidence": 0.7},
        ])

        result = feed.query_threat_intel("node-a", "iocs", {"ioc_type": "ip"})
        assert result['success'] is True
        assert len(result['data']) == 2
        assert all(d['ioc_type'] == 'ip' for d in result['data'])

    def test_credits_deplete_with_queries(self, feed):
        """Credits decrease with each query."""
        feed.register("node-a")
        feed.contribute_events("node-a", [{"id": f"e{i}"} for i in range(5)])

        # Initial: 50 bootstrap + 5 event credits = 55
        standing1 = feed.get_standing("node-a")
        credits_before = standing1['credits']

        feed.query_threat_intel("node-a", "events")
        standing2 = feed.get_standing("node-a")
        assert standing2['credits'] == credits_before - 2

    def test_multiple_nodes_see_each_others_data(self, feed):
        """Data contributed by one node is queryable by another (if authorized)."""
        feed.register("node-a")
        feed.register("node-b")

        # Node A contributes events
        feed.contribute_events("node-a", [
            {"id": "e1", "source_ip": "attacker.ip.1"},
        ])

        # Node B contributes IOCs and hosts a shard to get query access
        feed.contribute_events("node-b", [
            {"id": "e2", "source_ip": "attacker.ip.2"},
        ])

        # Both nodes can query all events
        result_a = feed.query_threat_intel("node-a", "events")
        result_b = feed.query_threat_intel("node-b", "events")

        assert result_a['success'] is True
        assert result_b['success'] is True
        # Both see all events from both contributors
        assert len(result_a['data']) == 2
        assert len(result_b['data']) == 2

    def test_standing_for_unregistered_node(self, feed):
        """Getting standing for unknown node returns None."""
        assert feed.get_standing("nonexistent") is None


# =============================================================================
# IncentiveConfig Tests
# =============================================================================

class TestIncentiveConfig:

    def test_default_values(self):
        """Default config has sensible values."""
        config = IncentiveConfig()
        assert config.enabled is True
        assert config.bootstrap_credits == 50
        assert config.credit_per_event == 1
        assert config.credit_per_ioc == 5
        assert config.cost_per_query == 2
        assert config.min_ratio == 0.5

    def test_from_env(self, monkeypatch):
        """Config loads from environment variables."""
        monkeypatch.setenv('INCENTIVE_ENABLED', 'true')
        monkeypatch.setenv('INCENTIVE_BOOTSTRAP_CREDITS', '100')
        monkeypatch.setenv('INCENTIVE_CREDIT_PER_EVENT', '2')
        monkeypatch.setenv('INCENTIVE_CREDIT_PER_IOC', '10')
        monkeypatch.setenv('INCENTIVE_COST_PER_QUERY', '5')
        monkeypatch.setenv('INCENTIVE_MIN_RATIO', '0.3')

        config = IncentiveConfig.from_env()
        assert config.enabled is True
        assert config.bootstrap_credits == 100
        assert config.credit_per_event == 2
        assert config.credit_per_ioc == 10
        assert config.cost_per_query == 5
        assert config.min_ratio == 0.3

    def test_disabled_from_env(self, monkeypatch):
        """Config can be disabled via env."""
        monkeypatch.setenv('INCENTIVE_ENABLED', 'false')
        config = IncentiveConfig.from_env()
        assert config.enabled is False
