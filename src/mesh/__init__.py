"""
Honey Claw - Geo-Distributed Mesh
Multi-region honeypot coordination with centralized correlation.

Includes BitTorrent-style incentive system: nodes must contribute
threat intel and host data shards to query the collective intelligence.
"""

from .coordinator import MeshCoordinator
from .node import MeshNode
from .incentive import (
    ThreatIntelFeed,
    ContributionLedger,
    ShardManager,
    QueryGate,
    IncentiveConfig,
)

__all__ = [
    'MeshCoordinator',
    'MeshNode',
    'ThreatIntelFeed',
    'ContributionLedger',
    'ShardManager',
    'QueryGate',
    'IncentiveConfig',
]
