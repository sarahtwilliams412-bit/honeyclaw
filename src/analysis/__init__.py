"""
Honeyclaw Analysis Module

Provides MITRE ATT&CK mapping, event enrichment, and behavioral analysis.
"""

from .mitre_mapper import MitreMapper, MitreMapping, enrich_event

__all__ = [
    'MitreMapper',
    'MitreMapping',
    'enrich_event',
]
