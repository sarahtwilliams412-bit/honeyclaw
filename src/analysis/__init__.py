"""
Honeyclaw Analysis Module

Provides MITRE ATT&CK mapping, event enrichment, and behavioral analysis.
Includes comprehensive tactic/technique ID constants and rule-based mapping.
"""

from .mitre_mapper import (
    MitreMapper,
    MitreMapping,
    TacticID,
    TechniqueID,
    enrich_event,
)

__all__ = [
    'MitreMapper',
    'MitreMapping',
    'TacticID',
    'TechniqueID',
    'enrich_event',
]
