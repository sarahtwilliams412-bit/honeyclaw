"""
Honeyclaw Analysis Module

Provides MITRE ATT&CK event mapping, behavioral analysis,
and threat intelligence correlation.
"""

from .mitre_mapper import MitreMapper, MitreMapping, TacticID, TechniqueID

__all__ = [
    'MitreMapper',
    'MitreMapping',
    'TacticID',
    'TechniqueID',
]
