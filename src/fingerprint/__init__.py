"""
Honeyclaw Attacker Fingerprinting Engine

Builds unique attacker profiles beyond IP address using behavioral 
and technical fingerprints to correlate sessions across IPs.
"""

from .engine import FingerprintEngine, AttackerProfile
from .database import FingerprintDatabase

__all__ = ['FingerprintEngine', 'AttackerProfile', 'FingerprintDatabase']
__version__ = '1.0.0'
