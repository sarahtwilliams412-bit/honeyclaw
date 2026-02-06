"""
Honey Claw - Canary Token Generator
Built-in canary token creation for defense-in-depth.

Supports:
- AWS keys (fake AKIA... that alert when used)
- Tracking URLs (unique URLs that alert on visit)
- DNS canaries (subdomain lookups)
- Fake credentials (embedded in honeypot responses)
"""

from .generator import CanaryGenerator, CanaryType, Canary
from .tracker import CanaryTracker

__all__ = ['CanaryGenerator', 'CanaryType', 'Canary', 'CanaryTracker']
