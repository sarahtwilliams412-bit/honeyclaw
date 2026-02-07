#!/usr/bin/env python3
"""
Honeyclaw Enhanced Logging Package

Provides:
- Correlation IDs for tracking multi-step attacks across services
- GeoIP enrichment at event creation time
- Immutable log storage with S3 Object Lock
- Backup log streams for redundancy
- Unified logging pipeline
"""

from src.logging.pipeline import (
    EnhancedLogger,
    get_enhanced_logger,
    enrich_event,
)

__all__ = [
    "EnhancedLogger",
    "get_enhanced_logger",
    "enrich_event",
]
