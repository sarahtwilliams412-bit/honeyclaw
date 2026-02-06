#!/usr/bin/env python3
"""
Honeyclaw Security Module

Container escape detection and sandbox security monitoring.
"""

from .patterns import (
    ESCAPE_PATTERNS,
    CVE_PATTERNS,
    CAPABILITY_ABUSE_PATTERNS,
    EscapeCategory,
    get_all_patterns,
)

from .escape_detector import (
    EscapeDetector,
    EscapeResponse,
    EscapeAttempt,
    get_detector,
    check_command,
    configure_detector,
)

__all__ = [
    # Patterns
    'ESCAPE_PATTERNS',
    'CVE_PATTERNS', 
    'CAPABILITY_ABUSE_PATTERNS',
    'EscapeCategory',
    'get_all_patterns',
    # Detector
    'EscapeDetector',
    'EscapeResponse',
    'EscapeAttempt',
    'get_detector',
    'check_command',
    'configure_detector',
]
