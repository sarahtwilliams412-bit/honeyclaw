#!/usr/bin/env python3
"""
Honeyclaw Auto-Abuse Reporting System

Automatically reports attackers to relevant abuse databases and ISPs.
Features:
- AbuseIPDB integration for crowdsourced threat intelligence
- ISP abuse contact lookup and notification
- Smart filtering to avoid reporting researchers and benign scanners
- Cooldown periods to prevent duplicate reports
- Comprehensive audit logging
"""

from .engine import ReportingEngine, ReportResult, ReportingConfig
from .filters import ReportFilter, should_report

__all__ = [
    'ReportingEngine',
    'ReportResult', 
    'ReportingConfig',
    'ReportFilter',
    'should_report',
]
