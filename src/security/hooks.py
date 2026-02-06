#!/usr/bin/env python3
"""
Honeyclaw Security Hooks

Ready-to-use hooks for integrating escape detection into honeypot handlers.
Import these hooks and wire them into your shell command processing.
"""

import os
from typing import Callable, Dict, Optional, Tuple

from .escape_detector import (
    EscapeDetector,
    EscapeResponse,
    EscapeAttempt,
    get_detector,
    configure_detector,
)


class ShellSecurityHook:
    """
    Security hook for shell command handlers.
    
    Usage in honeypot:
        from src.security.hooks import ShellSecurityHook
        
        hook = ShellSecurityHook()
        
        # In command handler:
        result = hook.check(command, client_ip, session_id)
        if result.blocked:
            return result.message
        # else process command...
    """
    
    def __init__(
        self,
        response: str = "alert_only",
        min_severity: int = 5,
        block_on_detect: bool = False,
    ):
        """
        Initialize the security hook.
        
        Args:
            response: Response action (alert_only|kill|migrate|block)
            min_severity: Minimum severity threshold (1-10)
            block_on_detect: Whether to block commands that trigger detection
        """
        self.block_on_detect = block_on_detect
        
        # Configure detector
        configure_detector(
            response=response,
            min_severity=min_severity,
        )
        self.detector = get_detector()
    
    def check(
        self,
        command: str,
        source_ip: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> 'HookResult':
        """
        Check a command for escape patterns.
        
        Args:
            command: Shell command to check
            source_ip: Client IP address
            session_id: Session identifier
            
        Returns:
            HookResult with blocked status and details
        """
        is_escape, detections = self.detector.check(command, source_ip, session_id)
        
        if is_escape:
            if self.block_on_detect:
                patterns = [d.pattern_name for d in detections]
                return HookResult(
                    blocked=True,
                    is_escape=True,
                    message=f"Permission denied",
                    detections=detections,
                    patterns=patterns,
                )
            return HookResult(
                blocked=False,
                is_escape=True,
                message="Escape attempt detected (allowed for intel)",
                detections=detections,
                patterns=[d.pattern_name for d in detections],
            )
        
        return HookResult(blocked=False, is_escape=False)
    
    def get_stats(self) -> Dict:
        """Get detection statistics."""
        return self.detector.get_stats()


class HookResult:
    """Result of a security hook check."""
    
    def __init__(
        self,
        blocked: bool = False,
        is_escape: bool = False,
        message: str = "",
        detections: list = None,
        patterns: list = None,
    ):
        self.blocked = blocked
        self.is_escape = is_escape
        self.message = message
        self.detections = detections or []
        self.patterns = patterns or []
    
    def __bool__(self):
        """Returns True if command should be blocked."""
        return self.blocked


# Pre-configured hooks for common scenarios

def create_intel_hook() -> ShellSecurityHook:
    """
    Create a hook configured for threat intelligence gathering.
    Alerts on all escape attempts but allows them to proceed.
    """
    return ShellSecurityHook(
        response="alert_only",
        min_severity=5,
        block_on_detect=False,
    )


def create_defensive_hook() -> ShellSecurityHook:
    """
    Create a hook configured for maximum security.
    Blocks escape attempts and kills container on critical patterns.
    """
    return ShellSecurityHook(
        response="kill",
        min_severity=8,
        block_on_detect=True,
    )


def create_balanced_hook() -> ShellSecurityHook:
    """
    Create a hook with balanced intel/security.
    Alerts on medium severity, blocks on high severity.
    """
    return ShellSecurityHook(
        response="block",
        min_severity=7,
        block_on_detect=True,
    )


# Simple function-based hook for minimal integration

def check_command_simple(
    command: str,
    source_ip: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Simple command check function.
    
    Returns:
        Tuple of (is_safe, message)
        is_safe: True if command appears safe
        message: Description if escape detected, empty if safe
    """
    detector = get_detector()
    is_escape, detections = detector.check(command, source_ip)
    
    if is_escape:
        patterns = ', '.join(d.pattern_name for d in detections)
        return False, f"Escape patterns detected: {patterns}"
    
    return True, ""


# Decorator for command handlers

def escape_protected(
    block: bool = False,
    on_detect: Optional[Callable[[str, list], None]] = None,
):
    """
    Decorator to add escape detection to command handlers.
    
    Args:
        block: Whether to block detected escape attempts
        on_detect: Optional callback when escape detected
    
    Usage:
        @escape_protected(block=False)
        def handle_command(command, client_ip):
            # Process command...
            pass
    """
    def decorator(func):
        def wrapper(command: str, *args, **kwargs):
            # Extract IP if provided
            source_ip = kwargs.get('client_ip') or kwargs.get('source_ip')
            if args and isinstance(args[0], str) and '.' in args[0]:
                source_ip = args[0]
            
            # Check for escape
            detector = get_detector()
            is_escape, detections = detector.check(command, source_ip)
            
            if is_escape:
                if on_detect:
                    on_detect(command, detections)
                
                if block:
                    return None  # Or raise exception
            
            return func(command, *args, **kwargs)
        return wrapper
    return decorator
