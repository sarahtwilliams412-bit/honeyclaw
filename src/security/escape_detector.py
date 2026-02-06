#!/usr/bin/env python3
"""
Honeyclaw Container Escape Detector

Detection engine for container/sandbox escape attempts.
Monitors shell commands and system interactions for escape patterns.
Provides configurable response actions: alert, kill, or migrate.
"""

import os
import json
import time
import signal
import threading
import subprocess
from enum import Enum
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict

from .patterns import (
    ESCAPE_PATTERNS,
    EscapePattern,
    EscapeCategory,
    get_all_patterns,
    match_text,
)


class EscapeResponse(Enum):
    """Response action when escape attempt is detected."""
    ALERT_ONLY = "alert_only"       # Log and alert, but allow (gather intel)
    KILL_CONTAINER = "kill"          # Immediately terminate container
    MIGRATE_SANDBOX = "migrate"      # Move to deeper isolation sandbox
    BLOCK_COMMAND = "block"          # Block the specific command


@dataclass
class EscapeAttempt:
    """
    Record of a detected escape attempt.
    
    Attributes:
        timestamp: ISO timestamp of detection
        pattern_name: Name of the matched pattern
        category: Category of escape technique
        severity: Severity level (1-10)
        command: The command/text that triggered detection
        matches: Specific regex matches found
        source_ip: Source IP if available
        session_id: Session identifier if available
        mitre_technique: Associated MITRE ATT&CK technique
        response_taken: Action taken in response
        additional_context: Any extra context data
    """
    timestamp: str
    pattern_name: str
    category: str
    severity: int
    command: str
    matches: List[str]
    source_ip: Optional[str] = None
    session_id: Optional[str] = None
    mitre_technique: str = ""
    response_taken: str = "alert_only"
    additional_context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())


class EscapeDetector:
    """
    Main container escape detection engine.
    
    Features:
    - Real-time command monitoring
    - Configurable response actions
    - Alert integration with Honeyclaw alerting system
    - Statistics and reporting
    - Thread-safe operation
    """
    
    def __init__(
        self,
        response: EscapeResponse = EscapeResponse.ALERT_ONLY,
        min_severity: int = 5,
        patterns: Optional[List[EscapePattern]] = None,
        alert_callback: Optional[Callable[[EscapeAttempt], None]] = None,
        kill_callback: Optional[Callable[[], None]] = None,
        migrate_callback: Optional[Callable[[], None]] = None,
        honeypot_id: Optional[str] = None,
    ):
        """
        Initialize the escape detector.
        
        Args:
            response: Default response action for detections
            min_severity: Minimum severity to trigger (1-10)
            patterns: Custom patterns (uses defaults if None)
            alert_callback: Function to call for alerts
            kill_callback: Function to call for container termination
            migrate_callback: Function to call for sandbox migration
            honeypot_id: Identifier for this honeypot instance
        """
        self.response = response
        self.min_severity = min_severity
        self.patterns = patterns or get_all_patterns()
        self.alert_callback = alert_callback
        self.kill_callback = kill_callback
        self.migrate_callback = migrate_callback
        self.honeypot_id = honeypot_id or os.environ.get('HONEYPOT_ID', 'honeyclaw')
        
        # Load configuration from environment
        self._load_env_config()
        
        # Statistics
        self._stats = {
            'total_checks': 0,
            'detections': 0,
            'by_category': {cat.value: 0 for cat in EscapeCategory},
            'by_severity': {i: 0 for i in range(1, 11)},
            'responses': {r.value: 0 for r in EscapeResponse},
        }
        self._lock = threading.Lock()
        
        # Detection history (ring buffer)
        self._history: List[EscapeAttempt] = []
        self._max_history = 1000
        
        # Connect to alert system if available
        self._setup_alerting()
    
    def _load_env_config(self):
        """Load configuration from environment variables."""
        # ESCAPE_RESPONSE: alert_only|kill|migrate|block
        env_response = os.environ.get('ESCAPE_RESPONSE', '').lower()
        if env_response:
            try:
                self.response = EscapeResponse(env_response)
            except ValueError:
                pass
        
        # ESCAPE_MIN_SEVERITY: 1-10
        env_severity = os.environ.get('ESCAPE_MIN_SEVERITY')
        if env_severity:
            try:
                self.min_severity = max(1, min(10, int(env_severity)))
            except ValueError:
                pass
    
    def _setup_alerting(self):
        """Connect to Honeyclaw alert system if available."""
        try:
            from src.alerts.dispatcher import get_dispatcher, AlertDispatcher
            from src.alerts.rules import Severity, AlertRule
            
            self._dispatcher = get_dispatcher()
            
            # Add escape-specific rules
            self._add_escape_alert_rules()
            
            # Set default alert callback if none provided
            if self.alert_callback is None:
                self.alert_callback = self._default_alert
                
        except ImportError:
            self._dispatcher = None
    
    def _add_escape_alert_rules(self):
        """Add escape detection rules to the alert engine."""
        try:
            from src.alerts.rules import AlertRule, Severity
            
            # Rule for escape attempts
            escape_rule = AlertRule(
                name="container_escape_attempt",
                description="Container escape attempt detected",
                severity=Severity.CRITICAL,
                event_types=["escape_attempt", "escape_*"],
                tags=["escape", "critical", "container", "security"],
                dedup_key=["ip", "pattern_name"],
                dedup_window_sec=60,
            )
            
            if self._dispatcher and hasattr(self._dispatcher, 'engine'):
                # Only add if not already present
                existing = self._dispatcher.engine.get_rule("container_escape_attempt")
                if not existing:
                    self._dispatcher.engine.add_rule(escape_rule)
                    
        except Exception as e:
            print(f"[ESCAPE] Warning: Could not add alert rules: {e}")
    
    def check(
        self,
        command: str,
        source_ip: Optional[str] = None,
        session_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, List[EscapeAttempt]]:
        """
        Check a command/text for escape patterns.
        
        Args:
            command: The command or text to check
            source_ip: Source IP address if available
            session_id: Session identifier if available
            context: Additional context data
            
        Returns:
            Tuple of (is_escape_attempt, list_of_detections)
        """
        if not command:
            return False, []
        
        with self._lock:
            self._stats['total_checks'] += 1
        
        # Match against all patterns
        matches = match_text(command)
        
        if not matches:
            return False, []
        
        # Filter by minimum severity
        detections = []
        for pattern, match_strings in matches:
            if pattern.severity < self.min_severity:
                continue
            
            # Create detection record
            attempt = EscapeAttempt(
                timestamp=datetime.utcnow().isoformat() + 'Z',
                pattern_name=pattern.name,
                category=pattern.category.value,
                severity=pattern.severity,
                command=command[:2000],  # Truncate long commands
                matches=match_strings[:10],  # Limit matches
                source_ip=source_ip,
                session_id=session_id,
                mitre_technique=pattern.mitre_technique,
                additional_context=context or {},
            )
            
            # Determine and execute response
            response_taken = self._handle_detection(attempt, pattern)
            attempt.response_taken = response_taken.value
            
            detections.append(attempt)
            
            # Update statistics
            self._update_stats(attempt, response_taken)
            
            # Store in history
            self._add_to_history(attempt)
        
        return len(detections) > 0, detections
    
    def _handle_detection(
        self,
        attempt: EscapeAttempt,
        pattern: EscapePattern,
    ) -> EscapeResponse:
        """
        Handle a detected escape attempt.
        
        Returns:
            The response action taken.
        """
        # Log the detection
        self._log_detection(attempt)
        
        # Always alert
        if self.alert_callback:
            try:
                self.alert_callback(attempt)
            except Exception as e:
                print(f"[ESCAPE] Alert callback error: {e}")
        
        # Determine response based on severity and configuration
        response = self.response
        
        # Override to KILL for severity 10 patterns unless explicitly alert-only
        if pattern.severity == 10 and response != EscapeResponse.ALERT_ONLY:
            response = EscapeResponse.KILL_CONTAINER
        
        # Execute response
        if response == EscapeResponse.KILL_CONTAINER:
            self._execute_kill()
        elif response == EscapeResponse.MIGRATE_SANDBOX:
            self._execute_migrate()
        elif response == EscapeResponse.BLOCK_COMMAND:
            pass  # Blocking handled by caller
        
        return response
    
    def _log_detection(self, attempt: EscapeAttempt):
        """Log escape attempt with high severity."""
        log_entry = {
            'timestamp': attempt.timestamp,
            'event': 'escape_attempt',
            'severity': 'CRITICAL',
            'pattern': attempt.pattern_name,
            'category': attempt.category,
            'pattern_severity': attempt.severity,
            'command': attempt.command[:500],
            'matches': attempt.matches,
            'source_ip': attempt.source_ip,
            'session_id': attempt.session_id,
            'mitre': attempt.mitre_technique,
            'response': attempt.response_taken,
            'honeypot_id': self.honeypot_id,
        }
        
        # Print to stdout (captured by log aggregator)
        print(json.dumps(log_entry), flush=True)
    
    def _default_alert(self, attempt: EscapeAttempt):
        """Default alert handler using Honeyclaw dispatcher."""
        if self._dispatcher is None:
            return
        
        event = {
            'ip': attempt.source_ip or 'unknown',
            'event': 'escape_attempt',
            'pattern_name': attempt.pattern_name,
            'category': attempt.category,
            'severity': attempt.severity,
            'command': attempt.command[:500],
            'matches': attempt.matches,
            'mitre_technique': attempt.mitre_technique,
            'session_id': attempt.session_id,
            'honeypot_id': self.honeypot_id,
        }
        
        try:
            self._dispatcher.process_event(event, 'escape_attempt')
        except Exception as e:
            print(f"[ESCAPE] Dispatcher error: {e}")
    
    def _execute_kill(self):
        """Execute container termination."""
        print("[ESCAPE] CRITICAL: Initiating container termination", flush=True)
        
        if self.kill_callback:
            try:
                self.kill_callback()
                return
            except Exception as e:
                print(f"[ESCAPE] Kill callback error: {e}")
        
        # Default: send SIGTERM to init process
        try:
            os.kill(1, signal.SIGTERM)
        except (ProcessLookupError, PermissionError) as e:
            print(f"[ESCAPE] Could not kill init: {e}")
            # Alternative: exit this process
            os._exit(1)
    
    def _execute_migrate(self):
        """Execute migration to deeper sandbox."""
        print("[ESCAPE] Initiating sandbox migration", flush=True)
        
        if self.migrate_callback:
            try:
                self.migrate_callback()
                return
            except Exception as e:
                print(f"[ESCAPE] Migrate callback error: {e}")
        
        # Default: log that migration was requested (external orchestrator handles)
        migrate_event = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event': 'migration_requested',
            'honeypot_id': self.honeypot_id,
            'reason': 'escape_attempt_detected',
        }
        print(json.dumps(migrate_event), flush=True)
    
    def _update_stats(self, attempt: EscapeAttempt, response: EscapeResponse):
        """Update detection statistics."""
        with self._lock:
            self._stats['detections'] += 1
            self._stats['by_category'][attempt.category] += 1
            self._stats['by_severity'][attempt.severity] += 1
            self._stats['responses'][response.value] += 1
    
    def _add_to_history(self, attempt: EscapeAttempt):
        """Add detection to history ring buffer."""
        with self._lock:
            self._history.append(attempt)
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detection statistics."""
        with self._lock:
            return dict(self._stats)
    
    def get_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent detection history."""
        with self._lock:
            recent = self._history[-limit:]
            return [a.to_dict() for a in recent]
    
    def set_response(self, response: EscapeResponse):
        """Change the response action."""
        self.response = response
    
    def set_min_severity(self, severity: int):
        """Change the minimum severity threshold."""
        self.min_severity = max(1, min(10, severity))


# =============================================================================
# Command Wrapper / Hook
# =============================================================================

def create_command_hook(
    detector: 'EscapeDetector',
    block_on_detect: bool = False,
) -> Callable[[str, Optional[str], Optional[str]], Tuple[bool, str]]:
    """
    Create a command hook function for shell handlers.
    
    Args:
        detector: The escape detector instance
        block_on_detect: Whether to block commands that trigger detection
        
    Returns:
        Hook function that returns (should_allow, modified_command)
    """
    def hook(
        command: str,
        source_ip: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Check command and determine if it should be allowed.
        
        Returns:
            Tuple of (should_allow, command_or_error_message)
        """
        is_escape, detections = detector.check(command, source_ip, session_id)
        
        if is_escape and block_on_detect:
            patterns = [d.pattern_name for d in detections]
            return False, f"Command blocked: detected escape patterns {patterns}"
        
        return True, command
    
    return hook


# =============================================================================
# Convenience Functions
# =============================================================================

_default_detector: Optional[EscapeDetector] = None


def get_detector() -> EscapeDetector:
    """Get or create the default escape detector."""
    global _default_detector
    if _default_detector is None:
        _default_detector = EscapeDetector()
    return _default_detector


def check_command(
    command: str,
    source_ip: Optional[str] = None,
    session_id: Optional[str] = None,
) -> Tuple[bool, List[EscapeAttempt]]:
    """
    Check a command using the default detector.
    
    Convenience function for honeypot integration.
    
    Usage:
        from src.security import check_command
        is_escape, detections = check_command('nsenter -t 1 -m -p', ip='1.2.3.4')
    """
    return get_detector().check(command, source_ip, session_id)


def configure_detector(
    response: Optional[str] = None,
    min_severity: Optional[int] = None,
    alert_callback: Optional[Callable] = None,
    kill_callback: Optional[Callable] = None,
    migrate_callback: Optional[Callable] = None,
):
    """
    Configure the default detector.
    
    Args:
        response: Response action (alert_only|kill|migrate|block)
        min_severity: Minimum severity threshold (1-10)
        alert_callback: Custom alert function
        kill_callback: Custom kill function
        migrate_callback: Custom migration function
    """
    global _default_detector
    
    kwargs = {}
    if response:
        kwargs['response'] = EscapeResponse(response)
    if min_severity:
        kwargs['min_severity'] = min_severity
    if alert_callback:
        kwargs['alert_callback'] = alert_callback
    if kill_callback:
        kwargs['kill_callback'] = kill_callback
    if migrate_callback:
        kwargs['migrate_callback'] = migrate_callback
    
    _default_detector = EscapeDetector(**kwargs)


# =============================================================================
# CLI for Testing
# =============================================================================

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python escape_detector.py <command_to_check>")
        print("       python escape_detector.py --test")
        print("       python escape_detector.py --stats")
        sys.exit(1)
    
    if sys.argv[1] == '--test':
        # Run test cases
        test_commands = [
            "ls -la",  # Safe
            "cat /var/run/docker.sock",  # Docker socket
            "nsenter -t 1 -m -p -n -- /bin/bash",  # Namespace escape
            "echo pwned > /sys/fs/cgroup/x/release_agent",  # Cgroup exploit
            "mount --bind / /mnt/host",  # Mount escape
            "insmod rootkit.ko",  # Kernel module
            "curl --unix-socket /var/run/docker.sock http://localhost/info",  # Docker API
            "/proc/1/root/bin/sh",  # Proc escape
        ]
        
        detector = EscapeDetector(response=EscapeResponse.ALERT_ONLY)
        
        print("=" * 60)
        print("Container Escape Detection Test")
        print("=" * 60)
        
        for cmd in test_commands:
            is_escape, detections = detector.check(cmd)
            status = "🚨 ESCAPE" if is_escape else "✅ SAFE"
            print(f"\n{status}: {cmd[:50]}")
            for d in detections:
                print(f"   Pattern: {d.pattern_name} (severity: {d.severity})")
                print(f"   Category: {d.category}")
                print(f"   MITRE: {d.mitre_technique}")
        
        print("\n" + "=" * 60)
        print("Statistics:")
        print(json.dumps(detector.get_stats(), indent=2))
        
    elif sys.argv[1] == '--stats':
        detector = get_detector()
        print(json.dumps(detector.get_stats(), indent=2))
        
    else:
        # Check provided command
        command = ' '.join(sys.argv[1:])
        is_escape, detections = check_command(command)
        
        if is_escape:
            print(f"🚨 ESCAPE ATTEMPT DETECTED")
            for d in detections:
                print(f"   Pattern: {d.pattern_name}")
                print(f"   Severity: {d.severity}/10")
                print(f"   Category: {d.category}")
                print(f"   MITRE: {d.mitre_technique}")
            sys.exit(1)
        else:
            print("✅ No escape patterns detected")
            sys.exit(0)
