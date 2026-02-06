#!/usr/bin/env python3
"""
Tests for Container Escape Detection Module

Run with: pytest src/security/test_escape_detector.py -v
"""

import pytest
from .patterns import (
    ESCAPE_PATTERNS,
    EscapeCategory,
    EscapePattern,
    get_all_patterns,
    get_patterns_by_category,
    get_patterns_by_severity,
    match_text,
)
from .escape_detector import (
    EscapeDetector,
    EscapeResponse,
    EscapeAttempt,
    check_command,
    configure_detector,
)


class TestPatterns:
    """Test pattern definitions and matching."""
    
    def test_patterns_loaded(self):
        """Verify patterns are loaded."""
        patterns = get_all_patterns()
        assert len(patterns) > 30, "Expected 30+ patterns"
    
    def test_pattern_categories(self):
        """Verify all categories have patterns."""
        for category in EscapeCategory:
            patterns = get_patterns_by_category(category)
            assert len(patterns) > 0, f"No patterns for {category.value}"
    
    def test_docker_socket_pattern(self):
        """Test Docker socket access detection."""
        matches = match_text("cat /var/run/docker.sock")
        assert len(matches) > 0
        assert any(p.name == "docker_socket_access" for p, _ in matches)
    
    def test_nsenter_pattern(self):
        """Test nsenter command detection."""
        matches = match_text("nsenter -t 1 -m -p -- /bin/bash")
        assert len(matches) > 0
        assert any(p.name == "nsenter_command" for p, _ in matches)
    
    def test_cgroup_release_agent(self):
        """Test cgroup release_agent exploit detection."""
        matches = match_text("echo /tmp/pwn > /sys/fs/cgroup/x/release_agent")
        assert len(matches) > 0
        assert any(p.category == EscapeCategory.CGROUP_EXPLOIT for p, _ in matches)
    
    def test_proc_root_access(self):
        """Test /proc/*/root access detection."""
        matches = match_text("ls /proc/1/root")
        assert len(matches) > 0
        assert any(p.name == "proc_root_access" for p, _ in matches)
    
    def test_safe_command_no_match(self):
        """Verify safe commands don't match."""
        safe_commands = [
            "ls -la",
            "cat /etc/passwd",
            "pwd",
            "whoami",
            "ps aux",
            "netstat -an",
        ]
        for cmd in safe_commands:
            matches = match_text(cmd)
            # Should have no matches or only low severity
            high_severity = [p for p, _ in matches if p.severity >= 7]
            assert len(high_severity) == 0, f"Safe command matched: {cmd}"
    
    def test_severity_filtering(self):
        """Test filtering patterns by severity."""
        high = get_patterns_by_severity(8)
        all_patterns = get_all_patterns()
        assert len(high) < len(all_patterns)
        assert all(p.severity >= 8 for p in high)
    
    def test_pattern_has_mitre(self):
        """Verify high-severity patterns have MITRE mapping."""
        high = get_patterns_by_severity(9)
        for p in high:
            assert p.mitre_technique, f"Pattern {p.name} missing MITRE technique"


class TestEscapeDetector:
    """Test the escape detector engine."""
    
    def test_detector_creation(self):
        """Test detector initialization."""
        detector = EscapeDetector()
        assert detector.response == EscapeResponse.ALERT_ONLY
        assert detector.min_severity == 5
    
    def test_detector_check_safe(self):
        """Test checking safe commands."""
        detector = EscapeDetector()
        is_escape, detections = detector.check("ls -la")
        assert not is_escape
        assert len(detections) == 0
    
    def test_detector_check_escape(self):
        """Test checking escape commands."""
        detector = EscapeDetector()
        is_escape, detections = detector.check("nsenter -t 1 -m -p /bin/sh")
        assert is_escape
        assert len(detections) > 0
        assert detections[0].category == "namespace_escape"
    
    def test_detector_with_context(self):
        """Test detection with IP and session context."""
        detector = EscapeDetector()
        is_escape, detections = detector.check(
            "cat /var/run/docker.sock",
            source_ip="192.168.1.100",
            session_id="sess123",
        )
        assert is_escape
        assert detections[0].source_ip == "192.168.1.100"
        assert detections[0].session_id == "sess123"
    
    def test_detector_min_severity(self):
        """Test minimum severity filtering."""
        # Low threshold - should detect
        detector_low = EscapeDetector(min_severity=5)
        is_escape_low, _ = detector_low.check("getcap /usr/bin/*")
        
        # High threshold - should not detect this pattern
        detector_high = EscapeDetector(min_severity=10)
        is_escape_high, _ = detector_high.check("getcap /usr/bin/*")
        
        # getcap pattern is severity 6, so only low threshold should catch it
        assert is_escape_low
        assert not is_escape_high
    
    def test_detector_statistics(self):
        """Test statistics tracking."""
        detector = EscapeDetector()
        
        # Initial stats
        stats = detector.get_stats()
        assert stats['total_checks'] == 0
        assert stats['detections'] == 0
        
        # Run some checks
        detector.check("ls -la")
        detector.check("nsenter -t 1 -m")
        detector.check("cat /var/run/docker.sock")
        
        stats = detector.get_stats()
        assert stats['total_checks'] == 3
        assert stats['detections'] == 2
    
    def test_detector_history(self):
        """Test detection history."""
        detector = EscapeDetector()
        detector.check("nsenter -t 1 -m")
        detector.check("cat /var/run/docker.sock")
        
        history = detector.get_history()
        assert len(history) == 2
    
    def test_response_configuration(self):
        """Test response configuration."""
        detector = EscapeDetector(response=EscapeResponse.KILL_CONTAINER)
        assert detector.response == EscapeResponse.KILL_CONTAINER
        
        detector.set_response(EscapeResponse.ALERT_ONLY)
        assert detector.response == EscapeResponse.ALERT_ONLY


class TestConvenienceFunctions:
    """Test module-level convenience functions."""
    
    def test_check_command(self):
        """Test the check_command function."""
        is_escape, detections = check_command("ls -la")
        assert not is_escape
        
        is_escape, detections = check_command("nsenter -t 1 -m")
        assert is_escape
    
    def test_configure_detector(self):
        """Test configure_detector function."""
        configure_detector(response="kill", min_severity=8)
        
        from .escape_detector import get_detector
        detector = get_detector()
        assert detector.response == EscapeResponse.KILL_CONTAINER
        assert detector.min_severity == 8
        
        # Reset
        configure_detector(response="alert_only", min_severity=5)


class TestEscapeAttempt:
    """Test EscapeAttempt data class."""
    
    def test_to_dict(self):
        """Test conversion to dictionary."""
        attempt = EscapeAttempt(
            timestamp="2024-01-01T00:00:00Z",
            pattern_name="test",
            category="test_cat",
            severity=10,
            command="test cmd",
            matches=["match1"],
        )
        d = attempt.to_dict()
        assert d['pattern_name'] == "test"
        assert d['severity'] == 10
    
    def test_to_json(self):
        """Test JSON serialization."""
        attempt = EscapeAttempt(
            timestamp="2024-01-01T00:00:00Z",
            pattern_name="test",
            category="test_cat",
            severity=10,
            command="test cmd",
            matches=["match1"],
        )
        j = attempt.to_json()
        assert '"pattern_name": "test"' in j


class TestKnownCVEs:
    """Test detection of known CVE exploit patterns."""
    
    def test_cve_2022_0492(self):
        """Test CVE-2022-0492 cgroup escape detection."""
        # Full exploit pattern
        cmd = "echo /tmp/exploit.sh > /sys/fs/cgroup/rdma/x/release_agent"
        is_escape, detections = check_command(cmd)
        assert is_escape
        
        # Check CVE reference
        cve_matches = [d for d in detections if "cve" in d.pattern_name.lower() or "release_agent" in d.pattern_name]
        assert len(cve_matches) > 0
    
    def test_cve_2019_5736_runc(self):
        """Test CVE-2019-5736 runc escape detection."""
        cmd = "#!/proc/self/exe"
        is_escape, detections = check_command(cmd)
        assert is_escape
    
    def test_dirty_pipe(self):
        """Test CVE-2022-0847 Dirty Pipe detection."""
        cmd = "splice(SPLICE_F_GIFT)"
        is_escape, detections = check_command(cmd)
        assert is_escape


class TestDockerEscape:
    """Test Docker-specific escape patterns."""
    
    def test_docker_socket_curl(self):
        """Test Docker API access via curl."""
        cmd = "curl --unix-socket /var/run/docker.sock http://localhost/info"
        is_escape, detections = check_command(cmd)
        assert is_escape
        assert any(d.category == "docker_socket" for d in detections)
    
    def test_docker_privileged_run(self):
        """Test privileged container spawn."""
        cmd = "docker run --privileged -v /:/host alpine"
        is_escape, detections = check_command(cmd)
        assert is_escape
    
    def test_docker_mount_root(self):
        """Test mounting host root filesystem."""
        cmd = "docker run -v /:/mnt/host ubuntu"
        is_escape, detections = check_command(cmd)
        assert is_escape


class TestCapabilityAbuse:
    """Test capability abuse detection."""
    
    def test_cap_sys_admin(self):
        """Test CAP_SYS_ADMIN detection."""
        cmd = "--cap-add=SYS_ADMIN"
        is_escape, detections = check_command(cmd)
        assert is_escape
    
    def test_cap_sys_ptrace(self):
        """Test CAP_SYS_PTRACE detection."""
        cmd = "CAP_SYS_PTRACE"
        is_escape, detections = check_command(cmd)
        assert is_escape


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
