#!/usr/bin/env python3
"""
Tests for HoneyClaw Health Monitoring & Self-Healing System
"""

import json
import os
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.health.monitor import (
    HealthMonitor,
    HealthConfig,
    HealthReport,
    HealthStatus,
    ServiceCheck,
    ServiceStatus,
    IsolationCheck,
    ResourceMetrics,
    CompromiseIndicator,
    get_monitor,
    check_health,
    start_monitoring,
    stop_monitoring,
)
from src.health.self_heal import (
    SelfHealer,
    SelfHealConfig,
    HealAction,
)


# ============================================================
# HealthConfig Tests
# ============================================================

class TestHealthConfig:
    def test_default_config(self):
        config = HealthConfig()
        assert config.enabled is True
        assert config.check_interval_sec == 60
        assert config.check_egress is True
        assert config.check_filesystem is True
        assert config.check_processes is True
        assert 'python' in config.allowed_processes

    def test_from_env(self):
        env = {
            'HEALTH_ENABLED': 'false',
            'HEALTH_CHECK_INTERVAL': '30',
            'HEALTH_CHECK_SERVICES': 'ssh:8022,api:8080',
            'HEALTH_CHECK_EGRESS': 'false',
            'HEALTH_CHECK_FILESYSTEM': 'false',
            'HEALTH_CHECK_PROCESSES': 'false',
            'HEALTH_ALLOWED_PROCESSES': '',
        }
        with patch.dict(os.environ, env):
            config = HealthConfig.from_env()

        assert config.enabled is False
        assert config.check_interval_sec == 30
        assert config.services == {'ssh': 8022, 'api': 8080}
        assert config.check_egress is False
        assert config.check_filesystem is False
        assert config.check_processes is False

    def test_from_env_defaults(self):
        """Ensure from_env works with no env vars set."""
        # Remove any HEALTH_* vars that might be set
        clean_env = {k: v for k, v in os.environ.items()
                     if not k.startswith('HEALTH_')}
        with patch.dict(os.environ, clean_env, clear=True):
            config = HealthConfig.from_env()

        assert config.enabled is True
        assert config.check_interval_sec == 60
        assert config.services == {}

    def test_services_parsing(self):
        env = {'HEALTH_CHECK_SERVICES': 'ssh:22, http:80, api:3000'}
        with patch.dict(os.environ, env):
            config = HealthConfig.from_env()

        assert config.services == {'ssh': 22, 'http': 80, 'api': 3000}

    def test_services_parsing_invalid(self):
        env = {'HEALTH_CHECK_SERVICES': 'ssh:notaport,valid:80'}
        with patch.dict(os.environ, env):
            config = HealthConfig.from_env()

        # Invalid port should be skipped
        assert config.services == {'valid': 80}


# ============================================================
# HealthMonitor Tests
# ============================================================

class TestHealthMonitor:
    def test_create_monitor(self):
        config = HealthConfig(
            check_egress=False,
            check_filesystem=False,
            check_processes=False,
        )
        monitor = HealthMonitor(config=config, honeypot_id='test-hp')
        assert monitor.honeypot_id == 'test-hp'
        assert monitor.is_running is False

    def test_run_checks_no_services(self):
        config = HealthConfig(
            services={},
            check_egress=False,
            check_filesystem=False,
            check_processes=False,
        )
        monitor = HealthMonitor(config=config)

        # Mock cron check to avoid environment-specific results
        with patch.object(monitor, '_check_cron_jobs', return_value=[]):
            report = monitor.run_checks()

        assert isinstance(report, HealthReport)
        assert report.status == HealthStatus.HEALTHY
        assert report.services == []
        assert isinstance(report.resources, ResourceMetrics)
        assert report.uptime_seconds >= 0

    def test_run_checks_with_down_service(self):
        # Use a port that's almost certainly not listening
        config = HealthConfig(
            services={'fake_service': 59999},
            check_egress=False,
            check_filesystem=False,
            check_processes=False,
        )
        monitor = HealthMonitor(config=config)

        # Mock cron check to avoid environment-specific results
        with patch.object(monitor, '_check_cron_jobs', return_value=[]):
            report = monitor.run_checks()

        assert report.status == HealthStatus.DEGRADED
        assert len(report.services) == 1
        assert report.services[0].name == 'fake_service'
        assert report.services[0].status == ServiceStatus.DOWN

    def test_resource_collection(self):
        config = HealthConfig(
            check_egress=False,
            check_filesystem=False,
            check_processes=False,
        )
        monitor = HealthMonitor(config=config)
        report = monitor.run_checks()

        res = report.resources
        assert isinstance(res, ResourceMetrics)
        # CPU can be 0.0 on first check (needs two samples)
        assert res.cpu_percent >= 0.0
        assert res.memory_mb >= 0.0
        assert res.disk_percent >= 0.0
        assert res.open_fds >= 0
        assert res.pid_count >= 0

    def test_check_logging_no_dir(self):
        config = HealthConfig(
            log_path='/nonexistent/path/health.json',
            check_egress=False,
            check_filesystem=False,
            check_processes=False,
        )
        monitor = HealthMonitor(config=config)
        check = monitor.check_logging(log_path='/nonexistent/path/health.json')

        assert check.name == 'logging'
        assert check.status == ServiceStatus.DOWN

    def test_check_logging_valid_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, 'health.json')
            config = HealthConfig(
                log_path=log_path,
                check_egress=False,
                check_filesystem=False,
                check_processes=False,
            )
            monitor = HealthMonitor(config=config)
            check = monitor.check_logging(log_path=log_path)

            assert check.name == 'logging'
            assert check.status == ServiceStatus.UP

    def test_stats_tracking(self):
        config = HealthConfig(
            check_egress=False,
            check_filesystem=False,
            check_processes=False,
        )
        monitor = HealthMonitor(config=config)

        with patch.object(monitor, '_check_cron_jobs', return_value=[]):
            monitor.run_checks()
            monitor.run_checks()

        stats = monitor.get_stats()
        assert stats['checks_performed'] == 2
        assert stats['checks_healthy'] == 2

    def test_report_to_dict(self):
        config = HealthConfig(
            check_egress=False,
            check_filesystem=False,
            check_processes=False,
        )
        monitor = HealthMonitor(config=config)
        report = monitor.run_checks()
        d = report.to_dict()

        assert 'status' in d
        assert 'services' in d
        assert 'isolation' in d
        assert 'resources' in d
        assert 'last_check' in d
        assert 'honeypot_id' in d
        assert 'uptime_seconds' in d

        # Should be JSON serializable
        json_str = json.dumps(d)
        assert json_str

    def test_get_last_report(self):
        config = HealthConfig(
            check_egress=False,
            check_filesystem=False,
            check_processes=False,
        )
        monitor = HealthMonitor(config=config)

        assert monitor.get_last_report() is None

        report = monitor.run_checks()
        assert monitor.get_last_report() is report

    def test_compromise_callback(self):
        callback_called = threading.Event()
        callback_report = {}

        def on_compromise(report):
            callback_report['report'] = report
            callback_called.set()

        config = HealthConfig(
            check_egress=False,
            check_filesystem=False,
            check_processes=False,
        )
        monitor = HealthMonitor(config=config, on_compromise=on_compromise)

        # Manually set an indicator to trigger compromise
        with patch.object(
            monitor, '_detect_compromise',
            return_value=[CompromiseIndicator(
                indicator_type='test',
                description='Test compromise',
                severity='high',
            )]
        ):
            monitor.run_checks()

        assert callback_called.is_set()
        assert callback_report['report'].status == HealthStatus.COMPROMISED

    def test_degraded_callback(self):
        callback_called = threading.Event()

        def on_degraded(report):
            callback_called.set()

        config = HealthConfig(
            services={'nonexistent': 59998},
            check_egress=False,
            check_filesystem=False,
            check_processes=False,
        )
        monitor = HealthMonitor(config=config, on_degraded=on_degraded)

        with patch.object(monitor, '_check_cron_jobs', return_value=[]):
            monitor.run_checks()

        assert callback_called.is_set()


# ============================================================
# Background Monitoring Tests
# ============================================================

class TestBackgroundMonitoring:
    def test_start_stop(self):
        config = HealthConfig(
            check_interval_sec=1,
            check_egress=False,
            check_filesystem=False,
            check_processes=False,
        )
        monitor = HealthMonitor(config=config)

        monitor.start()
        assert monitor.is_running is True

        # Wait for at least one check
        time.sleep(1.5)

        monitor.stop()
        assert monitor.is_running is False

        stats = monitor.get_stats()
        assert stats['checks_performed'] >= 1

    def test_double_start(self):
        config = HealthConfig(
            check_interval_sec=60,
            check_egress=False,
            check_filesystem=False,
            check_processes=False,
        )
        monitor = HealthMonitor(config=config)
        monitor.start()
        monitor.start()  # Should not create second thread
        assert monitor.is_running is True
        monitor.stop()

    def test_double_stop(self):
        config = HealthConfig(
            check_interval_sec=60,
            check_egress=False,
            check_filesystem=False,
            check_processes=False,
        )
        monitor = HealthMonitor(config=config)
        monitor.start()
        monitor.stop()
        monitor.stop()  # Should not raise
        assert monitor.is_running is False


# ============================================================
# Isolation Check Tests
# ============================================================

class TestIsolationChecks:
    def test_egress_test_blocked(self):
        config = HealthConfig(
            check_egress=True,
            check_filesystem=False,
            check_processes=False,
            egress_test_host='192.0.2.1',  # RFC 5737 TEST-NET, should time out
            egress_test_port=12345,
        )
        monitor = HealthMonitor(config=config)
        result = monitor._test_egress()

        # In this test environment, the connection likely fails/times out
        # which means egress is "blocked"
        assert 'blocked' in result
        assert 'message' in result

    def test_credential_check(self):
        config = HealthConfig(
            check_egress=False,
            check_filesystem=False,
            check_processes=False,
        )
        monitor = HealthMonitor(config=config)
        result = monitor._check_shared_credentials()

        assert 'clean' in result
        assert 'issues' in result


# ============================================================
# Compromise Detection Tests
# ============================================================

class TestCompromiseDetection:
    def test_resource_threshold_cpu(self):
        config = HealthConfig(
            check_egress=False,
            check_filesystem=False,
            check_processes=False,
            resource_thresholds={'cpu_percent': 10.0, 'memory_percent': 90.0,
                                 'disk_percent': 90.0, 'open_fds': 1024},
        )
        monitor = HealthMonitor(config=config)

        resources = ResourceMetrics(cpu_percent=50.0)
        indicators = monitor._check_resource_thresholds(resources)

        assert any(i.indicator_type == 'high_cpu' for i in indicators)

    def test_resource_threshold_memory(self):
        config = HealthConfig(
            check_egress=False,
            check_filesystem=False,
            check_processes=False,
            resource_thresholds={'cpu_percent': 80.0, 'memory_percent': 10.0,
                                 'disk_percent': 90.0, 'open_fds': 1024},
        )
        monitor = HealthMonitor(config=config)

        resources = ResourceMetrics(memory_percent=50.0)
        indicators = monitor._check_resource_thresholds(resources)

        assert any(i.indicator_type == 'high_memory' for i in indicators)

    def test_no_thresholds_exceeded(self):
        config = HealthConfig(
            check_egress=False,
            check_filesystem=False,
            check_processes=False,
            resource_thresholds={'cpu_percent': 80.0, 'memory_percent': 90.0,
                                 'disk_percent': 90.0, 'open_fds': 1024},
        )
        monitor = HealthMonitor(config=config)

        resources = ResourceMetrics(
            cpu_percent=5.0, memory_percent=30.0,
            disk_percent=20.0, open_fds=10,
        )
        indicators = monitor._check_resource_thresholds(resources)

        assert len(indicators) == 0


# ============================================================
# Status Determination Tests
# ============================================================

class TestStatusDetermination:
    def _make_monitor(self):
        config = HealthConfig(
            check_egress=False,
            check_filesystem=False,
            check_processes=False,
        )
        return HealthMonitor(config=config)

    def test_healthy(self):
        monitor = self._make_monitor()
        status = monitor._determine_status(
            services=[ServiceCheck(name='ssh', status=ServiceStatus.UP)],
            isolation=IsolationCheck(egress_blocked=True, filesystem_integrity=True),
            indicators=[],
        )
        assert status == HealthStatus.HEALTHY

    def test_degraded_service_down(self):
        monitor = self._make_monitor()
        status = monitor._determine_status(
            services=[ServiceCheck(name='ssh', status=ServiceStatus.DOWN)],
            isolation=IsolationCheck(egress_blocked=True, filesystem_integrity=True),
            indicators=[],
        )
        assert status == HealthStatus.DEGRADED

    def test_compromised_egress_open(self):
        monitor = self._make_monitor()
        status = monitor._determine_status(
            services=[],
            isolation=IsolationCheck(egress_blocked=False, filesystem_integrity=True),
            indicators=[],
        )
        assert status == HealthStatus.COMPROMISED

    def test_compromised_filesystem(self):
        monitor = self._make_monitor()
        status = monitor._determine_status(
            services=[],
            isolation=IsolationCheck(egress_blocked=True, filesystem_integrity=False),
            indicators=[],
        )
        assert status == HealthStatus.COMPROMISED

    def test_compromised_high_indicator(self):
        monitor = self._make_monitor()
        status = monitor._determine_status(
            services=[],
            isolation=IsolationCheck(egress_blocked=True, filesystem_integrity=True),
            indicators=[CompromiseIndicator(
                indicator_type='test', description='test', severity='high'
            )],
        )
        assert status == HealthStatus.COMPROMISED

    def test_degraded_medium_indicator(self):
        monitor = self._make_monitor()
        status = monitor._determine_status(
            services=[],
            isolation=IsolationCheck(egress_blocked=True, filesystem_integrity=True),
            indicators=[CompromiseIndicator(
                indicator_type='test', description='test', severity='medium'
            )],
        )
        assert status == HealthStatus.DEGRADED


# ============================================================
# SelfHealConfig Tests
# ============================================================

class TestSelfHealConfig:
    def test_default_config(self):
        config = SelfHealConfig()
        assert config.enabled is True
        assert config.auto_rebuild_on_compromise is True
        assert config.alert_on_degraded is True
        assert config.alert_on_compromise is True
        assert config.max_rebuild_attempts == 3
        assert config.rebuild_cooldown_sec == 600

    def test_from_env(self):
        env = {
            'SELF_HEAL_ENABLED': 'false',
            'SELF_HEAL_AUTO_REBUILD': 'false',
            'SELF_HEAL_MAX_REBUILDS': '5',
            'SELF_HEAL_REBUILD_COOLDOWN': '300',
        }
        with patch.dict(os.environ, env, clear=False):
            config = SelfHealConfig.from_env()

        assert config.enabled is False
        assert config.auto_rebuild_on_compromise is False
        assert config.max_rebuild_attempts == 5
        assert config.rebuild_cooldown_sec == 300


# ============================================================
# SelfHealer Tests
# ============================================================

class TestSelfHealer:
    def _make_report(self, status, indicators=None):
        return HealthReport(
            status=status,
            honeypot_id='test-hp',
            compromise_indicators=indicators or [],
        )

    def test_handle_healthy_report(self):
        config = SelfHealConfig(enabled=True)
        healer = SelfHealer(config=config)

        report = self._make_report(HealthStatus.HEALTHY)
        healer.handle_report(report)

        # No actions should be taken for healthy status
        assert len(healer.get_action_log()) == 0

    def test_handle_degraded_report(self):
        config = SelfHealConfig(enabled=True)
        callback = MagicMock()
        healer = SelfHealer(config=config, alert_callback=callback)

        report = self._make_report(HealthStatus.DEGRADED)
        healer.handle_report(report)

        # Should have sent an alert
        callback.assert_called_once()
        actions = healer.get_action_log()
        assert len(actions) >= 1
        assert actions[0]['action_type'] == 'alert'

    def test_handle_compromise_report(self):
        config = SelfHealConfig(
            enabled=True,
            auto_rebuild_on_compromise=False,  # Don't try to rebuild in tests
            forensic_snapshot_enabled=False,
        )
        callback = MagicMock()
        healer = SelfHealer(config=config, alert_callback=callback)

        report = self._make_report(
            HealthStatus.COMPROMISED,
            indicators=[CompromiseIndicator(
                indicator_type='test',
                description='Test compromise',
                severity='high',
            )],
        )
        healer.handle_report(report)

        callback.assert_called_once()

    def test_disabled_healer(self):
        config = SelfHealConfig(enabled=False)
        callback = MagicMock()
        healer = SelfHealer(config=config, alert_callback=callback)

        report = self._make_report(HealthStatus.COMPROMISED)
        healer.handle_report(report)

        callback.assert_not_called()

    def test_forensic_snapshot(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = SelfHealConfig(
                enabled=True,
                auto_rebuild_on_compromise=False,
                forensic_snapshot_enabled=True,
                forensic_snapshot_path=tmpdir,
                alert_on_compromise=False,
            )
            healer = SelfHealer(config=config)

            report = self._make_report(
                HealthStatus.COMPROMISED,
                indicators=[CompromiseIndicator(
                    indicator_type='test',
                    description='Test',
                    severity='high',
                )],
            )
            healer.handle_compromise(report)

            # Verify snapshot was created
            snapshot_dirs = list(Path(tmpdir).iterdir())
            assert len(snapshot_dirs) == 1

            snapshot_dir = snapshot_dirs[0]
            assert (snapshot_dir / 'health_report.json').exists()
            assert (snapshot_dir / 'environment.json').exists()

            # Verify secrets are redacted in environment
            env_data = json.loads((snapshot_dir / 'environment.json').read_text())
            for key, value in env_data.items():
                if any(s in key.upper() for s in ['SECRET', 'PASSWORD', 'TOKEN']):
                    assert value == '***REDACTED***', f"Secret {key} not redacted"

    @patch('src.health.self_heal.subprocess.run')
    def test_rebuild_cooldown(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout='ok', stderr='')

        config = SelfHealConfig(
            enabled=True,
            auto_rebuild_on_compromise=True,
            forensic_snapshot_enabled=False,
            alert_on_compromise=False,
            rebuild_command='echo "rebuild"',
            rebuild_cooldown_sec=3600,
        )
        healer = SelfHealer(config=config)

        report = self._make_report(HealthStatus.COMPROMISED)

        # First rebuild should proceed
        result1 = healer._trigger_rebuild(report, reason='test')
        assert result1 is True

        # Second rebuild should be blocked by cooldown
        result2 = healer._trigger_rebuild(report, reason='test')
        assert result2 is False

    @patch('src.health.self_heal.subprocess.run')
    def test_max_rebuild_attempts(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout='ok', stderr='')

        config = SelfHealConfig(
            enabled=True,
            rebuild_command='echo "rebuild"',
            max_rebuild_attempts=2,
            rebuild_cooldown_sec=0,
            forensic_snapshot_enabled=False,
            alert_on_compromise=False,
        )
        healer = SelfHealer(config=config)

        report = self._make_report(HealthStatus.COMPROMISED)

        assert healer._trigger_rebuild(report, reason='test') is True
        assert healer._trigger_rebuild(report, reason='test') is True
        assert healer._trigger_rebuild(report, reason='test') is False

    def test_no_rebuild_command(self):
        config = SelfHealConfig(
            enabled=True,
            rebuild_command='',
            forensic_snapshot_enabled=False,
            alert_on_compromise=False,
        )
        healer = SelfHealer(config=config)

        report = self._make_report(HealthStatus.COMPROMISED)
        result = healer._trigger_rebuild(report, reason='test')
        assert result is False

    def test_get_stats(self):
        config = SelfHealConfig(enabled=True)
        healer = SelfHealer(config=config)

        stats = healer.get_stats()
        assert 'total_actions' in stats
        assert 'rebuild_attempts' in stats
        assert 'config' in stats
        assert stats['total_actions'] == 0


# ============================================================
# Data Class Tests
# ============================================================

class TestDataClasses:
    def test_service_check_to_dict(self):
        check = ServiceCheck(
            name='ssh',
            status=ServiceStatus.UP,
            details={'port': 22, 'response_ms': 1.2},
        )
        d = check.to_dict()
        assert d['name'] == 'ssh'
        assert d['status'] == 'up'
        assert d['details']['port'] == 22

    def test_isolation_check_to_dict(self):
        check = IsolationCheck(
            egress_blocked=True,
            no_shared_credentials=True,
            filesystem_integrity=False,
        )
        d = check.to_dict()
        assert d['egress_blocked'] is True
        assert d['filesystem_integrity'] is False

    def test_resource_metrics_to_dict(self):
        metrics = ResourceMetrics(
            cpu_percent=12.34, memory_mb=256.7,
            memory_percent=45.6, disk_percent=23.1,
            open_fds=47, pid_count=15,
        )
        d = metrics.to_dict()
        assert d['cpu_percent'] == 12.3
        assert d['memory_mb'] == 256.7
        assert d['open_fds'] == 47

    def test_compromise_indicator_to_dict(self):
        ind = CompromiseIndicator(
            indicator_type='unexpected_process',
            description='Unexpected process: nc',
            severity='high',
            details={'pid': 1234, 'process_name': 'nc'},
        )
        d = ind.to_dict()
        assert d['indicator_type'] == 'unexpected_process'
        assert d['severity'] == 'high'
        assert d['details']['pid'] == 1234

    def test_heal_action_to_dict(self):
        action = HealAction(
            action_type='rebuild',
            trigger='compromise_detected',
            success=True,
            message='Rebuild completed',
        )
        d = action.to_dict()
        assert d['action_type'] == 'rebuild'
        assert d['success'] is True


# ============================================================
# Convenience Function Tests
# ============================================================

class TestConvenienceFunctions:
    def test_check_health(self):
        """check_health() should return a HealthReport."""
        # Reset the global monitor
        import src.health.monitor as monitor_mod
        monitor_mod._default_monitor = None

        report = check_health()
        assert isinstance(report, HealthReport)

    def test_get_monitor_singleton(self):
        import src.health.monitor as monitor_mod
        monitor_mod._default_monitor = None

        m1 = get_monitor()
        m2 = get_monitor()
        assert m1 is m2

        # Cleanup
        monitor_mod._default_monitor = None

    def test_start_stop_monitoring(self):
        import src.health.monitor as monitor_mod
        monitor_mod._default_monitor = None

        monitor = start_monitoring(config=HealthConfig(
            check_interval_sec=60,
            check_egress=False,
            check_filesystem=False,
            check_processes=False,
        ))
        assert monitor.is_running is True

        stop_monitoring()
        assert monitor.is_running is False

        monitor_mod._default_monitor = None
