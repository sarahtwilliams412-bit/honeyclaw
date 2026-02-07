"""Tests for the TimingSimulator."""

import asyncio
import pytest

from src.emulation.timing import TimingSimulator


class TestTimingSimulator:
    def setup_method(self):
        self.timer = TimingSimulator()

    def test_base_delay_positive(self):
        delay = self.timer.compute_delay_ms()
        assert delay >= self.timer.min_delay_ms
        assert delay <= self.timer.max_delay_ms

    def test_disk_command_delay(self):
        """Disk commands should have higher average delay than simple commands."""
        disk_delays = [self.timer.compute_delay_ms("cat /etc/passwd", output_size=1000,
                                                    is_disk_read=True) for _ in range(50)]
        simple_delays = [self.timer.compute_delay_ms("whoami") for _ in range(50)]
        assert sum(disk_delays) / len(disk_delays) > sum(simple_delays) / len(simple_delays)

    def test_network_command_delay(self):
        """Network commands should have higher average delay."""
        net_delays = [self.timer.compute_delay_ms("wget http://example.com",
                                                   is_network=True) for _ in range(50)]
        simple_delays = [self.timer.compute_delay_ms("whoami") for _ in range(50)]
        assert sum(net_delays) / len(net_delays) > sum(simple_delays) / len(simple_delays)

    def test_delay_has_variance(self):
        """Delays should not all be identical (Gaussian jitter)."""
        delays = [self.timer.compute_delay_ms("ls") for _ in range(100)]
        unique = set(delays)
        # With jitter, we should have many unique values
        assert len(unique) > 50

    def test_delay_within_bounds(self):
        """All delays should be within min/max bounds."""
        for _ in range(200):
            delay = self.timer.compute_delay_ms("ls", output_size=100)
            assert delay >= self.timer.min_delay_ms
            assert delay <= self.timer.max_delay_ms

    def test_large_output_increases_delay(self):
        """Larger output sizes should increase disk read delay."""
        small = [self.timer.compute_delay_ms("cat", output_size=100,
                                              is_disk_read=True) for _ in range(50)]
        large = [self.timer.compute_delay_ms("cat", output_size=100000,
                                              is_disk_read=True) for _ in range(50)]
        assert sum(large) / len(large) > sum(small) / len(small)

    def test_typing_delay(self):
        delay = self.timer.typing_delay_ms(10)
        assert delay > 0

    @pytest.mark.asyncio
    async def test_async_delay(self):
        """delay_for should actually sleep."""
        timer = TimingSimulator(base_delay_ms=10.0, jitter_stddev_ms=1.0,
                                min_delay_ms=5.0, max_delay_ms=50.0)
        start = asyncio.get_event_loop().time()
        await timer.delay_for("ls")
        elapsed = (asyncio.get_event_loop().time() - start) * 1000
        assert elapsed >= 4.0  # At least min_delay minus small tolerance

    def test_is_disk_command(self):
        assert TimingSimulator._is_disk_command("cat /etc/passwd")
        assert TimingSimulator._is_disk_command("grep root /etc/passwd")
        assert not TimingSimulator._is_disk_command("whoami")

    def test_is_network_command(self):
        assert TimingSimulator._is_network_command("wget http://x.com")
        assert TimingSimulator._is_network_command("curl http://x.com")
        assert TimingSimulator._is_network_command("ssh host")
        assert not TimingSimulator._is_network_command("ls")

    def test_is_cpu_command(self):
        assert TimingSimulator._is_cpu_command("find / -name foo")
        assert TimingSimulator._is_cpu_command("sort file.txt")
        assert not TimingSimulator._is_cpu_command("echo hello")
