"""
Timing Simulation

Adds realistic response delays to prevent timing-based fingerprinting.
Simulates disk I/O, network latency, and CPU load delays with Gaussian
jitter so responses don't have unnaturally uniform timing.
"""

import asyncio
import random
from typing import Optional


class TimingSimulator:
    """
    Generates realistic delays for shell command responses. Uses Gaussian
    distribution with configurable mean/stddev to avoid statistical
    detection of uniform honeypot timing.
    """

    def __init__(
        self,
        base_delay_ms: float = 15.0,
        jitter_stddev_ms: float = 8.0,
        disk_read_per_kb_ms: float = 0.05,
        network_latency_ms: float = 50.0,
        cpu_factor_ms: float = 5.0,
        min_delay_ms: float = 2.0,
        max_delay_ms: float = 5000.0,
    ):
        self.base_delay_ms = base_delay_ms
        self.jitter_stddev_ms = jitter_stddev_ms
        self.disk_read_per_kb_ms = disk_read_per_kb_ms
        self.network_latency_ms = network_latency_ms
        self.cpu_factor_ms = cpu_factor_ms
        self.min_delay_ms = min_delay_ms
        self.max_delay_ms = max_delay_ms

    def compute_delay_ms(
        self,
        command: str = "",
        output_size: int = 0,
        is_network: bool = False,
        is_disk_read: bool = False,
    ) -> float:
        """
        Compute a realistic delay in milliseconds for a command response.

        Args:
            command: The command being executed (affects delay heuristics).
            output_size: Size of the output in bytes (larger = longer read).
            is_network: Whether the command involves network I/O.
            is_disk_read: Whether the command reads from "disk".
        """
        delay = self.base_delay_ms

        # Add Gaussian jitter
        delay += random.gauss(0, self.jitter_stddev_ms)

        # Disk read simulation
        if is_disk_read or self._is_disk_command(command):
            kb = max(output_size / 1024, 1)
            delay += kb * self.disk_read_per_kb_ms
            # Random disk seek time
            delay += random.uniform(1.0, 10.0)

        # Network commands get extra latency
        if is_network or self._is_network_command(command):
            delay += self.network_latency_ms + random.gauss(0, 20.0)

        # CPU-intensive commands
        if self._is_cpu_command(command):
            delay += self.cpu_factor_ms * random.uniform(1.0, 5.0)

        # Clamp to bounds
        delay = max(self.min_delay_ms, min(delay, self.max_delay_ms))
        return delay

    async def delay_for(
        self,
        command: str = "",
        output_size: int = 0,
        is_network: bool = False,
        is_disk_read: bool = False,
    ):
        """Async sleep for a realistic delay period."""
        ms = self.compute_delay_ms(command, output_size, is_network, is_disk_read)
        await asyncio.sleep(ms / 1000.0)

    @staticmethod
    def _is_disk_command(command: str) -> bool:
        """Check if a command typically reads from disk."""
        disk_commands = {
            "cat", "head", "tail", "less", "more", "grep", "find",
            "ls", "stat", "file", "wc", "diff", "sort", "du",
        }
        cmd = command.split()[0] if command.split() else ""
        return cmd in disk_commands

    @staticmethod
    def _is_network_command(command: str) -> bool:
        """Check if a command involves network I/O."""
        net_commands = {
            "wget", "curl", "ssh", "scp", "sftp", "ping",
            "dig", "nslookup", "traceroute", "nc", "ncat",
            "apt", "yum", "pip",
        }
        cmd = command.split()[0] if command.split() else ""
        return cmd in net_commands

    @staticmethod
    def _is_cpu_command(command: str) -> bool:
        """Check if a command would be CPU-intensive on a real system."""
        cpu_commands = {
            "find", "grep", "sort", "awk", "sed", "tar", "gzip",
            "bzip2", "xz", "openssl", "sha256sum", "md5sum",
        }
        cmd = command.split()[0] if command.split() else ""
        return cmd in cpu_commands

    def typing_delay_ms(self, char_count: int = 1) -> float:
        """
        Simulate the delay of output being 'typed' to the terminal.
        This is for character-by-character output scenarios.
        """
        base = char_count * random.uniform(0.5, 2.0)
        return max(0.5, base + random.gauss(0, 0.5))
