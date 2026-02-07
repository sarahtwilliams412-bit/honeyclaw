#!/usr/bin/env python3
"""
Honeyclaw Timing Simulator

Adds realistic response delays to prevent timing-based fingerprinting.

Features:
- Gaussian-distributed response delays
- Command-specific delay profiles
- Disk I/O simulation (larger files take longer)
- Network latency simulation
- CPU load simulation
- Configurable jitter
- Async support
"""

import asyncio
import random
from typing import Dict, Optional


class TimingSimulator:
    """
    Generates realistic delays for shell command responses. Uses Gaussian
    distribution with configurable mean/stddev to avoid statistical
    detection of uniform honeypot timing.
    """

    def __init__(
        self,
        base_delay_ms: float = 30.0,
        jitter_stddev_ms: float = 15.0,
        disk_read_per_kb_ms: float = 0.3,
        network_latency_ms: float = 100.0,
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

        # Command categories and their typical execution times (ms)
        self._command_profiles: Dict[str, tuple] = {
            # (base_ms, stddev_ms)
            "ls": (30, 10),
            "cat": (20, 8),
            "cd": (5, 2),
            "pwd": (5, 2),
            "whoami": (8, 3),
            "id": (10, 4),
            "uname": (8, 3),
            "hostname": (5, 2),
            "ps": (80, 30),
            "netstat": (120, 40),
            "ss": (60, 20),
            "ifconfig": (40, 15),
            "ip": (30, 10),
            "env": (15, 5),
            "echo": (5, 2),
            "grep": (50, 20),
            "find": (200, 80),
            "which": (20, 8),
            "uptime": (10, 4),
            "w": (30, 10),
            "who": (25, 8),
            "df": (60, 20),
            "free": (15, 5),
            "mount": (20, 8),
            "date": (5, 2),
            "wget": (2000, 500),  # Network command - slow
            "curl": (1500, 400),
            "ssh": (3000, 800),
            "scp": (3000, 800),
            "sudo": (200, 50),   # Password prompt delay
            "history": (10, 3),
            "head": (25, 10),
            "tail": (25, 10),
            "wc": (30, 12),
            "stat": (20, 8),
            "file": (35, 15),
            "touch": (10, 5),
            "mkdir": (15, 6),
            "rm": (20, 8),
            "cp": (50, 20),
            "mv": (40, 15),
            "systemctl": (80, 30),
            "service": (70, 25),
            "apt": (500, 150),
            "dpkg": (100, 40),
            "pip": (200, 60),
            "python": (50, 20),
            "python3": (50, 20),
        }

    def command_delay(self, command: str) -> float:
        """
        Get a realistic delay for a command in seconds.

        Args:
            command: The command name

        Returns:
            Delay in seconds
        """
        cmd = command.strip().split()[0] if command.strip() else ""

        if cmd in self._command_profiles:
            base_ms, stddev_ms = self._command_profiles[cmd]
        else:
            base_ms = self.base_delay_ms
            stddev_ms = self.jitter_stddev_ms

        # Gaussian delay (clamp to positive)
        delay_ms = max(self.min_delay_ms, random.gauss(base_ms, stddev_ms))
        delay_ms = min(delay_ms, self.max_delay_ms)

        return delay_ms / 1000.0

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

    def disk_io_delay(self, size_bytes: int) -> float:
        """
        Simulate disk I/O delay based on data size.

        Args:
            size_bytes: Size of data being read

        Returns:
            Delay in seconds
        """
        size_kb = size_bytes / 1024
        delay_ms = size_kb * self.disk_read_per_kb_ms
        delay_ms += random.gauss(10, 5)  # Base disk access time
        return max(0.005, delay_ms / 1000.0)

    def network_delay(self) -> float:
        """
        Simulate network latency.

        Returns:
            Delay in seconds
        """
        delay_ms = max(10, random.gauss(self.network_latency_ms, self.network_latency_ms * 0.3))
        return delay_ms / 1000.0

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

    def typing_delay(self, text_length: int) -> float:
        """
        Simulate human typing delay for output.

        Args:
            text_length: Length of text being "typed"

        Returns:
            Delay in seconds
        """
        # Average 60 WPM = ~300 chars/min = 5 chars/sec
        char_delay = random.gauss(0.02, 0.008)
        return max(0, text_length * char_delay)

    def typing_delay_ms(self, char_count: int = 1) -> float:
        """
        Simulate the delay of output being 'typed' to the terminal in milliseconds.
        This is for character-by-character output scenarios.
        """
        base = char_count * random.uniform(0.5, 2.0)
        return max(0.5, base + random.gauss(0, 0.5))

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
