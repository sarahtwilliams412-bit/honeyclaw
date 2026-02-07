#!/usr/bin/env python3
"""
Honeyclaw Timing Simulator

Adds realistic response delays to prevent timing-based fingerprinting.

Features:
- Gaussian-distributed response delays
- Disk I/O simulation (larger files take longer)
- Network latency simulation
- CPU load simulation
- Configurable jitter
"""

import random
from typing import Dict, Optional


class TimingSimulator:
    """
    Simulates realistic response timing for shell commands.

    Prevents timing-based fingerprinting by adding Gaussian-distributed
    delays that match the expected behavior of a real system.
    """

    def __init__(
        self,
        base_delay_ms: float = 50.0,
        jitter_stddev_ms: float = 20.0,
        disk_delay_per_kb_ms: float = 0.5,
        network_delay_ms: float = 100.0,
    ):
        self.base_delay_ms = base_delay_ms
        self.jitter_stddev_ms = jitter_stddev_ms
        self.disk_delay_per_kb_ms = disk_delay_per_kb_ms
        self.network_delay_ms = network_delay_ms

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
        delay_ms = max(5, random.gauss(base_ms, stddev_ms))

        return delay_ms / 1000.0

    def disk_io_delay(self, size_bytes: int) -> float:
        """
        Simulate disk I/O delay based on data size.

        Args:
            size_bytes: Size of data being read

        Returns:
            Delay in seconds
        """
        size_kb = size_bytes / 1024
        delay_ms = size_kb * self.disk_delay_per_kb_ms
        delay_ms += random.gauss(10, 5)  # Base disk access time
        return max(0.005, delay_ms / 1000.0)

    def network_delay(self) -> float:
        """
        Simulate network latency.

        Returns:
            Delay in seconds
        """
        delay_ms = max(10, random.gauss(self.network_delay_ms, self.network_delay_ms * 0.3))
        return delay_ms / 1000.0

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
