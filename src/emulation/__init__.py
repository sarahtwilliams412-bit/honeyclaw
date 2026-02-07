"""
HoneyClaw Emulation Layer - Stateful Interaction & Realistic Environment

Provides realistic filesystem emulation, state-aware shell, timing simulation,
and OS profiles for realistic honeypot interaction to increase attacker dwell
time and intelligence gathering.
"""

from .filesystem import FakeFilesystem, load_profile
from .shell import ShellEmulator
from .timing import TimingSimulator

__all__ = [
    "FakeFilesystem",
    "ShellEmulator",
    "TimingSimulator",
    "load_profile",
]
