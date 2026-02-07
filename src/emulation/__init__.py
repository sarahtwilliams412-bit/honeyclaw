"""
HoneyClaw Emulation Layer - Stateful Interaction & Realistic Environment

Provides realistic filesystem emulation, state-aware shell, and timing
simulation to increase attacker dwell time and intelligence gathering.
"""

from src.emulation.filesystem import FakeFilesystem
from src.emulation.shell import ShellEmulator
from src.emulation.timing import TimingSimulator

__all__ = ["FakeFilesystem", "ShellEmulator", "TimingSimulator"]
