"""
Honeyclaw Emulation Module

Provides stateful shell emulation, fake filesystem, timing simulation,
and OS profiles for realistic honeypot interaction.
"""

from .shell import ShellEmulator
from .filesystem import FakeFilesystem
from .timing import TimingSimulator

__all__ = [
    'ShellEmulator',
    'FakeFilesystem',
    'TimingSimulator',
]
