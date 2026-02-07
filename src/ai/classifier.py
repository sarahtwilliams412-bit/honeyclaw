#!/usr/bin/env python3
"""
Honeyclaw Attacker Sophistication Classifier

Real-time classification of attacker skill level based on:
- Command sequence patterns (automated vs manual)
- Typing speed and patterns (key timing analysis)
- Tool signatures (Metasploit, Cobalt Strike, custom)
- Evasion technique usage
- Knowledge of system internals

Classification levels:
  AUTOMATED    (0.0-0.2): bots, scanners
  SCRIPT_KIDDIE (0.2-0.4): copy-paste exploits
  SKILLED      (0.4-0.7): manual ops, some evasion
  ADVANCED     (0.7-0.9): custom tools, good OPSEC
  APT          (0.9-1.0): state-level TTPs
"""

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class SophisticationLevel(Enum):
    """Attacker sophistication classification."""
    AUTOMATED = "automated"
    SCRIPT_KIDDIE = "script_kiddie"
    SKILLED = "skilled"
    ADVANCED = "advanced"
    APT = "apt"


@dataclass
class CommandEvent:
    """A single command event with timing."""
    command: str
    timestamp: float
    inter_command_delay: float = 0.0  # seconds since last command


@dataclass
class Classification:
    """Sophistication classification result."""
    level: SophisticationLevel
    score: float  # 0.0 - 1.0
    confidence: float  # 0.0 - 1.0
    signals: Dict[str, float] = field(default_factory=dict)
    command_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.value,
            "score": round(self.score, 3),
            "confidence": round(self.confidence, 3),
            "signals": {k: round(v, 3) for k, v in self.signals.items()},
            "command_count": self.command_count,
        }


# --- Known tool signatures ---

AUTOMATED_SIGNATURES = [
    # Metasploit
    r"^id$",
    r"^uname -a$",
    r"^cat /etc/issue$",
    r"echo\s+\w+\s*>\s*/tmp/",
    r"/dev/tcp/",
    r"msfvenom",
    r"meterpreter",
    # Mirai / IoT botnets
    r"cd /tmp; wget",
    r"busybox\s+\w+",
    r"/bin/busybox",
    r"tftp\s+-g",
    # Common scanners
    r"^cat /proc/cpuinfo$",
    r"^free -m$",
    r"(cat|head)\s+/etc/passwd\s*$",
]

EVASION_PATTERNS = [
    # History evasion
    r"unset HISTFILE",
    r"export HISTFILE=/dev/null",
    r"set \+o history",
    r"history -c",
    r"shred.*\.bash_history",
    # Log evasion
    r"rm.*(/var/log|auth\.log|syslog|wtmp|lastlog)",
    r"echo\s*>\s*/var/log",
    r"truncate.*log",
    # Anti-forensics
    r"timestomp",
    r"touch -r",
    r"find.*-exec.*shred",
    # Process hiding
    r"mount.*-o.*bind.*/proc",
    r"ld_preload",
    r"LD_PRELOAD",
]

ADVANCED_TECHNIQUES = [
    # Custom tooling indicators
    r"python3?\s+-c\s+['\"]import",
    r"perl\s+-e\s+['\"]",
    r"ruby\s+-e\s+['\"]",
    # Living off the land
    r"openssl\s+s_client",
    r"ncat\s+--ssl",
    r"socat",
    # Container awareness
    r"cat\s+/proc/1/cgroup",
    r"ls.*\.dockerenv",
    r"capsh\s+--print",
    r"cat\s+/proc/self/status.*Cap",
    # Persistence
    r"crontab\s+-e",
    r"systemctl.*enable",
    r"\.bashrc",
    r"authorized_keys",
    # Lateral movement
    r"ssh-keyscan",
    r"nmap",
    r"arp\s+-a",
    r"ip\s+neigh",
    # Data staging
    r"tar\s+czf",
    r"zip\s+.*-r",
    r"base64\s+",
]

APT_INDICATORS = [
    # Custom C2
    r"dns.*txt.*record",
    r"icmp.*tunnel",
    r"(encode|decode).*base(32|64)",
    # Advanced persistence
    r"insmod",
    r"modprobe",
    r"/etc/ld\.so\.preload",
    r"eBPF|bpf_load",
    # Kernel exploitation
    r"dirty.*cow|dirtypipe",
    r"CVE-\d{4}-\d+",
    r"exploit",
    r"/proc/kallsyms",
    # Advanced recon
    r"ethtool",
    r"/proc/net/arp",
    r"dmidecode",
    r"lspci",
]


class SophisticationClassifier:
    """
    Classifies attacker sophistication in real-time.

    Feed commands as they arrive; the classifier maintains state
    and refines its assessment over time.
    """

    def __init__(self):
        self._events: List[CommandEvent] = []
        self._last_timestamp: float = 0.0
        self._classification: Optional[Classification] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_command(self, command: str, timestamp: Optional[float] = None) -> Classification:
        """
        Add a command and return updated classification.

        Args:
            command: The command string
            timestamp: Event timestamp (default: now)

        Returns:
            Updated Classification
        """
        ts = timestamp or time.time()
        delay = ts - self._last_timestamp if self._last_timestamp > 0 else 0.0
        self._last_timestamp = ts

        event = CommandEvent(command=command, timestamp=ts, inter_command_delay=delay)
        self._events.append(event)

        self._classification = self._classify()
        return self._classification

    def get_classification(self) -> Classification:
        """Get the current classification."""
        if self._classification is None:
            return Classification(
                level=SophisticationLevel.AUTOMATED,
                score=0.0,
                confidence=0.0,
            )
        return self._classification

    def reset(self):
        """Reset classifier state."""
        self._events.clear()
        self._last_timestamp = 0.0
        self._classification = None

    # ------------------------------------------------------------------
    # Classification logic
    # ------------------------------------------------------------------

    def _classify(self) -> Classification:
        """Run all classification signals and compute final score."""
        signals: Dict[str, float] = {}

        # Signal 1: Timing patterns
        signals["timing"] = self._analyze_timing()

        # Signal 2: Command diversity
        signals["diversity"] = self._analyze_diversity()

        # Signal 3: Automated tool signatures
        signals["automation"] = self._detect_automation()

        # Signal 4: Evasion techniques
        signals["evasion"] = self._detect_evasion()

        # Signal 5: Advanced techniques
        signals["advanced"] = self._detect_advanced()

        # Signal 6: APT indicators
        signals["apt"] = self._detect_apt()

        # Signal 7: Command ordering logic
        signals["methodology"] = self._analyze_methodology()

        # Compute weighted score
        weights = {
            "timing": 0.15,
            "diversity": 0.10,
            "automation": -0.20,  # Automation lowers score
            "evasion": 0.15,
            "advanced": 0.20,
            "apt": 0.25,
            "methodology": 0.15,
        }

        raw_score = sum(signals[k] * weights[k] for k in weights)
        # Normalize to 0-1 range
        score = max(0.0, min(1.0, (raw_score + 0.2) / 1.2))

        # Confidence increases with more commands
        n = len(self._events)
        confidence = min(1.0, n / 10.0)  # Full confidence after 10 commands

        # Map score to level
        level = self._score_to_level(score)

        return Classification(
            level=level,
            score=score,
            confidence=confidence,
            signals=signals,
            command_count=n,
        )

    def _score_to_level(self, score: float) -> SophisticationLevel:
        """Map a numeric score to a sophistication level."""
        if score < 0.2:
            return SophisticationLevel.AUTOMATED
        elif score < 0.4:
            return SophisticationLevel.SCRIPT_KIDDIE
        elif score < 0.7:
            return SophisticationLevel.SKILLED
        elif score < 0.9:
            return SophisticationLevel.ADVANCED
        else:
            return SophisticationLevel.APT

    # ------------------------------------------------------------------
    # Signal analysis methods
    # ------------------------------------------------------------------

    def _analyze_timing(self) -> float:
        """
        Analyze inter-command timing patterns.

        Bots have very consistent, fast timing.
        Humans have variable timing with pauses.
        """
        if len(self._events) < 3:
            return 0.3

        delays = [e.inter_command_delay for e in self._events[1:] if e.inter_command_delay > 0]
        if not delays:
            return 0.3

        avg_delay = sum(delays) / len(delays)
        # Variance in timing
        variance = sum((d - avg_delay) ** 2 for d in delays) / len(delays)
        stddev = variance ** 0.5

        # Very consistent timing = likely automated (low score)
        # Variable timing = likely human (higher score)
        coefficient_of_variation = stddev / avg_delay if avg_delay > 0 else 0

        if coefficient_of_variation < 0.1:
            return 0.1  # Very consistent = bot
        elif coefficient_of_variation < 0.3:
            return 0.3  # Somewhat consistent = scripted
        elif coefficient_of_variation < 0.8:
            return 0.6  # Variable = human
        else:
            return 0.8  # Very variable = deliberate human

    def _analyze_diversity(self) -> float:
        """Analyze command diversity and uniqueness."""
        if not self._events:
            return 0.0

        commands = [e.command.strip().split()[0] for e in self._events if e.command.strip()]
        unique_ratio = len(set(commands)) / len(commands) if commands else 0

        # High diversity = more sophisticated
        if unique_ratio > 0.8:
            return 0.8
        elif unique_ratio > 0.5:
            return 0.5
        else:
            return 0.2

    def _detect_automation(self) -> float:
        """Detect signs of automated/scripted attacks."""
        score = 0.0
        commands = [e.command for e in self._events]

        for cmd in commands:
            for pattern in AUTOMATED_SIGNATURES:
                if re.search(pattern, cmd, re.IGNORECASE):
                    score += 0.3
                    break

        # Rapid sequential commands
        fast_commands = sum(
            1 for e in self._events[1:]
            if 0 < e.inter_command_delay < 0.5
        )
        if fast_commands > len(self._events) * 0.7:
            score += 0.3

        return min(1.0, score)

    def _detect_evasion(self) -> float:
        """Detect evasion technique usage."""
        score = 0.0
        for event in self._events:
            for pattern in EVASION_PATTERNS:
                if re.search(pattern, event.command, re.IGNORECASE):
                    score += 0.25
                    break

        return min(1.0, score)

    def _detect_advanced(self) -> float:
        """Detect advanced technique usage."""
        score = 0.0
        for event in self._events:
            for pattern in ADVANCED_TECHNIQUES:
                if re.search(pattern, event.command, re.IGNORECASE):
                    score += 0.2
                    break

        return min(1.0, score)

    def _detect_apt(self) -> float:
        """Detect APT-level indicators."""
        score = 0.0
        for event in self._events:
            for pattern in APT_INDICATORS:
                if re.search(pattern, event.command, re.IGNORECASE):
                    score += 0.3
                    break

        return min(1.0, score)

    def _analyze_methodology(self) -> float:
        """
        Analyze whether the attacker follows a logical methodology.

        Skilled attackers follow a pattern: recon -> access -> escalate -> persist -> exfil
        Script kiddies execute commands randomly.
        """
        if len(self._events) < 3:
            return 0.3

        # Define command phases
        phases = {
            "recon": {"uname", "whoami", "id", "hostname", "ifconfig", "ip", "netstat",
                       "ss", "ps", "cat", "ls", "find", "env", "w", "who"},
            "access": {"wget", "curl", "scp", "ssh", "ftp"},
            "escalate": {"sudo", "su", "chmod", "chown"},
            "persist": {"crontab", "systemctl", "echo", "cat"},
            "exfil": {"tar", "zip", "base64", "nc", "scp"},
        }

        # Check if commands follow a logical progression
        seen_phases = []
        for event in self._events:
            cmd = event.command.strip().split()[0] if event.command.strip() else ""
            for phase, cmds in phases.items():
                if cmd in cmds and (not seen_phases or seen_phases[-1] != phase):
                    seen_phases.append(phase)
                    break

        # Score based on how many phases and their logical ordering
        phase_order = ["recon", "access", "escalate", "persist", "exfil"]
        unique_phases = list(dict.fromkeys(seen_phases))

        if len(unique_phases) >= 4:
            # Check if they're in logical order
            ordered = all(
                phase_order.index(unique_phases[i]) <= phase_order.index(unique_phases[i + 1])
                for i in range(len(unique_phases) - 1)
                if unique_phases[i] in phase_order and unique_phases[i + 1] in phase_order
            )
            return 0.9 if ordered else 0.7
        elif len(unique_phases) >= 2:
            return 0.5
        else:
            return 0.2
