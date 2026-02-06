#!/usr/bin/env python3
"""
Behavioral Fingerprint Extractor

Extracts unique fingerprints from attacker behavior patterns:
- Command sequences and ordering
- Typing patterns and timing
- Typos and corrections
- Session patterns (time of day, duration)
- Reconnaissance vs exploitation phases
"""

import hashlib
import re
import statistics
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from collections import Counter


@dataclass
class CommandPattern:
    """Single command with timing metadata"""
    command: str
    timestamp: float
    time_since_last: float = 0.0  # Seconds since previous command
    has_typo: bool = False
    typo_corrected: bool = False
    is_recon: bool = False
    is_exploit: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'command': self.command,
            'time_since_last': round(self.time_since_last, 3),
            'has_typo': self.has_typo,
            'is_recon': self.is_recon,
            'is_exploit': self.is_exploit,
        }


@dataclass
class TypingPattern:
    """Keystroke dynamics fingerprint"""
    avg_char_delay: float = 0.0  # Average ms between keystrokes
    char_delay_stddev: float = 0.0
    avg_word_pause: float = 0.0  # Pause at word boundaries
    backspace_rate: float = 0.0  # Backspaces per 100 chars
    common_typos: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'avg_char_delay_ms': round(self.avg_char_delay, 1),
            'char_delay_stddev': round(self.char_delay_stddev, 1),
            'avg_word_pause_ms': round(self.avg_word_pause, 1),
            'backspace_rate': round(self.backspace_rate, 2),
            'common_typos': self.common_typos[:5],
        }


@dataclass
class SessionPattern:
    """Session-level behavioral patterns"""
    time_of_day: int = 0  # Hour (0-23) when session started
    day_of_week: int = 0  # 0=Monday, 6=Sunday
    session_duration: float = 0.0  # Seconds
    command_count: int = 0
    commands_per_minute: float = 0.0
    idle_periods: List[float] = field(default_factory=list)  # Gaps > 5s
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'time_of_day': self.time_of_day,
            'day_of_week': self.day_of_week,
            'session_duration_s': round(self.session_duration, 1),
            'command_count': self.command_count,
            'commands_per_minute': round(self.commands_per_minute, 2),
            'idle_periods': len(self.idle_periods),
        }


@dataclass
class BehaviorFingerprint:
    """Complete behavioral fingerprint"""
    # Command patterns
    command_sequence: List[str] = field(default_factory=list)
    command_sequence_hash: str = ""
    command_n_grams: Dict[str, int] = field(default_factory=dict)
    n_gram_hash: str = ""
    
    # Phase detection
    recon_commands: List[str] = field(default_factory=list)
    exploit_commands: List[str] = field(default_factory=list)
    phase_progression: str = ""  # e.g., "recon->exploit->persist"
    
    # Typing patterns
    typing: TypingPattern = field(default_factory=TypingPattern)
    
    # Session patterns
    session: SessionPattern = field(default_factory=SessionPattern)
    
    # Combined fingerprint
    behavior_hash: str = ""
    
    # Threat assessment
    threat_indicators: List[str] = field(default_factory=list)
    ttp_matches: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'command_sequence_hash': self.command_sequence_hash,
            'command_count': len(self.command_sequence),
            'n_gram_hash': self.n_gram_hash,
            'phase_progression': self.phase_progression,
            'recon_commands': len(self.recon_commands),
            'exploit_commands': len(self.exploit_commands),
            'typing': self.typing.to_dict(),
            'session': self.session.to_dict(),
            'behavior_hash': self.behavior_hash,
            'threat_indicators': self.threat_indicators,
            'ttp_matches': self.ttp_matches,
        }


class BehaviorFingerprintExtractor:
    """
    Extracts behavioral fingerprints from attacker sessions.
    
    Behavioral fingerprinting is powerful because:
    1. Attackers develop habits and muscle memory
    2. Different tools/playbooks create different patterns
    3. Timing can indicate human vs automated
    4. Command sequences often match known TTPs
    
    This can correlate the same attacker across different IPs
    and identify threat actors by their operational patterns.
    """
    
    # Commands that indicate reconnaissance phase
    RECON_COMMANDS = {
        'ls', 'dir', 'pwd', 'cd', 'cat', 'head', 'tail', 'less', 'more',
        'find', 'locate', 'which', 'whereis', 'type',
        'whoami', 'id', 'uname', 'hostname', 'ifconfig', 'ip',
        'netstat', 'ss', 'ps', 'top', 'htop', 'w', 'who', 'last',
        'env', 'printenv', 'set', 'echo',
        'df', 'du', 'free', 'lsblk', 'mount',
        'crontab', 'systemctl', 'service',
        'history', 'cat /etc/passwd', 'cat /etc/shadow',
        'getent', 'groups', 'sudo -l',
    }
    
    # Commands that indicate exploitation/persistence phase
    EXPLOIT_COMMANDS = {
        'wget', 'curl', 'fetch', 'scp', 'rsync',  # Download payloads
        'chmod', 'chown', 'chattr',  # Modify permissions
        'useradd', 'adduser', 'passwd', 'usermod',  # User manipulation
        'ssh-keygen', 'authorized_keys',  # SSH backdoors
        'crontab -e', 'at', 'systemctl enable',  # Persistence
        'iptables', 'ufw', 'firewall-cmd',  # Firewall manipulation
        'kill', 'pkill', 'killall',  # Process manipulation
        'rm -rf', 'shred', 'wipe',  # Covering tracks
        'base64', 'xxd', 'openssl',  # Encoding/crypto
        'nc', 'ncat', 'netcat', 'socat',  # Reverse shells
        'python -c', 'perl -e', 'ruby -e', 'php -r',  # One-liners
        'gcc', 'make', 'cc',  # Compilation
        'nmap', 'masscan', 'zmap',  # Scanning
    }
    
    # Known TTP patterns (MITRE ATT&CK inspired)
    TTP_PATTERNS = {
        'T1087_account_discovery': [
            ['whoami', 'id'],
            ['cat', '/etc/passwd'],
            ['getent', 'passwd'],
        ],
        'T1083_file_discovery': [
            ['ls', 'find'],
            ['ls', 'cat'],
            ['find', '/', '-name'],
        ],
        'T1082_system_discovery': [
            ['uname', 'hostname'],
            ['uname', '-a'],
            ['cat', '/etc/os-release'],
        ],
        'T1059_command_scripting': [
            ['bash', '-c'],
            ['sh', '-c'],
            ['python', '-c'],
        ],
        'T1105_ingress_transfer': [
            ['wget', 'http'],
            ['curl', '-o'],
            ['scp', '@'],
        ],
        'T1053_persistence_cron': [
            ['crontab', '-e'],
            ['echo', 'crontab'],
            ['/etc/cron'],
        ],
        'T1098_ssh_key_backdoor': [
            ['mkdir', '.ssh'],
            ['echo', 'authorized_keys'],
            ['ssh-keygen'],
        ],
    }
    
    # Common typo patterns (indicates human vs bot)
    TYPO_PATTERNS = [
        (r'sl\b', 'ls'),  # Common ls typo
        (r'gerp\b', 'grep'),
        (r'cta\b', 'cat'),
        (r'cdm\b', 'cmd'),
        (r'pign\b', 'ping'),
        (r'ifocnfig\b', 'ifconfig'),
        (r'suod\b', 'sudo'),
        (r'grpe\b', 'grep'),
        (r'tial\b', 'tail'),
        (r'ehco\b', 'echo'),
        (r'chmdo\b', 'chmod'),
        (r'mkidr\b', 'mkdir'),
        (r'rn\b', 'rm'),
    ]
    
    def __init__(self):
        self._command_cache = []
        self._keystroke_timings = []
    
    def extract_from_commands(self, commands: List[CommandPattern]) -> BehaviorFingerprint:
        """
        Extract behavioral fingerprint from a sequence of commands.
        
        Args:
            commands: List of CommandPattern objects with timing info
        """
        fp = BehaviorFingerprint()
        
        if not commands:
            return fp
        
        # Extract command sequence (normalized)
        fp.command_sequence = [self._normalize_command(c.command) for c in commands]
        fp.command_sequence_hash = self._hash_sequence(fp.command_sequence)
        
        # Generate n-grams (command pairs/triples)
        fp.command_n_grams = self._generate_ngrams(fp.command_sequence, n=2)
        fp.n_gram_hash = self._hash_ngrams(fp.command_n_grams)
        
        # Classify commands by phase
        for cmd in commands:
            normalized = self._normalize_command(cmd.command)
            if self._is_recon_command(normalized):
                cmd.is_recon = True
                fp.recon_commands.append(normalized)
            if self._is_exploit_command(normalized):
                cmd.is_exploit = True
                fp.exploit_commands.append(normalized)
            if self._has_typo(cmd.command):
                cmd.has_typo = True
        
        # Determine phase progression
        fp.phase_progression = self._analyze_phases(commands)
        
        # Extract typing patterns
        fp.typing = self._extract_typing_patterns(commands)
        
        # Extract session patterns
        fp.session = self._extract_session_patterns(commands)
        
        # Detect TTPs
        fp.ttp_matches = self._detect_ttps(fp.command_sequence)
        
        # Generate threat indicators
        fp.threat_indicators = self._generate_threat_indicators(fp, commands)
        
        # Compute combined behavior hash
        fp.behavior_hash = self._compute_behavior_hash(fp)
        
        return fp
    
    def extract_from_raw_session(self, session_data: Dict[str, Any]) -> BehaviorFingerprint:
        """
        Extract fingerprint from raw session data (log format).
        
        Expected format:
        {
            'commands': [
                {'command': 'ls -la', 'timestamp': 1234567890.123},
                ...
            ],
            'keystrokes': [  # Optional
                {'char': 'l', 'timestamp': 1234567890.100},
                ...
            ]
        }
        """
        commands = []
        last_ts = None
        
        for cmd_data in session_data.get('commands', []):
            cmd = CommandPattern(
                command=cmd_data.get('command', ''),
                timestamp=cmd_data.get('timestamp', 0),
            )
            if last_ts is not None:
                cmd.time_since_last = cmd.timestamp - last_ts
            last_ts = cmd.timestamp
            commands.append(cmd)
        
        fp = self.extract_from_commands(commands)
        
        # If keystroke data available, enhance typing patterns
        keystrokes = session_data.get('keystrokes', [])
        if keystrokes:
            fp.typing = self._extract_typing_from_keystrokes(keystrokes)
        
        return fp
    
    def _normalize_command(self, command: str) -> str:
        """Normalize command for fingerprinting"""
        # Get base command (first word)
        parts = command.strip().split()
        if not parts:
            return ""
        
        base = parts[0].lower()
        
        # Remove path prefix
        if '/' in base:
            base = base.split('/')[-1]
        
        return base
    
    def _is_recon_command(self, cmd: str) -> bool:
        """Check if command is reconnaissance-related"""
        return cmd in self.RECON_COMMANDS
    
    def _is_exploit_command(self, cmd: str) -> bool:
        """Check if command is exploitation-related"""
        return cmd in self.EXPLOIT_COMMANDS
    
    def _has_typo(self, command: str) -> bool:
        """Check if command contains a known typo pattern"""
        for pattern, _ in self.TYPO_PATTERNS:
            if re.search(pattern, command, re.I):
                return True
        return False
    
    def _generate_ngrams(self, sequence: List[str], n: int = 2) -> Dict[str, int]:
        """Generate n-grams from command sequence"""
        ngrams = Counter()
        for i in range(len(sequence) - n + 1):
            ngram = '->'.join(sequence[i:i+n])
            ngrams[ngram] += 1
        return dict(ngrams)
    
    def _hash_sequence(self, sequence: List[str]) -> str:
        """Hash command sequence"""
        if not sequence:
            return ""
        return hashlib.sha256('|'.join(sequence).encode()).hexdigest()[:24]
    
    def _hash_ngrams(self, ngrams: Dict[str, int]) -> str:
        """Hash n-gram distribution"""
        if not ngrams:
            return ""
        # Sort for deterministic ordering
        sorted_ngrams = sorted(ngrams.items())
        content = '|'.join(f"{k}:{v}" for k, v in sorted_ngrams)
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _analyze_phases(self, commands: List[CommandPattern]) -> str:
        """Analyze attack phase progression"""
        phases = []
        current_phase = None
        
        for cmd in commands:
            if cmd.is_recon and current_phase != 'recon':
                if 'recon' not in phases:
                    phases.append('recon')
                current_phase = 'recon'
            elif cmd.is_exploit and current_phase != 'exploit':
                if 'exploit' not in phases:
                    phases.append('exploit')
                current_phase = 'exploit'
        
        return '->'.join(phases) if phases else 'unknown'
    
    def _extract_typing_patterns(self, commands: List[CommandPattern]) -> TypingPattern:
        """Extract typing patterns from command timing"""
        tp = TypingPattern()
        
        # Analyze inter-command timing
        delays = [c.time_since_last for c in commands if c.time_since_last > 0]
        
        if delays:
            # Convert to milliseconds for the pattern
            delays_ms = [d * 1000 for d in delays]
            tp.avg_char_delay = statistics.mean(delays_ms) if delays_ms else 0
            tp.char_delay_stddev = statistics.stdev(delays_ms) if len(delays_ms) > 1 else 0
        
        # Count typos
        typo_count = sum(1 for c in commands if c.has_typo)
        total_chars = sum(len(c.command) for c in commands)
        tp.backspace_rate = (typo_count / max(total_chars, 1)) * 100
        
        # Collect common typos
        typos = []
        for cmd in commands:
            for pattern, correction in self.TYPO_PATTERNS:
                if re.search(pattern, cmd.command, re.I):
                    typos.append(correction)
        tp.common_typos = list(set(typos))
        
        return tp
    
    def _extract_typing_from_keystrokes(self, keystrokes: List[Dict]) -> TypingPattern:
        """Extract detailed typing patterns from keystroke data"""
        tp = TypingPattern()
        
        if len(keystrokes) < 2:
            return tp
        
        # Calculate inter-keystroke delays
        delays = []
        word_pauses = []
        backspace_count = 0
        
        for i in range(1, len(keystrokes)):
            delay = (keystrokes[i]['timestamp'] - keystrokes[i-1]['timestamp']) * 1000  # ms
            
            char = keystrokes[i].get('char', '')
            prev_char = keystrokes[i-1].get('char', '')
            
            if char == '\b' or char == 'backspace':
                backspace_count += 1
            
            # Word boundary detection
            if prev_char == ' ' or delay > 200:
                word_pauses.append(delay)
            else:
                delays.append(delay)
        
        if delays:
            tp.avg_char_delay = statistics.mean(delays)
            tp.char_delay_stddev = statistics.stdev(delays) if len(delays) > 1 else 0
        
        if word_pauses:
            tp.avg_word_pause = statistics.mean(word_pauses)
        
        tp.backspace_rate = (backspace_count / len(keystrokes)) * 100
        
        return tp
    
    def _extract_session_patterns(self, commands: List[CommandPattern]) -> SessionPattern:
        """Extract session-level patterns"""
        sp = SessionPattern()
        
        if not commands:
            return sp
        
        # Time analysis
        first_ts = commands[0].timestamp
        last_ts = commands[-1].timestamp
        
        if first_ts > 0:
            dt = datetime.fromtimestamp(first_ts)
            sp.time_of_day = dt.hour
            sp.day_of_week = dt.weekday()
        
        sp.session_duration = last_ts - first_ts if last_ts > first_ts else 0
        sp.command_count = len(commands)
        
        if sp.session_duration > 0:
            sp.commands_per_minute = (sp.command_count / sp.session_duration) * 60
        
        # Find idle periods (gaps > 5 seconds)
        sp.idle_periods = [c.time_since_last for c in commands if c.time_since_last > 5.0]
        
        return sp
    
    def _detect_ttps(self, command_sequence: List[str]) -> List[str]:
        """Detect known TTPs in command sequence"""
        matches = []
        sequence_str = ' '.join(command_sequence)
        
        for ttp_id, patterns in self.TTP_PATTERNS.items():
            for pattern in patterns:
                # Check if pattern appears in sequence
                pattern_found = True
                for cmd in pattern:
                    if cmd.lower() not in sequence_str.lower():
                        pattern_found = False
                        break
                
                if pattern_found and ttp_id not in matches:
                    matches.append(ttp_id)
                    break
        
        return matches
    
    def _generate_threat_indicators(self, fp: BehaviorFingerprint, 
                                   commands: List[CommandPattern]) -> List[str]:
        """Generate threat indicators based on behavior"""
        indicators = []
        
        # Fast command entry (likely automated)
        if fp.session.commands_per_minute > 30:
            indicators.append('high_command_rate')
        
        # No typos (likely automated)
        typo_count = sum(1 for c in commands if c.has_typo)
        if len(commands) > 10 and typo_count == 0:
            indicators.append('no_typos_suspicious')
        
        # Many typos (human, potentially inexperienced)
        if len(commands) > 5 and typo_count > len(commands) * 0.3:
            indicators.append('high_typo_rate')
        
        # Direct exploitation without recon
        if fp.exploit_commands and not fp.recon_commands:
            indicators.append('direct_exploitation')
        
        # Known TTPs detected
        if fp.ttp_matches:
            indicators.append(f'ttps_detected:{len(fp.ttp_matches)}')
        
        # Unusual timing (odd hours)
        if fp.session.time_of_day in range(2, 6):  # 2 AM - 6 AM
            indicators.append('unusual_hour')
        
        # Long session with few commands (manual browsing)
        if fp.session.session_duration > 600 and fp.session.command_count < 10:
            indicators.append('slow_manual_browsing')
        
        # Download followed by execution pattern
        seq_str = '|'.join(fp.command_sequence)
        if 'wget' in seq_str or 'curl' in seq_str:
            if 'chmod' in seq_str or 'bash' in seq_str or './' in seq_str:
                indicators.append('download_execute_pattern')
        
        return indicators
    
    def _compute_behavior_hash(self, fp: BehaviorFingerprint) -> str:
        """Compute combined behavioral fingerprint hash"""
        components = [
            fp.command_sequence_hash,
            fp.n_gram_hash,
            fp.phase_progression,
            str(int(fp.typing.avg_char_delay // 100)),  # Bucketed timing
            str(fp.session.time_of_day // 4),  # 6-hour buckets
        ]
        combined = '|'.join(filter(None, components))
        return hashlib.sha256(combined.encode()).hexdigest()[:32]
    
    def compute_similarity(self, fp1: BehaviorFingerprint, fp2: BehaviorFingerprint) -> float:
        """Compute behavioral similarity between two fingerprints"""
        if not fp1 or not fp2:
            return 0.0
        
        score = 0.0
        
        # Command sequence similarity
        if fp1.command_sequence_hash and fp1.command_sequence_hash == fp2.command_sequence_hash:
            score += 0.3
        elif fp1.n_gram_hash and fp1.n_gram_hash == fp2.n_gram_hash:
            score += 0.2
        
        # Phase progression match
        if fp1.phase_progression and fp1.phase_progression == fp2.phase_progression:
            score += 0.1
        
        # TTP overlap
        if fp1.ttp_matches and fp2.ttp_matches:
            overlap = len(set(fp1.ttp_matches) & set(fp2.ttp_matches))
            total = len(set(fp1.ttp_matches) | set(fp2.ttp_matches))
            if total > 0:
                score += 0.2 * (overlap / total)
        
        # Timing similarity (within 100ms buckets)
        if abs(fp1.typing.avg_char_delay - fp2.typing.avg_char_delay) < 100:
            score += 0.1
        
        # Session timing similarity (same time-of-day bucket)
        if fp1.session.time_of_day // 4 == fp2.session.time_of_day // 4:
            score += 0.1
        
        # Commands per minute similarity
        if fp1.session.commands_per_minute > 0 and fp2.session.commands_per_minute > 0:
            ratio = min(fp1.session.commands_per_minute, fp2.session.commands_per_minute) / \
                    max(fp1.session.commands_per_minute, fp2.session.commands_per_minute)
            if ratio > 0.7:
                score += 0.1
        
        return min(score, 1.0)
