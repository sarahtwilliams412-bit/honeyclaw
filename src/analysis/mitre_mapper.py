#!/usr/bin/env python3
"""
Honeyclaw MITRE ATT&CK Mapper

Maps observed honeypot behaviors to MITRE ATT&CK tactics and techniques.
Provides auto-tagging for events as they flow through the logging pipeline.

Supports:
- Event-type-based mapping (connection, auth, command, etc.)
- Pattern-based command analysis (regex matching on commands/payloads)
- Custom mapping rules loaded from YAML configuration
- Enrichment of both dict events and HoneypotEvent dataclass instances

Usage:
    from src.analysis.mitre_mapper import MitreMapper, enrich_event

    mapper = MitreMapper()

    # Enrich a raw event dict
    event = {'event': 'login_attempt', 'username': 'root', 'command': 'cat /etc/shadow'}
    enriched = mapper.enrich(event)
    # enriched['mitre_tactics'] -> ['Credential Access', 'Initial Access']
    # enriched['mitre_techniques'] -> ['T1078', 'T1003.008']
"""

import os
import re
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger('honeyclaw.analysis.mitre')


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class MitreMapping:
    """A single MITRE ATT&CK mapping result."""
    tactic: str           # e.g. "Initial Access"
    technique_id: str     # e.g. "T1078"
    technique_name: str   # e.g. "Valid Accounts"
    confidence: float = 1.0  # 0.0-1.0
    source: str = ""      # What triggered this mapping


@dataclass
class PatternRule:
    """A regex-based rule that maps command/payload patterns to MITRE."""
    pattern: re.Pattern
    tactic: str
    technique_id: str
    technique_name: str
    field: str = "command"     # Which event field to match against
    confidence: float = 0.9


# ---------------------------------------------------------------------------
# MITRE ATT&CK reference data
# ---------------------------------------------------------------------------

# Tactic ID -> Tactic Name (Enterprise ATT&CK v14)
TACTIC_NAMES = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}

# Event type -> default MITRE mappings
EVENT_TYPE_MAPPINGS: Dict[str, List[Tuple[str, str, str]]] = {
    # (tactic, technique_id, technique_name)
    "connection": [
        ("Reconnaissance", "T1595", "Active Scanning"),
    ],
    "auth_attempt": [
        ("Initial Access", "T1078", "Valid Accounts"),
        ("Credential Access", "T1110", "Brute Force"),
    ],
    "auth_success": [
        ("Initial Access", "T1078", "Valid Accounts"),
    ],
    "auth_failure": [
        ("Credential Access", "T1110", "Brute Force"),
    ],
    "login_attempt": [
        ("Initial Access", "T1078", "Valid Accounts"),
        ("Credential Access", "T1110", "Brute Force"),
    ],
    "login_success": [
        ("Initial Access", "T1078", "Valid Accounts"),
    ],
    "session_established": [
        ("Initial Access", "T1078", "Valid Accounts"),
    ],
    "pubkey_attempt": [
        ("Initial Access", "T1078.004", "Valid Accounts: Cloud Accounts"),
        ("Credential Access", "T1110", "Brute Force"),
    ],
    "command": [
        ("Execution", "T1059", "Command and Scripting Interpreter"),
    ],
    "shell_command": [
        ("Execution", "T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    ],
    "file_access": [
        ("Collection", "T1005", "Data from Local System"),
    ],
    "file_read": [
        ("Collection", "T1005", "Data from Local System"),
    ],
    "file_upload": [
        ("Execution", "T1105", "Ingress Tool Transfer"),
    ],
    "data_exfil": [
        ("Exfiltration", "T1041", "Exfiltration Over C2 Channel"),
    ],
    "scan": [
        ("Reconnaissance", "T1595", "Active Scanning"),
    ],
    "exploit_attempt": [
        ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    ],
    "malware": [
        ("Execution", "T1204", "User Execution"),
    ],
    "lateral_movement": [
        ("Lateral Movement", "T1021", "Remote Services"),
    ],
    "api_request": [
        ("Reconnaissance", "T1595.002", "Active Scanning: Vulnerability Scanning"),
    ],
    "http_request": [
        ("Reconnaissance", "T1595.002", "Active Scanning: Vulnerability Scanning"),
    ],
    "rate_limit_auth": [
        ("Credential Access", "T1110.001", "Brute Force: Password Guessing"),
    ],
    "rate_limit_connection": [
        ("Reconnaissance", "T1595.001", "Active Scanning: Scanning IP Blocks"),
    ],
    # Enterprise-sim service events
    "rdp_connection": [
        ("Lateral Movement", "T1021.001", "Remote Services: Remote Desktop Protocol"),
    ],
    "winrm_connection": [
        ("Lateral Movement", "T1021.006", "Remote Services: Windows Remote Management"),
    ],
    "ldap_query": [
        ("Discovery", "T1087.002", "Account Discovery: Domain Account"),
    ],
    "smb_connection": [
        ("Lateral Movement", "T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    ],
}

# Pattern-based rules for command analysis
DEFAULT_PATTERN_RULES: List[Dict[str, Any]] = [
    # File and directory discovery
    {
        "pattern": r"\b(ls|dir|find|tree)\b",
        "tactic": "Discovery",
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "field": "command",
    },
    # System information discovery
    {
        "pattern": r"\b(uname|hostname|hostnamectl|lsb_release|cat\s+/etc/(os-release|issue|redhat-release))\b",
        "tactic": "Discovery",
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "field": "command",
    },
    # Process discovery
    {
        "pattern": r"\b(ps\s|ps$|top\b|htop\b|pstree\b)",
        "tactic": "Discovery",
        "technique_id": "T1057",
        "technique_name": "Process Discovery",
        "field": "command",
    },
    # Network configuration discovery
    {
        "pattern": r"\b(ifconfig|ip\s+(addr|route|link)|netstat|ss\s|arp\b|route\b)",
        "tactic": "Discovery",
        "technique_id": "T1016",
        "technique_name": "System Network Configuration Discovery",
        "field": "command",
    },
    # Network connections discovery
    {
        "pattern": r"\b(netstat\s+-[a-z]*[tl]|ss\s+-[a-z]*[tl]|lsof\s+-i)",
        "tactic": "Discovery",
        "technique_id": "T1049",
        "technique_name": "System Network Connections Discovery",
        "field": "command",
    },
    # Account discovery
    {
        "pattern": r"\b(whoami|id\b|who\b|w\b|users\b|last\b|cat\s+/etc/passwd)",
        "tactic": "Discovery",
        "technique_id": "T1087",
        "technique_name": "Account Discovery",
        "field": "command",
    },
    # Permission groups discovery
    {
        "pattern": r"\b(groups\b|cat\s+/etc/group|getent\s+group)",
        "tactic": "Discovery",
        "technique_id": "T1069",
        "technique_name": "Permission Groups Discovery",
        "field": "command",
    },
    # Credential access - /etc/shadow
    {
        "pattern": r"(cat|less|more|head|tail|vi|vim|nano|strings)\s+/etc/shadow",
        "tactic": "Credential Access",
        "technique_id": "T1003.008",
        "technique_name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
        "field": "command",
    },
    # Credential access - SSH keys
    {
        "pattern": r"(cat|less|more|head|tail|cp|scp)\s+.*\.ssh/(id_rsa|id_ed25519|authorized_keys|known_hosts)",
        "tactic": "Credential Access",
        "technique_id": "T1552.004",
        "technique_name": "Unsecured Credentials: Private Keys",
        "field": "command",
    },
    # Credential access - AWS credentials
    {
        "pattern": r"(cat|less|more|head|tail)\s+.*\.aws/(credentials|config)",
        "tactic": "Credential Access",
        "technique_id": "T1552.001",
        "technique_name": "Unsecured Credentials: Credentials In Files",
        "field": "command",
    },
    # Data from local system (reading sensitive files)
    {
        "pattern": r"(cat|less|more|head|tail|strings)\s+.*(\.conf|\.cfg|\.ini|\.env|\.properties|config\.|secrets)",
        "tactic": "Collection",
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "field": "command",
    },
    # Exfiltration via network tools
    {
        "pattern": r"\b(wget|curl|nc|ncat|netcat|scp|rsync|ftp)\b.*\b(http|ftp|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)",
        "tactic": "Exfiltration",
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "field": "command",
    },
    # Ingress tool transfer
    {
        "pattern": r"\b(wget|curl)\s+.*(http|ftp).*(-O|-o|>)",
        "tactic": "Command and Control",
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "field": "command",
    },
    # Privilege escalation - sudo
    {
        "pattern": r"\bsudo\b",
        "tactic": "Privilege Escalation",
        "technique_id": "T1548.003",
        "technique_name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "field": "command",
    },
    # Privilege escalation - SUID
    {
        "pattern": r"\bchmod\s+[0-7]*[4-7][0-7]{2}\b|\bchmod\s+\+s\b",
        "tactic": "Privilege Escalation",
        "technique_id": "T1548.001",
        "technique_name": "Abuse Elevation Control Mechanism: Setuid and Setgid",
        "field": "command",
    },
    # Privilege escalation - su
    {
        "pattern": r"\bsu\s+(root|-\s|--login)",
        "tactic": "Privilege Escalation",
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "field": "command",
    },
    # Persistence - cron
    {
        "pattern": r"\b(crontab|/etc/cron)",
        "tactic": "Persistence",
        "technique_id": "T1053.003",
        "technique_name": "Scheduled Task/Job: Cron",
        "field": "command",
    },
    # Persistence - systemd
    {
        "pattern": r"\b(systemctl\s+(enable|start|daemon-reload)|/etc/systemd)",
        "tactic": "Persistence",
        "technique_id": "T1543.002",
        "technique_name": "Create or Modify System Process: Systemd Service",
        "field": "command",
    },
    # Persistence - authorized_keys modification
    {
        "pattern": r"(echo|>>|tee).*authorized_keys",
        "tactic": "Persistence",
        "technique_id": "T1098.004",
        "technique_name": "Account Manipulation: SSH Authorized Keys",
        "field": "command",
    },
    # Defense evasion - log clearing
    {
        "pattern": r"\b(rm|truncate|>)\s+.*(\.log|/var/log|auth\.log|syslog|wtmp|lastlog|history)",
        "tactic": "Defense Evasion",
        "technique_id": "T1070.002",
        "technique_name": "Indicator Removal: Clear Linux or Mac System Logs",
        "field": "command",
    },
    # Defense evasion - history clearing
    {
        "pattern": r"(history\s+-c|unset\s+HISTFILE|export\s+HISTSIZE=0|>/dev/null.*history|rm.*\.bash_history)",
        "tactic": "Defense Evasion",
        "technique_id": "T1070.003",
        "technique_name": "Indicator Removal: Clear Command History",
        "field": "command",
    },
    # Defense evasion - timestomping
    {
        "pattern": r"\btouch\s+-[a-z]*t\b",
        "tactic": "Defense Evasion",
        "technique_id": "T1070.006",
        "technique_name": "Indicator Removal: Timestomp",
        "field": "command",
    },
    # Execution - Python
    {
        "pattern": r"\bpython[23]?\s+(-c|.*\.py)",
        "tactic": "Execution",
        "technique_id": "T1059.006",
        "technique_name": "Command and Scripting Interpreter: Python",
        "field": "command",
    },
    # Execution - Perl/Ruby
    {
        "pattern": r"\b(perl|ruby)\s+(-e|.*\.(pl|rb))",
        "tactic": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "field": "command",
    },
    # Execution - encoded commands (base64)
    {
        "pattern": r"(base64\s+-d|echo\s+.*\|\s*base64|python.*decode\()",
        "tactic": "Defense Evasion",
        "technique_id": "T1140",
        "technique_name": "Deobfuscate/Decode Files or Information",
        "field": "command",
    },
    # Lateral movement - SSH
    {
        "pattern": r"\bssh\s+",
        "tactic": "Lateral Movement",
        "technique_id": "T1021.004",
        "technique_name": "Remote Services: SSH",
        "field": "command",
    },
    # Lateral movement - SCP
    {
        "pattern": r"\bscp\s+",
        "tactic": "Lateral Movement",
        "technique_id": "T1021.004",
        "technique_name": "Remote Services: SSH",
        "field": "command",
    },
    # Container escape patterns
    {
        "pattern": r"(docker\s+run|nsenter|mount.*/proc|/var/run/docker\.sock|kubectl\s+exec)",
        "tactic": "Privilege Escalation",
        "technique_id": "T1611",
        "technique_name": "Escape to Host",
        "field": "command",
    },
    # SQL injection (in path/query fields)
    {
        "pattern": r"('|\")\s*(or|and)\s+('|\")?\d+('|\")?\s*=\s*('|\")?\d+|union\s+select|;\s*(drop|delete|insert|update)\s",
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "field": "path",
    },
    # Path traversal
    {
        "pattern": r"\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f",
        "tactic": "Discovery",
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "field": "path",
    },
    # Software discovery
    {
        "pattern": r"\b(dpkg\s+-l|rpm\s+-qa|apt\s+list|pip\s+list|gem\s+list|npm\s+list)",
        "tactic": "Discovery",
        "technique_id": "T1518",
        "technique_name": "Software Discovery",
        "field": "command",
    },
    # Crypto mining
    {
        "pattern": r"(xmrig|minergate|coinhive|cryptonight|stratum\+tcp|mining\.pool|hashrate)",
        "tactic": "Execution",
        "technique_id": "T1496",
        "technique_name": "Resource Hijacking",
        "field": "command",
    },
]

# Threat detection type -> MITRE mappings (for fake-api detection results)
THREAT_TYPE_MAPPINGS: Dict[str, List[Tuple[str, str, str]]] = {
    "sql_injection": [
        ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    ],
    "xss": [
        ("Execution", "T1059.007", "Command and Scripting Interpreter: JavaScript"),
    ],
    "path_traversal": [
        ("Discovery", "T1083", "File and Directory Discovery"),
    ],
    "command_injection": [
        ("Execution", "T1059", "Command and Scripting Interpreter"),
    ],
}


# ---------------------------------------------------------------------------
# MitreMapper
# ---------------------------------------------------------------------------

class MitreMapper:
    """
    Maps honeypot events to MITRE ATT&CK tactics and techniques.

    Provides three mapping strategies:
    1. Event type mapping - maps event_type to default tactics/techniques
    2. Pattern matching - regex patterns against command/path/payload fields
    3. Threat detection mapping - maps threat detection results from fake-api

    All strategies are combined to produce a comprehensive mapping.
    """

    def __init__(
        self,
        custom_rules_path: Optional[str] = None,
        enable_patterns: bool = True,
    ):
        self._event_type_mappings = dict(EVENT_TYPE_MAPPINGS)
        self._threat_type_mappings = dict(THREAT_TYPE_MAPPINGS)
        self._pattern_rules: List[PatternRule] = []
        self._enable_patterns = enable_patterns

        # Load default pattern rules
        if enable_patterns:
            for rule_dict in DEFAULT_PATTERN_RULES:
                self._pattern_rules.append(PatternRule(
                    pattern=re.compile(rule_dict["pattern"], re.IGNORECASE),
                    tactic=rule_dict["tactic"],
                    technique_id=rule_dict["technique_id"],
                    technique_name=rule_dict["technique_name"],
                    field=rule_dict.get("field", "command"),
                    confidence=rule_dict.get("confidence", 0.9),
                ))

        # Load custom rules from YAML if provided
        if custom_rules_path:
            self._load_custom_rules(custom_rules_path)
        else:
            # Try default location
            default_path = os.path.join(
                os.path.dirname(__file__), 'mitre_rules.yaml'
            )
            if os.path.exists(default_path):
                self._load_custom_rules(default_path)

        logger.info(
            f"MitreMapper initialized: {len(self._event_type_mappings)} event types, "
            f"{len(self._pattern_rules)} pattern rules"
        )

    def _load_custom_rules(self, path: str):
        """Load custom mapping rules from a YAML file."""
        try:
            import yaml
        except ImportError:
            logger.warning("PyYAML not installed, skipping custom MITRE rules")
            return

        try:
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"Failed to load MITRE rules from {path}: {e}")
            return

        if not data:
            return

        # Load custom event type mappings
        for mapping in data.get('event_type_mappings', []):
            event_type = mapping.get('event_type')
            if not event_type:
                continue
            entries = []
            for m in mapping.get('mappings', []):
                entries.append((
                    m.get('tactic', ''),
                    m.get('technique_id', ''),
                    m.get('technique_name', ''),
                ))
            if entries:
                self._event_type_mappings[event_type] = entries

        # Load custom pattern rules
        for rule in data.get('pattern_rules', []):
            pattern_str = rule.get('pattern')
            if not pattern_str:
                continue
            try:
                compiled = re.compile(pattern_str, re.IGNORECASE)
            except re.error as e:
                logger.warning(f"Invalid regex in custom rule: {pattern_str}: {e}")
                continue
            self._pattern_rules.append(PatternRule(
                pattern=compiled,
                tactic=rule.get('tactic', ''),
                technique_id=rule.get('technique_id', ''),
                technique_name=rule.get('technique_name', ''),
                field=rule.get('field', 'command'),
                confidence=rule.get('confidence', 0.9),
            ))

        logger.info(f"Loaded custom MITRE rules from {path}")

    def map_event(self, event: Dict[str, Any]) -> List[MitreMapping]:
        """
        Map a raw event dict to MITRE ATT&CK tactics and techniques.

        Args:
            event: Event dictionary with fields like 'event', 'command', 'path', etc.

        Returns:
            List of MitreMapping objects.
        """
        mappings: List[MitreMapping] = []
        seen: Set[str] = set()  # Dedup by technique_id

        # 1. Event type mapping
        event_type = event.get('event', event.get('event_type', ''))
        if event_type:
            for tactic, tech_id, tech_name in self._event_type_mappings.get(event_type, []):
                key = f"{tactic}:{tech_id}"
                if key not in seen:
                    seen.add(key)
                    mappings.append(MitreMapping(
                        tactic=tactic,
                        technique_id=tech_id,
                        technique_name=tech_name,
                        confidence=0.8,
                        source=f"event_type:{event_type}",
                    ))

        # 2. Pattern-based matching
        if self._enable_patterns:
            for rule in self._pattern_rules:
                value = self._get_field_value(event, rule.field)
                if value and rule.pattern.search(value):
                    key = f"{rule.tactic}:{rule.technique_id}"
                    if key not in seen:
                        seen.add(key)
                        mappings.append(MitreMapping(
                            tactic=rule.tactic,
                            technique_id=rule.technique_id,
                            technique_name=rule.technique_name,
                            confidence=rule.confidence,
                            source=f"pattern:{rule.field}",
                        ))

        # 3. Username-based heuristics
        username = event.get('username', '')
        if username:
            lower_user = username.lower() if isinstance(username, str) else ''
            if lower_user in ('root', 'admin', 'administrator'):
                key = "Initial Access:T1078.001"
                if key not in seen:
                    seen.add(key)
                    mappings.append(MitreMapping(
                        tactic="Initial Access",
                        technique_id="T1078.001",
                        technique_name="Valid Accounts: Default Accounts",
                        confidence=0.7,
                        source="username_heuristic",
                    ))

        # 4. Threat detection results (from fake-api detectThreats)
        detections = event.get('detection', None)
        if detections and isinstance(detections, list):
            for detection in detections:
                threat_type = detection.get('type', '')
                for tactic, tech_id, tech_name in self._threat_type_mappings.get(threat_type, []):
                    key = f"{tactic}:{tech_id}"
                    if key not in seen:
                        seen.add(key)
                        mappings.append(MitreMapping(
                            tactic=tactic,
                            technique_id=tech_id,
                            technique_name=tech_name,
                            confidence=0.95,
                            source=f"threat_detection:{threat_type}",
                        ))

        return mappings

    def enrich(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich an event dict with MITRE ATT&CK fields in-place.

        Adds or extends:
        - mitre_tactics: List[str] of tactic names
        - mitre_techniques: List[str] of technique IDs
        - mitre_technique_names: List[str] of technique names
        - mitre_mappings: List[dict] with full mapping details

        Args:
            event: Event dictionary to enrich.

        Returns:
            The same event dict, now enriched with MITRE fields.
        """
        mappings = self.map_event(event)

        if not mappings:
            return event

        # Collect unique values, preserving order
        tactics: List[str] = list(event.get('mitre_tactics', []))
        techniques: List[str] = list(event.get('mitre_techniques', []))
        technique_names: List[str] = list(event.get('mitre_technique_names', []))

        tactics_set = set(tactics)
        techniques_set = set(techniques)

        for m in mappings:
            if m.tactic and m.tactic not in tactics_set:
                tactics.append(m.tactic)
                tactics_set.add(m.tactic)
            if m.technique_id and m.technique_id not in techniques_set:
                techniques.append(m.technique_id)
                techniques_set.add(m.technique_id)
                technique_names.append(m.technique_name)

        event['mitre_tactics'] = tactics
        event['mitre_techniques'] = techniques
        event['mitre_technique_names'] = technique_names

        return event

    def _get_field_value(self, event: Dict[str, Any], field_path: str) -> Optional[str]:
        """
        Get a string value from the event, supporting dot-notation
        and checking nested 'request' objects.
        """
        # Direct field
        value = event.get(field_path)
        if value and isinstance(value, str):
            return value

        # Dot notation (e.g., "request.path")
        if '.' in field_path:
            parts = field_path.split('.', 1)
            nested = event.get(parts[0])
            if isinstance(nested, dict):
                value = nested.get(parts[1])
                if value and isinstance(value, str):
                    return value

        # Check common nested locations
        if field_path == "path":
            # Also check request.path
            request = event.get('request', {})
            if isinstance(request, dict):
                value = request.get('path')
                if value and isinstance(value, str):
                    return value

        return None


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

_default_mapper: Optional[MitreMapper] = None


def get_mapper() -> MitreMapper:
    """Get or create the default MitreMapper instance."""
    global _default_mapper
    if _default_mapper is None:
        custom_path = os.environ.get('HONEYCLAW_MITRE_RULES')
        _default_mapper = MitreMapper(custom_rules_path=custom_path)
    return _default_mapper


def enrich_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich an event with MITRE ATT&CK mappings using the default mapper.

    Convenience function for integration into logging pipelines.

    Args:
        event: Event dict to enrich.

    Returns:
        The enriched event dict.
    """
    return get_mapper().enrich(event)
