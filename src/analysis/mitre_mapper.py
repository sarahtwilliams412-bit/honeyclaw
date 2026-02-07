#!/usr/bin/env python3
"""
Honeyclaw MITRE ATT&CK Mapper

Comprehensive mapping of observed honeypot behaviors to MITRE ATT&CK framework.

Auto-tags events as they flow through the logging pipeline, supporting:
- Tactic identification (TA0001-TA0011)
- Technique identification (T1xxx)
- Sub-technique identification (T1xxx.xxx)
- Event-type-based mapping
- Pattern-based command analysis (regex matching)
- Custom mapping rules via configuration
- Confidence scoring per mapping

Reference: https://attack.mitre.org/
"""

import os
import re
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger('honeyclaw.analysis.mitre')


# --- MITRE ATT&CK IDs ---

class TacticID:
    """MITRE ATT&CK Tactic IDs."""
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


class TechniqueID:
    """MITRE ATT&CK Technique IDs (commonly observed in honeypots)."""
    # Initial Access
    VALID_ACCOUNTS = "T1078"
    EXPLOIT_PUBLIC_APP = "T1190"
    EXTERNAL_REMOTE_SERVICES = "T1133"

    # Execution
    COMMAND_SCRIPTING = "T1059"
    UNIX_SHELL = "T1059.004"
    PYTHON = "T1059.006"

    # Persistence
    ACCOUNT_MANIPULATION = "T1098"
    CREATE_ACCOUNT = "T1136"
    SSH_AUTHORIZED_KEYS = "T1098.004"
    CRON_JOB = "T1053.003"
    SYSTEMD_SERVICE = "T1543.002"
    BOOT_LOGON_AUTOSTART = "T1547"
    RC_SCRIPTS = "T1037.004"

    # Privilege Escalation
    ABUSE_ELEVATION = "T1548"
    SUDO_ABUSE = "T1548.003"
    SETUID_SETGID = "T1548.001"
    EXPLOITATION_FOR_PRIV_ESC = "T1068"
    CONTAINER_ESCAPE = "T1611"

    # Defense Evasion
    INDICATOR_REMOVAL = "T1070"
    CLEAR_LINUX_LOGS = "T1070.002"
    FILE_DELETION = "T1070.004"
    TIMESTOMP = "T1070.006"
    HIDE_ARTIFACTS = "T1564"
    DISABLE_SECURITY_TOOLS = "T1562"
    PROCESS_INJECTION = "T1055"

    # Credential Access
    BRUTE_FORCE = "T1110"
    PASSWORD_GUESSING = "T1110.001"
    CREDENTIAL_STUFFING = "T1110.004"
    CREDENTIAL_DUMPING = "T1003"
    UNSECURED_CREDENTIALS = "T1552"
    CREDENTIALS_IN_FILES = "T1552.001"

    # Discovery
    SYSTEM_INFO_DISCOVERY = "T1082"
    FILE_DIR_DISCOVERY = "T1083"
    NETWORK_SERVICE_DISCOVERY = "T1046"
    PROCESS_DISCOVERY = "T1057"
    ACCOUNT_DISCOVERY = "T1087"
    SYSTEM_NETWORK_CONFIG = "T1016"
    SYSTEM_NETWORK_CONNECTIONS = "T1049"
    PERMISSION_GROUPS_DISCOVERY = "T1069"
    SYSTEM_OWNER_DISCOVERY = "T1033"
    SOFTWARE_DISCOVERY = "T1518"

    # Lateral Movement
    REMOTE_SERVICES = "T1021"
    SSH = "T1021.004"
    REMOTE_FILE_COPY = "T1105"

    # Collection
    DATA_FROM_LOCAL_SYSTEM = "T1005"
    DATA_STAGED = "T1074"
    ARCHIVE_DATA = "T1560"

    # Command and Control
    APPLICATION_LAYER_PROTOCOL = "T1071"
    INGRESS_TOOL_TRANSFER = "T1105"
    NON_STANDARD_PORT = "T1571"
    ENCRYPTED_CHANNEL = "T1573"

    # Exfiltration
    EXFIL_OVER_C2 = "T1041"
    EXFIL_OVER_WEB = "T1567"

    # Impact
    DATA_DESTRUCTION = "T1485"
    RESOURCE_HIJACKING = "T1496"
    DEFACEMENT = "T1491"


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
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}


@dataclass
class MitreMapping:
    """A single MITRE ATT&CK mapping result."""
    tactic: str           # e.g. "Initial Access"
    technique_id: str     # e.g. "T1078"
    technique_name: str   # e.g. "Valid Accounts"
    confidence: float = 0.8  # 0.0-1.0
    source: str = ""      # What triggered this mapping
    tactic_id: str = ""   # e.g. "TA0001"
    sub_technique_id: Optional[str] = None
    sub_technique_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "tactic": self.tactic,
            "tactic_id": self.tactic_id,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "confidence": round(self.confidence, 2),
        }
        if self.source:
            d["source"] = self.source
        if self.sub_technique_id:
            d["sub_technique_id"] = self.sub_technique_id
            d["sub_technique_name"] = self.sub_technique_name
        return d


@dataclass
class PatternRule:
    """A regex-based rule that maps command/payload patterns to MITRE."""
    pattern: re.Pattern
    tactic: str
    technique_id: str
    technique_name: str
    field: str = "command"     # Which event field to match against
    confidence: float = 0.9
    tactic_id: str = ""


# Event type -> default MITRE mappings
EVENT_TYPE_MAPPINGS: Dict[str, List[Tuple[str, str, str, str]]] = {
    # (tactic, tactic_id, technique_id, technique_name)
    "connection": [
        ("Reconnaissance", "TA0043", "T1595", "Active Scanning"),
    ],
    "auth_attempt": [
        ("Initial Access", "TA0001", "T1078", "Valid Accounts"),
        ("Credential Access", "TA0006", "T1110", "Brute Force"),
    ],
    "auth_success": [
        ("Initial Access", "TA0001", "T1078", "Valid Accounts"),
    ],
    "auth_failure": [
        ("Credential Access", "TA0006", "T1110", "Brute Force"),
    ],
    "login_attempt": [
        ("Initial Access", "TA0001", "T1078", "Valid Accounts"),
        ("Credential Access", "TA0006", "T1110", "Brute Force"),
    ],
    "login_success": [
        ("Initial Access", "TA0001", "T1078", "Valid Accounts"),
    ],
    "session_established": [
        ("Initial Access", "TA0001", "T1078", "Valid Accounts"),
    ],
    "pubkey_attempt": [
        ("Initial Access", "TA0001", "T1078.004", "Valid Accounts: Cloud Accounts"),
        ("Credential Access", "TA0006", "T1110", "Brute Force"),
    ],
    "command": [
        ("Execution", "TA0002", "T1059", "Command and Scripting Interpreter"),
    ],
    "shell_command": [
        ("Execution", "TA0002", "T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    ],
    "file_access": [
        ("Collection", "TA0009", "T1005", "Data from Local System"),
    ],
    "file_read": [
        ("Collection", "TA0009", "T1005", "Data from Local System"),
    ],
    "file_upload": [
        ("Execution", "TA0002", "T1105", "Ingress Tool Transfer"),
    ],
    "data_exfil": [
        ("Exfiltration", "TA0010", "T1041", "Exfiltration Over C2 Channel"),
    ],
    "scan": [
        ("Reconnaissance", "TA0043", "T1595", "Active Scanning"),
    ],
    "exploit_attempt": [
        ("Initial Access", "TA0001", "T1190", "Exploit Public-Facing Application"),
    ],
    "malware": [
        ("Execution", "TA0002", "T1204", "User Execution"),
    ],
    "lateral_movement": [
        ("Lateral Movement", "TA0008", "T1021", "Remote Services"),
    ],
    "api_request": [
        ("Reconnaissance", "TA0043", "T1595.002", "Active Scanning: Vulnerability Scanning"),
    ],
    "http_request": [
        ("Reconnaissance", "TA0043", "T1595.002", "Active Scanning: Vulnerability Scanning"),
    ],
    "rate_limit_auth": [
        ("Credential Access", "TA0006", "T1110.001", "Brute Force: Password Guessing"),
    ],
    "rate_limit_connection": [
        ("Reconnaissance", "TA0043", "T1595.001", "Active Scanning: Scanning IP Blocks"),
    ],
    "rdp_connection": [
        ("Lateral Movement", "TA0008", "T1021.001", "Remote Services: Remote Desktop Protocol"),
    ],
    "winrm_connection": [
        ("Lateral Movement", "TA0008", "T1021.006", "Remote Services: Windows Remote Management"),
    ],
    "ldap_query": [
        ("Discovery", "TA0007", "T1087.002", "Account Discovery: Domain Account"),
    ],
    "smb_connection": [
        ("Lateral Movement", "TA0008", "T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    ],
}

# Pattern-based rules for command analysis
DEFAULT_PATTERN_RULES: List[Dict[str, Any]] = [
    # File and directory discovery
    {
        "pattern": r"\b(ls|dir|find|tree)\b",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "field": "command",
    },
    # System information discovery
    {
        "pattern": r"\b(uname|hostname|hostnamectl|lsb_release|cat\s+/etc/(os-release|issue|redhat-release))\b",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "field": "command",
    },
    # Process discovery
    {
        "pattern": r"\b(ps\s|ps$|top\b|htop\b|pstree\b)",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "technique_id": "T1057",
        "technique_name": "Process Discovery",
        "field": "command",
    },
    # Network configuration discovery
    {
        "pattern": r"\b(ifconfig|ip\s+(addr|route|link)|netstat|ss\s|arp\b|route\b)",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "technique_id": "T1016",
        "technique_name": "System Network Configuration Discovery",
        "field": "command",
    },
    # Network connections discovery
    {
        "pattern": r"\b(netstat\s+-[a-z]*[tl]|ss\s+-[a-z]*[tl]|lsof\s+-i)",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "technique_id": "T1049",
        "technique_name": "System Network Connections Discovery",
        "field": "command",
    },
    # Account discovery
    {
        "pattern": r"\b(whoami|id\b|who\b|w\b|users\b|last\b|cat\s+/etc/passwd)",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "technique_id": "T1087",
        "technique_name": "Account Discovery",
        "field": "command",
    },
    # Permission groups discovery
    {
        "pattern": r"\b(groups\b|cat\s+/etc/group|getent\s+group)",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "technique_id": "T1069",
        "technique_name": "Permission Groups Discovery",
        "field": "command",
    },
    # Credential access - /etc/shadow
    {
        "pattern": r"(cat|less|more|head|tail|vi|vim|nano|strings)\s+/etc/shadow",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique_id": "T1003.008",
        "technique_name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
        "field": "command",
    },
    # Credential access - SSH keys
    {
        "pattern": r"(cat|less|more|head|tail|cp|scp)\s+.*\.ssh/(id_rsa|id_ed25519|authorized_keys|known_hosts)",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique_id": "T1552.004",
        "technique_name": "Unsecured Credentials: Private Keys",
        "field": "command",
    },
    # Credential access - AWS credentials
    {
        "pattern": r"(cat|less|more|head|tail)\s+.*\.aws/(credentials|config)",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique_id": "T1552.001",
        "technique_name": "Unsecured Credentials: Credentials In Files",
        "field": "command",
    },
    # Data from local system (reading sensitive files)
    {
        "pattern": r"(cat|less|more|head|tail|strings)\s+.*(\.conf|\.cfg|\.ini|\.env|\.properties|config\.|secrets)",
        "tactic": "Collection",
        "tactic_id": "TA0009",
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "field": "command",
    },
    # Exfiltration via network tools
    {
        "pattern": r"\b(wget|curl|nc|ncat|netcat|scp|rsync|ftp)\b.*\b(http|ftp|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "field": "command",
    },
    # Ingress tool transfer
    {
        "pattern": r"\b(wget|curl)\s+.*(http|ftp).*(-O|-o|>)",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "field": "command",
    },
    # Privilege escalation - sudo
    {
        "pattern": r"\bsudo\b",
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "technique_id": "T1548.003",
        "technique_name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "field": "command",
    },
    # Privilege escalation - SUID
    {
        "pattern": r"\bchmod\s+[0-7]*[4-7][0-7]{2}\b|\bchmod\s+\+s\b",
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "technique_id": "T1548.001",
        "technique_name": "Abuse Elevation Control Mechanism: Setuid and Setgid",
        "field": "command",
    },
    # Privilege escalation - su
    {
        "pattern": r"\bsu\s+(root|-\s|--login)",
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "field": "command",
    },
    # Persistence - cron
    {
        "pattern": r"\b(crontab|/etc/cron)",
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "technique_id": "T1053.003",
        "technique_name": "Scheduled Task/Job: Cron",
        "field": "command",
    },
    # Persistence - systemd
    {
        "pattern": r"\b(systemctl\s+(enable|start|daemon-reload)|/etc/systemd)",
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "technique_id": "T1543.002",
        "technique_name": "Create or Modify System Process: Systemd Service",
        "field": "command",
    },
    # Persistence - authorized_keys modification
    {
        "pattern": r"(echo|>>|tee).*authorized_keys",
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "technique_id": "T1098.004",
        "technique_name": "Account Manipulation: SSH Authorized Keys",
        "field": "command",
    },
    # Defense evasion - log clearing
    {
        "pattern": r"\b(rm|truncate|>)\s+.*(\.log|/var/log|auth\.log|syslog|wtmp|lastlog|history)",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "technique_id": "T1070.002",
        "technique_name": "Indicator Removal: Clear Linux or Mac System Logs",
        "field": "command",
    },
    # Defense evasion - history clearing
    {
        "pattern": r"(history\s+-c|unset\s+HISTFILE|export\s+HISTSIZE=0|>/dev/null.*history|rm.*\.bash_history)",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "technique_id": "T1070.003",
        "technique_name": "Indicator Removal: Clear Command History",
        "field": "command",
    },
    # Defense evasion - timestomping
    {
        "pattern": r"\btouch\s+-[a-z]*t\b",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "technique_id": "T1070.006",
        "technique_name": "Indicator Removal: Timestomp",
        "field": "command",
    },
    # Execution - Python
    {
        "pattern": r"\bpython[23]?\s+(-c|.*\.py)",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "technique_id": "T1059.006",
        "technique_name": "Command and Scripting Interpreter: Python",
        "field": "command",
    },
    # Execution - Perl/Ruby
    {
        "pattern": r"\b(perl|ruby)\s+(-e|.*\.(pl|rb))",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "field": "command",
    },
    # Execution - encoded commands (base64)
    {
        "pattern": r"(base64\s+-d|echo\s+.*\|\s*base64|python.*decode\()",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "technique_id": "T1140",
        "technique_name": "Deobfuscate/Decode Files or Information",
        "field": "command",
    },
    # Lateral movement - SSH
    {
        "pattern": r"\bssh\s+",
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "technique_id": "T1021.004",
        "technique_name": "Remote Services: SSH",
        "field": "command",
    },
    # Lateral movement - SCP
    {
        "pattern": r"\bscp\s+",
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "technique_id": "T1021.004",
        "technique_name": "Remote Services: SSH",
        "field": "command",
    },
    # Container escape patterns
    {
        "pattern": r"(docker\s+run|nsenter|mount.*/proc|/var/run/docker\.sock|kubectl\s+exec)",
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "technique_id": "T1611",
        "technique_name": "Escape to Host",
        "field": "command",
    },
    # SQL injection (in path/query fields)
    {
        "pattern": r"('|\")\s*(or|and)\s+('|\")?\d+('|\")?\s*=\s*('|\")?\d+|union\s+select|;\s*(drop|delete|insert|update)\s",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "field": "path",
    },
    # Path traversal
    {
        "pattern": r"\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "field": "path",
    },
    # Software discovery
    {
        "pattern": r"\b(dpkg\s+-l|rpm\s+-qa|apt\s+list|pip\s+list|gem\s+list|npm\s+list)",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "technique_id": "T1518",
        "technique_name": "Software Discovery",
        "field": "command",
    },
    # Crypto mining
    {
        "pattern": r"(xmrig|minergate|coinhive|cryptonight|stratum\+tcp|mining\.pool|hashrate)",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "technique_id": "T1496",
        "technique_name": "Resource Hijacking",
        "field": "command",
    },
]

# Threat detection type -> MITRE mappings (for fake-api detection results)
THREAT_TYPE_MAPPINGS: Dict[str, List[Tuple[str, str, str, str]]] = {
    "sql_injection": [
        ("Initial Access", "TA0001", "T1190", "Exploit Public-Facing Application"),
    ],
    "xss": [
        ("Execution", "TA0002", "T1059.007", "Command and Scripting Interpreter: JavaScript"),
    ],
    "path_traversal": [
        ("Discovery", "TA0007", "T1083", "File and Directory Discovery"),
    ],
    "command_injection": [
        ("Execution", "TA0002", "T1059", "Command and Scripting Interpreter"),
    ],
}


class MitreMapper:
    """
    Maps honeypot events to MITRE ATT&CK tactics and techniques.

    Provides multiple mapping strategies:
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

        # Statistics
        self._events_processed = 0
        self._events_mapped = 0

        # Load default pattern rules
        if enable_patterns:
            for rule_dict in DEFAULT_PATTERN_RULES:
                self._pattern_rules.append(PatternRule(
                    pattern=re.compile(rule_dict["pattern"], re.IGNORECASE),
                    tactic=rule_dict["tactic"],
                    tactic_id=rule_dict.get("tactic_id", ""),
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
                    m.get('tactic_id', ''),
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
                tactic_id=rule.get('tactic_id', ''),
                technique_id=rule.get('technique_id', ''),
                technique_name=rule.get('technique_name', ''),
                field=rule.get('field', 'command'),
                confidence=rule.get('confidence', 0.9),
            ))

        logger.info(f"Loaded custom MITRE rules from {path}")

    def map_event(self, event: Dict[str, Any], event_type: Optional[str] = None) -> List[MitreMapping]:
        """
        Map a raw event dict to MITRE ATT&CK tactics and techniques.

        Args:
            event: Event dictionary with fields like 'event', 'command', 'path', etc.
            event_type: Optional event type (if not provided, extracted from event).

        Returns:
            List of MitreMapping objects.
        """
        self._events_processed += 1
        mappings: List[MitreMapping] = []
        seen: Set[str] = set()  # Dedup by technique_id

        # Determine event type
        ev_type = event_type or event.get('event', event.get('event_type', ''))

        # 1. Event type mapping
        if ev_type:
            for tactic, tactic_id, tech_id, tech_name in self._event_type_mappings.get(ev_type, []):
                key = f"{tactic}:{tech_id}"
                if key not in seen:
                    seen.add(key)
                    mappings.append(MitreMapping(
                        tactic=tactic,
                        tactic_id=tactic_id,
                        technique_id=tech_id,
                        technique_name=tech_name,
                        confidence=0.8,
                        source=f"event_type:{ev_type}",
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
                            tactic_id=rule.tactic_id,
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
                        tactic_id="TA0001",
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
                for tactic, tactic_id, tech_id, tech_name in self._threat_type_mappings.get(threat_type, []):
                    key = f"{tactic}:{tech_id}"
                    if key not in seen:
                        seen.add(key)
                        mappings.append(MitreMapping(
                            tactic=tactic,
                            tactic_id=tactic_id,
                            technique_id=tech_id,
                            technique_name=tech_name,
                            confidence=0.95,
                            source=f"threat_detection:{threat_type}",
                        ))

        if mappings:
            self._events_mapped += 1

        return mappings

    def enrich(self, event: Dict[str, Any], event_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Enrich an event dict with MITRE ATT&CK fields in-place.

        Adds or extends:
        - mitre_tactics: List[str] of tactic names
        - mitre_techniques: List[str] of technique IDs
        - mitre_technique_names: List[str] of technique names
        - mitre_mappings: List[dict] with full mapping details

        Args:
            event: Event dictionary to enrich.
            event_type: Optional event type override.

        Returns:
            The same event dict, now enriched with MITRE fields.
        """
        mappings = self.map_event(event, event_type)

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
        event['mitre_mappings'] = [m.to_dict() for m in mappings]

        return event

    def enrich_event(self, event: Dict[str, Any], event_type: str = "") -> Dict[str, Any]:
        """Alias for enrich() for compatibility."""
        return self.enrich(event, event_type or None)

    def get_stats(self) -> Dict[str, Any]:
        """Get mapping statistics."""
        return {
            "events_processed": self._events_processed,
            "events_mapped": self._events_mapped,
            "coverage_percent": round(
                (self._events_mapped / self._events_processed * 100)
                if self._events_processed > 0 else 0.0, 1
            ),
            "event_type_mappings": len(self._event_type_mappings),
            "pattern_rules": len(self._pattern_rules),
        }

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


# Module-level singleton
_default_mapper: Optional[MitreMapper] = None


def get_mapper() -> MitreMapper:
    """Get or create the default MitreMapper instance."""
    global _default_mapper
    if _default_mapper is None:
        custom_path = os.environ.get('HONEYCLAW_MITRE_RULES')
        _default_mapper = MitreMapper(custom_rules_path=custom_path)
    return _default_mapper


def enrich_event(event: Dict[str, Any], event_type: str = "") -> Dict[str, Any]:
    """
    Enrich an event with MITRE ATT&CK mappings using the default mapper.

    Convenience function for integration into logging pipelines.

    Args:
        event: Event dict to enrich.
        event_type: Optional event type (extracted from event if not provided).

    Returns:
        The enriched event dict.
    """
    return get_mapper().enrich(event, event_type or None)


def map_event(event: Dict[str, Any], event_type: str = "") -> List[MitreMapping]:
    """Convenience function to map an event."""
    return get_mapper().map_event(event, event_type or None)
